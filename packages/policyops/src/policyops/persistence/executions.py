"""The execution ledger rows (T19, revision 0012): reservation, claims and versioned transitions.

Every function runs in the caller's workspace transaction. The caller takes the locks in the T18/T09 order (corpora
FOR SHARE, run, proposal, memberships FOR SHARE, then the execution) and reads the lease clock after them. The
database trigger independently refuses binding changes, updates of terminal rows, counter regressions and any
transition outside the T19 state machine; a refusal is raised as `ImmutableRecord`. `discover` runs as
`policyops_worker_discovery`, which can read only scheduling metadata.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, text

from policyops.persistence.database import IdempotencyConflict, PersistenceError
from policyops.persistence.records import ExecutionRecord
from policyops.persistence.repositories import _mapped, _one
from policyops_contracts.retail_service import MutationRequest
from policyops_contracts.scalars import RunScope


COLUMNS = ("id, workspace_id, case_id, run_id, operation_id, proposal_id, proposal_version, action_digest, "
           "approval_id, consent_id, argument_digest, tool, target_kind, target_id, operation_sha256, request, "
           "authorization_not_after, state, attempts, reconcile_attempts, outcome, resolved_by, last_code, receipt, "
           "claim_id, lease_owner, lease_expires_at, dispatched_at, next_attempt_at, created_at, updated_at, version")
MUTABLE = frozenset({"state", "attempts", "receipt", "claim_id", "lease_owner", "lease_expires_at", "outcome",
                     "resolved_by", "last_code", "dispatched_at", "next_attempt_at", "reconcile_attempts"})
JSON_COLUMNS = frozenset({"receipt"})
# The immutable binding (the trigger refuses any change to it): a caller's snapshot must agree with the stored
# row on every field before a transition is taken on its behalf.
BINDING = ("id", "workspace_id", "case_id", "run_id", "operation_id", "proposal_id", "proposal_version",
           "action_digest", "approval_id", "consent_id", "argument_digest", "tool", "target_kind", "target_id",
           "operation_sha256", "request", "authorization_not_after", "created_at")


class ExecutionInProgress(PersistenceError):
    """Another execution for the same case target (order or user) is still unresolved; nothing was reserved."""


class LostClaim(PersistenceError):
    """The execution changed since it was read (another worker, a recorded outcome or an expired claim)."""


def _record(row: dict[str, Any] | None) -> ExecutionRecord | None:
    return None if row is None else ExecutionRecord.model_validate(row, strict=False)


def request_digest(request: MutationRequest) -> str:
    return hashlib.sha256(request.model_dump_json().encode("utf-8")).hexdigest()


def target_of(request: MutationRequest) -> tuple[str, str]:
    call = request.call
    order_id = getattr(call, "order_id", None)
    if order_id is not None:
        return "order", str(order_id)
    return "user", str(call.user_id)  # type: ignore[union-attr]


def get(connection: Connection, execution_id: UUID, *, lock: bool = False,
        skip_locked: bool = False) -> ExecutionRecord | None:
    suffix = " FOR UPDATE SKIP LOCKED" if skip_locked else " FOR UPDATE" if lock else ""
    return _record(_one(connection, f"SELECT {COLUMNS} FROM app.tool_executions "  # noqa: S608 - fixed columns
                        "WHERE workspace_id = app.current_workspace() AND id = :id" + suffix, {"id": execution_id}))


def by_approval(connection: Connection, approval_id: UUID) -> ExecutionRecord | None:
    return _record(_one(connection, f"SELECT {COLUMNS} FROM app.tool_executions "  # noqa: S608 - fixed columns
                        "WHERE workspace_id = app.current_workspace() AND approval_id = :a", {"a": approval_id}))


def case_executions(connection: Connection, case_id: UUID, *, limit: int = 1000) -> list[ExecutionRecord]:
    """Every execution of the case (bounded; more than `limit` raises, it is never silently truncated)."""
    rows = connection.execute(text(f"SELECT {COLUMNS} FROM app.tool_executions "  # noqa: S608 - fixed columns
                                   "WHERE workspace_id = app.current_workspace() AND case_id = :c "
                                   "ORDER BY created_at, id LIMIT :limit"), {"c": case_id, "limit": limit + 1})
    records = [ExecutionRecord.model_validate(dict(row), strict=False) for row in rows.mappings()]
    if len(records) > limit:
        raise PersistenceError("too many executions in one case to evaluate its history")
    return records


def reserve(connection: Connection, *, run: RunScope, approval_id: UUID, consent_id: UUID, proposal_id: UUID,
            proposal_version: int, request: MutationRequest, operation_sha256_of: Any,
            authorization_not_after: datetime, now: datetime) -> tuple[ExecutionRecord, bool]:
    """Insert the approval's execution with a new operation ID, or return the existing one (`created` False). The
    operation ID is chosen exactly once: a repeated reservation returns the stored ID. A different request for the
    same approval raises IdempotencyConflict; an unresolved execution on the same target raises
    ExecutionInProgress. `operation_sha256_of(operation_id)` is the client's fingerprint function."""
    operation_id = uuid4()
    kind, target = target_of(request)
    params = {"id": uuid4(), "w": run.workspace_id, "c": run.case_id, "r": run.run_id, "op": operation_id,
              "pid": proposal_id, "pv": proposal_version, "digest": request.intent_sha256, "a": approval_id,
              "consent": consent_id, "args": request_digest(request), "tool": str(request.call.tool),
              "kind": kind, "target": target, "sha": operation_sha256_of(operation_id),
              "request": request.model_dump_json(), "not_after": authorization_not_after, "now": now}
    with _mapped():
        row = _one(connection, "INSERT INTO app.tool_executions (id, workspace_id, case_id, run_id, "  # noqa: S608
                   "operation_id, "
                   "proposal_id, proposal_version, action_digest, approval_id, consent_id, argument_digest, tool, "
                   "target_kind, target_id, operation_sha256, request, authorization_not_after, state, "
                   "next_attempt_at, created_at, updated_at) VALUES (:id, :w, :c, :r, :op, :pid, :pv, :digest, :a, "
                   ":consent, :args, :tool, :kind, :target, :sha, CAST(:request AS jsonb), :not_after, 'pending', "
                   f":now, :now, :now) ON CONFLICT DO NOTHING RETURNING {COLUMNS}", params)
    if row is not None:
        return ExecutionRecord.model_validate(row, strict=False), True
    existing = by_approval(connection, approval_id)
    if existing is None:
        raise ExecutionInProgress(f"an unresolved execution already targets {kind} {target}")
    if existing.argument_digest != params["args"] or not matches_reservation(
            existing, run=run, approval_id=approval_id, consent_id=consent_id, proposal_id=proposal_id,
            proposal_version=proposal_version):
        raise IdempotencyConflict(f"approval {approval_id} already has an execution with a different request")
    return existing, False


def update(connection: Connection, execution: ExecutionRecord, now: datetime, **changes: Any) -> ExecutionRecord:
    """Apply `changes` to the locked row if it still has the read version (else LostClaim)."""
    if not changes or not set(changes) <= MUTABLE:
        raise ValueError("only mutable execution columns can change")
    assignments = ", ".join(f"{name} = CAST(:{name} AS jsonb)" if name in JSON_COLUMNS else f"{name} = :{name}"
                            for name in sorted(changes))
    values = {name: (None if value is None else json.dumps(value)) if name in JSON_COLUMNS else value
              for name, value in changes.items()}
    with _mapped():
        row = _one(connection, f"UPDATE app.tool_executions SET {assignments}, version = version + 1, "  # noqa: S608
                   "updated_at = greatest(updated_at, :now) WHERE workspace_id = app.current_workspace() "
                   f"AND id = :id AND version = :version RETURNING {COLUMNS}",
                   {**values, "now": now, "id": execution.id, "version": execution.version})
    record = _record(row)
    if record is None:
        raise LostClaim(f"execution {execution.id} changed concurrently")
    return record


def claim(connection: Connection, execution: ExecutionRecord, *, owner: UUID, lease: timedelta,
          now: datetime) -> ExecutionRecord:
    return update(connection, execution, now, claim_id=uuid4(), lease_owner=owner, lease_expires_at=now + lease)


def same_binding(current: ExecutionRecord, snapshot: ExecutionRecord) -> bool:
    return all(getattr(current, name) == getattr(snapshot, name) for name in BINDING)


def matches_reservation(existing: ExecutionRecord, *, run: RunScope, approval_id: UUID, consent_id: UUID,
                        proposal_id: UUID, proposal_version: int) -> bool:
    """Whether a repeated reservation names exactly the stored execution's run and authority references."""
    return (existing.workspace_id, existing.case_id, existing.run_id, existing.approval_id, existing.consent_id,
            existing.proposal_id, existing.proposal_version) == (
        run.workspace_id, run.case_id, run.run_id, approval_id, consent_id, proposal_id, proposal_version)


def holds_claim(current: ExecutionRecord, claimed: ExecutionRecord, now: datetime) -> bool:
    return (current.claim_id is not None and current.claim_id == claimed.claim_id
            and current.lease_owner == claimed.lease_owner and current.lease_expires_at is not None
            and current.lease_expires_at > now)


def discover(connection: Connection, now: datetime, limit: int) -> list[tuple[UUID, UUID]]:
    """(workspace, execution) pairs that look due: open, scheduled, and not under a live claim. Only scheduling
    metadata is readable; the claim re-reads and re-checks everything as the app runtime."""
    rows = connection.execute(text(
        "SELECT workspace_id, id FROM app.tool_executions WHERE state IN ('pending', 'dispatched', 'unknown') "
        "AND next_attempt_at <= :now AND (lease_expires_at IS NULL OR lease_expires_at <= :now) "
        "ORDER BY next_attempt_at, id LIMIT :limit"), {"now": now, "limit": limit}).all()
    return [(row[0], row[1]) for row in rows]
