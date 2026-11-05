"""Keyed, typed repositories. Every function takes a Connection opened by `database.workspace_transaction` (tenant
tables, app runtime) or `database.transaction` (identity: auth runtime; evaluation: eval runtime). SQL is fixed
with bound parameters; callers cannot pass SQL fragments or untyped dictionaries.

These functions persist and read records; they do not decide authorization (T07) or workflow eligibility
(T18/T19). Row-level security and constraints in the database are the backstop, not a substitute for those checks.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from typing import Any
from uuid import UUID

from psycopg import errors as pg_errors
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError

from policyops.persistence.database import (
    DecisionConflict,
    IdempotencyConflict,
    ImmutableRecord,
    NotFound,
    StaleVersion,
)
from policyops.persistence.records import (
    AuditEvent,
    CaseRecord,
    CaseStatus,
    EvaluationRun,
    EvaluationTrial,
    ExecutionRecord,
    Membership,
    NewCase,
    NewJob,
    NewRun,
    Principal,
    UsageEvent,
    Workspace,
)
from policyops_contracts.consent import (
    ApprovalDecision,
    CaseMessage,
    CustomerConsent,
    MessageSource,
    ProposalPresentationRecord,
)
from policyops_contracts.digest import text_sha256
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.scalars import CaseScope, RunScope


MAX_PAGE = 200


def _one(connection: Connection, sql: str, params: Mapping[str, Any]) -> dict[str, Any] | None:
    row = connection.execute(text(sql), dict(params)).mappings().first()
    return dict(row) if row is not None else None


@contextmanager
def _mapped(conflict: type[Exception] | None = None) -> Iterator[None]:
    """Translate the database's own refusals into typed errors (the transaction is then unusable and rolls back)."""
    try:
        yield
    except DBAPIError as exc:
        original = exc.orig
        if isinstance(original, pg_errors.RaiseException):
            raise ImmutableRecord(str(original).splitlines()[0]) from exc
        if conflict is not None and isinstance(original, pg_errors.UniqueViolation):
            raise conflict(str(original).splitlines()[0]) from exc
        raise


# -- identity (auth runtime) ----------------------------------------------------------------------------------

def create_workspace(connection: Connection, workspace: Workspace) -> None:
    connection.execute(text("INSERT INTO identity.workspaces (id, slug, name, created_at) "
                            "VALUES (:id, :slug, :name, :created_at)"), workspace.model_dump())


def create_principal(connection: Connection, principal: Principal) -> None:
    connection.execute(text("INSERT INTO identity.principals (id, issuer, subject, display_name, created_at) "
                            "VALUES (:id, :issuer, :subject, :display_name, :created_at)"), principal.model_dump())


def add_membership(connection: Connection, membership: Membership) -> None:
    connection.execute(text(
        "INSERT INTO identity.memberships (id, workspace_id, principal_id, role, created_at, revoked_at, version) "
        "VALUES (:id, :workspace_id, :principal_id, :role, :created_at, :revoked_at, :version)"),
        membership.model_dump())


def find_principal(connection: Connection, issuer: str, subject: str) -> Principal | None:
    row = _one(connection, "SELECT id, issuer, subject, display_name, created_at FROM identity.principals "
               "WHERE issuer = :issuer AND subject = :subject", {"issuer": issuer, "subject": subject})
    return Principal.model_validate(row, strict=False) if row else None


def active_memberships(connection: Connection, principal_id: UUID) -> list[Membership]:
    rows = connection.execute(text(
        "SELECT id, workspace_id, principal_id, role, created_at, revoked_at, version FROM identity.memberships "
        "WHERE principal_id = :principal_id AND revoked_at IS NULL ORDER BY workspace_id, role"),
        {"principal_id": principal_id}).mappings().all()
    return [Membership.model_validate(dict(row), strict=False) for row in rows]


# -- memberships of the current workspace (app runtime, workspace scope; admin flows authorize first) -------

def workspace_memberships(connection: Connection) -> list[Membership]:
    rows = connection.execute(text(
        "SELECT id, workspace_id, principal_id, role, created_at, revoked_at, version FROM identity.memberships "
        "ORDER BY created_at, id LIMIT 500")).mappings().all()
    return [Membership.model_validate(dict(row), strict=False) for row in rows]


def revoke_membership(connection: Connection, membership_id: UUID, now: datetime) -> bool:
    """Revoke an active membership of the scoped workspace; False if it is not visible or already revoked."""
    return bool(connection.execute(text(
        "UPDATE identity.memberships SET revoked_at = :now, version = version + 1 WHERE id = :id "
        "AND revoked_at IS NULL"), {"id": membership_id, "now": now}).rowcount)


# -- cases and messages (app runtime, workspace scope) --------------------------------------------------------

def create_case(connection: Connection, case: NewCase) -> CaseRecord:
    row = _one(connection, "INSERT INTO app.cases (id, workspace_id, scenario, customer_user_id, created_by, "
               "created_at, status, updated_at) VALUES (:id, :workspace_id, :scenario, :customer_user_id, "
               ":created_by, :created_at, 'open', :created_at) "
               "RETURNING id, workspace_id, scenario, customer_user_id, created_by, created_at, status, "
               "updated_at, version", case.model_dump())
    return CaseRecord.model_validate(row, strict=False)


def get_case(connection: Connection, case_id: UUID) -> CaseRecord | None:
    row = _one(connection, "SELECT id, workspace_id, scenario, customer_user_id, created_by, created_at, status, "
               "updated_at, version "
               "FROM app.cases WHERE id = :id", {"id": case_id})
    return CaseRecord.model_validate(row, strict=False) if row else None


def set_case_status(connection: Connection, case_id: UUID, *, expected_version: int, status: CaseStatus,
                    now: datetime) -> CaseRecord:
    """Optimistic update: succeeds only if the row still has `expected_version`."""
    row = _one(connection, "UPDATE app.cases SET status = :status, updated_at = :now, version = version + 1 "
               "WHERE id = :id AND version = :expected "
               "RETURNING id, workspace_id, scenario, customer_user_id, created_by, created_at, status, "
               "updated_at, version",
               {"status": status, "now": now, "id": case_id, "expected": expected_version})
    if row is None:
        if get_case(connection, case_id) is None:
            raise NotFound(f"case {case_id}")
        raise StaleVersion(f"case {case_id} is no longer at version {expected_version}")
    return CaseRecord.model_validate(row, strict=False)


def append_message(connection: Connection, *, message_id: UUID, scope: CaseScope, source: MessageSource,
                   entered_by: UUID | None, text_value: str, created_at: datetime) -> CaseMessage:
    """Append with the next case sequence; the case row lock serializes concurrent appends (no gaps/duplicates)."""
    if _one(connection, "SELECT id FROM app.cases WHERE id = :id FOR UPDATE", {"id": scope.case_id}) is None:
        raise NotFound(f"case {scope.case_id}")
    sequence = connection.execute(text("SELECT coalesce(max(sequence), 0) + 1 FROM app.case_messages "
                                       "WHERE workspace_id = :w AND case_id = :c"),
                                  {"w": scope.workspace_id, "c": scope.case_id}).scalar_one()
    message = CaseMessage(message_id=message_id, scope=scope, sequence=sequence, source=source,
                          entered_by=entered_by, text=text_value, text_sha256=text_sha256(text_value),
                          created_at=created_at)
    connection.execute(text(
        "INSERT INTO app.case_messages (id, workspace_id, case_id, sequence, source, entered_by, text, text_sha256, "
        "created_at) VALUES (:id, :w, :c, :sequence, :source, :entered_by, :text, :digest, :created_at)"),
        {"id": message.message_id, "w": scope.workspace_id, "c": scope.case_id, "sequence": message.sequence,
         "source": message.source, "entered_by": message.entered_by, "text": message.text,
         "digest": message.text_sha256, "created_at": message.created_at})
    return message


def list_messages(connection: Connection, scope: CaseScope, *, after_sequence: int = 0,
                  limit: int = 50) -> list[CaseMessage]:
    if not 1 <= limit <= MAX_PAGE or after_sequence < 0:
        raise ValueError(f"limit must be 1..{MAX_PAGE} and after_sequence non-negative")
    rows = connection.execute(text(
        "SELECT id, sequence, source, entered_by, text, text_sha256, created_at FROM app.case_messages "
        "WHERE workspace_id = :w AND case_id = :c AND sequence > :after ORDER BY sequence LIMIT :limit"),
        {"w": scope.workspace_id, "c": scope.case_id, "after": after_sequence, "limit": limit}).mappings().all()
    return [CaseMessage.model_validate({"message_id": row["id"], "scope": scope, "sequence": row["sequence"],
                                        "source": row["source"], "entered_by": row["entered_by"],
                                        "text": row["text"], "text_sha256": row["text_sha256"],
                                        "created_at": row["created_at"]}, strict=False) for row in rows]


# -- runs and events ------------------------------------------------------------------------------------------

def create_run(connection: Connection, run: NewRun) -> None:
    connection.execute(text(
        "INSERT INTO app.runs (id, workspace_id, case_id, case_version, mode, graph_sha256, prompt_sha256, "
        "config_sha256, state, deadline_at, created_at, updated_at) VALUES (:id, :workspace_id, :case_id, "
        ":case_version, :mode, :graph_sha256, :prompt_sha256, :config_sha256, 'queued', :deadline_at, :created_at, "
        ":created_at)"), run.model_dump())


def append_run_event(connection: Connection, *, event_id: UUID, workspace_id: UUID, run_id: UUID, event_type: str,
                     schema_version: str, payload_json: str, occurred_at: datetime) -> int:
    if _one(connection, "SELECT id FROM app.runs WHERE id = :id FOR UPDATE", {"id": run_id}) is None:
        raise NotFound(f"run {run_id}")
    sequence = connection.execute(text("SELECT coalesce(max(sequence), 0) + 1 FROM app.run_events "
                                       "WHERE workspace_id = :w AND run_id = :r"),
                                  {"w": workspace_id, "r": run_id}).scalar_one()
    connection.execute(text(
        "INSERT INTO app.run_events (id, workspace_id, run_id, sequence, event_type, schema_version, payload, "
        "occurred_at) VALUES (:id, :w, :r, :sequence, :type, :schema, CAST(:payload AS jsonb), :at)"),
        {"id": event_id, "w": workspace_id, "r": run_id, "sequence": sequence, "type": event_type,
         "schema": schema_version, "payload": payload_json, "at": occurred_at})
    return int(sequence)


# -- proposals, consent, decisions, executions ----------------------------------------------------------------

def insert_proposal(connection: Connection, row_id: UUID, proposal: ActionProposal) -> None:
    """Store the complete validated proposal (body) with its binding keys as relational columns."""
    scope = proposal.scope
    with _mapped(IdempotencyConflict):
        connection.execute(text(
            "INSERT INTO app.action_proposals (id, workspace_id, case_id, run_id, proposal_id, proposal_version, "
            "tool_name, arguments, action_digest, intent_digest, presentation_sha256, body, policy_sha256, status, "
            "created_at, expires_at) VALUES (:id, :w, :c, :r, :pid, :pv, :tool, CAST(:arguments AS jsonb), :digest, "
            ":intent, :presentation, CAST(:body AS jsonb), :policy, 'created', :created_at, :expires_at)"),
            {"id": row_id, "w": scope.workspace_id, "c": scope.case_id, "r": scope.run_id,
             "pid": proposal.proposal_id, "pv": proposal.proposal_version, "tool": str(proposal.action.tool),
             "arguments": proposal.action.model_dump_json(), "digest": proposal.action_digest,
             "intent": proposal.intent_digest, "presentation": proposal.presentation.text_sha256,
             "body": proposal.model_dump_json(), "policy": proposal.policy.sha256,
             "created_at": proposal.created_at, "expires_at": proposal.expires_at})


def get_proposal(connection: Connection, proposal_id: UUID, proposal_version: int) -> ActionProposal | None:
    row = _one(connection, "SELECT body::text AS body, workspace_id, case_id, run_id, action_digest FROM "
               "app.action_proposals WHERE proposal_id = :pid AND proposal_version = :pv",
               {"pid": proposal_id, "pv": proposal_version})
    if row is None:
        return None
    proposal = ActionProposal.model_validate_json(row["body"])
    keys = (proposal.scope.workspace_id, proposal.scope.case_id, proposal.scope.run_id, proposal.action_digest)
    if keys != (row["workspace_id"], row["case_id"], row["run_id"], row["action_digest"]):
        raise ImmutableRecord(f"proposal {proposal_id} v{proposal_version} body disagrees with its keys")
    return proposal


def mark_presented(connection: Connection, presentation: ProposalPresentationRecord) -> None:
    """Record the complete presentation (append-only) and move the proposal to presented, in one transaction."""
    scope = presentation.scope
    with _mapped(DecisionConflict):
        connection.execute(text(
            "INSERT INTO app.proposal_presentations (workspace_id, case_id, run_id, proposal_id, proposal_version, "
            "action_digest, presentation_sha256, message_id, message_sequence, presented_at) VALUES (:w, :c, :r, "
            ":pid, :pv, :digest, :presentation, :message, :sequence, :at)"),
            {"w": scope.workspace_id, "c": scope.case_id, "r": scope.run_id, "pid": presentation.proposal_id,
             "pv": presentation.proposal_version, "digest": presentation.action_digest,
             "presentation": presentation.presentation_sha256, "message": presentation.message_id,
             "sequence": presentation.message_sequence, "at": presentation.presented_at})
    with _mapped():
        updated = connection.execute(text(
            "UPDATE app.action_proposals SET status = 'presented', presented_at = :at WHERE workspace_id = :w "
            "AND proposal_id = :pid AND proposal_version = :pv AND action_digest = :digest"),
            {"at": presentation.presented_at, "w": scope.workspace_id, "pid": presentation.proposal_id,
             "pv": presentation.proposal_version, "digest": presentation.action_digest}).rowcount
    if updated != 1:  # pragma: no cover - the presentation foreign key already proved the proposal exists
        raise NotFound(f"proposal {presentation.proposal_id} v{presentation.proposal_version}")


def get_presentation(connection: Connection, proposal_id: UUID,
                     proposal_version: int) -> ProposalPresentationRecord | None:
    row = _one(connection, "SELECT workspace_id, case_id, run_id, proposal_id, proposal_version, action_digest, "
               "presentation_sha256, message_id, message_sequence, presented_at FROM app.proposal_presentations "
               "WHERE proposal_id = :pid AND proposal_version = :pv", {"pid": proposal_id, "pv": proposal_version})
    if row is None:
        return None
    return ProposalPresentationRecord(
        scope=RunScope(workspace_id=row["workspace_id"], case_id=row["case_id"], run_id=row["run_id"]),
        proposal_id=row["proposal_id"], proposal_version=row["proposal_version"],
        action_digest=row["action_digest"], presentation_sha256=row["presentation_sha256"],
        message_id=row["message_id"], message_sequence=row["message_sequence"], presented_at=row["presented_at"])


def set_proposal_status(connection: Connection, workspace_id: UUID, proposal_id: UUID, proposal_version: int,
                        status: str) -> None:
    with _mapped():
        updated = connection.execute(text(
            "UPDATE app.action_proposals SET status = :status WHERE workspace_id = :w AND proposal_id = :pid "
            "AND proposal_version = :pv"), {"status": status, "w": workspace_id, "pid": proposal_id,
                                            "pv": proposal_version}).rowcount
    if updated != 1:
        raise NotFound(f"proposal {proposal_id} v{proposal_version}")


_CONSENT_FIELDS = ("consent_id", "proposal_id", "proposal_version", "action_digest", "presentation_sha256",
                   "presented_message_sequence", "customer_message_id", "customer_message_sequence",
                   "customer_message_sha256", "message_source", "entered_by", "basis", "confirmed_at", "expires_at")


def record_consent(connection: Connection, consent: CustomerConsent) -> None:
    """Store every field of the consent; the database checks each recorded case/run/sequence/digest/source against
    the referenced presentation and customer message."""
    params = {name: getattr(consent, name) for name in _CONSENT_FIELDS}
    params.update(w=consent.scope.workspace_id, c=consent.scope.case_id, r=consent.scope.run_id)
    with _mapped(DecisionConflict):
        connection.execute(text(
            "INSERT INTO app.customer_consents (id, workspace_id, case_id, run_id, proposal_id, proposal_version, "
            "action_digest, presentation_sha256, presented_message_sequence, customer_message_id, "
            "customer_message_sequence, customer_message_sha256, message_source, entered_by, basis, confirmed_at, "
            "expires_at) VALUES (:consent_id, :w, :c, :r, :proposal_id, :proposal_version, :action_digest, "
            ":presentation_sha256, :presented_message_sequence, :customer_message_id, :customer_message_sequence, "
            ":customer_message_sha256, :message_source, :entered_by, :basis, :confirmed_at, :expires_at)"), params)


def get_consent(connection: Connection, proposal_id: UUID, proposal_version: int) -> CustomerConsent | None:
    row = _one(connection, "SELECT id AS consent_id, workspace_id, case_id, run_id, proposal_id, proposal_version, "
               "action_digest, presentation_sha256, presented_message_sequence, customer_message_id, "
               "customer_message_sequence, customer_message_sha256, message_source, entered_by, basis, confirmed_at, "
               "expires_at FROM app.customer_consents WHERE proposal_id = :pid AND proposal_version = :pv",
               {"pid": proposal_id, "pv": proposal_version})
    if row is None:
        return None
    scope = RunScope(workspace_id=row.pop("workspace_id"), case_id=row.pop("case_id"), run_id=row.pop("run_id"))
    return CustomerConsent.model_validate({**row, "scope": scope}, strict=False)


def record_decision(connection: Connection, decision: ApprovalDecision) -> None:
    """At most one terminal decision per proposal version: a second (concurrent or replayed) one conflicts. The
    decision's case and run must be those of its consent (and so of the presentation and proposal)."""
    with _mapped(DecisionConflict):
        connection.execute(text(
            "INSERT INTO app.approval_decisions (id, workspace_id, case_id, run_id, proposal_id, proposal_version, "
            "action_digest, consent_id, principal_id, role, decision, reason, decided_at, expires_at) VALUES (:id, "
            ":w, :c, :r, :pid, :pv, :digest, :consent, :principal, :role, :decision, :reason, :decided_at, "
            ":expires_at)"),
            {"id": decision.approval_id, "w": decision.scope.workspace_id, "c": decision.scope.case_id,
             "r": decision.scope.run_id, "pid": decision.proposal_id, "pv": decision.proposal_version,
             "digest": decision.action_digest, "consent": decision.consent_id, "principal": decision.principal_id,
             "role": decision.role, "decision": decision.decision, "reason": decision.reason,
             "decided_at": decision.decided_at, "expires_at": decision.expires_at})


def get_decision(connection: Connection, proposal_id: UUID, proposal_version: int) -> ApprovalDecision | None:
    row = _one(connection, "SELECT id AS approval_id, workspace_id, case_id, run_id, proposal_id, proposal_version, "
               "action_digest, consent_id, principal_id, role, decision, reason, decided_at, expires_at FROM "
               "app.approval_decisions WHERE proposal_id = :pid AND proposal_version = :pv",
               {"pid": proposal_id, "pv": proposal_version})
    if row is None:
        return None
    scope = RunScope(workspace_id=row.pop("workspace_id"), case_id=row.pop("case_id"), run_id=row.pop("run_id"))
    return ApprovalDecision.model_validate({**row, "scope": scope}, strict=False)


def begin_execution(connection: Connection, *, execution_id: UUID, operation_id: UUID, decision: ApprovalDecision,
                    argument_digest: str, now: datetime) -> tuple[ExecutionRecord, bool]:
    """Create the execution for `operation_id`, or return the existing one if it carries the same approval and
    argument digest (`created` is False). Reuse with different content raises IdempotencyConflict."""
    params = {"id": execution_id, "w": decision.scope.workspace_id, "op": operation_id, "pid": decision.proposal_id,
              "pv": decision.proposal_version, "digest": decision.action_digest, "approval": decision.approval_id,
              "args": argument_digest, "now": now}
    row = _one(connection, "INSERT INTO app.tool_executions (id, workspace_id, operation_id, proposal_id, "
               "proposal_version, action_digest, approval_id, argument_digest, state, created_at, updated_at) VALUES "
               "(:id, :w, :op, :pid, :pv, :digest, :approval, :args, 'pending', :now, :now) "
               "ON CONFLICT (workspace_id, operation_id) DO NOTHING "
               "RETURNING id, workspace_id, operation_id, approval_id, argument_digest, state, "
               "attempts, version", params)
    if row is not None:
        return ExecutionRecord.model_validate(row, strict=False), True
    existing = _one(connection, "SELECT id, workspace_id, operation_id, approval_id, argument_digest, state, "
               "attempts, version "
                    "FROM app.tool_executions WHERE workspace_id = :w AND operation_id = :op", params)
    if existing is None:  # pragma: no cover - the conflicting row is committed and visible under READ COMMITTED
        raise IdempotencyConflict(f"operation {operation_id} conflicted but is not visible")
    record = ExecutionRecord.model_validate(existing, strict=False)
    if record.argument_digest != argument_digest or record.approval_id != decision.approval_id:
        raise IdempotencyConflict(f"operation {operation_id} was already used with a different payload")
    return record, False


# -- jobs, outbox, audit, usage --------------------------------------------------------------------------------

def job_request_sha256(job: NewJob) -> str:
    """Identity of an enqueue request: every requested field except the row ID and creation time, canonical JSON
    (sorted keys, UTC timestamps), hashed. Stored immutably, so it still matches after a worker reschedules the job."""
    request = job.model_dump(mode="json", exclude={"id", "created_at"})
    return hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def enqueue_job(connection: Connection, job: NewJob) -> tuple[UUID, bool]:
    """Idempotent by dedupe key: the same request returns the original ID (`created` False), however the job's
    mutable state has changed since; any difference in a requested field raises IdempotencyConflict."""
    params = {**job.model_dump(), "request": job_request_sha256(job)}
    row = _one(connection, "INSERT INTO app.jobs (id, workspace_id, run_id, dedupe_key, request_sha256, kind, "
               "run_generation, state, max_attempts, available_at, deadline_at, created_at, updated_at) VALUES (:id, "
               ":workspace_id, :run_id, :dedupe_key, :request, :kind, :run_generation, 'queued', :max_attempts, "
               ":available_at, :deadline_at, :created_at, :created_at) ON CONFLICT (workspace_id, dedupe_key) "
               "DO NOTHING RETURNING id", params)
    if row is not None:
        return row["id"], True
    existing = _one(connection, "SELECT id, request_sha256 FROM app.jobs WHERE workspace_id = :workspace_id AND "
                    "dedupe_key = :dedupe_key", params)
    if existing is None or existing["request_sha256"] != params["request"]:
        raise IdempotencyConflict(f"job key {job.dedupe_key!r} was already used for a different request")
    return existing["id"], False


def append_audit(connection: Connection, event: AuditEvent) -> None:
    connection.execute(text(
        "INSERT INTO app.audit_events (id, workspace_id, actor_kind, actor_principal_id, action, target_type, "
        "target_id, before_sha256, after_sha256, reason, correlation_id, occurred_at) VALUES (:id, :workspace_id, "
        ":actor_kind, :actor_principal_id, :action, :target_type, :target_id, :before_sha256, :after_sha256, "
        ":reason, :correlation_id, :occurred_at)"), event.model_dump())


_USAGE_FIELDS = ("reservation_id", "run_id", "actor", "model", "uncached_input_tokens", "cache_read_tokens",
                 "cache_write_tokens", "output_tokens", "reasoning_tokens", "price_revision", "cost_status",
                 "cost_usd")


def record_usage(connection: Connection, event: UsageEvent) -> bool:
    """Exactly one ledger row per provider request; a replay with identical content is a no-op (False), different
    content conflicts. Amounts are bound as exact Decimals."""
    params = event.model_dump()
    row = _one(connection, "INSERT INTO app.usage_events (id, workspace_id, reservation_id, run_id, actor, provider, "
               "model, provider_request_id, uncached_input_tokens, cache_read_tokens, cache_write_tokens, "
               "output_tokens, reasoning_tokens, price_revision, cost_status, cost_usd, created_at) VALUES (:id, "
               ":workspace_id, :reservation_id, :run_id, :actor, :provider, :model, :provider_request_id, "
               ":uncached_input_tokens, :cache_read_tokens, :cache_write_tokens, :output_tokens, :reasoning_tokens, "
               ":price_revision, :cost_status, :cost_usd, :created_at) "
               "ON CONFLICT (workspace_id, provider, provider_request_id) DO NOTHING RETURNING id", params)
    if row is not None:
        return True
    existing = _one(connection, "SELECT reservation_id, run_id, actor, model, uncached_input_tokens, "
                    "cache_read_tokens, cache_write_tokens, output_tokens, reasoning_tokens, price_revision, "
                    "cost_status, cost_usd FROM app.usage_events WHERE workspace_id = "
                    ":workspace_id AND provider = :provider AND provider_request_id = :provider_request_id", params)
    if existing is None or any(existing[name] != params[name] for name in _USAGE_FIELDS):
        raise IdempotencyConflict(f"provider request {event.provider_request_id!r} was recorded differently")
    return False


def usage_cost(connection: Connection, usage_id: UUID) -> tuple[str, Any]:
    row = _one(connection, "SELECT cost_status, cost_usd FROM app.usage_events WHERE id = :id", {"id": usage_id})
    if row is None:
        raise NotFound(f"usage {usage_id}")
    return row["cost_status"], row["cost_usd"]


# -- evaluation (eval runtime) --------------------------------------------------------------------------------

def create_evaluation_run(connection: Connection, run: EvaluationRun) -> None:
    connection.execute(text(
        "INSERT INTO evaluation.evaluation_runs (id, dataset, dataset_revision, split_id, config_sha256, config, "
        "status, created_at) VALUES (:id, :dataset, :dataset_revision, :split_id, :config_sha256, "
        "CAST(:config_json AS jsonb), 'planned', :created_at)"), run.model_dump())


def add_trial(connection: Connection, trial: EvaluationTrial) -> None:
    connection.execute(text(
        "INSERT INTO evaluation.evaluation_trials (id, evaluation_run_id, task_id, trial_index, seed, outcome, reward, "
        "components, error_class, cost_status, cost_usd, latency_ms, artifact_sha256, created_at) VALUES (:id, "
        ":evaluation_run_id, :task_id, :trial_index, :seed, :outcome, :reward, CAST(:components_json AS jsonb), "
        ":error_class, :cost_status, :cost_usd, :latency_ms, :artifact_sha256, :created_at)"), trial.model_dump())
