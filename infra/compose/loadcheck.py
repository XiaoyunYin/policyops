"""Reconcile N10 JSONL against runtime-scoped rows and the authenticated retail simulator."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from contextlib import closing, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, BinaryIO
from uuid import UUID

from pydantic import TypeAdapter
from sqlalchemy import Connection, Engine, event, text
from sqlalchemy.engine.interfaces import DBAPICursor, ExecutionContext

from infra.compose.load_identity import SeedError, load_config, require, verify_identity
from infra.compose.loadseed import retail_client, workspace_accounting
from infra.compose.runtime import demo, demo_bindings, own_engine
from policyops.adapters.retail_client import Unknown
from policyops.persistence import executions, identity, runs
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.services.review_outcomes import RefusalReason, refusal_message_id, refusal_text
from policyops_contracts.digest import canonical_bytes, text_sha256
from policyops_contracts.events import EventPayload, ReviewOutcome, ReviewReason
from policyops_contracts.retail import GetUserDetails
from policyops_contracts.retail_service import Receipt
from policyops_contracts.scalars import CaseScope


STALE = {
    "expired": "api.proposal_expired",
    "superseded": "api.proposal_superseded",
    "unconsented": "api.consent_required",
}
CANARIES = {"case_detail", "messages", "case_proposals", "run_snapshot", "proposal_detail", "stream"}
EVENT_PAYLOAD = TypeAdapter(EventPayload)


@dataclass(frozen=True)
class Execution:
    proposal_id: str
    version: int
    state: str
    outcome: str | None
    local_hash: str | None
    remote_hash: str | None
    remote_outcome: str | None


@dataclass(frozen=True)
class Observed:
    messages: tuple[str, ...]
    consents: tuple[str, ...]
    message_audit: int
    decision_ids: tuple[str, ...]
    decision_kinds: tuple[str, ...]
    decision_audit: int
    executions: tuple[Execution, ...]
    simulator_version: int
    stuck_jobs: int
    pending_outcomes: int
    run_state: str
    terminal_projection: str | None
    projection_message_id: str | None = None


def check_case(fixture: dict[str, Any], write: dict[str, Any], observed: Observed) -> list[str]:
    findings: list[str] = []
    mode = fixture["control"]
    stale = mode in STALE
    approved = not stale and mode != "reject"
    decisions = write.get("decisions", [])
    expected = [409] if stale else {"race": [201, 409], "replay": [200, 201]}.get(mode, [201])
    if Counter(decisions) != Counter(expected):
        findings.append("race" if mode == "race" else "decision_replay" if mode == "replay" else "decision_status")
    if stale and write.get("stale_rule_id") != STALE[mode]:
        findings.append("stale_refusal")
    if stale and observed.projection_message_id is not None:
        findings.append("stale_projection")
    if write.get("control") != mode or write.get("run_id") != fixture["run_id"]:
        findings.append("workflow_binding")
    if mode == "replay" and (
        write.get("consent_replay_status") != 201
        or not write.get("consent_replay_equal")
        or not write.get("decision_replay_equal")
    ):
        findings.append("replay_bytes")

    new_message = int(write.get("consent_status") == 201)
    new_decision = decisions.count(201)
    if (
        new_message != int(not stale)
        or len(observed.messages) != new_message
        or len(observed.consents) != new_message
        or (
            new_message
            and (observed.messages, observed.consents) != ((write.get("message_id"),), (write.get("consent_id"),))
        )
    ):
        findings.append("message_accounting")
    if (
        len(observed.decision_ids) != new_decision
        or (new_decision and observed.decision_ids != (write.get("approval_id"),))
        or observed.decision_kinds != (() if stale else ("approve" if approved else "reject",))
    ):
        findings.append("decision_accounting")
    if observed.message_audit != new_message or observed.decision_audit != new_decision:
        findings.append("audit_accounting")
    if len(observed.executions) != int(approved):
        findings.append("execution_count")
    if approved and observed.executions:
        execution = observed.executions[0]
        if (execution.proposal_id, execution.version, execution.state, execution.outcome, execution.remote_outcome) != (
            fixture["proposal_id"],
            fixture["proposal_version"],
            "succeeded",
            "committed",
            "committed",
        ):
            findings.append("execution_binding")
        if execution.local_hash is None or execution.local_hash != execution.remote_hash:
            findings.append("receipt_hash")
        if write.get("receipt") != execution.local_hash or execution.local_hash != observed.terminal_projection:
            findings.append("terminal_receipt")
    if approved and observed.run_state != "succeeded":
        findings.append("terminal_state")
    if mode == "reject" and (
        write.get("receipt") != "rejected"
        or observed.terminal_projection != "rejected"
        or observed.run_state not in {"failed", "cancelled", "succeeded"}
    ):
        findings.append("rejection_projection")
    if observed.simulator_version != fixture["simulator_version"] + int(approved):
        findings.append("simulator_version" if approved else "refusal_effect")
    if observed.stuck_jobs:
        findings.append("stuck_jobs")
    if observed.pending_outcomes:
        findings.append("pending_outcomes")
    return findings


def check_stream(
    expected: list[tuple[int, str, dict[str, Any]]], seen: list[dict[str, Any]], end: dict[str, Any],
    *, interrupted: bool = False,
) -> list[str]:
    if interrupted:
        expected = expected[:len(seen)]
    digests = [
        (sequence, identifier, hashlib.sha256(canonical_bytes(
            EVENT_PAYLOAD.validate_json(json.dumps(payload))
        )).hexdigest())
        for sequence, identifier, payload in expected
    ]
    actual = [(row["sequence"], row["event_id"], row["payload_sha256"]) for row in seen]
    if (
        (not interrupted and not expected)
        or digests != actual
        or end.get("sequence") != len(expected)
        or any(sequence != index for index, (sequence, _, _) in enumerate(expected, 1))
    ):
        return ["stream_db_continuity"]
    return []


def event_refs_owned(
    payload: dict[str, Any], inventory: dict[str, Any], case: str, run: str, proposals: list[dict[str, Any]],
) -> bool:
    execution = inventory["executions"].get(payload.get("execution_id"))
    operation = payload.get("operation_id")
    if operation is not None and (execution is None or execution["operation_id"] != operation):
        return False
    decision = payload.get("approval_id") or payload.get("decision_id")
    if execution is not None and decision is not None and execution["approval_id"] != decision:
        return False
    for identifier, table in (
        (payload.get("message_id"), "messages"), (payload.get("consent_id"), "consents"),
        (decision, "decisions"), (payload.get("execution_id"), "executions"),
    ):
        if identifier is not None:
            owner = inventory[table].get(identifier)
            if owner is None or owner["case_id"] != case or owner.get("run_id", run) != run:
                return False
    proposal = payload.get("proposal_id")
    return proposal is None or any(
        row["proposal_id"] == proposal and row["case_id"] == case and row["run_id"] == run
        and row["proposal_version"] == payload.get("proposal_version", row["proposal_version"])
        for row in proposals
    )


def receipt_hash(receipt: Receipt | None) -> str | None:
    return hashlib.sha256(receipt.model_dump_json().encode()).hexdigest() if receipt is not None else None


def read_case(app: Engine, fixture: dict[str, Any]) -> Observed:
    workspace, case, run = (UUID(fixture[key]) for key in ("workspace_id", "case_id", "run_id"))
    with workspace_transaction(app, workspace) as conn:
        messages = tuple(
            str(value)
            for value in conn.execute(
                text("SELECT id FROM app.case_messages WHERE case_id=:c AND source='operator_entered_customer'"),
                {"c": case},
            ).scalars()
        )
        consents = tuple(
            str(value)
            for value in conn.execute(
                text("SELECT id FROM app.customer_consents WHERE case_id=:c"), {"c": case}
            ).scalars()
        )
        decisions = conn.execute(
            text("SELECT id,decision FROM app.approval_decisions WHERE case_id=:c"), {"c": case}
        ).all()
        audits = conn.execute(
            text(
                "SELECT action,count(*) FROM app.audit_events WHERE "
                "(action='case.message_posted' AND target_id IN (SELECT id FROM app.case_messages WHERE case_id=:c)) "
                "OR (action='proposal.decide' AND target_id IN (SELECT id FROM app.action_proposals WHERE case_id=:c)) "
                "GROUP BY action"
            ),
            {"c": case},
        ).all()
        jobs = conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE state='dead' OR state='leased' OR (state='queued' AND "
                "(review_trigger IS DISTINCT FROM 'expiry' OR available_at <= clock_timestamp()))), "
                "count(*) FILTER (WHERE review_trigger='outcome' AND state IN ('queued','leased')) "
                "FROM app.jobs WHERE run_id=:r"
            ),
            {"r": run},
        ).one()
        persisted_run = runs.get_run(conn, run)
        if persisted_run is None:
            raise ValueError("missing run")
        projection = conn.execute(
            text(
                "SELECT payload FROM app.run_events WHERE run_id=:r AND event_type='review.outcome' "
                "ORDER BY sequence DESC LIMIT 1"
            ),
            {"r": run},
        ).scalar_one_or_none()
        ids = conn.execute(text("SELECT id FROM app.tool_executions WHERE case_id=:c"), {"c": case}).scalars()
        rows = [executions.get(conn, identifier) for identifier in ids]
    local = []
    with closing(retail_client(workspace, case)) as retail:
        for row in rows:
            if row is None:
                raise ValueError("missing execution")
            remote = retail.lookup(row.operation_id, row.request)
            if isinstance(remote, Unknown):
                raise ValueError("simulator lookup failed")
            result = remote.result
            local.append(
                Execution(
                    str(row.proposal_id),
                    row.proposal_version,
                    row.state,
                    row.outcome,
                    receipt_hash(row.receipt),
                    receipt_hash(result.receipt) if result else None,
                    result.outcome if result else None,
                )
            )
        remote_read = retail.read(GetUserDetails(user_id=demo()["customer_id"]))
        if isinstance(remote_read, Unknown):
            raise ValueError("simulator version read failed")
    counts = {action: int(count) for action, count in audits}
    receipt = (
        (projection.get("receipt_sha256") if projection.get("reason") != "review_rejected" else "rejected")
        if projection
        else None
    )
    return Observed(
        messages,
        consents,
        counts.get("case.message_posted", 0),
        tuple(str(row.id) for row in decisions),
        tuple(row.decision for row in decisions),
        counts.get("proposal.decide", 0),
        tuple(local),
        remote_read.case_version,
        jobs[0],
        jobs[1],
        persisted_run.state,
        receipt,
        projection["message_id"] if projection else None,
    )


def workspace_job_health(conn: Connection) -> dict[str, int]:
    row = conn.execute(text(
        "SELECT count(*) FILTER (WHERE state='dead') AS dead_jobs, "
        "count(*) FILTER (WHERE state='queued' AND available_at <= statement_timestamp()) AS overdue_queued_jobs, "
        "count(*) FILTER (WHERE state='leased' AND lease_expires_at <= statement_timestamp()) AS expired_job_leases "
        "FROM app.jobs"
    )).mappings().one()
    return dict(row)


def decision_binding(row: dict[str, Any]) -> tuple[Any, ...]:
    return row["run_id"], row["proposal_id"], row["proposal_version"]


def prior_expiry_message(
    workspace: UUID, job_id: str, job: dict[str, Any], before: dict[str, Any], after: dict[str, Any],
) -> tuple[str, str] | None:
    reason = RefusalReason.PROPOSAL_EXPIRED
    identifier = str(refusal_message_id(workspace, UUID(job["run_id"]), UUID(job_id)))
    message = after["messages"].get(identifier)
    if (message is None or identifier in before["messages"] or message["source"] != "agent"
            or message["entered_by"] is not None or message["text_sha256"] != text_sha256(refusal_text(reason))):
        return None
    expected = ReviewOutcome(
        proposal_id=UUID(job["proposal_id"]), proposal_version=job["proposal_version"],
        outcome="refused", reason=ReviewReason.PROPOSAL_EXPIRED, message_id=UUID(identifier),
    ).model_dump(mode="json")
    outcomes = [
        row for key, row in after.get("expiry_outcomes", {}).items()
        if key not in before.get("expiry_outcomes", {}) and row["run_id"] == job["run_id"]
        and row["case_id"] == message["case_id"] and row["payload"] == expected
    ]
    if len(outcomes) == 1:
        return identifier, message["case_id"]
    return None


def check_workspace(
    before: dict[str, Any], after: dict[str, Any], workflows: list[tuple[dict[str, Any], Observed]],
    *, workspace: UUID | None = None, cancelled_runs: frozenset[str] = frozenset(),
    undispatched_runs: frozenset[str] = frozenset(),
) -> list[str]:
    findings = []
    cases = {fixture["case_id"]: observed for fixture, observed in workflows}
    runs = {fixture["run_id"]: fixture for fixture, _ in workflows}
    expiry_messages = {}
    decisions = {
        decision_binding(row) for key, row in after["decisions"].items()
        if (before["decisions"].get(key) == row or row.get("run_id") in runs)
        and row["decision"] in {"approve", "reject"}
    }
    for table in ("decisions", "executions", "jobs", "messages", "consents"):
        old, new = before[table], after[table]
        changed = {key for key in old.keys() & new.keys() if old[key] != new[key]}
        if table == "jobs":
            for key in tuple(changed):
                job = old[key]
                if (job["kind"] != "run.review" or job["review_trigger"] != "expiry"
                        or job["run_id"] in undispatched_runs
                        or job["state"] not in {"queued", "leased"}):
                    continue
                binding = decision_binding(job)
                if binding in decisions and new[key] == {**job, "state": "done",
                                                         "last_error_code": "superseded_by_decision"}:
                    changed.remove(key)
                elif (workspace is not None and binding not in decisions and job["run_id"] not in runs
                      and new[key] == {**job, "state": "done", "last_error_code": "proposal_expired"}):
                    expiry = prior_expiry_message(workspace, key, job, before, after)
                    if expiry is not None:
                        identifier, case = expiry
                        expiry_messages[identifier] = (case, "agent")
                        changed.remove(key)
        if old.keys() - new.keys() or changed:
            findings.append(f"{table}_inventory_changed")
    for table, expected in (
        ("decisions", {identifier: case for case, row in cases.items() for identifier in row.decision_ids}),
        ("consents", {identifier: case for case, row in cases.items() for identifier in row.consents}),
        ("messages", expiry_messages | {
            identifier: (case, source)
            for case, row in cases.items()
            for identifier, source in (
                *((mid, "operator_entered_customer") for mid in row.messages),
                (row.projection_message_id if row.decision_ids else None, "agent"),
            )
            if identifier is not None
        }),
    ):
        observed = {
            key: (row["case_id"], row["source"]) if table == "messages" else row["case_id"]
            for key, row in after[table].items() if key not in before[table]
        }
        if observed != expected:
            findings.append(f"unexpected_{table}_inventory")
    new_executions = {
        key: row for key, row in after["executions"].items() if key not in before["executions"]
    }
    if Counter(row["case_id"] for row in new_executions.values()) != {
        case: len(row.executions) for case, row in cases.items() if row.executions
    }:
        findings.append("unexpected_executions_inventory")
    expected_jobs = Counter()
    optional_jobs = Counter()
    for fixture, row in workflows:
        for decision in row.decision_ids:
            expected_jobs[(fixture["run_id"], fixture["proposal_id"], fixture["proposal_version"],
                           "decision", decision, None)] += 1
    for identifier, row in new_executions.items():
        if row["case_id"] in cases:
            fixture = runs.get(row["run_id"])
            if fixture is not None:
                jobs = (
                    optional_jobs
                    if row["run_id"] in cancelled_runs and row["state"] in {"pending", "dispatched", "unknown"}
                    else expected_jobs
                )
                jobs[(row["run_id"], fixture["proposal_id"], fixture["proposal_version"],
                      "outcome", row["approval_id"], identifier)] += 1
    new_jobs = [row for key, row in after["jobs"].items() if key not in before["jobs"]]
    if (
        any(
            row["kind"] != "run.review" or (
                row["state"] != "done"
                and not (row["run_id"] in cancelled_runs and row["state"] in {"queued", "leased"})
            )
            for row in new_jobs
        )
        or not expected_jobs <= Counter(
            tuple(row[key] for key in (
                "run_id", "proposal_id", "proposal_version", "review_trigger", "decision_id", "execution_id",
            )) for row in new_jobs
        ) <= expected_jobs + optional_jobs
    ):
        findings.append("unexpected_jobs_inventory")
    return findings


def check_cancelled_case(fixture: dict[str, Any], write: dict[str, Any], observed: Observed) -> list[str]:
    """Check mutations and identifiers already observed when cancellation interrupted the workflow."""
    findings = []
    mode = fixture["control"]
    stale = mode in STALE
    if write.get("control") != mode or write.get("run_id") != fixture["run_id"]:
        findings.append("workflow_binding")
    if (
        len(observed.messages) > int(not stale) or len(observed.consents) > len(observed.messages)
        or (write.get("consent_status") == 201 and not observed.messages)
        or any(write.get(key) is not None and write[key] not in ids for key, ids in (
            ("message_id", observed.messages), ("consent_id", observed.consents),
        ))
    ):
        findings.append("message_accounting")
    if (
        len(observed.decision_ids) > int(not stale) or write["decisions"].count(201) > len(observed.decision_ids)
        or (write.get("approval_id") is not None and write["approval_id"] not in observed.decision_ids)
        or any(kind != ("reject" if mode == "reject" else "approve") for kind in observed.decision_kinds)
    ):
        findings.append("decision_accounting")
    if observed.message_audit != len(observed.messages) or observed.decision_audit != len(observed.decision_ids):
        findings.append("audit_accounting")
    approved = "approve" in observed.decision_kinds and not stale
    if len(observed.executions) > int(approved):
        findings.append("execution_count")
    for execution in observed.executions:
        if (execution.proposal_id, execution.version) != (fixture["proposal_id"], fixture["proposal_version"]):
            findings.append("execution_binding")
        if execution.state == "succeeded" and (
            execution.local_hash is None or execution.local_hash != execution.remote_hash
        ):
            findings.append("receipt_hash")
    if not fixture["simulator_version"] <= observed.simulator_version <= fixture["simulator_version"] + int(approved):
        findings.append("simulator_version" if approved else "refusal_effect")
    return findings


def check(app: Engine, auth: Engine, manifest: dict[str, Any], evidence: Iterable[dict[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    write_rows: dict[str, dict[str, Any]] = {}
    ends: dict[str, dict[str, Any]] = {}
    canaries: set[tuple[str, str, str]] = set()
    under_load: set[str] = set()
    stage, complete = {}, False
    abort_offset = None
    last_offset = 0.0
    workflow_slots = {}
    not_started = []
    not_dispatched = []
    cancelled = []
    fixtures = {fixture["case_id"]: fixture for fixture in manifest["writes"]}
    accepted_http: Counter[tuple[str, str]] = Counter()
    mutations = {"consent", "consent_replay", "decision", "decision_replay"}
    for row in evidence:
        kind = row["kind"]
        if row.get("correctness"):
            findings.append({"error": "client_correctness", "endpoint": row.get("endpoint", "stage"),
                             "detail": row.get("error", row.get("reason"))})
        if kind == "meta":
            stage = row["stage"]
            digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if row.get("manifest_sha256") != digest:
                findings.append({"error": "wrong_stage_manifest"})
        elif kind == "stage_start":
            last_offset = 0.0
        elif kind == "stage_end":
            complete = not row["aborted"]
            if row["aborted"] and row.get("abort_offset") is not None:
                abort_offset = row["abort_offset"]
        elif kind == "abort" and abort_offset is None:
            # Frozen evidence has no offset on abort rows. Use the preceding activity as a lower bound.
            abort_offset = row.get("offset", last_offset)
        elif kind == "slot" and row["endpoint"] == "workflow":
            workflow_slots[row["index"]] = row
        elif kind == "event":
            events[row["stream_id"]].append(row)
        elif kind == "stream_end":
            ends[row["stream_id"]] = row
        elif kind == "canary":
            if row["status"] != 404:
                findings.append({"error": "tenant_canary_visible", "endpoint": row["endpoint"]})
            else:
                canaries.add((row["workspace"], row["principal"], row["endpoint"]))
                if row["phase"] == "measured":
                    under_load.add(row["endpoint"])
        elif kind == "write":
            case = row["case_id"]
            if case not in fixtures or case in write_rows:
                findings.append({"error": "unexpected_workflow", "case_id": case})
            write_rows[case] = row
        elif kind == "http" and row["endpoint"] in mutations and row["status"] in (200, 201):
            accepted_http[row["case_id"], row["endpoint"]] += 1
        last_offset = max(last_offset, *(row.get(key) or 0.0 for key in ("done", "finished", "offset")))
    if complete and not stage.get("limiter") and under_load != {"case_detail", "stream"}:
        findings.append({"error": "missing_under_load_canary"})
    if not all(
        (workspace, user, route) in canaries
        for workspace in manifest["workspaces"]
        for user in manifest["principals"]
        for route in CANARIES
    ):
        findings.append({"error": "missing_tenant_canary"})
    with transaction(auth) as conn:
        if any(
            identity.active_roles(conn, UUID(principal), UUID(manifest["foreign"]))
            for principal in manifest["principals"].values()
        ):
            findings.append({"error": "foreign_membership"})
    accounting: dict[str, list[tuple[dict[str, Any], Observed]]] = defaultdict(list)
    cancelled_runs = set()
    undispatched_runs = set()
    workflow_streams = set()
    for index, (case, fixture) in enumerate(fixtures.items()):
        slot = workflow_slots.get(index, {})
        row = write_rows.get(case, {})
        error = slot.get("error")
        if not complete and not row and slot.get("sent") is None and error == "aborted":
            not_started.append({"case_id": case, "abort_offset": abort_offset})
            if any(accepted_http[case, route] for route in mutations):
                findings.append({"error": "unexpected_http_write", "case_id": case})
            continue
        observed = read_case(app, fixture)
        if slot.get("sent") is None and error in {"missed_slot", "overflow"}:
            not_dispatched.append({"index": index, "case_id": case, "reason": error})
            undispatched_runs.add(fixture["run_id"])
            if row or any(accepted_http[case, route] for route in mutations):
                findings.append({"error": "unexpected_http_write", "case_id": case})
            if (
                observed.messages or observed.consents or observed.decision_ids or observed.executions
                or observed.message_audit or observed.decision_audit or observed.stuck_jobs or observed.pending_outcomes
                or observed.projection_message_id is not None or observed.terminal_projection is not None
                or observed.simulator_version != fixture["simulator_version"]
            ):
                findings.append({"error": "undispatched_workflow_effect", "case_id": case})
            # Omit this fixture from the expected additions in the workspace inventory comparison.
            continue
        accounting[fixture["workspace_id"]].append((fixture, observed))
        if not row:
            findings.append({"error": "missing_workflow", "case_id": case})
        if fixture["control"] not in STALE:
            workflow_streams.add(fixture["run_id"])
        interrupted = not complete and slot.get("sent") is not None and (
            error == "cancelled_by_abort"
            or (error == "drain_deadline" and abort_offset is not None and slot["done"] >= abort_offset)
        )
        if interrupted:
            cancelled.append({"case_id": case, "abort_offset": abort_offset})
            cancelled_runs.add(fixture["run_id"])
        counts.update(
            {
                "messages": len(observed.messages),
                "consents": len(observed.consents),
                "decisions": len(observed.decision_ids),
                "executions": len(observed.executions),
                "consent_replays": int(row.get("consent_replay_status") == 201),
                "decision_replays": row.get("decisions", []).count(200),
            }
        )
        if row:
            check_observed = check_cancelled_case if interrupted else check_case
            findings.extend({"error": error, "case_id": case} for error in check_observed(fixture, row, observed))
        expected_http = {
            "consent": len(observed.messages),
            "decision": len(observed.decision_ids),
            "consent_replay": int(fixture["control"] == "replay"),
            "decision_replay": int(fixture["control"] == "replay"),
        }
        if any(
            accepted_http[case, route] > count if interrupted else accepted_http[case, route] != count
            for route, count in expected_http.items()
        ):
            findings.append({"error": "http_to_row_accounting", "case_id": case})
    if any(case not in fixtures for case, _route in accepted_http):
        findings.append({"error": "unexpected_http_write"})
    snapshots = {}
    snapshot_app = app.execution_options(isolation_level="REPEATABLE READ")
    for workspace in (manifest["demo"], manifest["second"], manifest["foreign"]):
        with workspace_transaction(snapshot_app, UUID(workspace)) as conn:
            after = workspace_accounting(conn)
            health = workspace_job_health(conn)
        snapshots[workspace] = after
        findings.extend({"error": error, "workspace": workspace, "count": count} for error, count in health.items()
                        if count)
        findings.extend(
            {"error": error, "workspace": workspace}
            for error in check_workspace(
                manifest["accounting"][workspace], after, accounting[workspace], workspace=UUID(workspace),
                cancelled_runs=frozenset(cancelled_runs),
                undispatched_runs=frozenset(undispatched_runs),
            )
        )

    holds = {f"hold-{index}" for index in range(stage.get("streams", 0))}
    allowed_streams = holds | workflow_streams
    required_streams = workflow_streams - cancelled_runs
    if complete:
        required_streams.update(holds)
    if not required_streams <= ends.keys() <= allowed_streams or not events.keys() <= ends.keys():
        findings.append({"error": "stream_inventory"})
    for key in allowed_streams & ends.keys():
        end = ends[key]
        workspace, run, case = (str(end[field]) for field in ("workspace", "run_id", "case_id"))
        inv = manifest["workspaces"].get(workspace, {})
        stream_owner = inv.get("runs", {}).get(run) == case and (
            run in inv.get("hold", []) if key.startswith("hold-") else key == run
        )
        if not stream_owner or any(
            (row["workspace"], row["run_id"], row["case_id"]) != (workspace, run, case) for row in events[key]
        ):
            findings.append({"error": "stream_scope", "stream_id": key})
            continue
        with workspace_transaction(app, UUID(workspace)) as conn:
            expected = [
                (seq, str(eid), payload)
                for seq, eid, payload in conn.execute(
                    text("SELECT sequence,id,payload FROM app.run_events WHERE run_id=:r ORDER BY sequence"),
                    {"r": UUID(run)},
                )
            ]
        interrupted = key in cancelled_runs or (not complete and key in holds)
        findings.extend(
            {"error": error, "stream_id": key}
            for error in check_stream(expected, events[key], end, interrupted=interrupted)
        )
        if any(
            not event_refs_owned(payload, snapshots[workspace], case, run, inv["proposals"])
            for _, _, payload in expected
        ):
            findings.append({"error": "stream_reference_scope", "stream_id": key})
        counts["stream_events"] += len(events[key])
    counts["successful_canaries"] = len(canaries)
    return {
        "ok": complete and not findings, "complete": complete, "abort_offset": abort_offset,
        "counts": dict(counts), "violations": findings, "not_started": not_started, "cancelled_by_abort": cancelled,
        "not_dispatched": not_dispatched,
    }


class Captured(Exception):
    def __init__(self, statement: str, parameters: Any) -> None:
        self.statement, self.parameters = statement, parameters


def explain_one(engine: Engine, connection: Connection, query: Callable[[], object], needle: str) -> Any:
    # Capture the repository's real bound SELECT before execution so its mapper never sees an EXPLAIN row.
    def capture(
        _conn: Connection,
        _cursor: DBAPICursor,
        statement: str,
        parameters: Any,
        _context: ExecutionContext | None,
        _executemany: bool,
    ) -> None:
        if needle in statement and statement.lstrip().upper().startswith("SELECT"):
            raise Captured(statement, parameters)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        query()
    except Captured as captured:
        source = captured
    else:
        raise ValueError("could not capture requested SELECT")
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    return connection.exec_driver_sql(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + source.statement, source.parameters
    ).scalar_one()


def explain(app: Engine, auth: Engine, manifest: dict[str, Any]) -> dict[str, Any]:
    demo_ws = UUID(manifest["demo"])
    data = manifest["workspaces"][str(demo_ws)]
    run_id = UUID(data["browse_runs"][0])
    case_id = UUID(data["runs"][str(run_id)])
    plans: dict[str, Any] = {}
    with workspace_transaction(app, demo_ws) as conn:
        run = runs.get_run(conn, run_id)
        if run is None:
            raise ValueError("no representative run")
        anchor = repo.case_page(conn, status=None, before=None, limit=26)[-1]
        before = anchor.created_at, anchor.id
        scope = CaseScope(workspace_id=demo_ws, case_id=case_id)
        now = datetime.now(UTC)
        plans["cases"] = explain_one(
            app, conn, lambda: repo.case_page(conn, status=None, before=before, limit=26), "FROM app.cases"
        )
        plans["cases_filtered"] = explain_one(
            app, conn, lambda: repo.case_page(conn, status="open", before=before, limit=26), "FROM app.cases"
        )
        plans["messages"] = explain_one(
            app, conn, lambda: repo.list_messages(conn, scope, limit=26), "FROM app.case_messages"
        )
        plans["events_after"] = explain_one(
            app, conn, lambda: runs.events_after(conn, run, 0, 100), "FROM app.run_events"
        )
        plans["inbox"] = explain_one(
            app, conn, lambda: repo.inbox_page(conn, now=now, after=None, limit=26), "FROM app.action_proposals"
        )
        plans["bindings"] = explain_one(app, conn, lambda: demo_bindings(app), "FROM app.runs r JOIN app.cases")
    with transaction(auth) as conn:
        cookie_digest = conn.execute(
            text(
                "SELECT cookie_sha256 FROM identity.sessions WHERE workspace_id=:w AND revoked_at IS NULL "
                "ORDER BY last_seen_at DESC LIMIT 1"
            ),
            {"w": demo_ws},
        ).scalar_one()
        principal = UUID(manifest["principals"]["bob"])
        plans["load_session"] = explain_one(
            auth, conn, lambda: identity.load_session(conn, cookie_digest), "FROM identity.sessions"
        )
        # PostgreSQL could print the lookup key in its index condition. Keep it out of evidence.
        plans["load_session"] = json.loads(json.dumps(plans["load_session"]).replace(cookie_digest, "[redacted]"))
        plans["active_roles"] = explain_one(
            auth, conn, lambda: identity.active_roles(conn, principal, demo_ws), "FROM identity.memberships"
        )
    return plans


def evidence_rows(stream: BinaryIO, update_digest: Callable[[bytes], None]) -> Iterable[dict[str, Any]]:
    for index, line in enumerate(stream):
        update_digest(line)
        decoded = line.decode("utf-8-sig" if index == 0 else "utf-8")
        if decoded.strip():
            yield json.loads(decoded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "explain"))
    parser.add_argument("--input", type=Path, help="Manifest on the first line, followed by raw JSONL for check")
    args = parser.parse_args()
    try:
        identity = load_config()
        with own_engine("policyops_app_runtime") as app, own_engine("policyops_auth_runtime") as auth:
            verify_identity(app, identity)
            verify_identity(auth, identity)
            source = args.input.open("rb") if args.input else nullcontext(sys.stdin.buffer)
            with source as stream:
                manifest = json.loads(stream.readline().decode("utf-8-sig"))
                require(
                    manifest.get("v") == 2 and manifest.get("load_run_id") == identity.run_id,
                    "manifest does not belong to this load volume",
                )
                if args.mode == "explain":
                    result = {"ok": True, "plans": explain(app, auth, manifest)}
                else:
                    digest = hashlib.sha256()
                    result = check(app, auth, manifest, evidence_rows(stream, digest.update))
                    result["raw_sha256"] = digest.hexdigest()
        print(json.dumps(result, separators=(",", ":")))
        return int(not result["ok"])
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error) if isinstance(error, SeedError) else type(error).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
