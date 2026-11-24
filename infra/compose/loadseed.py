"""Seed fictional N10 rows through the runtime roles. Run as a module in the overlay worker."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime, timedelta
import json
import os
import random
import re
import sys
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import Connection, Engine, text

from infra.compose.load_identity import (
    LoadIdentity,
    SeedError,
    initialize,
    load_config,
    require,
    verify_identity,
    wave_admission,
)
from infra.compose.runtime import SECRETS, browser_case_id, demo, own_engine
from policyops.adapters.retail_client import RetailClient, Unknown
from policyops.domain.retail_rules import RetailFacts, propose
from policyops.domain.session import CustomerSession
from policyops.persistence import customer_authentications, runs
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, NewCase, Workspace
from policyops.runtime.clock import DatabaseLeaseClock, FixedLeaseClock
from policyops.services.proposals import Presented, ProposalService
from policyops_contracts.clock import FixedClock
from policyops_contracts.digest import text_sha256
from policyops_contracts.events import RunStateChanged
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import FindUserIdByEmail, GetUserDetails, ModifyUserAddress
from policyops_contracts.retail_service import FIXTURE_SHA256, UserIdOutput, UserOutput
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication


NAMESPACE = UUID("a0ea212d-2d9a-493a-bd22-8030f623a23d")
HISTORY = datetime(2026, 11, 2, tzinfo=UTC)
MAX_WRITE_RUNS = 900


def scoped_id(seed: int, name: str) -> UUID:
    return uuid5(NAMESPACE, f"{seed}:{name}")


def workspaces(seed: int) -> tuple[UUID, UUID, UUID]:
    return UUID(demo()["workspace_id"]), scoped_id(seed, "second"), scoped_id(seed, "foreign")


def retail_client(workspace: UUID, case: UUID) -> RetailClient:
    return RetailClient(
        os.environ["POLICYOPS_RETAIL_ORIGIN"],
        (SECRETS / "retail_key").read_bytes(),
        tenant_id=workspace,
        case_id=case,
        customer_id=demo()["customer_id"],
        fixture_sha256=FIXTURE_SHA256,
    )


def fixture(workspace: UUID, case: UUID) -> tuple[RetailFacts, int, str]:
    customer = demo()["customer_id"]
    with closing(retail_client(workspace, case)) as retail:
        if isinstance(retail.initialize(), Unknown):
            raise SeedError("simulator initialization failed")
        result = retail.read(GetUserDetails(user_id=customer))
        if isinstance(result, Unknown) or not isinstance(result.output, UserOutput):
            raise SeedError("fixture read failed")
        lookup_call = FindUserIdByEmail(email=result.output.user.email)
        lookup = retail.read(lookup_call)
        if (
            isinstance(lookup, Unknown)
            or not isinstance(lookup.output, UserIdOutput)
            or (lookup.output.user_id != customer)
        ):
            raise SeedError("fixture lookup failed")
        return (
            RetailFacts(customer=result.output.user.to_snapshot()),
            result.case_version,
            text_sha256(lookup_call.model_dump_json()),
        )


def membership(auth: Engine, default: UUID, second: UUID, foreign: UUID, now: datetime) -> None:
    with transaction(auth) as conn:
        exists = conn.execute(
            text("SELECT count(*) FROM identity.workspaces WHERE id IN (:s,:f)"), {"s": second, "f": foreign}
        ).scalar_one()
        require(exists == 0, "base seed already exists, use a fresh load volume")
        for workspace, label in ((second, "second"), (foreign, "foreign")):
            repo.create_workspace(
                conn, Workspace(id=workspace, slug=f"n10-{label}", name=f"N10 fictional {label}", created_at=now)
            )
        for user in demo()["users"]:
            principal = uuid5(default, user["name"])
            repo.add_membership(
                conn,
                Membership(
                    id=uuid5(second, user["name"]),
                    workspace_id=second,
                    principal_id=principal,
                    role=user["role"],
                    created_at=now,
                ),
            )


def waiting_run(
    conn: Connection, scope: RunScope, version: int, initiator: UUID, now: datetime, *, approval: bool
) -> None:
    run = runs.create_run(
        conn,
        run_id=scope.run_id,
        workspace_id=scope.workspace_id,
        case_id=scope.case_id,
        case_version=version,
        graph_sha256=text_sha256("n10 deterministic fixture"),
        prompt_sha256=text_sha256("no model"),
        config_sha256=text_sha256("n10-retail-v1"),
        initiated_by=initiator,
        deadline_at=now + timedelta(hours=1),
        now=now,
    )
    state: runs.RunState = "waiting_approval" if approval else "waiting_input"
    waiting = runs.set_state(conn, run, state, now)
    runs.append_event(conn, waiting, RunStateChanged(previous="queued", current=state), now)


def seal(
    conn: Connection,
    scope: RunScope,
    facts: RetailFacts,
    lookup_sha: str,
    created: datetime,
    *,
    version: int = 1,
    record_auth: bool = False,
) -> ActionProposal:
    config = demo()
    user = config["customer_id"]
    authentication = CustomerAuthentication(
        scope=scope,
        user_id=user,
        lookup_tool="find_user_id_by_email",
        lookup_call_sha256=lookup_sha,
        step_sequence=1,
        authenticated_at=created,
    )
    if record_auth:
        customer_authentications.record(conn, authentication)
    binding = CaseCustomerBinding(
        scope=CaseScope(workspace_id=scope.workspace_id, case_id=scope.case_id),
        user_id=user,
        seed_id=config["seed_id"],
        bound_at=created,
    )
    session = CustomerSession(binding=binding, run=scope, authentication=authentication)
    call = ModifyUserAddress(
        user_id=user,
        address1=f"38 Fictional Lane {scope.run_id.hex[:8]}",
        address2="",
        city="Seattle",
        state="WA",
        country="USA",
        zip="98101",
    )
    result = propose(
        proposal_id=uuid5(scope.run_id, "n10-proposal"),
        proposal_version=version,
        session=session,
        call=call,
        facts=facts,
        evidence=(),
        rationale="Fictional customer requested an address change.",
        now=created,
    )
    if not isinstance(result, ActionProposal):
        raise SeedError("fixture proposal could not be sealed")
    repo.insert_proposal(conn, uuid5(result.proposal_id, str(version)), result)
    return result


def seed_history(
    app: Engine, workspace: UUID, seed: int, count: int, facts: RetailFacts, lookup_sha: str, *, foreign: bool = False
) -> None:
    rng = random.Random(seed ^ workspace.int)  # noqa: S311 - reproducible fictional history
    config = demo()
    initiator = uuid5(UUID(config["workspace_id"]), "alice")
    # Transaction chunks bound lock retention and make the workload reasonably quick on small devices.
    for begin in range(0, count, 100):
        with workspace_transaction(app, workspace) as conn:
            for index in range(begin, min(begin + 100, count)):
                case = uuid5(workspace, f"n10-browse:{index}")
                now = HISTORY + timedelta(seconds=index)
                record = repo.create_case(
                    conn,
                    NewCase(
                        id=case,
                        workspace_id=workspace,
                        scenario="retail",
                        customer_user_id=config["customer_id"],
                        created_by=None,
                        created_at=now,
                    ),
                )
                for number in range(rng.randint(1, 20)):
                    repo.append_message(
                        conn,
                        message_id=uuid5(case, f"n10-message:{number}"),
                        scope=CaseScope(workspace_id=workspace, case_id=case),
                        source="seeded",
                        entered_by=None,
                        text_value=f"Fictional retail address inquiry {index + 1}, message {number + 1}.",
                        created_at=now,
                    )
                if index >= 100 and index % 3 == 0:
                    repo.set_case_status(conn, case, expected_version=record.version, status="resolved", now=now)
                if index < 100 or foreign:
                    run = uuid5(case, "n10-browse-run")
                    scope = RunScope(workspace_id=workspace, case_id=case, run_id=run)
                    waiting_run(conn, scope, record.version, initiator, now, approval=False)
                    proposal = seal(conn, scope, facts, lookup_sha, now)
                    repo.set_proposal_status(conn, workspace, proposal.proposal_id, 1, "expired")


def controls(count: int, warm_slots: int, seed: int, wave: str, *, sanity: bool) -> list[str]:
    labels = ["approve"] * count
    if sanity:
        return labels
    order = list(range(warm_slots, count))
    if len(order) < 6:
        raise SeedError("a write wave needs at least six measured workflows for the controls")
    random.Random(f"{seed}:{wave}:controls").shuffle(order)  # noqa: S311 - reproducible control allocation
    plans = (
        ["race"] * max(1, round(count * 0.10))
        + ["replay"] * max(1, round(count * 0.05))
        + ["expired", "superseded", "unconsented", "reject"]
    )
    require(len(plans) <= len(order), "write controls exceed the measured cohort")
    for index, label in zip(order[: len(plans)], plans, strict=True):
        labels[index] = label
    return labels


def seed_wave(app: Engine, workspace: UUID, seed: int, name: str, labels: Sequence[str]) -> list[dict[str, Any]]:
    config = demo()
    analyst = uuid5(workspace, "alice")
    with workspace_transaction(app, workspace) as conn:
        existing = conn.execute(
            text(
                "SELECT count(*) FROM app.runs r JOIN app.cases c ON c.id=r.case_id AND c.workspace_id=r.workspace_id "
                "WHERE c.workspace_id=:w AND c.scenario='retail' AND c.customer_user_id=:u AND c.created_by=:p"
            ),
            {"w": workspace, "u": config["customer_id"], "p": analyst},
        ).scalar_one()
    require(existing + len(labels) <= MAX_WRITE_RUNS, "write binding limit requires a fresh volume")
    service = ProposalService(app_engine=app, clock=DatabaseLeaseClock())
    result = []
    for index, label in enumerate(labels):
        run = scoped_id(seed, f"wave:{name}:{index}")
        case = browser_case_id(run)
        scope = RunScope(workspace_id=workspace, case_id=case, run_id=run)
        facts, simulator_version, lookup_sha = fixture(workspace, case)
        with workspace_transaction(app, workspace) as conn:
            now = service.clock.now(conn)
            created = now - timedelta(minutes=16) if label == "expired" else now
            record = repo.create_case(
                conn,
                NewCase(
                    id=case,
                    workspace_id=workspace,
                    scenario="retail",
                    customer_user_id=config["customer_id"],
                    created_by=analyst,
                    created_at=created,
                ),
            )
            waiting_run(conn, scope, record.version, analyst, created, approval=True)
            proposal = seal(conn, scope, facts, lookup_sha, created, record_auth=True)
            presentation = None
            if label == "superseded":
                repo.set_proposal_status(conn, workspace, proposal.proposal_id, 1, "superseded")
                seal(conn, scope, facts, lookup_sha, now, version=2)
            else:
                presenter = (
                    ProposalService(app_engine=app, clock=FixedLeaseClock(FixedClock(created)))
                    if label == "expired" else service
                )
                shown = presenter._present_tx(conn, scope, proposal.proposal_id, proposal.proposal_version)
                if not isinstance(shown, Presented):
                    raise SeedError("fixture proposal could not be presented")
                presentation = str(shown.message.message_id)
                if label == "expired":
                    # Keep the worker's expiry projection out of the control window. The proposal's own
                    # sealed timestamp remains elapsed, and the persisted proposal remains presented.
                    conn.execute(
                        text("UPDATE app.jobs SET available_at=:later WHERE run_id=:r AND review_trigger='expiry'"),
                        {"later": now + timedelta(hours=1), "r": run},
                    )
            persisted_case = repo.get_case(conn, case)
            if persisted_case is None:
                raise SeedError("fixture case is absent")
        result.append(
            {
                "workspace_id": str(workspace),
                "case_id": str(case),
                "run_id": str(run),
                "proposal_id": str(proposal.proposal_id),
                "proposal_version": proposal.proposal_version,
                "action_digest": proposal.action_digest,
                "expires_at": proposal.expires_at.isoformat(),
                "control": label,
                "case_version": persisted_case.version,
                "simulator_version": simulator_version,
                "presentation_message_id": presentation,
            }
        )
    return result


def workspace_accounting(conn: Connection) -> dict[str, dict[str, dict[str, Any]]]:
    selects = {
        # A decision is the persisted approval record for either choice.
        "decisions": "SELECT id, case_id, run_id, proposal_id, proposal_version, decision FROM app.approval_decisions",
        "executions": "SELECT id, case_id, run_id, approval_id, operation_id, state FROM app.tool_executions",
        "jobs": "SELECT id, run_id, state, kind, review_trigger, proposal_id, proposal_version, "
        "decision_id, execution_id, last_error_code FROM app.jobs",
        "messages": "SELECT id, case_id, source, entered_by, sequence, text_sha256 FROM app.case_messages",
        "consents": "SELECT id, case_id, run_id, proposal_id, proposal_version FROM app.customer_consents",
        "expiry_outcomes": (
            "SELECT e.id, e.run_id, r.case_id, e.payload FROM app.run_events e "
            "JOIN app.runs r ON r.id=e.run_id "
            "JOIN app.action_proposals p ON p.run_id=r.id AND p.case_id=r.case_id "
            "AND p.proposal_id::text=e.payload->>'proposal_id' "
            "AND p.proposal_version::text=e.payload->>'proposal_version' "
            "WHERE e.event_type='review.outcome' AND e.payload->>'reason'='proposal_expired' "
            "AND r.state='failed' AND p.status='expired'"
        ),
    }
    result = {}
    for name, query in selects.items():
        result[name] = {
            str(row["id"]): {key: str(value) if isinstance(value, UUID) else value
                             for key, value in row.items() if key != "id"}
            for row in conn.execute(text(query)).mappings()
        }
    return result


def inventory(app: Engine, workspace: UUID) -> dict[str, Any]:
    with workspace_transaction(app.execution_options(isolation_level="REPEATABLE READ"), workspace) as conn:
        case_rows = conn.execute(text(
            "SELECT id,created_by,status,version,scenario,customer_user_id "
            "FROM app.cases ORDER BY created_at DESC,id DESC"
        )).all()
        case_ids = sorted(str(row.id) for row in case_rows)
        default_case = UUID(demo()["case_id"])
        browse = sorted(str(row.id) for row in case_rows if row.created_by is None and row.id != default_case)
        browse_set = set(browse)
        run_rows = conn.execute(text("SELECT id,case_id,state,initiated_by FROM app.runs ORDER BY id")).all()
        run_ids = {str(row.id): str(row.case_id) for row in run_rows}
        browse_runs = [run for run, case in run_ids.items() if case in browse_set]
        hold = [str(row.id) for row in run_rows if row.state == "waiting_input" and str(row.case_id) in browse_set]
        props = conn.execute(
            text(
                "SELECT proposal_id,proposal_version,case_id,run_id,action_digest,status,body "
                "FROM app.action_proposals ORDER BY proposal_id,proposal_version"
            )
        ).all()
        proposals = [
            {
                "workspace_id": str(workspace),
                "case_id": str(row.case_id),
                "run_id": str(row.run_id),
                "proposal_id": str(row.proposal_id),
                "proposal_version": row.proposal_version,
                "action_digest": row.action_digest,
            }
            for row in props
        ]
        event_rows = conn.execute(text(
            "SELECT id,run_id,sequence,payload FROM app.run_events ORDER BY run_id,sequence"
        )).all()
        events = {str(row.id): str(row.run_id) for row in event_rows}
        event_digests = {
            str(row.id): text_sha256(json.dumps(row.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
            for row in event_rows
        }
        accounting = workspace_accounting(conn)
    # Normalize generated event/message identifiers and wave timestamps, keeping content and ordering.
    logical = {
        "cases": [
            (str(row.id), row.status, row.version, row.scenario, row.customer_user_id,
             str(row.created_by) if row.created_by else None)
            for row in case_rows
        ],
        "messages": sorted(
            (row["case_id"], row["sequence"], row["source"], row["entered_by"] or "", row["text_sha256"])
            for row in accounting["messages"].values()
        ),
        "runs": {str(row.id): row.state for row in run_rows},
        "proposals": [
            (row.status, {key: value for key, value in row.body.items()
                          if key not in {"created_at", "expires_at", "action_digest"}})
            for row in props
        ],
        "consents": sorted(
            (row["case_id"], row["run_id"], row["proposal_id"], row["proposal_version"])
            for row in accounting["consents"].values()
        ),
        "decisions": sorted(
            (row["case_id"], row["run_id"], row["proposal_id"], row["proposal_version"], row["decision"])
            for row in accounting["decisions"].values()
        ),
        "events": [
            (str(row.run_id), row.sequence, {
                key: value for key, value in row.payload.items()
                if key not in {"message_id", "correlation_id", "expires_at", "action_digest"}
            })
            for row in event_rows
        ],
    }
    browse_proposals = [prop for prop in proposals if prop["case_id"] in browse_set]
    return {
        "cases": case_ids,
        "browse": browse,
        "runs": run_ids,
        "run_principals": {str(row.id): str(row.initiated_by) if row.initiated_by else None for row in run_rows},
        "browse_runs": browse_runs,
        "hold": hold,
        "proposals": proposals,
        "browse_proposals": browse_proposals,
        "proposal_cases": sorted({prop["case_id"] for prop in browse_proposals}),
        "messages": {mid: row["case_id"] for mid, row in accounting["messages"].items()},
        "events": events,
        "event_digests": event_digests,
        "dataset": text_sha256(json.dumps(logical, sort_keys=True, separators=(",", ":"))),
        "accounting": accounting,
    }


def manifest(app: Engine, seed: int, writes: list[dict[str, Any]], *, run_id: str) -> dict[str, Any]:
    default, second, foreign = workspaces(seed)
    inventories = {str(ws): inventory(app, ws) for ws in (default, second, foreign)}
    canary = inventories[str(foreign)]["proposals"]
    hidden = inventories[str(foreign)]
    require(len(canary) == 1, "foreign canary fixture missing")
    counts = {
        ws: {table: len(inv[table]) for table in ("cases", "messages", "runs", "proposals", "events")}
        for ws, inv in inventories.items()
    }
    accounting = {ws: snapshot.pop("accounting") for ws, snapshot in inventories.items()}
    visible = {str(ws): inventories[str(ws)] for ws in (default, second)}
    require(
        all(inv["browse"] and inv["browse_runs"] and inv["browse_proposals"] for inv in visible.values()),
        "base browse seed is missing",
    )
    return {
        "v": 2,
        "load_run_id": run_id,
        "seed": seed,
        "demo": str(default),
        "second": str(second),
        "foreign": str(foreign),
        "principals": {user["name"]: str(uuid5(default, user["name"])) for user in demo()["users"]},
        "customer_user_id": demo()["customer_id"],
        "workspaces": visible,
        "accounting": accounting,
        "canary": canary[0],
        "foreign_dataset": hidden["dataset"],
        "foreign_ids": sorted(set(hidden["messages"]) | set(hidden["events"])),
        "counts": counts,
        "writes": writes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("init", "base", "wave"))
    parser.add_argument("--seed", type=int)
    parser.add_argument("--cases", type=int, default=2000)
    parser.add_argument("--name")
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--warm-slots", type=int, default=0)
    parser.add_argument("--sanity", action="store_true")
    args = parser.parse_args()
    try:
        identity = load_config()
        if args.mode == "init":
            with own_engine("postgres") as postgres, postgres.begin() as conn:
                initialize(conn, identity)
            print("Disposable database enrolled.")
            return 0
        if args.seed is None:
            raise SeedError("base and wave require --seed")
        with own_engine("policyops_app_runtime") as app:
            verify_identity(app, identity)
            with wave_admission(app):
                result = seed_manifest(app, args, identity)
            print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as error:
        print(str(error) if isinstance(error, SeedError) else type(error).__name__, file=sys.stderr)
        return 1


def seed_manifest(app: Engine, args: argparse.Namespace, identity: LoadIdentity) -> dict[str, Any]:
    default, second, foreign = workspaces(args.seed)
    if args.mode == "base":
        require(1 <= args.cases <= 2000, "case count must be between 1 and 2000")
        with own_engine("policyops_auth_runtime") as auth:
            verify_identity(auth, identity)
            membership(auth, default, second, foreign, datetime.now(UTC))
        facts, _, lookup_sha = fixture(default, UUID(demo()["case_id"]))
        for workspace in (default, second, foreign):
            seed_history(app, workspace, args.seed, 1 if workspace == foreign else args.cases,
                         facts, lookup_sha, foreign=workspace == foreign)
        writes = []
    else:
        require(
            bool(args.name and re.fullmatch(r"[a-z0-9-]+", args.name))
            and 0 <= args.warm_slots < args.count <= MAX_WRITE_RUNS,
            "invalid write wave bounds",
        )
        labels = controls(args.count, args.warm_slots, args.seed, args.name, sanity=args.sanity)
        writes = seed_wave(app, default, args.seed, args.name, labels)
    return manifest(app, args.seed, writes, run_id=identity.run_id)


if __name__ == "__main__":
    raise SystemExit(main())
