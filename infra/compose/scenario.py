"""Local fictional browser scenario, using runtime repositories and the authenticated real simulator.

Seed prepares/presents an address change; it never supplies consent, approval, execution or a receipt.
The browser supplies staff-entered customer consent (Alice) and independent staff approval (Bob).
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from typing import Any
from uuid import UUID, uuid4, uuid5

from runtime import SECRETS, browser_case_id, demo, own_engine
from sqlalchemy import text

from policyops.adapters.retail_client import RetailClient, Unknown
from policyops.gateway.facts import Collected, collect
from policyops.gateway.ports import load_scope
from policyops.persistence import customer_authentications, executions, runs
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import NewCase, Workspace
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.services.execution import LedgerHistory
from policyops.services.proposals import Created, Presented, ProposalService
from policyops_contracts.digest import text_sha256
from policyops_contracts.events import RunStateChanged
from policyops_contracts.retail import FindUserIdByEmail, GetUserDetails, ModifyUserAddress
from policyops_contracts.retail_service import FIXTURE_SHA256, Receipt, UserIdOutput, UserOutput
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication


class ScenarioError(RuntimeError):
    """An allowlisted scenario diagnostic, without third-party exception/connection text."""


def require(value: bool, label: str) -> None:
    if not value:
        raise ScenarioError(label)


def client(case_id: UUID) -> RetailClient:
    config = demo()
    return RetailClient(
        os.environ["POLICYOPS_RETAIL_ORIGIN"],
        (SECRETS / "retail_key").read_bytes(),
        tenant_id=UUID(config["workspace_id"]),
        case_id=case_id,
        customer_id=config["customer_id"],
        fixture_sha256=FIXTURE_SHA256,
    )


def receipt_sha(receipt: Receipt | None) -> str | None:
    return None if receipt is None else hashlib.sha256(receipt.model_dump_json().encode("utf-8")).hexdigest()


def foreign() -> dict[str, str]:
    workspace, case, now = uuid4(), uuid4(), datetime.now(UTC)
    with own_engine("policyops_auth_runtime") as auth, own_engine("policyops_app_runtime") as app:
        with transaction(auth) as conn:
            repo.create_workspace(
                conn,
                Workspace(
                    id=workspace, slug="foreign-" + workspace.hex, name="Unrelated fictional workspace", created_at=now
                ),
            )
        with workspace_transaction(app, workspace) as conn:
            repo.create_case(
                conn,
                NewCase(
                    id=case,
                    workspace_id=workspace,
                    scenario="retail",
                    customer_user_id=None,
                    created_by=None,
                    created_at=now,
                ),
            )
    return {"foreign_case_id": str(case)}


def seed() -> dict[str, Any]:
    config, now, run_id = demo(), datetime.now(UTC), uuid4()
    workspace, case = UUID(config["workspace_id"]), browser_case_id(run_id)
    scope = RunScope(workspace_id=workspace, case_id=case, run_id=run_id)
    binding = CaseCustomerBinding(
        scope=CaseScope(workspace_id=workspace, case_id=case),
        user_id=config["customer_id"],
        seed_id=config["seed_id"],
        bound_at=now,
    )
    with own_engine("policyops_app_runtime") as app, closing(client(case)) as retail:
        initialized = retail.initialize()
        require(not isinstance(initialized, Unknown), "simulator initialization failed")
        user = retail.read(GetUserDetails(user_id=config["customer_id"]))
        require(not isinstance(user, Unknown) and isinstance(user.output, UserOutput), "customer read failed")
        if isinstance(user, Unknown) or not isinstance(user.output, UserOutput):
            raise ScenarioError("customer read failed")
        lookup = FindUserIdByEmail(email=user.output.user.email)
        authenticated = retail.read(lookup)
        require(
            not isinstance(authenticated, Unknown)
            and isinstance(authenticated.output, UserIdOutput)
            and authenticated.output.user_id == config["customer_id"],
            "customer lookup failed",
        )
        with workspace_transaction(app, workspace) as conn:
            repo.create_case(conn, NewCase(id=case, workspace_id=workspace, scenario="retail",
                customer_user_id=config["customer_id"], created_by=uuid5(workspace, "alice"), created_at=now))
            record = repo.lock_case(conn, case)
            require(record is not None, "seeded case absent")
            if record is None:
                raise ScenarioError("seeded case absent")
            run = runs.create_run(
                conn,
                run_id=run_id,
                workspace_id=workspace,
                case_id=case,
                case_version=record.version,
                graph_sha256=text_sha256("compose deterministic scenario v1"),
                prompt_sha256=text_sha256("no model"),
                config_sha256=text_sha256("t38-browser-v1"),
                initiated_by=uuid5(workspace, "alice"),
                deadline_at=now + timedelta(hours=1),
                now=now,
            )
            customer_authentications.record(
                conn,
                CustomerAuthentication(
                    scope=scope,
                    user_id=config["customer_id"],
                    lookup_tool="find_user_id_by_email",
                    lookup_call_sha256=text_sha256(lookup.model_dump_json()),
                    step_sequence=1,
                    authenticated_at=now,
                ),
            )
            waiting = runs.set_state(conn, run, "waiting_approval", now)
            runs.append_event(conn, waiting, RunStateChanged(previous="queued", current="waiting_approval"), now)
        gateway = load_scope(app, workspace_id=workspace, run_id=run_id, binding=binding, fixture_sha256=FIXTURE_SHA256)
        call = ModifyUserAddress(
            user_id=config["customer_id"],
            address1="38 Fictional Lane " + run_id.hex[:8],
            address2="",
            city="Seattle",
            state="WA",
            country="USA",
            zip="98101",
        )
        facts = collect(retail, gateway, call, LedgerHistory(app, scope))
        if not isinstance(facts, Collected):
            raise ScenarioError("gateway facts unavailable")
        proposals = ProposalService(app_engine=app, clock=DatabaseLeaseClock())
        made = proposals.create(gateway, call, facts, rationale="Fictional customer requested this address change.")
        if not isinstance(made, Created):
            raise ScenarioError("proposal creation refused")
        proposal = made.proposal
        shown = proposals.present(scope, proposal.proposal_id, proposal.proposal_version)
        require(isinstance(shown, Presented), "proposal presentation refused")
        return {
            "case_id": str(case),
            "run_id": str(run_id),
            "proposal_id": str(proposal.proposal_id),
            "proposal_version": proposal.proposal_version,
            "action_digest": proposal.action_digest,
            "case_version_before": user.case_version,
        }


def inspect(case_id: UUID) -> dict[str, Any]:
    config = demo()
    workspace = UUID(config["workspace_id"])
    with own_engine("policyops_app_runtime") as app, closing(client(case_id)) as retail:
        with workspace_transaction(app, workspace) as conn:
            ids = (
                conn.execute(
                    text("SELECT id FROM app.tool_executions WHERE case_id=:c ORDER BY created_at,id"),
                    {"c": case_id},
                )
                .scalars()
                .all()
            )
            rows = [executions.get(conn, identifier) for identifier in ids]
        result = []
        for row in rows:
            if row is None:
                raise ScenarioError("execution absent")
            remote = retail.lookup(row.operation_id, row.request)
            if isinstance(remote, Unknown):
                raise ScenarioError("receipt lookup unavailable")
            receipt = None if remote.result is None else remote.result.receipt
            result.append(
                {
                    "execution_id": str(row.id),
                    "run_id": str(row.run_id),
                    "operation_id": str(row.operation_id),
                    "state": row.state,
                    "attempts": row.attempts,
                    "resolved_by": row.resolved_by,
                    "receipt_sha256": receipt_sha(row.receipt),
                    "remote_receipt_sha256": receipt_sha(receipt),
                    "remote_outcome": None if remote.result is None else remote.result.outcome,
                }
            )
        read = retail.read(GetUserDetails(user_id=config["customer_id"]))
        if isinstance(read, Unknown):
            raise ScenarioError("case version unavailable")
        with workspace_transaction(app, workspace) as conn:
            pending = conn.execute(
                text(
                    "SELECT count(*) FROM app.jobs WHERE state IN ('queued','leased') "
                    "AND kind='run.review' AND review_trigger='outcome' AND run_id IN "
                    "(SELECT id FROM app.runs WHERE case_id=:c)"
                ),
                {"c": case_id},
            ).scalar_one()
        return {"executions": result, "case_version": read.case_version, "pending_outcomes": pending}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("seed", "foreign", "inspect"))
    parser.add_argument("--case-id", type=UUID)
    args = parser.parse_args()
    try:
        require(os.environ.get("POLICYOPS_ENV") == "local", "scenario is local only")
        if args.mode == "inspect":
            require(args.case_id is not None, "inspect requires an explicit scenario case")
            result = inspect(args.case_id)
        else:
            result = {"seed": seed, "foreign": foreign}[args.mode]()
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"mode": args.mode, "error_type": type(error).__name__,
                          "detail": str(error) if isinstance(error, ScenarioError) else "details omitted"}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
