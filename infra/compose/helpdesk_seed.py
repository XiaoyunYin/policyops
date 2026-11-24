"""Provision a disposable Zammad fixture and prepare a scripted proposal for its imported case."""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4, uuid5

import httpx
from runtime import demo, helpdesk_settings, own_engine
from scenario import client, require
from sqlalchemy import text

from policyops.adapters.retail_client import Unknown
from policyops.gateway.facts import Collected, collect
from policyops.persistence import customer_authentications, runs
from policyops.persistence import helpdesk as store
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.runtime.review import BoundScopes
from policyops.services.execution import LedgerHistory
from policyops.services.proposals import Created, Presented, ProposalService
from policyops.settings import HelpdeskSettings
from policyops_contracts.digest import text_sha256
from policyops_contracts.retail import FindUserIdByEmail, GetUserDetails, ModifyUserAddress
from policyops_contracts.retail_service import FIXTURE_SHA256, UserIdOutput, UserOutput
from policyops_contracts.scalars import RunScope
from policyops_contracts.seeds import CustomerAuthentication


class SeedError(RuntimeError):
    """Sanitized diagnostic for a disposable fixture operation."""


def admin(origin: str, token_file: Path) -> httpx.Client:
    url = urlsplit(origin)
    if (url.scheme not in {"http", "https"} or url.hostname not in {"127.0.0.1", "::1"}
            or url.port is None or origin != f"{url.scheme}://{url.netloc}" or url.username is not None):
        raise SeedError("admin origin must be a loopback origin with an explicit port")
    with token_file.open("r", encoding="ascii") as handle:
        token = handle.read(257).strip()
    if not 24 <= len(token) <= 256:
        raise SeedError("invalid admin token file")
    return httpx.Client(base_url=origin, follow_redirects=False, trust_env=False, timeout=5,
                        headers={"Authorization": f"Token token={token}"})


def create(zammad: httpx.Client, resource: str, body: dict[str, Any]) -> int:
    result = zammad.post(f"/api/v1/{resource}", json=body)
    if not result.is_success:
        raise SeedError(f"{resource} create returned HTTP {result.status_code}")
    identity = result.json()["id"]
    if type(identity) is not int or not 1 <= identity < 2**53:
        raise SeedError(f"{resource} create returned an invalid ID")
    return identity


def provision(zammad: httpx.Client) -> dict[str, Any]:
    # Fresh instance only. On partial failure inspect created objects by name before attempting recovery.
    roles = zammad.get("/api/v1/roles")
    roles.raise_for_status()
    by_name = {role["name"]: role["id"] for role in roles.json()}
    allowed = create(zammad, "groups", {"name": "PolicyOps N11", "active": True})
    denied = create(zammad, "groups", {"name": "PolicyOps N11 quarantine", "active": True})
    agent = create(zammad, "users", {
        "firstname": "PolicyOps", "lastname": "Integration", "login": "policyops-n11",
        "email": "policyops-n11@example.invalid", "active": True, "role_ids": [by_name["Agent"]],
        "group_ids": {str(allowed): ["full"], str(denied): ["read"]},
    })
    customer = create(zammad, "users", {
        "firstname": "Fictional", "lastname": "Customer", "login": "customer-n11",
        "email": "customer-n11@example.invalid", "active": True, "role_ids": [by_name["Customer"]],
    })
    return {"group_id": allowed, "disallowed_group_id": denied, "integration_user_id": agent,
            "requester_id": customer, "customer_user_id": demo()["customer_id"]}


def wire(zammad: httpx.Client, settings_file: Path, connection_id: str, port: int) -> dict[str, int]:
    config = HelpdeskSettings.from_secret_file(settings_file).connection(connection_id)
    if config is None or not 1 <= port <= 65535:
        raise SeedError("invalid connection or receiver port")
    # Management JSON is a smoke assumption. The admin UI has equivalent options.
    webhook_id = create(zammad, "webhooks", {
        "name": f"PolicyOps {connection_id}", "active": True, "ssl_verify": True,
        "endpoint": f"http://policyops-helpdesk:{port}/api/v1/integrations/zammad/{connection_id}/events",
        "signature_token": config.signing_secret.get_secret_value(), "custom_payload": True,
        "payload": '{"ticket_id":#{ticket.id},"updated_at":"#{ticket.updated_at}"}',
    })
    trigger = create(zammad, "triggers", {
        "name": f"PolicyOps {connection_id}", "active": True, "condition": {},
        "perform": {"notification.webhook": {"webhook_id": webhook_id}}, "execution": "always",
    })
    return {"webhook_id": webhook_id, "trigger_id": trigger}


def binding(connection_id: str, requester_id: int) -> dict[str, int]:
    fixture = demo()
    workspace = local_workspace(connection_id)
    if workspace != UUID(fixture["workspace_id"]):
        raise SeedError("binding requires the local fixture workspace")
    with own_engine("policyops_app_runtime") as app, workspace_transaction(app, workspace) as connection:
        store.seed_binding(connection, workspace=workspace, connection_id=connection_id, requester_id=requester_id,
                           customer=fixture["customer_id"], seed_id=fixture["seed_id"],
                           now=DatabaseLeaseClock().now(connection))
    return {"requester_id": requester_id}


def local_workspace(connection_id: str) -> UUID:
    settings = helpdesk_settings()
    endpoint = None if settings is None else settings.connection(connection_id)
    if endpoint is None:
        raise SeedError("no such local connection")
    return endpoint.workspace_id


def prepare(case_id: UUID) -> dict[str, str]:
    fixture = demo()
    workspace, run_id = UUID(fixture["workspace_id"]), uuid4()
    scope = RunScope(workspace_id=workspace, case_id=case_id, run_id=run_id)
    clock = DatabaseLeaseClock()
    if helpdesk_settings() is None:
        raise SeedError("preparation requires the local help desk overlay")
    with own_engine("policyops_app_runtime") as app, closing(client(case_id)) as retail:
        with workspace_transaction(app, workspace) as connection:
            link = store.case_link(connection, case_id)
            if link is None or link.customer_user_id != fixture["customer_id"]:
                raise SeedError("case does not belong to the local help desk fixture")
        require(not isinstance(retail.initialize(), Unknown), "simulator initialization failed")
        user = retail.read(GetUserDetails(user_id=fixture["customer_id"]))
        if isinstance(user, Unknown) or not isinstance(user.output, UserOutput):
            raise SeedError("simulator user unavailable")
        lookup = FindUserIdByEmail(email=user.output.user.email)
        authenticated = retail.read(lookup)
        if (isinstance(authenticated, Unknown) or not isinstance(authenticated.output, UserIdOutput)
                or authenticated.output.user_id != fixture["customer_id"]):
            raise SeedError("simulator authentication failed")
        with workspace_transaction(app, workspace) as connection:
            case = repo.lock_case(connection, case_id)
            if case is None:
                raise SeedError("imported case is missing")
            now = clock.now(connection)
            run = runs.create_run(connection, run_id=run_id, workspace_id=workspace, case_id=case_id,
                case_version=case.version, graph_sha256=text_sha256("compose scripted scenario"),
                prompt_sha256=text_sha256("no model"), config_sha256=text_sha256("helpdesk-smoke-v1"),
                initiated_by=uuid5(workspace, "alice"), deadline_at=now + timedelta(hours=1), now=now)
            customer_authentications.record(connection, CustomerAuthentication(scope=scope,
                user_id=fixture["customer_id"], lookup_tool="find_user_id_by_email",
                lookup_call_sha256=text_sha256(lookup.model_dump_json()), step_sequence=1, authenticated_at=now))
            runs.set_state(connection, run, "waiting_approval", now)
        gateway = BoundScopes(app, (), FIXTURE_SHA256).scope(scope)
        action = ModifyUserAddress(user_id=fixture["customer_id"], address1=f"11 Fictional Lane {run_id.hex[:8]}",
                                   address2="", city="Seattle", state="WA", country="USA", zip="98101")
        facts = collect(retail, gateway, action, LedgerHistory(app, scope))
        if not isinstance(facts, Collected):
            raise SeedError("simulator facts unavailable")
        proposals = ProposalService(app_engine=app, clock=clock)
        made = proposals.create(gateway, action, facts, rationale="Fictional customer requested an address change.")
        if not isinstance(made, Created):
            raise SeedError("proposal creation refused")
        proposal = made.proposal
        require(isinstance(proposals.present(scope, proposal.proposal_id, proposal.proposal_version), Presented),
                "proposal presentation refused")
    return {"case_id": str(case_id), "run_id": str(run_id), "proposal_id": str(proposal.proposal_id)}


def inspect(connection_id: str, ticket_id: int) -> dict[str, Any]:
    workspace = local_workspace(connection_id)
    params = {"connection": connection_id, "ticket": ticket_id}
    with own_engine("policyops_app_runtime") as app, workspace_transaction(app, workspace) as connection:
        events = connection.execute(text("""
            SELECT state, reason, body_sha256 FROM app.helpdesk_events
            WHERE connection_id=:connection AND ticket_id=:ticket ORDER BY created_at, id LIMIT 100
        """), params).mappings().all()
        link = connection.execute(text("""
            SELECT case_id FROM app.helpdesk_ticket_links WHERE connection_id=:connection AND ticket_id=:ticket
        """), params).scalar_one_or_none()
        notes = connection.execute(text("""
            SELECT id, state, reason, attempts, reconciles, article_id, article_created_at, duplicate_article_ids
            FROM app.helpdesk_writebacks WHERE case_id=:case ORDER BY created_at, id LIMIT 100
        """), {"case": link}).mappings().all()
        count = connection.execute(text("""
            SELECT count(*) FROM app.case_messages WHERE case_id=:case AND source='helpdesk_ticket'
        """), {"case": link}).scalar_one()
        rejections = connection.execute(text("""
            SELECT count(*) FROM app.audit_events a JOIN app.helpdesk_events e
                ON a.workspace_id=e.workspace_id AND a.target_id=e.id
            WHERE e.connection_id=:connection AND e.ticket_id=:ticket AND a.action='helpdesk.rejected_mapping'
        """), params).scalar_one()
    return {"events": [dict(row) for row in events], "case_id": link,
            "writebacks": [dict(row) for row in notes], "imported_messages": count,
            "rejected_mapping_audits": rejections}


def capture(connection_id: str, ticket_id: int) -> dict[str, str]:
    workspace = local_workspace(connection_id)
    with own_engine("policyops_app_runtime") as app, workspace_transaction(app, workspace) as connection:
        row = connection.execute(text("""
            SELECT payload, body_sha256 FROM app.helpdesk_events
            WHERE connection_id = :connection AND ticket_id = :ticket AND state = 'applied'
            ORDER BY created_at, id LIMIT 1
        """), {"connection": connection_id, "ticket": ticket_id}).one_or_none()
    if row is None:
        raise SeedError("no accepted trigger for this ticket")
    return {"body_base64": base64.b64encode(row.payload).decode("ascii"), "body_sha256": row.body_sha256}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    provisioning, webhook, bind, inspection, capturing = (modes.add_parser(mode) for mode in (
        "provision", "wire", "bind", "inspect", "capture"))
    for mode in (provisioning, webhook):
        mode.add_argument("--admin-origin", required=True)
        mode.add_argument("--admin-token-file", type=Path, required=True)
    webhook.add_argument("--settings-file", type=Path, required=True)
    webhook.add_argument("--receiver-port", type=int, default=8080)
    for mode in (webhook, bind, inspection, capturing):
        mode.add_argument("--connection", required=True)
    bind.add_argument("--requester-id", type=int, required=True)
    inspection.add_argument("--ticket-id", type=int, required=True)
    capturing.add_argument("--ticket-id", type=int, required=True)
    modes.add_parser("prepare").add_argument("--case-id", type=UUID, required=True)
    args = parser.parse_args()
    try:
        if args.mode in {"provision", "wire"}:
            with admin(args.admin_origin, args.admin_token_file) as zammad:
                result = (provision(zammad) if args.mode == "provision" else
                          wire(zammad, args.settings_file, args.connection, args.receiver_port))
        elif args.mode == "bind":
            result = binding(args.connection, args.requester_id)
        elif args.mode == "prepare":
            result = prepare(args.case_id)
        elif args.mode == "capture":
            result = capture(args.connection, args.ticket_id)
        else:
            result = inspect(args.connection, args.ticket_id)
    except SeedError as error:
        print(f"help desk seed failed ({error})")
        return 1
    except Exception as error:
        print(f"help desk seed failed ({type(error).__name__})")
        return 1
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
