"""The gateway end to end: the real `RetailClient`, the owned retail-simulator process and real PostgreSQL (T17).

The application side runs as the actual runtime LOGIN role:
- the scope is loaded from the persisted run and case;
- the lookup authentication is persisted in `app.customer_authentications`;
- the approver's membership is read from `identity.memberships`.

The retail service is the T16 owned child process, reused unchanged through the T16 `Service` helper (loaded from
its test module by path).

**Test-only stand-ins.** The decision records come from an injected `MemoryDecisions`, and the operation history
from `TestOnlyCompleteHistory`; neither has a production implementation before T18/T19. The final `mutate` call is
this test standing in for the T19 dispatcher. T17 itself dispatches nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
import importlib.util
from itertools import count
import json
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

import pytest

from policyops.adapters.retail_client import RetailClient
from policyops.domain.retail_rules import propose
from policyops.gateway.ports import PgMembership, PgSessionStore, load_scope
from policyops.gateway.precheck import AuthorityRefs, Cleared, PrecheckRefused, precheck
from policyops.gateway.steps import Gateway, parse_result
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, verify_runtime_role, workspace_transaction
from policyops.persistence.records import Membership, NewCase, NewRun, Principal, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.clock import FixedClock, SystemClock
from policyops_contracts.digest import text_sha256
from policyops_contracts.gateway import (
    HandoffObservation,
    LookupObservation,
    ProposalPreview,
    ReadObservation,
    ToolError,
)
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail_service import FIXTURE_SHA256, CaseState, OperationResult, OrderOutput
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.gateway_cases import MemoryDecisions, TestOnlyCompleteHistory, authority, tool
from policyops_testing.postgres import OwnedPostgres


pytestmark = pytest.mark.postgres


def _t16_support() -> ModuleType:
    """The T16 service helper, loaded from its (unchanged) test module."""
    path = Path(__file__).with_name("test_retail_client.py")
    spec = importlib.util.spec_from_file_location("policyops_t16_retail_client_support", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T16 = _t16_support()
CUSTOMER, ORDER, CARD = T16.CUSTOMER, T16.ORDER, T16.CARD
EMAIL, NAME = "james.johnson7869@example.com", ("James", "Johnson", "60625")
PROCESSED = "#W3723163"
ITEM, REPLACEMENT = "5172162216", "4068787148"


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def other_customer() -> tuple[str, str]:
    """An order and an email of a different fixture customer (read from the reviewed fixture, not hard-coded)."""
    db = json.loads((T16.reviewed_tree() / "data/tau2/domains/retail/db.json").read_text(encoding="utf-8"))
    order_id = next(oid for oid, order in sorted(db["orders"].items()) if order["user_id"] != CUSTOMER)
    return order_id, db["users"][db["orders"][order_id]["user_id"]]["email"]


@pytest.fixture
def service(postgres: OwnedPostgres, new_app_database: NewDatabase, tmp_path: Path) -> Any:
    return T16.Service(postgres, new_app_database("gateway_retail"), tmp_path)


def seed(db: AppDatabase, now: datetime) -> tuple[RunScope, UUID, UUID]:
    """A workspace, a reviewer membership and a case bound to the fixture customer with one run."""
    ws, case, run, reviewer = uuid4(), uuid4(), uuid4(), uuid4()
    membership = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=ws, slug=f"ws-{ws.hex[:12]}", name="Gateway e2e", created_at=now))
        repo.create_principal(conn, Principal(id=reviewer, issuer="https://issuer.example.invalid",
                                              subject=f"s-{reviewer.hex}", display_name="Synthetic Reviewer",
                                              created_at=now))
        repo.add_membership(conn, Membership(id=membership, workspace_id=ws, principal_id=reviewer,
                                             role="reviewer", created_at=now))
    with workspace_transaction(db.engine(APP_RUNTIME), ws) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=ws, scenario="retail",
                                                customer_user_id=CUSTOMER, created_by=None, created_at=now))
        repo.create_run(conn, NewRun(id=run, workspace_id=ws, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=now + timedelta(hours=1),
                                     created_at=now))
    return RunScope(workspace_id=ws, case_id=case, run_id=run), reviewer, membership


class Steps:
    def __init__(self, gateway: Gateway) -> None:
        self.gateway, self.sequence = gateway, count(2)

    def __call__(self, raw: Any, previous: Any = None) -> Any:
        parsed = parse_result(raw)
        assert not isinstance(parsed, ToolError), parsed
        return self.gateway.step(parsed, previous=previous, sequence=next(self.sequence))


@pytest.fixture
def e2e(service: Any, now: datetime) -> Iterator[tuple[Any, AppDatabase, RunScope, UUID, UUID]]:
    db = service.database
    scope, reviewer, membership = seed(db, now)
    yield service, db, scope, reviewer, membership


def test_gateway_lookup_reads_previews_and_precheck_against_the_real_service(e2e: Any, now: datetime) -> None:
    service, db, scope, reviewer, membership = e2e
    runtime = db.engine(APP_RUNTIME)
    verify_runtime_role(runtime, APP_RUNTIME)
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=scope.workspace_id, case_id=scope.case_id),
                                  seed_id="retail-demo-9999", user_id=CUSTOMER, bound_at=now)
    gateway_scope = load_scope(runtime, workspace_id=scope.workspace_id, run_id=scope.run_id, binding=binding,
                               fixture_sha256=FIXTURE_SHA256)
    foreign_order, foreign_email = other_customer()
    with service.running() as origin, closing(RetailClient(origin, service.key, tenant_id=scope.workspace_id,
                                                           case_id=scope.case_id, customer_id=CUSTOMER)) as client:
        assert isinstance(client.initialize(), CaseState)
        sessions = PgSessionStore(runtime)
        step = Steps(Gateway(gateway_scope, retail=client, sessions=sessions, clock=SystemClock()))

        denied = step(tool("get_order_details", order_id=ORDER)).observation
        assert isinstance(denied, ToolError) and denied.code == "customer_not_authenticated"
        for raw in (tool("find_user_id_by_name_zip", first_name=NAME[0], last_name=NAME[1], zip="00000"),
                    tool("find_user_id_by_email", email=foreign_email)):  # another customer is not revealed
            assert step(raw).observation.outcome == "not_found"
        assert sessions.load(scope) is None
        authenticated = step(tool("find_user_id_by_email", email=EMAIL)).observation
        assert authenticated == LookupObservation(tool="find_user_id_by_email", outcome="authenticated")
        stored = sessions.load(scope)
        assert stored is not None and stored.user_id == CUSTOMER

        for raw in (tool("get_user_details", user_id=CUSTOMER), tool("get_order_details", order_id=ORDER),
                    tool("get_product_details", product_id="1808611083"), tool("get_item_details", item_id=REPLACEMENT),
                    tool("list_all_product_types"), tool("calculate", expression="(48.51 + 3.5) * 2")):
            assert isinstance(step(raw).observation, ReadObservation), raw
        hidden = step(tool("get_order_details", order_id=foreign_order)).observation
        assert isinstance(hidden, ToolError) and hidden.code == "not_found"

        cancel = tool("cancel_pending_order", order_id=ORDER, reason="no longer needed")
        preview = step(cancel)
        assert isinstance(preview.observation, ProposalPreview) and preview.observation.actionable is False
        processed = step(tool("cancel_pending_order", order_id=PROCESSED, reason="no longer needed")).observation
        assert isinstance(processed, ToolError) and (processed.code, processed.rule_id) == ("policy_denied",
                                                                                            "status.actionable")
        single = tool("modify_pending_order_items", order_id=ORDER, item_ids=[ITEM], new_item_ids=[REPLACEMENT],
                      payment_method_id=CARD)
        escalated = step(single).observation
        assert isinstance(escalated, ToolError) and (escalated.code, escalated.rule_id) == (
            "policy_unsupported", "orders.modify_exchange_once")  # the production history is incomplete
        tested = Steps(Gateway(gateway_scope, retail=client, sessions=sessions, clock=SystemClock(),
                               history=TestOnlyCompleteHistory()))(single)
        assert isinstance(tested.observation, ProposalPreview)  # only with the labelled test-only history
        assert isinstance(step(tool("modify_user_address", user_id=CUSTOMER, address1="1 Main St", address2="",
                                    city="Chicago", state="IL", country="USA", zip="60601")).observation,
                          ProposalPreview)
        assert isinstance(step(tool("transfer_to_human_agents", summary="Customer asks about loyalty points")
                               ).observation, HandoffObservation)

        # The precheck, with test-only persisted records; the mutate call below stands in for T19.
        parsed = parse_result(cancel)
        assert isinstance(parsed, ToolCallStep) and preview.collected is not None
        proposal = propose(proposal_id=uuid4(), proposal_version=1, session=step.gateway.session(),
                           call=parsed.call, facts=preview.collected.facts, evidence=(),  # type: ignore[arg-type]
                           rationale="The customer no longer needs the order.", now=now)
        assert isinstance(proposal, ActionProposal)
        refs = AuthorityRefs(proposal_id=proposal.proposal_id, proposal_version=1, consent_id=uuid4(),
                             approval_id=uuid4())
        consent, approval = authority(proposal, approver=reviewer, entered_by=uuid4(), refs=refs)
        clock = FixedClock(now + timedelta(minutes=3))
        membership_port = PgMembership(runtime)

        def check(decisions: Any = None) -> Cleared | PrecheckRefused:
            return precheck(gateway_scope, refs, retail=client, sessions=sessions, membership=membership_port,
                            clock=clock, decisions=decisions)

        default = check()
        assert isinstance(default, PrecheckRefused) and default.detail == "no_decision_store"
        decisions = MemoryDecisions(proposal, consent, approval)
        assert isinstance(check(decisions), Cleared)
        with workspace_transaction(runtime, scope.workspace_id) as conn:
            assert repo.revoke_membership(conn, membership, now)
        revoked = check(decisions)
        assert isinstance(revoked, PrecheckRefused) and revoked.detail == "approver_not_current_reviewer"
        with transaction(db.engine(AUTH_RUNTIME)) as conn:
            repo.add_membership(conn, Membership(id=uuid4(), workspace_id=scope.workspace_id, principal_id=reviewer,
                                                 role="reviewer", created_at=now))
        cleared = check(decisions)
        assert isinstance(cleared, Cleared)
        committed = client.mutate(uuid4(), cleared.request,
                                  authorization_not_after=cleared.authorization_not_after.timestamp())
        assert isinstance(committed, OperationResult) and committed.outcome == "committed"
        after = check(decisions)  # the approval cannot override the now-invalid policy
        assert isinstance(after, PrecheckRefused) and (after.code, after.rule_id) == ("policy_denied",
                                                                                      "status.actionable")

    db.dispose()  # restart both sides: the service process and the application's connections
    with service.running() as origin, closing(RetailClient(origin, service.key, tenant_id=scope.workspace_id,
                                                           case_id=scope.case_id, customer_id=CUSTOMER)) as client:
        restarted = Gateway(gateway_scope, retail=client, sessions=PgSessionStore(db.engine(APP_RUNTIME)),
                            clock=SystemClock())
        read = Steps(restarted)(tool("get_order_details", order_id=ORDER)).observation  # no new lookup needed
        assert isinstance(read, ReadObservation) and isinstance(read.output, OrderOutput)
        assert read.output.order.status == "cancelled"
    with db.superuser() as conn:
        assert conn.execute("SELECT count(*) FROM app.customer_authentications").fetchone() == (1,)
