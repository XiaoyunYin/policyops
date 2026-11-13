"""Persisted authority and execution environment shared by T19 and T30."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any, Literal
from uuid import UUID, uuid4

from policyops.adapters.retail_client import RetailClient, Unknown
from policyops.auth.service import Authorized, SessionContext
from policyops.domain.consent_rules import Consented
from policyops.gateway.facts import Collected, collect
from policyops.gateway.ports import GatewayScope, PgMembership, PgSessionStore, load_scope
from policyops.gateway.precheck import AuthorityRefs, Cleared, precheck
from policyops.gateway.stores import PgDecisionStore, PgEvidencePort
from policyops.persistence import customer_authentications as auth_rows
from policyops.persistence import executions as ledger
from policyops.persistence import repositories as repo
from policyops.persistence import runs as run_store
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, NewCase, NewRun, Principal, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.executions import ExecutionDispatcher, build_execution_dispatcher
from policyops.services.decisions import DecisionService
from policyops.services.execution import (
    ExecutionHooks,
    ExecutionLimits,
    LedgerHistory,
    Reserved,
)
from policyops.services.proposal_views import DecisionRequest
from policyops.services.proposals import Created, Presented, ProposalService
from policyops_contracts.clock import FixedClock
from policyops_contracts.digest import text_sha256
from policyops_contracts.retail import (
    CancelPendingOrder,
    ExchangeDeliveredOrderItems,
    GetOrderDetails,
    ModifyPendingOrderItems,
    ReturnDeliveredOrderItems,
)
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication
from policyops_testing.app_database import AppDatabase
from policyops_testing.safety import retail as T16


CUSTOMER, ORDER, CARD = T16.CUSTOMER, T16.ORDER, T16.CARD
CANCEL = CancelPendingOrder(order_id=ORDER, reason="no longer needed")
ITEMS = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                payment_method_id=CARD)
LEASE = ExecutionLimits().lease
# A delivered order of another fixture customer (the T16 effect tests' exchange target).
DELIVERED_CUSTOMER, DELIVERED, DELIVERED_CARD = "raj_sanchez_2970", "#W1067251", "credit_card_3362387"
RETURN = ReturnDeliveredOrderItems(order_id=DELIVERED, item_ids=("6452271382",), payment_method_id=DELIVERED_CARD)
EXCHANGE = ExchangeDeliveredOrderItems(order_id=DELIVERED, item_ids=("7848293342",), new_item_ids=("3876764226",),
                                       payment_method_id=DELIVERED_CARD)


class ConsentNotRecorded(ValueError):
    """The real customer-reply service returned an outcome other than Consented."""


@dataclass
class Env:
    db: AppDatabase
    service: Any
    origin: str
    clock: FixedClock
    scope: GatewayScope
    reviewer: UUID
    membership: UUID
    customer: str = CUSTOMER
    order: str = ORDER

    @property
    def run(self) -> RunScope:
        return self.scope.run

    @property
    def app(self) -> Any:
        return self.db.engine(APP_RUNTIME, pool_size=6)

    def client(self, origin: str | None = None) -> RetailClient:
        return RetailClient(origin or self.origin, self.service.key, tenant_id=self.run.workspace_id,
                            case_id=self.run.case_id, customer_id=self.customer)

    def effects(self) -> int:
        """Committed effects on the simulator case (its version starts at 1 and each commit adds exactly 1)."""
        with closing(self.client()) as client:
            read = client.read(GetOrderDetails(order_id=self.order))
        assert not isinstance(read, Unknown)
        return read.case_version - 1

    def arm(self, fault: str, count: int = 1) -> None:
        with closing(self.client()) as client:
            sent = client._send("PUT", client._path("faults"), "write", T16.Fault(fault=fault, count=count))
        assert not isinstance(sent, Unknown) and sent.status_code == 204

    def row(self, execution_id: UUID) -> dict[str, Any]:
        with self.db.superuser() as conn:  # inspection only
            cursor = conn.execute("SELECT state, outcome, attempts, reconcile_attempts, resolved_by, last_code, "
                                  "receipt IS NOT NULL, next_attempt_at, claim_id FROM app.tool_executions "
                                  "WHERE id = %s", (execution_id,))
            names = ("state", "outcome", "attempts", "reconciles", "resolved_by", "code", "receipt", "next", "claim")
            return dict(zip(names, cursor.fetchone(), strict=True))

    def states(self) -> list[str]:
        with self.db.superuser() as conn:
            rows = conn.execute("SELECT payload->>'state' FROM app.run_events WHERE run_id = %s AND event_type = "
                                "'execution.changed' ORDER BY sequence", (self.run.run_id,)).fetchall()
        return [row[0] for row in rows]

    def retail(self, origin: str | None = None) -> Callable[[GatewayScope], Any]:
        @contextmanager
        def open_client(scope: GatewayScope) -> Iterator[RetailClient]:
            assert scope == self.scope
            with closing(self.client(origin)) as client:
                yield client
        return open_client

    def dispatcher(self, *, hooks: ExecutionHooks | None = None, limits: ExecutionLimits | None = None,
                   origin: str | None = None) -> ExecutionDispatcher:
        env = self

        class Scopes:
            def scope(self, run: RunScope) -> GatewayScope:
                assert run == env.run
                return env.scope

        return build_execution_dispatcher(env="test", app_engine=self.app,
                                          discovery_engine=self.db.engine(WORKER_DISCOVERY), scopes=Scopes(),
                                          retail=self.retail(origin), clock=FixedLeaseClock(self.clock),
                                          hooks=hooks, limits=limits)

    def approve(self, call: Any = CANCEL, *, source: Literal["simulated_customer", "staff_note",
                "operator_entered_customer"] = "simulated_customer", entered_by: UUID | None = None,
                decision_kind: Literal["approve", "reject"] = "approve", decide: bool = True) -> AuthorityRefs:
        """A real T18 approval of a proposal built from the simulator's current facts."""
        lease = FixedLeaseClock(self.clock)
        with closing(self.client()) as client:
            collected = collect(client, self.scope, call, LedgerHistory(self.app, self.run))
        assert isinstance(collected, Collected), collected
        proposals = ProposalService(app_engine=self.app, clock=lease)
        created = proposals.create(self.scope, call, collected, rationale="Customer asked.")
        assert isinstance(created, Created), created
        proposal = created.proposal
        self.clock.advance(timedelta(seconds=1))
        assert isinstance(proposals.present(self.run, proposal.proposal_id, proposal.proposal_version), Presented)
        self.clock.advance(timedelta(seconds=1))
        with workspace_transaction(self.app, self.run.workspace_id) as conn:
            message = repo.append_message(conn, message_id=uuid4(), scope=CaseScope(
                workspace_id=self.run.workspace_id, case_id=self.run.case_id), source=source,
                entered_by=entered_by, text_value="yes", created_at=self.clock.now())
        self.clock.advance(timedelta(seconds=1))
        consent = proposals.record_customer_reply(self.run, message.message_id)
        if not isinstance(consent, Consented):
            raise ConsentNotRecorded(type(consent).__name__)
        if not decide:
            return AuthorityRefs(proposal.proposal_id, proposal.proposal_version, consent.consent.consent_id, uuid4())
        session = SessionContext(session_id=uuid4(), principal_id=self.reviewer, workspace_id=self.run.workspace_id,
                                 expires_at=self.clock.now() + timedelta(hours=1), csrf_sha256="0" * 64)
        authorized = Authorized(session=session, workspace_id=self.run.workspace_id,
                                roles=frozenset({"reviewer"}))  # type: ignore[arg-type]
        decided = DecisionService(app_engine=self.app, clock=lease).decide(
            authorized, proposal.proposal_id, DecisionRequest.model_validate({
                "proposal_version": proposal.proposal_version, "action_digest": proposal.action_digest,
                "decision": decision_kind, "reason": "Order and policy checked."}))
        decision = decided.decision
        return AuthorityRefs(proposal.proposal_id, proposal.proposal_version, decision.consent_id,
                             decision.approval_id)

    def reserve(self, refs: AuthorityRefs, dispatcher: ExecutionDispatcher | None = None) -> UUID:
        reserved = (dispatcher or self.dispatcher()).executor.reserve(self.scope, refs)
        assert isinstance(reserved, Reserved) and reserved.created, reserved
        return reserved.execution.id

    def cancel_run(self) -> None:
        with workspace_transaction(self.app, self.run.workspace_id) as conn:
            run = run_store.get_run(conn, self.run.run_id, lock=True)
            assert run is not None
            run_store.set_state(conn, run, "cancelled", self.clock.now(), bump_generation=True)


def make_env(live: tuple[Any, str], shared_db: AppDatabase) -> Env:
    service, origin = live
    start = datetime.now(UTC).replace(microsecond=0)
    workspace, case, run, reviewer, membership = uuid4(), uuid4(), uuid4(), uuid4(), uuid4()
    with transaction(shared_db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=workspace, slug=f"t19-{workspace.hex[:12]}", name="T19",
                                              created_at=start))
        repo.create_principal(conn, Principal(id=reviewer, issuer="https://issuer.example.invalid",
                                              subject=f"r-{reviewer.hex}", display_name="Reviewer", created_at=start))
        repo.add_membership(conn, Membership(id=membership, workspace_id=workspace, principal_id=reviewer,
                                             role="reviewer", created_at=start))
    app = shared_db.engine(APP_RUNTIME, pool_size=6)
    run_scope = RunScope(workspace_id=workspace, case_id=case, run_id=run)
    with workspace_transaction(app, workspace) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=workspace, scenario="retail",
                                                customer_user_id=CUSTOMER, created_by=None, created_at=start))
        repo.create_run(conn, NewRun(id=run, workspace_id=workspace, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=start + timedelta(hours=2),
                                     created_at=start))
        auth_rows.record(conn, CustomerAuthentication(
            scope=run_scope, user_id=CUSTOMER, lookup_tool="find_user_id_by_email",
            lookup_call_sha256=hashlib.sha256(str(run).encode()).hexdigest(), step_sequence=1,
            authenticated_at=start))
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=workspace, case_id=case), seed_id="retail-demo-9999",
                                  user_id=CUSTOMER, bound_at=start)
    scope = load_scope(app, workspace_id=workspace, run_id=run, binding=binding, fixture_sha256=FIXTURE_SHA256)
    result = Env(shared_db, service, origin, FixedClock(start + timedelta(seconds=1)), scope, reviewer, membership)
    with closing(result.client()) as client:
        assert not isinstance(client.initialize(), Unknown)
    return result


def due(env: Env) -> None:
    env.clock.advance(LEASE + timedelta(seconds=90))  # past any lease and backoff, still within the approval




def fresh_case(previous: Env, customer: str | None = None, order: str | None = None, *,
               case_id: UUID | None = None, run_id: UUID | None = None) -> Env:
    """A new case (and simulator case) for the next trial, in the same workspace and with the same reviewer."""
    customer, order = customer or previous.customer, order or previous.order
    case, run = case_id or uuid4(), run_id or uuid4()
    start = previous.clock.now()
    with workspace_transaction(previous.app, previous.run.workspace_id) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=previous.run.workspace_id, scenario="retail",
                                                customer_user_id=customer, created_by=None, created_at=start))
        repo.create_run(conn, NewRun(id=run, workspace_id=previous.run.workspace_id, case_id=case,
                                     case_version=record.version, mode="workbench", graph_sha256=text_sha256("g"),
                                     prompt_sha256=text_sha256("p"), config_sha256=text_sha256("c"),
                                     deadline_at=start + timedelta(hours=2), created_at=start))
        run_scope = RunScope(workspace_id=previous.run.workspace_id, case_id=case, run_id=run)
        auth_rows.record(conn, CustomerAuthentication(
            scope=run_scope, user_id=customer, lookup_tool="find_user_id_by_email",
            lookup_call_sha256=hashlib.sha256(str(run).encode()).hexdigest(), step_sequence=1, authenticated_at=start))
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=previous.run.workspace_id, case_id=case),
                                  seed_id="retail-demo-9999", user_id=customer, bound_at=start)
    scope = load_scope(previous.app, workspace_id=previous.run.workspace_id, run_id=run, binding=binding,
                       fixture_sha256=FIXTURE_SHA256)
    env = Env(previous.db, previous.service, previous.origin, FixedClock(start), scope, previous.reviewer,
              previous.membership, customer, order)
    with closing(env.client()) as client:
        assert not isinstance(client.initialize(), Unknown)
    return env


def cleared_request(env: Env, refs: AuthorityRefs, client: RetailClient) -> Cleared:
    cleared = precheck(env.scope, refs, retail=client, sessions=PgSessionStore(env.app),
                       membership=PgMembership(env.app), clock=env.clock, decisions=PgDecisionStore(env.app),
                       history=LedgerHistory(env.app, env.run), evidence=PgEvidencePort(env.app))
    assert isinstance(cleared, Cleared), cleared
    return cleared


def next_run(previous: Env) -> Env:
    """The case's next run on the same simulator case; the current run is cancelled first (one active run per
    case). Its executions keep reconciling after the run is terminal."""
    previous.cancel_run()
    run, start = uuid4(), previous.clock.now()
    with workspace_transaction(previous.app, previous.run.workspace_id) as conn:
        case = repo.get_case(conn, previous.run.case_id)
        assert case is not None
        repo.create_run(conn, NewRun(id=run, workspace_id=case.workspace_id, case_id=case.id,
                                     case_version=case.version, mode="workbench", graph_sha256=text_sha256("g"),
                                     prompt_sha256=text_sha256("p"), config_sha256=text_sha256("c"),
                                     deadline_at=start + timedelta(hours=2), created_at=start))
        auth_rows.record(conn, CustomerAuthentication(
            scope=RunScope(workspace_id=case.workspace_id, case_id=case.id, run_id=run), user_id=previous.customer,
            lookup_tool="find_user_id_by_email", lookup_call_sha256=hashlib.sha256(str(run).encode()).hexdigest(),
            step_sequence=1, authenticated_at=start))
    scope = load_scope(previous.app, workspace_id=previous.run.workspace_id, run_id=run,
                       binding=previous.scope.binding, fixture_sha256=FIXTURE_SHA256)
    return replace(previous, scope=scope)


def ledger_record(env: Env, execution: UUID) -> Any:
    with workspace_transaction(env.app, env.run.workspace_id) as conn:
        return ledger.get(conn, execution)


def study_case(previous: Env, customer: str | None = None, order: str | None = None, *,
               case_id: UUID | None = None, run_id: UUID | None = None) -> Env:
    """Fresh compatible wall/application clock for each long-study case, then controlled advances.

    T19's fresh_case keeps its caller's clock contract. A long T30 matrix must not
    reuse a lease timestamp from the beginning of the entire study for later HTTP calls.
    """
    aligned = replace(previous, clock=FixedClock(datetime.now(UTC)))
    return fresh_case(aligned, customer, order, case_id=case_id, run_id=run_id)

