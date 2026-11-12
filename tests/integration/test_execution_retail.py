"""T19 end to end: the execution dispatcher, the real `RetailClient`, the owned T16 retail-simulator process and real
PostgreSQL, all application access as the actual runtime and discovery LOGIN roles.

Authority is real: proposals, consents and approvals are written by the T18 services and read back by the executor's
own `Pg*` ports. The simulator's committed effects are read from the simulator (its case version), never inferred
from the ledger. Faults are finite: simulator fault plans (`commit_then_503`, `fail_503_before`), `CrashHooks`
around the HTTP call, a closed loopback port for an unreachable service, and a controlled lease clock.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.adapters.retail_client import Refused, RetailClient, Unknown
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
from policyops.persistence.database import IdempotencyConflict, ImmutableRecord, transaction, workspace_transaction
from policyops.persistence.migrate import revisions
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.records import Membership, NewCase, NewRun, Principal, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.executions import ExecutionDispatcher, build_execution_dispatcher
from policyops.services.decisions import DecisionService
from policyops.services.execution import (
    ExecutionHooks,
    ExecutionIntegrityError,
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
from policyops_testing import network
from policyops_testing.app_database import AppDatabase
from policyops_testing.evidence import git_identity
from policyops_testing.execution_faults import Crash, CrashHooks, Trial, fault_plan, write_report


pytestmark = pytest.mark.postgres


def _t16_support() -> ModuleType:
    path = Path(__file__).with_name("test_retail_client.py")
    spec = importlib.util.spec_from_file_location("policyops_t19_retail_client_support", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T16 = _t16_support()
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


@pytest.fixture(scope="module")
def live(postgres: Any, shared_db: AppDatabase, tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Any, str]]:
    service = T16.Service(postgres, shared_db, tmp_path_factory.mktemp("t19-retail"))
    with service.running() as origin:
        yield service, origin


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

    def approve(self, call: Any = CANCEL) -> AuthorityRefs:
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
                workspace_id=self.run.workspace_id, case_id=self.run.case_id), source="simulated_customer",
                entered_by=None, text_value="yes", created_at=self.clock.now())
        self.clock.advance(timedelta(seconds=1))
        assert isinstance(proposals.record_customer_reply(self.run, message.message_id), Consented)
        session = SessionContext(session_id=uuid4(), principal_id=self.reviewer, workspace_id=self.run.workspace_id,
                                 expires_at=self.clock.now() + timedelta(hours=1), csrf_sha256="0" * 64)
        authorized = Authorized(session=session, workspace_id=self.run.workspace_id,
                                roles=frozenset({"reviewer"}))  # type: ignore[arg-type]
        decided = DecisionService(app_engine=self.app, clock=lease).decide(
            authorized, proposal.proposal_id, DecisionRequest.model_validate({
                "proposal_version": proposal.proposal_version, "action_digest": proposal.action_digest,
                "decision": "approve", "reason": "Order and policy checked."}))
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


@pytest.fixture
def env(live: tuple[Any, str], shared_db: AppDatabase) -> Env:
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


# -- outcomes -----------------------------------------------------------------------------------------------------

def test_commit_then_lost_response_reconciles_to_the_receipt_with_one_effect(env: Env) -> None:
    dispatcher = env.dispatcher()
    refs = env.approve()
    execution = env.reserve(refs, dispatcher)
    again = dispatcher.executor.reserve(env.scope, refs)  # the operation ID is chosen once
    assert isinstance(again, Reserved) and not again.created and again.execution.id == execution
    env.arm("commit_then_503")
    [step] = dispatcher.dispatch_once()
    assert (step.action, step.code) == ("unknown", "http_503")
    assert env.row(execution)["state"] == "unknown" and env.effects() == 1
    assert dispatcher.dispatch_once() == []  # backoff: not due yet
    due(env)
    [step] = dispatcher.dispatch_once()
    assert (step.action, step.state) == ("recorded", "succeeded")
    row = env.row(execution)
    assert (row["outcome"], row["resolved_by"], row["attempts"], row["receipt"], row["next"]) == (
        "committed", "lookup", 1, True, None)
    assert env.effects() == 1 and env.states() == ["pending", "dispatched", "unknown", "succeeded"]
    with env.db.superuser() as conn:  # each transition committed its outbox intent and audit row with it
        assert conn.execute("SELECT count(*) FROM app.outbox_events WHERE run_id = %s",
                            (env.run.run_id,)).fetchone()[0] >= 4
        assert conn.execute("SELECT count(*) FROM app.audit_events WHERE target_id = %s",
                            (execution,)).fetchone()[0] == 4


def test_crash_after_checkpoint_or_after_response_recovers_with_the_same_operation(env: Env) -> None:
    crash = CrashHooks(before_send=1)
    execution = env.reserve(env.approve())
    with pytest.raises(Crash):
        env.dispatcher(hooks=crash).dispatch_once()
    assert env.row(execution)["state"] == "dispatched" and env.effects() == 0  # checkpoint committed, nothing sent
    assert env.dispatcher().dispatch_once() == []  # the dead worker's lease is still live
    due(env)
    restarted = env.dispatcher()  # restart: lookup unknown, fresh precheck, the same operation ID again
    [step] = restarted.dispatch_once()
    assert step.state == "succeeded" and env.row(execution)["attempts"] == 2 and env.effects() == 1


def test_crash_after_the_response_is_recovered_by_lookup(env: Env) -> None:
    execution = env.reserve(env.approve())
    with pytest.raises(Crash):
        env.dispatcher(hooks=CrashHooks(after_response=1)).dispatch_once()
    assert env.row(execution)["state"] == "dispatched" and env.effects() == 1
    due(env)
    [step] = env.dispatcher().dispatch_once()
    assert (step.state, env.row(execution)["resolved_by"], env.effects()) == ("succeeded", "lookup", 1)


def test_a_stale_worker_cannot_write_unknown_and_its_late_receipt_is_idempotent(env: Env) -> None:
    execution = env.reserve(env.approve())
    late: list[Any] = []

    class TakenOver(ExecutionHooks):
        test_only = True

        def before_send(self, record: Any) -> None:
            if late:
                return
            late.append(record)
            due(env)  # worker A stalls past its lease; worker B claims and completes the same operation
            assert env.dispatcher().dispatch_once()[0].state == "succeeded"
            env.arm("fail_503_before")  # A's late request now fails: its Unknown must not be written

    [step] = env.dispatcher(hooks=TakenOver()).dispatch_once()
    assert (step.action, step.state) == ("unchanged", "succeeded")
    assert env.row(execution)["state"] == "succeeded" and env.effects() == 1
    # A's late request replays the stored receipt: recording it again is a no-op, not a second event.
    with closing(env.client()) as client:
        replay = client.mutate(late[0].operation_id, late[0].request)
    assert not isinstance(replay, Unknown) and replay.replayed
    assert env.dispatcher().executor.record(late[0], replay, "response").action == "unchanged"
    assert env.states().count("succeeded") == 1


def test_expiry_after_an_unknown_fences_and_the_late_original_replays_fenced(env: Env) -> None:
    execution = env.reserve(env.approve())
    env.arm("fail_503_before")
    assert env.dispatcher().dispatch_once()[0].action == "unknown"
    env.clock.advance(timedelta(minutes=16))  # past the approval: no new mutation, only lookup and fence
    [step] = env.dispatcher().dispatch_once()
    assert (step.state, step.code) == ("reconciled", "fenced") and env.effects() == 0
    row = env.row(execution)
    assert (row["attempts"], row["resolved_by"], row["receipt"]) == (1, "fence", False)
    with env.db.superuser() as conn:
        op = conn.execute("SELECT operation_id FROM app.tool_executions WHERE id = %s", (execution,)).fetchone()[0]
    stored = ledger_record(env, execution)
    with closing(env.client()) as client:
        original = client.mutate(op, stored.request)  # the in-flight original arrives late
    assert not isinstance(original, Unknown) and original.outcome == "fenced" and env.effects() == 0
    assert env.dispatcher().executor.record(stored, original, "response").action == "unchanged"


def ledger_record(env: Env, execution: UUID) -> Any:
    with workspace_transaction(env.app, env.run.workspace_id) as conn:
        return ledger.get(conn, execution)


def test_cancel_after_dispatch_keeps_the_known_receipt_and_cancel_before_settles(env: Env) -> None:
    execution = env.reserve(env.approve())
    env.arm("commit_then_503")
    assert env.dispatcher().dispatch_once()[0].action == "unknown"
    env.cancel_run()  # cannot recall the committed request
    due(env)
    assert env.dispatcher().dispatch_once()[0].state == "succeeded"
    assert env.row(execution)["state"] == "succeeded" and env.effects() == 1
    assert env.states()[-1] == "succeeded"  # durable after the run's cancellation (the run is not reopened)
    with env.db.superuser() as conn:
        assert conn.execute("SELECT state FROM app.runs WHERE id = %s", (env.run.run_id,)).fetchone()[0] == "cancelled"


def test_authority_changed_between_precheck_and_checkpoint_sends_nothing(env: Env) -> None:
    def revoke(record: Any) -> None:
        with workspace_transaction(env.app, env.run.workspace_id) as conn:
            assert repo.revoke_membership(conn, env.membership, env.clock.now())

    class Revoking(CrashHooks):
        pass

    execution = env.reserve(env.approve())
    [step] = env.dispatcher(hooks=Revoking(before_checkpoint=revoke)).dispatch_once()
    assert (step.action, step.code) == ("settled", "approver_not_current_reviewer")
    row = env.row(execution)
    assert (row["state"], row["outcome"], row["attempts"]) == ("failed", "precheck_refused", 0)
    assert env.effects() == 0 and env.states() == ["pending", "failed"]


def test_cancel_before_any_checkpoint_settles_locally(env: Env) -> None:
    execution = env.reserve(env.approve())
    env.cancel_run()
    [step] = env.dispatcher().dispatch_once()
    assert (step.state, env.row(execution)["outcome"], env.effects()) == ("failed", "cancelled_before_dispatch", 0)


def test_concurrent_dispatchers_claim_once_and_a_second_approval_on_the_order_waits(env: Env) -> None:
    execution = env.reserve(env.approve())
    barrier, results = threading.Barrier(2), []

    def work() -> None:
        dispatcher = env.dispatcher()
        barrier.wait()
        results.append(dispatcher.dispatch_once())

    threads = [threading.Thread(target=work) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads)
    steps = [step for batch in results for step in batch if step.action != "skipped"]
    assert [step.state for step in steps] == ["succeeded"] and env.effects() == 1
    assert env.row(execution)["attempts"] == 1


def test_the_same_operation_with_a_conflicting_payload_is_refused(env: Env) -> None:
    execution = env.reserve(env.approve())
    assert env.dispatcher().dispatch_once()[0].state == "succeeded"
    stored = ledger_record(env, execution)
    other = stored.request.model_copy(update={"intent_sha256": "c" * 64})
    with closing(env.client()) as client, pytest.raises(Refused) as refused:
        client.mutate(stored.operation_id, other)
    assert (refused.value.status, refused.value.code) == (409, "operation_conflict") and env.effects() == 1


def test_once_per_order_history_needs_the_contiguous_receipt_chain(env: Env) -> None:
    history = LedgerHistory(env.app, env.run)
    assert history.history(ORDER, case_version=1).complete
    execution = env.reserve(env.approve(ITEMS))
    assert not history.history(ORDER, case_version=1).complete  # an unresolved execution
    assert env.dispatcher().dispatch_once()[0].state == "succeeded" and env.effects() == 1
    known = history.history(ORDER, case_version=2)
    assert known.complete and [str(tool) for tool in known.successful_tools] == ["modify_pending_order_items"]
    assert not history.history(ORDER, case_version=3).complete  # a commit the ledger did not record
    assert env.row(execution)["state"] == "succeeded"


def test_an_unreachable_service_leaves_the_execution_explicitly_unresolved(env: Env) -> None:
    execution = env.reserve(env.approve())
    port = T16.free_port()
    limits = ExecutionLimits(max_reconciles=2)
    env.arm("fail_503_before")
    assert env.dispatcher(limits=limits).dispatch_once()[0].action == "unknown"  # sent once, outcome unknown
    with network.allow("127.0.0.1", port):
        closed = f"http://127.0.0.1:{port}"  # then the service becomes unreachable: lookup and fence fail
        for expected in ("unknown", "capped"):
            due(env)
            assert env.dispatcher(origin=closed, limits=limits).dispatch_once()[0].action == expected
    row = env.row(execution)
    assert (row["state"], row["outcome"], row["receipt"], row["next"], row["code"]) == (
        "unknown", None, False, None, "transport_error")
    due(env)
    assert env.dispatcher().dispatch_once() == []  # never rediscovered: held, reported, not guessed


# -- the ledger as the database enforces it -------------------------------------------------------------------

def test_runtime_and_discovery_roles_cannot_bypass_the_ledger(env: Env) -> None:
    execution = env.reserve(env.approve())
    assert env.dispatcher().dispatch_once()[0].state == "succeeded"
    with workspace_transaction(env.app, env.run.workspace_id) as conn:
        current = ledger.get(conn, execution)
        assert current is not None
    for changes in ({"state": "unknown"}, {"receipt": None}):
        with pytest.raises(ImmutableRecord), workspace_transaction(env.app, env.run.workspace_id) as conn:
            ledger.update(conn, current, env.clock.now(), **changes)  # terminal rows never change
    for sql in ("DELETE FROM app.tool_executions", "UPDATE app.tool_executions SET target_id = 'x'"):
        with pytest.raises(DBAPIError), workspace_transaction(env.app, env.run.workspace_id) as conn:
            conn.exec_driver_sql(sql)
    with pytest.raises(DBAPIError), transaction(env.db.engine(WORKER_DISCOVERY)) as conn:
        conn.exec_driver_sql("SELECT request FROM app.tool_executions")
    with workspace_transaction(env.app, uuid4()) as conn:  # another workspace sees nothing
        assert ledger.get(conn, execution) is None
    with env.db.superuser() as conn, pytest.raises(Exception, match="retained"):
        conn.execute("DELETE FROM app.tool_executions WHERE id = %s", (execution,))


def test_a_populated_ledger_refuses_the_downgrade(env: Env) -> None:
    execution = env.reserve(env.approve())
    try:
        with workspace_transaction(env.app, env.run.workspace_id) as conn:
            before = ledger.get(conn, execution)
            assert before is not None
        chain = revisions()
        for allow in (False, True):  # the row may be an unresolved remote operation, even with the override
            try:
                with pytest.raises(DataLossRefused):
                    env.db.downgrade("0011", allow_data_loss=allow)
                # Each downgrade commits separately; the refusing revision remains applied.
                # Later guards may refuse first, but the 0012 ledger must survive intact.
                stopped_at = env.db.current()
                assert stopped_at is not None and chain.index(stopped_at) >= chain.index("0012")
                with workspace_transaction(env.app, env.run.workspace_id) as conn:
                    assert ledger.get(conn, execution) == before
            finally:
                env.db.upgrade()  # restore head for the dispatcher and the module's shared database
    finally:
        # Settle even when an assertion above fails, so later module tests cannot discover this due row.
        assert env.dispatcher().dispatch_once()[0].state == "succeeded"
        assert env.row(execution)["state"] == "succeeded"


# -- E04 development harness (seeded, small; the >=100-trial comparative study is T30) ----------------------------

def test_seeded_fault_trials_keep_at_most_one_effect_and_a_receipt_for_every_effect(env: Env, seed: int) -> None:
    """Paired development arms: each seeded fault runs once through the ledger and once through a naive client that
    retries with a new operation ID, each on its own fresh simulator case. The naive arm is a baseline, not a straw
    man: whatever it scores is reported (the simulator's version preconditions may refuse its duplicate)."""
    trials: list[Trial] = []
    plan = fault_plan(seed, 4)
    for index, fault in enumerate(plan):
        for arm, runner in (("ledger", run_trial), ("naive_new_id", run_naive_trial)):
            env = fresh_case(env)
            try:
                trials.append(runner(env, seed, index, fault))
            except Exception as error:
                # Only the exception type: a message (e.g. a connection error) can carry generated credentials.
                trials.append(Trial(seed=seed, index=index, arm=arm, fault=fault, final_state="aborted",
                                    outcome=None, attempts=0, reconcile_attempts=0, effects=-1,
                                    error=type(error).__name__))
    report_dir = Path(os.environ.get("POLICYOPS_REPORT_DIR", os.environ["POLICYOPS_TEMP_DIR"])) / "e04-t19"
    config = {"seed": seed, "trials_per_arm": len(plan), "plan": plan, "limits": repr(ExecutionLimits()),
              "naive_max_sends": NAIVE_SENDS, "fixture_sha256": FIXTURE_SHA256,
              "code": git_identity(Path(__file__).resolve().parents[2]).__dict__,
              "limitations": ["one coherent retail database and ledger lifetime; a retail reset is not detected (T38)",
                              "crashes are modelled exceptions at hook points, not OS process death",
                              "a small seeded development run, not the >=100-trial T30 study"]}
    report = write_report(report_dir / f"paired-{seed}.json", config, trials)
    assert [trial.error for trial in trials if trial.error] == []  # reported above, never dropped
    for trial in trials:
        assert trial.receipt_sha256 == [hashlib.sha256(json_bytes(body)).hexdigest() for body in trial.receipts]
    summary = report["summary"]["ledger"]
    assert summary["trials"] == report["summary"]["naive_new_id"]["trials"] == len(plan)
    assert summary["duplicate_effects"] == 0 and summary["effects_without_receipt"] == 0
    assert summary["success_without_effect"] == 0 and summary["unresolved"] == 0


def fresh_case(previous: Env, customer: str | None = None, order: str | None = None) -> Env:
    """A new case (and simulator case) for the next trial, in the same workspace and with the same reviewer."""
    customer, order = customer or previous.customer, order or previous.order
    case, run = uuid4(), uuid4()
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
    env = Env(previous.db, previous.service, previous.origin, previous.clock, scope, previous.reviewer,
              previous.membership, customer, order)
    with closing(env.client()) as client:
        assert not isinstance(client.initialize(), Unknown)
    return env


def run_trial(env: Env, seed: int, index: int, fault: str) -> Trial:
    execution = env.reserve(env.approve())
    hooks = CrashHooks(before_send=int(fault == "crash_before_send"),
                       after_response=int(fault == "crash_after_response"))
    if fault in ("commit_then_503", "fail_503_before"):
        env.arm(fault)
    unknowns, passes = [], 0
    for _ in range(6):  # bounded passes
        passes += 1
        try:
            steps = env.dispatcher(hooks=hooks).dispatch_once()
        except Crash:
            steps = []
        unknowns += [step.code or "" for step in steps if step.action == "unknown"]
        if env.row(execution)["state"] not in ("pending", "dispatched", "unknown"):
            break
        due(env)
    stored = ledger_record(env, execution)
    bodies = [] if stored.receipt is None else [stored.receipt.model_dump(mode="json")]
    return Trial(seed=seed, index=index, arm="ledger", fault=fault, final_state=stored.state, outcome=stored.outcome,
                 attempts=stored.attempts, reconcile_attempts=stored.reconcile_attempts, effects=env.effects(),
                 receipt_sha256=[hashlib.sha256(json_bytes(body)).hexdigest() for body in bodies], receipts=bodies,
                 unknowns=unknowns, crashes=list(hooks.fired), passes=passes)


NAIVE_SENDS = 3


def json_bytes(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def cleared_request(env: Env, refs: AuthorityRefs, client: RetailClient) -> Cleared:
    cleared = precheck(env.scope, refs, retail=client, sessions=PgSessionStore(env.app),
                       membership=PgMembership(env.app), clock=env.clock, decisions=PgDecisionStore(env.app),
                       history=LedgerHistory(env.app, env.run), evidence=PgEvidencePort(env.app))
    assert isinstance(cleared, Cleared), cleared
    return cleared


def run_naive_trial(env: Env, seed: int, index: int, fault: str) -> Trial:
    """The baseline: the same approved request and fault, no ledger, a new operation ID on every send, retried until
    a stored outcome (at most NAIVE_SENDS sends). A modelled crash loses the process's memory of what it sent."""
    refs = env.approve()
    if fault in ("commit_then_503", "fail_503_before"):
        env.arm(fault)
    unknowns: list[str] = []
    crashes: list[str] = []
    final, sends, passes = None, 0, 0
    with closing(env.client()) as client:
        request = cleared_request(env, refs, client).request
        while sends < NAIVE_SENDS and final is None:
            passes += 1
            if fault == "crash_before_send" and not crashes:
                crashes.append("before_send")
                continue
            sends += 1
            try:
                result = client.mutate(uuid4(), request)
            except Refused as refused:
                unknowns.append(f"refused_{refused.status}_{refused.code}")
                break
            if isinstance(result, Unknown):
                unknowns.append(result.reason)
                continue
            if fault == "crash_after_response" and not crashes:
                crashes.append("after_response")  # the result dies with the process; the restart resends
                continue
            final = result
    bodies = [] if final is None or final.receipt is None else [final.receipt.model_dump(mode="json")]
    state = "unknown" if final is None else "succeeded" if final.outcome == "committed" else "failed"
    return Trial(seed=seed, index=index, arm="naive_new_id", fault=fault, final_state=state,
                 outcome=None if final is None else final.outcome, attempts=sends, reconcile_attempts=0,
                 effects=env.effects(),
                 receipt_sha256=[hashlib.sha256(json_bytes(body)).hexdigest() for body in bodies],
                 receipts=bodies, unknowns=unknowns, crashes=crashes, passes=passes)


# -- C1 regressions -------------------------------------------------------------------------------------------------

def test_an_aborted_trial_is_reported_without_its_exception_message(tmp_path: Path,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    canary = f"diagnostic-canary-{uuid4().hex}"  # synthetic, not a credential; no database is used

    def broken(*args: object) -> Trial:
        raise RuntimeError(canary)

    monkeypatch.setattr(sys.modules[__name__], "fresh_case", lambda previous: previous)
    monkeypatch.setattr(sys.modules[__name__], "run_trial", broken)
    monkeypatch.setattr(sys.modules[__name__], "run_naive_trial", broken)
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setenv("POLICYOPS_REPORT_DIR", str(tmp_path))
    with pytest.raises(AssertionError):  # reported first, then the test fails: nothing is dropped
        test_seeded_fault_trials_keep_at_most_one_effect_and_a_receipt_for_every_effect(None, 3)  # type: ignore
    body = (tmp_path / "e04-t19" / "paired-3.json").read_bytes().decode("utf-8")
    trials = json.loads(body)["trials"]
    assert len(trials) == 8 and {trial["error"] for trial in trials} == {"RuntimeError"} and canary not in body

def test_a_foreign_operation_result_or_snapshot_cannot_settle_the_execution(env: Env) -> None:
    worker = env.dispatcher(hooks=CrashHooks(before_send=1)).executor
    execution = env.reserve(env.approve())
    with pytest.raises(Crash):
        worker.step(env.run.workspace_id, execution)
    original = ledger_record(env, execution)
    with closing(env.client()) as client:
        foreign_id = uuid4()
        foreign = client.fence(foreign_id, original.request)  # a genuine terminal result of another operation
        assert not isinstance(foreign, Unknown) and foreign.outcome == "fenced"
        snapshot = type(original).model_validate({**original.model_dump(mode="python"), "operation_id": foreign_id,
                                                  "operation_sha256": client.fingerprint(foreign_id, original.request)})
    for record, result in ((snapshot, foreign), (original, foreign), (snapshot, Unknown("late"))):
        with pytest.raises(ExecutionIntegrityError):
            worker.record(record, result, "fence")
    assert env.row(execution)["state"] == "dispatched" and env.effects() == 0
    due(env)
    assert env.dispatcher().dispatch_once()[0].state == "succeeded" and env.effects() == 1  # the real operation


def test_a_repeated_reservation_must_name_the_stored_run_and_references(env: Env) -> None:
    refs = env.approve()
    executor = env.dispatcher().executor
    first = executor.reserve(env.scope, refs)
    assert isinstance(first, Reserved) and first.created
    other = fresh_case(env)
    for scope, changed in ((env.scope, AuthorityRefs(refs.proposal_id, refs.proposal_version, uuid4(),
                                                     refs.approval_id)),
                           (env.scope, AuthorityRefs(refs.proposal_id, refs.proposal_version + 1, refs.consent_id,
                                                     refs.approval_id)),
                           (other.scope, refs)):
        with pytest.raises(IdempotencyConflict):
            executor.reserve(scope, changed)
    env.clock.advance(timedelta(days=2))  # past the approval: a replay neither renews it nor mints an operation
    again = executor.reserve(env.scope, refs)
    assert isinstance(again, Reserved) and not again.created
    assert again.execution.operation_id == first.execution.operation_id
    env.cancel_run()  # settle locally so no due row outlives the test
    assert env.dispatcher().dispatch_once()[0].state == "failed" and env.effects() == 0


@pytest.mark.parametrize("assignment", [
    "state = 'failed', outcome = NULL, resolved_by = 'response'",
    "state = 'failed', outcome = 'upstream_rejected', resolved_by = NULL",
    "state = 'failed', outcome = 'precheck_refused', resolved_by = 'precheck'",  # a local refusal after a send
    "state = 'reconciled', outcome = NULL, resolved_by = 'fence'",
    "state = 'succeeded', outcome = NULL, resolved_by = 'lookup', receipt = '{}'::jsonb",
    "state = 'succeeded', outcome = 'fenced', resolved_by = 'lookup', receipt = '{}'::jsonb",
])
def test_a_sent_operation_becomes_terminal_only_with_an_explicit_remote_outcome(env: Env, assignment: str) -> None:
    dispatcher = env.dispatcher(hooks=CrashHooks(before_send=1))
    execution = env.reserve(env.approve(), dispatcher)
    with pytest.raises(Crash):
        dispatcher.executor.step(env.run.workspace_id, execution)
    with pytest.raises(DBAPIError, match="tool_executions_outcome_rule"), \
            workspace_transaction(env.app, env.run.workspace_id) as conn:  # the actual runtime role
        conn.execute(text(f"UPDATE app.tool_executions SET {assignment}, claim_id = NULL, lease_owner = NULL, "  # noqa: S608
                          "lease_expires_at = NULL, next_attempt_at = NULL, version = version + 1 WHERE id = :id"),
                     {"id": execution})
    assert env.row(execution)["state"] == "dispatched"
    due(env)
    assert env.dispatcher().dispatch_once()[0].state == "succeeded" and env.effects() == 1


def test_a_worker_whose_claim_lapsed_during_lookup_sends_no_fence(env: Env) -> None:
    initial = env.dispatcher(hooks=CrashHooks(before_send=1))
    execution = env.reserve(env.approve(), initial)
    with pytest.raises(Crash):
        initial.executor.step(env.run.workspace_id, execution)
    due(env)
    fences: list[UUID] = []

    @contextmanager
    def slow_lookup(scope: GatewayScope) -> Iterator[Any]:
        with env.retail()(scope) as client:
            lookup, fence = client.lookup, client.fence

            def delayed(operation_id: UUID, request: Any) -> Any:
                found = lookup(operation_id, request)
                env.clock.advance(timedelta(hours=1))  # the claim and the approval lapse while the reply is awaited
                return found

            def counted(operation_id: UUID, request: Any, **kwargs: Any) -> Any:
                fences.append(operation_id)
                return fence(operation_id, request, **kwargs)

            client.lookup, client.fence = delayed, counted
            yield client

    stale = env.dispatcher().executor
    stale.retail = slow_lookup
    assert stale.step(env.run.workspace_id, execution).action == "lost_claim"
    assert fences == [] and env.row(execution)["state"] == "dispatched" and env.effects() == 0
    current = env.dispatcher().dispatch_once()  # a newly claimed worker fences after expiry: recovery, no effect
    assert [step.state for step in current] == ["reconciled"] and env.effects() == 0


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


def test_a_second_approval_on_the_order_waits_until_the_first_execution_is_resolved(env: Env) -> None:
    dispatcher = env.dispatcher(hooks=CrashHooks(before_send=1))
    first = env.reserve(env.approve(), dispatcher)
    with pytest.raises(Crash):
        dispatcher.executor.step(env.run.workspace_id, first)  # dispatched; its outcome is not known
    later = next_run(env)
    second = later.approve()  # a real second T18 approval of the same order, in the case's next run
    with pytest.raises(ledger.ExecutionInProgress):
        later.dispatcher().executor.reserve(later.scope, second)
    due(env)
    assert [step.state for step in env.dispatcher().dispatch_once()] == ["reconciled"] and env.effects() == 0
    execution = later.reserve(second)  # the target is free only once the first is proven to have no effect
    assert [step.state for step in later.dispatcher().dispatch_once()] == ["succeeded"] and env.effects() == 1
    assert env.row(execution)["attempts"] == 1


def test_a_delivered_order_is_refunded_once_and_not_exchanged_after_its_return(env: Env) -> None:
    env = fresh_case(env, customer=DELIVERED_CUSTOMER, order=DELIVERED)
    refs = env.approve(RETURN)
    execution = env.reserve(refs)
    env.arm("commit_then_503")  # the refund commits and its response is lost
    assert env.dispatcher().dispatch_once()[0].action == "unknown"
    due(env)
    assert [step.state for step in env.dispatcher().dispatch_once()] == ["succeeded"] and env.effects() == 1
    stored = ledger_record(env, execution)
    assert stored.receipt is not None and str(stored.receipt.tool) == "return_delivered_order_items"
    replay = env.dispatcher().executor.reserve(env.scope, refs)  # the same approval cannot refund twice
    assert isinstance(replay, Reserved) and not replay.created and replay.execution.id == execution
    later = next_run(env)
    proposals = ProposalService(app_engine=later.app, clock=FixedLeaseClock(later.clock))
    for call in (RETURN, EXCHANGE):  # neither a second return nor an exchange of the returned items is proposed
        with closing(later.client()) as client:
            collected = collect(client, later.scope, call, LedgerHistory(later.app, later.run))
        assert isinstance(collected, Collected), collected
        created = proposals.create(later.scope, call, collected, rationale="Customer asked again.")
        assert not isinstance(created, Created), created
    assert env.effects() == 1 and env.dispatcher().dispatch_once() == []
