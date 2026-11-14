"""T22 Slice B: real runtime-role PostgreSQL, real retail simulator, controlled clocks.

Collection has no container side effects; these cases run in the PostgreSQL suite (`pytest -m postgres`).
"""

from contextlib import closing
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from policyops.adapters.retail_client import Unknown
from policyops.auth.service import Authorized, SessionContext
from policyops.budget.config import Configuration
from policyops.domain.roles import Role
from policyops.gateway.facts import Collected, collect
from policyops.persistence import executions as ledger
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs as jobs
from policyops.persistence import runs as store
from policyops.persistence.database import workspace_transaction
from policyops.persistence.roles import WORKER_DISCOVERY
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.investigation import build_investigation_spec
from policyops.runtime.spec import RuntimeCatalog
from policyops.runtime.worker import build_worker
from policyops.services.cases import CaseService
from policyops.services.decisions import DecisionService
from policyops.services.execution import ExecutionLimits, LedgerHistory
from policyops.services.proposal_views import DecisionRequest
from policyops.services.proposals import Created, Presented, ProposalService
from policyops.services.review_outcomes import outcome_message_id
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retrieval import RetrievalConfig, RetrievalScope
from policyops_testing.agent_fakes import ScriptedModel, calls, fictional_policy
from policyops_testing.execution_faults import Crash as DispatchCrash
from policyops_testing.execution_faults import CrashHooks
from policyops_testing.retrieval_fixtures import TOKENIZER, Embeddings
from tests.integration import test_execution_retail as execution_tests
from tests.integration.test_execution_retail import CANCEL, Env
from tests.integration.test_proposal_decisions import grant, principal
from tests.integration.test_review_continuation import Crash, job_of, run_state, runtime, waiting


pytestmark = pytest.mark.postgres
env = execution_tests.env
live = execution_tests.live


def authorized(env: Env, actor: UUID, role: Role) -> Authorized:
    return Authorized(session=SessionContext(session_id=uuid4(), principal_id=actor,
        workspace_id=env.run.workspace_id, expires_at=env.clock.now()+timedelta(hours=1), csrf_sha256="0"*64),
        workspace_id=env.run.workspace_id, roles=frozenset({role}))


def presented(env: Env) -> ActionProposal:
    waiting(env)
    with closing(env.client()) as client:
        facts = collect(client, env.scope, CANCEL, LedgerHistory(env.app, env.run))
    assert isinstance(facts, Collected)
    service = ProposalService(env.app, FixedLeaseClock(env.clock))
    created = service.create(env.scope, CANCEL, facts, rationale="Customer asked to cancel.")
    assert isinstance(created, Created)
    assert isinstance(service.present(env.run, created.proposal.proposal_id,
                                      created.proposal.proposal_version), Presented)
    return created.proposal


def post(env: Env, source: Any = "operator_entered_customer", text_value: str = "Yes, please.") -> UUID:
    operator = principal(env.db, "customer-entry")
    grant(env.db, env.run.workspace_id, operator, "analyst")
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        case = repo.get_case(connection, env.run.case_id)
        assert case is not None
    result = CaseService(env.app, env.clock, FixedLeaseClock(env.clock)).post_message(
        authorized(env, operator, Role.ANALYST), key=f"reply-{uuid4().hex}", case_id=env.run.case_id,
        expected_version=case.version, source=source, text_value=text_value)
    assert result.status == 201 and result.message_id is not None
    return result.message_id


def decide(env: Env, proposal: ActionProposal) -> None:
    DecisionService(env.app, FixedLeaseClock(env.clock)).decide(authorized(env, env.reviewer, Role.REVIEWER),
        proposal.proposal_id, DecisionRequest(proposal_version=proposal.proposal_version,
            action_digest=proposal.action_digest, decision="approve", reason="Checked the request and policy."))


def outcomes(env: Env) -> list[store.Job]:
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        ids = connection.execute(text("SELECT id FROM app.jobs WHERE run_id = :r AND review_trigger = 'outcome' "
                                       "ORDER BY execution_version"), {"r": env.run.run_id}).scalars()
        result = [store.get_job(connection, identity) for identity in ids]
    assert all(item is not None for item in result)
    return [item for item in result if item is not None]


def current(env: Env) -> Any:
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        rows = ledger.case_executions(connection, env.run.case_id)
        assert len(rows) == 1
        return rows[0]


def messages(env: Env) -> list[str]:
    with env.db.superuser() as connection:
        return [row[0] for row in connection.execute(
            "SELECT m.text FROM app.case_messages m JOIN app.run_events e ON "
            "e.payload->>'message_id' = m.id::text WHERE e.run_id = %s AND e.event_type = 'review.outcome' "
            "ORDER BY e.sequence", (env.run.run_id,)).fetchall()]


def reserved(env: Env) -> Any:
    env.approve()
    waiting(env)
    handler = runtime(env)
    assert handler.process(job_of(env).id, env.run.workspace_id, uuid4())
    return handler


def capped(env: Env) -> tuple[Any, Any]:
    handler = reserved(env)
    executor = env.dispatcher(hooks=CrashHooks(after_response=1),
                              limits=ExecutionLimits(max_reconciles=1)).executor
    with pytest.raises(DispatchCrash):
        executor.step(env.run.workspace_id, current(env).id)
    dispatched = current(env)
    assert env.effects() == 1
    assert executor.record(dispatched, Unknown("unreachable"), "fence").action == "capped"
    return handler, dispatched


def late_receipt(env: Env, handler: Any, dispatched: Any) -> None:
    with closing(env.client()) as client:
        found = client.lookup(dispatched.operation_id, dispatched.request)
    assert not isinstance(found, Unknown) and found.result is not None
    assert handler.executor.record(dispatched, found.result, "lookup").state == "succeeded"


def test_operator_reply_approval_dispatch_and_actual_receipt_summary(env: Env) -> None:
    proposal = presented(env)
    reply = post(env)
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        consent = repo.get_consent(connection, proposal.proposal_id, proposal.proposal_version)
        assert consent is not None and consent.customer_message_id == reply
        assert consent.message_source == "operator_entered_customer"
    decide(env, proposal)
    handler = runtime(env)
    assert handler.process(job_of(env).id, env.run.workspace_id, uuid4())
    assert run_state(env) == "reconciling" and env.effects() == 0 and outcomes(env) == []
    executor = env.dispatcher().executor
    assert executor.step(env.run.workspace_id, current(env).id).state == "succeeded"
    row = current(env)
    assert row.receipt is not None
    assert handler.process(outcomes(env)[0].id, env.run.workspace_id, uuid4())
    assert env.effects() == 1 and run_state(env) == "succeeded"
    [summary] = messages(env)
    assert row.receipt.operation_id in summary and row.receipt.committed_at.isoformat() in summary
    assert f"{row.receipt.case_version_before} -> {row.receipt.case_version_after}" in summary
    assert not handler.process(outcomes(env)[0].id, env.run.workspace_id, uuid4())


@pytest.mark.parametrize("source,text_value,expired,reason", [
    ("staff_note", "yes", False, None),
    ("operator_entered_customer", "yes if it is free", False, "ambiguous_reply"),
    ("operator_entered_customer", "yes", True, "expired"),
])
def test_consent_capture_ignores_notes_and_clarifies_ambiguity_or_expiry(
        env: Env, source: str, text_value: str, expired: bool, reason: str | None) -> None:
    proposal = presented(env)
    if expired:
        env.clock.advance(proposal.expires_at-env.clock.now())
    post(env, source, text_value)
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        assert repo.get_consent(connection, proposal.proposal_id, proposal.proposal_version) is None
        reasons = connection.execute(text("SELECT payload->>'reason' FROM app.run_events WHERE run_id = :r "
            "AND event_type = 'consent.clarification_requested'"), {"r": env.run.run_id}).scalars().all()
        assert reasons == ([] if reason is None else [reason])
    assert env.effects() == 0


def test_consent_and_customer_message_roll_back_together(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    proposal = presented(env)
    original = repo.record_consent

    def crash(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        raise Crash()

    monkeypatch.setattr(repo, "record_consent", crash)
    with pytest.raises(Crash):
        post(env)
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        assert repo.get_consent(connection, proposal.proposal_id, proposal.proposal_version) is None
        assert connection.execute(text("SELECT count(*) FROM app.case_messages WHERE case_id = :c AND "
            "source = 'operator_entered_customer'"), {"c": env.run.case_id}).scalar_one() == 0


def test_remote_ambiguity_has_no_summary_until_truth_is_known(env: Env) -> None:
    handler = reserved(env)
    env.arm("commit_then_503")
    assert env.dispatcher().executor.step(env.run.workspace_id, current(env).id).state == "unknown"
    assert outcomes(env) == [] and messages(env) == [] and run_state(env) == "reconciling"
    execution_tests.due(env)
    env.dispatcher().executor.step(env.run.workspace_id, current(env).id)
    assert handler.process(outcomes(env)[0].id, env.run.workspace_id, uuid4())
    assert "Action committed" in messages(env)[0] and env.effects() == 1


def test_capped_unknown_summary_and_late_receipt_correction(env: Env) -> None:
    handler, dispatched = capped(env)
    assert handler.process(outcomes(env)[0].id, env.run.workspace_id, uuid4())
    [unknown] = messages(env)
    assert "unconfirmed" in unknown and "requires reconciliation" in unknown
    assert not any(word in unknown.lower() for word in ("success", "completed", "committed"))
    assert run_state(env) == "reconciling"
    late_receipt(env, handler, dispatched)
    assert handler.process(outcomes(env)[1].id, env.run.workspace_id, uuid4())
    assert len(messages(env)) == 2 and "Action committed" in messages(env)[1]
    assert run_state(env) == "succeeded" and env.effects() == 1


def test_obsolete_and_duplicate_wakeups_coalesce_to_current_truth(env: Env) -> None:
    handler, dispatched = capped(env)
    late_receipt(env, handler, dispatched)
    old, new = outcomes(env)
    assert handler.process(old.id, env.run.workspace_id, uuid4())
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        before = repo.get_case(connection, env.run.case_id)
        assert jobs.enqueue_outcome(connection, current(env)) == new.id
    assert handler.process(new.id, env.run.workspace_id, uuid4())
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        assert repo.get_case(connection, env.run.case_id) == before
        assert jobs.enqueue_outcome(connection, current(env)) == new.id
    assert not handler.process(new.id, env.run.workspace_id, uuid4())
    assert len(messages(env)) == 1 and "Action committed" in messages(env)[0] and env.effects() == 1


@pytest.mark.parametrize("after_commit", [False, True])
def test_summary_crash_before_or_after_commit_is_atomic_and_replay_safe(
        env: Env, monkeypatch: pytest.MonkeyPatch, after_commit: bool) -> None:
    handler = reserved(env)
    env.dispatcher().executor.step(env.run.workspace_id, current(env).id)
    work = outcomes(env)[0]
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        before = repo.get_case(connection, env.run.case_id)
    if after_commit:
        finish = handler.finish

        def crash_after(*args: Any, **kwargs: Any) -> None:
            finish(*args, **kwargs)
            raise Crash()

        monkeypatch.setattr(handler, "finish", crash_after)
    else:
        end = store.end_job

        def crash_before(*args: Any, **kwargs: Any) -> None:
            end(*args, **kwargs)  # every summary/state write has happened, but COMMIT has not
            raise Crash()

        monkeypatch.setattr(store, "end_job", crash_before)
    with pytest.raises(Crash):
        handler.process(work.id, env.run.workspace_id, uuid4())
    assert len(messages(env)) == int(after_commit)
    assert run_state(env) == ("succeeded" if after_commit else "reconciling")
    if not after_commit:
        with workspace_transaction(env.app, env.run.workspace_id) as connection:
            assert repo.get_case(connection, env.run.case_id) == before
    monkeypatch.undo()
    env.clock.advance(jobs.LEASE+timedelta(seconds=1))
    runtime(env).process(work.id, env.run.workspace_id, uuid4())
    assert len(messages(env)) == 1 and outcomes(env)[0].state == "done" and env.effects() == 1


@pytest.mark.parametrize("after_remote_commit", [False, True])
def test_cancel_after_dispatch_or_commit_preserves_cancellation_and_appends_truth(
        env: Env, after_remote_commit: bool) -> None:
    handler = reserved(env)
    hooks = CrashHooks(after_response=int(after_remote_commit), before_send=int(not after_remote_commit))
    with pytest.raises(DispatchCrash):
        env.dispatcher(hooks=hooks).executor.step(env.run.workspace_id, current(env).id)
    env.cancel_run()
    execution_tests.due(env)
    env.dispatcher().executor.step(env.run.workspace_id, current(env).id)
    assert current(env).state == ("succeeded" if after_remote_commit else "reconciled")
    # Delivery still works past the execution deadline and with all staff authority revoked.
    env.clock.advance(timedelta(hours=3))
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        assert repo.revoke_membership(connection, env.membership, env.clock.now())
    assert handler.process(outcomes(env)[0].id, env.run.workspace_id, uuid4())
    assert run_state(env) == "cancelled" and env.effects() == int(after_remote_commit)
    assert ("Action committed" if after_remote_commit else "No business effect committed") in messages(env)[0]


def test_integrity_mismatch_retries_delivery_then_dead_letters_without_changing_run(env: Env) -> None:
    handler = reserved(env)
    env.dispatcher().executor.step(env.run.workspace_id, current(env).id)
    row, work = current(env), outcomes(env)[0]
    identity = outcome_message_id(row.workspace_id, row.run_id, row.id, row.version)
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        assert repo.lock_case(connection, env.run.case_id) is not None
        repo.append_message(connection, message_id=identity, scope=env.scope.binding.scope, source="agent",
                            entered_by=None, text_value="Different bytes", created_at=env.clock.now())
    for _ in range(jobs.MAX_ATTEMPTS):
        assert handler.process(work.id, env.run.workspace_id, uuid4())
        env.clock.advance(timedelta(minutes=6))
    assert outcomes(env)[0].state == "dead" and messages(env) == []
    assert run_state(env) == "reconciling" and env.effects() == 1


@pytest.mark.parametrize("exhausted", ["deadline", "attempts"])
def test_projection_delivery_exhaustion_keeps_evidence_and_does_not_fail_run(env: Env, exhausted: str) -> None:
    handler = reserved(env)
    env.dispatcher().executor.step(env.run.workspace_id, current(env).id)
    work = outcomes(env)[0]
    if exhausted == "deadline":
        env.clock.advance(jobs.DELIVERY_TIMEOUT)
    else:
        with workspace_transaction(env.app, env.run.workspace_id) as connection:
            connection.execute(text("UPDATE app.jobs SET attempts = max_attempts WHERE id = :id"), {"id": work.id})
    assert not handler.process(work.id, env.run.workspace_id, uuid4())
    assert outcomes(env)[0].state == "dead" and messages(env) == [] and run_state(env) == "reconciling"


def test_full_investigation_to_customer_consent_staff_approval_dispatch_and_summary(env: Env) -> None:
    model = ScriptedModel([calls("cancel_pending_order", {"order_id": env.order, "reason": "no longer needed"})])
    # One owned client for the graph's read-only port; the dispatcher owns its separate mutation client.
    with closing(env.client()) as client:
        spec = build_investigation_spec(env="test", engine=env.app, configuration=Configuration(),
            policy=fictional_policy(), retrieval_scope=RetrievalScope(corpus_key="test-retail"),
            retrieval_config=RetrievalConfig(mode="lexical"), bindings=(env.scope.binding,),
            fixture_sha256=env.scope.fixture_sha256, retail=lambda scope: client,
            providers=Embeddings().providers(), tokenizer=TOKENIZER, clock=FixedLeaseClock(env.clock),
            wall_clock=env.clock, test_model=lambda ledger, run: model)
        # Fixture's run is not started yet. Install its server-owned runtime identity before creating its job.
        with env.db.superuser() as connection:
            connection.execute("UPDATE app.runs SET initiated_by = %s, graph_sha256 = %s, prompt_sha256 = %s, "
                "config_sha256 = %s WHERE id = %s", (env.reviewer, spec.graph_sha256, spec.prompt_sha256,
                                                     spec.config_sha256, env.run.run_id))
        with workspace_transaction(env.app, env.run.workspace_id) as connection:
            repo.append_message(connection, message_id=uuid4(), scope=env.scope.binding.scope, source="seeded",
                entered_by=None, text_value="Please cancel my pending order.", created_at=env.clock.now())
            run = store.get_run(connection, env.run.run_id)
            assert run is not None
            execute_id = store.create_execute_job(connection, run, max_attempts=3, now=env.clock.now())
        handler = runtime(env)
        worker = build_worker(env="test", app_engine=env.app, discovery_engine=env.db.engine(WORKER_DISCOVERY),
            clock=handler.executor.clock, catalog=RuntimeCatalog.of([spec], default=spec.spec_id), review=handler)
        assert worker.process(execute_id, env.run.workspace_id)
    assert run_state(env) == "waiting_approval"
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        [row] = repo.presented_rows_of_run(connection, env.run.run_id)
        proposal = repo.get_proposal(connection, row.proposal_id, row.proposal_version)
        assert proposal is not None
    post(env)
    decide(env, proposal)
    assert worker.process(job_of(env).id, env.run.workspace_id)
    assert run_state(env) == "reconciling"
    assert env.dispatcher().executor.step(env.run.workspace_id, current(env).id).state == "succeeded"
    assert worker.process(outcomes(env)[0].id, env.run.workspace_id)
    assert run_state(env) == "succeeded" and env.effects() == 1 and len(messages(env)) == 1
    assert len(model.requests) == 1  # review, dispatch and summary do not return to the model
