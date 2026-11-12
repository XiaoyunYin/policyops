"""T22 Slice A against actual runtime/discovery roles and the owned retail simulator.

No Docker work occurs at import/collection. BaseException simulates process death;
the subsequent claimant must recover the same durable reservation.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text

from policyops.adapters.retail_client import Unknown
from policyops.auth.service import AuthError, Authorized, SessionContext
from policyops.domain.roles import Role
from policyops.gateway import precheck as precheck_module
from policyops.gateway.precheck import AuthorityRefs, Cleared
from policyops.persistence import executions as ledger
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs as jobs
from policyops.persistence import runs as store
from policyops.persistence.database import workspace_transaction
from policyops.persistence.roles import WORKER_DISCOVERY
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.review import ReviewRuntime, build_review_runtime
from policyops.runtime.worker import build_worker
from policyops.services.decisions import DecisionService
from policyops.services.execution import Reserved
from policyops.services.proposal_views import DecisionRequest
from policyops.services.review_outcomes import refusal_message_id
from policyops_contracts.policy import RETAIL_POLICY
from tests.integration import test_execution_retail as execution_tests
from tests.integration.test_execution_retail import Env
from tests.integration.test_proposal_decisions import grant, principal


pytestmark = pytest.mark.postgres
env = execution_tests.env
live = execution_tests.live


class Crash(BaseException):
    pass


def runtime(env: Env) -> ReviewRuntime:
    ports = env.dispatcher().executor
    return build_review_runtime(env="test", app_engine=env.app, bindings=(env.scope.binding,),
        fixture_sha256=env.scope.fixture_sha256, retail_origin=env.origin, retail_key=env.service.key,
        clock=FixedLeaseClock(env.clock), scopes=ports.scopes, retail=ports.retail)


def waiting(env: Env) -> None:
    with env.db.superuser() as connection:  # fixture setup only; normal run start sets this immutable identity
        connection.execute("UPDATE app.runs SET initiated_by = %s WHERE id = %s", (env.reviewer, env.run.run_id))
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        run = store.get_run(connection, env.run.run_id, lock=True)
        assert run is not None
        store.set_state(connection, run, "waiting_approval", env.clock.now())


def job_of(env: Env, trigger: str = "decision") -> store.Job:
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        job_id = connection.execute(text("SELECT id FROM app.jobs WHERE run_id = :r AND review_trigger = :t"),
                                    {"r": env.run.run_id, "t": trigger}).scalar_one()
        result = store.get_job(connection, job_id)
        assert result is not None
        return result


def execution(env: Env, refs: AuthorityRefs) -> Any:
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        return ledger.by_approval(connection, refs.approval_id)


def run_state(env: Env) -> str:
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        result = store.get_run(connection, env.run.run_id)
        assert result is not None
        return result.state


def summary(env: Env, job: store.Job) -> str | None:
    with env.db.superuser() as connection:
        row = connection.execute("SELECT text FROM app.case_messages WHERE id = %s",
                                 (refusal_message_id(env.run.workspace_id, env.run.run_id, job.id),)).fetchone()
        return None if row is None else str(row[0])


def test_identical_decision_and_concurrent_job_replay_reserve_once(env: Env) -> None:
    refs = env.approve()
    waiting(env)
    handler = runtime(env)
    job = job_of(env)
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        decision = repo.decision_by_id(connection, env.run, refs.approval_id)
        assert decision is not None
    authorized = Authorized(session=SessionContext(session_id=uuid4(), principal_id=env.reviewer,
        workspace_id=env.run.workspace_id, expires_at=env.clock.now()+timedelta(hours=1), csrf_sha256="0"*64),
        workspace_id=env.run.workspace_id, roles=frozenset({Role.REVIEWER}))
    for _ in range(2):
        result = DecisionService(env.app, handler.executor.clock).decide(authorized, refs.proposal_id,
            DecisionRequest(proposal_version=refs.proposal_version, action_digest=decision.action_digest,
                            decision="approve", reason=decision.reason))
        assert result.replayed and job_of(env).id == job.id
    with pytest.raises(AuthError) as error:
        DecisionService(env.app, handler.executor.clock).decide(authorized, refs.proposal_id,
            DecisionRequest(proposal_version=refs.proposal_version, action_digest=decision.action_digest,
                            decision="reject", reason="Conflicting decision."))
    assert error.value.status == 409 and job_of(env).id == job.id and run_state(env) == "waiting_approval"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: handler.process(job.id, env.run.workspace_id, uuid4()), range(2)))
    assert sum(results) == 1
    assert execution(env, refs) is not None and job_of(env).state == "done"
    assert run_state(env) == "reconciling" and env.effects() == 0 and summary(env, job) is None
    assert not handler.process(job.id, env.run.workspace_id, uuid4())
    with env.db.superuser() as connection:
        assert connection.execute("SELECT count(*) FROM app.tool_executions WHERE run_id = %s",
                                  (env.run.run_id,)).fetchone() == (1,)


@pytest.mark.parametrize("after_reservation", [False, True])
def test_crash_around_reservation_recovers_one_operation(env: Env, after_reservation: bool,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    refs = env.approve()
    waiting(env)
    handler = runtime(env)
    job = job_of(env)
    reserve = handler.executor.reserve

    def crash(*args: Any, **kwargs: Any) -> Any:
        if after_reservation:
            reserve(*args, **kwargs)
        raise Crash()

    monkeypatch.setattr(handler.executor, "reserve", crash)
    with pytest.raises(Crash):
        handler.process(job.id, env.run.workspace_id, uuid4())
    before = execution(env, refs)
    assert (before is not None) == after_reservation
    assert job_of(env).state == "leased"
    env.clock.advance(jobs.LEASE + timedelta(seconds=1))
    restarted = runtime(env)
    assert restarted.process(job.id, env.run.workspace_id, uuid4())
    recovered = execution(env, refs)
    assert recovered is not None and job_of(env).state == "done" and env.effects() == 0
    if before is not None:
        assert (recovered.id, recovered.operation_id) == (before.id, before.operation_id)


def test_decision_before_graph_finish_defers_without_consuming_attempt_or_generation(env: Env) -> None:
    env.approve()
    waiting(env)
    handler = runtime(env)
    job = job_of(env)
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        run = store.get_run(connection, env.run.run_id, lock=True)
        assert run is not None
        run = store.set_state(connection, run, "running", env.clock.now())
        execute_id = store.create_execute_job(connection, run, max_attempts=3, now=env.clock.now())
        execute_job = store.get_job(connection, execute_id, lock=True)
        assert execute_job is not None
        graph_token = store.claim(connection, run, execute_job, owner=uuid4(), lease=jobs.LEASE, now=env.clock.now())
    assert not handler.process(job.id, env.run.workspace_id, uuid4())
    assert job_of(env).attempts == 0 and run_state(env) == "running"
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        run, graph_job, now = store.check_fence(connection, graph_token, handler.executor.clock)
        store.set_state(connection, run, "waiting_approval", now, bump_generation=True)
        store.end_job(connection, graph_job, state="done", now=now)
    env.clock.advance(timedelta(seconds=3))
    assert handler.process(job.id, env.run.workspace_id, uuid4())
    assert job_of(env).state == "done" and run_state(env) == "reconciling" and env.effects() == 0


@pytest.mark.parametrize("cancel_after_claim", [False, True])
def test_cancellation_before_reservation_preserves_cancelled_run(env: Env, cancel_after_claim: bool) -> None:
    refs = env.approve()
    waiting(env)
    handler = runtime(env)
    job = job_of(env)
    if cancel_after_claim:
        token = handler.claim(job.id, env.run.workspace_id, uuid4())
        assert token is not None
        env.cancel_run()
        with pytest.raises(store.Fenced):
            handler.execute(token)
        env.clock.advance(jobs.LEASE + timedelta(seconds=1))
    else:
        env.cancel_run()
    assert handler.process(job.id, env.run.workspace_id, uuid4())
    assert run_state(env) == "cancelled" and execution(env, refs) is None and env.effects() == 0
    assert "No action was executed" in (summary(env, job) or "")


def test_worker_routes_review_without_runtime_catalog_and_expiry_is_superseded(env: Env) -> None:
    refs = env.approve()
    waiting(env)
    handler = runtime(env)
    worker = build_worker(env="test", app_engine=env.app, discovery_engine=env.db.engine(WORKER_DISCOVERY),
                          clock=handler.executor.clock, review=handler)
    assert worker.process(job_of(env).id, env.run.workspace_id)
    assert execution(env, refs) is not None
    expiry = job_of(env, "expiry")
    env.clock.advance(expiry.available_at-env.clock.now())
    assert not worker.process(expiry.id, env.run.workspace_id)
    assert job_of(env, "expiry").last_error_code == "superseded_by_decision"
    assert run_state(env) == "reconciling" and summary(env, expiry) is None


def test_cancel_during_precheck_cannot_insert_new_reservation(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    refs = env.approve()
    waiting(env)
    handler = runtime(env)
    token = handler.claim(job_of(env).id, env.run.workspace_id, uuid4())
    assert token is not None
    original = handler.executor._precheck

    def cancel(*args: Any, **kwargs: Any) -> Any:
        cleared = original(*args, **kwargs)
        env.cancel_run()
        return cleared

    monkeypatch.setattr(handler.executor, "_precheck", cancel)
    with pytest.raises(store.Fenced):
        handler.execute(token)
    assert execution(env, refs) is None and env.effects() == 0


def test_run_deadline_at_dispatch_checkpoint_refuses_even_a_cleared_precheck(env: Env) -> None:
    from policyops_testing.execution_faults import CrashHooks

    refs = env.approve()
    execution_id = env.reserve(refs)

    def pass_deadline(record: Any) -> None:
        with workspace_transaction(env.app, env.run.workspace_id) as connection:
            run = store.get_run(connection, env.run.run_id)
            assert run is not None
        env.clock.advance(run.deadline_at-env.clock.now())

    # The execution lease also needs to outlast the test's deadline boundary.
    with env.db.superuser() as connection:
        connection.execute("UPDATE app.runs SET deadline_at = %s WHERE id = %s",
                           (env.clock.now()+timedelta(seconds=1), env.run.run_id))
    step = env.dispatcher(hooks=CrashHooks(before_checkpoint=pass_deadline)).executor.step(
        env.run.workspace_id, execution_id)
    assert step.state == "failed" and step.code == "run_deadline_exceeded" and env.effects() == 0


@pytest.mark.parametrize("fault", ["superseded", "tampered", "policy", "reviewer_revoked", "consent_expired",
                                   "resource_changed", "initiator_revoked"])
def test_changed_authority_is_refused_without_a_new_execution(env: Env, fault: str,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    if fault == "consent_expired":
        original_record = repo.record_consent

        def shorter(connection: Any, consent: Any) -> None:
            # A valid shorter consent window, persisted before the decision is made.
            original_record(connection, type(consent).model_validate(consent.model_dump() | {
                "expires_at": consent.confirmed_at + timedelta(seconds=5)}))

        monkeypatch.setattr(repo, "record_consent", shorter)
    refs = env.approve()
    waiting(env)
    handler, job = runtime(env), job_of(env)
    expected_effects = 0
    if fault == "superseded":
        with workspace_transaction(env.app, env.run.workspace_id) as connection:
            repo.set_proposal_status(connection, env.run.workspace_id, refs.proposal_id, refs.proposal_version,
                                     "superseded")
    elif fault == "tampered":
        with env.db.superuser() as connection:
            connection.execute("ALTER TABLE app.action_proposals DISABLE TRIGGER action_proposals_guard")
            try:
                connection.execute("UPDATE app.action_proposals SET body = jsonb_set(body, '{rationale}', "
                                   "'\"tampered\"') WHERE run_id = %s", (env.run.run_id,))
            finally:
                connection.execute("ALTER TABLE app.action_proposals ENABLE TRIGGER action_proposals_guard")
    elif fault == "policy":
        monkeypatch.setattr(precheck_module, "RETAIL_POLICY", RETAIL_POLICY.model_copy(update={"sha256": "f"*64}))
    elif fault in ("reviewer_revoked", "initiator_revoked"):
        if fault == "reviewer_revoked":
            starter = principal(env.db, "starter")
            grant(env.db, env.run.workspace_id, starter, "analyst")
            with env.db.superuser() as connection:
                connection.execute("UPDATE app.runs SET initiated_by = %s WHERE id = %s", (starter, env.run.run_id))
        with workspace_transaction(env.app, env.run.workspace_id) as connection:
            assert repo.revoke_membership(connection, env.membership, env.clock.now())
    elif fault == "consent_expired":
        env.clock.advance(timedelta(seconds=6))
    elif fault == "resource_changed":
        # A separate writer changes the actual simulator state, outside this ledger.
        with handler.executor.retail(env.scope) as client:
            cleared = handler.executor._precheck(env.scope, None, refs, client)
            assert isinstance(cleared, Cleared)
            result = client.mutate(uuid4(), cleared.request)
            assert not isinstance(result, Unknown) and result.outcome == "committed"
        expected_effects = 1
    assert handler.process(job.id, env.run.workspace_id, uuid4())
    assert execution(env, refs) is None and env.effects() == expected_effects
    assert run_state(env) == "failed" and job_of(env).state == "done"
    assert "No action was executed" in (summary(env, job) or "")


def test_exhaustion_after_reservation_and_cancellation_never_claims_no_effect(env: Env) -> None:
    refs = env.approve()
    waiting(env)
    handler, job = runtime(env), job_of(env)
    token = handler.claim(job.id, env.run.workspace_id, uuid4())
    assert token is not None
    reserved = handler.execute(token)  # commit reservation, abandon job finish
    assert isinstance(reserved, Reserved)
    env.cancel_run()
    env.clock.advance(timedelta(hours=3))  # authority and run deadlines have passed; delivery still live
    with workspace_transaction(env.app, env.run.workspace_id) as connection:
        connection.execute(text("UPDATE app.jobs SET attempts = max_attempts WHERE id = :id"), {"id": job.id})
    assert not runtime(env).process(job.id, env.run.workspace_id, uuid4())
    recovered = execution(env, refs)
    assert recovered is not None and recovered.operation_id == reserved.execution.operation_id
    assert job_of(env).state == "done" and summary(env, job) is None and run_state(env) == "cancelled"
