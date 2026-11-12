"""Review migration, scoped bindings, tombstones, rejection and no-consent expiry on PostgreSQL."""

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from psycopg import errors
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.domain.consent_rules import Consented
from policyops.gateway.ports import GatewayScope
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs as jobs
from policyops.persistence import runs as store
from policyops.persistence.database import workspace_transaction
from policyops.persistence.migrate import head
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.records import NewCase, NewRun
from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.review import ReviewRuntime, build_review_runtime
from policyops.runtime.spec import AwaitingApproval
from policyops.runtime.worker import Context
from policyops.services.execution import RetailOperations
from policyops.services.proposals import Presented
from policyops.services.review_outcomes import refusal_message_id
from policyops_contracts.scalars import RunScope
from policyops_testing.app_database import AppCluster, NewDatabase
from policyops_testing.gateway_cases import FakeRetail, state
from tests.integration import test_proposal_evidence as evidence_tests
from tests.integration.test_investigation import scenario
from tests.integration.test_proposal_decisions import Tenant, ask, consented, created, tenant


pytestmark = pytest.mark.postgres
cited = evidence_tests.cited


def waiting(t: Tenant) -> None:
    with t.db.superuser() as connection:
        connection.execute("UPDATE app.runs SET initiated_by = %s WHERE id = %s", (t.analyst, t.run.run_id))
    with workspace_transaction(t.engine, t.run.workspace_id) as connection:
        run = store.get_run(connection, t.run.run_id, lock=True)
        assert run is not None
        store.set_state(connection, run, "waiting_approval", t.clock.now())


def no_retail(t: Tenant) -> ReviewRuntime:
    class Scopes:
        def scope(self, run: RunScope) -> Any:
            raise AssertionError("refusal must not resolve a retail scope")

    def retail(scope: Any) -> AbstractContextManager[RetailOperations]:
        raise AssertionError("refusal must not contact a provider")

    return build_review_runtime(env="test", app_engine=t.engine, bindings=(), fixture_sha256="0"*64,
        retail_origin="http://127.0.0.1:1", retail_key=b"x"*32, clock=FixedLeaseClock(t.clock),
        scopes=Scopes(), retail=retail)


def job_of(t: Tenant, trigger: str) -> store.Job:
    with workspace_transaction(t.engine, t.run.workspace_id) as connection:
        identity = connection.execute(text("SELECT id FROM app.jobs WHERE run_id = :r AND review_trigger = :t"),
                                      {"r": t.run.run_id, "t": trigger}).scalar_one()
        job = store.get_job(connection, identity)
        assert job is not None
        return job


@pytest.mark.parametrize("run_status", ["live", "deadline", "cancelled"])
def test_recorded_reject_is_atomic_refusal_and_replay_does_not_append(new_app_database: NewDatabase,
                                                                   run_status: str) -> None:
    t = tenant(new_app_database("t22_reject"))
    proposal = consented(t)
    waiting(t)
    decision = t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal, decision="reject"))
    if run_status == "deadline":
        t.clock.advance(timedelta(hours=3))
    elif run_status == "cancelled":
        with workspace_transaction(t.engine, t.run.workspace_id) as connection:
            run = store.get_run(connection, t.run.run_id, lock=True)
            assert run is not None
            store.set_state(connection, run, "cancelled", t.clock.now(), bump_generation=True)
    handler, job = no_retail(t), job_of(t, "decision")
    assert handler.process(job.id, t.run.workspace_id, uuid4())
    assert job_of(t, "decision").last_error_code == "review_rejected"
    assert t.value("SELECT state FROM app.runs WHERE id = %s", t.run.run_id) == (
        "cancelled" if run_status == "cancelled" else "failed")
    identity = refusal_message_id(t.run.workspace_id, t.run.run_id, job.id)
    assert "review_rejected" in t.value("SELECT text FROM app.case_messages WHERE id = %s", identity)
    before = t.value("SELECT version FROM app.cases WHERE id = %s", t.run.case_id)
    assert t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id,
                              ask(proposal, decision="reject")).decision == decision.decision
    assert not handler.process(job.id, t.run.workspace_id, uuid4())
    assert t.value("SELECT version FROM app.cases WHERE id = %s", t.run.case_id) == before
    assert t.count("SELECT count(*) FROM app.tool_executions WHERE run_id = %s", t.run.run_id) == 0
    assert t.count("SELECT count(*) FROM app.run_events WHERE run_id = %s AND event_type = 'case.message_posted'",
                   t.run.run_id) == 2  # presentation and refusal; each also has a durable outbox intent
    assert t.count("SELECT count(*) FROM app.outbox_events WHERE run_id = %s", t.run.run_id) == t.count(
        "SELECT count(*) FROM app.run_events WHERE run_id = %s", t.run.run_id)


@pytest.mark.parametrize("deadline_first", [False, True])
def test_no_consent_expiry_ends_without_a_decision_or_provider(new_app_database: NewDatabase,
                                                            deadline_first: bool) -> None:
    t = tenant(new_app_database("t22_expiry"))
    proposal = created(t)
    if deadline_first:
        with t.db.superuser() as connection:
            connection.execute("UPDATE app.runs SET deadline_at = %s WHERE id = %s",
                               (t.clock.now()+timedelta(seconds=30), t.run.run_id))
    assert isinstance(t.proposals().present(t.run, proposal.proposal_id, 1), Presented)
    waiting(t)
    job = job_of(t, "expiry")
    assert not no_retail(t).process(job.id, t.run.workspace_id, uuid4())  # not due
    t.clock.advance(job.available_at-t.clock.now())
    assert no_retail(t).process(job.id, t.run.workspace_id, uuid4())
    assert job_of(t, "expiry").last_error_code == ("run_deadline_exceeded" if deadline_first else "proposal_expired")
    assert t.value("SELECT state FROM app.runs WHERE id = %s", t.run.run_id) == "failed"
    assert t.count("SELECT count(*) FROM app.approval_decisions WHERE run_id = %s", t.run.run_id) == 0
    assert t.count("SELECT count(*) FROM app.tool_executions WHERE run_id = %s", t.run.run_id) == 0


@pytest.mark.parametrize("allow_data_loss", [False, True])
def test_completed_tombstone_refuses_downgrade_even_with_override(new_app_database: NewDatabase,
                                                                allow_data_loss: bool) -> None:
    t = tenant(new_app_database("t22_tombstone"))
    proposal = consented(t)
    waiting(t)
    t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal, decision="reject"))
    job = job_of(t, "decision")
    no_retail(t).process(job.id, t.run.workspace_id, uuid4())
    with pytest.raises(DataLossRefused, match="tombstones"):
        t.db.downgrade("0013", allow_data_loss=allow_data_loss)
    assert t.db.current() == head() and job_of(t, "decision").state == "done"
    with t.db.superuser() as connection:
        for sql in ("DELETE FROM app.jobs WHERE id = %s", "UPDATE app.jobs SET state = 'queued' WHERE id = %s",
                    "UPDATE app.jobs SET proposal_version = 2 WHERE id = %s"):
            with pytest.raises(Exception, match=r"retained|immutable"):
                connection.execute(sql, (job.id,))


def test_upgrade_preserves_ordinary_jobs_and_empty_review_downgrade_roundtrip(new_app_database: NewDatabase) -> None:
    from policyops.persistence.importer import import_synthetic_world
    from policyops.persistence.roles import AUTH_RUNTIME

    db = new_app_database("t22_upgrade", revision="0013")
    import_synthetic_world(auth=db.engine(AUTH_RUNTIME), app=db.engine(APP_RUNTIME))
    with db.superuser() as connection:
        before = connection.execute("SELECT id, request_sha256, state FROM app.jobs ORDER BY id").fetchall()
        assert connection.execute("SELECT has_column_privilege(%s, 'app.jobs', 'kind', 'SELECT')",
                                  (WORKER_DISCOVERY,)).fetchone() == (False,)
    db.upgrade()
    with db.superuser() as connection:
        assert connection.execute("SELECT id, request_sha256, state FROM app.jobs ORDER BY id").fetchall() == before
        assert connection.execute("SELECT has_column_privilege(%s, 'app.jobs', 'kind', 'SELECT')",
                                  (WORKER_DISCOVERY,)).fetchone() == (True,)
    db.downgrade("0013")
    assert db.current() == "0013"
    with db.superuser() as connection:
        assert connection.execute("SELECT has_column_privilege(%s, 'app.jobs', 'kind', 'SELECT')",
                                  (WORKER_DISCOVERY,)).fetchone() == (False,)
    db.upgrade()
    assert db.current() == head()


def test_binding_fks_and_rls_reject_cross_run_and_cross_tenant(new_app_database: NewDatabase) -> None:
    t = tenant(new_app_database("t22_scope"))
    original = consented(t)
    t.decisions().decide(t.authorized(t.reviewer), original.proposal_id, ask(original))
    other = tenant(t.db)
    foreign = created(other)
    unpresented = created(t)
    # A second run in the same workspace, on another case: tenant-only FKs would permit this mix.
    case_id, run_id = uuid4(), uuid4()
    with workspace_transaction(t.engine, t.run.workspace_id) as connection:
        case = repo.create_case(connection, NewCase(id=case_id, workspace_id=t.run.workspace_id, scenario="retail",
            customer_user_id=t.scope.customer_user_id, created_by=None, created_at=t.clock.now()))
        repo.create_run(connection, NewRun(id=run_id, workspace_id=t.run.workspace_id, case_id=case.id,
            case_version=case.version, mode="workbench", graph_sha256="a"*64, prompt_sha256="b"*64,
            config_sha256="c"*64, deadline_at=t.clock.now()+timedelta(hours=1), created_at=t.clock.now()))
    for run, proposal in ((run_id, unpresented), (t.run.run_id, foreign)):
        with pytest.raises(DBAPIError) as error, workspace_transaction(t.engine, t.run.workspace_id) as connection:
            jobs.enqueue(connection, jobs.NewReviewJob(workspace_id=t.run.workspace_id, run_id=run,
                binding=jobs.ExpiryBinding(proposal_id=proposal.proposal_id,
                                          proposal_version=proposal.proposal_version),
                created_at=t.clock.now(), available_at=t.clock.now()))
        assert isinstance(error.value.orig, errors.ForeignKeyViolation)
        assert error.value.orig.diag.constraint_name == "jobs_review_proposal"
    with workspace_transaction(t.engine, t.run.workspace_id) as connection:
        decision = repo.get_decision(connection, original.proposal_id, original.proposal_version)
        assert decision is not None
    # A decision from another proposal (even in this same run) cannot authorize the new proposal.
    with pytest.raises(DBAPIError) as error, workspace_transaction(t.engine, t.run.workspace_id) as connection:
        jobs.enqueue(connection, jobs.NewReviewJob(workspace_id=t.run.workspace_id, run_id=t.run.run_id,
            binding=jobs.DecisionBinding(proposal_id=unpresented.proposal_id,
                proposal_version=unpresented.proposal_version, decision_id=decision.approval_id),
            created_at=t.clock.now(), available_at=t.clock.now()))
    assert isinstance(error.value.orig, errors.ForeignKeyViolation)
    assert error.value.orig.diag.constraint_name == "jobs_review_decision"
    with workspace_transaction(t.engine, other.run.workspace_id) as connection:
        assert store.get_job(connection, job_of(t, "decision").id) is None
        with pytest.raises(DBAPIError) as error:
            jobs.enqueue(connection, jobs.NewReviewJob(workspace_id=t.run.workspace_id, run_id=run_id,
                binding=jobs.ExpiryBinding(proposal_id=uuid4(), proposal_version=1),
                created_at=t.clock.now(), available_at=t.clock.now()))
        assert isinstance(error.value.orig, errors.InsufficientPrivilege)
    with t.db.engine(WORKER_DISCOVERY).connect() as connection:
        assert connection.execute(text("SELECT id, workspace_id, state FROM app.jobs")).all()
        for column in jobs.REFERENCE_COLUMNS:
            with pytest.raises(DBAPIError):
                connection.execute(text(f"SELECT {column} FROM app.jobs"))  # noqa: S608 - fixed column list
            connection.rollback()


def test_restore_retains_completed_job_and_refusal_identity(app_cluster: AppCluster,
                                                          new_app_database: NewDatabase) -> None:
    t = tenant(new_app_database("t22_restore_source"))
    proposal = consented(t)
    waiting(t)
    t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal, decision="reject"))
    job = job_of(t, "decision")
    no_retail(t).process(job.id, t.run.workspace_id, uuid4())
    target = new_app_database("t22_restore_target", extensions=False, revision=None)
    app_cluster.server.dump_and_restore(t.db.name, target.name)
    with workspace_transaction(target.engine(APP_RUNTIME), t.run.workspace_id) as connection:
        restored = store.get_job(connection, job.id)
        assert restored is not None and restored.state == "done" and jobs.binding_of(restored) == jobs.binding_of(job)
        assert repo.message_by_id(connection, t.scope.binding.scope,
                                 refusal_message_id(t.run.workspace_id, t.run.run_id, job.id)) is not None


@pytest.mark.parametrize("columns", [
    {"review_trigger": None}, {"proposal_version": None}, {"proposal_version": 0},
    {"review_trigger": "decision", "decision_id": None},
    {"review_trigger": "expiry", "execution_version": 1},
    {"review_trigger": "outcome", "decision_id": uuid4(), "execution_id": uuid4(), "execution_version": None},
    {"kind": "run.execute", "review_trigger": "expiry"},
])
def test_database_rejects_null_and_mixed_review_shapes(new_app_database: NewDatabase,
                                                     columns: dict[str, Any]) -> None:
    t = tenant(new_app_database("t22_shapes"))
    proposal = created(t)
    params = dict(id=uuid4(), w=t.run.workspace_id, r=t.run.run_id, key=f"forged:{uuid4()}",
        kind="run.review", review_trigger="expiry", proposal_id=proposal.proposal_id, proposal_version=1,
        decision_id=None, execution_id=None, execution_version=None, now=t.clock.now(),
        deadline=t.clock.now()+timedelta(hours=1)) | columns
    with pytest.raises(DBAPIError) as error, workspace_transaction(t.engine, t.run.workspace_id) as connection:
        connection.execute(text("INSERT INTO app.jobs (id, workspace_id, run_id, dedupe_key, request_sha256, "
            "kind, run_generation, state, max_attempts, available_at, deadline_at, created_at, updated_at, "
            "review_trigger, proposal_id, proposal_version, decision_id, execution_id, execution_version) VALUES "
            "(:id, :w, :r, :key, repeat('a', 64), :kind, 0, 'queued', 10, :now, :deadline, :now, :now, "
            ":review_trigger, :proposal_id, :proposal_version, :decision_id, :execution_id, :execution_version)"),
                           params)
    assert isinstance(error.value.orig, errors.CheckViolation)
    assert error.value.orig.diag.constraint_name == "jobs_review_shape"


def test_refusal_summary_and_run_state_roll_back_together(new_app_database: NewDatabase,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    t = tenant(new_app_database("t22_atomic"))
    proposal = consented(t)
    waiting(t)
    t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal, decision="reject"))
    handler, job = no_retail(t), job_of(t, "decision")
    token = handler.claim(job.id, t.run.workspace_id, uuid4())
    assert token is not None
    result = handler.execute(token)
    original = store.end_job

    def crash(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("summary_crash")

    monkeypatch.setattr(store, "end_job", crash)
    with pytest.raises(RuntimeError, match="summary_crash"):
        handler.finish(token, result)
    assert t.count("SELECT count(*) FROM app.case_messages WHERE id = %s",
                   refusal_message_id(t.run.workspace_id, t.run.run_id, job.id)) == 0
    assert t.value("SELECT state FROM app.runs WHERE id = %s", t.run.run_id) == "waiting_approval"
    monkeypatch.setattr(store, "end_job", original)
    t.clock.advance(jobs.LEASE+timedelta(seconds=1))
    assert handler.process(job.id, t.run.workspace_id, uuid4())
    assert t.count("SELECT count(*) FROM app.case_messages WHERE id = %s",
                   refusal_message_id(t.run.workspace_id, t.run.run_id, job.id)) == 1


def test_retired_evidence_refuses_review_reservation(cited: evidence_tests.Cited) -> None:
    citation = evidence_tests.cite(cited, cited.run.run_id, "ten days")
    prepared = evidence_tests.create(cited, [citation])
    refs = evidence_tests.approve(cited, prepared.proposal)
    evidence_tests.publish(cited.world, evidence_tests.V2, evidence_tests.KEY_A)
    engine = cited.world.engine
    with cited.world.db.superuser() as connection:
        connection.execute("UPDATE app.runs SET initiated_by = %s WHERE id = %s", (cited.reviewer, cited.run.run_id))
    with workspace_transaction(engine, cited.run.workspace_id) as connection:
        run = store.get_run(connection, cited.run.run_id, lock=True)
        assert run is not None
        store.set_state(connection, run, "waiting_approval", cited.clock.now())
        job_id = connection.execute(text("SELECT id FROM app.jobs WHERE decision_id = :id"),
                                    {"id": refs.approval_id}).scalar_one()

    class Scopes:
        def scope(self, run: RunScope) -> Any:
            assert run == cited.run
            return cited.scope

    @contextmanager
    def retail(scope: Any) -> Iterator[RetailOperations]:
        fake = FakeRetail(state(), tenant_id=cited.run.workspace_id, case_id=cited.run.case_id,
                          customer_id=cited.scope.customer_user_id)
        yield cast(RetailOperations, fake)  # refusal precedes fingerprint/mutation; this port implements reads only
        assert all(type(call).__name__.startswith(("Get", "Find")) for call in fake.calls)

    handler = build_review_runtime(env="test", app_engine=engine, bindings=(),
        fixture_sha256=cited.scope.fixture_sha256, retail_origin="http://127.0.0.1:1", retail_key=b"x"*32,
        clock=FixedLeaseClock(cited.clock), scopes=Scopes(), retail=retail)
    assert handler.process(job_id, cited.run.workspace_id, uuid4())
    with workspace_transaction(engine, cited.run.workspace_id) as connection:
        job = store.get_job(connection, job_id)
        assert job is not None and (job.state, job.last_error_code) == ("done", "precheck_refused")
        assert connection.execute(text("SELECT count(*) FROM app.tool_executions WHERE run_id = :r"),
                                  {"r": cited.run.run_id}).scalar_one() == 0


@pytest.mark.parametrize("before_terminal_checkpoint", [False, True])
def test_early_decision_preserves_actual_investigation_preparation_and_checkpoint_replay(
        new_app_database: NewDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        before_terminal_checkpoint: bool) -> None:
    from policyops.services.proposals import ProposalService
    from tests.integration.test_proposal_decisions import customer_says, grant, principal

    class ProcessDeath(BaseException):
        pass

    db = new_app_database("t22_graph_replay")
    test = scenario(db, tmp_path, "proposal")
    context = test.claim()
    original = ProposalService.create_once

    def lost_preparation(*args: Any, **kwargs: Any) -> Any:
        original(*args, **kwargs)
        raise ProcessDeath() from None

    if before_terminal_checkpoint:
        monkeypatch.setattr(ProposalService, "create_once", lost_preparation)
        with pytest.raises(ProcessDeath):
            test.executor.execute(context)
        monkeypatch.setattr(ProposalService, "create_once", original)
    else:
        assert isinstance(test.executor.execute(context), AwaitingApproval)
    model_calls = len(test.model.keys)
    assert test.state() == "running"
    reviewer = principal(db, "early-reviewer")
    grant(db, test.world.ws, reviewer, "reviewer")
    scope = GatewayScope(run=RunScope(workspace_id=test.world.ws, case_id=test.case_id, run_id=test.run_id),
                         binding=test.executor.bindings[0], fixture_sha256=test.executor.fixture_sha256)
    t = Tenant(db, test.api.clock, scope, reviewer, reviewer, reviewer, {})
    with workspace_transaction(t.engine, t.run.workspace_id) as connection:
        row = repo.presented_rows_of_run(connection, t.run.run_id)[0]
        proposal = repo.get_proposal(connection, row.proposal_id, row.proposal_version)
        assert proposal is not None
    message_id = customer_says(t, "yes")
    assert isinstance(t.proposals().record_customer_reply(t.run, message_id), Consented)
    t.decisions().decide(t.authorized(reviewer), proposal.proposal_id, ask(proposal, decision="reject"))
    handler, job = no_retail(t), job_of(t, "decision")
    assert not handler.process(job.id, t.run.workspace_id, uuid4())
    assert job_of(t, "decision").attempts == 0 and test.state() == "running"
    with workspace_transaction(t.engine, t.run.workspace_id) as connection:
        store.check_fence(connection, context.claim_token, handler.executor.clock)
    t.clock.advance(timedelta(minutes=1))
    claimed = test.worker.claim(context.claim_token.job_id, t.run.workspace_id)
    assert claimed is not None
    token, case_id, spec = claimed
    recovered = Context(test.worker, token, case_id, spec)
    outcome = replace(test.executor).execute(recovered)
    assert isinstance(outcome, AwaitingApproval)
    test.worker.finish(token, outcome)
    assert test.state() == "waiting_approval" and len(test.model.keys) == model_calls
    assert handler.process(job.id, t.run.workspace_id, uuid4())
    assert test.state() == "failed" and job_of(t, "decision").last_error_code == "review_rejected"
    assert test.world.count("app.action_proposals") == test.world.count("app.proposal_presentations") == 1
