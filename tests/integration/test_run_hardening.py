"""T23 Slice A: real role/SQL/clock admission tests. Collection never acquires PostgreSQL."""

from dataclasses import replace
from datetime import timedelta
import threading
import time
from uuid import uuid4

import pytest
from sqlalchemy import text

from policyops.budget.config import Configuration
from policyops.budget.ledger import DispatchRefused, RunBinding, Settlement
from policyops.budget.pricing import Usage
from policyops.persistence import runs
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.database import (
    SQL_TIMEOUTS,
    DatabaseUnavailable,
    SqlProfile,
    SqlTimeouts,
    TransactionOutcomeUnknown,
    workspace_transaction,
)
from policyops.persistence.roles import APP_RUNTIME
from policyops.runtime.clock import FixedLeaseClock
from policyops_testing.app_database import NewDatabase
from policyops_testing.checkpoint_cases import Claimed, claimed


pytestmark = pytest.mark.postgres
REQUEST = "c" * 64


@pytest.fixture
def owner(new_app_database: NewDatabase) -> Claimed:
    result = claimed(new_app_database("t23_hardening"))
    with workspace_transaction(result.db.engine(APP_RUNTIME), result.scope.run.workspace_id) as connection:
        run = runs.get_run(connection, result.token.run_id, lock=True)
        assert run is not None
        runs.set_state(connection, run, "running", result.clock.now())
    return result


def books(owner: Claimed, token: runs.ClaimToken | None = None):  # type: ignore[no-untyped-def]
    return build_app_ledger(env="test", engine=owner.db.engine(APP_RUNTIME), workspace_id=owner.token.workspace_id,
                            configuration=Configuration(), clock=FixedLeaseClock(owner.clock), claim_token=token)


@pytest.mark.parametrize("wait", ["waiting_input", "waiting_approval"])
def test_wait_resume_same_state_and_terminal_preserve_active_allowance(owner: Claimed, wait: str) -> None:
    engine, workspace = owner.db.engine(APP_RUNTIME), owner.token.workspace_id
    owner.clock.advance(timedelta(seconds=20))
    with workspace_transaction(engine, workspace) as connection:
        run = runs.get_run(connection, owner.token.run_id, lock=True)
        assert run is not None
        paused = runs.set_state(connection, run, wait, owner.clock.now())  # type: ignore[arg-type]
        assert paused.active_started_at is None and paused.deadline_at is None
        allowance = paused.active_remaining_us
    owner.clock.advance(timedelta(hours=1))  # much longer than the default 180-second allowance
    with workspace_transaction(engine, workspace) as connection:
        run = runs.get_run(connection, owner.token.run_id, lock=True)
        assert run is not None and runs.remaining_us(run, owner.clock.now()) == allowance
        paused_again = runs.set_state(connection, run, wait, owner.clock.now())  # type: ignore[arg-type]
        resumed = runs.set_state(connection, paused_again, "reconciling", owner.clock.now())
        assert resumed.deadline_at == owner.clock.now() + timedelta(microseconds=allowance)
    owner.clock.advance(timedelta(seconds=5))
    with workspace_transaction(engine, workspace) as connection:
        run = runs.get_run(connection, owner.token.run_id, lock=True)
        assert run is not None
        repeated = runs.set_state(connection, run, "reconciling", owner.clock.now())
        assert repeated.deadline_at == resumed.deadline_at
        done = runs.set_state(connection, repeated, "failed", owner.clock.now())
        assert done.deadline_at is None and done.active_started_at is None
        assert done.active_remaining_us == allowance - 5_000_000


@pytest.mark.parametrize("actor", ["agent", "embedding", "reranker"])
@pytest.mark.parametrize("fault", ["missing", "foreign", "owner", "attempt", "generation", "lease", "waiting", "kind"])
def test_run_bound_admission_requires_live_exact_investigation_claim(owner: Claimed, actor: str, fault: str) -> None:
    token = owner.token
    if fault == "missing":
        token = None  # type: ignore[assignment]
    elif fault == "foreign":
        token = replace(token, run_id=uuid4())
    elif fault == "owner":
        token = replace(token, owner=uuid4())
    elif fault == "attempt":
        token = replace(token, attempt=token.attempt + 1)
    elif fault == "generation":
        token = replace(token, generation=token.generation + 1)
    elif fault == "lease":
        owner.clock.advance(timedelta(minutes=1))
    elif fault == "kind":
        with owner.db.superuser() as connection:
            connection.execute("UPDATE app.jobs SET kind = 'run.other' WHERE id = %s", (owner.token.job_id,))
    else:
        with workspace_transaction(owner.db.engine(APP_RUNTIME), owner.token.workspace_id) as connection:
            run = runs.get_run(connection, owner.token.run_id, lock=True)
            assert run is not None
            runs.set_state(connection, run, "waiting_approval", owner.clock.now())
    with pytest.raises(runs.Fenced):
        books(owner, token).reserve(RunBinding(owner.token.run_id), uuid4(), actor, "new", REQUEST)
    with owner.db.superuser() as connection:
        assert connection.execute("SELECT count(*) FROM app.usage_attempts").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM app.budget_scopes").fetchone() == (0,)


def test_fenced_count_and_dispatch_keep_settlement_and_release_available(owner: Claimed) -> None:
    ledger = books(owner, owner.token)
    dispatched, reserved = uuid4(), uuid4()
    for identity in (dispatched, reserved):
        ledger.reserve(RunBinding(owner.token.run_id), identity, "agent", str(identity), REQUEST)
        ledger.claim_count(identity, REQUEST)
        ledger.record_count(identity, tokens=100, source="test.fixed")
    ledger.begin_dispatch(dispatched, REQUEST)
    owner.clock.advance(timedelta(minutes=1))
    with pytest.raises(runs.Fenced):
        ledger.begin_dispatch(reserved, REQUEST)
    with pytest.raises(runs.Fenced):
        ledger.claim_count(reserved, REQUEST)
    assert ledger.release(reserved).state == "released"
    settlement = Settlement(Usage(100, output=10), "t23-settlement")
    assert not ledger.settle(dispatched, settlement).replayed
    assert ledger.settle(dispatched, settlement).replayed


@pytest.mark.parametrize("actor", ["agent", "embedding", "reranker"])
def test_fenced_composed_provider_paths_send_no_count_or_inference(owner: Claimed, actor: str) -> None:
    import asyncio

    from policyops.persistence.embeddings import EmbeddingStore
    from policyops.providers.calls import call
    from policyops.providers.embedding_calls import prepare_job, run_job
    from policyops_contracts.embedding import EmbeddingJob
    from policyops_testing.retrieval_fixtures import TOKENIZER, Scripted
    from tests.unit.test_provider_call_grants import REQUEST as MODEL_REQUEST

    ledger, provider = books(owner, owner.token), Scripted()
    owner.clock.advance(timedelta(minutes=1))  # expired but unreclaimed
    with pytest.raises(runs.Fenced):
        if actor == "embedding":
            prepared = prepare_job(EmbeddingJob(purpose="query", subject_key=f"query.{owner.token.run_id}.1",
                                               inputs=("Refunds?",)),
                                   ledger.configuration, TOKENIZER, deadline=time.monotonic() + 30)
            store = EmbeddingStore(owner.db.engine(APP_RUNTIME), owner.token.workspace_id, env="test",
                                   clock=FixedLeaseClock(owner.clock))
            asyncio.run(run_job(ledger, store, provider.providers()(), prepared, deadline=time.monotonic() + 30,
                                 run_id=owner.token.run_id))
        else:
            asyncio.run(call(ledger, provider.providers()(), RunBinding(owner.token.run_id), uuid4(), "fenced",
                             MODEL_REQUEST, actor, deadline=time.monotonic() + 30))  # type: ignore[arg-type]
    assert provider.seen == [] and provider.requests == []
    with owner.db.superuser() as connection:
        assert connection.execute("SELECT count(*) FROM app.usage_attempts").fetchone() == (0,)


@pytest.mark.parametrize("actor", ["agent", "embedding", "reranker"])
def test_admission_rechecks_lease_after_scope_lock_wait(owner: Claimed, actor: str) -> None:
    ledger = books(owner, owner.token)
    first = uuid4()
    ledger.reserve(RunBinding(owner.token.run_id), first, "agent", "first", REQUEST)
    outcomes: list[BaseException] = []

    def reserve() -> None:
        try:
            ledger.reserve(RunBinding(owner.token.run_id), uuid4(), actor, "late", REQUEST)
        except BaseException as error:
            outcomes.append(error)

    thread = threading.Thread(target=reserve)
    with owner.db.server.connect("postgres", owner.db.name) as holder:
        holder.execute("SELECT id FROM app.budget_scopes WHERE run_id = %s FOR UPDATE", (owner.token.run_id,))
        thread.start()
        try:
            with owner.db.superuser() as watcher:
                until = time.monotonic() + 5
                while not watcher.execute("SELECT 1 FROM pg_stat_activity WHERE datname = current_database() "
                                          "AND wait_event_type = 'Lock'").fetchone():
                    assert time.monotonic() < until
                    time.sleep(0.005)
            owner.clock.advance(timedelta(minutes=1))
        finally:
            holder.rollback()
            thread.join(5)
    assert not thread.is_alive()
    assert len(outcomes) == 1 and isinstance(outcomes[0], runs.Fenced)
    assert outcomes[0].reason == "lease_expired"
    with owner.db.superuser() as connection:
        assert connection.execute("SELECT count(*) FROM app.usage_attempts").fetchone() == (1,)
        assert connection.execute("SELECT calls_held FROM app.budget_scopes").fetchone() == (1,)


def test_lock_statement_timeouts_rollback_and_connection_is_reusable(owner: Claimed,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    engine, workspace = owner.db.engine(APP_RUNTIME, pool_size=1), owner.token.workspace_id
    with engine.connect() as connection:
        baseline = connection.execute(text("SELECT current_setting('statement_timeout')")).scalar_one()
    monkeypatch.setitem(SQL_TIMEOUTS, SqlProfile.DEFAULT, SqlTimeouts(500, 100, 2000))
    with owner.db.server.connect("postgres", owner.db.name) as holder:
        holder.execute("SELECT id FROM app.runs WHERE id = %s FOR UPDATE", (owner.token.run_id,))
        started = time.monotonic()
        with pytest.raises(DatabaseUnavailable) as failure, workspace_transaction(engine, workspace) as connection:
            runs.get_run(connection, owner.token.run_id, lock=True)
        assert failure.value.sqlstate == "55P03" and failure.value.phase == "body"
        assert time.monotonic() - started < 5
    with pytest.raises(DatabaseUnavailable) as failure, workspace_transaction(engine, workspace) as connection:
        connection.execute(text("SELECT pg_sleep(2)"))
    assert failure.value.sqlstate == "57014"
    with workspace_transaction(engine, workspace) as connection:
        assert runs.get_run(connection, owner.token.run_id, lock=True) is not None
    monkeypatch.undo()
    with workspace_transaction(engine, workspace, profile=SqlProfile.LEASE) as connection:
        assert connection.execute(text("SELECT current_setting('statement_timeout')")).scalar_one() == "1s"
    with workspace_transaction(engine, workspace) as connection:
        assert connection.execute(text("SELECT current_setting('statement_timeout')")).scalar_one() == "5s"
    with engine.connect() as connection:
        assert connection.execute(text("SELECT current_setting('statement_timeout')")).scalar_one() == baseline


def test_pool_checkout_is_bounded(owner: Claimed) -> None:
    engine, workspace = owner.db.engine(APP_RUNTIME, pool_size=1), owner.token.workspace_id
    with engine.connect():
        started = time.monotonic()
        with pytest.raises(DatabaseUnavailable) as failure, workspace_transaction(engine, workspace):
            pytest.fail("a saturated pool cannot admit another connection")
        assert failure.value.phase == "acquire" and time.monotonic() - started < 5


def test_idle_transaction_termination_discards_session(owner: Claimed, monkeypatch: pytest.MonkeyPatch) -> None:
    engine, workspace = owner.db.engine(APP_RUNTIME, pool_size=1), owner.token.workspace_id
    monkeypatch.setitem(SQL_TIMEOUTS, SqlProfile.DEFAULT, SqlTimeouts(500, 100, 100))
    with pytest.raises(DatabaseUnavailable) as failure, workspace_transaction(engine, workspace) as connection:
        before = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        time.sleep(0.3)  # exercise the server's idle-session timeout, not a caller deadline
        connection.execute(text("SELECT 1"))
    assert failure.value.sqlstate == "25P03" and failure.value.reconcile
    with workspace_transaction(engine, workspace) as connection:
        assert connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != before


def test_embedding_accounting_failure_retains_available_usage_and_stops(owner: Claimed,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from policyops.persistence.embeddings import EmbeddingStore
    from policyops.providers.accounting import AccountingUnconfirmed
    from policyops.providers.embedding_calls import prepare_job, run_job
    from policyops_contracts.embedding import EmbeddingJob
    from policyops_testing.retrieval_fixtures import TOKENIZER, Embeddings

    ledger = books(owner, owner.token)

    def fail(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise DatabaseUnavailable("body", "55P03")

    monkeypatch.setattr(ledger, "settle", fail)
    prepared = prepare_job(EmbeddingJob(purpose="query", subject_key=f"query.{owner.token.run_id}.1",
                                       inputs=("Refund rule?",)),
                           ledger.configuration, TOKENIZER, deadline=time.monotonic() + 30)
    provider = Embeddings()
    store = EmbeddingStore(owner.db.engine(APP_RUNTIME), owner.token.workspace_id, env="test",
                           clock=FixedLeaseClock(owner.clock))
    with pytest.raises(AccountingUnconfirmed) as stopped:
        asyncio.run(run_job(ledger, store, provider.providers()(), prepared, deadline=time.monotonic() + 30,
                             run_id=owner.token.run_id))
    report = stopped.value.report
    assert report.pending_billing is not None and report.pending_billing.prompt_tokens > 0
    assert report.pending_evidence is not None and report.pending_cleanup_confirmed is True
    assert len(provider.requests) == 1
    with owner.db.superuser() as connection:
        assert connection.execute("SELECT state FROM app.usage_attempts").fetchone() == ("dispatching",)
        assert connection.execute("SELECT held_usd > 0 FROM app.budget_scopes").fetchone() == (True,)


@pytest.mark.parametrize("phase", ["reserve", "dispatch", "settlement"])
def test_lost_commit_acknowledgement_reconciles_original_attempt_without_new_grant(
        owner: Claimed, phase: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy.engine import RootTransaction

    ledger, identity = books(owner, owner.token), uuid4()
    if phase != "reserve":
        ledger.reserve(RunBinding(owner.token.run_id), identity, "agent", "same-operation", REQUEST)
        ledger.claim_count(identity, REQUEST)
        ledger.record_count(identity, tokens=100, source="test.fixed")
    if phase == "settlement":
        ledger.begin_dispatch(identity, REQUEST)
    commit = RootTransaction.commit

    def lose_ack(tx: RootTransaction) -> None:
        commit(tx)  # actual PostgreSQL commit, followed by a lost acknowledgement
        raise OSError("synthetic lost acknowledgement")

    settlement = Settlement(Usage(100, output=10), "t23-unknown-commit")
    with monkeypatch.context() as faults:
        faults.setattr(RootTransaction, "commit", lose_ack)
        with pytest.raises(TransactionOutcomeUnknown):
            if phase == "reserve":
                ledger.reserve(RunBinding(owner.token.run_id), identity, "agent", "same-operation", REQUEST)
            elif phase == "dispatch":
                ledger.begin_dispatch(identity, REQUEST)
            else:
                ledger.settle(identity, settlement)
    if phase == "reserve":
        assert not ledger.reserve(RunBinding(owner.token.run_id), identity, "agent", "same-operation", REQUEST).created
    elif phase == "dispatch":
        decision = ledger.begin_dispatch(identity, REQUEST)
        assert isinstance(decision, DispatchRefused) and decision.reason == "dispatching"
    else:
        assert ledger.settle(identity, settlement).replayed
    with owner.db.superuser() as connection:
        assert connection.execute("SELECT count(*) FROM app.usage_attempts").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM app.usage_events").fetchone() == (
            1 if phase == "settlement" else 0,)
