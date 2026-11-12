"""T29 durable claims as the actual evaluation role, including concurrent admission."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from policyops.budget.config import Caps, Configuration
from policyops.budget.ledger import BudgetExhausted, Ledger, Settlement
from policyops.budget.pricing import Usage
from policyops.persistence import evaluation, migrate, repositories
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.database import TransactionOutcomeUnknown, transaction
from policyops.persistence.evaluation import ClaimRefused, EvaluationRepository, Slot
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.records import EvaluationRun, EvaluationTrial
from policyops.persistence.roles import EVAL_RUNTIME
from policyops_testing.app_database import AppDatabase, NewDatabase


pytestmark = pytest.mark.postgres
SHA = "c" * 64


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("evaluation_claims")


def scheduled(db: AppDatabase, *, caps: Caps | None = None, tasks: int = 1
              ) -> tuple[EvaluationRepository, EvalLedgerStore, Caps, list[Slot], UUID]:
    caps = caps or Caps()
    engine = db.engine(EVAL_RUNTIME, pool_size=6)
    store = EvalLedgerStore(engine, env="test")
    repository = EvaluationRepository(engine)
    study = store.ensure_study(f"claims-{uuid4()}", SHA, cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    run = EvaluationRun(id=uuid4(), study_scope=study, dataset="tau2-retail", dataset_revision="1" * 40,
        split_id="dev", config_sha256=SHA, config_json='{"fixture":"claims"}', created_at=datetime.now(UTC))
    assert repository.ensure_run(run) == repository.ensure_run(run) == run.id
    invocation = store.ensure_invocation(study, uuid4(), caps)
    slots = []
    for i in range(tasks):
        scenario = store.ensure_scenario(study, str(i), 0, SHA, caps)
        slot = Slot(uuid4(), run.id, study, SHA, str(i), 0, 7, scenario, "scheduled")
        repository.schedule(slot)
        slots.append(slot)
    return repository, store, caps, slots, invocation


def terminal(slot: Slot) -> EvaluationTrial:
    return EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id, task_id=slot.task_id,
        trial_index=slot.trial_index, seed=slot.seed, outcome="aborted", reward=None,
        components_json='{"fixture":true}',
        error_class="fixture_abort", cost_status="unknown", cost_usd=None, created_at=datetime.now(UTC))


def test_claim_race_has_one_winner_and_terminal_replay_is_exact(db: AppDatabase) -> None:
    repository, _, _, slots, invocation = scheduled(db)
    slot = slots[0]
    barrier = threading.Barrier(2)
    with repository.study_lock(slot.study_id) as lease:
        def claim() -> Any:
            barrier.wait(timeout=5)
            return repository.claim(slot, invocation, lease)

        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(claim) for _ in range(2)]
            winners = [token for f in futures if (token := f.result(timeout=10)) is not None]
        assert len(winners) == 1
        result = terminal(slot)
        with pytest.raises(ClaimRefused):
            repository.finalize(result, replace(winners[0], owner=uuid4()), lease)
        repository.finalize(result, winners[0], lease)
        repository.finalize(result, winners[0], lease)
        assert repository.claim(slot, invocation, lease) is None
        with pytest.raises(ClaimRefused, match="terminal_result_conflict"):
            repository.finalize(result.model_copy(update={"error_class": "different"}), winners[0], lease)
        assert len(repository.results(slot.run_id)) == 1


def test_shared_study_reservation_race_under_two_claims(db: AppDatabase) -> None:
    caps = replace(Caps(), study_calls=1)
    repository, store, _, slots, invocation = scheduled(db, caps=caps, tasks=2)
    barrier = threading.Barrier(2)
    with repository.study_lock(slots[0].study_id) as lease:
        tokens = [repository.claim(slot, invocation, lease) for slot in slots]
        assert all(tokens)

        def reserve(index: int) -> str:
            token = tokens[index]
            assert token is not None
            books = Ledger(EvalLedgerStore(repository.engine, env="test", claim_token=token), Configuration(caps=caps))
            barrier.wait(timeout=5)
            try:
                books.reserve(token.binding, uuid4(), "agent", "race", SHA)
                return "reserved"
            except BudgetExhausted:
                return "exhausted"

        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(reserve, i) for i in range(2)]
            assert sorted(f.result(timeout=10) for f in futures) == ["exhausted", "reserved"]
        snapshot = store.scope(slots[0].study_id)
        assert snapshot is not None and snapshot.calls_held == 1 and snapshot.held_usd == Decimal("0.002624")


def test_finalized_claim_refuses_count_dispatch_reserve_but_allows_late_settlement(db: AppDatabase) -> None:
    repository, _, caps, slots, invocation = scheduled(db)
    slot = slots[0]
    with repository.study_lock(slot.study_id) as lease:
        token = repository.claim(slot, invocation, lease)
        assert token is not None
        books = Ledger(EvalLedgerStore(repository.engine, env="test", claim_token=token), Configuration(caps=caps))
        attempt = uuid4()
        books.reserve(token.binding, attempt, "agent", "late", SHA)
        books.claim_count(attempt, SHA)
        books.record_count(attempt, tokens=100, source="provider")
        books.begin_dispatch(attempt, SHA)
        repository.finalize(terminal(slot), token, lease)
        for action in (lambda: books.reserve(token.binding, uuid4(), "agent", "late-2", SHA),
                       lambda: books.claim_count(attempt, SHA), lambda: books.begin_dispatch(attempt, SHA)):
            with pytest.raises(ClaimRefused, match="claim_not_running"):
                action()
        books.settle(attempt, Settlement(Usage(100, output=10), provider_request_id="resp_late"))
        usage = repository.usage(slot.scenario_id)
        assert usage["held_usd"] == 0 and usage["spent_usd"] > 0
        assert len(repository.results(slot.run_id)) == 1


def test_restart_recovers_running_to_aborted_and_preserves_holds(db: AppDatabase) -> None:
    repository, _, caps, slots, invocation = scheduled(db, tasks=2)
    with repository.study_lock(slots[0].study_id) as lease:
        token = repository.claim(slots[0], invocation, lease)
        assert token is not None
        books = Ledger(EvalLedgerStore(repository.engine, env="test", claim_token=token), Configuration(caps=caps))
        books.reserve(token.binding, uuid4(), "agent", "lost-invocation", SHA)
        with pytest.raises(ClaimRefused, match="study_already_running"), repository.study_lock(slots[0].study_id):
            pass
    restarted = EvaluationRepository(repository.engine)
    with restarted.study_lock(slots[0].study_id) as lease:
        restarted.abort(slots[0], lease)
        restarted.abort(slots[0], lease)  # terminal recovery is idempotent
        restarted.abort(slots[1], lease, reason="explicit_study_abort")
        restarted.finish_run(slots[0].run_id, lease)
        assert all(s.state == "finalized" for s in restarted.slots(slots[0].run_id))
        assert [r["outcome"] for r in restarted.results(slots[0].run_id)] == ["aborted", "aborted"]
        assert restarted.usage(slots[0].scenario_id)["held_usd"] == Decimal("0.002624")
        with pytest.raises(ClaimRefused):
            books.reserve(token.binding, uuid4(), "agent", "lost-lock", SHA)


def test_scope_wait_rechecks_lost_study_lock_before_admission(db: AppDatabase) -> None:
    repository, _, caps, slots, invocation = scheduled(db)
    slot = slots[0]
    with ThreadPoolExecutor(1) as pool, repository.study_lock(slot.study_id) as lease:
        token = repository.claim(slot, invocation, lease)
        assert token is not None
        books = Ledger(EvalLedgerStore(repository.engine, env="test", claim_token=token), Configuration(caps=caps))
        with transaction(repository.engine) as connection:
            connection.execute(text("SELECT id FROM evaluation.budget_scopes WHERE id = :id FOR UPDATE"),
                               {"id": slot.study_id})
            future = pool.submit(books.reserve, token.binding, uuid4(), "agent", "wait", SHA)
            limit = time.monotonic() + 0.7
            waiting = False
            with db.superuser() as observer:
                while time.monotonic() < limit:
                    waiting = observer.execute("SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                        "WHERE datname = current_database() AND wait_event_type = 'Lock')").fetchone()[0]
                    if waiting:
                        break
                    time.sleep(0.01)
            assert waiting
            # Explicitly release the owning session while the reservation
            # waits. Its post-wait admission must see the missing lock.
            with db.superuser() as observer:
                observer.execute("SELECT pg_terminate_backend(%s)", (lease.pid,))
        with pytest.raises(ClaimRefused, match="study_lock_lost"):
            future.result(timeout=5)
    assert repository.usage(slot.scenario_id)["held_usd"] == 0


def test_ambiguous_terminal_commit_reconciles_same_hash(db: AppDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
    repository, _, _, slots, invocation = scheduled(db)
    slot = slots[0]
    real = transaction
    with repository.study_lock(slot.study_id) as lease:
        token = repository.claim(slot, invocation, lease)
        assert token is not None
        once = True

        @contextmanager
        def unknown(engine: Any) -> Any:
            nonlocal once
            with real(engine) as connection:
                yield connection
            if once:
                once = False
                raise TransactionOutcomeUnknown()

        monkeypatch.setattr(evaluation, "transaction", unknown)
        result = terminal(slot)
        repository.finalize(result, token, lease)
        assert repository.result_hash(slot.id) == evaluation.result_digest(result)
        assert len(repository.results(slot.run_id)) == 1


@pytest.mark.parametrize("sql", ["DELETE FROM evaluation.trial_claims", "DELETE FROM evaluation.evaluation_trials",
    "UPDATE evaluation.evaluation_trials SET reward = 1", "UPDATE evaluation.evaluation_runs SET config = '{}'",
    "UPDATE evaluation.trial_claims SET seed = 9", "CREATE TABLE evaluation.forbidden (id int)"])
def test_eval_role_denies_result_updates_identity_updates_delete_and_ddl(db: AppDatabase, sql: str) -> None:
    with pytest.raises(ProgrammingError), transaction(db.engine(EVAL_RUNTIME)) as connection:
        connection.execute(text(sql))


def test_immutable_slot_conflict_and_result_without_finalization_refused(db: AppDatabase) -> None:
    repository, _, _, slots, invocation = scheduled(db)
    slot = slots[0]
    repository.schedule(slot)
    with pytest.raises(ClaimRefused, match="immutable_run_conflict"):
        repository.ensure_run(EvaluationRun(id=slot.run_id, study_scope=slot.study_id, dataset="tau2-retail",
            dataset_revision="1" * 40, split_id="dev", config_sha256=SHA, config_json='{"fixture":"different"}',
            created_at=datetime.now(UTC)))
    with pytest.raises(ClaimRefused, match="immutable_slot_conflict"):
        repository.schedule(replace(slot, seed=8))
    with repository.study_lock(slot.study_id) as lease:
        assert repository.claim(slot, invocation, lease) is not None
        with pytest.raises((DBAPIError, TransactionOutcomeUnknown)), transaction(repository.engine) as connection:
            repositories.add_trial(connection, terminal(slot))  # deferred FK requires finalized claim at COMMIT


@pytest.mark.parametrize("statement", [
    "UPDATE evaluation.trial_claims SET state = 'running' WHERE id = :id",
    "UPDATE evaluation.trial_claims SET owner_token = gen_random_uuid() WHERE id = :id",
    "UPDATE evaluation.trial_claims SET state = 'finalized', finished_at = clock_timestamp() WHERE id = :id",
    "UPDATE evaluation.trial_claims SET started_at = clock_timestamp() WHERE id = :id"])
def test_claim_state_owner_and_time_checks(db: AppDatabase, statement: str) -> None:
    repository, _, _, slots, _ = scheduled(db)
    with pytest.raises(DBAPIError), transaction(repository.engine) as connection:
        # Fixed test strings only, never an application input.
        connection.execute(text(statement), {"id": slots[0].id})


def test_0016_backfills_old_terminal_trials_and_refuses_loss(new_app_database: NewDatabase) -> None:
    db = new_app_database("eval_backfill", revision="0015")
    run, result = uuid4(), uuid4()
    # Historical SQL only. Current row models/repos require the current head.
    with db.superuser() as connection:
        connection.execute("INSERT INTO evaluation.evaluation_runs "
            "(id, dataset, dataset_revision, split_id, config_sha256, config, status, created_at) VALUES "
            "(%s, 'tau2-retail', repeat('a',40), 'dev', repeat('b',64), '{}', 'planned', clock_timestamp())", (run,))
        connection.execute("INSERT INTO evaluation.evaluation_trials "
            "(id, evaluation_run_id, task_id, trial_index, seed, outcome, reward, components, cost_status, created_at) "
            "VALUES (%s, %s, '24', 0, 7, 'aborted', NULL, '{}', 'unknown', clock_timestamp())", (result, run))
    db.upgrade(migrate.head())
    with transaction(db.engine(EVAL_RUNTIME)) as connection:
        row = connection.execute(text("SELECT id, state, result_id, owner_token FROM evaluation.trial_claims "
                                      "WHERE id = :id"), {"id": result}).one()
        assert tuple(row) == (result, "finalized", result, None)
        assert connection.execute(text("SELECT count(*) FROM evaluation.evaluation_trials")).scalar_one() == 1
    with pytest.raises(DataLossRefused):
        db.downgrade("0015")
    stopped_at = db.current()
    chain = migrate.revisions()
    assert stopped_at is not None and chain.index(stopped_at) >= chain.index("0016")
    with transaction(db.engine(EVAL_RUNTIME)) as connection:
        assert tuple(connection.execute(text("SELECT id, state, result_id, owner_token FROM evaluation.trial_claims "
                                             "WHERE id = :id"), {"id": result}).one()) == tuple(row)
        assert connection.execute(text("SELECT count(*) FROM evaluation.evaluation_trials")).scalar_one() == 1


def test_0016_empty_down_up_and_pinned_guard(new_app_database: NewDatabase) -> None:
    db = new_app_database("eval_empty")
    with db.superuser() as connection:
        assert connection.execute("SELECT proconfig FROM pg_proc WHERE oid = "
            "'evaluation.guard_trial_claim()'::regprocedure").fetchone() == (["search_path=pg_catalog, evaluation"],)
    db.downgrade("0015")
    assert db.current() == "0015"
    db.upgrade(migrate.head())
    assert db.current() == migrate.head()
