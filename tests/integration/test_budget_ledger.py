"""The T10 usage ledger on real PostgreSQL, as the actual app-runtime and eval-runtime roles (revision 0006).

Races are made real: a superuser transaction holds the contended scope row while the competing ledger calls queue
on it (confirmed in `pg_stat_activity`). It then commits, so they run one after another in an order the test does
not choose. Every outcome is checked against the exact counters. No provider is involved: "dispatch" is only the
ledger's grant.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import partial
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from policyops.budget.config import Caps, Configuration
from policyops.budget.ledger import (
    Binding,
    BudgetExhausted,
    CountGranted,
    DispatchGranted,
    DispatchRefused,
    EvalBinding,
    IllegalTransition,
    Ledger,
    LedgerConflict,
    NotFound,
    OperationBinding,
    Reserved,
    RunBinding,
    ScopeInactive,
    Settled,
    Settlement,
)
from policyops.budget.pricing import Usage
from policyops.domain.examples import World
from policyops.persistence import repositories as repo
from policyops.persistence.budget import AppLedgerStore, EvalLedgerStore, build_app_ledger, build_eval_ledger
from policyops.persistence.database import IdempotencyConflict, RuntimeRoleError, transaction, workspace_transaction
from policyops.persistence.importer import import_synthetic_world
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.records import NewCase, NewRun, UsageEvent, Workspace
from policyops.persistence.roles import APP_MIGRATOR, APP_RUNTIME, AUTH_RUNTIME, EVAL_RUNTIME
from policyops.runtime.clock import FixedLeaseClock, UnsafeTestHook
from policyops_contracts.clock import FixedClock
from policyops_contracts.digest import text_sha256
from policyops_testing.app_database import AppDatabase, NewDatabase


pytestmark = pytest.mark.postgres
HOLD = Decimal("0.002624")  # the default agent reservation: 16000 in + 2048 out on Luna, short tier, no cache
SHA = "a" * 64
REQUEST = "c" * 64  # a request fingerprint; T11's provider tests bind real prepared requests


class Books:
    """The T10 ledger behaviour under the T11 (v2) API. Each newly reserved attempt is bound to `REQUEST` and
    counted once (1000 tokens, admitted), so `begin_dispatch` sees an admitted count as T11 requires."""

    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    def reserve(self, binding: Binding, attempt_id: UUID, actor: Any, operation_id: str) -> Reserved:
        reserved = self.ledger.reserve(binding, attempt_id, actor, operation_id, REQUEST)
        if reserved.created:
            assert isinstance(self.ledger.claim_count(attempt_id, REQUEST), CountGranted)
            self.ledger.record_count(attempt_id, tokens=1000, source="test.fixed")
        return reserved

    def begin_dispatch(self, attempt_id: UUID) -> DispatchGranted | DispatchRefused:
        return self.ledger.begin_dispatch(attempt_id, REQUEST)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.ledger, name)


# -- setup -------------------------------------------------------------------------------------------------------

def workspace(db: AppDatabase) -> UUID:
    ws = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=ws, slug=f"ws-{ws.hex[:12]}", name="Budget test",
                                              created_at=datetime.now(UTC)))
    return ws


def new_run(db: AppDatabase, ws: UUID) -> UUID:
    case, run, now = uuid4(), uuid4(), datetime.now(UTC)
    with workspace_transaction(db.engine(APP_RUNTIME), ws) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=ws, scenario="retail", customer_user_id=None,
                                                created_by=None, created_at=now))
        repo.create_run(conn, NewRun(id=run, workspace_id=ws, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=now + timedelta(hours=1),
                                     created_at=now))
    return run


def ledger(db: AppDatabase, ws: UUID, caps: Caps | None = None) -> Books:
    return Books(build_app_ledger(env="test", engine=db.engine(APP_RUNTIME, pool_size=6), workspace_id=ws,
                                  configuration=Configuration(caps=caps or Caps())))


def scope_row(db: AppDatabase, run: UUID) -> dict[str, Any]:
    with db.superuser() as conn:
        row = conn.execute("SELECT id, spent_usd, held_usd, calls_consumed, calls_held, overrun, cap_usd, cap_calls "
                           "FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone()
    keys = ("id", "spent", "held", "consumed", "calls_held", "overrun", "cap_usd", "cap_calls")
    return dict(zip(keys, row, strict=True))


def eval_scope(db: AppDatabase, scope_id: UUID) -> tuple[Any, ...]:
    with db.superuser() as conn:
        return tuple(conn.execute("SELECT spent_usd, held_usd, calls_consumed, calls_held, overrun FROM "
                                  "evaluation.budget_scopes WHERE id = %s", (scope_id,)).fetchone())


def attempt_state(db: AppDatabase, attempt: UUID, table: str = "app.usage_attempts") -> str:
    with db.superuser() as conn:
        # `table` is one of two fixed names in this file.
        return str(conn.execute(f"SELECT state FROM {table} WHERE id = %s", (attempt,)).fetchone()[0])  # noqa: S608


def contended(db: AppDatabase, table: str, row_id: UUID, *calls: Callable[[], Any]) -> list[Any]:
    """Run `calls` concurrently while a superuser transaction holds `row_id` in `table`. Once every call waits on
    a lock, the holder commits. Each result is the return value or the raised exception."""
    results: list[Any] = [None] * len(calls)

    def run(index: int, call: Callable[[], Any]) -> None:
        try:
            results[index] = call()
        except Exception as error:  # the outcome under test
            results[index] = error

    with db.server.connect("postgres", db.name) as holder:
        holder.execute(f"SELECT 1 FROM {table} WHERE id = %s FOR UPDATE", (row_id,))  # noqa: S608 (fixed names)
        threads = [threading.Thread(target=run, args=(i, call), daemon=True) for i, call in enumerate(calls)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 20
        with db.superuser() as watcher:
            while watcher.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = %s AND wait_event_type = "
                                  "'Lock'", (db.name,)).fetchone()[0] < len(calls):
                assert time.monotonic() < deadline, "the competing calls never queued on the held row"
                assert all(thread.is_alive() for thread in threads), results
                time.sleep(0.02)
        holder.commit()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    return results


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("budget")


def first_hold(db: AppDatabase, caps: Caps | None = None) -> tuple[UUID, UUID, Books, UUID]:
    """A workspace and run with one reserved agent attempt (which also creates the run's scope)."""
    ws = workspace(db)
    run = new_run(db, ws)
    books = ledger(db, ws, caps)
    attempt = uuid4()
    assert books.reserve(RunBinding(run), attempt, "agent", "turn-1").created
    return ws, run, books, attempt


# -- reservations ------------------------------------------------------------------------------------------------

def test_concurrent_holds_cannot_overcommit_the_run(db: AppDatabase) -> None:
    _ws, run, books, first = first_hold(db, Caps(run_usd=Decimal("0.006")))  # room for two holds, not three
    scope = scope_row(db, run)
    a, b = uuid4(), uuid4()
    results = contended(db, "app.budget_scopes", scope["id"],
                        lambda: books.reserve(RunBinding(run), a, "agent", "turn-2"),
                        lambda: books.reserve(RunBinding(run), b, "agent", "turn-3"))
    won = [r for r in results if isinstance(r, Reserved)]
    lost = [r for r in results if isinstance(r, BudgetExhausted)]
    assert len(won) == 1 and len(lost) == 1 and lost[0].reason == "usd_cap", results
    after = scope_row(db, run)
    assert (after["held"], after["calls_held"], after["spent"], after["consumed"]) == (2 * HOLD, 2, 0, 0)
    assert first != won[0].attempt.id


def test_call_cap_counts_held_and_consumed_calls(db: AppDatabase) -> None:
    _ws, run, books, first = first_hold(db, Caps(run_calls=2))
    assert isinstance(books.begin_dispatch(first), DispatchGranted)  # consumed 1
    books.reserve(RunBinding(run), uuid4(), "judge", "turn-2")  # held 1
    with pytest.raises(BudgetExhausted) as refused:
        books.reserve(RunBinding(run), uuid4(), "reranker", "turn-3")
    assert refused.value.reason == "call_cap" and refused.value.rule_id == "budget.call_cap"


def test_reserve_replay_is_idempotent_and_a_changed_intent_conflicts(db: AppDatabase) -> None:
    ws, run, books, attempt = first_hold(db)
    replay = books.reserve(RunBinding(run), attempt, "agent", "turn-1")
    assert not replay.created and replay.attempt.state == "reserved"
    assert ledger(db, ws).reserve(RunBinding(run), attempt, "agent", "turn-1").created is False  # a new process
    for actor, operation in (("judge", "turn-1"), ("agent", "turn-2")):
        with pytest.raises(LedgerConflict):
            books.reserve(RunBinding(run), attempt, actor, operation)
    other_run = new_run(db, ws)
    with pytest.raises(LedgerConflict):  # the same attempt ID under another run's scope
        books.reserve(RunBinding(other_run), attempt, "agent", "turn-1")
    scope = scope_row(db, run)
    assert (scope["held"], scope["calls_held"]) == (HOLD, 1)  # nothing was charged twice
    with pytest.raises(NotFound):
        books.reserve(RunBinding(uuid4()), uuid4(), "agent", "turn-1")


def test_run_caps_cannot_be_reset_by_a_new_process_or_changed_caps(db: AppDatabase) -> None:
    ws, run, _books, _attempt = first_hold(db)
    restarted = ledger(db, ws)
    restarted.reserve(RunBinding(run), uuid4(), "agent", "turn-2")
    assert scope_row(db, run)["held"] == 2 * HOLD  # the same scope, not a fresh budget
    with pytest.raises(LedgerConflict, match="different caps"):
        ledger(db, ws, Caps(run_usd=Decimal("1"))).reserve(RunBinding(run), uuid4(), "agent", "turn-3")
    with db.superuser() as conn:
        assert conn.execute("SELECT count(*) FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone() == (1,)


def test_operation_scopes_budget_non_run_work(db: AppDatabase) -> None:
    ws = workspace(db)
    books = ledger(db, ws, Caps(operation_calls=1))
    binding = OperationBinding("ingestion", "document-set-1")
    attempt = uuid4()
    books.reserve(binding, attempt, "embedding", "batch-1")
    with pytest.raises(BudgetExhausted, match="call_cap"):
        books.reserve(binding, uuid4(), "embedding", "batch-2")
    assert isinstance(books.begin_dispatch(attempt), DispatchGranted)
    settled = books.settle(attempt, Settlement(Usage(4000)))
    assert settled.attempt.actual_usd == Decimal("0.00008")
    with db.superuser() as conn:
        assert conn.execute("SELECT kind, spent_usd, held_usd, run_id FROM app.budget_scopes WHERE workspace_id = %s",
                            (ws,)).fetchone() == ("operation", Decimal("0.00008"), 0, None)
        assert conn.execute("SELECT count(*) FROM app.runs WHERE workspace_id = %s", (ws,)).fetchone() == (0,)


# -- dispatch, release and settlement ----------------------------------------------------------------------------

def test_one_attempt_gets_at_most_one_dispatch_grant(db: AppDatabase) -> None:
    _ws, run, books, attempt = first_hold(db)
    results = contended(db, "app.budget_scopes", scope_row(db, run)["id"],
                        lambda: books.begin_dispatch(attempt), lambda: books.begin_dispatch(attempt),
                        lambda: books.begin_dispatch(attempt))
    granted = [r for r in results if isinstance(r, DispatchGranted)]
    refused = [r for r in results if isinstance(r, DispatchRefused)]
    assert len(granted) == 1 and len(refused) == 2 and {r.reason for r in refused} == {"dispatching"}, results
    scope = scope_row(db, run)
    assert (scope["consumed"], scope["calls_held"], scope["held"]) == (1, 0, HOLD)  # the hold stays until settled
    later = books.begin_dispatch(attempt)
    assert isinstance(later, DispatchRefused) and later.reason == "dispatching"


def test_release_and_dispatch_race_has_one_consistent_winner(db: AppDatabase) -> None:
    _ws, run, books, _first = first_hold(db)
    outcomes = set()
    for turn in range(4):
        attempt = uuid4()
        books.reserve(RunBinding(run), attempt, "agent", f"race-{turn}")
        before = scope_row(db, run)
        release, dispatch = contended(db, "app.budget_scopes", before["id"], partial(books.release, attempt),
                                      partial(books.begin_dispatch, attempt))
        after = scope_row(db, run)
        if isinstance(dispatch, DispatchGranted):
            assert isinstance(release, IllegalTransition) and attempt_state(db, attempt) == "dispatching"
            assert (after["held"], after["consumed"]) == (before["held"], before["consumed"] + 1)
            outcomes.add("dispatched")
        else:
            assert isinstance(dispatch, DispatchRefused) and dispatch.reason == "released", (release, dispatch)
            assert attempt_state(db, attempt) == "released"
            assert (after["held"], after["consumed"]) == (before["held"] - HOLD, before["consumed"])
            outcomes.add("released")
        assert after["calls_held"] == before["calls_held"] - 1
    assert outcomes  # either order is legal; each was consistent


def test_settlement_is_exact_replayable_and_never_downgraded(db: AppDatabase) -> None:
    _ws, run, books, attempt = first_hold(db)
    books.begin_dispatch(attempt)
    usage = Settlement(Usage(12000, cache_read=4000, output=1500, reasoning=500), provider_request_id="resp_1")
    results = contended(db, "app.budget_scopes", scope_row(db, run)["id"], lambda: books.settle(attempt, usage),
                        lambda: books.mark_unresolved(attempt))
    settled, _marked = results
    assert isinstance(settled, Settled) and not isinstance(_marked, Exception), results
    assert attempt_state(db, attempt) == "settled"  # whichever ran first, the known result stands
    actual = Decimal("0.00159")  # (8000 x 0.10 + 4000 x 0.01 + 1500 x 0.50) / 1e6
    scope = scope_row(db, run)
    assert (scope["spent"], scope["held"], scope["consumed"], scope["overrun"]) == (actual, 0, 1, False)
    assert books.settle(attempt, usage).replayed
    assert books.mark_unresolved(attempt).state == "settled"
    with pytest.raises(LedgerConflict):
        books.settle(attempt, Settlement(Usage(12000, output=1500), provider_request_id="resp_1"))
    with pytest.raises(IllegalTransition):
        books.release(attempt)
    assert scope_row(db, run)["spent"] == actual
    with db.superuser() as conn:
        event = conn.execute("SELECT attempt_id, run_id, provider_request_id, uncached_input_tokens, "
                             "cache_read_tokens, output_tokens, reasoning_tokens, cost_status, cost_usd, "
                             "price_revision FROM app.usage_events WHERE attempt_id = %s", (attempt,)).fetchall()
        stored = conn.execute("SELECT usage, actual_tier, actual_usd FROM app.usage_attempts WHERE id = %s",
                              (attempt,)).fetchone()
    assert event == [(attempt, run, "resp_1", 8000, 4000, 1500, 500, "known", actual, "pricing.2026-11-05.v1")]
    assert stored[1:] == ("short", actual) and stored[0]["input_total"] == 12000


def test_unknown_usage_keeps_the_hold_and_a_zero_usage_request_keeps_its_slot(db: AppDatabase) -> None:
    _ws, run, books, attempt = first_hold(db, Caps(run_calls=2))
    with pytest.raises(IllegalTransition):  # never dispatched, so it cannot be unknown
        books.mark_unresolved(attempt)
    books.begin_dispatch(attempt)
    assert books.mark_unresolved(attempt).state == "unresolved"
    scope = scope_row(db, run)
    assert (scope["held"], scope["consumed"], scope["calls_held"]) == (HOLD, 1, 0)  # conservative: kept
    with pytest.raises(IllegalTransition):
        books.release(attempt)  # it may have been billed
    books.settle(attempt, Settlement(Usage(0)))  # a known zero-cost result: the slot stays consumed
    scope = scope_row(db, run)
    assert (scope["spent"], scope["held"], scope["consumed"]) == (0, 0, 1)
    books.reserve(RunBinding(run), uuid4(), "agent", "turn-2")
    with pytest.raises(BudgetExhausted, match="call_cap"):
        books.reserve(RunBinding(run), uuid4(), "agent", "turn-3")


def test_an_overrun_blocks_new_holds_and_earlier_reserved_dispatches(db: AppDatabase) -> None:
    _ws, run, books, attempt = first_hold(db, Caps(run_usd=Decimal("1")))
    waiting = uuid4()
    books.reserve(RunBinding(run), waiting, "agent", "turn-2")
    books.begin_dispatch(attempt)
    over = books.settle(attempt, Settlement(Usage(30000, output=100)))  # more prompt than the admitted 16000
    assert over.attempt.overrun and over.attempt.actual_usd == Decimal("0.00305") > HOLD
    scope = scope_row(db, run)
    assert scope["overrun"] and scope["spent"] == Decimal("0.00305")  # the true amount, far below the cap
    with pytest.raises(BudgetExhausted) as blocked:
        books.reserve(RunBinding(run), uuid4(), "agent", "turn-3")
    assert blocked.value.reason == "blocked_by_overrun"
    refused = books.begin_dispatch(waiting)
    assert isinstance(refused, DispatchRefused) and refused.reason == "blocked_by_overrun"
    assert refused.attempt.state == "reserved"
    assert books.release(waiting).state == "released"  # proven never dispatched
    assert scope_row(db, run)["held"] == 0


def test_settlement_after_cancellation_records_the_bill_but_authorizes_nothing(db: AppDatabase) -> None:
    _ws, run, books, attempt = first_hold(db)
    waiting = uuid4()
    books.reserve(RunBinding(run), waiting, "simulator", "turn-2")
    books.begin_dispatch(attempt)
    with db.superuser() as conn:
        conn.execute("UPDATE app.runs SET state = 'cancelled' WHERE id = %s", (run,))
    assert books.settle(attempt, Settlement(Usage(1000, output=10))).attempt.actual_usd == Decimal("0.000105")
    with pytest.raises(ScopeInactive):
        books.reserve(RunBinding(run), uuid4(), "agent", "turn-3")
    refused = books.begin_dispatch(waiting)
    assert isinstance(refused, DispatchRefused) and refused.reason == "run_not_active"
    books.release(waiting)
    scope = scope_row(db, run)
    assert (scope["spent"], scope["held"], scope["consumed"], scope["calls_held"]) == (Decimal("0.000105"), 0, 1, 0)


def test_a_provider_request_id_belongs_to_one_attempt(db: AppDatabase) -> None:
    ws, run, books, first = first_hold(db)
    second = uuid4()
    books.reserve(RunBinding(run), second, "agent", "turn-2")
    books.begin_dispatch(first)
    books.begin_dispatch(second)
    books.settle(first, Settlement(Usage(100, output=10), provider_request_id="resp_shared"))
    with pytest.raises(LedgerConflict):
        books.settle(second, Settlement(Usage(100, output=10), provider_request_id="resp_shared"))
    assert attempt_state(db, second) == "dispatching"  # rolled back: the hold is kept, nothing invented
    assert scope_row(db, run)["held"] == HOLD
    with workspace_transaction(db.engine(APP_RUNTIME), ws) as conn, pytest.raises(IdempotencyConflict):
        repo.record_usage(conn, UsageEvent(  # the legacy path sees the same identity
            id=uuid4(), workspace_id=ws, actor="agent", provider="openai", model="gpt-6-luna",
            provider_request_id="resp_shared", uncached_input_tokens=1, cache_read_tokens=0, cache_write_tokens=0,
            output_tokens=0, reasoning_tokens=0, price_revision="pricing.2026-11-05.v1", cost_status="known",
            cost_usd=Decimal("0"), created_at=datetime.now(UTC)))
    books.settle(second, Settlement(Usage(100, output=10)))  # without a provider ID: identified by the attempt
    assert scope_row(db, run)["held"] == 0


def test_another_workspace_cannot_see_or_charge_this_ledger(db: AppDatabase) -> None:
    _ws, run, books, attempt = first_hold(db)
    intruder_ws = workspace(db)
    intruder = ledger(db, intruder_ws)
    with pytest.raises(NotFound):
        intruder.reserve(RunBinding(run), uuid4(), "agent", "turn-1")
    for call in (lambda: intruder.begin_dispatch(attempt), lambda: intruder.release(attempt),
                 lambda: intruder.mark_unresolved(attempt),
                 lambda: intruder.settle(attempt, Settlement(Usage(1)))):
        with pytest.raises(NotFound):
            call()
    own_run = new_run(db, intruder_ws)
    with pytest.raises(LedgerConflict):  # a colliding attempt ID is refused, never adopted
        intruder.reserve(RunBinding(own_run), attempt, "agent", "turn-1")
    assert attempt_state(db, attempt) == "reserved"
    assert books.begin_dispatch(attempt).attempt.state == "dispatching"


# -- evaluation ledger -------------------------------------------------------------------------------------------

def eval_ledger(db: AppDatabase, caps: Caps | None = None) -> tuple[Books, EvalLedgerStore, Caps]:
    caps = caps or Caps()
    books, store = build_eval_ledger(env="test", engine=db.engine(EVAL_RUNTIME, pool_size=6),
                                     configuration=Configuration(caps=caps))
    return Books(books), store, caps


def test_eval_attempts_charge_scenario_invocation_and_study(db: AppDatabase) -> None:
    books, store, caps = eval_ledger(db)
    study = store.ensure_study("study-a", SHA, cap_usd=Decimal("0.005"), cap_calls=100)
    assert store.ensure_study("study-a", SHA, cap_usd=Decimal("0.005"), cap_calls=100) == study  # replay
    with pytest.raises(LedgerConflict):
        store.ensure_study("study-a", "b" * 64, cap_usd=Decimal("0.005"), cap_calls=100)
    with pytest.raises(LedgerConflict):
        store.ensure_study("study-a", SHA, cap_usd=Decimal("5"), cap_calls=100)  # a reset by new caps
    invocation = store.ensure_invocation(study, uuid4(), caps)
    scenario = store.ensure_scenario(study, "task-1", 0, SHA, caps)
    assert store.ensure_scenario(study, "task-1", 0, SHA, caps) == scenario
    attempt = uuid4()
    books.reserve(EvalBinding(study, invocation, scenario), attempt, "agent", "turn-1")
    for scope_id in (study, invocation, scenario):
        assert eval_scope(db, scope_id) == (0, HOLD, 0, 1, False)
    books.begin_dispatch(attempt)
    books.settle(attempt, Settlement(Usage(1000, output=100), provider_request_id="msg_1"))
    for scope_id in (study, invocation, scenario):
        assert eval_scope(db, scope_id) == (Decimal("0.00015"), 0, 1, 0, False)
    # A new invocation (a new process) still sees the study's spend; it cannot omit the study.
    second = store.ensure_invocation(study, uuid4(), caps)
    other = store.ensure_scenario(study, "task-2", 0, SHA, caps)
    books.reserve(EvalBinding(study, second, other), uuid4(), "judge", "turn-1")  # 0.00015 + 0.002624 held
    with pytest.raises(BudgetExhausted, match="study budget: usd_cap"):  # another 0.002624 would exceed 0.005
        books.reserve(EvalBinding(study, second, other), uuid4(), "judge", "turn-2")
    snapshot = store.study_by_key("study-a")
    assert snapshot is not None and snapshot.held_usd == HOLD and snapshot.spent_usd == Decimal("0.00015")
    assert snapshot.available_usd == Decimal("0.005") - Decimal("0.00015") - HOLD


def test_eval_bindings_must_share_one_study(db: AppDatabase) -> None:
    books, store, caps = eval_ledger(db)
    one = store.ensure_study("study-one", SHA, cap_usd=Decimal(5), cap_calls=100)
    two = store.ensure_study("study-two", SHA, cap_usd=Decimal(5), cap_calls=100)
    invocation = store.ensure_invocation(one, uuid4(), caps)
    foreign = store.ensure_scenario(two, "task-1", 0, SHA, caps)
    with pytest.raises(NotFound):
        books.reserve(EvalBinding(one, invocation, foreign), uuid4(), "agent", "turn-1")
    with pytest.raises(NotFound):
        books.reserve(EvalBinding(two, invocation, foreign), uuid4(), "agent", "turn-1")
    with pytest.raises(LedgerConflict):  # an invocation ID cannot move to another study
        store.ensure_invocation(two, invocation, caps)
    with pytest.raises(NotFound):
        store.ensure_scenario(uuid4(), "task-1", 0, SHA, caps)
    with pytest.raises(TypeError):
        books.reserve(RunBinding(uuid4()), uuid4(), "agent", "turn-1")
    with db.superuser() as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute("INSERT INTO evaluation.usage_attempts (id, study_scope_id, invocation_scope_id, "
                     "scenario_scope_id, actor, provider, model, price_revision, config_sha256, cache_mode, max_input, "
                     "max_output, operation_id, intent_sha256, reserved_usd, state, request_sha256, created_at, "
                     "updated_at) VALUES (gen_random_uuid(), %s, %s, %s, 'agent', 'openai', 'gpt-6-luna', 'r', %s, "
                     "'none', 1, 1, 'o', %s, 0, 'reserved', %s, now(), now())",
                     (one, invocation, foreign, SHA, SHA, SHA))


def test_concurrent_eval_holds_respect_the_shared_study(db: AppDatabase) -> None:
    books, store, caps = eval_ledger(db)
    study = store.ensure_study("study-race", SHA, cap_usd=Decimal("0.004"), cap_calls=100)  # room for one hold
    bindings = [EvalBinding(study, store.ensure_invocation(study, uuid4(), caps),
                            store.ensure_scenario(study, f"task-{i}", 0, SHA, caps)) for i in range(2)]
    results = contended(db, "evaluation.budget_scopes", study,
                        *[lambda b=b: books.reserve(b, uuid4(), "agent", "turn-1") for b in bindings])
    assert sorted(type(r).__name__ for r in results) == ["BudgetExhausted", "Reserved"], results
    assert eval_scope(db, study) == (0, HOLD, 0, 1, False)


# -- composition, roles and grants -------------------------------------------------------------------------------

def test_stores_refuse_the_wrong_role_and_a_test_clock_outside_tests(db: AppDatabase) -> None:
    ws = workspace(db)
    for role in (APP_MIGRATOR, EVAL_RUNTIME, AUTH_RUNTIME):
        with pytest.raises(RuntimeRoleError):
            AppLedgerStore(db.engine(role), ws, env="test")
    for role in (APP_MIGRATOR, APP_RUNTIME):
        with pytest.raises(RuntimeRoleError):
            EvalLedgerStore(db.engine(role), env="test")
    fixed = FixedLeaseClock(FixedClock(datetime(2026, 11, 5, tzinfo=UTC)))
    with pytest.raises(UnsafeTestHook):
        AppLedgerStore(db.engine(APP_RUNTIME), ws, env="production", clock=fixed)
    with pytest.raises(UnsafeTestHook):
        build_eval_ledger(env="production", engine=db.engine(EVAL_RUNTIME), configuration=Configuration(),
                          clock=fixed)


def test_runtime_roles_cannot_rewrite_caps_intent_or_cross_schemas(db: AppDatabase) -> None:
    ws, run, _books, attempt = first_hold(db)
    _eval_books, store, _caps = eval_ledger(db)
    study = store.ensure_study("study-grants", SHA, cap_usd=Decimal(5), cap_calls=100)
    app_statements = ("UPDATE app.budget_scopes SET cap_usd = 100", "UPDATE app.budget_scopes SET run_id = NULL",
                      "UPDATE app.usage_attempts SET reserved_usd = 0", "UPDATE app.usage_attempts SET actor = 'judge'",
                      "DELETE FROM app.usage_attempts", "DELETE FROM app.budget_scopes",
                      "SELECT 1 FROM evaluation.budget_scopes", "SELECT 1 FROM evaluation.usage_attempts")
    with db.server.connect(APP_RUNTIME, db.name) as conn:
        conn.execute("SELECT set_config('policyops.workspace_id', %s, false)", (str(ws),))
        for statement in app_statements:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
            conn.rollback()
            conn.execute("SELECT set_config('policyops.workspace_id', %s, false)", (str(ws),))
    eval_statements = ("UPDATE evaluation.budget_scopes SET cap_usd = 100",
                       "UPDATE evaluation.budget_scopes SET parent_id = NULL",
                       "UPDATE evaluation.usage_attempts SET reserved_usd = 0", "DELETE FROM evaluation.budget_scopes",
                       "SELECT 1 FROM app.budget_scopes", "SELECT 1 FROM app.usage_attempts",
                       "SELECT 1 FROM app.usage_events")
    with db.server.connect(EVAL_RUNTIME, db.name) as conn:
        for statement in eval_statements:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
            conn.rollback()
    with db.superuser() as conn:
        assert conn.execute("SELECT cap_usd FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone() == (
            Decimal("0.05"),)
        assert conn.execute("SELECT cap_usd FROM evaluation.budget_scopes WHERE id = %s", (study,)).fetchone() == (
            Decimal(5),)
    assert attempt_state(db, attempt) == "reserved"


def test_counter_constraints_hold_on_the_server(db: AppDatabase) -> None:
    _ws, run, _books, attempt = first_hold(db)
    scope = scope_row(db, run)["id"]
    with db.superuser() as conn:
        for statement, constraint in (
                ("UPDATE app.budget_scopes SET calls_held = 13 WHERE id = %s", "budget_scopes_calls_within_cap"),
                ("UPDATE app.budget_scopes SET held_usd = -1 WHERE id = %s", "budget_scopes_held_usd_exact"),
                ("UPDATE app.budget_scopes SET spent_usd = 0.0000000000000000001 WHERE id = %s",
                 "budget_scopes_spent_usd_exact")):
            with pytest.raises(psycopg.errors.CheckViolation, match=constraint):
                conn.execute(statement, (scope,))
        with pytest.raises(psycopg.errors.CheckViolation, match="usage_attempts_settled_has_usage"):
            conn.execute("UPDATE app.usage_attempts SET state = 'settled' WHERE id = %s", (attempt,))
        with pytest.raises(psycopg.errors.CheckViolation, match="usage_attempts_overrun_only_settled"):
            conn.execute("UPDATE app.usage_attempts SET overrun = true WHERE id = %s", (attempt,))
        with pytest.raises(psycopg.errors.CheckViolation, match="usage_events_identity"):
            conn.execute("INSERT INTO app.usage_events (id, workspace_id, actor, provider, model, "
                         "uncached_input_tokens, cache_read_tokens, cache_write_tokens, output_tokens, "
                         "reasoning_tokens, price_revision, cost_status, cost_usd, created_at) SELECT "
                         "gen_random_uuid(), workspace_id, 'agent', 'openai', 'gpt-6-luna', 1, 0, 0, 0, 0, 'r', "
                         "'known', 0, now() FROM app.budget_scopes WHERE id = %s",
                         (scope,))


# -- migration ---------------------------------------------------------------------------------------------------

def legacy_event(ws: UUID, request_id: str, output: int = 5) -> UsageEvent:
    return UsageEvent(id=uuid4(), workspace_id=ws, actor="agent", provider="fake", model="fake-small",
                      provider_request_id=request_id, uncached_input_tokens=10, cache_read_tokens=0,
                      cache_write_tokens=0, output_tokens=output, reasoning_tokens=0, price_revision="synthetic-1",
                      cost_status="known", cost_usd=Decimal("0.000001"), created_at=World.now)


def legacy_settled(conn: Any, ws: UUID, run: UUID, request_id: str | None) -> UUID:
    """A revision-0006 (T10, intent v1) settled attempt and its usage event, written directly as 0006 rows: the 0006
    downgrade is about data that existed before 0007, which new (v2) code can no longer create."""
    scope = conn.execute("SELECT id FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone()
    if scope is None:
        scope = conn.execute(
            "INSERT INTO app.budget_scopes (id, workspace_id, kind, run_id, cap_usd, cap_calls, spent_usd, "
            "calls_consumed, created_at, updated_at) VALUES (gen_random_uuid(), %s, 'run', %s, 0.05, 12, 0, 0, now(), "
            "now()) RETURNING id", (ws, run)).fetchone()
    attempt = uuid4()
    conn.execute(
        "INSERT INTO app.usage_attempts (id, workspace_id, scope_id, actor, provider, model, price_revision, "
        "config_sha256, cache_mode, max_input, max_output, operation_id, intent_sha256, reserved_usd, state, "
        "provider_request_id, usage, usage_sha256, actual_tier, actual_usd, created_at, updated_at) VALUES "
        "(%s, %s, %s, 'agent', 'openai', 'gpt-6-luna', 'pricing.2026-11-05.v1', %s, 'none', 16000, 2048, %s, %s, "
        "0.002624, 'settled', %s, '{}'::jsonb, %s, 'short', 0.0000105, now(), now())",
        (attempt, ws, scope[0], SHA, f"turn-{attempt}", SHA, request_id, SHA))
    conn.execute(
        "INSERT INTO app.usage_events (id, workspace_id, attempt_id, run_id, actor, provider, model, "
        "provider_request_id, uncached_input_tokens, cache_read_tokens, cache_write_tokens, output_tokens, "
        "reasoning_tokens, price_revision, cost_status, cost_usd, created_at) VALUES (gen_random_uuid(), %s, %s, %s, "
        "'agent', 'openai', 'gpt-6-luna', %s, 100, 0, 0, 1, 0, 'pricing.2026-11-05.v1', 'known', 0.0000105, now())",
        (ws, attempt, run, request_id))
    return attempt


def test_0006_upgrades_populated_data_and_guards_its_downgrade(new_app_database: NewDatabase) -> None:
    database = new_app_database("budget_upgrade", revision="0005")
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    world = World()
    event = legacy_event(world.workspace, "legacy-1")
    with workspace_transaction(database.engine(APP_RUNTIME), world.workspace) as conn:
        assert repo.record_usage(conn, event)
    database.upgrade("0006")
    assert database.current() == "0006"
    with workspace_transaction(database.engine(APP_RUNTIME), world.workspace) as conn:
        assert repo.record_usage(conn, event) is False  # the legacy replay key still holds
        assert repo.record_usage(conn, legacy_event(world.workspace, "legacy-1")) is False  # same content
        with pytest.raises(IdempotencyConflict):
            repo.record_usage(conn, legacy_event(world.workspace, "legacy-1", output=6))
    with database.superuser() as conn:
        legacy_settled(conn, world.workspace, world.run, "resp_kept")
        legacy_settled(conn, world.workspace, world.run, None)
    with pytest.raises(DataLossRefused, match=r"app\.budget_scopes"):
        database.downgrade("0005")
    assert database.current() == "0006"
    database.downgrade("0005", allow_data_loss=True)
    with database.superuser() as conn:
        assert conn.execute("SELECT provider_request_id FROM app.usage_events ORDER BY 1").fetchall() == [
            ("legacy-1",), ("resp_kept",)]  # the attempt-only event could not survive NOT NULL
        assert conn.execute("SELECT bool_and(relforcerowsecurity) FROM pg_class c JOIN pg_namespace n "
                            "ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND relkind = 'r'").fetchone() == (True,)
        assert conn.execute("SELECT to_regclass('app.usage_attempts'), to_regclass('evaluation.budget_scopes')"
                            ).fetchone() == (None, None)
    database.upgrade()
    assert database.current() == "0007"


def force_state(database: AppDatabase) -> bool:
    with database.superuser() as conn:
        return bool(conn.execute("SELECT relforcerowsecurity FROM pg_class WHERE oid = "
                                 "'app.usage_events'::regclass").fetchone()[0])


@pytest.mark.parametrize("initially_forced", [True, False])
def test_0006_downgrade_restores_the_exact_previous_force_state(new_app_database: NewDatabase,
                                                                initially_forced: bool) -> None:
    database = new_app_database("budget_force", revision="0006")
    ws = workspace(database)
    run = new_run(database, ws)
    with database.superuser() as conn:
        legacy_settled(conn, ws, run, None)  # an attempt-only event, deleted by the lossy path
    if not initially_forced:
        with database.superuser() as conn:
            conn.execute("ALTER TABLE app.usage_events NO FORCE ROW LEVEL SECURITY")
    assert force_state(database) is initially_forced
    with pytest.raises(DataLossRefused):
        database.downgrade("0005")
    assert force_state(database) is initially_forced  # the refusal rolled back
    database.downgrade("0005", allow_data_loss=True)
    assert force_state(database) is initially_forced
    with database.superuser() as conn:
        assert conn.execute("SELECT count(*) FROM app.usage_events").fetchone() == (0,)
