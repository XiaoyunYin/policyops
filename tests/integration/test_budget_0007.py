"""Revision 0007 and the T11 ledger extensions on real PostgreSQL, as the actual runtime roles: request-bound v2
intents, one persisted count per attempt, dispatch gating on the admitted count, contract blocks across every parent
scope, legacy v1 rows after the upgrade, and the downgrade that always refuses populated 0007 data.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.budget.ledger import (
    BudgetExhausted,
    CountGranted,
    CountRefused,
    Diagnostic,
    DispatchGranted,
    DispatchRefused,
    EvalBinding,
    Ledger,
    LedgerConflict,
    NotFound,
    RunBinding,
    Settlement,
)
from policyops.budget.pricing import Usage
from policyops.persistence import repositories as repo
from policyops.persistence.budget import build_eval_ledger
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.records import NewCase, NewRun, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, EVAL_RUNTIME
from policyops_contracts.digest import text_sha256
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.claims import component_ledger as build_app_ledger


pytestmark = pytest.mark.postgres
REQUEST, OTHER, SHA = "c" * 64, "d" * 64, "a" * 64
HOLD = Decimal("0.002624")


def workspace(db: AppDatabase) -> UUID:
    ws = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=ws, slug=f"ws-{ws.hex[:12]}", name="Budget 0007 test",
                                              created_at=datetime.now(UTC)))
    return ws


def new_run(db: AppDatabase, ws: UUID) -> UUID:
    case, run, now = uuid4(), uuid4(), datetime.now(UTC)
    from policyops_testing.migration_fixtures import seed_at_head

    with seed_at_head(db), workspace_transaction(db.engine(APP_RUNTIME), ws) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=ws, scenario="retail", customer_user_id=None,
                                                created_by=None, created_at=now))
        repo.create_run(conn, NewRun(id=run, workspace_id=ws, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=now + timedelta(hours=1),
                                     created_at=now))
    return run


def ledger(db: AppDatabase, ws: UUID, configuration: Configuration | None = None) -> Ledger:
    return build_app_ledger(env="test", engine=db.engine(APP_RUNTIME, pool_size=6), workspace_id=ws,
                            configuration=configuration or Configuration())


def scope(db: AppDatabase, run: UUID) -> dict[str, Any]:
    with db.superuser() as conn:
        row = conn.execute("SELECT id, held_usd, calls_held, calls_consumed, counts_used, cap_counts, contract_block "
                           "FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone()
    return dict(zip(("id", "held", "calls_held", "consumed", "counts", "cap_counts", "block"), row, strict=True))


def attempt_row(db: AppDatabase, attempt: UUID, table: str = "app.usage_attempts") -> dict[str, Any]:
    with db.superuser() as conn:
        # `table` is one of two fixed names in this file.
        row = conn.execute(f"SELECT state, intent_version, request_sha256, count_state, counted_input_tokens, "  # noqa: S608
                           f"contract_block, diagnostic, actual_usd FROM {table} WHERE id = %s", (attempt,)).fetchone()
    keys = ("state", "version", "request", "count_state", "counted", "block", "diagnostic", "actual_usd")
    return dict(zip(keys, row, strict=True))


def contended(db: AppDatabase, table: str, row_id: UUID, *calls: Callable[[], Any]) -> list[Any]:
    """Run `calls` concurrently while a superuser transaction holds `row_id`; once all wait on it, it commits."""
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
                time.sleep(0.02)
        holder.commit()
    for thread in threads:
        thread.join(timeout=30)
    return results


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("budget0007")


def reserved(db: AppDatabase, caps: Caps | None = None) -> tuple[UUID, UUID, Ledger, UUID]:
    ws = workspace(db)
    run = new_run(db, ws)
    books = ledger(db, ws, Configuration(caps=caps or Caps()))
    attempt = uuid4()
    assert books.reserve(RunBinding(run), attempt, "agent", "turn-1", REQUEST).created
    return ws, run, books, attempt


# -- counts -------------------------------------------------------------------------------------------------------

def test_one_count_grant_per_attempt_under_contention(db: AppDatabase) -> None:
    _ws, run, books, attempt = reserved(db)
    results = contended(db, "app.budget_scopes", scope(db, run)["id"],
                        *[lambda: books.claim_count(attempt, REQUEST) for _ in range(3)])
    granted = [r for r in results if isinstance(r, CountGranted)]
    refused = [r for r in results if isinstance(r, CountRefused)]
    assert len(granted) == 1 and len(refused) == 2 and {r.reason for r in refused} == {"count_claimed"}, results
    assert scope(db, run)["counts"] == 1
    assert attempt_row(db, attempt)["count_state"] == "claimed"


def test_count_units_are_never_returned_and_are_capped(db: AppDatabase) -> None:
    _ws, run, books, first = reserved(db, Caps(run_calls=2))
    assert scope(db, run)["cap_counts"] == 2
    assert isinstance(books.claim_count(first, REQUEST), CountGranted)
    books.record_count(first, tokens=None, source="failed")
    books.release(first)
    second = uuid4()
    books.reserve(RunBinding(run), second, "agent", "turn-2", REQUEST)
    assert isinstance(books.claim_count(second, REQUEST), CountGranted)
    books.release(second)  # the claimed count unit is not returned
    third = uuid4()
    books.reserve(RunBinding(run), third, "agent", "turn-3", REQUEST)  # call slots are free again ...
    refused = books.claim_count(third, REQUEST)
    assert isinstance(refused, CountRefused) and refused.reason == "count_cap"  # ... but counts are not
    after = scope(db, run)
    assert (after["counts"], after["calls_held"]) == (2, 1)


def test_dispatch_itself_requires_the_bound_request_and_an_admitted_count(db: AppDatabase) -> None:
    _ws, run, books, attempt = reserved(db)

    def refusal(request: str = REQUEST) -> str:
        decision = books.begin_dispatch(attempt, request)
        assert isinstance(decision, DispatchRefused)
        return decision.reason

    assert refusal() == "count_not_admitted"
    assert refusal(OTHER) == "request_mismatch"
    assert isinstance(books.claim_count(attempt, OTHER), CountRefused)  # a different body cannot be counted here
    assert isinstance(books.claim_count(attempt, REQUEST), CountGranted)
    assert refusal() == "count_not_admitted"  # claimed, not yet recorded
    rejected = books.record_count(attempt, tokens=15_800, source="openai.count")  # 15800 + 1580 > 16000
    assert rejected.count_state == "rejected"
    assert refusal() == "count_not_admitted"
    assert books.record_count(attempt, tokens=15_800, source="openai.count").count_state == "rejected"  # replay
    with pytest.raises(LedgerConflict):
        books.record_count(attempt, tokens=100, source="openai.count")
    assert isinstance(books.claim_count(attempt, REQUEST), CountRefused)  # no recount
    books.release(attempt)
    admitted = uuid4()
    books.reserve(RunBinding(run), admitted, "agent", "turn-2", REQUEST)
    books.claim_count(admitted, REQUEST)
    assert books.record_count(admitted, tokens=14_000, source="openai.count").count_state == "admitted"
    assert isinstance(books.begin_dispatch(admitted, REQUEST), DispatchGranted)
    assert attempt_row(db, admitted)["counted"] == 14_000


def test_a_changed_actor_configuration_cannot_send_an_old_attempt(db: AppDatabase) -> None:
    ws, _run, books, attempt = reserved(db)
    books.claim_count(attempt, REQUEST)
    books.record_count(attempt, tokens=1000, source="openai.count")
    changed = Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "gpt-6-luna", "none")})
    decision = ledger(db, ws, changed).begin_dispatch(attempt, REQUEST)
    assert isinstance(decision, DispatchRefused) and decision.reason == "configuration_changed"
    assert isinstance(books.begin_dispatch(attempt, REQUEST), DispatchGranted)


def test_another_workspace_cannot_claim_a_count(db: AppDatabase) -> None:
    _ws, _run, _books, attempt = reserved(db)
    intruder = ledger(db, workspace(db))
    with pytest.raises(NotFound):
        intruder.claim_count(attempt, REQUEST)
    with pytest.raises(NotFound):
        intruder.record_count(attempt, tokens=1, source="x")
    assert attempt_row(db, attempt)["count_state"] == "none"


# -- contract blocks ----------------------------------------------------------------------------------------------

def sent(books: Ledger, binding: Any, actor: Any = "agent") -> UUID:
    attempt = uuid4()
    books.reserve(binding, attempt, actor, f"op-{attempt}", REQUEST)
    books.claim_count(attempt, REQUEST)
    books.record_count(attempt, tokens=1000, source="openai.count")
    assert isinstance(books.begin_dispatch(attempt, REQUEST), DispatchGranted)
    return attempt


def test_unpriceable_evidence_holds_and_blocks_every_parent_scope(db: AppDatabase) -> None:
    books, store = build_eval_ledger(env="test", engine=db.engine(EVAL_RUNTIME, pool_size=6),
                                     configuration=Configuration())
    caps = Caps()
    study = store.ensure_study("study-block", SHA, cap_usd=Decimal(5), cap_calls=100)
    invocation = store.ensure_invocation(study, uuid4(), caps)
    one = store.ensure_scenario(study, "task-1", 0, SHA, caps)
    two = store.ensure_scenario(study, "task-2", 0, SHA, caps)
    waiting = uuid4()  # reserved and counted in another scenario before the block
    books.reserve(EvalBinding(study, invocation, two), waiting, "judge", "waiting", REQUEST)
    books.claim_count(waiting, REQUEST)
    books.record_count(waiting, tokens=1000, source="anthropic.count")
    attempt = sent(books, EvalBinding(study, invocation, one), "judge")
    diagnostic = Diagnostic(("cache_ttl_unknown",), {"input_tokens": 400, "cache_creation": 200,
                                                     "cache_creation_5m": None})
    books.mark_unresolved(attempt, block="cache_ttl_unknown", diagnostic=diagnostic)
    row = attempt_row(db, attempt, "evaluation.usage_attempts")
    assert (row["state"], row["block"], row["actual_usd"]) == ("unresolved", "cache_ttl_unknown", None)
    assert row["diagnostic"]["codes"] == ["cache_ttl_unknown"]  # allowlisted counts and codes only
    with db.superuser() as conn:
        blocks = conn.execute("SELECT kind, contract_block, held_usd FROM evaluation.budget_scopes WHERE id = ANY(%s) "
                              "ORDER BY kind", ([study, invocation, one],)).fetchall()
    assert [(kind, block) for kind, block, _ in blocks] == [("invocation", "cache_ttl_unknown"),
                                                             ("scenario", "cache_ttl_unknown"),
                                                             ("study", "cache_ttl_unknown")]
    refused = books.begin_dispatch(waiting, REQUEST)  # the study is blocked, so the other scenario is too
    assert isinstance(refused, DispatchRefused) and refused.reason == "blocked_by_contract"
    with pytest.raises(BudgetExhausted, match="blocked_by_contract"):
        books.reserve(EvalBinding(study, invocation, two), uuid4(), "judge", "after", REQUEST)
    reopened, _store = build_eval_ledger(env="test", engine=db.engine(EVAL_RUNTIME, pool_size=2),
                                         configuration=Configuration())
    assert isinstance(reopened.begin_dispatch(waiting, REQUEST), DispatchRefused)  # survives a new store
    books.release(waiting)  # an unused hold can still be released


def test_a_known_mismatch_settles_the_exact_bill_and_blocks(db: AppDatabase) -> None:
    _ws, run, books, _attempt = reserved(db)
    attempt = sent(books, RunBinding(run))
    usage = Usage(1000, cache_read=400, cache_writes={"30m": 200}, output=120, reasoning=20)
    books.settle(attempt, Settlement(usage, "resp_1", block="cache_write_under_none"))
    row = attempt_row(db, attempt)
    assert (row["state"], row["actual_usd"], row["block"]) == ("settled", Decimal("0.000129"),
                                                               "cache_write_under_none")
    assert scope(db, run)["block"] == "cache_write_under_none"
    with pytest.raises(BudgetExhausted, match="blocked_by_contract"):
        books.reserve(RunBinding(run), uuid4(), "agent", "next", REQUEST)


# -- migration ----------------------------------------------------------------------------------------------------

def legacy_rows(conn: Any, ws: UUID, run: UUID) -> dict[str, UUID]:
    """Revision-0006 (intent v1) rows, written as 0006 data: one reserved, one dispatching, one settled."""
    scope_id = conn.execute(
        "INSERT INTO app.budget_scopes (id, workspace_id, kind, run_id, cap_usd, cap_calls, held_usd, calls_held, "
        "calls_consumed, created_at, updated_at) VALUES (gen_random_uuid(), %s, 'run', %s, 0.05, 12, 0.005248, 1, 2, "
        "now(), now()) RETURNING id", (ws, run)).fetchone()[0]
    ids = {}
    for state in ("reserved", "dispatching", "settled", "reserved2"):
        ids[state] = attempt = uuid4()
        settled = state == "settled"
        conn.execute(
            "INSERT INTO app.usage_attempts (id, workspace_id, scope_id, actor, provider, model, price_revision, "
            "config_sha256, cache_mode, max_input, max_output, operation_id, intent_sha256, reserved_usd, state, "
            "usage, usage_sha256, actual_tier, actual_usd, created_at, updated_at) VALUES (%s, %s, %s, 'agent', "
            "'openai', 'gpt-6-luna', 'pricing.2026-11-05.v1', %s, 'none', 16000, 2048, %s, %s, 0.002624, %s, %s, "
            "%s, %s, %s, now(), now())",
            (attempt, ws, scope_id, SHA, f"legacy-{state}", SHA, state.rstrip("2"),
             '{}' if settled else None, SHA if settled else None, "short" if settled else None,
             Decimal("0.0000105") if settled else None))
    return ids


def test_0007_upgrades_legacy_rows_which_settle_but_never_dispatch(new_app_database: NewDatabase) -> None:
    database = new_app_database("budget0007_upgrade", revision="0006")
    ws = workspace(database)
    run = new_run(database, ws)
    with database.superuser() as conn:
        ids = legacy_rows(conn, ws, run)
    database.upgrade("0007")
    assert database.current() == "0007"
    for attempt in ids.values():
        row = attempt_row(database, attempt)
        assert (row["version"], row["request"], row["count_state"]) == (1, None, "none")
    assert scope(database, run)["cap_counts"] == 12
    database.upgrade()
    books = ledger(database, ws)
    books.settle(ids["dispatching"], Settlement(Usage(100, output=1)))  # legal for a v1 attempt
    for refusal in (books.begin_dispatch(ids["reserved"], REQUEST), ):
        assert isinstance(refusal, DispatchRefused) and refusal.reason == "legacy_intent"
    refused = books.claim_count(ids["reserved"], REQUEST)
    assert isinstance(refused, CountRefused) and refused.reason == "legacy_intent"
    with pytest.raises(LedgerConflict):  # a v2 reservation can never adopt a v1 attempt's ID
        books.reserve(RunBinding(run), ids["reserved2"], "agent", "legacy-reserved2", REQUEST)
    books.release(ids["reserved"])
    with database.superuser() as conn:
        with pytest.raises(psycopg.errors.CheckViolation, match="intent version 2"):
            conn.execute("INSERT INTO app.usage_attempts (id, workspace_id, scope_id, actor, provider, model, "
                         "price_revision, config_sha256, cache_mode, max_input, max_output, operation_id, "
                         "intent_sha256, reserved_usd, state, intent_version, created_at, updated_at) SELECT "
                         "gen_random_uuid(), workspace_id, id, 'agent', 'openai', 'gpt-6-luna', 'r', %s, 'none', 1, 1, "
                         "'o', %s, 0, 'reserved', 1, now(), now() FROM app.budget_scopes WHERE run_id = %s",
                         (SHA, SHA, run))
        with pytest.raises(psycopg.errors.CheckViolation, match="request_by_version"):
            conn.execute("INSERT INTO app.usage_attempts (id, workspace_id, scope_id, actor, provider, model, "
                         "price_revision, config_sha256, cache_mode, max_input, max_output, operation_id, "
                         "intent_sha256, reserved_usd, state, created_at, updated_at) SELECT gen_random_uuid(), "
                         "workspace_id, id, 'agent', 'openai', 'gpt-6-luna', 'r', %s, 'none', 1, 1, 'o', %s, 0, "
                         "'reserved', now(), now() FROM app.budget_scopes WHERE run_id = %s", (SHA, SHA, run))


def force_flags(database: AppDatabase) -> tuple[bool, ...]:
    with database.superuser() as conn:
        return tuple(row[0] for row in conn.execute(
            "SELECT relforcerowsecurity FROM pg_class WHERE oid IN ('app.budget_scopes'::regclass, "
            "'app.usage_attempts'::regclass) ORDER BY oid").fetchall())


def test_a_populated_0007_downgrade_is_refused_even_with_allow_data_loss(db: AppDatabase) -> None:
    _ws, _run, _books, _attempt = reserved(db)  # one v2 attempt exists
    db.downgrade("0007", allow_data_loss=True)
    before = force_flags(db)
    for allow in (False, True):
        with pytest.raises(DataLossRefused, match="0007 downgrade is not supported"):
            db.downgrade("0006", allow_data_loss=allow)
        assert db.current() == "0007" and force_flags(db) == before


@pytest.mark.parametrize("initially_forced", [True, False])
def test_an_empty_0007_downgrade_keeps_legacy_rows_and_the_exact_force_flags(new_app_database: NewDatabase,
                                                                              initially_forced: bool) -> None:
    database = new_app_database("budget0007_down", revision="0006")
    ws = workspace(database)
    run = new_run(database, ws)
    with database.superuser() as conn:
        ids = legacy_rows(conn, ws, run)
    database.upgrade("0007")
    if not initially_forced:
        with database.superuser() as conn:
            conn.execute("ALTER TABLE app.budget_scopes NO FORCE ROW LEVEL SECURITY")
    before = force_flags(database)
    database.downgrade("0006")
    assert database.current() == "0006" and force_flags(database) == before
    with database.superuser() as conn:
        assert conn.execute("SELECT count(*) FROM app.usage_attempts WHERE id = ANY(%s)",
                            (list(ids.values()),)).fetchone() == (4,)
        assert conn.execute("SELECT to_regprocedure('app.refuse_legacy_usage_attempt()')").fetchone() == (None,)
    database.upgrade("0007")
    assert database.current() == "0007"
