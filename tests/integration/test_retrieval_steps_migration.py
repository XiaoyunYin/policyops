"""Revision 0011 (T13 retrieval step intents) on real PostgreSQL: a populated 0010 database upgrades with every old
row intact (equal row counts and equal full-row inventories of every pre-existing table); a populated downgrade
is refused by default and works only with the explicit override, keeping every remaining table's rows intact; an
empty one downgrades and re-upgrades cleanly; the actual runtime role sees only its workspace, cannot reference another
workspace's run, and can neither update nor delete an intent; concurrent same-step intents keep exactly one row."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import time
from typing import Any
from uuid import uuid4

from psycopg import sql
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.persistence import migrate
from policyops.persistence.database import workspace_transaction
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.retrieval import RetrievalStore, StepRefused
from policyops.retrieval.search import worst_case_trace
from policyops_contracts.retrieval import RetrievalConfig, RetrievalQuery, RetrievalScope
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.retrieval_fixtures import Embeddings, World, documents, run_threads


pytestmark = pytest.mark.postgres
KEY = "test-banking"
DOCS = [("a", "Refunds", "Refunds take ten days.")]
# Every application schema. The public schema (Alembic's version row, which advances with each revision by design) is
# deliberately not covered: its revision is asserted with `current()` instead.
APP_SCHEMAS = ("identity", "app", "evaluation", "checkpoints")
MAX_INVENTORY_ROWS = 10_000  # the synthetic fixture holds far fewer; a bound keeps the inventory a bounded read


def counts(database: AppDatabase) -> dict[str, int]:
    with database.superuser() as conn:
        tables = [row[0] for row in conn.execute(
            "SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname = ANY(%s) ORDER BY 1",
            (list(APP_SCHEMAS),)).fetchall()]
        # Table names come from pg_tables of this owned test database, not from input.
        return {t: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in tables}  # noqa: S608


def inventory(database: AppDatabase) -> dict[str, str]:
    """The full-row content of every APP_SCHEMAS table: SHA-256 of its rows' canonical `jsonb` text, sorted by bytes
    (a stable order independent of physical row order). Only digests leave this helper, never rows."""
    digests: dict[str, str] = {}
    with database.superuser() as conn:
        tables = conn.execute("SELECT schemaname, tablename FROM pg_tables WHERE schemaname = ANY(%s) ORDER BY 1, 2",
                              (list(APP_SCHEMAS),)).fetchall()
        for schema, table in tables:
            rows = [row[0].encode("utf-8") for row in conn.execute(
                sql.SQL("SELECT to_jsonb(t)::text FROM {}.{} AS t LIMIT %s").format(
                    sql.Identifier(schema), sql.Identifier(table)), (MAX_INVENTORY_ROWS + 1,)).fetchall()]
            assert len(rows) <= MAX_INVENTORY_ROWS, f"{schema}.{table} exceeds the bounded inventory"
            digests[f"{schema}.{table}"] = hashlib.sha256(b"\n".join(sorted(rows))).hexdigest()
    return digests


def one_step(world: World) -> None:
    query = RetrievalQuery(text="refunds", run_id=world.run(), step=1, scope=RetrievalScope(corpus_key=KEY),
                           config=RetrievalConfig(mode="lexical"))
    result = asyncio.run(world.retriever(Embeddings()).retrieve(query, deadline=time.monotonic() + 60))
    assert type(result).__name__ == "RetrievalResult", result


def test_a_populated_0010_database_upgrades_to_0011_intact(new_app_database: NewDatabase, tmp_path: Path) -> None:
    database = new_app_database("ret_up", revision="0010")
    world = World(database, tmp_path)
    world.publish(documents(DOCS), key=KEY)
    before, rows_before = counts(database), inventory(database)
    assert "app.retrieval_steps" not in before and set(rows_before) == set(before)
    populated = ("app.corpora", "app.index_generations", "app.document_versions", "app.chunks")
    assert all(before[t] > 0 for t in populated)  # a populated fixture, not empty tables
    database.upgrade()
    after, rows_after = counts(database), inventory(database)
    assert database.current() == migrate.head() == "0011"
    assert {t: after[t] for t in before} == before and after["app.retrieval_steps"] == 0
    assert {t: rows_after[t] for t in rows_before} == rows_before  # every old row's full content unchanged
    assert set(rows_after) - set(rows_before) == {"app.retrieval_steps"}
    with database.superuser() as conn:
        flags = conn.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                             "WHERE oid = 'app.retrieval_steps'::regclass").fetchone()
    assert flags == (True, True)
    one_step(world)
    # Control: a value rewrite that keeps every count changes the inventory (counts alone would miss it).
    stepped, stepped_rows = counts(database), inventory(database)
    with database.superuser() as conn:
        conn.execute("UPDATE app.retrieval_steps SET query_sha256 = repeat('0', 64)")
    assert counts(database) == stepped and inventory(database) != stepped_rows


def test_a_populated_downgrade_is_refused_unless_explicitly_destructive(new_app_database: NewDatabase,
                                                                        tmp_path: Path) -> None:
    database = new_app_database("ret_down")
    world = World(database, tmp_path)
    world.publish(documents(DOCS), key=KEY)
    one_step(world)
    with pytest.raises(DataLossRefused, match=r"app\.retrieval_steps"):
        database.downgrade("0010")
    assert database.current() == "0011"
    kept, kept_rows = counts(database), inventory(database)
    assert kept["app.retrieval_steps"] == 1 and kept["app.retrieval_traces"] == 1
    database.downgrade("0010", allow_data_loss=True)
    after, after_rows = counts(database), inventory(database)
    assert database.current() == "0010" and "app.retrieval_steps" not in after
    assert set(after) == set(kept) - {"app.retrieval_steps"}  # only the intent table is dropped
    assert {t: after[t] for t in after} == {t: kept[t] for t in after}  # traces and everything else remain
    assert after_rows == {t: kept_rows[t] for t in after_rows}  # with their full content
    database.upgrade()
    assert database.current() == "0011"
    again, again_rows = counts(database), inventory(database)
    assert again == after | {"app.retrieval_steps": 0}  # the dropped intents are not restored
    assert {t: again_rows[t] for t in after_rows} == after_rows


def test_an_empty_0011_downgrades_and_upgrades_again_cleanly(new_app_database: NewDatabase) -> None:
    database = new_app_database("ret_empty")
    database.downgrade("0010")
    assert database.current() == "0010" and "app.retrieval_steps" not in counts(database)
    database.upgrade()
    assert database.current() == "0011"


def test_runtime_role_isolation_foreign_keys_and_immutability(shared_db: AppDatabase, tmp_path: Path) -> None:
    world, other = World(shared_db, tmp_path / "a"), World(shared_db, tmp_path / "b")
    world.publish(documents(DOCS), key=KEY)
    one_step(world)
    with workspace_transaction(other.engine, other.ws) as conn:
        assert conn.execute(text("SELECT count(*) FROM app.retrieval_steps")).scalar_one() == 0
    foreign_run = world.run()
    insert = text("INSERT INTO app.retrieval_steps (workspace_id, run_id, step, trace_id, request_sha256, "
                  "query_sha256, scope_sha256, config_sha256, created_at) VALUES (app.current_workspace(), :r, 1, "
                  ":t, :d, :d, :d, :d, now())")
    with pytest.raises(DBAPIError, match="retrieval_steps_run"), workspace_transaction(other.engine, other.ws) as conn:
        conn.execute(insert, {"r": foreign_run, "t": uuid4(), "d": "a" * 64})
    for statement in ("UPDATE app.retrieval_steps SET step = step + 1", "DELETE FROM app.retrieval_steps"):
        with pytest.raises(DBAPIError, match="permission denied"), \
                workspace_transaction(world.engine, world.ws) as conn:
            conn.execute(text(statement))


def test_concurrent_same_step_intents_keep_exactly_one_row(shared_db: AppDatabase, tmp_path: Path) -> None:
    world = World(shared_db, tmp_path)
    world.publish(documents(DOCS), key=KEY)
    run_id = world.run()
    store = RetrievalStore(world.engine, world.ws)
    query = RetrievalQuery(text="refunds", run_id=run_id, step=7, scope=RetrievalScope(corpus_key=KEY),
                           config=RetrievalConfig(mode="lexical"))
    trace_id = uuid4()
    outcomes: list[Any] = []

    def create(request: str) -> None:
        try:
            outcomes.append(store.create_intent(
                run_id=run_id, step=7, trace_id=trace_id, request_sha256=request, query_sha256="b" * 64,
                scope_sha256="c" * 64, config_sha256="d" * 64, corpus_key=KEY, allowlist=(), full_policy=False,
                worst_case=worst_case_trace(query)).created)
        except StepRefused as refused:
            outcomes.append(refused.code)

    run_threads(shared_db, [lambda: create("e" * 64) for _ in range(4)], timeout=60)  # owned, bounded
    assert sorted(outcomes, key=str) == [False, False, False, True]
    create("f" * 64)
    assert outcomes[-1] == "step_conflict"
    assert world.count("app.retrieval_steps") == 1
