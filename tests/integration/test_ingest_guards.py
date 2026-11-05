"""Revision 0010 database guards on real PostgreSQL as the actual app runtime: lock-protected building-only
insertion into `chunks` and `generation_documents` in both race orders (two real connections, bounded waits, joined
threads), direct insertion into ready or retired generations, the transition table for every generation, the deferred
structural publication guard (a corpus generation is never left building; ready exactly when pointed at) and legacy
behaviour."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from policyops.persistence import repositories as repo
from policyops.persistence.database import SCOPE_SETTING, transaction
from policyops.persistence.records import Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_contracts.digest import text_sha256
from policyops_testing.app_database import AppDatabase


pytestmark = pytest.mark.postgres
VECTOR = "[" + ",".join(["0"] * 1535 + ["1"]) + "]"
NOW = datetime.now(UTC)


@contextmanager
def scoped(engine: Engine, ws: UUID) -> Iterator[Connection]:
    """A manually controlled transaction (begin; commit or roll back explicitly) in one workspace scope."""
    with engine.connect() as conn:
        conn.execute(text("SELECT set_config(:n, :v, true)"), {"n": SCOPE_SETTING, "v": str(ws)})
        try:
            yield conn
        finally:
            if conn.in_transaction():
                conn.rollback()


class World:
    def __init__(self, db: AppDatabase) -> None:
        self.db, self.ws = db, uuid4()
        with transaction(db.engine(AUTH_RUNTIME)) as conn:
            repo.create_workspace(conn, Workspace(id=self.ws, slug=f"ws-{self.ws.hex[:12]}", name="Guards",
                                                  created_at=NOW))
        self.engine = db.engine(APP_RUNTIME, pool_size=6)
        self.document, self.version = uuid4(), uuid4()
        with scoped(self.engine, self.ws) as conn:
            conn.execute(text("INSERT INTO app.documents (id, workspace_id, domain, publisher, source_uri, license, "
                              "created_at) VALUES (:id, :w, 'retail', 'Synthetic', :u, 'CC0', :t)"),
                         {"id": self.document, "w": self.ws, "u": f"urn:test:{uuid4()}", "t": NOW})
            conn.execute(text("INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, "
                              "body, status, effective_from, created_at) VALUES (:id, :w, :d, 1, :s, 'Body text.', "
                              "'active', :t, :t)"),
                         {"id": self.version, "w": self.ws, "d": self.document, "s": text_sha256("Body text."),
                          "t": NOW})
            conn.commit()

    def generation(self, status: str = "building") -> UUID:
        """A committed legacy-style generation (no corpus key)."""
        generation = uuid4()
        with scoped(self.engine, self.ws) as conn:
            conn.execute(text("INSERT INTO app.index_generations (id, workspace_id, policy_sha256, parser_version, "
                              "embedding_model, dimension, status, created_at) VALUES (:id, :w, :s, 'p1', 'fake', "
                              "1536, 'building', :t)"), {"id": generation, "w": self.ws, "s": "3" * 64, "t": NOW})
            if status in ("ready", "retired"):
                conn.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = :t WHERE id = :id"),
                             {"id": generation, "t": NOW})
            if status == "retired":
                conn.execute(text("UPDATE app.index_generations SET status = 'retired' WHERE id = :id"),
                             {"id": generation})
            if status == "failed":
                conn.execute(text("UPDATE app.index_generations SET status = 'failed' WHERE id = :id"),
                             {"id": generation})
            conn.commit()
        return generation

    def insert_member(self, conn: Connection, table: str, generation: UUID, start: int = 0) -> None:
        if table == "app.chunks":
            conn.execute(text("INSERT INTO app.chunks (id, workspace_id, generation_id, document_version_id, "
                              "heading, start_offset, end_offset, text, sha256, embedding, created_at) VALUES (:id, "
                              ":w, :g, :v, '', :s, :e, 'Body', :h, CAST(:vec AS public.vector), :t)"),
                         {"id": uuid4(), "w": self.ws, "g": generation, "v": self.version, "s": start,
                          "e": start + 4, "h": "a" * 64, "vec": VECTOR, "t": NOW})
        else:
            conn.execute(text("INSERT INTO app.generation_documents (workspace_id, generation_id, "
                              "document_version_id, ordinal, source_uri, source_path, git_blob, raw_sha256, "
                              "raw_bytes, chunk_count, created_at) VALUES (:w, :g, :v, 0, 'urn:x', 'x.md', :b, :r, "
                              "10, 0, :t)"),
                         {"w": self.ws, "g": generation, "v": self.version, "b": "b" * 40, "r": "c" * 64, "t": NOW})

    def count(self, table: str, generation: UUID) -> int:
        with self.db.superuser() as conn:
            # `table` is one of the two fixed member tables.
            return int(conn.execute(f"SELECT count(*) FROM {table} WHERE generation_id = %s",  # noqa: S608
                                    (generation,)).fetchone()[0])


def waiting_on_lock(db: AppDatabase, pid: int, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with db.superuser() as conn:
            row = conn.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s", (pid,)).fetchone()
        if row is not None and row[0] == "Lock":
            return True
        time.sleep(0.05)
    return False


def backend_pid(conn: Connection) -> int:
    return int(conn.execute(text("SELECT pg_backend_pid()")).scalar_one())


MEMBERS = ("app.chunks", "app.generation_documents")


@pytest.mark.parametrize("table", MEMBERS)
def test_a_paused_insert_blocks_activation_and_the_activator_sees_the_row(shared_db: AppDatabase,
                                                                         table: str) -> None:
    world = World(shared_db)
    generation = world.generation()
    outcome: dict[str, Any] = {}
    started = threading.Event()

    def activate() -> None:
        with scoped(world.engine, world.ws) as activator:
            outcome["pid"] = backend_pid(activator)
            started.set()
            activator.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = now() "
                                   "WHERE id = :id"), {"id": generation})
            outcome["seen"] = activator.execute(
                text(f"SELECT count(*) FROM {table} WHERE generation_id = :g"),  # noqa: S608 - fixed table
                {"g": generation}).scalar_one()
            activator.rollback()

    thread = threading.Thread(target=activate)
    try:
        with scoped(world.engine, world.ws) as inserter:
            world.insert_member(inserter, table, generation)  # holds FOR SHARE on the generation row, uncommitted
            thread.start()
            assert started.wait(10)
            assert waiting_on_lock(shared_db, outcome["pid"])  # the status update waits for the insert
            inserter.commit()
    finally:  # on any failure the inserter rolled back on exit, so the activator is released: bounded join
        if thread.ident is not None:
            thread.join(20)
    assert not thread.is_alive()
    assert outcome["seen"] == 1  # a fresh statement after the wait sees the committed row: verification would fail


@pytest.mark.parametrize("table", MEMBERS)
def test_an_insert_after_an_uncommitted_activation_waits_and_is_then_refused(shared_db: AppDatabase,
                                                                            table: str) -> None:
    world = World(shared_db)
    generation = world.generation()
    outcome: dict[str, Any] = {}
    started = threading.Event()

    def insert() -> None:
        with scoped(world.engine, world.ws) as inserter:
            outcome["pid"] = backend_pid(inserter)
            started.set()
            try:
                world.insert_member(inserter, table, generation)
                outcome["error"] = None
            except DBAPIError as exc:
                outcome["error"] = str(exc.orig)

    thread = threading.Thread(target=insert)
    try:
        with scoped(world.engine, world.ws) as activator:
            activator.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = now() "
                                   "WHERE id = :id"), {"id": generation})
            thread.start()
            assert started.wait(10)
            assert waiting_on_lock(shared_db, outcome["pid"])
            activator.commit()
    finally:  # on any failure the activator rolled back on exit, so the inserter is released: bounded join
        if thread.ident is not None:
            thread.join(20)
    assert not thread.is_alive()
    assert outcome["error"] is not None and "generation_not_building" in outcome["error"]
    assert world.count(table, generation) == 0


@pytest.mark.parametrize("table", MEMBERS)
@pytest.mark.parametrize("status", ["ready", "retired", "failed"])
def test_direct_insertion_into_a_non_building_generation_is_refused(shared_db: AppDatabase, table: str,
                                                                   status: str) -> None:
    world = World(shared_db)
    generation = world.generation(status)
    with scoped(world.engine, world.ws) as conn, pytest.raises(DBAPIError, match="generation_not_building"):
        world.insert_member(conn, table, generation)


@pytest.mark.parametrize("table", MEMBERS)
def test_a_generation_another_transaction_has_not_committed_is_not_visible(shared_db: AppDatabase,
                                                                          table: str) -> None:
    world = World(shared_db)
    generation = uuid4()
    with scoped(world.engine, world.ws) as creator:
        creator.execute(text("INSERT INTO app.index_generations (id, workspace_id, policy_sha256, parser_version, "
                             "embedding_model, dimension, status, created_at) VALUES (:id, :w, :s, 'p1', 'f', 1536, "
                             "'building', :t)"), {"id": generation, "w": world.ws, "s": "3" * 64, "t": NOW})
        with scoped(world.engine, world.ws) as other, pytest.raises(DBAPIError, match="generation_not_visible"):
            world.insert_member(other, table, generation)


@pytest.mark.parametrize(("start", "target", "allowed"), [
    ("building", "ready", True), ("building", "failed", True), ("ready", "retired", True),
    ("ready", "building", False), ("retired", "ready", False), ("failed", "building", False),
    ("failed", "ready", False), ("ready", "failed", False), ("retired", "building", False),
])
def test_the_generation_transition_table(shared_db: AppDatabase, start: str, target: str, allowed: bool) -> None:
    world = World(shared_db)
    generation = world.generation(start)
    with scoped(world.engine, world.ws) as conn:
        statement = text("UPDATE app.index_generations SET status = :s, ready_at = CASE WHEN :s = 'ready' "
                         "THEN coalesce(ready_at, now()) ELSE ready_at END WHERE id = :id")
        if allowed:
            conn.execute(statement, {"s": target, "id": generation})
            conn.commit()
        else:
            with pytest.raises(DBAPIError, match="generation_transition_refused"):
                conn.execute(statement, {"s": target, "id": generation})


def test_ready_at_is_immutable_outside_the_ready_transition(shared_db: AppDatabase) -> None:
    world = World(shared_db)
    generation = world.generation("ready")
    with scoped(world.engine, world.ws) as conn, pytest.raises(DBAPIError, match="generation_ready_at_immutable"):
        conn.execute(text("UPDATE app.index_generations SET ready_at = now() + interval '1 hour' WHERE id = :id"),
                     {"id": generation})


def corpus_generation(conn: Connection, ws: UUID, key: str, status: str = "building") -> UUID:
    generation = uuid4()
    conn.execute(text(
        "INSERT INTO app.index_generations (id, workspace_id, policy_sha256, parser_version, embedding_model, "
        "dimension, status, created_at, corpus_key, source_repository, source_commit, source_tree, "
        "source_manifest_sha256, corpus_manifest_sha256, license_scope, render, chunk_config, tokenizer_sha256, "
        "request_config_sha256, expected_set_sha256, generation_key_sha256, document_count, chunk_count) VALUES "
        "(:id, :w, :d, 'p', 'm', 1536, :status, now(), :k, 'r', :c, :c, :d, :d, 'scope', 'identity', 'c', :d, :d, "
        ":d, :d, 0, 0)"), {"id": generation, "w": ws, "d": "d" * 64, "c": "e" * 40, "k": key, "status": status})
    return generation


def new_corpus(conn: Connection, ws: UUID) -> str:
    key = f"corpus-{uuid4().hex[:8]}"
    conn.execute(text("INSERT INTO app.corpora (workspace_id, corpus_key, domain, active_generation_id, version, "
                      "created_at, updated_at) VALUES (:w, :k, 'retail', NULL, 1, now(), now())"), {"w": ws, "k": key})
    return key


def test_a_corpus_generation_must_start_building(shared_db: AppDatabase) -> None:
    world = World(shared_db)
    with scoped(world.engine, world.ws) as conn:
        key = new_corpus(conn, world.ws)
        with pytest.raises(DBAPIError, match="generation_must_start_building"):
            corpus_generation(conn, world.ws, key, status="ready")


def test_a_corpus_generation_cannot_be_committed_building(shared_db: AppDatabase) -> None:
    world = World(shared_db)
    with scoped(world.engine, world.ws) as conn:
        key = new_corpus(conn, world.ws)
        corpus_generation(conn, world.ws, key)
        with pytest.raises(DBAPIError, match="generation_left_building"):
            conn.commit()


def test_ready_requires_the_corpus_pointer_and_the_pointer_requires_ready(shared_db: AppDatabase) -> None:
    world = World(shared_db)
    with scoped(world.engine, world.ws) as conn:
        key = new_corpus(conn, world.ws)
        generation = corpus_generation(conn, world.ws, key)
        conn.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = now() WHERE id = :id"),
                     {"id": generation})
        with pytest.raises(DBAPIError, match="generation_pointer_mismatch"):
            conn.commit()  # ready but not pointed at
    with scoped(world.engine, world.ws) as conn:
        key = new_corpus(conn, world.ws)
        generation = corpus_generation(conn, world.ws, key)
        conn.execute(text("UPDATE app.index_generations SET status = 'failed' WHERE id = :id"), {"id": generation})
        conn.execute(text("UPDATE app.corpora SET active_generation_id = :g, version = 2 WHERE corpus_key = :k"),
                     {"g": generation, "k": key})
        with pytest.raises(DBAPIError, match=r"corpus_pointer_not_ready|generation_pointer_mismatch"):
            conn.commit()  # pointed at but not ready
    with scoped(world.engine, world.ws) as conn:
        key = new_corpus(conn, world.ws)
        generation = corpus_generation(conn, world.ws, key)
        conn.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = now() WHERE id = :id"),
                     {"id": generation})
        conn.execute(text("UPDATE app.corpora SET active_generation_id = :g, version = 2 WHERE corpus_key = :k"),
                     {"g": generation, "k": key})
        conn.commit()  # consistent: accepted


def test_the_pointer_cannot_name_another_corpus_generation(shared_db: AppDatabase) -> None:
    world = World(shared_db)
    with scoped(world.engine, world.ws) as conn:
        first, second = new_corpus(conn, world.ws), new_corpus(conn, world.ws)
        generation = corpus_generation(conn, world.ws, first)
        with pytest.raises(DBAPIError, match="corpora_active_generation"):
            conn.execute(text("UPDATE app.corpora SET active_generation_id = :g WHERE corpus_key = :k"),
                         {"g": generation, "k": second})


def test_the_legacy_building_then_ready_flow_is_unchanged(shared_db: AppDatabase) -> None:
    world = World(shared_db)
    generation = world.generation()
    with scoped(world.engine, world.ws) as conn:
        world.insert_member(conn, "app.chunks", generation)
        conn.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = now() WHERE id = :id"),
                     {"id": generation})
        assert conn.execute(text("SELECT count(*) FROM app.chunks WHERE generation_id = :g"),
                            {"g": generation}).scalar_one() == 1
        conn.commit()
