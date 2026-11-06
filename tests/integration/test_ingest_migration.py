"""Revision 0010 (T12 ingestion) on real PostgreSQL: a populated 0009 database upgrades with every old row intact
(legacy retrieval rows keep their meaning, new provenance columns stay NULL); existing rows that violate the new
constraints refuse the whole upgrade with counts and change nothing; a populated 0010 downgrade is refused by
default and, with the explicit destructive override, keeps the ingested documents, versions and chunks as legacy rows
before a clean re-upgrade; and a populated 0010 database dumps and restores with its guards working."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.domain.examples import World
from policyops.persistence.database import workspace_transaction
from policyops.persistence.importer import import_synthetic_world
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers import tokenizer as tk
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops_contracts.digest import text_sha256
from policyops_testing.app_database import AppCluster, AppDatabase, NewDatabase
from policyops_testing.corpus_fixtures import CredentialReads, FixtureCorpus, ScriptedEmbeddings, banking, write


pytestmark = pytest.mark.postgres
WS = World().workspace
RUN = World().run
APP_SCHEMAS = ("identity", "app", "evaluation", "checkpoints")
NEW_TABLES = ("app.corpora", "app.generation_documents")
VECTOR = "[" + ",".join(["0"] * 1535 + ["1"]) + "]"
CAPS = PaidCaps("text-embedding-3-small", 1536, Decimal("0.01"), 20, 100_000, 900)


def counts(database: AppDatabase) -> dict[str, int]:
    with database.superuser() as conn:
        tables = [row[0] for row in conn.execute(
            "SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname = ANY(%s) ORDER BY 1",
            (list(APP_SCHEMAS),)).fetchall()]
        # Table names come from pg_tables of this owned test database, not from input.
        return {table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
                for table in tables}


def legacy_rows(database: AppDatabase, *, version_mismatch: bool = False, generation_mismatch: bool = False,
                span_outside: bool = False, duplicate_document: bool = False,
                duplicate_chunk: bool = False) -> dict[str, UUID]:
    """Pre-0010 retrieval rows written as the app runtime (no 0010 guard exists yet), optionally inconsistent."""
    ids = {name: uuid4() for name in ("document", "version", "other_version", "generation", "other_generation",
                                      "chunk", "trace", "citation")}
    body = "Legacy body text for retrieval."
    with workspace_transaction(database.engine(APP_RUNTIME), WS) as conn:
        for document in (ids["document"], *([uuid4()] if duplicate_document else [])):
            conn.execute(text("INSERT INTO app.documents (id, workspace_id, domain, publisher, source_uri, license, "
                              "created_at) VALUES (:id, :w, 'legacy', 'Old', 'urn:legacy:one', 'CC0', now())"),
                         {"id": document, "w": WS})
        for key, number in (("version", 1), ("other_version", 2)):
            conn.execute(text("INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, "
                              "body, status, effective_from, created_at) VALUES (:id, :w, :d, :n, :s, :b, 'active', "
                              "now(), now())"), {"id": ids[key], "w": WS, "d": ids["document"], "n": number,
                                                 "s": text_sha256(body + str(number)), "b": body + str(number)})
        for key in ("generation", "other_generation"):
            conn.execute(text("INSERT INTO app.index_generations (id, workspace_id, policy_sha256, parser_version, "
                              "embedding_model, dimension, status, created_at, ready_at) VALUES (:id, :w, :s, 'p0', "
                              "'legacy-model', 1536, 'ready', now(), now())"),
                         {"id": ids[key], "w": WS, "s": "4" * 64})
        for chunk in (ids["chunk"], *([uuid4()] if duplicate_chunk else [])):
            conn.execute(text("INSERT INTO app.chunks (id, workspace_id, generation_id, document_version_id, "
                              "heading, start_offset, end_offset, text, sha256, embedding, created_at) VALUES (:id, "
                              ":w, :g, :v, 'Legacy', 0, 6, 'Legacy', :h, CAST(:e AS public.vector), now())"),
                         {"id": chunk, "w": WS, "g": ids["generation"], "v": ids["version"], "h": "5" * 64,
                          "e": VECTOR})
        conn.execute(text("INSERT INTO app.retrieval_traces (id, workspace_id, run_id, generation_id, query_sha256, "
                          "authorized_scope, candidates, final_chunk_ids, created_at) VALUES (:id, :w, :r, :g, :q, "
                          "'{}'::jsonb, '[]'::jsonb, '{}', now())"),
                     {"id": ids["trace"], "w": WS, "r": RUN, "q": "6" * 64,
                      "g": ids["other_generation" if generation_mismatch else "generation"]})
        conn.execute(text("INSERT INTO app.citations (id, workspace_id, trace_id, chunk_id, document_version_id, "
                          "span_start, span_end, created_at) VALUES (:id, :w, :t, :c, :v, :s, :e, now())"),
                     {"id": ids["citation"], "w": WS, "t": ids["trace"], "c": ids["chunk"],
                      "v": ids["other_version" if version_mismatch else "version"], "s": 0,
                      "e": 9 if span_outside else 6})
    return ids


def populated_0009(new_app_database: NewDatabase, label: str, **legacy: bool) -> AppDatabase:
    database = new_app_database(label, revision="0009")
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    legacy_rows(database, **legacy)
    return database


def ingest_once(database: AppDatabase, root: Path, content: str = "Policy text one.") -> dict[str, Any]:
    raw, digest = write(root, [FixtureCorpus("mig-corpus", "banking_knowledge", "tau2-banking/v1",
                                             {"a": banking("a", "Policy", content)})])
    outcome = ingest(Request(WS, "mig-corpus", raw, digest, root, "execute", CAPS),
                     engine=database.engine(APP_RUNTIME, pool_size=6), tokenizer=tk.load(),
                     providers=CredentialReads(ScriptedEmbeddings()), env="test")
    assert outcome.outcome == "activated", outcome.to_json()
    return outcome.details


def test_a_populated_0009_database_upgrades_with_old_rows_intact(new_app_database: NewDatabase,
                                                                 tmp_path: Path) -> None:
    database = populated_0009(new_app_database, "ing_up")
    before = counts(database)
    assert not set(NEW_TABLES) & set(before)
    database.upgrade("0010")  # this revision's own upgrade (0011 has its own migration tests)
    after = counts(database)
    assert database.current() == "0010"
    assert {table: after[table] for table in before} == before
    assert {table: after[table] for table in NEW_TABLES} == dict.fromkeys(NEW_TABLES, 0)
    with database.superuser() as conn:
        legacy = conn.execute("SELECT corpus_key, expected_set_sha256 FROM app.index_generations").fetchall()
        chunk = conn.execute("SELECT text_sha256, embed_input_sha256 FROM app.chunks").fetchall()
        forced = conn.execute("SELECT bool_and(relforcerowsecurity) FROM pg_class c JOIN pg_namespace n "
                              "ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relkind = 'r'").fetchone()
    assert set(legacy) == {(None, None)} and set(chunk) == {(None, None)} and forced == (True,)
    with workspace_transaction(database.engine(APP_RUNTIME), WS) as conn:
        assert conn.execute(text("SELECT count(*) FROM app.chunks")).scalar_one() == 1  # legacy ready chunk
    ingest_once(database, tmp_path)  # and the new revision works on the upgraded database


@pytest.mark.parametrize(("legacy", "violation"), [
    ({"version_mismatch": True}, "citation_version_mismatch"),
    ({"generation_mismatch": True}, "citation_generation_mismatch"),
    ({"span_outside": True}, "citation_span_outside_chunk"),
    ({"duplicate_document": True}, "duplicate_document_source"),
    ({"duplicate_chunk": True}, "duplicate_chunk_position"),
])
def test_incompatible_existing_rows_refuse_the_upgrade_and_change_nothing(new_app_database: NewDatabase,
                                                                          legacy: dict[str, bool],
                                                                          violation: str) -> None:
    database = populated_0009(new_app_database, "ing_legacy", **legacy)
    before = counts(database)
    # Alembic loads revision files under its own module names, so the class is matched by name, not identity.
    with pytest.raises(Exception, match=f"'{violation}': 1") as refused:
        database.upgrade("0010")
    assert type(refused.value).__name__ == "LegacyIncompatible"
    assert database.current() == "0009" and counts(database) == before
    with database.superuser() as conn:
        forced = conn.execute("SELECT bool_and(relforcerowsecurity) FROM pg_class c JOIN pg_namespace n "
                              "ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relkind = 'r'").fetchone()
    assert forced == (True,)


def test_a_populated_0010_downgrade_is_refused_unless_explicitly_destructive(new_app_database: NewDatabase,
                                                                            tmp_path: Path) -> None:
    database = new_app_database("ing_down", revision="0010")
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    details = ingest_once(database, tmp_path)
    with pytest.raises(DataLossRefused, match=r"app\.corpora|app\.generation_documents"):
        database.downgrade("0009")
    assert database.current() == "0010"
    with database.superuser() as conn:
        forced = conn.execute("SELECT bool_and(relforcerowsecurity) FROM pg_class c JOIN pg_namespace n "
                              "ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relkind = 'r'").fetchone()
    assert forced == (True,)
    kept = counts(database)
    database.downgrade("0009", allow_data_loss=True)  # explicit: provenance and membership are lost
    after = counts(database)
    assert database.current() == "0009" and not set(NEW_TABLES) & set(after)
    for table in ("app.documents", "app.document_versions", "app.chunks", "app.index_generations",
                  "app.embedding_cache"):
        assert after[table] == kept[table], table  # ingested content remains as legacy rows
    with database.superuser() as conn:
        generation = conn.execute("SELECT status FROM app.index_generations WHERE id = %s",
                                  (UUID(details["generation_id"]),)).fetchone()
    assert generation == ("ready",)
    database.upgrade("0010")
    assert database.current() == "0010"


def test_an_empty_0010_downgrades_and_upgrades_again_cleanly(new_app_database: NewDatabase) -> None:
    database = new_app_database("ing_empty_down", revision="0010")
    database.downgrade("0009")
    assert database.current() == "0009" and not set(NEW_TABLES) & set(counts(database))
    with database.superuser() as conn:
        functions = conn.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                                 "WHERE n.nspname = 'app' AND p.proname LIKE '%generation%'").fetchone()
    assert functions == (0,)
    database.upgrade("0010")
    assert database.current() == "0010" and set(NEW_TABLES) <= set(counts(database))


def test_a_populated_0010_database_dumps_and_restores_with_working_guards(app_cluster: AppCluster,
                                                                         new_app_database: NewDatabase,
                                                                         tmp_path: Path) -> None:
    source = new_app_database("ing_dump_src", revision="0010")
    import_synthetic_world(auth=source.engine(AUTH_RUNTIME), app=source.engine(APP_RUNTIME))
    details = ingest_once(source, tmp_path)
    target = new_app_database("ing_dump_dst", extensions=False, revision=None)
    dump = app_cluster.server.dump_and_restore(source.name, target.name)
    assert dump.is_file() and dump.stat().st_size > 0
    target.report = target.provision_extensions()
    assert counts(target) == counts(source) and target.current() == "0010"
    with workspace_transaction(target.engine(APP_RUNTIME), WS) as conn:
        assert conn.execute(text("SELECT count(*) FROM app.chunks WHERE generation_id = :g"),
                            {"g": UUID(details["generation_id"])}).scalar_one() == 1
    with pytest.raises(DBAPIError, match="generation_not_building"), \
            workspace_transaction(target.engine(APP_RUNTIME), WS) as conn:
        conn.execute(text("INSERT INTO app.generation_documents (workspace_id, generation_id, document_version_id, "
                          "ordinal, source_uri, source_path, git_blob, raw_sha256, raw_bytes, chunk_count, "
                          "created_at) SELECT workspace_id, generation_id, document_version_id, 7, 'urn:extra', "
                          "'x', git_blob, raw_sha256, raw_bytes, 0, now() FROM app.generation_documents LIMIT 1"))
    assert not list((app_cluster.server.root / "secrets").glob("pgpass-*"))
