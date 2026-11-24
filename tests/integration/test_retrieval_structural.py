"""G0.3 real runtime-role ingestion/retrieval and owner-run 0017 migration guards."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from decimal import Decimal
import json
from pathlib import Path
import time
from typing import Any
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Connection, text

from policyops.persistence.corpora import CorpusStore, VerificationMismatch
from policyops.persistence.database import workspace_transaction
from policyops.persistence.migration_guard import DataLossRefused
from policyops.retrieval.ingest import Outcome, PaidCaps, Request, ingest
from policyops.retrieval.parse import CHUNK_CONFIG as MD_CHUNK_CONFIG
from policyops.retrieval.parse import PARSER_VERSION as MD_PARSER_VERSION
from policyops.retrieval.structural import CHUNK_CONFIG, PARSER_VERSION
from policyops_contracts.retrieval import RetrievalConfig, RetrievalQuery, RetrievalResult, RetrievalScope
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.retrieval_fixtures import TOKENIZER, Embeddings, World, axis, documents
from policyops_testing.structural_fixtures import KEY, passage, write


pytestmark = pytest.mark.postgres
CAPS = PaidCaps("text-embedding-3-small", 1536, Decimal("1"), 90, 600_000, 3600)


def structural(world: World, root: Path, rows: Sequence[dict[str, Any]], provider: Embeddings, *,
               before_verify: Callable[[Connection, UUID], None] | None = None) -> Outcome:
    raw, digest = write(root, rows)
    return ingest(Request(world.ws, KEY, raw, digest, root, "execute", CAPS, "structural"),
                  engine=world.engine, tokenizer=TOKENIZER, providers=provider.providers(), env="test",
                  before_verify=before_verify)


def test_runtime_structural_repeat_failed_activation_and_markdown_compatibility(shared_db: AppDatabase,
                                                                               tmp_path: Path) -> None:
    world = World(shared_db, tmp_path)
    provider = Embeddings({"Refunds\n\nRefunds return to the original card.": axis(0),
                           "Exchanges\n\nExchanges keep product size.": axis(1)})
    rows = [passage(), passage(1, body="Exchanges keep product size.", heading="Exchanges"),
            passage(2, body="Heading only", heading="Heading only", heading_only=True)]
    first = structural(world, tmp_path / "first", rows, provider)
    assert first.outcome == "activated", first.to_json()
    with workspace_transaction(world.engine, world.ws) as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "policyops_app_runtime"
        generation = conn.execute(text("SELECT parser_version, chunk_config, document_count, chunk_count "
                                       "FROM app.index_generations WHERE corpus_key = :key"), {"key": KEY}).one()
        assert tuple(generation) == (PARSER_VERSION, CHUNK_CONFIG, 3, 3)
        members = conn.execute(text("SELECT m.source_path, m.chunk_count, k.start_offset, k.end_offset, "
            "k.text, v.body FROM app.generation_documents m JOIN app.chunks k "
            "ON k.generation_id = m.generation_id AND k.document_version_id = m.document_version_id "
            "JOIN app.document_versions v ON v.id = m.document_version_id")).all()
        assert len(members) == 3
        for member in members:
            origin = json.loads(member[0])
            assert origin["document_id"] == "Original document:#1" and origin["start"] == 17
            assert origin["end"] - origin["start"] == len(member[5])
            assert member[1] == 1 and member[2] == 0 and member[3] == len(member[5])
            assert member[4] == member[5]
    calls = len(provider.requests)
    repeat = structural(world, tmp_path / "repeat", rows, provider)
    assert repeat.outcome == "unchanged" and len(provider.requests) == calls
    assert world.count("app.index_generations") == 1
    previous = CorpusStore(world.engine, world.ws).snapshot(KEY)

    def refuse_activation(connection: Connection, generation: UUID) -> None:
        raise VerificationMismatch("injected_activation_failure")

    failed = structural(world, tmp_path / "failed", [passage(body="Changed refund rule.")], provider,
                        before_verify=refuse_activation)
    assert failed.outcome == "verification_failed"
    assert CorpusStore(world.engine, world.ws).snapshot(KEY) == previous
    assert world.count("app.index_generations") == 1

    query_provider = Embeddings({"refunds": axis(0)})
    for mode in ("lexical", "dense", "hybrid"):
        query = RetrievalQuery(text="refunds", run_id=world.run(), step=1, scope=RetrievalScope(corpus_key=KEY),
                               config=RetrievalConfig(mode=mode))
        result = asyncio.run(world.retriever(query_provider).retrieve(query, deadline=time.monotonic() + 60))
        assert isinstance(result, RetrievalResult), result
        assert result.evidence and result.evidence[0].source_uri == f"md2d:dmv/{passage()['passage_id']}"
    other = World(shared_db, tmp_path / "other")
    assert not CorpusStore(other.engine, other.ws).snapshot(KEY).exists

    world.publish(documents([("md", "Markdown", "Refunds follow the old Markdown policy.")]), key="markdown")
    query = RetrievalQuery(text="refunds", run_id=world.run(), step=1,
        scope=RetrievalScope(corpus_key="markdown"), config=RetrievalConfig(mode="lexical"))
    result = asyncio.run(world.retriever(Embeddings()).retrieve(query, deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalResult) and result.evidence[0].source_uri == "tau2:banking_knowledge/md"
    with workspace_transaction(world.engine, world.ws) as conn:
        assert tuple(conn.execute(text("SELECT parser_version, chunk_config FROM app.index_generations "
            "WHERE corpus_key = 'markdown'")).one()) == (MD_PARSER_VERSION, MD_CHUNK_CONFIG)


def catalog(db: AppDatabase) -> list[Any]:
    with db.superuser() as conn:
        return list(conn.execute("SELECT c.relname, c.relowner::regrole::text, c.relrowsecurity, "
            "c.relforcerowsecurity, c.relacl::text, x.conname, pg_get_constraintdef(x.oid) FROM pg_class c "
            "JOIN pg_constraint x ON x.conrelid = c.oid WHERE c.oid IN "
            "('app.index_generations'::regclass, 'app.generation_documents'::regclass) "
            "ORDER BY c.relname, x.conname").fetchall())


def test_0017_upgrade_4110_and_atomic_refused_then_successful_downgrade(new_app_database: NewDatabase,
                                                                     tmp_path: Path) -> None:
    db = new_app_database("structural_bounds", revision="0016")
    before = catalog(db)
    db.upgrade("0017")
    assert db.current() == "0017"
    after = catalog(db)
    changed = [a[5] for b, a in zip(before, after, strict=True) if b != a]
    assert changed == ["generation_documents_ordinal", "index_generations_document_count"]
    assert [r[:5] for r in before] == [r[:5] for r in after]  # ownership, policies and grants unchanged
    world = World(db, tmp_path)
    outcome = structural(world, tmp_path / "large", [passage(n) for n in range(4110)], Embeddings())
    assert outcome.outcome == "activated", outcome.to_json()
    assert world.count("app.documents") == world.count("app.generation_documents") == 4110
    assert world.count("app.chunks") == 4110
    for override in (False, True):
        with pytest.raises(DataLossRefused, match=r"0017 downgrade refused.*index_generations"):
            db.downgrade("0016", allow_data_loss=override)
        assert db.current() == "0017" and catalog(db) == after
        assert world.count("app.generation_documents") == 4110
    with db.superuser() as conn:
        # Isolate the ordinal guard, including its cross-workspace visibility as migrator.
        conn.execute("UPDATE app.index_generations SET document_count = 2000")
    with pytest.raises(DataLossRefused, match=r"0017 downgrade refused.*generation_documents"):
        db.downgrade("0016")
    assert db.current() == "0017" and catalog(db) == after
    with db.superuser() as conn:
        for statement in ("UPDATE app.index_generations SET document_count = 5001",
                          "UPDATE app.index_generations SET chunk_count = 10001",
                          "UPDATE app.generation_documents SET ordinal = 5000 WHERE ordinal = 4109"):
            with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
                conn.execute(statement)
        # Test-owned rows only; deletion belongs to this test, never to the migration.
        with conn.transaction():
            conn.execute("UPDATE app.corpora SET active_generation_id = NULL")
            for table in ("app.chunks", "app.generation_documents", "app.index_generations",
                          "app.document_versions", "app.documents", "app.corpora"):
                conn.execute(f"DELETE FROM {table}")  # noqa: S608
    db.downgrade("0016")
    assert db.current() == "0016" and catalog(db) == before
    db.upgrade("0017")
    assert db.current() == "0017" and catalog(db) == after
