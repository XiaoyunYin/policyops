"""Citation integrity (0010) and the historical citation read port on real PostgreSQL as the actual app runtime:
the insert guard (ready chunk, trace generation, document version, span inside the chunk), the composite version
foreign key, resolution of a citation after its generation was retired (the chunk itself is no longer readable),
and truthful check reporting for corrupt, foreign and legacy rows. Corrupt rows are constructed by the superuser with
triggers disabled and labelled as such; the resolver does not authorize access or validate claims."""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.domain.examples import World
from policyops.persistence.corpora import CitationRefused, CorpusStore
from policyops.persistence.database import workspace_transaction
from policyops.persistence.importer import import_synthetic_world
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers import tokenizer as tk
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops_contracts.digest import text_sha256
from policyops_testing.app_database import AppDatabase
from policyops_testing.corpus_fixtures import CredentialReads, FixtureCorpus, ScriptedEmbeddings, banking, write


pytestmark = pytest.mark.postgres
TOKENIZER = tk.load()
WORLD = World()
WS, RUN = WORLD.workspace, WORLD.run
CAPS = PaidCaps("text-embedding-3-small", 1536, Decimal("0.01"), 20, 100_000, 900)
VECTOR = "[" + ",".join(["0"] * 1535 + ["1"]) + "]"


class Corpus:
    def __init__(self, db: AppDatabase, root: Path) -> None:
        self.db, self.root, self.n = db, root, 0
        self.engine = db.engine(APP_RUNTIME, pool_size=6)
        self.credentials = CredentialReads(ScriptedEmbeddings())

    def activate(self, content: str) -> UUID:
        self.n += 1
        documents = {"p": banking("p", "Policy", content), "q": banking("q", "Other", "A stable second rule.")}
        root = self.root / f"acq-{self.n}"
        raw, digest = write(root, [FixtureCorpus("cite-corpus", "banking_knowledge", "tau2-banking/v1", documents)])
        outcome = ingest(Request(WS, "cite-corpus", raw, digest, root, "execute", CAPS), engine=self.engine,
                         tokenizer=TOKENIZER, providers=self.credentials, env="test")
        assert outcome.outcome == "activated", outcome.to_json()
        return UUID(outcome.details["generation_id"])

    def chunk(self, generation: UUID, document_key: str = "p") -> dict[str, Any]:
        """The first chunk of one document in a generation (inspection as the superuser: any status)."""
        with self.db.superuser() as conn:
            row = conn.execute("SELECT k.id, k.document_version_id, k.start_offset, k.end_offset, k.text "
                               "FROM app.chunks k JOIN app.document_versions v ON v.id = k.document_version_id "
                               "JOIN app.documents d ON d.id = v.document_id WHERE k.generation_id = %s "
                               "AND d.source_uri = %s ORDER BY k.start_offset LIMIT 1",
                               (generation, f"tau2:banking_knowledge/{document_key}")).fetchone()
        return {"id": row[0], "version": row[1], "start": row[2], "end": row[3], "text": row[4]}

    def active(self) -> UUID:
        """The corpus's currently active generation, read each time (tests never rely on each other's order)."""
        with self.db.superuser() as conn:
            row = conn.execute("SELECT active_generation_id FROM app.corpora WHERE workspace_id = %s "
                               "AND corpus_key = 'cite-corpus'", (WS,)).fetchone()
        return UUID(str(row[0]))

    def retired(self) -> UUID:
        with self.db.superuser() as conn:
            row = conn.execute("SELECT id FROM app.index_generations WHERE workspace_id = %s AND corpus_key = "
                               "'cite-corpus' AND status = 'retired' ORDER BY ready_at LIMIT 1", (WS,)).fetchone()
        return UUID(str(row[0]))

    def trace(self, generation: UUID, run: UUID = RUN) -> UUID:
        trace = uuid4()
        with workspace_transaction(self.engine, WS) as conn:
            conn.execute(text("INSERT INTO app.retrieval_traces (id, workspace_id, run_id, generation_id, "
                              "query_sha256, authorized_scope, candidates, final_chunk_ids, created_at) VALUES "
                              "(:id, :w, :r, :g, :q, '{}'::jsonb, '[]'::jsonb, '{}', now())"),
                         {"id": trace, "w": WS, "r": run, "g": generation, "q": "f" * 64})
        return trace

    def cite(self, trace: UUID, chunk: dict[str, Any], start: int, end: int, version: UUID | None = None) -> UUID:
        citation = uuid4()
        with workspace_transaction(self.engine, WS) as conn:
            conn.execute(text("INSERT INTO app.citations (id, workspace_id, trace_id, chunk_id, document_version_id, "
                              "span_start, span_end, created_at) VALUES (:id, :w, :t, :c, :v, :s, :e, now())"),
                         {"id": citation, "w": WS, "t": trace, "c": chunk["id"], "v": version or chunk["version"],
                          "s": start, "e": end})
        return citation

    def corrupt_citation(self, trace: UUID, chunk: UUID, version: UUID, start: int, end: int) -> UUID:
        """Superuser with triggers and foreign keys disabled: a row the guards would refuse (test fixture only)."""
        citation = uuid4()
        with self.db.superuser() as conn:
            conn.execute("SET session_replication_role = replica")
            conn.execute("INSERT INTO app.citations (id, workspace_id, trace_id, chunk_id, document_version_id, "
                         "span_start, span_end, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, now())",
                         (citation, WS, trace, chunk, version, start, end))
            conn.execute("SET session_replication_role = DEFAULT")
        return citation


@pytest.fixture(scope="module")
def corpus(app_cluster: Any, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Corpus]:
    """One database with two activations (one retired, one active); each test reads the live state it needs."""
    database = app_cluster.create_database("citations")
    database.upgrade()
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    corpus = Corpus(database, tmp_path_factory.mktemp("citations"))
    corpus.activate("Refunds return to the original payment method within ten days.")
    corpus.activate("Refunds return to store credit only.")
    yield corpus
    database.dispose()


def test_a_valid_citation_resolves_from_the_version_body(corpus: Corpus) -> None:
    active = corpus.active()
    chunk = corpus.chunk(active)
    citation = corpus.cite(corpus.trace(active), chunk, chunk["start"], chunk["start"] + 7)
    resolved = CorpusStore(corpus.engine, WS).resolve_citation_text(citation, RUN)
    assert resolved.text == chunk["text"][:7] and resolved.generation_id == active
    assert dict(resolved.checks) == {"run_match": "checked", "version_digest": "checked",
                                     "span_within_version": "checked", "version_in_generation": "checked",
                                     "chunk_containment": "write_time_guard"}


@pytest.mark.parametrize(("case", "error"), [
    ("retired_chunk", "citation_chunk_not_ready"),
    ("trace_generation", "citation_generation_mismatch"),
    ("version", "citation_version_mismatch"),
    ("span_before", "citation_span_outside_chunk"),
    ("span_after", "citation_span_outside_chunk"),
])
def test_the_insert_guard_refuses_inconsistent_citations(corpus: Corpus, case: str, error: str) -> None:
    active, old = corpus.active(), corpus.retired()
    current = corpus.chunk(active)
    retired = corpus.chunk(old)
    other = corpus.chunk(active, "q")
    trace = corpus.trace(active)
    arguments = {
        "retired_chunk": (corpus.trace(old), retired, retired["start"], retired["start"] + 3, None),
        "trace_generation": (corpus.trace(old), current, current["start"], current["start"] + 3, None),
        "version": (trace, current, current["start"], current["start"] + 3, other["version"]),
        "span_before": (trace, current, current["start"] - 1, current["start"] + 3, None) if current["start"]
        else (trace, current, 0, current["end"] + 1, None),
        "span_after": (trace, current, current["start"], current["end"] + 1, None),
    }[case]
    with pytest.raises(DBAPIError, match=error):
        corpus.cite(*arguments)


def test_a_citation_still_resolves_after_its_generation_is_retired(corpus: Corpus) -> None:
    generation = corpus.activate("Exchanges keep the same product type.")
    chunk = corpus.chunk(generation)
    citation = corpus.cite(corpus.trace(generation), chunk, chunk["start"], chunk["end"])
    newer = corpus.activate("Exchanges may change the product type.")
    assert newer != generation
    with workspace_transaction(corpus.engine, WS) as conn:
        visible = conn.execute(text("SELECT count(*) FROM app.chunks WHERE id = :id"),
                               {"id": chunk["id"]}).scalar_one()
    assert visible == 0  # retired: not a retrieval candidate, not readable as a chunk
    resolved = CorpusStore(corpus.engine, WS).resolve_citation_text(citation, RUN)
    assert resolved.text == chunk["text"] and resolved.generation_id == generation


def test_run_mismatch_and_foreign_workspace_are_refused(corpus: Corpus) -> None:
    active = corpus.active()
    chunk = corpus.chunk(active)
    citation = corpus.cite(corpus.trace(active), chunk, chunk["start"], chunk["start"] + 4)
    store = CorpusStore(corpus.engine, WS)
    with pytest.raises(CitationRefused, match="citation_run_mismatch"):
        store.resolve_citation_text(citation, uuid4())
    with pytest.raises(CitationRefused, match="citation_not_found"):
        CorpusStore(corpus.engine, uuid4()).resolve_citation_text(citation, RUN)
    with workspace_transaction(corpus.engine, uuid4()) as conn, pytest.raises(DBAPIError):
        conn.execute(text("INSERT INTO app.citations (id, workspace_id, trace_id, chunk_id, document_version_id, "
                          "span_start, span_end, created_at) VALUES (:id, app.current_workspace(), :t, :c, :v, 0, 1, "
                          "now())"), {"id": uuid4(), "t": uuid4(), "c": chunk["id"], "v": chunk["version"]})


def test_corrupt_stored_rows_are_refused_with_the_check_that_failed(corpus: Corpus) -> None:
    active = corpus.active()
    chunk = corpus.chunk(active)
    trace = corpus.trace(active)
    store = CorpusStore(corpus.engine, WS)
    beyond = corpus.corrupt_citation(trace, chunk["id"], chunk["version"], 0, 10_000)
    with pytest.raises(CitationRefused, match="citation_span_outside_version"):
        store.resolve_citation_text(beyond, RUN)
    too_long = corpus.corrupt_citation(trace, chunk["id"], chunk["version"], 0, 20_001)
    with pytest.raises(CitationRefused, match="citation_span_too_long"):
        store.resolve_citation_text(too_long, RUN)
    stray = uuid4()
    with workspace_transaction(corpus.engine, WS) as conn:
        document = conn.execute(text("SELECT document_id FROM app.document_versions WHERE id = :v"),
                                {"v": chunk["version"]}).scalar_one()
        conn.execute(text("INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, body, "
                          "status, effective_from, created_at) VALUES (:id, app.current_workspace(), :d, 99, :s, "
                          "'Stray body.', 'retired', now(), now())"),
                     {"id": stray, "d": document, "s": text_sha256("Stray body.")})
    outside = corpus.corrupt_citation(trace, chunk["id"], stray, 0, 5)
    with pytest.raises(CitationRefused, match="citation_version_not_in_generation"):
        store.resolve_citation_text(outside, RUN)
    lying = uuid4()
    with workspace_transaction(corpus.engine, WS) as conn:
        conn.execute(text("INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, body, "
                          "status, effective_from, created_at) VALUES (:id, app.current_workspace(), :d, 98, :s, "
                          "'Claimed body.', 'retired', now(), now())"),
                     {"id": lying, "d": document, "s": text_sha256("A different body.")})
    mismatched = corpus.corrupt_citation(trace, chunk["id"], lying, 0, 5)
    with pytest.raises(CitationRefused, match="citation_version_digest_mismatch"):
        store.resolve_citation_text(mismatched, RUN)


def test_a_legacy_generation_reports_what_it_cannot_check(corpus: Corpus) -> None:
    document, version, generation, chunk = uuid4(), uuid4(), uuid4(), uuid4()
    body = "Legacy policy body."
    with workspace_transaction(corpus.engine, WS) as conn:
        conn.execute(text("INSERT INTO app.documents (id, workspace_id, domain, publisher, source_uri, license, "
                          "created_at) VALUES (:id, :w, 'legacy', 'Old', :u, 'CC0', now())"),
                     {"id": document, "w": WS, "u": f"urn:legacy:{document}"})
        conn.execute(text("INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, body, "
                          "status, effective_from, created_at) VALUES (:id, :w, :d, 1, :s, :b, 'active', now(), "
                          "now())"), {"id": version, "w": WS, "d": document, "s": text_sha256(body), "b": body})
        conn.execute(text("INSERT INTO app.index_generations (id, workspace_id, policy_sha256, parser_version, "
                          "embedding_model, dimension, status, created_at) VALUES (:id, :w, :s, 'p1', 'fake', 1536, "
                          "'building', now())"), {"id": generation, "w": WS, "s": "3" * 64})
        conn.execute(text("INSERT INTO app.chunks (id, workspace_id, generation_id, document_version_id, heading, "
                          "start_offset, end_offset, text, sha256, embedding, created_at) VALUES (:id, :w, :g, :v, "
                          "'', 0, 6, 'Legacy', :h, CAST(:e AS public.vector), now())"),
                     {"id": chunk, "w": WS, "g": generation, "v": version, "h": "a" * 64, "e": VECTOR})
        conn.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = now() WHERE id = :id"),
                     {"id": generation})
    citation = corpus.cite(corpus.trace(generation), {"id": chunk, "version": version}, 0, 6)
    resolved = CorpusStore(corpus.engine, WS).resolve_citation_text(citation, RUN)
    assert resolved.text == "Legacy"
    assert resolved.checks["version_in_generation"] == "not_recorded_legacy"
    assert resolved.checks["chunk_containment"] == "upgrade_validated_or_pre_guard"
    assert resolved.checks["run_match"] == resolved.checks["span_within_version"] == "checked"
