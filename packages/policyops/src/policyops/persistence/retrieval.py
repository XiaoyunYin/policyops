"""Retrieval step persistence (T13; schema 0002 traces, 0010 corpora, 0011 step intents). Static SQL only.

Runs as the app runtime (verified at construction) inside workspace-scoped transactions, so forced RLS confines every
row to one workspace; another workspace's run, corpus, trace or intent reads as absent. Three kinds of transaction,
all short, with no provider, file or tokenizer work inside:

- **intent** (READ COMMITTED, read-write): the run `FOR SHARE` and active, the corpus and its pointer, the allowlist
  resolved to the corpus's own documents, the worst-case trace JSONB sizes measured by the database, then the
  immutable `retrieval_steps` row inserted or found. A different stored request fingerprint is a conflict;
- **snapshot** (`REPEATABLE READ READ ONLY`): the pointer, the generation and its configuration, both branch queries
  and the bounded candidate texts, all from one snapshot, so a concurrent activation cannot mix generations or hide a
  branch's chunks mid-step;
- **trace** (read-write): the actual JSONB sizes checked against the column limits, then the trace inserted with its
  deterministic ID (`ON CONFLICT DO NOTHING`).

Plus read-only lookups: an existing trace and its intent (replay), the step's own query job, the immutable version
spans for replay (with the body digest checked) and, for T14 query-less verification, the step's trace with its full
intent row (`step_record`). The span and step-record reads are also available on a caller's own connection
(`read_spans`, `read_step_record`) for the citation recorder's single transaction.

Runtime SQL profiles bound individual statements/locks/idle transactions. Synchronous waits can delay cancellation;
network and COMMIT ambiguity prevent a total wall-clock guarantee.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from policyops.persistence.database import (
    DatabaseUnavailable,
    SqlProfile,
    classify_sql_failure,
    connect_runtime,
    connection_transaction,
    verify_runtime_role,
    workspace_transaction,
)
from policyops.persistence.roles import APP_RUNTIME
from policyops.persistence.runs import ACTIVE_STATES, WAITING_STATES
from policyops.retrieval.rank import ChunkRow, Hit


CANDIDATES_LIMIT = 65_536  # retrieval_traces_candidates_size
SCOPE_LIMIT = 8_192  # retrieval_traces_scope_size
MAX_TEXT_CODE_POINTS = 20_000  # chunks_text_length (a CHECK since 0002, on every row)
LexicalMode = Literal["all_terms", "any_terms", "bm25"]
MAX_ANY_TERM_LEXEMES = 64  # refuse above this distinct normalized-lexeme count; never truncate
BM25_K1 = 1.2  # fixed Okapi constants, not fitted to the corpus
BM25_B = 0.75


class StepRefused(Exception):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class Intent:
    trace_id: UUID
    request_sha256: str
    created: bool
    domain: str
    document_ids: tuple[UUID, ...]


@dataclass(frozen=True)
class StoredTrace:
    run_id: UUID
    generation_id: UUID
    query_sha256: str
    authorized_scope: str  # JSON text, parsed and validated by the caller
    candidates: str
    final_chunk_ids: tuple[UUID, ...]
    intent_request_sha256: str | None


@dataclass(frozen=True)
class StepJob:
    """The step's query job with its immutable identity and, per batch, its state and ledger attempt state
    (None when the attempt was never reserved)."""

    job_id: UUID
    state: str
    purpose: str
    subject_key: str
    input_set_sha256: str
    input_count: int
    request_config_sha256: str
    tokenizer_sha256: str
    batch_states: tuple[str, ...]
    attempt_states: tuple[str | None, ...]


@dataclass
class Snapshot:
    generation_id: UUID
    domain: str
    embedding_model: str | None
    dimension: int
    request_config_sha256: str | None
    lexical_status: Literal["ok", "empty_query", "not_used"] = "not_used"
    lexical: list[Hit] = field(default_factory=list)
    dense: list[Hit] = field(default_factory=list)
    rows: dict[UUID, ChunkRow] = field(default_factory=dict)
    dense_nan_distance: int = 0
    text_oversized: int = 0


@dataclass(frozen=True)
class Span:
    document_version_id: UUID
    document_id: UUID
    source_uri: str
    version_number: int
    text: str | None  # None when the span lies outside the body
    body_digest_ok: bool
    version_sha256: str | None = None  # the stored body digest (verified against the body by `body_digest_ok`)


@dataclass(frozen=True)
class IntentRecord:
    """The immutable `retrieval_steps` row of a step (digests only, no query text)."""

    run_id: UUID
    step: int
    trace_id: UUID
    request_sha256: str
    query_sha256: str
    scope_sha256: str
    config_sha256: str


@dataclass(frozen=True)
class StepRecord:
    """A step's stored trace (with its intent's request digest, as `find_trace` returns it) and its full intent row;
    either may be absent."""

    trace: StoredTrace | None
    intent: IntentRecord | None


_ROW_COLUMNS = ("k.id AS chunk_id, d.id AS document_id, v.id AS version_id, d.source_uri, v.version, k.heading, "
                "k.start_offset, k.end_offset, k.text")
_JOINS = ("JOIN app.document_versions v ON v.workspace_id = k.workspace_id AND v.id = k.document_version_id "
          "JOIN app.documents d ON d.workspace_id = v.workspace_id AND d.id = v.document_id")
_FILTER = ("k.generation_id = :g AND char_length(k.text) <= 20000 "
           "AND (CAST(:docs AS uuid[]) IS NULL OR d.id = ANY(CAST(:docs AS uuid[])))")


def _branch_sql(score: str, match: str, order: str, *, ctes: str = "") -> str:
    """Per-document best chunk (`order` is ASC or DESC on the score), top documents and their best chunks, with a
    total order (`COLLATE "C"` for code-point order of source URIs, chunk IDs as the last tie-breaker)."""
    best = "max" if order == "DESC" else "min"
    # Composed only from the fixed constants of this module, never from input.
    return f"""
WITH {ctes}scored AS (
    SELECT d.id AS document_id, d.source_uri, k.id AS chunk_id, k.start_offset, k.end_offset, {score} AS score
    FROM app.chunks k {_JOINS}
    WHERE {_FILTER} AND {match}
), chunks AS (
    SELECT *, row_number() OVER (PARTITION BY document_id ORDER BY score {order}, start_offset, end_offset,
                                 chunk_id::text) AS chunk_rank,
           {best}(score) OVER (PARTITION BY document_id) AS document_score
    FROM scored
), documents AS (
    SELECT document_id, source_uri, document_score,
           row_number() OVER (ORDER BY document_score {order}, source_uri COLLATE "C", document_id::text) AS rank
    FROM chunks WHERE chunk_rank = 1
)
SELECT d.rank, d.document_id, d.source_uri, d.document_score::text AS score,
       array_agg(c.chunk_id ORDER BY c.chunk_rank) AS chunk_ids
FROM documents d JOIN chunks c ON c.document_id = d.document_id
WHERE d.rank <= :n AND c.chunk_rank <= :per
GROUP BY d.rank, d.document_id, d.source_uri, d.document_score
ORDER BY d.rank"""  # noqa: S608


LEXICAL_SQL = _branch_sql("ts_rank_cd(k.tsv, websearch_to_tsquery('english', :q), 32)",
                          "k.tsv @@ websearch_to_tsquery('english', :q)", "DESC")
# Only PostgreSQL-normalized lexemes enter the OR expression. Its own tsvector serializer quotes/escapes each
# single lexeme; casting to tsquery avoids a second dictionary/stemming pass. Raw query text is always a bind.
ANY_TERMS_QUERY_SQL = """
WITH parsed AS MATERIALIZED (
    SELECT tsvector_to_array(to_tsvector('english', :q)) AS lexemes
)
SELECT lexemes, cardinality(lexemes) AS lexeme_count,
       CASE WHEN cardinality(lexemes) <= :lexeme_cap THEN
           COALESCE((SELECT string_agg(array_to_tsvector(ARRAY[lexeme])::text, ' | ' ORDER BY lexeme COLLATE "C")
                     FROM unnest(lexemes) AS terms(lexeme)), '')
       END AS query
FROM parsed"""
LEXICAL_ANY_SQL = _branch_sql("ts_rank_cd(k.tsv, CAST(:lexical_query AS tsquery), 32)",
                             "k.tsv @@ CAST(:lexical_query AS tsquery)", "DESC")
# Length is the sum of retained position counts, not length(tsvector) (distinct lexemes), nor max(position).
# PostgreSQL keeps at most 255 positions per lexeme (measured) and clamps positions above 16383
# (then merges duplicates).
# These queries score the stored, possibly capped vector exactly; lost original occurrences cannot be recovered.
BM25_STATS_SQL = """
SELECT count(*) AS n, COALESCE(avg(lengths.dl), 0)::double precision AS avgdl
FROM app.chunks k
CROSS JOIN LATERAL (
    SELECT COALESCE(sum(cardinality(positions)), 0) AS dl FROM unnest(k.tsv)
) lengths
WHERE k.generation_id = :g"""
BM25_DF_CTE = """
terms AS MATERIALIZED (
    SELECT lexeme, CAST(array_to_tsvector(ARRAY[lexeme])::text AS tsquery) AS term_query
    FROM unnest(CAST(:lexemes AS text[])) AS query_terms(lexeme)
), df AS MATERIALIZED (
    SELECT terms.lexeme, (
        SELECT count(*) FROM app.chunks f WHERE f.generation_id = :g AND f.tsv @@ terms.term_query
    ) AS frequency FROM terms
), """
LEXICAL_BM25_SQL = _branch_sql("""(
    SELECT COALESCE(sum(
        ln(1.0 + (:bm25_n - df.frequency + 0.5) / (df.frequency + 0.5))
        * tokens.tf * (1.0 + :bm25_k1)
        / (tokens.tf + :bm25_k1 * (1.0 - :bm25_b + :bm25_b * tokens.dl / NULLIF(:bm25_avgdl, 0)))
        ORDER BY tokens.lexeme COLLATE "C"), 0)
    FROM (
        SELECT lexeme, cardinality(positions) AS tf, sum(cardinality(positions)) OVER () AS dl
        FROM unnest(k.tsv)
    ) tokens JOIN df ON df.lexeme = tokens.lexeme
)""", "k.tsv @@ CAST(:lexical_query AS tsquery)", "DESC", ctes=BM25_DF_CTE)
DENSE_SQL = _branch_sql("(k.embedding <=> CAST(:qv AS public.vector))",
                        "k.embedding IS NOT NULL AND NOT ((k.embedding <=> CAST(:qv AS public.vector)) = 'NaN')",
                        "ASC")


def _one(connection: Connection, sql: str, params: Mapping[str, Any]) -> dict[str, Any] | None:
    row = connection.execute(text(sql), dict(params)).mappings().first()
    return None if row is None else dict(row)


def _hits(rows: Sequence[Any]) -> list[Hit]:
    return [Hit(r["document_id"], r["source_uri"], r["rank"], r["score"], tuple(r["chunk_ids"])) for r in rows]


def _chunk_row(r: Any) -> ChunkRow:
    return ChunkRow(r["chunk_id"], r["document_id"], r["version_id"], r["source_uri"], r["version"], r["heading"],
                    r["start_offset"], r["end_offset"], r["text"])


SPANS_SQL = (
    "SELECT e.ordinal, v.id, v.document_id, d.source_uri, v.version, v.sha256, "
    "CASE WHEN e.span_end <= char_length(v.body) THEN "
    "substring(v.body FROM e.span_start + 1 FOR e.span_end - e.span_start) END AS span, "
    "encode(sha256(convert_to(v.body, 'UTF8')), 'hex') = v.sha256 AS digest_ok "
    "FROM unnest(CAST(:versions AS uuid[]), CAST(:starts AS integer[]), CAST(:ends AS integer[])) "
    "WITH ORDINALITY AS e(version_id, span_start, span_end, ordinal) "
    "JOIN app.document_versions v ON v.workspace_id = app.current_workspace() AND v.id = e.version_id "
    "JOIN app.documents d ON d.workspace_id = v.workspace_id AND d.id = v.document_id ORDER BY e.ordinal")


def read_spans(connection: Connection, entries: Sequence[tuple[UUID, int, int]]) -> list[Span | None]:
    """Immutable version slices on the caller's workspace-scoped connection: `(document_version_id, start, end)`
    each, with the stored body digest verified against the actual body. Reads versions and documents only (never
    `app.chunks`), so it works for any historical generation."""
    if not entries:
        return []
    rows = connection.execute(text(SPANS_SQL), {"versions": [e[0] for e in entries], "starts": [e[1] for e in entries],
                                                "ends": [e[2] for e in entries]}).mappings().all()
    found: dict[int, Span] = {r["ordinal"]: Span(r["id"], r["document_id"], r["source_uri"], r["version"], r["span"],
                                                 bool(r["digest_ok"]), r["sha256"]) for r in rows}
    return [found.get(position) for position in range(1, len(entries) + 1)]


@dataclass(frozen=True)
class DocumentSource:
    """A document's stable source identity, read from the workspace's own `app.documents` row."""

    document_id: UUID
    corpus_key: str | None
    source_uri: str


@dataclass(frozen=True)
class GenerationMembers:
    """A generation's corpus and which of the asked versions it contains (`generation_documents`; no chunk read, so
    it works for any historical generation)."""

    corpus_key: str | None
    versions: frozenset[UUID]


def read_document_sources(connection: Connection, document_ids: Sequence[UUID]) -> dict[UUID, DocumentSource]:
    if not document_ids:
        return {}
    rows = connection.execute(text(
        "SELECT id, corpus_key, source_uri FROM app.documents WHERE id = ANY(CAST(:ids AS uuid[]))"),
        {"ids": list(document_ids)}).mappings().all()
    return {r["id"]: DocumentSource(r["id"], r["corpus_key"], r["source_uri"]) for r in rows}


def read_generation_members(connection: Connection, generation_id: UUID,
                            version_ids: Sequence[UUID]) -> GenerationMembers | None:
    corpus = connection.execute(text("SELECT corpus_key FROM app.index_generations WHERE id = :g"),
                                {"g": generation_id}).mappings().first()
    if corpus is None:
        return None
    members = connection.execute(text(
        "SELECT document_version_id FROM app.generation_documents WHERE generation_id = :g "
        "AND document_version_id = ANY(CAST(:v AS uuid[]))"), {"g": generation_id, "v": list(version_ids)}).scalars()
    return GenerationMembers(corpus["corpus_key"], frozenset(members))


def read_step_record(connection: Connection, trace_id: UUID) -> StepRecord:
    """A step's trace and full intent row on the caller's workspace-scoped connection (read-only, static SQL)."""
    trace = _one(connection, (
        "SELECT t.run_id, t.generation_id, t.query_sha256, t.authorized_scope::text AS authorized_scope, "
        "t.candidates::text AS candidates, t.final_chunk_ids, s.request_sha256 AS intent_request_sha256 "
        "FROM app.retrieval_traces t LEFT JOIN app.retrieval_steps s ON s.workspace_id = t.workspace_id "
        "AND s.trace_id = t.id WHERE t.id = :id"), {"id": trace_id})
    intent = _one(connection, (
        "SELECT run_id, step, trace_id, request_sha256, query_sha256, scope_sha256, config_sha256 "
        "FROM app.retrieval_steps WHERE trace_id = :id"), {"id": trace_id})
    stored = None if trace is None else StoredTrace(
        trace["run_id"], trace["generation_id"], trace["query_sha256"], trace["authorized_scope"],
        trace["candidates"], tuple(trace["final_chunk_ids"]), trace["intent_request_sha256"])
    return StepRecord(stored, None if intent is None else IntentRecord(
        intent["run_id"], intent["step"], intent["trace_id"], intent["request_sha256"], intent["query_sha256"],
        intent["scope_sha256"], intent["config_sha256"]))


class RetrievalStore:
    def __init__(self, engine: Engine, workspace_id: UUID) -> None:
        if not isinstance(workspace_id, UUID):
            raise TypeError("workspace_id must be a UUID")
        verify_runtime_role(engine, APP_RUNTIME)
        self.engine, self.workspace_id = engine, workspace_id
        # One immutable entry, workspace/store-local and keyed by the head verified inside each snapshot.
        # Concurrent misses may recompute; replacing the whole tuple cannot mix a generation's N and avgdl.
        self._bm25_stats: tuple[UUID, int, float] | None = None

    @contextmanager
    def _tx(self) -> Iterator[Connection]:
        with workspace_transaction(self.engine, self.workspace_id) as connection:
            yield connection

    # -- read-only lookups -----------------------------------------------------------------------------------------

    def find_trace(self, trace_id: UUID) -> StoredTrace | None:
        with self._tx() as connection:
            row = _one(connection, (
                "SELECT t.run_id, t.generation_id, t.query_sha256, t.authorized_scope::text AS authorized_scope, "
                "t.candidates::text AS candidates, t.final_chunk_ids, s.request_sha256 AS intent_request_sha256 "
                "FROM app.retrieval_traces t LEFT JOIN app.retrieval_steps s ON s.workspace_id = t.workspace_id "
                "AND s.trace_id = t.id WHERE t.id = :id"), {"id": trace_id})
        if row is None:
            return None
        return StoredTrace(row["run_id"], row["generation_id"], row["query_sha256"], row["authorized_scope"],
                           row["candidates"], tuple(row["final_chunk_ids"]), row["intent_request_sha256"])

    def find_step_job(self, subject_key: str) -> StepJob | None:
        """The query job for this exact subject (any purpose with this subject is returned, so a mismatching purpose
        is visible to the caller), with its identity, batch states and ledger attempt states."""
        with self._tx() as connection:
            job = _one(connection, (
                "SELECT id, state, purpose, subject_key, input_set_sha256, input_count, request_config_sha256, "
                "tokenizer_sha256 FROM app.embedding_jobs WHERE subject_key = :subject ORDER BY purpose LIMIT 1"),
                {"subject": subject_key})
            if job is None:
                return None
            batches = connection.execute(text(
                "SELECT b.state, a.state AS attempt_state FROM app.embedding_batches b "
                "LEFT JOIN app.usage_attempts a ON a.workspace_id = b.workspace_id AND a.id = b.attempt_id "
                "WHERE b.job_id = :job ORDER BY b.ordinal"), {"job": job["id"]}).mappings().all()
        return StepJob(job["id"], job["state"], job["purpose"], job["subject_key"], job["input_set_sha256"],
                       job["input_count"], job["request_config_sha256"], job["tokenizer_sha256"],
                       tuple(b["state"] for b in batches), tuple(b["attempt_state"] for b in batches))

    def pointer(self, corpus_key: str) -> UUID | None:
        with self._tx() as connection:
            value = connection.execute(text("SELECT active_generation_id FROM app.corpora WHERE corpus_key = :k"),
                                       {"k": corpus_key}).scalar()
        return value if isinstance(value, UUID) else None

    def spans(self, entries: Sequence[tuple[UUID, int, int]]) -> list[Span | None]:
        """Immutable version slices for replay: `(document_version_id, start, end)` each, at most 16, with the stored
        body digest verified against the actual body."""
        if not entries:
            return []
        with self._tx() as connection:
            return read_spans(connection, entries)

    def step_record(self, trace_id: UUID) -> StepRecord:
        """Read-only: the step's trace and its full intent row (T14 query-less verification)."""
        with self._tx() as connection:
            return read_step_record(connection, trace_id)

    def document_sources(self, document_ids: Sequence[UUID]) -> dict[UUID, DocumentSource]:
        """Read-only (T15a export): source identities of this workspace's documents; others read as absent."""
        with self._tx() as connection:
            return read_document_sources(connection, document_ids)

    def generation_members(self, generation_id: UUID, version_ids: Sequence[UUID]) -> GenerationMembers | None:
        """Read-only (T15a export): the generation's corpus and which given versions it contains."""
        with self._tx() as connection:
            return read_generation_members(connection, generation_id, version_ids)

    # -- the intent transaction ------------------------------------------------------------------------------------

    def create_intent(self, *, run_id: UUID, step: int, trace_id: UUID, request_sha256: str, query_sha256: str,
                      scope_sha256: str, config_sha256: str, corpus_key: str, allowlist: Sequence[str],
                      full_policy: bool, worst_case: tuple[str, str]) -> Intent:
        """Check the run, corpus and allowlist, measure the worst-case trace sizes, then insert or find the intent.
        Raises `StepRefused` (nothing written) on any failed check or a conflicting stored request."""
        with self._tx() as connection:
            run = _one(connection, "SELECT state FROM app.runs WHERE id = :id FOR SHARE", {"id": run_id})
            if run is None or run["state"] not in ACTIVE_STATES - WAITING_STATES:
                raise StepRefused("run_not_active")
            existing = _one(connection, "SELECT trace_id, request_sha256 FROM app.retrieval_steps "
                            "WHERE run_id = :run AND step = :step", {"run": run_id, "step": step})
            if existing is not None and (existing["request_sha256"], existing["trace_id"]) != (request_sha256,
                                                                                               trace_id):
                raise StepRefused("step_conflict", "this step already holds a different request")
            corpus = _one(connection, "SELECT domain, active_generation_id FROM app.corpora WHERE corpus_key = :k",
                          {"k": corpus_key})
            if corpus is None:
                raise StepRefused("corpus_not_found")
            if corpus["active_generation_id"] is None:
                raise StepRefused("corpus_not_active")
            if full_policy and corpus["domain"] != "retail":
                raise StepRefused("full_policy_not_supported", "full policy is the retail-only control")
            documents: tuple[UUID, ...] = ()
            if allowlist:
                found = connection.execute(text(
                    "SELECT id FROM app.documents WHERE corpus_key = :k AND source_uri = ANY(:uris) "
                    "ORDER BY source_uri COLLATE \"C\""), {"k": corpus_key, "uris": list(allowlist)}).scalars().all()
                if len(found) != len(allowlist):
                    raise StepRefused("scope_invalid", "an allowlisted document is not in the corpus")
                documents = tuple(found)
            scope_size, candidates_size = connection.execute(text(
                "SELECT pg_column_size(CAST(:scope AS jsonb)), pg_column_size(CAST(:candidates AS jsonb))"),
                {"scope": worst_case[0], "candidates": worst_case[1]}).one()
            if scope_size > SCOPE_LIMIT * 0.9 or candidates_size > CANDIDATES_LIMIT * 0.9:
                raise StepRefused("config_trace_too_large", f"measured worst case {scope_size}/{candidates_size}")
            created = connection.execute(text(
                "INSERT INTO app.retrieval_steps (workspace_id, run_id, step, trace_id, request_sha256, query_sha256, "
                "scope_sha256, config_sha256, created_at) VALUES (app.current_workspace(), :run, :step, :trace, "
                ":request, :query, :scope, :config, now()) ON CONFLICT (workspace_id, run_id, step) DO NOTHING "
                "RETURNING trace_id"),
                {"run": run_id, "step": step, "trace": trace_id, "request": request_sha256, "query": query_sha256,
                 "scope": scope_sha256, "config": config_sha256}).first() is not None
            stored = _one(connection, "SELECT trace_id, request_sha256 FROM app.retrieval_steps WHERE run_id = :run "
                          "AND step = :step", {"run": run_id, "step": step})
            if stored is None:  # pragma: no cover - inserted or found under the same scope
                raise StepRefused("step_conflict", "the intent is not visible")
            if stored["request_sha256"] != request_sha256 or stored["trace_id"] != trace_id:
                raise StepRefused("step_conflict", "this step already holds a different request")
        return Intent(trace_id, request_sha256, created, corpus["domain"], documents)

    # -- the snapshot ----------------------------------------------------------------------------------------------

    def snapshot(self, *, corpus_key: str, mode: str, query: str, query_vector: str | None,
                 document_ids: Sequence[UUID], branch_documents: int, chunks_per_document: int,
                 full_policy_max_chunks: int, lexical_mode: LexicalMode = "all_terms") -> Snapshot:
        """One `REPEATABLE READ READ ONLY` transaction: pointer, generation, branches and candidate texts.

        The connection is owned from acquisition: option setup, the transaction and every read run inside the
        protected region, and it is always closed. A close failure after a primary failure is attached to the primary
        as a note (never replacing it); after success it propagates."""
        if lexical_mode not in ("all_terms", "any_terms", "bm25"):
            raise StepRefused("lexical_mode_invalid")
        connection = connect_runtime(self.engine)
        try:
            result = self._snapshot_in(connection, corpus_key=corpus_key, mode=mode, query=query,
                                       query_vector=query_vector, document_ids=document_ids,
                                       branch_documents=branch_documents, chunks_per_document=chunks_per_document,
                                       full_policy_max_chunks=full_policy_max_chunks, lexical_mode=lexical_mode)
        except BaseException as primary:
            try:
                connection.close()
            except BaseException as cleanup:
                primary.add_note(f"snapshot connection close also failed: {type(cleanup).__name__}")
            raise
        connection.close()
        return result

    def _snapshot_in(self, connection: Connection, *, corpus_key: str, mode: str, query: str,
                     query_vector: str | None, document_ids: Sequence[UUID], branch_documents: int,
                     chunks_per_document: int, full_policy_max_chunks: int,
                     lexical_mode: LexicalMode = "all_terms") -> Snapshot:
        docs = list(document_ids) or None
        connection.execution_options(isolation_level="REPEATABLE READ", postgresql_readonly=True)
        with connection_transaction(connection, self.workspace_id, profile=SqlProfile.RETRIEVAL):
            head = _one(connection, (
                "SELECT c.domain, g.id, g.status, g.embedding_model, g.dimension, g.request_config_sha256 "
                "FROM app.corpora c JOIN app.index_generations g ON g.workspace_id = c.workspace_id "
                "AND g.id = c.active_generation_id WHERE c.corpus_key = :k"), {"k": corpus_key})
            if head is None or head["status"] != "ready":
                raise StepRefused("corpus_not_active")
            result = Snapshot(head["id"], head["domain"], head["embedding_model"], head["dimension"],
                              head["request_config_sha256"])
            base = {"g": result.generation_id, "docs": docs}
            result.text_oversized = connection.execute(text(
                "SELECT count(*) FROM app.chunks k WHERE k.generation_id = :g AND char_length(k.text) > 20000"),
                {"g": result.generation_id}).scalar_one()
            if mode == "full_policy":
                total = connection.execute(text(f"SELECT count(*) FROM app.chunks k {_JOINS} "  # noqa: S608
                                                f"WHERE {_FILTER}"),
                                           base).scalar_one()
                if total > full_policy_max_chunks:
                    raise StepRefused("full_policy_too_many_chunks")
                rows = connection.execute(text(f"SELECT {_ROW_COLUMNS} FROM app.chunks k "  # noqa: S608
                                               f"{_JOINS} WHERE {_FILTER}"),
                                          base).mappings().all()
                result.rows = {r["chunk_id"]: _chunk_row(r) for r in rows}
                return result
            limits = base | {"n": branch_documents, "per": chunks_per_document}
            if mode in ("lexical", "hybrid"):
                lexical_sql = LEXICAL_SQL
                params: dict[str, Any] = {"q": query}
                empty_sql = "SELECT numnode(websearch_to_tsquery('english', :q)) = 0"
                if lexical_mode in ("any_terms", "bm25"):
                    parsed = connection.execute(text(ANY_TERMS_QUERY_SQL),
                        {"q": query, "lexeme_cap": MAX_ANY_TERM_LEXEMES}).mappings().one()
                    if parsed["lexeme_count"] > MAX_ANY_TERM_LEXEMES:
                        raise StepRefused("lexical_query_too_many_lexemes",
                                          f"{lexical_mode} permits at most 64 distinct lexemes")
                    params = {"lexical_query": parsed["query"]}
                    empty_sql = "SELECT numnode(CAST(:lexical_query AS tsquery)) = 0"
                    lexical_sql = LEXICAL_ANY_SQL
                    if lexical_mode == "bm25" and parsed["lexeme_count"]:
                        stats = self._bm25_stats
                        if stats is None or stats[0] != result.generation_id:
                            measured = connection.execute(text(BM25_STATS_SQL),
                                {"g": result.generation_id}).mappings().one()
                            if measured["n"] > 10_000:
                                raise StepRefused("bm25_generation_too_large")
                            stats = (result.generation_id, int(measured["n"]), float(measured["avgdl"]))
                            self._bm25_stats = stats
                        params |= {"lexemes": parsed["lexemes"], "bm25_n": stats[1], "bm25_avgdl": stats[2],
                                   "bm25_k1": BM25_K1, "bm25_b": BM25_B}
                        lexical_sql = LEXICAL_BM25_SQL
                empty = connection.execute(text(empty_sql), params).scalar_one()
                if empty:
                    result.lexical_status = "empty_query"
                else:
                    result.lexical_status = "ok"
                    result.lexical = _hits(connection.execute(text(lexical_sql), limits | params)
                                           .mappings().all())
            if query_vector is not None:
                result.dense_nan_distance = connection.execute(text(
                    "SELECT count(*) FROM app.chunks k WHERE k.generation_id = :g AND (k.embedding IS NULL OR "
                    "(k.embedding <=> CAST(:qv AS public.vector)) = 'NaN')"),
                    {"g": result.generation_id, "qv": query_vector}).scalar_one()
                result.dense = _hits(connection.execute(text(DENSE_SQL), limits | {"qv": query_vector})
                                     .mappings().all())
            ids = sorted({c for hits in (result.lexical, result.dense) for h in hits for c in h.chunk_ids},
                         key=str)
            if ids:
                rows = connection.execute(text(
                    f"SELECT {_ROW_COLUMNS} FROM app.chunks k {_JOINS} WHERE k.generation_id = :g "  # noqa: S608
                    "AND k.id = ANY(:ids)"), {"g": result.generation_id, "ids": ids}).mappings().all()
                result.rows = {r["chunk_id"]: _chunk_row(r) for r in rows}
            return result

    # -- the trace -------------------------------------------------------------------------------------------------

    def insert_trace(self, *, trace_id: UUID, run_id: UUID, generation_id: UUID, query_sha256: str,
                     authorized_scope: str, candidates: str, final_chunk_ids: Sequence[UUID]) -> bool:
        """True if this call wrote the trace, False if a trace with this ID already existed. Raises `StepRefused`
        (`trace_unavailable`) if the actual JSONB sizes exceed the column limits or the insert fails."""
        try:
            with self._tx() as connection:
                scope_size, candidates_size = connection.execute(text(
                    "SELECT pg_column_size(CAST(:scope AS jsonb)), pg_column_size(CAST(:candidates AS jsonb))"),
                    {"scope": authorized_scope, "candidates": candidates}).one()
                if scope_size > SCOPE_LIMIT or candidates_size > CANDIDATES_LIMIT:
                    raise StepRefused("trace_unavailable", f"trace JSONB {scope_size}/{candidates_size} bytes")
                return connection.execute(text(
                    "INSERT INTO app.retrieval_traces (id, workspace_id, run_id, generation_id, query_sha256, "
                    "authorized_scope, candidates, final_chunk_ids, created_at) VALUES (:id, app.current_workspace(), "
                    ":run, :generation, :query, CAST(:scope AS jsonb), CAST(:candidates AS jsonb), :chunks, now()) "
                    "ON CONFLICT (id) DO NOTHING RETURNING id"),
                    {"id": trace_id, "run": run_id, "generation": generation_id, "query": query_sha256,
                     "scope": authorized_scope, "candidates": candidates, "chunks": list(final_chunk_ids)}
                ).first() is not None
        except DBAPIError as error:
            if isinstance(classify_sql_failure(error, "body"), DatabaseUnavailable):
                raise
            raise StepRefused("trace_unavailable", "the trace insert failed") from None
