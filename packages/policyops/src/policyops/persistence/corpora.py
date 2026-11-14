"""Corpus snapshot, atomic generation publication and the historical citation read port (T12; schema 0010).
Static SQL only.

The store runs as the app runtime inside `workspace_transaction`, so forced RLS confines every row to one
workspace, and it verifies at construction that its engine really authenticates as that restricted role.

**Publication** (`publish`) is one bounded transaction. It does no provider or file I/O; its size is bounded by the
corpus limits. Runtime SQL profiles configure per-statement/lock/idle bounds; synchronous SQL can delay cancellation,
and network/COMMIT acknowledgement ambiguity prevents a total wall-clock bound. It:

1. creates the corpus row if absent and locks it `FOR UPDATE`, then compares it with the snapshot taken at the start
   of the import (compare-and-swap, including the no-existing-corpus case); a difference is `StaleActivation`;
2. inserts or reuses documents (a source identity owned by another corpus, or by no corpus, is refused, as is a
   change of its immutable metadata) and their versions: only the one reuse candidate per document (the stored
   version with the expected body digest) is read and hashed, never unrelated history; it is reused only if its
   actual body has that digest, a candidate that does not refuses the publication and is never rewritten; otherwise
   a new version is numbered after the document's latest;
3. inserts the generation (`building`), its document membership and its chunks with their cached vectors, without
   `RETURNING` (the ready-only chunk policy correctly denies reading building rows);
4. retires the previous ready generation, makes the new one ready, moves the corpus pointer and version, and marks
   document versions active or retired;
5. verifies, as the actual runtime role through the ready-only policy in the same transaction: the chunk and
   membership counts, every member's actual body digest against its recorded version digest (documents without
   chunks included) and its membership source identity and corpus against the documents row, every chunk slice
   against its version body, every stored text digest and composite chunk
   identity against its own fields and against the expected value, every vector against its cache entry, and the
   whole expected-set digest recomputed from the rows read back. Any difference raises and rolls everything back.

Part of step 5 re-reads values this process just wrote; it catches database-side differences (offset semantics,
encoding, vector rounding, visibility) and compares the exact set rather than a count. It is not an independent
oracle. The database guards (0010) independently prevent later additions to the published generation.

**Citations** (`resolve_citation_text`) read the cited span from the immutable version body. The checks performed
are reported in the result; they do not authorize access (the service must already have checked run and case
access) and do not establish that a span supports any claim.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
import time
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, text

from policyops.persistence.database import verify_runtime_role, workspace_transaction
from policyops.persistence.embeddings import vector_text
from policyops.persistence.roles import APP_RUNTIME
from policyops.retrieval.corpus import Expected, chunk_entry, chunk_identity, set_digest


MAX_CITATION_CODE_POINTS = 20_000


class StaleActivation(RuntimeError):
    """The corpus changed since the import's snapshot; nothing was written."""


class PublishRefused(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


class VerificationMismatch(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CitationRefused(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CorpusSnapshot:
    exists: bool
    domain: str | None
    active_generation_id: UUID | None
    version: int | None
    active_generation_key_sha256: str | None


@dataclass(frozen=True)
class JobRow:
    id: UUID
    state: str
    created_at: datetime
    deadline_at: datetime
    request_config_sha256: str
    tokenizer_sha256: str

    @property
    def window_seconds(self) -> float:
        return (self.deadline_at - self.created_at).total_seconds()


@dataclass
class PublishResult:
    generation_id: UUID
    retired_generation_id: UUID | None
    documents_new: int
    documents_reused: int
    versions_new: int
    versions_reused: int
    chunks: int
    inserted_text_bytes: int
    inserted_vector_text_bytes: int
    seconds: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class ResolvedCitation:
    text: str
    document_version_id: UUID
    version_sha256: str
    source_uri: str
    generation_id: UUID
    checks: Mapping[str, str]


def _one(connection: Connection, sql: str, params: Mapping[str, Any]) -> dict[str, Any] | None:
    row = connection.execute(text(sql), dict(params)).mappings().first()
    return None if row is None else dict(row)


class CorpusStore:
    def __init__(self, engine: Engine, workspace_id: UUID) -> None:
        if not isinstance(workspace_id, UUID):
            raise TypeError("workspace_id must be a UUID")
        verify_runtime_role(engine, APP_RUNTIME)
        self.engine = engine
        self.workspace_id = workspace_id

    @contextmanager
    def _tx(self) -> Iterator[Connection]:
        with workspace_transaction(self.engine, self.workspace_id) as connection:
            yield connection

    # -- read-only ---------------------------------------------------------------------------------------------------

    def workspace_visible(self) -> bool:
        with self._tx() as connection:
            return connection.execute(text("SELECT EXISTS (SELECT 1 FROM identity.workspaces WHERE id = :id)"),
                                      {"id": self.workspace_id}).scalar_one() is True

    def snapshot(self, corpus_key: str) -> CorpusSnapshot:
        with self._tx() as connection:
            row = _one(connection, "SELECT c.domain, c.active_generation_id, c.version, g.generation_key_sha256 "
                       "FROM app.corpora c LEFT JOIN app.index_generations g ON g.workspace_id = c.workspace_id "
                       "AND g.id = c.active_generation_id WHERE c.corpus_key = :key", {"key": corpus_key})
        if row is None:
            return CorpusSnapshot(False, None, None, None, None)
        return CorpusSnapshot(True, row["domain"], row["active_generation_id"], row["version"],
                              row["generation_key_sha256"])

    def find_job(self, purpose: str, subject_key: str) -> JobRow | None:
        with self._tx() as connection:
            row = _one(connection, "SELECT id, state, created_at, deadline_at, request_config_sha256, "
                       "tokenizer_sha256 FROM app.embedding_jobs WHERE purpose = :purpose "
                       "AND subject_key = :subject", {"purpose": purpose, "subject": subject_key})
        return None if row is None else JobRow(**row)

    def batch_states(self, job_id: UUID) -> dict[str, int]:
        with self._tx() as connection:
            rows = connection.execute(text("SELECT state, count(*) FROM app.embedding_batches WHERE job_id = :job "
                                           "GROUP BY state ORDER BY state"), {"job": job_id}).all()
        return {state: count for state, count in rows}

    # -- publication -----------------------------------------------------------------------------------------------

    def publish(self, expected: Expected, vectors: Mapping[str, Sequence[float]], snapshot: CorpusSnapshot, *,
                before_verify: Callable[[Connection, UUID], None] | None = None) -> PublishResult:
        missing = {c.embed_input_sha256 for c in expected.chunks} - set(vectors)
        if missing:
            raise PublishRefused("vectors_missing", str(len(missing)))
        vector_texts = {digest: vector_text(vectors[digest]) for digest in {c.embed_input_sha256
                                                                             for c in expected.chunks}}
        started = time.monotonic()
        with self._tx() as connection:
            result = self._publish(connection, expected, vector_texts, snapshot, before_verify, started)
            result.seconds["verified"] = time.monotonic() - started
        ended = time.monotonic()
        result.seconds["total"] = ended - started
        result.seconds["lock_held"] = ended - result.seconds.pop("lock_acquired_at")
        return result

    def _publish(self, connection: Connection, expected: Expected, vector_texts: Mapping[str, str],
                 snapshot: CorpusSnapshot, before_verify: Callable[[Connection, UUID], None] | None,
                 started: float) -> PublishResult:
        spec = expected.corpus.corpus
        key = {"key": spec.corpus_key}
        created = connection.execute(text(
            "INSERT INTO app.corpora (workspace_id, corpus_key, domain, active_generation_id, version, created_at, "
            "updated_at) VALUES (app.current_workspace(), :key, :domain, NULL, 1, now(), now()) "
            "ON CONFLICT (workspace_id, corpus_key) DO NOTHING RETURNING version"),
            key | {"domain": spec.domain}).first() is not None
        row = _one(connection, "SELECT domain, active_generation_id, version FROM app.corpora "
                   "WHERE corpus_key = :key FOR UPDATE", key)
        lock_acquired_at = time.monotonic()
        if row is None:  # pragma: no cover - just inserted or found under the same scope
            raise StaleActivation("the corpus row is not visible")
        if snapshot.exists:
            if created or (row["active_generation_id"], row["version"]) != (snapshot.active_generation_id,
                                                                            snapshot.version):
                raise StaleActivation("the corpus changed since this import's snapshot")
        elif not created:
            raise StaleActivation("the corpus was created by another import since this import's snapshot")
        if row["domain"] != spec.domain:
            raise PublishRefused("corpus_domain_conflict", spec.corpus_key)
        documents, documents_new = self._documents(connection, expected)
        versions, versions_new = self._versions(connection, expected, documents)
        generation = uuid4()
        header = expected.header
        connection.execute(text(
            "INSERT INTO app.index_generations (id, workspace_id, policy_sha256, parser_version, embedding_model, "
            "dimension, status, created_at, corpus_key, source_repository, source_commit, source_tree, "
            "source_manifest_sha256, corpus_manifest_sha256, license_scope, render, chunk_config, tokenizer_sha256, "
            "request_config_sha256, expected_set_sha256, generation_key_sha256, document_count, chunk_count) "
            "VALUES (:id, app.current_workspace(), :policy, :parser, :model, :dimensions, 'building', now(), :key, "
            ":repository, :commit, :tree, :source_manifest, :corpus_manifest, :license_scope, :render, "
            ":chunk_config, :tokenizer, :config, :expected_set, :generation_key, :documents, :chunks)"),
            {"id": generation, "policy": expected.corpus.corpus_manifest_sha256,
             "parser": expected.corpus.parser_version,
             "model": header["model"], "dimensions": header["dimensions"], "key": spec.corpus_key,
             "repository": expected.corpus.revision.repository, "commit": expected.corpus.revision.commit,
             "tree": expected.corpus.revision.tree,
             "source_manifest": expected.corpus.revision.source_manifest_sha256,
             "corpus_manifest": expected.corpus.corpus_manifest_sha256, "license_scope": spec.license_scope,
             "render": spec.render, "chunk_config": expected.corpus.chunk_config,
             "tokenizer": expected.tokenizer_sha256,
             "config": expected.request_config_sha256, "expected_set": expected.expected_set_sha256,
             "generation_key": expected.generation_key_sha256, "documents": len(expected.documents),
             "chunks": len(expected.chunks)})
        connection.execute(text(
            "INSERT INTO app.generation_documents (workspace_id, generation_id, document_version_id, ordinal, "
            "source_uri, source_path, git_blob, raw_sha256, raw_bytes, chunk_count, created_at) VALUES "
            "(app.current_workspace(), :generation, :version, :ordinal, :uri, :path, :blob, :raw, :size, :chunks, "
            "now())"),
            [{"generation": generation, "version": versions[d.source.source_uri], "ordinal": d.ordinal,
              "uri": d.source.source_uri, "path": d.source.path, "blob": d.source.git_blob,
              "raw": d.source.raw_sha256, "size": d.source.raw_bytes, "chunks": d.chunk_count}
             for d in expected.documents])
        if expected.chunks:
            connection.execute(text(
                "INSERT INTO app.chunks (id, workspace_id, generation_id, document_version_id, parent_id, heading, "
                "start_offset, end_offset, text, sha256, embedding, created_at, section_ordinal, section_start, "
                "section_end, text_sha256, embed_input_sha256, request_config_sha256) VALUES (:id, "
                "app.current_workspace(), :generation, :version, NULL, :heading, :start, :end, :text, :sha256, "
                "CAST(:embedding AS public.vector), now(), :ordinal, :section_start, :section_end, :text_sha256, "
                ":input, :config)"),
                [{"id": uuid4(), "generation": generation, "version": versions[c.source_uri], "heading": c.heading,
                  "start": c.start, "end": c.end, "text": c.text, "sha256": c.sha256,
                  "embedding": vector_texts[c.embed_input_sha256], "ordinal": c.section_ordinal,
                  "section_start": c.section_start, "section_end": c.section_end, "text_sha256": c.text_sha256,
                  "input": c.embed_input_sha256, "config": expected.request_config_sha256}
                 for c in expected.chunks])
        retired = row["active_generation_id"]
        if retired is not None:
            done = connection.execute(text("UPDATE app.index_generations SET status = 'retired' WHERE id = :id "
                                           "AND status = 'ready'"), {"id": retired}).rowcount
            if done != 1:
                raise StaleActivation("the active generation is no longer ready")
        connection.execute(text("UPDATE app.index_generations SET status = 'ready', ready_at = now() WHERE id = :id"),
                           {"id": generation})
        connection.execute(text("UPDATE app.corpora SET active_generation_id = :generation, version = version + 1, "
                                "updated_at = now() WHERE corpus_key = :key"), key | {"generation": generation})
        active = sorted(set(versions.values()))
        connection.execute(text("UPDATE app.document_versions SET status = 'active', effective_to = NULL "
                                "WHERE id = ANY(:ids) AND (status <> 'active' OR effective_to IS NOT NULL)"),
                           {"ids": active})
        connection.execute(text(
            "UPDATE app.document_versions v SET status = 'retired', effective_to = now() FROM app.documents d "
            "WHERE d.workspace_id = v.workspace_id AND d.id = v.document_id AND d.corpus_key = :key "
            "AND v.status = 'active' AND NOT (v.id = ANY(:ids))"), key | {"ids": active})
        if before_verify is not None:
            before_verify(connection, generation)
        self._verify(connection, expected, generation)
        documents_reused = len(expected.documents) - documents_new
        return PublishResult(
            generation, retired, documents_new, documents_reused, versions_new, len(expected.documents) - versions_new,
            len(expected.chunks), sum(len(c.text.encode("utf-8")) for c in expected.chunks),
            sum(len(vector_texts[c.embed_input_sha256]) for c in expected.chunks),
            {"lock_acquired_at": lock_acquired_at, "locked_after": lock_acquired_at - started})

    def _documents(self, connection: Connection, expected: Expected) -> tuple[dict[str, UUID], int]:
        spec = expected.corpus.corpus
        uris = [d.source.source_uri for d in expected.documents]
        rows = connection.execute(text("SELECT id, source_uri, domain, publisher, license, corpus_key "
                                       "FROM app.documents WHERE source_uri = ANY(:uris)"), {"uris": uris}
                                  ).mappings().all()
        found: dict[str, UUID] = {}
        for row in rows:
            if row["corpus_key"] is None:
                raise PublishRefused("source_identity_legacy_conflict", row["source_uri"])
            if row["corpus_key"] != spec.corpus_key:
                raise PublishRefused("source_identity_owned_by_other_corpus", row["source_uri"])
            if (row["domain"], row["publisher"], row["license"]) != (spec.domain, spec.publisher, spec.license):
                raise PublishRefused("document_metadata_changed", row["source_uri"])
            found[row["source_uri"]] = row["id"]
        new = [uri for uri in uris if uri not in found]
        if new:
            ids = {uri: uuid4() for uri in new}
            connection.execute(text(
                "INSERT INTO app.documents (id, workspace_id, domain, publisher, source_uri, license, created_at, "
                "corpus_key) VALUES (:id, app.current_workspace(), :domain, :publisher, :uri, :license, now(), :key)"),
                [{"id": ids[uri], "domain": spec.domain, "publisher": spec.publisher, "uri": uri,
                  "license": spec.license, "key": spec.corpus_key} for uri in new])
            found |= ids
        return found, len(new)

    def _versions(self, connection: Connection, expected: Expected, documents: Mapping[str, UUID]
                  ) -> tuple[dict[str, UUID], int]:
        """At most one reusable candidate (the unique `(document, sha256)` match) and the latest version number per
        imported document, through the existing unique indexes: unrelated history is neither loaded nor hashed.
        The schema checks only the format of a stored digest, so a candidate is reused only if its actual body
        has that digest; a corrupt candidate refuses the publication and is never rewritten."""
        wanted = [(documents[d.source.source_uri], d.source.version_sha256) for d in expected.documents]
        document_ids = [w[0] for w in wanted]
        params = {"documents": document_ids, "digests": [w[1] for w in wanted]}
        candidates = connection.execute(text(
            "SELECT v.id, v.document_id, v.sha256, encode(sha256(convert_to(v.body, 'UTF8')), 'hex') AS actual "
            "FROM unnest(CAST(:documents AS uuid[]), CAST(:digests AS text[])) AS w(document_id, sha256) "
            "JOIN app.document_versions v ON v.workspace_id = app.current_workspace() "
            "AND v.document_id = w.document_id AND v.sha256 = w.sha256"), params).mappings().all()
        for row in candidates:
            if row["sha256"] != row["actual"]:
                raise PublishRefused("version_body_digest_mismatch", str(row["id"]))
        by_digest = {(row["document_id"], row["sha256"]): row["id"] for row in candidates}
        highest: dict[UUID, int] = {row[0]: row[1] for row in connection.execute(text(
            "SELECT v.document_id, max(v.version) FROM app.document_versions v "
            "WHERE v.document_id = ANY(:documents) GROUP BY v.document_id"),
            {"documents": sorted(set(document_ids))}).all()}
        versions: dict[str, UUID] = {}
        inserts = []
        for document in expected.documents:
            source = document.source
            document_id = documents[source.source_uri]
            existing = by_digest.get((document_id, source.version_sha256))
            if existing is not None:
                versions[source.source_uri] = existing
                continue
            version_id = uuid4()
            highest[document_id] = highest.get(document_id, 0) + 1
            inserts.append({"id": version_id, "document": document_id, "version": highest[document_id],
                            "sha256": source.version_sha256, "body": source.body})
            versions[source.source_uri] = version_id
        if inserts:
            connection.execute(text(
                "INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, body, status, "
                "effective_from, created_at) VALUES (:id, app.current_workspace(), :document, :version, :sha256, "
                ":body, 'active', now(), now())"), inserts)
        return versions, len(inserts)

    def _verify(self, connection: Connection, expected: Expected, generation: UUID) -> None:
        params = {"generation": generation}
        state = _one(connection, "SELECT status, expected_set_sha256, generation_key_sha256, chunk_count, "
                     "document_count FROM app.index_generations WHERE id = :generation", params)
        if state is None or state["status"] != "ready":
            raise VerificationMismatch("generation_not_ready")
        if (state["expected_set_sha256"], state["generation_key_sha256"], state["chunk_count"],
                state["document_count"]) != (expected.expected_set_sha256, expected.generation_key_sha256,
                                             len(expected.chunks), len(expected.documents)):
            raise VerificationMismatch("generation_row_mismatch")
        counted = connection.execute(text(
            "SELECT (SELECT count(*) FROM app.chunks WHERE generation_id = :generation), "
            "(SELECT count(*) FROM app.generation_documents WHERE generation_id = :generation)"), params).one()
        if tuple(counted) != (len(expected.chunks), len(expected.documents)):
            raise VerificationMismatch("count_mismatch")
        bad = connection.execute(text(
            "SELECT count(*) FROM app.chunks k JOIN app.document_versions v ON v.workspace_id = k.workspace_id "
            "AND v.id = k.document_version_id WHERE k.generation_id = :generation AND ("
            "substring(v.body FROM k.start_offset + 1 FOR k.end_offset - k.start_offset) IS DISTINCT FROM k.text "
            "OR k.text_sha256 IS DISTINCT FROM encode(sha256(convert_to(k.text, 'UTF8')), 'hex') "
            "OR k.embedding IS NULL OR vector_dims(k.embedding) <> 1536)"), params).scalar_one()
        if bad:
            raise VerificationMismatch("chunk_slice_or_digest_mismatch")
        bad = connection.execute(text(
            "SELECT count(*) FROM app.chunks k LEFT JOIN app.embedding_cache e ON e.workspace_id = k.workspace_id "
            "AND e.input_sha256 = k.embed_input_sha256 AND e.request_config_sha256 = k.request_config_sha256 "
            "WHERE k.generation_id = :generation AND (e.vector IS NULL "
            "OR k.embedding::text IS DISTINCT FROM e.vector::text)"), params).scalar_one()
        if bad:
            raise VerificationMismatch("vector_mismatch")
        members = connection.execute(text(
            "SELECT g.ordinal, g.source_uri, d.source_uri AS document_uri, d.corpus_key, v.sha256, "
            "encode(sha256(convert_to(v.body, 'UTF8')), 'hex') AS actual, g.source_path, g.git_blob, "
            "g.raw_sha256, g.raw_bytes, g.chunk_count FROM app.generation_documents g "
            "JOIN app.document_versions v ON v.workspace_id = g.workspace_id AND v.id = g.document_version_id "
            "JOIN app.documents d ON d.workspace_id = v.workspace_id AND d.id = v.document_id "
            "WHERE g.generation_id = :generation ORDER BY g.ordinal"), params).mappings().all()
        documents = []
        for member in members:  # every member, including documents without chunks, against its stored body
            if member["actual"] != member["sha256"]:
                raise VerificationMismatch("version_body_digest_mismatch")
            if member["source_uri"] != member["document_uri"]:
                raise VerificationMismatch("member_source_identity_mismatch")
            if member["corpus_key"] != expected.corpus.corpus.corpus_key:
                raise VerificationMismatch("member_corpus_mismatch")
            documents.append([member["ordinal"], member["document_uri"], member["actual"], member["source_path"],
                              member["git_blob"], member["raw_sha256"], member["raw_bytes"], member["chunk_count"]])
        rows = connection.execute(text(
            "SELECT d.source_uri, v.sha256 AS version_sha256, k.start_offset, k.end_offset, k.sha256, k.text_sha256, "
            "k.heading, k.section_ordinal, k.section_start, k.section_end, k.embed_input_sha256 FROM app.chunks k "
            "JOIN app.document_versions v ON v.workspace_id = k.workspace_id AND v.id = k.document_version_id "
            "JOIN app.documents d ON d.workspace_id = v.workspace_id AND d.id = v.document_id "
            "WHERE k.generation_id = :generation"), params).mappings().all()
        expected_by_position = {(c.source_uri, c.start, c.end): c for c in expected.chunks}
        entries = []
        for row in rows:
            want = expected_by_position.get((row["source_uri"], row["start_offset"], row["end_offset"]))
            if want is None:
                raise VerificationMismatch("unexpected_chunk")
            if row["text_sha256"] != want.text_sha256:
                raise VerificationMismatch("text_digest_mismatch")
            recomputed = chunk_identity(row["source_uri"], row["version_sha256"], row["start_offset"],
                                        row["end_offset"], row["heading"], row["section_ordinal"],
                                        row["section_start"], row["section_end"], row["text_sha256"],
                                        parser=expected.corpus.parser_version,
                                        chunk_config=expected.corpus.chunk_config)
            if row["sha256"] != recomputed or row["sha256"] != want.sha256:
                raise VerificationMismatch("chunk_identity_mismatch")
            if row["embed_input_sha256"] != want.embed_input_sha256:
                raise VerificationMismatch("embed_input_digest_mismatch")
            entries.append([row["source_uri"], row["version_sha256"], row["start_offset"], row["end_offset"],
                            row["sha256"], row["text_sha256"], row["heading"], row["section_ordinal"],
                            row["section_start"], row["section_end"], row["embed_input_sha256"]])
        if sorted(entries, key=lambda e: (e[0], e[2], e[3])) != [chunk_entry(c) for c in expected.chunks]:
            raise VerificationMismatch("chunk_set_mismatch")
        if set_digest(expected.header, documents, entries) != expected.expected_set_sha256:
            raise VerificationMismatch("expected_set_mismatch")

    # -- historical citations --------------------------------------------------------------------------------------

    def resolve_citation_text(self, citation_id: UUID, run_id: UUID) -> ResolvedCitation:
        """The cited span from the immutable version body, with the checks actually performed. Not authorization:
        run and case access must already have been checked by the service; the run equality is a re-check."""
        with self._tx() as connection:
            row = _one(connection, (
                "SELECT c.span_start, c.span_end, c.document_version_id, t.run_id, t.generation_id, v.sha256, "
                "encode(sha256(convert_to(v.body, 'UTF8')), 'hex') AS actual, "
                "char_length(v.body) AS body_length, d.source_uri, g.corpus_key IS NOT NULL AS corpus_generation, "
                "EXISTS (SELECT 1 FROM app.generation_documents m WHERE m.workspace_id = c.workspace_id "
                "AND m.generation_id = t.generation_id AND m.document_version_id = c.document_version_id) AS member, "
                "CASE WHEN c.span_end - c.span_start <= :limit THEN "
                "substring(v.body FROM c.span_start + 1 FOR c.span_end - c.span_start) END AS span_text "
                "FROM app.citations c "
                "JOIN app.retrieval_traces t ON t.workspace_id = c.workspace_id AND t.id = c.trace_id "
                "JOIN app.document_versions v ON v.workspace_id = c.workspace_id AND v.id = c.document_version_id "
                "JOIN app.documents d ON d.workspace_id = v.workspace_id AND d.id = v.document_id "
                "JOIN app.index_generations g ON g.workspace_id = t.workspace_id AND g.id = t.generation_id "
                "WHERE c.id = :citation"), {"citation": citation_id, "limit": MAX_CITATION_CODE_POINTS})
        if row is None:
            raise CitationRefused("citation_not_found")
        if row["run_id"] != run_id:
            raise CitationRefused("citation_run_mismatch")
        if row["actual"] != row["sha256"]:
            raise CitationRefused("citation_version_digest_mismatch")  # the recorded digest is not these bytes
        if row["span_end"] - row["span_start"] > MAX_CITATION_CODE_POINTS:
            raise CitationRefused("citation_span_too_long")
        if row["span_end"] > row["body_length"]:
            raise CitationRefused("citation_span_outside_version")
        if row["corpus_generation"] and not row["member"]:
            raise CitationRefused("citation_version_not_in_generation")
        checks = {"run_match": "checked", "version_digest": "checked", "span_within_version": "checked"}
        if row["corpus_generation"]:
            checks |= {"version_in_generation": "checked", "chunk_containment": "write_time_guard"}
        else:
            checks |= {"version_in_generation": "not_recorded_legacy",
                       "chunk_containment": "upgrade_validated_or_pre_guard"}
        return ResolvedCitation(row["span_text"], row["document_version_id"], row["sha256"], row["source_uri"],
                                row["generation_id"], checks)
