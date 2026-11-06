"""Authoritative read-only export of stored retrieval steps into E01 step records (T15a).

Nothing here is taken on trust from JSON. For one `(run, step)` of this workspace the exporter:

1. reads the step's trace and full intent row and runs the shared query-less checks (`check_step`): trace ID derived
   from workspace, run and step; intent and scope bound to this run, step and corpus; request recomputed from the
   intent digests; payload digest; delivered chunk IDs equal the trace's final chunk IDs;
2. verifies every delivered entry against its immutable version span and body digest and the evidence-text digest
   (`check_step_evidence`);
3. maps every delivered and candidate document UUID through this workspace's own `app.documents` rows: the corpus key
   must be the study corpus and the `source_uri` must be `tau2:<domain>/<key>` with `key` in the reviewed ingest
   manifest's document list. A missing, foreign, unlisted or inconsistent mapping is an `ExportError`;
4. requires the trace generation to belong to the study corpus and every delivered version to be a member of that
   generation (`generation_documents`; no chunk read, so historical generations stay exportable).

The record carries identities, stems, digests and counts only: no query text, labels or instructions. The query
digest is the immutable intent's (equal to the scope's and the trace's, checked above); no raw query text is accepted.
Candidates are the trace's bounded `fused` pool (full policy: the delivered documents); `ranked` is the order delivery
used (an applied rerank's window order, then the rest of the fused order; empty for full policy). These are
consistency checks of stored records, not semantic, authorization or current-policy truth. A step record says nothing
about per-invocation cost: that belongs to the ledger.

Because the records omit query text, they alone do not support a full offline query replay: the frozen visible-query
sidecar with its provenance (and an exact UTF-8 query-digest recheck against the immutable intent) is T15b work.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from sqlalchemy import Engine

from policyops.persistence.retrieval import DocumentSource, GenerationMembers, RetrievalStore, Span, StepRecord
from policyops.retrieval.grounding import StepFailure, check_step, check_step_evidence
from policyops.retrieval.search import span_entries, trace_id_for
from policyops.retrieval.sources import load_manifest, source_uri
from policyops.runtime.clock import UnsafeTestHook
from policyops_contracts.e01 import CandidateDocument, DeliveredDocument, RetrievalStepRecord


class ExportError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class SourceAllowlist:
    """The reviewed ingest manifest's document keys for one corpus (the only stems an export may emit)."""

    corpus_key: str
    domain: str
    keys: frozenset[str]
    manifest_sha256: str

    def stem(self, uri: str) -> str | None:
        prefix = source_uri(self.domain, "")
        if not uri.startswith(prefix):
            return None
        key = uri[len(prefix):]
        return key if key in self.keys else None


def allowlist_from_manifest(raw: bytes, sha256: str, corpus_key: str) -> SourceAllowlist:
    manifest = load_manifest(raw, sha256)  # digest, strict shape, sorted unique keys
    corpus = next((c for c in manifest.corpora if c.corpus_key == corpus_key), None)
    if corpus is None:
        raise ExportError("corpus_not_in_manifest", corpus_key)
    return SourceAllowlist(corpus_key, corpus.domain, frozenset(d.document_key for d in corpus.documents), sha256)


class SourceReader(Protocol):
    workspace_id: UUID

    def step_record(self, trace_id: UUID) -> StepRecord: ...

    def spans(self, entries: Sequence[tuple[UUID, int, int]]) -> list[Span | None]: ...

    def pointer(self, corpus_key: str) -> UUID | None: ...

    def document_sources(self, document_ids: Sequence[UUID]) -> dict[UUID, DocumentSource]: ...

    def generation_members(self, generation_id: UUID, version_ids: Sequence[UUID]) -> GenerationMembers | None: ...


class TraceExporter:
    """Read-only, for one workspace, as the app runtime (verified by the store). A replacement reader is accepted only
    from a `test_only` reader of the same workspace with `env="test"`."""

    def __init__(self, engine: Engine, workspace_id: UUID, allowlist: SourceAllowlist, *,
                 store: SourceReader | None = None, env: str | None = None) -> None:
        if store is not None:
            if getattr(store, "test_only", False) is not True or env != "test":
                raise UnsafeTestHook("a replacement source reader must be test-only in the test environment")
            if store.workspace_id != workspace_id:
                raise ValueError("the source reader belongs to another workspace")
        self.store: SourceReader = store if store is not None else RetrievalStore(engine, workspace_id)
        self.workspace_id, self.allowlist = workspace_id, allowlist

    def export_step(self, *, run_id: UUID, step: int) -> RetrievalStepRecord:
        allowlist = self.allowlist
        record = self.store.step_record(trace_id_for(self.workspace_id, run_id, step))
        checked = check_step(record, workspace_id=self.workspace_id, run_id=run_id, step=step,
                             corpus_key=allowlist.corpus_key)
        if isinstance(checked, StepFailure):
            raise ExportError(checked.status, checked.detail)
        candidates = checked.candidates
        evidence = check_step_evidence(checked, self.store.spans(span_entries(candidates)))
        if isinstance(evidence, StepFailure):
            raise ExportError(evidence.status, evidence.detail)
        fused = [f.document_id for f in candidates.fused]
        delivered_ids = [d.document_id for d in candidates.delivered]
        if candidates.mode != "full_policy":
            # Internal trace contradictions (never produced by the T13/T14 runtime) are refused, not repaired.
            window = list(candidates.rerank.order) if candidates.rerank is not None else []
            if (len(set(fused)) != len(fused) or not set(delivered_ids) <= set(fused)
                    or len(set(window)) != len(window) or not set(window) <= set(fused)):
                raise ExportError("trace_contradiction", "delivered or reranked documents outside the fused pool")
        sources = self.store.document_sources(sorted(set(fused) | set(delivered_ids), key=str))
        stems: dict[UUID, str] = {}
        for document_id in set(fused) | set(delivered_ids):
            source = sources.get(document_id)
            if source is None:
                raise ExportError("document_not_visible", str(document_id))
            stem = allowlist.stem(source.source_uri)
            if source.corpus_key != allowlist.corpus_key or stem is None:
                raise ExportError("document_not_in_corpus", str(document_id))
            stems[document_id] = stem
        for chunk, span in zip(evidence.chunks, evidence.spans, strict=True):
            if span.source_uri != sources[chunk.document_id].source_uri:
                raise ExportError("source_mismatch", str(chunk.document_id))
        versions = sorted({d.document_version_id for d in candidates.delivered}, key=str)
        members = self.store.generation_members(candidates.generation_id, versions)
        if members is None or members.corpus_key != allowlist.corpus_key:
            raise ExportError("generation_not_in_corpus", str(candidates.generation_id))
        if not set(versions) <= members.versions:
            raise ExportError("version_not_in_generation", str(candidates.generation_id))
        if candidates.mode == "full_policy":
            pool: list[UUID] = list(dict.fromkeys(delivered_ids))  # C = D for the full-policy control
            ranked: list[UUID] = []
        else:
            pool = fused
            rerank = candidates.rerank
            window = list(rerank.order) if rerank is not None and rerank.status == "applied" else []
            ranked = window + [d for d in fused if d not in window]
        current = self.store.pointer(allowlist.corpus_key) == candidates.generation_id
        return RetrievalStepRecord(
            step=step, trace_id=checked.trace_id, payload_sha256=candidates.payload_sha256,
            request_sha256=checked.intent.request_sha256, query_sha256=checked.intent.query_sha256,
            config_sha256=checked.intent.config_sha256,
            generation_id=candidates.generation_id, generation_current_at_export=current, mode=candidates.mode,
            delivered=tuple(DeliveredDocument(evidence_number=d.evidence_number, document_id=d.document_id,
                                              document_version_id=d.document_version_id, stem=stems[d.document_id])
                            for d in candidates.delivered),
            candidates=tuple(CandidateDocument(rank=i, document_id=d, stem=stems[d]) for i, d in enumerate(pool, 1)),
            ranked=tuple(stems[d] for d in ranked), evidence_tokens=candidates.evidence_tokens,
            rerank_status=None if candidates.rerank is None else candidates.rerank.status)
