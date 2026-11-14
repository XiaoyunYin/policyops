"""Read-only lexical policy search using the same T13 snapshot, fusion and delivery components.

Unlike Retriever.retrieve this does not create intents, traces, jobs or provider calls. The caller must authorize
the workspace and run first. Returned source spans are citations, not a claim of semantic support or current truth.
"""

from __future__ import annotations

import time
from uuid import UUID

from sqlalchemy import Engine

from policyops.persistence.retrieval import RetrievalStore, StepRefused
from policyops.providers.tokenizer import load
from policyops.retrieval.counting import EvidenceCounter
from policyops.retrieval.rank import ChunkRow, deliver, fuse
from policyops_contracts.retrieval import RetrievalConfig
from policyops_contracts.scalars import RunScope


def search(engine: Engine, scope: RunScope, corpus_key: str, query: str, *, deadline: float
           ) -> tuple[UUID, tuple[ChunkRow, ...]]:
    config = RetrievalConfig(mode="lexical", max_chunks=4, max_evidence_tokens=4096)
    tokenizer = load()
    tokenizer.count(query)  # same local query computational limits as the retrieval foundation
    store = RetrievalStore(engine, scope.workspace_id)
    snapshot = store.snapshot(
        corpus_key=corpus_key, mode="lexical", query=query, query_vector=None, document_ids=(),
        branch_documents=config.branch_documents, chunks_per_document=config.chunks_per_document,
        full_policy_max_chunks=config.full_policy_max_chunks)
    delivery = deliver(fuse(snapshot.lexical, (), config.rrf_k), snapshot.rows, config,
                       EvidenceCounter(tokenizer, deadline=deadline))
    # Reuse grounding's immutable-body read, not chunk text as its own provenance oracle.
    spans = store.spans([(c.document_version_id, c.start, c.end) for c in delivery.chunks])
    if len(spans) != len(delivery.chunks) or any(
            span is None or not span.body_digest_ok or
            (span.document_id, span.document_version_id, span.source_uri, span.version_number, span.text) !=
            (chunk.document_id, chunk.document_version_id, chunk.source_uri, chunk.version_number, chunk.text)
            for chunk, span in zip(delivery.chunks, spans, strict=True)):
        raise StepRefused("citation_integrity")
    if time.monotonic() >= deadline:
        raise TimeoutError("policy search deadline")
    return snapshot.generation_id, delivery.chunks
