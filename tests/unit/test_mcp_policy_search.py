"""The read-only gateway search verifies citations against immutable source bodies using grounding's port."""

from dataclasses import replace
import time
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy import Engine

from policyops.gateway import policy_search
from policyops.persistence.retrieval import Snapshot, Span, StepRefused
from policyops.retrieval.rank import ChunkRow, Hit
from policyops_testing.gateway_cases import INJECTION, W


@pytest.mark.parametrize("defect", [None, "digest", "text", "source", "version", "missing", "count"])
def test_search_citation_integrity(monkeypatch: pytest.MonkeyPatch, defect: str | None) -> None:
    chunk = ChunkRow(uuid4(), uuid4(), uuid4(), "policy://untrusted.example", 1, "Policy", 0,
                     len(INJECTION), INJECTION)
    span = Span(chunk.document_version_id, chunk.document_id, chunk.source_uri, 1, INJECTION, True)
    generation = uuid4()
    snapshot = Snapshot(generation, "banking_knowledge", None, 1536, None,
        lexical=[Hit(chunk.document_id, chunk.source_uri, 1, "1", (chunk.chunk_id,))], rows={chunk.chunk_id: chunk})
    spans: list[Span | None] = [span]
    if defect == "digest":
        spans = [replace(span, body_digest_ok=False)]
    elif defect == "text":
        spans = [replace(span, text="different source text")]
    elif defect == "source":
        spans = [replace(span, source_uri="policy://foreign")]
    elif defect == "version":
        spans = [replace(span, document_version_id=uuid4())]
    elif defect == "missing":
        spans = [None]
    elif defect == "count":
        spans = []
    class Store:
        def snapshot(self, **kwargs: Any) -> Snapshot:
            assert kwargs["mode"] == "lexical" and kwargs["query_vector"] is None
            return snapshot

        def spans(self, entries: object) -> list[Span | None]:
            assert entries == [(chunk.document_version_id, chunk.start, chunk.end)]
            return spans
    monkeypatch.setattr(policy_search, "RetrievalStore", lambda *args: Store())
    if defect:
        with pytest.raises(StepRefused, match="citation_integrity"):
            policy_search.search(cast(Engine, object()), W.run_scope, "fixed-corpus", "policy",
                                 deadline=time.monotonic() + 5)
    else:
        result = policy_search.search(cast(Engine, object()), W.run_scope, "fixed-corpus", "policy",
                                      deadline=time.monotonic() + 5)
        assert result == (generation, (chunk,))
