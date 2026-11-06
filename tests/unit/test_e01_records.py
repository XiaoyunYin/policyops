"""E01 step-record export (T15a) against a test-only reader of digest-consistent synthetic stored steps: the
delivered set, the bounded candidate pool, the delivery order (applied rerank first), the full-policy definition C = D,
historical generations, and refusals for every unmapped, foreign, unlisted or inconsistent relationship. The real
PostgreSQL path is in tests/integration/test_e01_records.py."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
import hashlib
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest

from policyops.persistence.retrieval import (
    DocumentSource,
    GenerationMembers,
    IntentRecord,
    Span,
    StepRecord,
    StoredTrace,
)
from policyops.retrieval.rank import ChunkRow, assemble
from policyops.retrieval.records import ExportError, SourceAllowlist, TraceExporter, allowlist_from_manifest
from policyops.retrieval.search import trace_id_for
from policyops.runtime.clock import UnsafeTestHook
from policyops_contracts.retrieval import (
    DeliveredChunk,
    FusedDocument,
    RerankTrace,
    TraceCandidates,
    TraceScope,
    canonical_sha256,
)
from policyops_testing.corpus_fixtures import FixtureCorpus, banking, write


WS, RUN, GEN = UUID(int=31), UUID(int=32), UUID(int=33)
CORPUS = "test-banking"
KEYS = ("a", "b", "c", "d")
ALLOW = SourceAllowlist(CORPUS, "banking_knowledge", frozenset(KEYS), "f" * 64)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def doc(key: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"doc:{key}")


def version(key: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"ver:{key}")


@dataclass
class Reader:
    steps: dict[UUID, tuple[StepRecord, list[Span | None]]] = field(default_factory=dict)
    sources: dict[UUID, DocumentSource] = field(default_factory=dict)
    members: GenerationMembers | None = None
    current: UUID | None = GEN
    workspace_id: UUID = WS
    test_only: bool = True

    def step_record(self, trace_id: UUID) -> StepRecord:
        return self.steps[trace_id][0] if trace_id in self.steps else StepRecord(None, None)

    def spans(self, entries: Sequence[tuple[UUID, int, int]]) -> list[Span | None]:
        for _record, spans in self.steps.values():
            return list(spans)
        return [None] * len(entries)

    def pointer(self, corpus_key: str) -> UUID | None:
        return self.current

    def document_sources(self, document_ids: Sequence[UUID]) -> dict[UUID, DocumentSource]:
        return {d: self.sources[d] for d in document_ids if d in self.sources}

    def generation_members(self, generation_id: UUID, version_ids: Sequence[UUID]) -> GenerationMembers | None:
        return self.members


def stored(step: int, delivered: Sequence[str], fused: Sequence[str], *, mode: str = "lexical",
           rerank_order: Sequence[str] | None = None) -> Reader:
    texts = {k: f"Policy text {k}." for k in KEYS}
    entries: list[DeliveredChunk] = []
    spans: list[Span | None] = []
    chunks: list[ChunkRow] = []
    for n, key in enumerate(delivered, 1):
        text = texts[key]
        entries.append(DeliveredChunk(evidence_number=n, chunk_id=uuid5(NAMESPACE_URL, f"chunk:{key}"),
                                      document_id=doc(key), document_version_id=version(key), version_number=1,
                                      start=0, end=len(text), heading=key, text_sha256=sha(text)))
        spans.append(Span(version(key), doc(key), f"tau2:banking_knowledge/{key}", 1, text, True, sha(text)))
        chunks.append(ChunkRow(entries[-1].chunk_id, doc(key), version(key), f"tau2:banking_knowledge/{key}", 1, key,
                               0, len(text), text))
    query, scope_digest, config = sha("q"), sha("s"), sha("c")
    request = canonical_sha256({"v": "policyops.retrieval-request/v1", "query_sha256": query,
                                "scope_sha256": scope_digest, "config_sha256": config})
    rerank = None if rerank_order is None else RerankTrace(
        status="applied", model="gpt-6-luna", prompt_sha256="1" * 64, request_identity="2" * 64,
        max_output_tokens=512, window=len(rerank_order), order=tuple(doc(k) for k in rerank_order))
    body = TraceCandidates(
        request_sha256=request, generation_id=GEN, mode=mode,  # type: ignore[arg-type]
        lexical_status="not_used" if mode == "full_policy" else "ok", dense_status="not_used",
        fused=tuple(FusedDocument(document_id=doc(k), rank=i, rrf=f"1/{60 + i}", lexical_rank=i)
                    for i, k in enumerate(fused, 1)),
        delivered=tuple(entries), evidence_tokens=10, evidence_text_sha256=sha(assemble(chunks)), rerank=rerank,
        payload_sha256="0" * 64)
    body = body.model_copy(update={"payload_sha256": body.computed_payload_sha256()})
    scope = TraceScope(corpus_key=CORPUS, step=step, allowlist_sha256="a" * 64, config_sha256=config,
                       query_sha256=query)
    trace = trace_id_for(WS, RUN, step)
    record = StepRecord(StoredTrace(RUN, GEN, query, scope.model_dump_json(), body.model_dump_json(),
                                    tuple(e.chunk_id for e in entries), request),
                        IntentRecord(RUN, step, trace, request, query, scope_digest, config))
    return Reader(steps={trace: (record, spans)},
                  sources={doc(k): DocumentSource(doc(k), CORPUS, f"tau2:banking_knowledge/{k}") for k in KEYS},
                  members=GenerationMembers(CORPUS, frozenset(version(k) for k in KEYS)))


def export(reader: Reader, step: int = 1, allow: SourceAllowlist = ALLOW) -> Any:
    return TraceExporter(None, WS, allow, store=reader, env="test").export_step(run_id=RUN, step=step)  # type: ignore[arg-type]


def test_delivered_candidates_and_delivery_order() -> None:
    plain = export(stored(1, ["b", "a"], ["b", "a", "c"]))
    assert [d.stem for d in plain.delivered] == ["b", "a"] and [c.stem for c in plain.candidates] == ["b", "a", "c"]
    assert plain.ranked == ("b", "a", "c") and plain.query_sha256 == sha("q") and plain.generation_current_at_export
    reranked = export(stored(1, ["c", "b"], ["b", "a", "c", "d"], mode="hybrid", rerank_order=["c", "b", "a"]))
    assert reranked.ranked == ("c", "b", "a", "d") and reranked.rerank_status == "applied"
    assert [c.stem for c in reranked.candidates] == ["b", "a", "c", "d"]  # the bounded fused pool, not the order


def test_full_policy_candidates_are_the_delivered_documents_and_there_is_no_ranking() -> None:
    record = export(stored(1, ["a", "b", "c"], [], mode="full_policy"))
    assert [c.stem for c in record.candidates] == ["a", "b", "c"] and record.ranked == ()


def test_a_historical_generation_stays_exportable() -> None:
    reader = stored(1, ["a"], ["a"])
    reader.current = UUID(int=99)
    assert export(reader).generation_current_at_export is False


@pytest.mark.parametrize("break_it", ["unmapped", "foreign_corpus", "unlisted", "uri_shape", "source_mismatch",
                                      "generation_corpus", "generation_missing", "version_member", "no_trace",
                                      "tampered_payload"])
def test_every_unproven_relationship_refuses(break_it: str) -> None:
    reader = stored(1, ["a", "b"], ["a", "b", "c"])
    allow = ALLOW
    if break_it == "unmapped":
        del reader.sources[doc("c")]
    elif break_it == "foreign_corpus":
        reader.sources[doc("b")] = replace(reader.sources[doc("b")], corpus_key="other")
    elif break_it == "unlisted":
        allow = replace(ALLOW, keys=frozenset({"a", "b"}))
    elif break_it == "uri_shape":
        reader.sources[doc("c")] = replace(reader.sources[doc("c")], source_uri="https://example.invalid/c")
    elif break_it == "source_mismatch":
        reader.sources[doc("a")] = replace(reader.sources[doc("a")], source_uri="tau2:banking_knowledge/d")
    elif break_it == "generation_corpus":
        reader.members = GenerationMembers("other", reader.members.versions)  # type: ignore[union-attr]
    elif break_it == "generation_missing":
        reader.members = None
    elif break_it == "version_member":
        reader.members = GenerationMembers(CORPUS, frozenset({version("a")}))
    elif break_it == "no_trace":
        reader.steps.clear()
    else:
        (record, spans), = reader.steps.values()
        assert record.trace is not None
        tampered = record.trace.candidates.replace('"evidence_tokens":10', '"evidence_tokens":11')
        reader.steps = {trace_id_for(WS, RUN, 1): (replace(record, trace=replace(record.trace, candidates=tampered)),
                                                    spans)}
    with pytest.raises(ExportError) as raised:
        export(reader, allow=allow)
    expected = {"unmapped": "document_not_visible", "foreign_corpus": "document_not_in_corpus",
                "unlisted": "document_not_in_corpus", "uri_shape": "document_not_in_corpus",
                "source_mismatch": "source_mismatch", "generation_corpus": "generation_not_in_corpus",
                "generation_missing": "generation_not_in_corpus", "version_member": "version_not_in_generation",
                "no_trace": "trace_not_found", "tampered_payload": "trace_integrity"}[break_it]
    assert raised.value.code == expected


def test_the_reader_seam_is_test_only_and_workspace_bound() -> None:
    with pytest.raises(UnsafeTestHook):
        TraceExporter(None, WS, ALLOW, store=Reader(test_only=False), env="test")  # type: ignore[arg-type]
    with pytest.raises(UnsafeTestHook):
        TraceExporter(None, WS, ALLOW, store=Reader(), env="production")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="another workspace"):
        TraceExporter(None, UUID(int=1), ALLOW, store=Reader(), env="test")  # type: ignore[arg-type]


def test_the_allowlist_comes_from_a_digest_verified_ingest_manifest(tmp_path: Any) -> None:
    raw, digest = write(tmp_path, [FixtureCorpus(CORPUS, "banking_knowledge", "tau2-banking/v1",
                                                 {k: banking(k, k.upper(), f"Text {k}.") for k in KEYS})])
    allow = allowlist_from_manifest(raw, digest, CORPUS)
    assert allow.keys == frozenset(KEYS) and allow.stem("tau2:banking_knowledge/a") == "a"
    assert allow.stem("tau2:banking_knowledge/z") is None and allow.stem("tau2:retail/a") is None
    with pytest.raises(ExportError, match="corpus_not_in_manifest"):
        allowlist_from_manifest(raw, digest, "other-corpus")
    with pytest.raises(Exception):  # noqa: B017 - the T12 loader's own digest refusal
        allowlist_from_manifest(raw, "0" * 64, CORPUS)


def test_internal_trace_contradictions_are_refused_not_repaired() -> None:
    outside = stored(1, ["d"], ["a", "b"])  # a delivered document outside the fused pool
    with pytest.raises(ExportError, match="trace_contradiction"):
        export(outside)
    stray_rerank = stored(1, ["a"], ["a", "b"], mode="hybrid", rerank_order=["c", "a"])
    with pytest.raises(ExportError, match="trace_contradiction"):
        export(stray_rerank)
