"""Retrieval step contracts (T13): query, scope, configuration, result, refusal and the typed trace records.

One step retrieves from exactly one corpus's current generation, in one of four modes:

- `full_policy`: every chunk of the (retail-only) corpus, within the same evidence budget, or a refusal;
- `lexical`: PostgreSQL full-text search (`websearch_to_tsquery`, `ts_rank_cd(..., 32)`);
- `dense`: exact pgvector cosine distance;
- `hybrid`: document-level reciprocal-rank fusion of the two (exact fractions).

Scores travel as decimal strings: faithful presentations of the database's computed values, not exact arithmetic.
Only the RRF fractions are exact. There are no floats and no free-form dictionaries anywhere in these contracts.

A result never establishes current-policy validity, source support or authorization: those constant fields say so.
The caller must already have authorized the run, case and corpus.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.scalars import SafeDetail, Sha256Hex, Slug


RetrievalMode = Literal["full_policy", "lexical", "dense", "hybrid"]
DensePolicy = Literal["lexical_fallback", "refuse"]
LexicalStatus = Literal["ok", "empty_query", "not_used"]
DenseStatus = Literal["ok", "unavailable", "not_used"]
DenseUnavailable = Literal["budget", "unresolved", "vectors_invalid", "job_unsettled", "missing_vector"]
RefusalCode = Literal[
    "query_empty", "query_too_long", "query_too_many_tokens", "query_invalid_text", "scope_invalid",
    "config_invalid", "config_trace_too_large", "run_not_active", "corpus_not_found", "corpus_not_active",
    "step_conflict", "step_in_progress", "full_policy_not_supported", "full_policy_too_many_chunks",
    "full_policy_exceeds_budget", "evidence_uncountable", "deadline_invalid", "deadline_passed",
    "embedding_unavailable", "embedding_integrity", "query_vector_invalid", "trace_unavailable",
    "replay_unsupported", "replay_integrity",
]
MAX_QUERY_CODE_POINTS = 2000
MAX_ALLOWLIST = 32
MAX_EVIDENCE_ITEMS = 16


def _query_text(value: str) -> str:
    if not value.strip():
        raise ValueError("a query is not only whitespace")
    if any(ord(c) < 32 and c not in "\t\n\r" for c in value) or "\x7f" in value:
        raise ValueError("a query has no control characters other than tab and line breaks")
    return value


QueryText = Annotated[str, StringConstraints(min_length=1, max_length=MAX_QUERY_CODE_POINTS),
                      AfterValidator(_query_text)]
SourceUri = Annotated[str, StringConstraints(min_length=1, max_length=2000, pattern=r"^[^\x00-\x1f\x7f]+$")]
_DECIMAL = r"^-?(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,20})?(?:e-?[0-9]{1,3})?$"
DecimalText = Annotated[str, StringConstraints(pattern=_DECIMAL, max_length=40)]
FractionText = Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]{0,40}/[1-9][0-9]{0,60}$", max_length=103)]
Rank = Annotated[int, Field(ge=1, le=1000)]
Step = Annotated[int, Field(ge=0, le=9999)]


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


class RetrievalConfig(WireModel):
    """Versioned, caller-supplied configuration. Every field is in `sha256()` and therefore in the step's request
    fingerprint and trace. `full_policy_max_chunks` is the explicit baseline exception to `max_chunks`; both modes
    share `max_evidence_tokens` (the whole formatted, concatenated evidence string counted with cl100k)."""

    v: Literal["policyops.retrieval-config/v2"] = "policyops.retrieval-config/v2"
    mode: RetrievalMode
    branch_documents: Annotated[int, Field(ge=1, le=50)] = 20
    chunks_per_document: Annotated[int, Field(ge=1, le=3)] = 2
    rrf_k: Annotated[int, Field(ge=1, le=1000)] = 60
    max_chunks: Annotated[int, Field(ge=1, le=MAX_EVIDENCE_ITEMS)] = 6
    max_evidence_tokens: Annotated[int, Field(ge=1, le=16000)] = 4096
    full_policy_max_chunks: Annotated[int, Field(ge=1, le=MAX_EVIDENCE_ITEMS)] = 16
    max_admission_attempts: Annotated[int, Field(ge=1, le=256)] = 64
    dense_policy: DensePolicy = "lexical_fallback"
    fts_config: Literal["english"] = "english"
    fts_rank: Literal["ts_rank_cd/32"] = "ts_rank_cd/32"
    evidence_format: Literal["policyops.evidence-format/v1"] = "policyops.evidence-format/v1"
    embedding_model: Literal["text-embedding-3-small"] = "text-embedding-3-small"
    embedding_dimensions: Literal[1536] = 1536

    def sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class RetrievalScope(WireModel):
    """One corpus, optionally restricted to an allowlist of stable source identities (sorted, unique)."""

    corpus_key: Slug
    document_allowlist: Annotated[tuple[SourceUri, ...], Field(max_length=MAX_ALLOWLIST)] = ()

    @model_validator(mode="after")
    def _canonical(self) -> Self:
        if list(self.document_allowlist) != sorted(set(self.document_allowlist)):
            raise ValueError("the allowlist is sorted and unique")
        return self

    def sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class RetrievalQuery(WireModel):
    """One retrieval step: `(run_id, step)` is the caller-owned stable step identity."""

    text: QueryText
    run_id: UUID
    step: Step
    scope: RetrievalScope
    config: RetrievalConfig

    def query_sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    def request_sha256(self) -> str:
        return canonical_sha256({"v": "policyops.retrieval-request/v1", "query_sha256": self.query_sha256(),
                                 "scope_sha256": self.scope.sha256(), "config_sha256": self.config.sha256()})


class BranchDocument(WireModel):
    document_id: UUID
    rank: Rank
    score: DecimalText
    chunk_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=3)]


class FusedDocument(WireModel):
    document_id: UUID
    rank: Rank
    rrf: FractionText
    lexical_rank: Rank | None = None
    dense_rank: Rank | None = None


class DeliveredChunk(WireModel):
    """One delivered evidence block as recorded in the trace (immutable identities and spans only)."""

    evidence_number: Annotated[int, Field(ge=1, le=MAX_EVIDENCE_ITEMS)]
    chunk_id: UUID
    document_id: UUID
    document_version_id: UUID
    version_number: Annotated[int, Field(ge=1, le=2**53)]
    start: Annotated[int, Field(ge=0, le=2**31 - 1)]
    end: Annotated[int, Field(ge=1, le=2**31 - 1)]
    heading: Annotated[str, StringConstraints(max_length=500)]  # retired chunks are not readable later
    text_sha256: Sha256Hex


class Exclusions(WireModel):
    dense_nan_distance: Annotated[int, Field(ge=0, le=10_000)] = 0
    text_oversized: Annotated[int, Field(ge=0, le=10_000)] = 0
    count_refused: Annotated[int, Field(ge=0, le=256)] = 0


class TraceCandidates(WireModel):
    """The typed `retrieval_traces.candidates` record. `payload_sha256` covers everything here except itself."""

    v: Literal["policyops.retrieval-trace/v1"] = "policyops.retrieval-trace/v1"
    request_sha256: Sha256Hex
    generation_id: UUID
    mode: RetrievalMode
    lexical_status: LexicalStatus
    dense_status: DenseStatus
    dense_unavailable: DenseUnavailable | None = None
    lexical: Annotated[tuple[BranchDocument, ...], Field(max_length=50)] = ()
    dense: Annotated[tuple[BranchDocument, ...], Field(max_length=50)] = ()
    fused: Annotated[tuple[FusedDocument, ...], Field(max_length=100)] = ()
    delivered: Annotated[tuple[DeliveredChunk, ...], Field(max_length=MAX_EVIDENCE_ITEMS)] = ()
    evidence_tokens: Annotated[int, Field(ge=0, le=16000)]
    evidence_text_sha256: Sha256Hex
    admission_attempts: Annotated[int, Field(ge=0, le=256)] = 0
    exclusions: Exclusions = Exclusions()
    payload_sha256: Sha256Hex

    def computed_payload_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json", exclude={"payload_sha256"}))


class TraceScope(WireModel):
    """The typed `retrieval_traces.authorized_scope` record: what the step was bound to (no query text)."""

    v: Literal["policyops.retrieval-scope/v1"] = "policyops.retrieval-scope/v1"
    corpus_key: Slug
    step: Step
    allowlist_sha256: Sha256Hex
    document_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_ALLOWLIST)] = ()
    config_sha256: Sha256Hex
    query_sha256: Sha256Hex
    embedding_job_id: UUID | None = None


class EvidenceChunk(WireModel):
    evidence_id: Annotated[str, StringConstraints(pattern=r"^E(?:[1-9]|1[0-6])$")]
    chunk_id: UUID
    document_id: UUID
    document_version_id: UUID
    source_uri: SourceUri
    version_number: Annotated[int, Field(ge=1, le=2**53)]
    heading: Annotated[str, StringConstraints(max_length=500)]
    start: Annotated[int, Field(ge=0, le=2**31 - 1)]
    end: Annotated[int, Field(ge=1, le=2**31 - 1)]
    text: Annotated[str, StringConstraints(min_length=1, max_length=20000)]


class RetrievalResult(WireModel):
    trace_id: UUID
    run_id: UUID
    step: Step
    generation_id: UUID
    generation_current: bool
    replayed: bool
    mode: RetrievalMode
    lexical_status: LexicalStatus
    dense_status: DenseStatus
    dense_unavailable: DenseUnavailable | None = None
    lexical: Annotated[tuple[BranchDocument, ...], Field(max_length=50)] = ()
    dense: Annotated[tuple[BranchDocument, ...], Field(max_length=50)] = ()
    fused: Annotated[tuple[FusedDocument, ...], Field(max_length=100)] = ()
    evidence: Annotated[tuple[EvidenceChunk, ...], Field(max_length=MAX_EVIDENCE_ITEMS)] = ()
    evidence_text: Annotated[str, StringConstraints(max_length=400_000)]
    evidence_tokens: Annotated[int, Field(ge=0, le=16000)]
    config_sha256: Sha256Hex
    request_sha256: Sha256Hex
    payload_sha256: Sha256Hex
    provider_requests: Annotated[int, Field(ge=0, le=1)] = 0
    current_policy_validated: Literal[False] = False
    claim_support_validated: Literal[False] = False
    caller_authorized_scope: Literal["required"] = "required"


class RetrievalRefused(WireModel):
    code: RefusalCode
    detail: SafeDetail | None = None
