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

T14 adds an optional, off-by-default rerank stage (`RetrievalConfig.rerank`), its trace record
(`TraceCandidates.rerank`), a historical summary on the result and this invocation's own provider work
(`InvocationWork`). Every addition is omitted from serialization when it is None, so a configuration, request or trace
without reranking keeps exactly its T13 bytes and digests, and stored T13 traces parse and verify unchanged.
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
    "replay_unsupported", "replay_integrity", "rerank_unavailable", "rerank_integrity",
]
RerankPolicy = Literal["baseline_fallback", "refuse"]
RerankStatus = Literal[
    "applied",                 # a domain-valid ranking reordered the window
    "skipped_few_candidates",  # fewer than 2 window documents: no call
    "skipped_input_bound",     # the bounded prompt cannot fit: no call
    "skipped_deadline",        # too little time before the reserved margin: no call
    "timeout",                 # the rerank sub-deadline expired while the global deadline was alive
    "budget",                  # the budget refused the reservation or the count: nothing dispatched
    "count_failed",            # the count failed or did not admit the prompt: released, nothing dispatched
    "failed",                  # a provider or transport failure (no retry)
    "refused", "truncated", "invalid_output",  # model outcomes (billed when dispatched)
    "invalid_ranking",         # structured, but not a domain-valid ranking of this window
    "contract_block",          # the provider response broke the contract (billed, scope blocked)
    "prior_attempt",           # this step's rerank attempt already exists: no new key, no new attempt
]
# The registry's chat models (a unit test keeps this equal to them): the configured reranker actor's model.
RerankModel = Literal["gpt-6-luna", "claude-haiku-5-5"]
AttemptFateText = Literal["settled", "unresolved", "released", "replayed", "refused", "not_reserved"]
MAX_RERANK_DOCUMENTS = 20
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


def _is_none(value: object) -> bool:
    return value is None


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


class RerankConfig(WireModel):
    """The optional rerank stage (T14): one bounded structured request ordering the first `documents` fused
    documents. `seconds` is the stage's own sub-deadline length; `max_output_tokens` is the request's output limit
    (at most the reranker actor's maximum, checked before any work)."""

    v: Literal["policyops.rerank-config/v1"] = "policyops.rerank-config/v1"
    documents: Annotated[int, Field(ge=2, le=MAX_RERANK_DOCUMENTS)] = MAX_RERANK_DOCUMENTS
    excerpt_bytes: Annotated[int, Field(ge=64, le=1000)] = 500
    max_output_tokens: Annotated[int, Field(ge=64, le=1024)] = 512
    seconds: Annotated[int, Field(ge=1, le=30)] = 10
    policy: RerankPolicy = "baseline_fallback"
    prompt: Literal["policyops.rerank-prompt/v1"] = "policyops.rerank-prompt/v1"

    def sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class RetrievalConfig(WireModel):
    """Versioned, caller-supplied configuration. Every field is in `sha256()` and therefore in the step's request
    fingerprint and trace. `full_policy_max_chunks` is the explicit baseline exception to `max_chunks`; both modes
    share `max_evidence_tokens` (the whole formatted, concatenated evidence string counted with cl100k).

    `rerank` (T14) is omitted from the serialization, and therefore from `sha256()`, when it is None: every T13
    configuration keeps its digest and request fingerprint."""

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
    rerank: RerankConfig | None = Field(default=None, exclude_if=_is_none)

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


class RerankAttempt(WireModel):
    """A pointer into the ledger (the billing authority): the attempt, its fate and whether its client closed."""

    attempt_id: UUID
    fate: AttemptFateText
    cleanup_confirmed: bool | None = None


class RerankTrace(WireModel):
    """The rerank stage as recorded in the step's trace (historical: identical for every replay of the step). No
    prompt, query or model text is stored: only digests, the bounded reason code and the final window order."""

    v: Literal["policyops.rerank-trace/v1"] = "policyops.rerank-trace/v1"
    status: RerankStatus
    reason: Slug | None = None
    model: RerankModel
    prompt_sha256: Sha256Hex
    request_identity: Sha256Hex
    input_sha256: Sha256Hex | None = None
    max_output_tokens: Annotated[int, Field(ge=64, le=1024)]
    excerpts_truncated: Annotated[int, Field(ge=0, le=MAX_RERANK_DOCUMENTS)] = 0
    window: Annotated[int, Field(ge=0, le=MAX_RERANK_DOCUMENTS)] = 0
    order: Annotated[tuple[UUID, ...], Field(max_length=MAX_RERANK_DOCUMENTS)] = ()
    attempts: Annotated[tuple[RerankAttempt, ...], Field(max_length=1)] = ()


class TraceCandidates(WireModel):
    """The typed `retrieval_traces.candidates` record. `payload_sha256` covers everything here except itself.

    `rerank` (T14) is omitted when None, so a T13 trace keeps its bytes and its payload digest."""

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
    rerank: RerankTrace | None = Field(default=None, exclude_if=_is_none)
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


class RerankSummary(WireModel):
    """The step's rerank outcome as stored in its trace (historical, the same for every replay)."""

    status: RerankStatus
    applied: bool
    reason: Slug | None = None
    model: RerankModel
    order: Annotated[tuple[UUID, ...], Field(max_length=MAX_RERANK_DOCUMENTS)] = ()
    attempts: Annotated[tuple[RerankAttempt, ...], Field(max_length=1)] = ()


class InvocationWork(WireModel):
    """What THIS invocation itself did, never stored in a trace and never replayed. Grants are ledger grants this
    call obtained (not proof that bytes left the process); the ledger stays the billing authority."""

    embedding_requests: Annotated[int, Field(ge=0, le=1)] = 0
    rerank_counts_claimed: Annotated[int, Field(ge=0, le=1)] = 0
    rerank_inferences_dispatched: Annotated[int, Field(ge=0, le=1)] = 0
    cleanup_unconfirmed: bool = False


class RetrievalResult(WireModel):
    """`replayed` means only that the returned trace was stored earlier (by another writer or call); it is never
    evidence that this invocation did no work. `provider_requests` is this invocation's embedding requests;
    `invocation` (present for rerank-configured steps) adds this invocation's rerank grants."""

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
    rerank: RerankSummary | None = Field(default=None, exclude_if=_is_none)
    invocation: InvocationWork | None = Field(default=None, exclude_if=_is_none)

    @model_validator(mode="after")
    def _invocation_matches(self) -> Self:
        if self.invocation is not None and self.invocation.embedding_requests != self.provider_requests:
            raise ValueError("the invocation's embedding requests are the result's provider requests")
        return self


class RetrievalRefused(WireModel):
    """`invocation` (when known) reports what this invocation did before it refused, e.g. a dispatched rerank."""

    code: RefusalCode
    detail: SafeDetail | None = None
    invocation: InvocationWork | None = Field(default=None, exclude_if=_is_none)
