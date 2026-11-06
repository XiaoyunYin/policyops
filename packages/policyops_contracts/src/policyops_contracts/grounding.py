"""Grounded answers, deterministic citation checks and citation recording (T14).

**Model-facing** (`GroundedAnswer`): an answer of cited assertions, or an abstention. Every property is required and
optional values are nullable, so the schema stays inside the strict-provider subset; a structured answer is still only
a proposal for the deterministic validator.

**Server-produced** (`ValidatedAnswer`, `CitationClaim`, `CitationBundle`, `RecordOutcome`, `ReconcileOutcome`): what
the validator and the recorder established. Three claims are kept apart and never conflated:

- historical identity (`verified`): the run's own digest-verified trace delivered this chunk, the version body digest
  holds and the quote is exactly those code points;
- current-ready (`generation_current`, the recorder's lock and guard): an observation at validation time, or at commit
  only; a later activation can always follow;
- claim support: constant False. Nothing here checks entailment, and a model's `policy_dependent` label is not
  verifiable.

A claim carries no status. It is an assertion the recorder rechecks field by field; nothing in it is trusted. None of
these records is user authorization, consent or approval: the caller authorizes the run, case, corpus and steps.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.retrieval import Step
from policyops_contracts.scalars import SafeDetail, Sha256Hex, Slug


MAX_ASSERTIONS = 16
MAX_CITATIONS_PER_ASSERTION = 4
MAX_CLAIMS = MAX_ASSERTIONS * MAX_CITATIONS_PER_ASSERTION
MAX_QUOTE_CODE_POINTS = 1000
MAX_CHUNK_CODE_POINTS = 20_000


def _plain_text(value: str) -> str:
    if any(ord(c) < 32 and c not in "\t\n\r" for c in value) or "\x7f" in value:
        raise ValueError("no control characters other than tab and line breaks")
    return value


EvidenceRef = Annotated[str, StringConstraints(pattern=r"^E(?:[1-9]|1[0-6])$")]
QuoteText = Annotated[str, StringConstraints(min_length=1, max_length=MAX_QUOTE_CODE_POINTS),
                      AfterValidator(_plain_text)]
AssertionText = Annotated[str, StringConstraints(min_length=1, max_length=2000), AfterValidator(_plain_text)]
ChunkOffset = Annotated[int, Field(ge=0, le=MAX_CHUNK_CODE_POINTS)]
BodyOffset = Annotated[int, Field(ge=0, le=2**31 - 1)]
AssertionIndex = Annotated[int, Field(ge=0, lt=MAX_ASSERTIONS)]
CitationIndex = Annotated[int, Field(ge=0, lt=MAX_CITATIONS_PER_ASSERTION)]
ClaimIndex = Annotated[int, Field(ge=0, lt=MAX_CLAIMS)]
Count = Annotated[int, Field(ge=0, le=MAX_CLAIMS)]


# -- model-facing --------------------------------------------------------------------------------------------------

class CitedQuote(WireModel):
    """A verbatim quote from one delivered evidence chunk of one step. Offsets, when given, are code points within
    that chunk's text, both or neither, with `end - start == len(quote)`."""

    step: Step
    evidence_id: EvidenceRef
    quote: QuoteText
    start: ChunkOffset | None
    end: ChunkOffset | None

    @model_validator(mode="after")
    def _offsets(self) -> Self:
        if (self.start is None) != (self.end is None):
            raise ValueError("offsets are both given or both omitted")
        if self.start is not None and self.end is not None and self.end - self.start != len(self.quote):
            raise ValueError("the offsets span exactly the quote")
        return self


class Assertion(WireModel):
    text: AssertionText
    policy_dependent: bool  # the model's own label: not verifiable deterministically
    citations: Annotated[tuple[CitedQuote, ...], Field(max_length=MAX_CITATIONS_PER_ASSERTION)]


class Abstention(WireModel):
    reason: Literal["insufficient_evidence", "contradictory_evidence", "outside_policy_scope"]
    detail: SafeDetail | None


class GroundedAnswer(WireModel):
    v: Literal["policyops.grounded-answer/v1"]
    outcome: Literal["answer", "abstain"]
    assertions: Annotated[tuple[Assertion, ...], Field(max_length=MAX_ASSERTIONS)]
    abstention: Abstention | None

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if self.outcome == "answer" and (not self.assertions or self.abstention is not None):
            raise ValueError("an answer has 1-16 assertions and no abstention")
        if self.outcome == "abstain" and (self.assertions or self.abstention is None):
            raise ValueError("an abstention has a reason and no assertions")
        return self


# -- validator output (server-produced; never an input to anything that writes) -------------------------------------

CitationStatus = Literal[
    "verified",             # historical identity verified (not current policy, not entailment, not authorization)
    "step_not_authorized",  # outside the caller's authorized steps: never read
    "trace_not_found",      # no trace, or no intent, for this run's step
    "trace_integrity",      # the stored trace or its evidence failed a consistency check
    "corpus_mismatch",      # the step retrieved from another corpus
    "unknown_evidence",     # no delivered evidence with that E-number
    "span_invalid", "quote_mismatch", "quote_not_found", "quote_ambiguous",
    "duplicate",            # the same step, evidence and span earlier in the same assertion
    "mixed_generation",     # verified citations of one answer from more than one generation: all rejected
]


class CitationCheck(WireModel):
    """One citation's deterministic result. Spans are version-body code points (the `app.citations` coordinates)."""

    assertion: AssertionIndex
    citation: CitationIndex
    step: Step
    evidence_id: EvidenceRef
    status: CitationStatus
    trace_id: UUID | None = None
    chunk_id: UUID | None = None
    document_id: UUID | None = None
    document_version_id: UUID | None = None
    generation_id: UUID | None = None
    span_start: BodyOffset | None = None
    span_end: BodyOffset | None = None


class AssertionCheck(WireModel):
    assertion: AssertionIndex
    policy_dependent: bool
    status: Literal["cited_identity_verified", "insufficient_evidence", "not_policy_dependent"]
    verified_citations: Annotated[int, Field(ge=0, le=MAX_CITATIONS_PER_ASSERTION)]


class CitationClaim(WireModel):
    """What one verified citation asserts. Not proof and not authorization: the recorder rechecks every field
    against the stored trace, intent and immutable version body on its own connection."""

    v: Literal["policyops.citation-claim/v1"] = "policyops.citation-claim/v1"
    step: Step
    evidence_id: EvidenceRef
    trace_id: UUID
    trace_payload_sha256: Sha256Hex
    request_sha256: Sha256Hex
    generation_id: UUID
    chunk_id: UUID
    document_id: UUID
    document_version_id: UUID
    version_sha256: Sha256Hex
    chunk_text_sha256: Sha256Hex
    span_start: BodyOffset
    span_end: BodyOffset
    quote: QuoteText
    quote_sha256: Sha256Hex


class CitationBundle(WireModel):
    v: Literal["policyops.citation-bundle/v1"] = "policyops.citation-bundle/v1"
    run_id: UUID
    corpus_key: Slug
    claims: Annotated[tuple[CitationClaim, ...], Field(min_length=1, max_length=MAX_CLAIMS)]


class ValidatedAnswer(WireModel):
    """The validator's result. `bundle` is set only for a `grounded` outcome and holds exactly its verified
    citations; every failed check stays visible in `citations` and never enters a bundle."""

    v: Literal["policyops.validated-answer/v1"] = "policyops.validated-answer/v1"
    outcome: Literal["grounded", "insufficient_evidence", "stale_evidence", "no_policy_assertions", "abstained"]
    abstention: Abstention | None = None
    assertions: Annotated[tuple[AssertionCheck, ...], Field(max_length=MAX_ASSERTIONS)] = ()
    citations: Annotated[tuple[CitationCheck, ...], Field(max_length=MAX_CLAIMS)] = ()
    generation_id: UUID | None = None
    generation_current: bool | None = None  # an observation at validation time, not a guarantee
    bundle: CitationBundle | None = None
    claim_support_validated: Literal[False] = False
    caller_authorized_scope: Literal["required"] = "required"
    identity_basis: Literal["stored_trace_and_version_body"] = "stored_trace_and_version_body"

    @model_validator(mode="after")
    def _bundle_only_when_grounded(self) -> Self:
        if (self.bundle is not None) != (self.outcome == "grounded"):
            raise ValueError("a bundle exists exactly for a grounded outcome")
        return self


class GroundingRefused(WireModel):
    code: Literal["deadline_invalid", "deadline_passed", "context_invalid"]
    detail: SafeDetail | None = None


# -- recording -----------------------------------------------------------------------------------------------------

RecordCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}(?::[a-z][a-z0-9_]{0,63})?$")]


class RecordOutcome(WireModel):
    """`recorded`: COMMIT acknowledged and every distinct ID observed equal in the same transaction. `refused`:
    nothing new written (`existing_ids` are equal rows that were already present). `record_ambiguous`: COMMIT raised
    with an unknown outcome; reconcile or retry with the same bundle. `deadline_passed` with `committed="observed"`:
    COMMIT acknowledged after the deadline, the rows are kept."""

    v: Literal["policyops.citation-record/v1"] = "policyops.citation-record/v1"
    status: Literal["recorded", "refused", "record_ambiguous", "deadline_passed"]
    code: RecordCode | None = None
    failing_claim: ClaimIndex | None = None
    committed: Literal["observed", "none", "unknown"]
    claims: Count
    distinct: Count
    inserted: Count = 0
    existing: Count = 0
    missing: Count = 0
    claim_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CLAIMS)] = ()
    distinct_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CLAIMS)] = ()
    existing_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CLAIMS)] = ()

    @model_validator(mode="after")
    def _counters(self) -> Self:
        if self.status == "recorded" and (self.inserted + self.existing != self.distinct or self.missing):
            raise ValueError("a recorded outcome observed every distinct ID")
        return self


class ReconcileOutcome(WireModel):
    """Read-only, historical reconciliation (never a write authorization). `not_observed_yet` and `missing_ids` are
    never proof of absence: an ambiguous COMMIT may still be completing. There is no definitive "not recorded"."""

    v: Literal["policyops.citation-reconcile/v1"] = "policyops.citation-reconcile/v1"
    status: Literal["recorded", "incomplete", "not_observed_yet", "citation_integrity", "citation_id_conflict",
                    "refused", "deadline_passed"]
    code: RecordCode | None = None
    failing_claim: ClaimIndex | None = None
    claim_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CLAIMS)] = ()
    distinct_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CLAIMS)] = ()
    matched_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CLAIMS)] = ()
    missing_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CLAIMS)] = ()
    generation_current: bool | None = None
    absence_proven: Literal[False] = False
