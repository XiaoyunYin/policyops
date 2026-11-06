"""Deterministic evidence validation (T14): a model's `GroundedAnswer` against this run's own stored step traces.

The caller (T21) must already have authorized the user or actor for the run, case and corpus, and chooses
`authorized_steps`: the steps whose delivered evidence the answer may cite. This validator rechecks the workspace (RLS
and its construction binding), run, steps, corpus and every stored identity. It is not user authorization, consent or
approval.

Per distinct authorized cited step, one `step_record` read and one `spans` read (all delivered entries), each followed
by a deadline checkpoint, then the shared C2 trace checks (`verify_record`/`verify_evidence`) without the query and the
query-less binding checks below. **Not reconstructable without the original query**, and therefore not claimed: that
the query text hashes to `query_sha256`, that the scope's allowlist matches `scope_sha256` and that the configuration's
fields match `config_sha256`. The validator proves the internal consistency of the stored records, not the original
request's content; it deliberately does not read the embedding foundation's stored job inputs.

Quotes match exactly, in code points, with no whitespace, case or Unicode normalization. Without offsets the quote must
occur exactly once, counting **overlapping** occurrences (`text.find(q)`, then `text.find(q, i + 1)`): bounded to two
searches per citation over at most 20,000 code points. Mixed generations among otherwise verified citations reject
all of them. `generation_current` is one pointer observation at validation time. A model's `policy_dependent` label is
not verifiable (a mislabelled policy claim escapes abstention); `claim_support_validated` is always False.

SQL waits are not interrupted by the deadline; the checkpoints decide what is returned once control comes back.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
import hashlib
import math
import re
import time
from typing import Literal, Protocol
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import Engine

from policyops.persistence.retrieval import IntentRecord, RetrievalStore, Span, StepRecord, StoredTrace
from policyops.retrieval.rank import ChunkRow
from policyops.retrieval.search import TraceProblem, span_entries, trace_id_for, verify_evidence, verify_record
from policyops.runtime.clock import UnsafeTestHook
from policyops_contracts.grounding import (
    AssertionCheck,
    CitationBundle,
    CitationCheck,
    CitationClaim,
    CitationStatus,
    GroundedAnswer,
    GroundingRefused,
    ValidatedAnswer,
)
from policyops_contracts.retrieval import DeliveredChunk, TraceCandidates, TraceScope, canonical_sha256


_SLUG = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
MAX_AUTHORIZED_STEPS = 16


def deadline_problem(deadline: object, clock: Callable[[], float]) -> Literal["deadline_invalid",
                                                                              "deadline_passed"] | None:
    if isinstance(deadline, bool) or not isinstance(deadline, int | float) or not math.isfinite(deadline):
        return "deadline_invalid"
    return "deadline_passed" if clock() >= deadline else None


def context_problem(run_id: object, authorized_steps: object, corpus_key: object) -> str | None:
    """The caller's separate context (never taken from the answer or a bundle)."""
    if not isinstance(run_id, UUID):
        return "run_id"
    if not isinstance(corpus_key, str) or not _SLUG.match(corpus_key):
        return "corpus_key"
    if not isinstance(authorized_steps, tuple | list | frozenset | set) or len(authorized_steps) > MAX_AUTHORIZED_STEPS:
        return "authorized_steps"
    steps = list(authorized_steps)
    # Scalar types first: an unhashable or non-integer element must refuse, never raise while deduplicating.
    if not all(isinstance(s, int) and not isinstance(s, bool) and 0 <= s <= 9999 for s in steps):
        return "authorized_steps"
    if len(set(steps)) != len(steps):
        return "authorized_steps"
    return None


# -- shared step checks (the validator and the citation recorder) --------------------------------------------------

StepFailureStatus = Literal["trace_not_found", "trace_integrity", "corpus_mismatch"]


@dataclass(frozen=True)
class StepFailure:
    status: StepFailureStatus
    detail: str


@dataclass(frozen=True)
class CheckedStep:
    step: int
    trace_id: UUID
    stored: StoredTrace
    intent: IntentRecord
    candidates: TraceCandidates
    scope: TraceScope


@dataclass(frozen=True)
class StepEvidence:
    checked: CheckedStep
    chunks: tuple[ChunkRow, ...]
    spans: tuple[Span, ...]

    def entry(self, evidence_id: str) -> tuple[DeliveredChunk, ChunkRow, Span] | None:
        number = int(evidence_id[1:])
        if not 1 <= number <= len(self.chunks):
            return None
        return self.checked.candidates.delivered[number - 1], self.chunks[number - 1], self.spans[number - 1]


def check_step(record: StepRecord, *, workspace_id: UUID, run_id: UUID, step: int,
               corpus_key: str) -> CheckedStep | StepFailure:
    """Query-less verification of one step's stored records (pure): the C2 record checks plus the intent binding."""
    trace_id = trace_id_for(workspace_id, run_id, step)
    stored, intent = record.trace, record.intent
    if stored is None or intent is None:
        return StepFailure("trace_not_found", "no trace or no intent for this run's step")
    checked = verify_record(stored, run_id=run_id)
    if isinstance(checked, TraceProblem):
        return StepFailure("trace_integrity", checked.detail)
    candidates, scope = checked.candidates, checked.scope
    if (intent.trace_id, intent.run_id, intent.step) != (trace_id, run_id, step) or scope.step != step:
        return StepFailure("trace_integrity", "the intent or scope is bound to another step")
    if not scope.query_sha256 == intent.query_sha256 == stored.query_sha256:
        return StepFailure("trace_integrity", "query digest")
    if scope.config_sha256 != intent.config_sha256:
        return StepFailure("trace_integrity", "configuration digest")
    recomputed = canonical_sha256({"v": "policyops.retrieval-request/v1", "query_sha256": intent.query_sha256,
                                   "scope_sha256": intent.scope_sha256, "config_sha256": intent.config_sha256})
    if intent.request_sha256 != recomputed:
        return StepFailure("trace_integrity", "request digest")
    if scope.corpus_key != corpus_key:
        return StepFailure("corpus_mismatch", "the step retrieved from another corpus")
    return CheckedStep(step, trace_id, stored, intent, candidates, scope)


def check_step_evidence(checked: CheckedStep, spans: Sequence[Span | None]) -> StepEvidence | StepFailure:
    evidence = verify_evidence(checked.candidates, spans)
    if isinstance(evidence, TraceProblem):
        return StepFailure("trace_integrity", evidence.detail)
    chunks, _ = evidence
    return StepEvidence(checked, tuple(chunks), tuple(s for s in spans if s is not None))


QuoteStatus = Literal["matched", "span_invalid", "quote_mismatch", "quote_not_found", "quote_ambiguous"]


def match_quote(text: str, quote: str, start: int | None, end: int | None) -> tuple[QuoteStatus, int]:
    """Exact code-point match within one chunk's text; returns the chunk-relative start when matched."""
    if start is not None and end is not None:
        if not 0 <= start < end <= len(text):
            return "span_invalid", 0
        return ("matched", start) if text[start:end] == quote else ("quote_mismatch", 0)
    first = text.find(quote)
    if first < 0:
        return "quote_not_found", 0
    if text.find(quote, first + 1) >= 0:  # overlapping occurrences count
        return "quote_ambiguous", 0
    return "matched", first


# -- the validator -------------------------------------------------------------------------------------------------

class _Expired(Exception):
    pass


@dataclass
class _Citation:
    assertion: int
    citation: int
    step: int
    evidence_id: str
    quote: str
    start: int | None
    end: int | None
    status: CitationStatus = "verified"
    claim: CitationClaim | None = None


class StepReader(Protocol):
    workspace_id: UUID

    def step_record(self, trace_id: UUID) -> StepRecord: ...

    def spans(self, entries: Sequence[tuple[UUID, int, int]]) -> list[Span | None]: ...

    def pointer(self, corpus_key: str) -> UUID | None: ...


class EvidenceValidator:
    """Read-only. Constructed for one workspace; the app runtime role is verified as by the C2 stores. A `store`
    replacement is accepted only from a `test_only` reader of the same workspace with `env="test"`."""

    def __init__(self, engine: Engine, workspace_id: UUID, *, clock: Callable[[], float] = time.monotonic,
                 store: StepReader | None = None, env: str | None = None) -> None:
        if store is not None:
            if getattr(store, "test_only", False) is not True or env != "test":
                raise UnsafeTestHook("a replacement step reader must be test-only in the test environment")
            if store.workspace_id != workspace_id:
                raise ValueError("the step reader belongs to another workspace")
        self.store: StepReader = store if store is not None else RetrievalStore(engine, workspace_id)
        self.workspace_id, self.clock = workspace_id, clock

    def _checkpoint(self, deadline: float) -> None:
        if self.clock() >= deadline:
            raise _Expired

    def validate(self, answer: GroundedAnswer, *, run_id: UUID, authorized_steps: Collection[int], corpus_key: str,
                 deadline: float) -> ValidatedAnswer | GroundingRefused:
        problem = deadline_problem(deadline, self.clock)
        if problem is not None:
            return GroundingRefused(code=problem)
        context = context_problem(run_id, authorized_steps, corpus_key)
        if context is not None:
            return GroundingRefused(code="context_invalid", detail=context)
        try:
            answer = GroundedAnswer.model_validate_json(answer.model_dump_json())  # never trust a constructed DTO
        except (ValidationError, AttributeError):
            return GroundingRefused(code="context_invalid", detail="answer")
        try:
            return self._validate(answer, run_id, frozenset(authorized_steps), corpus_key, float(deadline))
        except _Expired:
            return GroundingRefused(code="deadline_passed")

    def _validate(self, answer: GroundedAnswer, run_id: UUID, authorized: frozenset[int], corpus_key: str,
                  deadline: float) -> ValidatedAnswer:
        if answer.outcome == "abstain":
            self._checkpoint(deadline)
            return ValidatedAnswer(outcome="abstained", abstention=answer.abstention)
        citations = [_Citation(a, c, q.step, q.evidence_id, q.quote, q.start, q.end)
                     for a, assertion in enumerate(answer.assertions) for c, q in enumerate(assertion.citations)]
        steps: dict[int, StepEvidence | StepFailure] = {}
        for cited in citations:
            if cited.step in authorized and cited.step not in steps:
                steps[cited.step] = self._step(run_id, cited.step, corpus_key, deadline)
        seen: dict[int, set[tuple[int, int, int, int]]] = {}  # per assertion (local to this call)
        for cited in citations:
            self._check(cited, steps, seen.setdefault(cited.assertion, set()))
        verified = [c for c in citations if c.status == "verified"]
        generations = {c.claim.generation_id for c in verified if c.claim is not None}
        if len(generations) > 1:  # all-or-none: never a majority pick
            for cited in verified:
                cited.status = "mixed_generation"
            verified = []
        generation = next(iter(generations)) if len(generations) == 1 else None
        current: bool | None = None
        if generation is not None:
            current = self.store.pointer(corpus_key) == generation
            self._checkpoint(deadline)
        checks = self._assertions(answer, citations)
        outcome = self._outcome(checks, current)
        bundle = None
        if outcome == "grounded":
            bundle = CitationBundle(run_id=run_id, corpus_key=corpus_key,
                                    claims=tuple(c.claim for c in verified if c.claim is not None))
        result = ValidatedAnswer(
            outcome=outcome, assertions=checks, citations=tuple(self._report(c) for c in citations),
            generation_id=generation, generation_current=current, bundle=bundle)
        self._checkpoint(deadline)  # never a result after the deadline (nothing was written)
        return result

    def _step(self, run_id: UUID, step: int, corpus_key: str, deadline: float) -> StepEvidence | StepFailure:
        record = self.store.step_record(trace_id_for(self.workspace_id, run_id, step))
        self._checkpoint(deadline)
        checked = check_step(record, workspace_id=self.workspace_id, run_id=run_id, step=step, corpus_key=corpus_key)
        if isinstance(checked, StepFailure):
            return checked
        spans = self.store.spans(span_entries(checked.candidates))
        self._checkpoint(deadline)
        return check_step_evidence(checked, spans)

    @staticmethod
    def _check(cited: _Citation, steps: dict[int, StepEvidence | StepFailure],
               seen: set[tuple[int, int, int, int]]) -> None:
        if cited.step not in steps:
            cited.status = "step_not_authorized"
            return
        evidence = steps[cited.step]
        if isinstance(evidence, StepFailure):
            cited.status = evidence.status
            return
        found = evidence.entry(cited.evidence_id)
        if found is None:
            cited.status = "unknown_evidence"
            return
        entry, chunk, span = found
        status, start = match_quote(chunk.text, cited.quote, cited.start, cited.end)
        if status != "matched":
            cited.status = status
            return
        span_start = entry.start + start
        span_end = span_start + len(cited.quote)
        key = (cited.step, int(cited.evidence_id[1:]), span_start, span_end)
        if key in seen:
            cited.status = "duplicate"
            return
        seen.add(key)
        checked = evidence.checked
        if span.version_sha256 is None:  # pragma: no cover - always read by `read_spans`
            cited.status = "trace_integrity"
            return
        cited.claim = CitationClaim(
            step=cited.step, evidence_id=cited.evidence_id, trace_id=checked.trace_id,
            trace_payload_sha256=checked.candidates.payload_sha256, request_sha256=checked.intent.request_sha256,
            generation_id=checked.candidates.generation_id, chunk_id=entry.chunk_id, document_id=entry.document_id,
            document_version_id=entry.document_version_id, version_sha256=span.version_sha256,
            chunk_text_sha256=entry.text_sha256, span_start=span_start, span_end=span_end, quote=cited.quote,
            quote_sha256=hashlib.sha256(cited.quote.encode("utf-8")).hexdigest())

    @staticmethod
    def _assertions(answer: GroundedAnswer, citations: Sequence[_Citation]) -> tuple[AssertionCheck, ...]:
        checks = []
        for index, assertion in enumerate(answer.assertions):
            verified = sum(1 for c in citations if c.assertion == index and c.status == "verified")
            status: Literal["cited_identity_verified", "insufficient_evidence", "not_policy_dependent"]
            if not assertion.policy_dependent:
                status = "not_policy_dependent"
            else:
                status = "cited_identity_verified" if verified else "insufficient_evidence"
            checks.append(AssertionCheck(assertion=index, policy_dependent=assertion.policy_dependent, status=status,
                                         verified_citations=verified))
        return tuple(checks)

    @staticmethod
    def _outcome(checks: Sequence[AssertionCheck], current: bool | None
                 ) -> Literal["grounded", "insufficient_evidence", "stale_evidence", "no_policy_assertions"]:
        if any(c.status == "insufficient_evidence" for c in checks):
            return "insufficient_evidence"
        if any(c.status == "cited_identity_verified" for c in checks):
            # Re-retrieve with a NEW step: a same-step replay is historical and cannot refresh.
            return "grounded" if current else "stale_evidence"
        return "no_policy_assertions"

    @staticmethod
    def _report(cited: _Citation) -> CitationCheck:
        claim = cited.claim  # identities of a verified (or mixed-generation) citation; never of a failed match
        return CitationCheck(
            assertion=cited.assertion, citation=cited.citation, step=cited.step, evidence_id=cited.evidence_id,
            status=cited.status, trace_id=None if claim is None else claim.trace_id,
            chunk_id=None if claim is None else claim.chunk_id,
            document_id=None if claim is None else claim.document_id,
            document_version_id=None if claim is None else claim.document_version_id,
            generation_id=None if claim is None else claim.generation_id,
            span_start=None if claim is None else claim.span_start, span_end=None if claim is None else claim.span_end)
