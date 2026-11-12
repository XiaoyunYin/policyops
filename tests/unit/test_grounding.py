"""T14 deterministic evidence validation and recording, offline: the validator against a test-only fake step reader
(synthetic, digest-consistent step records, plus the GENUINE accepted-C5 legacy fixture captured from real
PostgreSQL), exact quote semantics, the shared trace verifier's C2 parity, the citation ID material, the recorder's
pure recheck and its ordering/cleanup against a fake connection. Nothing here proves entailment or authorization."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from psycopg import Error, errors
from pydantic import ValidationError
import pytest
from sqlalchemy.exc import DBAPIError

from policyops.persistence import citations as citations_module
from policyops.persistence.citations import CITATION_NAMESPACE, CitationRecorder, FaultPlan, citation_id, recheck
from policyops.persistence.database import DatabaseUnavailable
from policyops.persistence.retrieval import IntentRecord, Span, StepRecord, StoredTrace
from policyops.providers.schema import check_schema
from policyops.retrieval.grounding import (
    EvidenceValidator,
    StepFailure,
    check_step,
    check_step_evidence,
    match_quote,
)
from policyops.retrieval.rank import ChunkRow, assemble
from policyops.retrieval.search import TraceProblem, trace_id_for, verify_record
from policyops.runtime.clock import UnsafeTestHook
from policyops_contracts.grounding import (
    Abstention,
    Assertion,
    CitationBundle,
    CitationClaim,
    CitedQuote,
    GroundedAnswer,
    GroundingRefused,
    RecordOutcome,
    ValidatedAnswer,
)
from policyops_contracts.retrieval import DeliveredChunk, TraceCandidates, TraceScope, canonical_sha256


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "retrieval" / "legacy-c5-retrieval.json"
WS, RUN = UUID(int=11), UUID(int=12)
GEN_1, GEN_2 = UUID(int=21), UUID(int=22)
CORPUS = "test-banking"


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class Step:
    record: StepRecord
    spans: list[Span | None]


def synthetic(step: int, texts: Sequence[str], *, run: UUID = RUN, generation: UUID = GEN_1, corpus: str = CORPUS,
              prefix: str = "Intro. ") -> Step:
    """A digest-consistent stored step (lexical), one document version per text, each chunk inside its body."""
    query, scope_digest, config = sha(f"q{step}"), sha(f"s{step}"), sha("c")
    request = canonical_sha256({"v": "policyops.retrieval-request/v1", "query_sha256": query,
                                "scope_sha256": scope_digest, "config_sha256": config})
    delivered: list[DeliveredChunk] = []
    spans: list[Span | None] = []
    chunks: list[ChunkRow] = []
    for n, chunk_text in enumerate(texts, start=1):
        document, version = uuid5(NAMESPACE_URL, f"d{generation}{n}"), uuid5(NAMESPACE_URL, f"v{generation}{n}")
        chunk = uuid5(NAMESPACE_URL, f"k{generation}{n}{step}")
        body = prefix + chunk_text + " Outro."
        start, end = len(prefix), len(prefix) + len(chunk_text)
        delivered.append(DeliveredChunk(evidence_number=n, chunk_id=chunk, document_id=document,
                                        document_version_id=version, version_number=1, start=start, end=end,
                                        heading="H", text_sha256=sha(chunk_text)))
        spans.append(Span(version, document, f"u:{n}", 1, chunk_text, True, sha(body)))
        chunks.append(ChunkRow(chunk, document, version, f"u:{n}", 1, "H", start, end, chunk_text))
    candidates = TraceCandidates(request_sha256=request, generation_id=generation, mode="lexical",
                                 lexical_status="ok", dense_status="not_used", delivered=tuple(delivered),
                                 evidence_tokens=10, evidence_text_sha256=sha(assemble(chunks)),
                                 payload_sha256="0" * 64)
    candidates = candidates.model_copy(update={"payload_sha256": candidates.computed_payload_sha256()})
    scope = TraceScope(corpus_key=corpus, step=step, allowlist_sha256="a" * 64, config_sha256=config,
                       query_sha256=query)
    trace_id = trace_id_for(WS, run, step)
    stored = StoredTrace(run, generation, query, scope.model_dump_json(), candidates.model_dump_json(),
                         tuple(d.chunk_id for d in delivered), request)
    return Step(StepRecord(stored, IntentRecord(run, step, trace_id, request, query, scope_digest, config)), spans)


@dataclass
class Reader:
    """A test-only step reader. `late` advances the clock past everything at the named call."""

    steps: dict[UUID, Step] = field(default_factory=dict)
    current: UUID | None = GEN_1
    workspace_id: UUID = WS
    clock: list[float] = field(default_factory=lambda: [0.0])
    late: str | None = None
    log: list[str] = field(default_factory=list)
    test_only: bool = True

    def add(self, step: int, entry: Step, *, run: UUID = RUN, workspace: UUID | None = None) -> None:
        self.steps[trace_id_for(workspace or self.workspace_id, run, step)] = entry

    def _call(self, name: str) -> None:
        self.log.append(name)
        if self.late == name:
            self.clock[0] = 1e9

    def step_record(self, trace_id: UUID) -> StepRecord:
        self._call("step_record")
        entry = self.steps.get(trace_id)
        return entry.record if entry else StepRecord(None, None)

    def spans(self, entries: Sequence[tuple[UUID, int, int]]) -> list[Span | None]:
        self._call("spans")
        for entry in self.steps.values():
            stored = entry.record.trace
            if stored and [(d.document_version_id, d.start, d.end) for d in
                           TraceCandidates.model_validate_json(stored.candidates).delivered] == list(entries):
                return list(entry.spans)
        return [None] * len(entries)

    def pointer(self, corpus_key: str) -> UUID | None:
        self._call("pointer")
        return self.current


def validator(reader: Reader) -> EvidenceValidator:
    return EvidenceValidator(None, reader.workspace_id, clock=lambda: reader.clock[0], store=reader,  # type: ignore[arg-type]
                             env="test")


def quote(step: int, evidence: str, text_value: str, start: int | None = None) -> CitedQuote:
    return CitedQuote(step=step, evidence_id=evidence, quote=text_value, start=start,
                      end=None if start is None else start + len(text_value))


def answer(*assertions: tuple[bool, Sequence[CitedQuote]]) -> GroundedAnswer:
    return GroundedAnswer(v="policyops.grounded-answer/v1", outcome="answer", abstention=None, assertions=tuple(
        Assertion(text="A claim.", policy_dependent=policy, citations=tuple(cites)) for policy, cites in assertions))


def check(reader: Reader, value: GroundedAnswer, *, steps: Sequence[int] = (1, 2), corpus: str = CORPUS,
          run: UUID = RUN, deadline: float = 100.0) -> ValidatedAnswer | GroundingRefused:
    return validator(reader).validate(value, run_id=run, authorized_steps=tuple(steps), corpus_key=corpus,
                                      deadline=deadline)


def ok(result: ValidatedAnswer | GroundingRefused) -> ValidatedAnswer:
    assert isinstance(result, ValidatedAnswer), result
    return result


TEXTS = ["Refunds take ten days.", "Gift cards are instant.", "aaa abab é a\r\nb"]


@pytest.fixture
def reader() -> Reader:
    reader = Reader()
    reader.add(1, synthetic(1, TEXTS))
    return reader


# -- the model-facing contract -------------------------------------------------------------------------------------

def test_the_grounded_answer_schema_is_inside_the_strict_provider_subset() -> None:
    check_schema(json.dumps(GroundedAnswer.model_json_schema()))


@pytest.mark.parametrize("bad", [
    {"outcome": "answer", "assertions": [], "abstention": None},
    {"outcome": "abstain", "assertions": [], "abstention": None},
    {"outcome": "answer", "assertions": [{"text": "x", "policy_dependent": True, "citations": []}],
     "abstention": {"reason": "insufficient_evidence", "detail": None}},
])
def test_answer_shapes_are_strict(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GroundedAnswer.model_validate({"v": "policyops.grounded-answer/v1", **bad})


@pytest.mark.parametrize("cited", [
    {"quote": "abc", "start": 0, "end": None}, {"quote": "abc", "start": 1, "end": 1},
    {"quote": "abc", "start": 0, "end": 2}, {"quote": "a\x00b", "start": None, "end": None},
    {"quote": "", "start": None, "end": None}, {"quote": "x" * 1001, "start": None, "end": None},
])
def test_quote_contract_bounds(cited: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CitedQuote.model_validate({"step": 1, "evidence_id": "E1", **cited})


def test_claim_support_is_never_validated() -> None:
    with pytest.raises(ValidationError):
        ValidatedAnswer(outcome="abstained", claim_support_validated=True)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ValidatedAnswer(outcome="grounded", bundle=None)  # a grounded outcome always carries its bundle


def test_the_citation_id_material_and_namespace_are_pinned() -> None:
    assert CITATION_NAMESPACE == uuid5(NAMESPACE_URL, "policyops:citation/v1") == UUID(
        "f8e784d0-826a-5af5-a4c1-3eee9cf87aec")
    assert citation_id(UUID(int=1), UUID(int=2), UUID(int=3), 10, 20) == UUID("fa65b9fc-026e-5002-a3b5-0293c45946fd")


# -- quote semantics -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("text_value", "quoted", "start", "expected"), [
    ("aaa", "aa", None, ("quote_ambiguous", 0)),          # overlapping occurrences count
    ("abab", "ab", None, ("quote_ambiguous", 0)),         # adjacent repeats
    ("abab", "ba", None, ("matched", 1)),
    ("café", "café", None, ("quote_not_found", 0)),  # NFC body, NFD quote: no normalization
    ("a\r\nb", "\r\nb", 1, ("matched", 1)),               # CRLF is two code points
    ("a\r\nb", "\nb", 1, ("quote_mismatch", 0)),          # off by one across the CR
    ("a\r\nb", "\nb", 2, ("matched", 2)),
    ("abc", "bc", 2, ("span_invalid", 0)),                # beyond the end
    ("abc", "x", None, ("quote_not_found", 0)),
])
def test_quotes_match_exact_code_points(text_value: str, quoted: str, start: int | None,
                                        expected: tuple[str, int]) -> None:
    end = None if start is None else start + len(quoted)
    assert match_quote(text_value, quoted, start, end) == expected


def test_pathological_quotes_are_bounded() -> None:
    text_value = "a" * 20_000
    reader = Reader()
    reader.add(1, synthetic(1, [text_value] * 16))
    near = "a" * 999 + "b"
    value = answer(*[(True, [quote(1, f"E{(i * 4 + j) % 16 + 1}", near) for j in range(4)]) for i in range(16)])
    began = time.perf_counter()
    result = ok(check(reader, value))
    assert time.perf_counter() - began < 2.0
    assert {c.status for c in result.citations} == {"quote_not_found"} and len(result.citations) == 64


# -- the validator -------------------------------------------------------------------------------------------------

def test_a_grounded_answer_carries_exactly_its_verified_claims(reader: Reader) -> None:
    result = ok(check(reader, answer((True, [quote(1, "E1", "ten days")]), (False, [quote(1, "E2", "instant")]))))
    assert result.outcome == "grounded" and result.generation_current and result.generation_id == GEN_1
    assert [c.status for c in result.citations] == ["verified", "verified"]
    assert result.bundle is not None and len(result.bundle.claims) == 2
    claim = result.bundle.claims[0]
    entry = reader.steps[trace_id_for(WS, RUN, 1)]
    delivered = TraceCandidates.model_validate_json(entry.record.trace.candidates).delivered[0]  # type: ignore[union-attr]
    assert (claim.trace_id, claim.chunk_id, claim.document_version_id) == (
        trace_id_for(WS, RUN, 1), delivered.chunk_id, delivered.document_version_id)
    assert (claim.span_start, claim.span_end) == (delivered.start + 13, delivered.start + 21)
    assert claim.quote_sha256 == sha("ten days") and claim.chunk_text_sha256 == delivered.text_sha256
    assert not result.claim_support_validated and result.caller_authorized_scope == "required"
    assert [a.status for a in result.assertions] == ["cited_identity_verified", "not_policy_dependent"]


def test_every_failure_is_visible_and_never_in_a_bundle(reader: Reader) -> None:
    reader.add(2, synthetic(2, ["Other step."], corpus="other-corpus"))
    cites = [quote(3, "E1", "x"), quote(1, "E9", "x"), quote(1, "E1", "ten days", 100), quote(1, "E1", "ten", 0),
             quote(1, "E1", "eleven"), quote(1, "E3", "a"), quote(2, "E1", "Other"), quote(4, "E1", "x")]
    value = answer((True, cites[:4]), (True, cites[4:]), (True, [quote(1, "E1", "ten days"),
                                                                 quote(1, "E1", "ten days", 13)]))
    result = ok(check(reader, value, steps=(1, 2, 4)))
    assert [c.status for c in result.citations] == [
        "step_not_authorized", "unknown_evidence", "span_invalid", "quote_mismatch", "quote_not_found",
        "quote_ambiguous", "corpus_mismatch", "trace_not_found", "verified", "duplicate"]
    assert result.outcome == "insufficient_evidence" and result.bundle is None
    failed = [c for c in result.citations if c.status != "verified"]
    assert all(c.chunk_id is None and c.span_start is None for c in failed)
    assert reader.log.count("step_record") == 3 and reader.log.count("spans") == 1  # step 3 never read


def test_mixed_generations_reject_every_verified_citation() -> None:
    reader = Reader()
    reader.add(1, synthetic(1, TEXTS))
    reader.add(2, synthetic(2, ["Gift cards are instant."], generation=GEN_2))
    result = ok(check(reader, answer((True, [quote(1, "E1", "ten days")]), (True, [quote(2, "E1", "instant")]))))
    assert [c.status for c in result.citations] == ["mixed_generation", "mixed_generation"]
    assert result.outcome == "insufficient_evidence" and result.bundle is None and result.generation_id is None
    assert "pointer" not in reader.log


def test_outcome_precedence(reader: Reader) -> None:
    assert ok(check(reader, answer((True, [quote(1, "E1", "ten days")]), (True, [])))).outcome == \
        "insufficient_evidence"
    assert ok(check(reader, answer((False, [quote(1, "E1", "ten days")])))).outcome == "no_policy_assertions"
    reader.current = GEN_2  # a later activation: historical identity still verified, not current
    stale = ok(check(reader, answer((True, [quote(1, "E1", "ten days")]))))
    assert stale.outcome == "stale_evidence" and stale.generation_current is False and stale.bundle is None
    abstain = GroundedAnswer(v="policyops.grounded-answer/v1", outcome="abstain", assertions=(),
                             abstention=Abstention(reason="insufficient_evidence", detail=None))
    reader.log.clear()
    assert ok(check(reader, abstain)).outcome == "abstained" and reader.log == []


@pytest.mark.parametrize("tamper", ["payload", "final_ids", "intent_request", "scope_step", "query_digest",
                                    "config_digest", "request_recompute", "intent_step", "body_digest", "document",
                                    "version", "slice", "evidence_text", "missing_span", "unsupported"])
def test_query_less_checks_catch_every_inconsistency(tamper: str) -> None:
    entry = synthetic(1, TEXTS)
    stored, intent = entry.record.trace, entry.record.intent
    assert stored is not None and intent is not None
    candidates = json.loads(stored.candidates)
    scope = json.loads(stored.authorized_scope)
    spans = list(entry.spans)
    if tamper == "payload":
        candidates["evidence_tokens"] = 11
    elif tamper == "final_ids":
        stored = replace(stored, final_chunk_ids=stored.final_chunk_ids[::-1])
    elif tamper == "intent_request":
        stored = replace(stored, intent_request_sha256="f" * 64)
    elif tamper == "scope_step":
        scope["step"] = 2
    elif tamper == "query_digest":
        intent = replace(intent, query_sha256="f" * 64)
    elif tamper == "config_digest":
        intent = replace(intent, config_sha256="f" * 64)
    elif tamper == "request_recompute":
        intent = replace(intent, scope_sha256="f" * 64)
    elif tamper == "intent_step":
        intent = replace(intent, step=2)
    elif tamper in ("body_digest", "document", "version", "slice"):
        span = spans[0]
        assert span is not None
        spans[0] = {"body_digest": replace(span, body_digest_ok=False), "document": replace(span, document_id=uuid4()),
                    "version": replace(span, version_number=2), "slice": replace(span, text=f"{span.text}!")}[tamper]
    elif tamper == "evidence_text":
        candidates["evidence_text_sha256"] = "f" * 64
    elif tamper == "missing_span":
        spans[1] = None
    else:
        candidates["mode"] = "unknown"
    if tamper in ("payload", "evidence_text"):
        candidates["payload_sha256"] = candidates["payload_sha256"] if tamper == "payload" else \
            TraceCandidates.model_validate_json(json.dumps(candidates)).computed_payload_sha256()
    stored = replace(stored, candidates=json.dumps(candidates), authorized_scope=json.dumps(scope))
    checked = check_step(StepRecord(stored, intent), workspace_id=WS, run_id=RUN, step=1, corpus_key=CORPUS)
    outcome = checked if isinstance(checked, StepFailure) else check_step_evidence(checked, spans)
    assert isinstance(outcome, StepFailure) and outcome.status == "trace_integrity", (tamper, outcome)


def test_missing_traces_intents_and_other_runs_are_not_found() -> None:
    entry = synthetic(1, TEXTS)
    assert check_step(StepRecord(entry.record.trace, None), workspace_id=WS, run_id=RUN, step=1,
                      corpus_key=CORPUS) == StepFailure("trace_not_found", "no trace or no intent for this run's step")
    other = synthetic(1, TEXTS, run=UUID(int=99))  # a same-tenant other run's records presented for this run
    failure = check_step(other.record, workspace_id=WS, run_id=RUN, step=1, corpus_key=CORPUS)
    assert isinstance(failure, StepFailure) and failure.status == "trace_integrity"


def test_the_shared_verifier_keeps_the_c2_replay_codes() -> None:
    entry = synthetic(1, TEXTS)
    stored = entry.record.trace
    assert stored is not None
    request = stored.intent_request_sha256
    assert verify_record(replace(stored, candidates="{}"), run_id=RUN, expected_request=request) == TraceProblem(
        "replay_unsupported", "the stored trace is not a supported retrieval trace")
    assert verify_record(replace(stored, intent_request_sha256=None), run_id=RUN, expected_request=request) == \
        TraceProblem("replay_unsupported", "the stored trace has no recorded intent")
    assert verify_record(stored, run_id=RUN, expected_request="f" * 64) == TraceProblem(
        "step_conflict", "this step already holds a different request")
    assert verify_record(stored, run_id=RUN, expected_request=request, expected_query_sha256="f" * 64) == \
        TraceProblem("replay_integrity", "the stored trace does not match its own record")
    assert verify_record(replace(stored, final_chunk_ids=()), run_id=RUN, expected_request=request) == TraceProblem(
        "replay_integrity", "delivered chunk IDs")


@pytest.mark.parametrize("late", ["step_record", "spans", "pointer"])
def test_late_reads_never_return_a_result(reader: Reader, late: str) -> None:
    reader.late = late
    assert check(reader, answer((True, [quote(1, "E1", "ten days")]))) == GroundingRefused(code="deadline_passed")


@pytest.mark.parametrize(("deadline", "code"), [(float("nan"), "deadline_invalid"), (float("inf"), "deadline_invalid"),
                                                (True, "deadline_invalid"), (0.0, "deadline_passed")])
def test_invalid_or_passed_deadlines_refuse_before_any_read(reader: Reader, deadline: Any, code: str) -> None:
    refused = check(reader, answer((True, [quote(1, "E1", "ten days")])), deadline=deadline)
    assert isinstance(refused, GroundingRefused) and refused.code == code
    assert reader.log == []


@pytest.mark.parametrize(("steps", "corpus"), [((1, 1), CORPUS), (tuple(range(17)), CORPUS), ((True,), CORPUS),
                                               ((1,), "Not A Slug"), ((10_000,), CORPUS)])
def test_the_caller_context_is_validated_before_any_read(reader: Reader, steps: Any, corpus: str) -> None:
    result = check(reader, answer((True, [quote(1, "E1", "ten days")])), steps=steps, corpus=corpus)
    assert isinstance(result, GroundingRefused) and result.code == "context_invalid" and reader.log == []


def test_the_store_seam_is_test_only_and_workspace_bound() -> None:
    with pytest.raises(UnsafeTestHook):
        EvidenceValidator(None, WS, store=Reader(test_only=False), env="test")  # type: ignore[arg-type]
    with pytest.raises(UnsafeTestHook):
        EvidenceValidator(None, WS, store=Reader(), env="production")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="another workspace"):
        EvidenceValidator(None, UUID(int=999), store=Reader(), env="test")  # type: ignore[arg-type]


# -- the genuine accepted-C5 legacy fixture ------------------------------------------------------------------------

def legacy() -> dict[str, Any]:
    value: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return value


def legacy_reader(fixture: dict[str, Any], names: Sequence[str]) -> tuple[Reader, list[dict[str, Any]]]:
    steps = [s for s in fixture["steps"] if s["name"] in names]
    ws = UUID(steps[0]["workspace_id"])
    reader = Reader(workspace_id=ws, current=UUID(fixture["generations"]["banking_1"]))
    digests = {b["document_version_id"]: b["sha256"] for s in steps for b in s["bodies"]}
    for s in steps:
        t, i = s["trace"], s["intent"]
        stored = StoredTrace(UUID(t["run_id"]), UUID(t["generation_id"]), t["query_sha256"], t["authorized_scope"],
                             t["candidates"], tuple(UUID(x) for x in t["final_chunk_ids"]), i["request_sha256"])
        intent = IntentRecord(UUID(i["run_id"]), i["step"], UUID(i["trace_id"]), i["request_sha256"],
                              i["query_sha256"], i["scope_sha256"], i["config_sha256"])
        spans: list[Span | None] = [Span(UUID(x["document_version_id"]), UUID(x["document_id"]), x["source_uri"],
                                         x["version_number"], x["text"], x["body_digest_ok"],
                                         digests[x["document_version_id"]]) for x in s["spans"]]
        reader.add(i["step"], Step(StepRecord(stored, intent), spans), run=UUID(i["run_id"]), workspace=ws)
    return reader, steps


def test_genuine_legacy_traces_verify_query_less_and_ground_a_quote() -> None:
    fixture = legacy()
    reader, (step,) = legacy_reader(fixture, ["hybrid-default-dense-ok"])
    evidence = json.loads(step["first_result_json"])["evidence"]
    target = next(e for e in evidence if "—" in e["text"])  # a non-ASCII body: code points, not bytes
    quoted = target["text"][target["text"].index("ten days"):][:30]
    run, number = UUID(step["intent"]["run_id"]), step["intent"]["step"]
    result = validator(reader).validate(
        answer((True, [quote(number, target["evidence_id"], quoted)])), run_id=run, authorized_steps=(number,),
        corpus_key="legacy-banking", deadline=100.0)
    assert isinstance(result, ValidatedAnswer) and result.outcome == "grounded", result
    claim = result.bundle.claims[0]  # type: ignore[union-attr]
    body = next(b["body"] for b in step["bodies"] if b["document_version_id"] == str(claim.document_version_id))
    assert body[claim.span_start:claim.span_end] == quoted and claim.chunk_id == UUID(target["chunk_id"])
    assert claim.trace_payload_sha256 == json.loads(step["first_result_json"])["payload_sha256"]
    reader.current = UUID(fixture["generations"]["banking_2"])  # the genuine later activation
    later = validator(reader).validate(
        answer((True, [quote(number, target["evidence_id"], quoted)])), run_id=run, authorized_steps=(number,),
        corpus_key="legacy-banking", deadline=100.0)
    assert isinstance(later, ValidatedAnswer) and later.outcome == "stale_evidence"


def test_every_genuine_legacy_step_passes_the_shared_query_less_checks() -> None:
    fixture = legacy()
    for step in fixture["steps"]:
        reader, _ = legacy_reader(fixture, [step["name"]])
        trace_id = UUID(step["trace_id"])
        record = reader.steps[trace_id].record
        corpus = json.loads(step["query_json"])["scope"]["corpus_key"]
        checked = check_step(record, workspace_id=UUID(step["workspace_id"]), run_id=UUID(step["intent"]["run_id"]),
                             step=step["intent"]["step"], corpus_key=corpus)
        assert not isinstance(checked, StepFailure), (step["name"], checked)
        evidence = check_step_evidence(checked, reader.steps[trace_id].spans)
        assert not isinstance(evidence, StepFailure), (step["name"], evidence)


# -- the recorder: pure recheck, wiring and cleanup ----------------------------------------------------------------

def verified_claim(reader: Reader, step: int = 1, evidence: str = "E1", text_value: str = "ten days") -> CitationClaim:
    result = ok(check(reader, answer((True, [quote(step, evidence, text_value)]))))
    assert result.bundle is not None
    return result.bundle.claims[0]


@pytest.mark.parametrize(("change", "field_name"), [
    ({"trace_id": uuid4()}, "trace_id"), ({"step": 2}, "trace_id"), ({"trace_payload_sha256": "f" * 64},
                                                                     "trace_payload_sha256"),
    ({"request_sha256": "f" * 64}, "request_sha256"), ({"generation_id": GEN_2}, "generation_id"),
    ({"evidence_id": "E9"}, "evidence_id"), ({"evidence_id": "E2"}, "chunk_id"), ({"chunk_id": uuid4()}, "chunk_id"),
    ({"document_id": uuid4()}, "document_id"), ({"document_version_id": uuid4()}, "document_version_id"),
    ({"chunk_text_sha256": "f" * 64}, "chunk_text_sha256"), ({"version_sha256": "f" * 64}, "version_sha256"),
    ({"span_start": 0, "span_end": 8}, "span"), ({"quote_sha256": "f" * 64}, "quote_sha256"),
    ({"span_start": 21, "span_end": 29}, "quote"),
])
def test_the_recheck_names_the_first_contradicted_field(reader: Reader, change: dict[str, Any],
                                                        field_name: str) -> None:
    claim = verified_claim(reader)
    entry = reader.steps[trace_id_for(WS, RUN, 1)]
    checked = check_step(entry.record, workspace_id=WS, run_id=RUN, step=1, corpus_key=CORPUS)
    assert not isinstance(checked, StepFailure)
    evidence = check_step_evidence(checked, entry.spans)
    assert not isinstance(evidence, StepFailure)
    assert recheck(claim, evidence, workspace_id=WS, run_id=RUN) is None
    forged = claim.model_copy(update=change)
    assert recheck(forged, evidence, workspace_id=WS, run_id=RUN) == field_name


class FakeConnection:
    def __init__(self, log: list[str], *, fail_close: bool = False, fail_on: str | None = None) -> None:
        self.log, self.fail_close, self.fail_on = log, fail_close, fail_on

    def execution_options(self, **options: Any) -> FakeConnection:
        self.log.append(f"options:{options}")
        return self

    def begin(self) -> Any:
        self.log.append("begin")
        log = self.log

        class Tx:
            def rollback(self) -> None:
                log.append("rollback")

            def commit(self) -> None:
                log.append("commit")

        return Tx()

    def execute(self, statement: Any, params: Any = None) -> Any:
        sql = str(statement)
        self.log.append(sql.split()[0] + (" FOR SHARE" if "FOR SHARE" in sql else ""))
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("synthetic failure")
        if "set_config" in sql:
            return None
        raise AssertionError("no further statement is scripted")

    def close(self) -> None:
        self.log.append("close")
        if self.fail_close:
            raise OSError("synthetic close failure")


class FakeEngine:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def connect(self) -> FakeConnection:
        self.connection.log.append("connect")
        return self.connection


def recorder(monkeypatch: pytest.MonkeyPatch, connection: FakeConnection, **kwargs: Any) -> CitationRecorder:
    monkeypatch.setattr(citations_module, "verify_runtime_role", lambda engine, role: None)
    monkeypatch.setattr(citations_module, "RetrievalStore", lambda engine, ws: None)
    return CitationRecorder(FakeEngine(connection), WS, clock=lambda: 0.0, **kwargs)  # type: ignore[arg-type]


def bundle_for(claim: CitationClaim, *, run: UUID = RUN) -> CitationBundle:
    return CitationBundle(run_id=run, corpus_key=CORPUS, claims=(claim,))


@pytest.mark.parametrize("original", [errors.LockNotAvailable(), errors.QueryCanceled(),
                                      errors.ConnectionFailure(), errors.IdleInTransactionSessionTimeout(),
                                      errors.CheckViolation()])
def test_citation_insert_preserves_transient_failure_instead_of_integrity_refusal(
        reader: Reader, monkeypatch: pytest.MonkeyPatch, original: Error) -> None:
    claim = verified_claim(reader)
    entry = reader.steps[trace_id_for(WS, RUN, 1)]
    checked = check_step(entry.record, workspace_id=WS, run_id=RUN, step=1, corpus_key=CORPUS)
    assert not isinstance(checked, StepFailure)
    evidence = check_step_evidence(checked, entry.spans)
    assert not isinstance(evidence, StepFailure)
    error = DBAPIError("private SQL", {"private": "values"}, original)

    class InsertFailure(FakeConnection):
        def execute(self, statement: Any, params: Any = None) -> Any:
            sql = str(statement)
            if "FOR SHARE" in sql:
                return SimpleNamespace(mappings=lambda: SimpleNamespace(first=lambda: {
                    "corpus_key": CORPUS, "active_generation_id": claim.generation_id}))
            if "INSERT INTO app.citations" in sql:
                raise error
            return super().execute(statement, params)

    log: list[str] = []
    service = recorder(monkeypatch, InsertFailure(log))
    monkeypatch.setattr(citations_module, "_rows", lambda *args: {})
    monkeypatch.setattr(service, "_evidence", lambda *args: {1: evidence})
    if isinstance(original, errors.CheckViolation):
        result = service.record(bundle_for(claim), run_id=RUN, authorized_steps=(1,),
                                corpus_key=CORPUS, deadline=10.0)
        assert (result.status, result.code) == ("refused", "citation_integrity")
    else:
        with pytest.raises(DatabaseUnavailable) as caught:
            service.record(bundle_for(claim), run_id=RUN, authorized_steps=(1,), corpus_key=CORPUS, deadline=10.0)
        assert caught.value.sqlstate == original.sqlstate and caught.value.__cause__ is error
    assert log[-2:] == ["rollback", "close"]


@pytest.mark.parametrize("context", [{"run_id": uuid4()}, {"corpus_key": "other"}, {"authorized_steps": (2,)},
                                     {"authorized_steps": (1, 1)}])
def test_a_context_mismatch_refuses_before_any_sql(reader: Reader, monkeypatch: pytest.MonkeyPatch,
                                                   context: dict[str, Any]) -> None:
    log: list[str] = []
    claim = verified_claim(reader)
    arguments = {"run_id": RUN, "authorized_steps": (1,), "corpus_key": CORPUS, "deadline": 10.0} | context
    for method in ("record", "reconcile"):
        outcome = getattr(recorder(monkeypatch, FakeConnection(log)), method)(bundle_for(claim), **arguments)
        assert (outcome.status, outcome.code) == ("refused", "record_context_mismatch")
    assert log == []


def test_the_transaction_starts_with_the_corpus_share_lock_and_a_cleanup_failure_is_only_a_note(
        reader: Reader, monkeypatch: pytest.MonkeyPatch) -> None:
    log: list[str] = []
    claim = verified_claim(reader)
    connection = FakeConnection(log, fail_close=True, fail_on="FOR SHARE")
    with pytest.raises(RuntimeError, match="synthetic failure") as raised:
        recorder(monkeypatch, connection).record(bundle_for(claim), run_id=RUN, authorized_steps=(1,),
                                                 corpus_key=CORPUS, deadline=10.0)
    assert log == ["connect", "options:{'isolation_level': 'READ COMMITTED'}", "begin",
                   "SELECT", "SELECT", "SELECT", "SELECT", "SELECT FOR SHARE",
                   "rollback", "close"]
    assert any("close also failed: OSError" in note for note in raised.value.__notes__)


def test_fault_plans_are_test_only(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="only allowed"):
        recorder(monkeypatch, FakeConnection([]), faults=FaultPlan(before_commit=True))
    with pytest.raises(ValueError, match="only allowed"):
        recorder(monkeypatch, FakeConnection([]), faults=FaultPlan(), env="production")
    assert recorder(monkeypatch, FakeConnection([]), faults=FaultPlan(), env="test") is not None


@pytest.mark.parametrize(("deadline", "status"), [(float("nan"), "refused"), (0.0, "deadline_passed")])
def test_invalid_or_passed_record_deadlines_open_no_connection(reader: Reader, monkeypatch: pytest.MonkeyPatch,
                                                               deadline: float, status: str) -> None:
    log: list[str] = []
    claim = verified_claim(reader)
    outcome = recorder(monkeypatch, FakeConnection(log)).record(bundle_for(claim), run_id=RUN, authorized_steps=(1,),
                                                                corpus_key=CORPUS, deadline=deadline)
    assert outcome.status == status and outcome.committed == "none" and log == []


def test_duplicate_claims_map_to_sorted_distinct_ids(reader: Reader, monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = verified_claim(reader), verified_claim(reader, evidence="E2", text_value="instant")
    log: list[str] = []
    bundle = CitationBundle(run_id=RUN, corpus_key=CORPUS, claims=(first, second, first))
    outcome = recorder(monkeypatch, FakeConnection(log)).record(bundle, run_id=uuid4(), authorized_steps=(1,),
                                                                corpus_key=CORPUS, deadline=10.0)
    ids = [citation_id(WS, c.trace_id, c.chunk_id, c.span_start, c.span_end) for c in (first, second, first)]
    assert outcome.claim_ids == tuple(ids) and outcome.distinct_ids == tuple(sorted(set(ids)))
    assert (outcome.claims, outcome.distinct) == (3, 2)



# -- review regressions (draft-findings-1) -------------------------------------------------------------------------

@pytest.mark.parametrize("steps", [[[]], [{}], [1, [2]], list(range(1000)), ["1"], [1.0], {"a"}])
def test_malformed_authorized_steps_are_typed_refusals_with_no_store_activity(
        reader: Reader, monkeypatch: pytest.MonkeyPatch, steps: Any) -> None:
    value = answer((True, [quote(1, "E1", "ten days")]))
    result = check(reader, value, steps=steps)
    assert isinstance(result, GroundingRefused) and result.code == "context_invalid" and reader.log == []
    claim = verified_claim(reader)
    reader.log.clear()
    log: list[str] = []
    for method in ("record", "reconcile"):
        outcome = getattr(recorder(monkeypatch, FakeConnection(log)), method)(
            bundle_for(claim), run_id=RUN, authorized_steps=steps, corpus_key=CORPUS, deadline=10.0)
        assert (outcome.status, outcome.code) == ("refused", "record_context_mismatch")
    assert log == [] and reader.log == []


@pytest.mark.parametrize(("close_seconds", "status"), [(0.0, "recorded"), (10.0, "deadline_passed")])
def test_a_success_is_never_returned_after_the_cleanup_crosses_the_deadline(
        reader: Reader, monkeypatch: pytest.MonkeyPatch, close_seconds: float, status: str) -> None:
    """Actual `record` entry, close and return around a scripted acknowledged transaction (no SQL is claimed)."""
    clock = [0.0]
    claim = verified_claim(reader)

    class Closing(FakeConnection):
        def close(self) -> None:
            self.log.append("close")
            clock[0] += close_seconds  # a blocking close/reset

    def acknowledged(self: CitationRecorder, connection: Any, prepared: Any, run_id: UUID, corpus_key: str,
                     deadline: float) -> Any:
        return RecordOutcome(status="recorded", committed="observed", inserted=1, existing=0,
                                              **prepared.counts())

    monkeypatch.setattr(CitationRecorder, "_record_in", acknowledged)
    unit = recorder(monkeypatch, Closing([]))
    unit.clock = lambda: clock[0]
    outcome = unit.record(bundle_for(claim), run_id=RUN, authorized_steps=(1,), corpus_key=CORPUS, deadline=5.0)
    assert (outcome.status, outcome.committed, outcome.inserted, outcome.distinct) == (status, "observed", 1, 1)
    assert outcome.code == (None if status == "recorded" else "deadline_passed")
