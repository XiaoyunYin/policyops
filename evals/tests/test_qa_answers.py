"""Offline text isolation, frozen bindings, stage failure and recovery contracts."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
import json
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest

from policyops.providers.calls import Providers
from policyops.providers.tokenizer import Tokenizer
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import answers as a
from policyops_evals.qa_studies import judges
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies.config import (
    AnswerGeneration,
    ClosedBook,
    CrossEncoder,
    QAStudy,
    Rerank,
    load_study,
    preflight,
)
from policyops_evals.qa_studies.cross_encoder import CrossEncoderClient, WorkerError
from policyops_evals.qa_studies.registration import run_id
from policyops_testing.retrieval_fixtures import TOKENIZER

from .test_qa_runner import Executor, Memory, memory
from .test_qa_study_config import parse
from .test_qa_study_registration import SOURCE


__all__ = ["memory"]
CONFIG = Path(__file__).parents[1] / "qa_studies/g1-dev-answers-v1.json"
P = "md2d.p/" + "a" * 64
P2 = "md2d.p/" + "b" * 64


def answer_study(tmp_path: Path) -> tuple[QAStudy, r.Inputs, Path, dict[str, Any]]:
    value = json.loads(CONFIG.read_bytes())
    value["study_id"] = str(uuid4())
    source = dict(SOURCE, lock_sha256=dict.fromkeys(("uv.lock", "evals/uv.lock", "reranker/uv.lock"), "0" * 64))
    value["provenance"]["locks"] = [{"path": k, "sha256": v} for k, v in source["lock_sha256"].items()]
    value["schedule"]["cohorts"][0].update(question_count=2, dialogue_count=1)
    for comparison in value["analysis"]["comparisons"]:
        comparison["required_questions"] = 2
    receipt = {"schema_version": "policyops.g6-selection/v1", "protocol": "policyops.g6/v1",
               "selection_rule_version": "g6-selection/v2", "binding": judges.ARMS[1].binding()}
    # Synthetic selection for the tiny tests; production dev metadata follows the selected Haiku judge.
    value["judge"].update({k: v for k, v in judges.ARMS[1].binding().items() if k in value["judge"]})
    value["judge"].pop("test_report_sha256", None)  # synthetic judge has no registered test report
    for stage in value["execution"]["stages"]:
        if stage["role"] == "judge":
            stage["model"] = "gpt-6-luna"
    raw = canonical_bytes(receipt)
    path = tmp_path / "selection.json"
    path.write_bytes(raw)
    value["judge"]["selection_receipt_sha256"] = sha256_bytes(raw)
    study = parse(value)
    ids = ("md2d.q/train/fictional/0", "md2d.q/train/fictional/1")
    queries = {q: r.QueryInput(q, "fictional/dialogue", "retrieval private", "last user",
                             "user: chronological first [SEP] agent: earlier [SEP] user: current") for q in ids}
    passages = {P: a.Passage(P, "Refunds", "Refunds return to the card."),
                P2: a.Passage(P2, "Other", "Keep receipts.")}
    inputs = r.Inputs(queries, dict.fromkeys(ids, r.Gold((P,), "responding")), {"dev": ids},
        {p.id: sha256_bytes(canonical_bytes([p.heading, p.body])) for p in passages.values()},
        passages, dict.fromkeys(ids, "GOLD TARGET NEVER SENT"))
    return study, inputs, path, source


def test_dev_config_schedule_envelopes_and_placeholder_refusal(tmp_path: Path) -> None:
    study = load_study(CONFIG)
    study.validate_data()
    r.supported(study)
    assert study.purpose == "dev" and study.schedule.cohorts[0].question_count == 500
    assert [arm.kind for arm in study.arms] == ["answer_generation", "answer_generation", "rerank", "rerank",
                                              "closed_book"]
    assert {arm.max_claims for arm in study.arms if isinstance(arm, (AnswerGeneration, Rerank, ClosedBook))} == {1}
    plan = preflight(study)
    assert plan["within_caps"] and Decimal(plan["ceiling_usd"]) == Decimal("4.98039200")
    assert plan["planned_calls"] == 5800 and study.execution.cumulative_caps.usd == 5
    with pytest.raises(a.AnswerError, match="judge_receipt_mismatch"):
        a.selected_judge(study.judge, tmp_path / "absent")


@pytest.mark.parametrize(("text", "expected"), [("", ()), (" \n !!! ", ()),
    ("One sentence", ("One sentence",)), ("One. Two!\nThree? Four.", ("One.", "Two!", "Three?", "Four.")),
    ("Dr. Smith paid 1.5 dollars.", ("Dr.", "Smith paid 1.5 dollars.")),
    ("• Keep receipts; bring ID.", ("• Keep receipts; bring ID.",)), ("合法。", ("合法。",))])
def test_fixed_splitter(text: str, expected: tuple[str, ...]) -> None:
    assert a.sentences(text) == expected


def test_splitter_overflow_never_discards_suffix() -> None:
    with pytest.raises(a.AnswerError, match="too_many_claims"):
        a.sentences("One. Two. Three. Four. Five.")
    with pytest.raises(a.AnswerError, match="too_many_claims"):
        a.sentences("One. Two.", maximum=1)


def test_whole_delivery_skip_continue_and_access_validation() -> None:
    class Counter:
        def count(self, text: str) -> int:
            return len(text)
    passages = {P: a.Passage(P, "heading", "x" * 5000), P2: a.Passage(P2, "heading", "small")}
    context = load_study(CONFIG).arms[0]
    assert isinstance(context, AnswerGeneration)
    delivery = a.deliver([P, P2], passages, context.context, cast(Tokenizer, Counter()))
    assert delivery.passages == (passages[P2],) and delivery.skipped_overflow == (P,)
    invalid = a.Answer(answer="A claim.", citations=[P], abstain=False)
    assert not a.citations(invalid, delivery)[0].valid
    assert a.cited_document(invalid, delivery) == ""
    valid = invalid.model_copy(update={"citations": [P2]})
    assert a.citations(valid, delivery)[0].valid
    assert a.cited_document(valid, delivery) == passages[P2].block()


@pytest.mark.parametrize("payload", [None, '{"answer":"x","citations":[],"abstain":true}',
    '{"answer":"","citations":[],"abstain":false}',
    '{"answer":"x","citations":[],"abstain":false,"gold":"hidden"}',
    '{"answer":"x","answer":"y","citations":[],"abstain":false}'])
def test_invalid_answer(payload: str | None) -> None:
    with pytest.raises(a.AnswerError, match="invalid_answer"):
        a.parse_answer(payload)


def test_receipt_byte_model_and_prompt_mismatch(tmp_path: Path) -> None:
    study, _, path, _ = answer_study(tmp_path)
    assert a.selected_judge(study.judge, path) == judges.ARMS[1]
    assert study.judge is not None
    for update in ({"selection_receipt_sha256": "f" * 64}, {"prompt_sha256": "f" * 64},
                   {"model": "claude-haiku-5-5"}, {"effort": "high"}):
        with pytest.raises(a.AnswerError):
            a.selected_judge(study.judge.model_copy(update=update), path)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(a.AnswerError, match="receipt_mismatch"):
        a.selected_judge(study.judge, path)


@pytest.mark.parametrize(("kind", "answer", "citations", "verdicts", "failed", "q"), [
    ("grounded", "Claim.", [P], [True], False, "1"), ("grounded", "Claim.", [P], [None], False, "0"),
    ("grounded", "Claim.", [P], [False], False, "0"), ("grounded", "Claim.", [P2], [True], False, "0"),
    ("grounded", "Claim.", [], [True], False, "0"), ("grounded", "Claim.", [P], [], False, "0"),
    ("grounded", "Claim.", [P], [True], True, "0"), ("grounded", "", [], [], False, "0"),
    ("closed", "Claim.", [], [], False, None)])
def test_q_edges(kind: str, answer: str, citations: list[str], verdicts: list[bool | None], failed: bool,
                 q: str | None) -> None:
    study = load_study(CONFIG)
    state = r.AnswerState(ranking=(P,), delivery=a.Delivery((a.Passage(P, "h", "evidence"),), (), (), 10),
        answer=a.Answer(answer=answer, citations=citations, abstain=not answer),
        claims=a.sentences(answer), verdicts=verdicts)
    metrics = r.answer_metrics(state, study.arms[-1] if kind == "closed" else study.arms[0],
                               r.Gold((P,), "responding"), "Claim.", failed=failed)
    assert metrics["quality_q"] == q
    assert metrics["false_abstention"] == ("1" if not answer else "0")
    if kind == "closed":
        assert metrics["citation_precision"] is metrics["delivered_support"] is None


def test_inputs_only_chronological_and_delivered_text(tmp_path: Path) -> None:
    _, inputs, _, _ = answer_study(tmp_path)
    query = next(iter(inputs.queries.values()))
    request = a.request(query.generation, [inputs.passage_text[P]], max_claims=4, max_output=256)
    raw = request.model_dump_json()
    assert "chronological first" in raw and "retrieval private" not in raw
    assert "GOLD TARGET" not in raw and "reference" not in raw and "target_act" not in raw
    assert P in raw and P2 not in raw
    assert not {"gold", "reference", "target", "passage_ids"} & set(vars(query))


def fake_ce(binding: CrossEncoder, deadline: float) -> CrossEncoderClient:
    class Client:
        def rerank(self, *args: Any, **kwargs: Any) -> Any:
            raise WorkerError("worker_eof_or_line_bound")
    return cast(CrossEncoderClient, Client())


def install_paid(monkeypatch: pytest.MonkeyPatch, memory: Memory, *, failing_judge: bool = False,
                 answer_payload: str | None = None, failing_role: str | None = None
                 ) -> list[tuple[str, str, int]]:
    seen: list[tuple[str, str, int]] = []
    monkeypatch.setattr(r.AnswerExecutor, "ledger", lambda *args, **kwargs: None)
    monkeypatch.setattr(r.AnswerExecutor, "cost", lambda *args: "0")
    def paid(self: r.AnswerExecutor, role: str, model: Any, request: Any, state: r.AnswerState,
             deadline: float, index: int = 0) -> str:
        key = str(self.item.id), role, index
        assert key not in seen
        self.boundary("before_" + role)
        seen.append(key)
        self.boundary(role + "_dispatched")
        state.stage_latency_ms[role] = 1
        state.stage_cost_usd[role] = "0"  # this memory fixture performs no ledger reservation/settlement
        self.boundary("after_" + role)
        if role == failing_role:
            raise r.Refused(role + "_call_failed")
        if role == "judge":
            if failing_judge:
                raise r.Refused("invalid_judge_verdict")
            state.verdicts.append(True)
        if role == "answer":
            if answer_payload is not None:
                return answer_payload
            return json.dumps({"answer": "Refunds return to the card.",
                "citations": [] if self.item.arm == "closed-book-luna" else [P], "abstain": False})
        return '{"ranking":["D02","D01"]}'
    monkeypatch.setattr(r.AnswerExecutor, "paid", paid)
    return seen


class Candidates(Executor):
    def execute(self, *args: Any, **kwargs: Any) -> tuple[str, ...]:
        return P, P2


def execute_answers(study: QAStudy, inputs: r.Inputs, receipt: Path, source: dict[str, Any], memory: Memory,
                    **kwargs: Any) -> dict[str, Any]:
    return r.run(study, inputs, memory.repository(), memory.store(), Candidates(memory), allow_paid=True,
        resume=kwargs.pop("resume", False), source=source, providers=lambda: cast(Providers, None),
        tokenizer=TOKENIZER, selection_receipt=receipt, cross_encoder=fake_ce, **kwargs)


@pytest.mark.parametrize("boundary", ["before_answer", "answer_dispatched", "after_answer", "before_judge",
    "judge_dispatched", "after_judge", "before_rerank", "rerank_dispatched", "after_rerank"])
def test_resume_new_boundaries_never_reissue(boundary: str, tmp_path: Path, memory: Memory,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, path, source = answer_study(tmp_path)
    seen = install_paid(monkeypatch, memory)
    def crash(at: str) -> None:
        if at == boundary:
            raise SystemExit("process loss")
    with pytest.raises(SystemExit):
        execute_answers(study, inputs, path, source, memory, boundary=crash)
    previous = set(seen)
    assert execute_answers(study, inputs, path, source, memory, resume=True)["execution_complete"]
    assert previous <= set(seen)
    assert sum(row["outcome"] == "aborted" for row in memory.rows.values()) == 1


def test_ce_and_invalid_judge_are_failures_and_export_has_no_text(tmp_path: Path, memory: Memory,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, path, source = answer_study(tmp_path)
    install_paid(monkeypatch, memory, failing_judge=True)
    result = execute_answers(study, inputs, path, source, memory)
    assert result["execution_complete"]
    public = r.export(study, r.schedule(study, inputs), memory.repository(),
                      {arm.name: run_id(study, memory.scope, arm.name) for arm in study.arms})
    ce = [row for row in public["slots"] if row["arm"] == "rrf-bm25-base-ce"]
    assert all(row["failure_code"] == "cross_encoder_failure" and row["outcome"] == "error" for row in ce)
    assert all(row["metrics"].get("quality_q") != "1" for row in public["slots"])
    raw = json.dumps(public)
    for text in ("chronological first", "return to the card", "GOLD TARGET", "Keep receipts"):
        assert text not in raw
    assert any(row["failure_code"] == "invalid_judge_verdict" for row in public["slots"])


def test_four_claims_must_reserve_four_judges(tmp_path: Path) -> None:
    study, _, _, _ = answer_study(tmp_path)
    value = study.model_dump(mode="json")
    value["arms"][0]["max_claims"] = 4
    stage = next(s for s in value["execution"]["stages"] if s["role"] == "judge")
    stage["planned_calls"] = 7  # two questions require eight judges
    with pytest.raises(ValueError, match="envelope"):
        parse(value)


@pytest.mark.parametrize("field", ["usd", "calls", "counts", "input_tokens", "output_tokens", "seconds"])
def test_role_runtime_caps_not_reset_by_new_invocations(field: str, tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    study, _, _, _ = answer_study(tmp_path)
    stage = next(s for s in study.execution.stages if s.role == "answer")
    cap = stage.caps.model_copy(update={field: Decimal(0) if field == "usd" else 0})
    stage = stage.model_copy(update={"caps": cap})
    class Result:
        def mappings(self) -> Result:
            return self
        def all(self) -> list[Any]:
            return []
        def scalar_one(self) -> Decimal:
            return Decimal(0)
    class Connection:
        def execute(self, *args: Any) -> Result:
            return Result()
    @contextmanager
    def tx(*args: Any) -> Iterator[Connection]:
        yield Connection()
    monkeypatch.setattr(r, "transaction", tx)
    assert not r.admit_role(study, stage, cast(Any, type("Repo", (), {"engine": None})()), uuid4(),
                            r.SharedUsage(), Decimal("0.0001"))


@pytest.mark.parametrize(("payload", "fate", "error"), [
    ('{"supported":true,"reason":"Supported."}', "settled", False),
    ('{"supported":false,"reason":"Missing detail."}', "settled", False),
    ('{"supported":"true","reason":"Wrong type."}', "settled", True),
    ('{"supported":true}', "settled", True),
    ('{"supported":true,"reason":"Supported."}', "unresolved", True)])
def test_paid_judge_requires_strict_settled_verdict(payload: str, fate: str, error: bool, tmp_path: Path,
                                                 memory: Memory, monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.budget.ledger import EvalBinding
    from policyops.persistence.evaluation import EvaluationClaimToken
    from policyops.providers.calls import AttemptRecord, CallReport
    from policyops_contracts.model import ModelResult, ReportedUsage

    study, inputs, _, _ = answer_study(tmp_path)
    item = r.schedule(study, inputs)[0]
    token = EvaluationClaimToken(item.id, uuid4(), EvalBinding(memory.scope, uuid4(), uuid4()), 7)
    executor = r.AnswerExecutor(study, memory.repository(), memory.scope, token, item, r.SharedUsage(),
                                lambda: cast(Providers, None), lambda _: None)
    monkeypatch.setattr(executor, "ledger", lambda *args: cast(Any, object()))
    monkeypatch.setattr(executor, "cost", lambda *args: "0.001")
    def call(*args: Any, **kwargs: Any) -> CallReport:
        assert args[2] == token.binding and args[3] == item.id and args[4] == "judge/0"
        assert args[6] == "judge"
        assert kwargs["limits"].retries_per_request == kwargs["limits"].repairs == 0
        return CallReport(ModelResult(provider="openai", requested_model="gpt-6-luna", outcome="structured",
            structured_json=payload, usage=ReportedUsage(state="known", input_total=100, cache_read=0, output=20)),
            "result", None, [AttemptRecord(uuid4(), "judge/0", None, fate=cast(Any, fate))])
    monkeypatch.setattr(r, "call_sync", call)
    state = r.AnswerState()
    assert study.judge is not None
    import time
    if error:
        with pytest.raises(r.Refused, match="invalid_judge_verdict"):
            executor.paid("judge", study.judge, judges.request(judges.ARMS[1], "Evidence.", "Claim."), state,
                          time.monotonic() + 60)
        assert state.verdicts == []
    else:
        executor.paid("judge", study.judge, judges.request(judges.ARMS[1], "Evidence.", "Claim."), state,
                      time.monotonic() + 60)
        assert state.verdicts == [json.loads(payload)["supported"]]


def test_g6_test_report_is_byte_bound_and_gate_propagates(tmp_path: Path) -> None:
    study, _, _, _ = answer_study(tmp_path)
    assert study.judge is not None
    assert a.judge_gate(study.judge, None) is None
    path = tmp_path / "report.json"
    result = {"selection_receipt_sha256": study.judge.selection_receipt_sha256, "complete": True,
              "kappa": "0.8", "kappa_lower": "0.6", "false_pass": "0.05"}
    report = {"schema_version": "policyops.g6-report/v1", "split": "test", "accounting_settled": True,
              "selection_receipt_sha256": study.judge.selection_receipt_sha256, "judge_result": result}
    raw = canonical_bytes(report)
    path.write_bytes(raw)
    binding = study.judge.model_copy(update={"test_report_sha256": sha256_bytes(raw)})
    gate = a.judge_gate(binding, path)
    assert gate is not None and gate.passed()
    with pytest.raises(a.AnswerError, match="unbound_judge_report"):
        a.judge_gate(study.judge, path)
    report["accounting_settled"] = False
    path.write_bytes(canonical_bytes(report))
    with pytest.raises(a.AnswerError, match="judge_report_mismatch"):
        a.judge_gate(binding, path)
    binding = binding.model_copy(update={"test_report_sha256": sha256_bytes(path.read_bytes())})
    gate = a.judge_gate(binding, path)
    assert gate is not None and not gate.passed()


def test_answer_aggregate_paired_q_and_closed_book_na(tmp_path: Path, memory: Memory,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, receipt, source = answer_study(tmp_path)
    install_paid(monkeypatch, memory)
    execute_answers(study, inputs, receipt, source, memory)
    public = r.export(study, r.schedule(study, inputs), memory.repository(),
                      {arm.name: run_id(study, memory.scope, arm.name) for arm in study.arms})
    report = r.report(study, inputs, public, memory.repository(), memory.scope, source)
    closed = next(row for row in report["aggregates"] if row["arm"] == "closed-book-luna")
    assert closed["metrics"]["quality_q"] is None
    assert closed["metrics"]["citation_precision"] is None
    assert all(comparison["status"] == "descriptive" for comparison in report["comparisons"])
    ranked = next(row for row in report["aggregates"] if row["arm"] == "rrf-bm25-luna-rerank")
    assert ranked["metrics"]["quality_q"] == "1"


def test_public_failure_and_stage_projection_never_copy_text() -> None:
    assert r.public_failure("private query text") == "unclassified_failure"
    assert r.public_failure("cross_encoder_failure") == "cross_encoder_failure"
    assert r.public_stages({"answer": {"latency_ms": 10, "cost_usd": "0.001", "text": "PRIVATE"},
                            "query": "PRIVATE"}) == {"answer": {"latency_ms": 10, "cost_usd": "0.001"}}


def test_ce_arms_require_identical_pools_and_truncation(tmp_path: Path) -> None:
    study, _, _, _ = answer_study(tmp_path)
    arm = next(arm for arm in study.arms if isinstance(arm, Rerank) and isinstance(arm.reranker, CrossEncoder))
    assert isinstance(arm, Rerank) and isinstance(arm.reranker, CrossEncoder)
    different = arm.model_copy(update={"name": "finetuned", "reranker": arm.reranker.model_copy(update={
        "query_token_cap": 127})})
    with pytest.raises(r.Refused, match="cross_encoder_contract_binding"):
        r.supported(study.model_copy(update={"arms": (*study.arms, different)}))


def test_public_stages_normalizes_exponent_decimal_costs() -> None:
    # Coordinator regression (G0.4b PG run): the ledger's exact zero serializes as "0E-8".
    from policyops_evals.qa_studies.runner import Refused, public_stages

    assert public_stages({"judge": {"latency_ms": 5, "cost_usd": "0E-8"}})["judge"]["cost_usd"] == "0.00000000"
    exact = public_stages({"answer": {"latency_ms": None, "cost_usd": "0.00012340"}})
    assert exact["answer"]["cost_usd"] == "0.00012340"
    for bad in ("-1", "NaN", "Infinity", "1e400000", "abc"):
        try:
            public_stages({"answer": {"latency_ms": None, "cost_usd": bad}})
        except Refused:
            continue
        raise AssertionError(bad)


def test_v2_envelopes_and_supported_none_effort(tmp_path: Path) -> None:
    from policyops.providers.serialize import prepare

    v1 = load_study(CONFIG)
    study = load_study(CONFIG.with_name("g1-dev-answers-v2.json"))
    assert study.study_id != v1.study_id
    assert study.schedule == v1.schedule
    assert study.judge is not None and v1.judge is not None
    assert study.judge.selection_receipt_sha256 == v1.judge.selection_receipt_sha256
    assert study.judge.test_report_sha256 == v1.judge.test_report_sha256
    assert study.judge.max_input_tokens == 6500
    r.supported(study)
    for arm in study.arms:
        assert isinstance(arm, (AnswerGeneration, Rerank, ClosedBook))
        assert arm.max_claims == 4 and arm.generator is not None
        assert arm.generator.effort == "none" and arm.generator.max_output_tokens == 1024
        request = a.request("user: refunds?", (), max_claims=4, max_output=1024)
        wire = json.loads(prepare(request, r.composition_configuration(study, arm.generator), "agent").body)
        assert wire["reasoning"] == {"effort": "none"} and wire["max_output_tokens"] == 1024
        if isinstance(arm, Rerank) and arm.reranker.kind == "luna":
            model = arm.reranker.model
            assert model.effort == "none" and model.max_output_tokens == 1024
    plan = preflight(study)
    assert plan["within_caps"] and Decimal(plan["ceiling_usd"]) == Decimal("10.868392")
    assert study.execution.cumulative_caps.usd == Decimal(plan["ceiling_usd"]) <= 12
    assert plan["planned_calls"] == plan["planned_counts"] == 11800
    assert plan["input_token_envelope"] == 75219600 and plan["output_token_envelope"] == 7168000
    synthetic, _, receipt, _ = answer_study(tmp_path)
    assert synthetic.judge is not None
    assert a.selected_judge(synthetic.judge.model_copy(update={"max_input_tokens": 6500}), receipt) == judges.ARMS[1]
    with pytest.raises(a.AnswerError, match="judge_selection_binding"):
        a.selected_judge(synthetic.judge.model_copy(update={"max_input_tokens": 10001}), receipt)


@pytest.mark.parametrize("role", ["answer", "rerank"])
@pytest.mark.parametrize(("outcome", "stop", "code"), [("truncated", "max_output_tokens", "output_limit"),
    ("truncated", "content_filter", "call_failed"), ("failed", None, "call_failed")])
def test_paid_output_limit_has_closed_code(role: str, outcome: str, stop: str | None, code: str,
                                          tmp_path: Path, memory: Memory, monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.budget.ledger import EvalBinding
    from policyops.persistence.evaluation import EvaluationClaimToken
    from policyops.providers.calls import AttemptRecord, CallReport
    from policyops_contracts.model import ModelResult, ReportedUsage

    study, inputs, _, _ = answer_study(tmp_path)
    item = r.schedule(study, inputs)[0]
    token = EvaluationClaimToken(item.id, uuid4(), EvalBinding(memory.scope, uuid4(), uuid4()), 7)
    executor = r.AnswerExecutor(study, memory.repository(), memory.scope, token, item, r.SharedUsage(),
                                lambda: cast(Providers, None), lambda _: None)
    monkeypatch.setattr(executor, "ledger", lambda *args: cast(Any, object()))
    monkeypatch.setattr(executor, "cost", lambda *args: "0.001")
    report = CallReport(ModelResult(provider="openai", requested_model="gpt-6-luna", outcome=cast(Any, outcome),
        stop_reason=stop, usage=ReportedUsage(state="known", input_total=100, cache_read=0, output=256,
                                             reasoning=199)), "result", None,
        [AttemptRecord(uuid4(), role + "/0", None, fate="settled")])
    monkeypatch.setattr(r, "call_sync", lambda *args, **kwargs: report)
    state = r.AnswerState()
    arm = study.arms[0]
    assert isinstance(arm, AnswerGeneration)
    with pytest.raises(r.Refused, match="^" + role + "_" + code + "$"):
        executor.paid(role, arm.generator, a.request("user", (), max_claims=4, max_output=1024), state, 1e20)
    assert len(state.audit) == 1 and state.stage_cost_usd[role] == "0.001"
    assert r.public_failure(role + "_" + code) == role + "_" + code


@pytest.mark.parametrize("failure", ["answer", "judge", "rerank", "retrieval"])
def test_stage_failure_preserves_only_completed_ranking(failure: str, tmp_path: Path, memory: Memory,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, receipt, source = answer_study(tmp_path)
    install_paid(monkeypatch, memory, failing_judge=failure == "judge",
                 failing_role=failure if failure in {"answer", "rerank"} else None)
    if failure == "retrieval":
        def refuse(*args: Any, **kwargs: Any) -> tuple[str, ...]:
            raise r.Refused("lexical_query_too_many_lexemes")
        monkeypatch.setattr(Candidates, "execute", refuse)
    execute_answers(study, inputs, receipt, source, memory)
    public = r.export(study, r.schedule(study, inputs), memory.repository(),
                      {arm.name: run_id(study, memory.scope, arm.name) for arm in study.arms})
    rows = [row for row in public["slots"] if row["arm"] == "rrf-bm25-luna-rerank"]
    complete = failure in {"answer", "judge"}
    for row in rows:
        assert row["outcome"] == "error" and row["metrics"]["quality_q"] == "0"
        assert row["metrics"]["recall_at_5"] == ("1" if complete else "0")
        assert (row["metrics"]["ndcg_at_10"] != "0") == complete
        assert row["metric_failures"]["recall_at_5"] is not complete
        assert row["metric_failures"]["citation_precision"] is True
        assert row["metrics"]["citation_precision"] == "0"
    report = r.report(study, inputs, public, memory.repository(), memory.scope, source)
    aggregate = next(row for row in report["aggregates"] if row["arm"] == "rrf-bm25-luna-rerank")
    assert aggregate["metrics"]["recall_at_5"] == ("1" if complete else "0")
    assert aggregate["metric_failed_counts"]["ndcg_at_10"] == (0 if complete else 2)
    assert aggregate["metric_failed_counts"]["quality_q"] == 2
    if failure == "retrieval":
        assert aggregate["failure_counts"]["lexical_query_too_many_lexemes"] == 2
    if failure == "answer":
        # CE fails at rerank; the RRF reference completes retrieval before its
        # answer fails. Both ordinary and decision intervals retain that score.
        comparison = next(c for c in report["comparisons"] if c["name"] == "ce-v-rrf-ndcg")
        assert comparison["point"] == "-1"
        assert Decimal(comparison["result"]["adjusted_lower"]) == -1
        assert comparison["result"]["observations"][1]["failed"] == 0
    directory = r.directory_for(study)
    artifacts = [json.loads(p.read_bytes()) for p in directory.parent.parent.rglob("*.json")
                 if p.stem in {row["slot_id"] for row in rows}]
    assert len(artifacts) == 2
    assert all(bool(p["ranked_passage_ids"]) == complete for p in artifacts)


@pytest.mark.parametrize(("citations", "code", "precision", "recall", "integrity"), [
    ([], "uncited_answer", "0", "0", "1"),
    (["md2d.p/" + "c" * 64], "undelivered_citation", "0", "0", "0"),
    ([P, "md2d.p/" + "c" * 64], "undelivered_citation", "1", "1", "0")])
def test_citation_quality_outcomes_complete_without_judging(citations: list[str], code: str, precision: str,
        recall: str, integrity: str, tmp_path: Path, memory: Memory, monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, receipt, source = answer_study(tmp_path)
    seen = install_paid(monkeypatch, memory, answer_payload=json.dumps({"answer": "Can you clarify?",
        "citations": citations, "abstain": False}))
    execute_answers(study, inputs, receipt, source, memory)
    assert all(role != "judge" for _, role, _ in seen)
    public = r.export(study, r.schedule(study, inputs), memory.repository(),
                      {arm.name: run_id(study, memory.scope, arm.name) for arm in study.arms})
    rows = [row for row in public["slots"] if row["arm"] == "dense-history-luna"]
    for row in rows:
        assert row["outcome"] == "success" and row["outcome_code"] == code and row["failure_code"] is None
        assert row["metrics"]["quality_q"] == "0"
        assert row["metrics"]["citation_precision"] == precision
        assert row["metrics"]["citation_recall"] == recall
        assert row["metrics"]["citation_integrity"] == integrity
        assert not any(row["metric_failures"].values())
    report = r.report(study, inputs, public, memory.repository(), memory.scope, source)
    aggregate = next(row for row in report["aggregates"] if row["arm"] == "dense-history-luna")
    assert aggregate["outcome_counts"][code] == 2 and aggregate["failed_or_missing"] == 0
    assert aggregate["latency"]["p95"]["censored_count"] == 0
