"""Deterministic citation, latency and cascade routing contracts."""
from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
import time
from typing import Any

import pytest

from policyops_evals.canonical import sha256_bytes
from policyops_evals.qa_studies import answers as a
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies.config import AnswerGeneration, QAStudy, load_study, preflight
from policyops_evals.qa_studies.registration import run_id

from .test_qa_answers import P2, P, answer_study, execute_answers, install_paid
from .test_qa_runner import Memory, memory
from .test_qa_study_config import parse


__all__ = ["memory"]


def test_dev_cascade_caps_match_four_claim_stage_demands() -> None:
    study = load_study(Path(__file__).parents[1] / "qa_studies/g2-dev-cascade-v1.json")
    assert study.execution.cumulative_caps.usd == Decimal("13.00")
    assert {getattr(arm, "max_claims", getattr(getattr(arm, "policy", None), "max_claims", None))
            for arm in study.arms} == {4}
    plan = preflight(study)
    assert plan["within_caps"] and Decimal(plan["ceiling_usd"]) == Decimal("12.78339200")
    assert plan["planned_calls"] == plan["planned_counts"] == 14800
    for stage in plan["stages"]:
        assert Decimal(stage["ceiling_usd"]) == Decimal(stage["caps"]["usd"])
        for key in ("calls", "counts", "input_tokens", "output_tokens"):
            assert stage[key] == stage["caps"][key]


def cascade_study(tmp_path: Path) -> tuple[QAStudy, r.Inputs, Path, dict[str, Any]]:
    study, inputs, receipt, source = answer_study(tmp_path)
    value = study.model_dump(mode="json")
    reference = value["arms"][0]
    reference["name"] = "reference"
    fallback = dict(reference["generator"], model="claude-haiku-5-5", effort="low")
    first = dict(reference["generator"], effort="none", max_input_tokens=2500, max_output_tokens=512,
        prompt_sha256=sha256_bytes(a.cascade_prompt(1).encode()), schema_sha256=a.CASCADE_SCHEMA_SHA256)
    policy = {"kind": "policy", "name": "cascade", "retrieval": reference["retrieval"],
        "policy": {"kind": "cascade", "first": first, "fallback": fallback,
            "first_context": dict(reference["context"], max_passages=2, evidence_tokens=1536),
            "fallback_context": reference["context"], "confidence_threshold": "0.8", "max_claims": 1,
            "escalation_rule": "invalid-or-abstain-or-request-or-low-confidence-v1"}}
    value["arms"] = [reference, policy]
    value["schedule"]["assignments"] = [{"arm": name, "cohort": "dev"} for name in ("reference", "cascade")]
    comparison = dict(value["analysis"]["comparisons"][0], name="cascade-v-reference", candidate="cascade",
        reference="reference", estimand="gold_citation", decision="noninferior_and_cheaper", margin="-0.05",
        compound={"cost_ratio_upper": "0.80", "latency_ratio_max": "1.5", "latency_seconds_max": "30"})
    value["analysis"]["comparisons"] = [comparison]
    stages = [s for s in value["execution"]["stages"] if s["arm"] is None]
    template = next(s for s in value["execution"]["stages"] if s["role"] == "answer")
    judge = next(s for s in value["execution"]["stages"] if s["role"] == "judge")
    for name in ("reference", "cascade"):
        models = [("answer", reference["generator"])] if name == "reference" else [
            ("answer.first", first), ("answer.fallback", fallback)]
        for role, model in models:
            stages.append(dict(template, name=name+"."+role, role=role, arm=name, model=model["model"],
                max_input_tokens=model["max_input_tokens"], max_output_tokens=model["max_output_tokens"]))
        stages.append(dict(judge, arm=name, name=name+".judge"))
    from policyops.budget.prices import SNAPSHOT_2026_11_05
    from policyops.budget.pricing import worst_case
    for stage in stages:
        n = 2 if stage["cohort"] is not None else stage["planned_calls"]
        stage.update(planned_calls=n, planned_counts=n)
        stage["caps"] = dict(usd=str(n * worst_case(SNAPSHOT_2026_11_05.price(stage["model"]),
            max_input=stage["max_input_tokens"], max_output=stage["max_output_tokens"], cache_mode="none")),
            calls=n, counts=n, input_tokens=n*stage["max_input_tokens"],
            output_tokens=n*stage["max_output_tokens"], seconds=max(300, n*60))
    value["execution"]["stages"] = stages
    return parse(value), inputs, receipt, source


@pytest.mark.parametrize(("changes", "failure", "reason"), [
    ({}, "answer.first_call_failed", "call_failed"),
    ({}, "answer.first_output_limit", "output_limit"),
    ({"confidence": "high"}, None, "schema_invalid"),
    ({"answer": "One. Two.", "escalate": True}, None, "too_many_claims"),
    ({"citations": [P2], "escalate": True}, None, "citation_integrity"),
    ({"citations": [], "escalate": True}, None, "uncited_answer"),
    ({"answer": "", "citations": [], "abstain": True, "escalate": True}, None, "abstained"),
    ({"escalate": True, "confidence": 0.1}, None, "requested"),
    ({"confidence": 0.799}, None, "low_confidence"),
    ({"confidence": 0.8}, None, None), ({"confidence": 1}, None, None)])
def test_ordered_escalation(changes: dict[str, Any], failure: str | None, reason: str | None) -> None:
    payload = dict(answer="Supported claim.", citations=[P], abstain=False, confidence=0.9, escalate=False)
    payload.update(changes)
    delivery = a.Delivery((a.Passage(P, "h", "evidence"),), (), (), 10)
    _, actual = a.escalation_reason(json.dumps(payload), delivery, threshold=0.8, max_claims=1, failure=failure)
    assert actual == reason


@pytest.mark.parametrize(("answer", "cited", "abstain", "failed", "expected"), [
    ("Claim.", [P], False, False, "1"), ("Claim.", [P2], False, False, "0"),
    ("Claim.", [], False, False, "0"), ("Claim.", [P, "unknown"], False, False, "0"),
    ("", [], True, False, "0"), ("Claim.", [P], False, True, "0")])
def test_gold_outcomes(answer: str, cited: list[str], abstain: bool, failed: bool, expected: str) -> None:
    study = load_study(Path(__file__).parents[1] / "qa_studies/g1-dev-answers-v2.json")
    state = r.AnswerState(ranking=(P, P2), ranking_complete=True,
        delivery=a.Delivery((a.Passage(P, "h", "x"), a.Passage(P2, "h", "y")), (), (), 10),
        answer=a.Answer(answer=answer, citations=cited, abstain=abstain))
    assert r.answer_metrics(state, study.arms[0], r.Gold((P,), "responding"), "", failed=failed)[
        "gold_citation"] == expected
    assert r.answer_metrics(state, study.arms[-1], r.Gold((P,), "responding"), "", failed=failed)[
        "gold_citation"] is None


@pytest.mark.parametrize("failure", [None, "judge", "answer"])
def test_policy_latency_and_gold_ignore_judge(failure: str | None, tmp_path: Path, memory: Memory,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, receipt, source = answer_study(tmp_path)
    install_paid(monkeypatch, memory, failing_judge=failure == "judge", failing_role=failure)
    execute_answers(study, inputs, receipt, source, memory)
    public = r.export(study, r.schedule(study, inputs), memory.repository(),
        {arm.name: run_id(study, memory.scope, arm.name) for arm in study.arms}, inputs)
    rows = [s for s in public["slots"] if s["arm"] == "dense-history-luna"]
    for row in rows:
        assert row["policy_latency_provenance"] == "measured"
        assert row["policy_latency_censored"] == (failure == "answer")
        assert (row["policy_latency_ms"] is not None) == (failure != "answer")
        assert row["metrics"]["gold_citation"] == ("0" if failure == "answer" else "1")
        assert row["metric_failures"]["gold_citation"] == (failure == "answer")
    report = r.report(study, inputs, public, memory.repository(), memory.scope, source)
    aggregate = next(s for s in report["aggregates"] if s["arm"] == "dense-history-luna")
    assert aggregate["policy_latency"]["p95"]["failed_count"] == (2 if failure == "answer" else 0)
    assert aggregate["latency"]["p95"]["censored_count"] == (0 if failure is None else 2)


def test_old_records_recompute_from_bound_private_artifacts(tmp_path: Path, memory: Memory,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, receipt, source = answer_study(tmp_path)
    install_paid(monkeypatch, memory, failing_judge=True)
    execute_answers(study, inputs, receipt, source, memory)
    from policyops_evals.studies.taxonomy import inventory
    found = inventory(r.directory_for(study))
    for identity, row in memory.rows.items():
        matches = [(digest, paths) for (name, digest), paths in found.items() if name == str(identity)+".json"]
        row["artifact_sha256"] = matches[0][0]
        row["components"].pop("citation_record")
        row["components"].pop("policy_latency_ms")
        row["components"]["metrics"].pop("gold_citation")
        row["components"]["metric_failures"].pop("gold_citation", None)
    public = r.export(study, r.schedule(study, inputs), memory.repository(),
        {arm.name: run_id(study, memory.scope, arm.name) for arm in study.arms}, inputs)
    rows = [s for s in public["slots"] if s["arm"] == "dense-history-luna"]
    assert all(s["metrics"]["gold_citation"] == "1" and not s["metric_failures"]["gold_citation"] for s in rows)
    assert all(s["policy_latency_ms"] == 1 and s["policy_latency_provenance"] == "derived-stage-sum" for s in rows)
    arm = study.arms[0]
    assert isinstance(arm, AnswerGeneration)
    assert r.stored_policy_latency({}, {"stage_latency_ms": {"answer": 10}}, complete=True, arm=arm)[0] is None


def test_existing_digests_are_unchanged() -> None:
    # Pins from the assigned clean base, independently of changed serializers.
    expected = {
        "g1-dev-answers-v1.json": {
            "study": "436c3ac608b0ae518b9a76d3a5ccbd8953278a6496c0365d85d084cfd43e3ba5",
            "arms": {
                "dense-history-luna": "7f9c01421e5597839acbff718f8848ac474d3d4ceb7c6efcbd01bf93c9e83f3e",
                "rrf-bm25-history-luna": "25a884dde875f81f405a0589a765a7c8f5ad135bd9e1507d86e1b549a1a5d288",
                "rrf-bm25-luna-rerank": "65cffd32d1c216234ce691f949c57a2fcceb629744f77d0d8015769cc0253a84",
                "rrf-bm25-base-ce": "5104c06a2a88857efb211a41c687c2769c41820a2114edd05f79417b49f96018",
                "closed-book-luna": "129a00935a8f301303fcc4e1e91e7adab30dd361272b13dc23cfdfadaf901b85"
            }
        },
        "g1-dev-answers-v2.json": {
            "study": "0a7de8461a0f804d25069ea4edad085d591ecd50b13edfaa277627497501d42c",
            "arms": {
                "dense-history-luna": "29196bd67165f42784095858988d61b53b4bde64ab6198e110e8b0213cd4680c",
                "rrf-bm25-history-luna": "e394891166fb385ab0977ca131d6103d9a1b2430d2e1f44293c1f337603bd5c4",
                "rrf-bm25-luna-rerank": "6c69e14c31605a2bc7608cf2102f007a375dc503265b8d65e3107c1db1ad42ef",
                "rrf-bm25-base-ce": "f472825e1466b00f4fb4399bd04a04807ae1b9ff6bd5f3621974b1264b8e4f2c",
                "closed-book-luna": "f930f61beec4fb3f85ecb851285b5c660403596ef791749f7d82eb819d645675"
            }
        },
        "g1-dev-example-v1.json": {
            "study": "d5586e13a5491f6ab706cfc49bdf9e796bba71c3ded864378a582c60646bc1c4",
            "arms": {
                "fts": "e0f837f85aed9139a195760eaa02dc4214d7957110a7c8305d433ab9d6f56026",
                "rrf": "7b70f8dabbc7255c9d69ea73c63bbf32c508fbc40fae1ff6a447916713865105"
            }
        },
        "g1-dev-retrieval-v1.json": {
            "study": "fe41e983fdd3fe94f69eb4d54d16a9187e4d9d85b844d13c0a5aad4b5b7319b9",
            "arms": {
                "fts-history": "7a5c44e602de15918003e3a17c288cee39c4eff258c32ee53e367cab9cc5a6df",
                "dense-history": "15096ed093a492db33fa7e074512716fe2516f7f41c43caacc7101d50af76613",
                "rrf-history": "04ac78da0fe313dd9fb064e8413e0a169138fcd49a2aff3a341b38d01fa5ad29",
                "fts-last": "428119ef0c15654f00c57794faacfe1c292b00b57e0dd4583250fd68a69bd71b",
                "dense-last": "cb1aa4e88abadde5f01ac977a55fd10a761ce494a1e4c337e828e23d7b0383d0",
                "rrf-last": "04a1d415d23722247683486685955378e1cb556567b5226a6bde60ada494cdcf"
            }
        },
        "g1-dev-retrieval-v2.json": {
            "study": "12de795f8a25b71e6b15394ebb7e5540d330f01035121c82316b2ba24278eccd",
            "arms": {
                "fts-history-any": "318d39bcd0fb523b0dbeca27ae3a1a5e99527aaa7f6146fadc6376bc62485b91",
                "dense-history": "40f6988366ba6fefe3d8cd00f2ed3564dcf5b11322bfd392fe235c935094690c",
                "rrf-history-any": "68265a6cabef31c8829dddcc89d19a1f2e010c0008b1df18c5b912d1687ab165",
                "fts-last-any": "a9e96af856c78aafde90d64e72158bee705c817f57bbbba82d099fe10c3e4af9",
                "dense-last": "cb485ebe7f6b4500e09ce7a185e7b26aca905a8168ae006523b3937562755b18",
                "rrf-last-any": "f8867631f43995d5dc017eeb4ba0d274ff4fd472792badfe35ee3f6037403005",
                "fts-history-all": "6cf3d8aac861d4aabaf6fcda554961f6a1ff863a1ef082350cdd7a6670881a5b",
                "rrf-history-all": "6b655c1b3cbf824a3ebc241e662364864523af3bc7faad548545bef41f4f778b"
            }
        },
        "g1-dev-retrieval-v3.json": {
            "study": "d3d02ff4a009be94cbde959a0c8fe0281e5e6354296a9125bf333b5fbd40a1ee",
            "arms": {
                "bm25-history": "e5e5c4858cbac1fc1fa7f76df28a566ac6d532912779775e278d6a74b21c022f",
                "rrf-bm25-history": "1037c3ff7cb53e0ed31251fce45bf6176e4480d9db7d54cbfd07519d23c0a362",
                "bm25-last": "1f4d56b8f3e5b8149772cd7e24edc9c90369184b5247c5197f9d7a5789e1f625",
                "rrf-bm25-last": "3537a26defc24bc86c09a88903cd3641d3526fa33991a8adab3dc56e090d7caf",
                "dense-history": "c6084b81a34fc989c33383e63a02635649b3b0a81117a46d79b318a903db9f4b",
                "dense-last": "d3ba2b61fca298d6adb82fd5f4186da1096b67e0ba2da222c7db23363a61ec30",
                "rrf-any-history": "56637a44499074f9fa99886020e9ca55f9e3739e1320e80854fae28a792a7f45",
                "any-history": "261145336332a0b21a63487e926333fb211be35387a0e586bb6a5e953a166fdf",
                "any-last": "e31d710254037ac43d4c3f416c0304daeab8b706c4a9561f9856b5467a75281c"
            }
        }
    }
    for name, digests in expected.items():
        study = load_study(Path(__file__).parents[1] / "qa_studies" / name)
        assert study.digest() == digests["study"]
        assert {a.name: study.arm_digest(a) for a in study.arms} == digests["arms"]


@pytest.mark.parametrize("estimand", ["gold_citation", "quality_q", "citation_recall", "recall_at_5", "ndcg_at_10"])
def test_compound_estimands(estimand: str, tmp_path: Path) -> None:
    study, _, _, _ = cascade_study(tmp_path)
    value = study.model_dump(mode="json")
    value["analysis"]["comparisons"][0]["estimand"] = estimand
    if estimand in {"gold_citation", "quality_q"}:
        assert parse(value).analysis.comparisons[0].margin == Decimal("-0.05")
    else:
        with pytest.raises(ValueError):
            parse(value)

@pytest.mark.parametrize("fail_fallback", [False, True])
def test_mixed_routes_final_answer_only_and_fallback_failure(tmp_path: Path, memory: Memory,
        monkeypatch: pytest.MonkeyPatch, fail_fallback: bool) -> None:
    study, inputs, receipt, source = cascade_study(tmp_path)
    install_paid(monkeypatch, memory)
    seen: list[tuple[str, str]] = []
    def paid(self: r.AnswerExecutor, role: str, model: Any, request: Any, state: r.AnswerState,
             deadline: float, index: int = 0) -> str:
        seen.append((self.item.question, role))
        state.stage_latency_ms[role] = 1
        state.stage_cost_usd[role] = "0"
        if role == "judge":
            assert ("FIRST ANSWER" in request.model_dump_json()) == (self.item.arm == "cascade"
                                                                  and self.item.question.endswith("/0"))
            state.verdicts.append(True)
            return '{"supported":true,"reason":"Supported."}'
        if role == "answer.first":
            assert model.model == "gpt-6-luna" and model.effort == "none"
            return json.dumps(dict(answer="FIRST ANSWER.", citations=[P], abstain=False,
                confidence=0.8 if self.item.question.endswith("/0") else 0.7, escalate=False))
        if role == "answer.fallback":
            assert model.model == "claude-haiku-5-5" and model.effort == "low"
            assert "FIRST ANSWER" not in request.model_dump_json()
            assert "chronological first" in request.model_dump_json()
            if fail_fallback:
                raise r.Refused("answer.fallback_call_failed")
        return json.dumps(dict(answer="FINAL ANSWER.", citations=[P], abstain=False))
    monkeypatch.setattr(r.AnswerExecutor, "paid", paid)
    execute_answers(study, inputs, receipt, source, memory)
    public = r.export(study, r.schedule(study, inputs), memory.repository(),
        {arm.name: run_id(study, memory.scope, arm.name) for arm in study.arms}, inputs)
    rows = [s for s in public["slots"] if s["arm"] == "cascade"]
    assert {s["route"] for s in rows} == {"first", "fallback"}
    fallback = next(s for s in rows if s["route"] == "fallback")
    assert fallback["escalation_reason"] == "low_confidence"
    assert fallback["failure_code"] == ("answer.fallback_call_failed" if fail_fallback else None)
    assert fallback["metrics"]["gold_citation"] == ("0" if fail_fallback else "1")
    assert fallback["policy_latency_censored"] == fail_fallback
    assert sum(role == "answer.first" for _, role in seen) == 2
    assert sum(role == "answer.fallback" for _, role in seen) == 1


@pytest.mark.parametrize("expired", [False, True])
def test_resume_settled_first_checkpoint_without_reissue(tmp_path: Path, memory: Memory,
        monkeypatch: pytest.MonkeyPatch, expired: bool) -> None:
    from collections.abc import Iterator
    from contextlib import contextmanager
    study, inputs, receipt, source = cascade_study(tmp_path)
    install_paid(monkeypatch, memory)
    calls: list[tuple[str, str]] = []
    def paid(self: r.AnswerExecutor, role: str, model: Any, request: Any, state: r.AnswerState,
             deadline: float, index: int = 0) -> str:
        key = str(self.item.id), role
        assert key not in calls
        calls.append(key)
        state.stage_latency_ms[role] = 1
        state.stage_cost_usd[role] = "0"
        if role == "judge":
            state.verdicts.append(True)
            return '{}'
        if role == "answer.first":
            return json.dumps(dict(answer="FIRST.", citations=[P], abstain=False, confidence=0.1, escalate=False))
        assert "FIRST." not in request.model_dump_json()
        return json.dumps(dict(answer="Final.", citations=[P], abstain=False))
    monkeypatch.setattr(r.AnswerExecutor, "paid", paid)
    def crash(at: str) -> None:
        if at == "cascade_first_checkpoint":
            raise SystemExit("process loss")
    with pytest.raises(SystemExit):
        execute_answers(study, inputs, receipt, source, memory, boundary=crash)
    checkpoint_path = next(r.directory_for(study).glob("*-cascade.json"))
    checkpoint = json.loads(checkpoint_path.read_bytes())
    slot_id = checkpoint["slot_id"]
    class Connection:
        sql = ""
        def execute(self, query: Any, *args: Any) -> Connection:
            self.sql = str(query)
            return self
        def scalar_one(self) -> Any:
            return True if "pg_locks" in self.sql else Decimal(0)
        def mappings(self) -> Connection:
            return self
        def one(self) -> dict[str, Any]:
            from uuid import UUID
            return dict(owner_token=UUID(checkpoint["owner"]), invocation_scope=UUID(checkpoint["invocation"]),
                        state="running")
        def all(self) -> list[dict[str, Any]]:
            return [{"operation_id": "qa/cascade.answer.first/frozen", "state": "settled"}]
    @contextmanager
    def tx(*args: Any) -> Iterator[Connection]:
        yield Connection()
    monkeypatch.setattr(r, "transaction", tx)
    if expired:
        now = time.time()
        monkeypatch.setattr(time, "time", lambda: now + study.execution.request_deadline_seconds + 1)
    assert execute_answers(study, inputs, receipt, source, memory, resume=True)["execution_complete"]
    assert calls.count((slot_id, "answer.first")) == 1
    assert calls.count((slot_id, "answer.fallback")) == (0 if expired else 1)
    assert memory.rows[next(identity for identity in memory.rows if str(identity) == slot_id)]["outcome"] == (
        "aborted" if expired else "success")


def test_compound_uses_observed_policy_latency_despite_judge_failure(tmp_path: Path, memory: Memory) -> None:
    study, inputs, _, source = cascade_study(tmp_path)
    slots = []
    for item in r.schedule(study, inputs):
        slots.append(dict(cohort=item.cohort, question_id=item.question, arm=item.arm, repetition=item.repetition,
            metrics={"gold_citation": "1"}, metric_failures={"gold_citation": False}, outcome="error",
            failure_code="invalid_judge_verdict", cost_usd="0.10", policy_cost_usd="0.01", held_liability_usd="0",
            latency_ms=100000, policy_latency_ms=1000 if item.arm == "cascade" else 2000,
            policy_latency_censored=False, policy_latency_provenance="measured"))
    report = r.report(study, inputs, {"slots": slots}, memory.repository(), memory.scope, source)
    result = report["comparisons"][0]["result"]
    assert Decimal(result["candidate_p95_seconds"]) == 1
    assert Decimal(result["reference_p95_seconds"]) == 2
    assert report["comparisons"][0]["point"] == "0"
    assert all(a["policy_latency"]["p95"]["failed_count"] == 0 for a in report["aggregates"])
    assert all(a["latency"]["p95"]["censored_count"] == 2 for a in report["aggregates"])


@pytest.mark.parametrize("failures", [1, 2])
def test_report_policy_failure_as_worst(tmp_path: Path, memory: Memory, failures: int) -> None:
    study, inputs, _, source = cascade_study(tmp_path)
    query = next(iter(inputs.queries.values()))
    gold = next(iter(inputs.gold.values()))
    ids = tuple(f"q{i:02d}" for i in range(20))
    inputs = replace(inputs, queries=dict.fromkeys(ids, query), gold=dict.fromkeys(ids, gold), cohorts={"dev": ids})
    raw = study.model_dump(mode="json")
    raw["schedule"]["cohorts"][0].update(question_count=20)
    raw["analysis"]["comparisons"][0]["required_questions"] = 20
    for stage in raw["execution"]["stages"]:
        if stage["cohort"] is not None:
            stage.update(planned_calls=20, planned_counts=20)
            stage["caps"] = {key: str(Decimal(value) * 10) if key == "usd" else value * 10
                             for key, value in stage["caps"].items()}
    study = parse(raw)
    slots = []
    for item in r.schedule(study, inputs):
        failed = item.arm == "cascade" and ids.index(item.question) < failures
        slots.append(dict(cohort=item.cohort, question_id=item.question, arm=item.arm, repetition=item.repetition,
            metrics={"gold_citation": "1"}, metric_failures={"gold_citation": False}, outcome="error",
            failure_code="unavailable_policy_timing" if failed else "invalid_judge_verdict",
            cost_usd="0.10", policy_cost_usd="0.01", held_liability_usd="0", latency_ms=100000,
            policy_latency_ms=None if failed else 1000, policy_latency_censored=failed,
            policy_latency_provenance="derived-stage-sum"))
    report = r.report(study, inputs, {"slots": slots}, memory.repository(), memory.scope, source)
    aggregate = next(a for a in report["aggregates"] if a["arm"] == "cascade")
    p95 = aggregate["policy_latency"]["p95"]
    assert p95 == {"seconds": "1" if failures == 1 else None, "n": 20, "failed_count": failures}
    assert aggregate["policy_latency_rule"] == "failure-as-worst-v1"
    assert aggregate["latency"]["p95"]["seconds"] is None
    assert report["comparisons"][0]["result"]["candidate_p95_seconds"] == p95["seconds"]
    assert report["comparisons"][0]["policy_latency_failed_counts"] == {"cascade": failures, "reference": 0}
    assert any("failure-as-worst-v1" in item for item in report["limitations"])


@pytest.mark.parametrize("value", [None, "0" * 64])
def test_dev_selection_receipt_optional_but_sealed_required(tmp_path: Path, value: str | None) -> None:
    study, _, _, _ = cascade_study(tmp_path)
    raw = study.model_dump(mode="json")
    raw["arms"][1]["selection_receipt_sha256"] = value
    assert parse(raw).arms[1].kind == "policy"
    raw["purpose"] = "sealed_test"
    raw["schedule"]["cohorts"][0]["split"] = "validation"
    if value is None:
        with pytest.raises(ValueError, match="selection receipt"):
            parse(raw)
    else:
        with pytest.raises(ValueError, match="absent from provenance"):
            parse(raw)
        raw["provenance"]["development_selection_receipts"] = [value]
        assert parse(raw).purpose == "sealed_test"



def test_gold_quality_survives_unavailable_policy_latency(tmp_path: Path, memory: Memory) -> None:
    study, inputs, _, source = cascade_study(tmp_path)
    slots = []
    for item in r.schedule(study, inputs):
        slots.append(dict(cohort=item.cohort, question_id=item.question, arm=item.arm, repetition=item.repetition,
            metrics={"gold_citation": "1" if item.arm == "cascade" else "0"},
            metric_failures={"gold_citation": False}, outcome="error", failure_code="invalid_judge_verdict",
            cost_usd="0.10", policy_cost_usd="0.01", held_liability_usd="0", latency_ms=100000,
            policy_latency_ms=None, policy_latency_censored=True, policy_latency_provenance="derived-stage-sum"))
    report = r.report(study, inputs, {"slots": slots}, memory.repository(), memory.scope, source)
    comparison = report["comparisons"][0]
    assert comparison["point"] == "1" and Decimal(comparison["result"]["adjusted_lower"]) == 1
    assert comparison["result"]["candidate_p95_seconds"] is None
    assert all(s["failed"] == 0 for s in comparison["result"]["observations"])
