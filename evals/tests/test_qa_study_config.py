"""Schema, bounded admission and compatibility for the independent QA contract."""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError
import pytest

from policyops_evals.cli import main
from policyops_evals.qa_studies.config import Arm, QAStudy, RetrievalOnly, load_study, preflight


EXAMPLE = Path(__file__).parents[1] / "qa_studies/g1-dev-example-v1.json"


def body() -> dict[str, Any]:
    result: dict[str, Any] = json.loads(EXAMPLE.read_bytes())
    return result


def parse(value: dict[str, Any]) -> QAStudy:
    return QAStudy.model_validate_json(json.dumps(value))


def model_binding() -> dict[str, Any]:
    return {"model": "gpt-6-luna", "effort": "low", "prompt_sha256": "1" * 64,
            "schema_sha256": "2" * 64, "max_input_tokens": 1000, "max_output_tokens": 100,
            "cache_policy": "none"}


def answer_body(*, compound: bool = False) -> dict[str, Any]:
    value = body()
    value["judge"] = model_binding() | {"selection_receipt_sha256": "3" * 64}
    value["execution"]["stages"] = [value["execution"]["stages"][0]]
    for arm in value["arms"]:
        arm["kind"] = "answer_generation"
        arm["generator"] = model_binding()
        arm["context"] = {"max_passages": 5, "evidence_tokens": 512,
                          "policy": "whole-passages-skip-overflow-v1"}
        for role in ("answer", "judge"):
            value["execution"]["stages"].append({"name": arm["name"] + "-" + role,
                "arm": arm["name"], "cohort": "dev", "role": role, "model": "gpt-6-luna",
                "planned_calls": 500, "planned_counts": 500, "max_input_tokens": 1000,
                "max_output_tokens": 100, "cache_policy": "none",
                "caps": deepcopy(value["execution"]["cumulative_caps"])})
    cap = value["execution"]["cumulative_caps"]
    cap.update(calls=10000, counts=10000, input_tokens=10_000_000, output_tokens=10_000_000)
    comparison = value["analysis"]["comparisons"][0]
    comparison["estimand"] = "quality_q"
    if compound:
        comparison.update(decision="noninferior_and_cheaper", margin="-0.05",
            compound={"cost_ratio_upper": "0.80", "latency_ratio_max": "1.5", "latency_seconds_max": "30"})
    return value


def test_example_and_cli_validate(capsys: pytest.CaptureFixture[str]) -> None:
    study = load_study(EXAMPLE)
    assert study.example and study.registration_sha256 is None
    assert main(["qa-study", "validate", "--study", str(EXAMPLE)]) == 0
    assert json.loads(capsys.readouterr().out)["registered"] is False
    assert preflight(study)["within_caps"]


@pytest.mark.parametrize("mode", ["any_terms", "bm25"])
def test_lexical_mode_default_preserves_digest_and_any_terms_is_explicit(mode: str) -> None:
    value = body()
    default = parse(value)
    for arm in default.arms:
        assert isinstance(arm, RetrievalOnly) and arm.retrieval.lexical_mode == "all_terms"
        assert "lexical_mode" not in arm.model_dump(mode="json")["retrieval"]
    for arm in value["arms"]:
        arm["retrieval"]["lexical_mode"] = "all_terms"
    explicit = parse(value)
    assert explicit.digest() == default.digest()
    assert explicit.arm_digest(explicit.arms[0]) == default.arm_digest(default.arms[0])
    value["arms"][0]["retrieval"]["lexical_mode"] = mode
    any_terms = parse(value)
    assert any_terms.digest() != default.digest()
    assert any_terms.arm_digest(any_terms.arms[0]) != default.arm_digest(default.arms[0])
    assert any_terms.arms[0].model_dump(mode="json")["retrieval"]["lexical_mode"] == mode
    value["arms"][0]["retrieval"]["lexical_mode"] = "raw_tsquery"
    with pytest.raises(ValidationError):
        parse(value)


def test_v2_dev_modes_baselines_and_conservative_preflight() -> None:
    path = EXAMPLE.with_name("g1-dev-retrieval-v2.json")
    study = load_study(path)
    assert study.purpose == "dev" and len(study.arms) == 8
    arms = {a.name: a.model_dump(mode="json")["retrieval"] for a in study.arms}
    assert all(arms[name]["lexical_mode"] == "any_terms" for name in arms if not name.endswith("-all"))
    assert {name for name in arms if name.endswith("-all")} == {"fts-history-all", "rrf-history-all"}
    assert all("lexical_mode" not in arms[name] for name in arms if name.endswith("-all"))
    pairs = {(c.candidate, c.reference) for c in study.analysis.comparisons}
    assert {("rrf-history-any", "dense-history"), ("rrf-last-any", "dense-last"),
            ("fts-history-any", "fts-history-all")} <= pairs
    admission = preflight(study)
    assert admission["within_caps"] and Decimal(admission["ceiling_usd"]) > 0


def test_v3_bm25_dev_pairs_and_preserved_dense_baselines() -> None:
    study = load_study(EXAMPLE.with_name("g1-dev-retrieval-v3.json"))
    previous = load_study(EXAMPLE.with_name("g1-dev-retrieval-v2.json"))
    assert study.purpose == "dev" and study.study_id != previous.study_id
    arms = {a.name: a.model_dump(mode="json")["retrieval"] for a in study.arms}
    assert set(arms) == {"bm25-history", "rrf-bm25-history", "bm25-last", "rrf-bm25-last",
                         "dense-history", "dense-last", "rrf-any-history", "any-history", "any-last"}
    assert all(arms[n]["lexical_mode"] == "bm25" for n in arms if "bm25" in n)
    for profile in ("history", "last"):
        assert arms[f"dense-{profile}"] == next(a for a in previous.arms if a.name == f"dense-{profile}").model_dump(
            mode="json")["retrieval"]
    assert {(c.candidate, c.reference) for c in study.analysis.comparisons} == {
        (f"{candidate}-{profile}", f"{baseline}-{profile}") for profile in ("history", "last")
        for candidate, baseline in (("rrf-bm25", "dense"), ("bm25", "any"))}
    assert all(a.retrieval.query_profile == ("history-four-v1" if a.name.endswith("history")
                                            else "last-user-turn-v1")
               for a in study.arms if isinstance(a, RetrievalOnly))
    admission = preflight(study)
    assert admission["within_caps"] and Decimal(admission["ceiling_usd"]) == Decimal("0.03522560")


def test_offline_cli_preflight_digest_and_example_registration_refusal(capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops_evals.qa_studies import registration

    def no_database() -> None:
        pytest.fail("offline/example command must not open the database")

    monkeypatch.setattr(registration, "environment_repository", no_database)
    for command in ("digest", "preflight"):
        assert main(["qa-study", command, "--study", str(EXAMPLE)]) == 0
        result = json.loads(capsys.readouterr().out)
        assert len(result["registration_payload_sha256"]) == 64
        if command == "preflight":
            assert result["planned_calls"] == result["planned_counts"] == 500
            assert Decimal(result["ceiling_usd"]) == Decimal("0.01024")
            assert result["authorizes_paid_execution"] is False
    assert main(["qa-study", "preflight", "--study", str(EXAMPLE), "--register"]) == 1
    assert "refused: ValueError" in capsys.readouterr().err


@pytest.mark.parametrize(("path", "replacement"), [
    (("unexpected",), 1), (("arms", 0, "unexpected"), 1),
    (("schedule", "cohorts", 0, "question_count"), 10001),
    (("schedule", "cohorts", 0, "question_count"), 0),
    (("schedule", "cohorts", 0, "question_count"), "500"),
    (("schedule", "cohorts", 0, "question_count"), True),
    (("schedule", "cohorts", 0, "dialogue_count"), 501),
    (("execution", "cumulative_caps", "usd"), "0.0000000000001"),
    (("execution", "cumulative_caps", "usd"), "NaN"),
    (("execution", "cumulative_caps", "usd"), 1.1),
    (("execution", "cumulative_caps", "usd"), "-1"),
    (("execution", "cumulative_caps", "usd"), "not-money"),
    (("execution", "cumulative_caps", "calls"), 1_000_001),
    (("execution", "retries"), 1), (("execution", "repairs"), 1),
    (("execution", "price_snapshot_id"), "latest"),
    (("analysis", "comparisons", 0, "alpha"), "0.05001"),
    (("analysis", "comparisons", 0, "alpha"), "0"),
    (("analysis", "comparisons", 0, "margin"), "0.01"),
    (("analysis", "comparisons", 0, "direction"), "reference-minus-candidate"),
    (("data", "corpus", "path"), "evals/../private.json"),
    (("data", "corpus", "path"), "C:/private.json"),
    (("data", "corpus", "sha256"), "A" * 64),
    (("purpose",), "holdout"),
])
def test_strict_schema(path: tuple[str | int, ...], replacement: Any) -> None:
    value = body()
    target: Any = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(ValidationError):
        parse(value)


def test_frozen_nested_models_and_no_money_float_coercion() -> None:
    study = parse(body())
    cap: Any = study.execution.cumulative_caps
    with pytest.raises(ValidationError):
        cap.usd = Decimal("10")
    assert isinstance(study.execution.cumulative_caps.usd, Decimal)


def test_alpha_allocation_and_equal_boundary() -> None:
    value = body()
    first = value["analysis"]["comparisons"][0]
    value["analysis"]["comparisons"] = [dict(first, name=f"claim-{i}") for i in range(4)]
    assert len(parse(value).analysis.comparisons) == 4
    value["analysis"]["comparisons"].append(dict(first, name="claim-4"))
    with pytest.raises(ValidationError, match="familywise"):
        parse(value)


def test_explicit_limits_above_twenty_thousand_but_bounded() -> None:
    value = body()
    value["execution"]["cumulative_caps"].update(calls=50000, counts=50000)
    assert parse(value).execution.cumulative_caps.calls == 50000


def test_tiny_preflight_is_hand_computed_and_caps_are_inclusive() -> None:
    value = answer_body()
    for cohort in value["schedule"]["cohorts"]:
        cohort.update(question_count=2, dialogue_count=1)
    value["analysis"]["comparisons"][0]["required_questions"] = 2
    for stage in value["execution"]["stages"]:
        stage.update(planned_calls=2, planned_counts=2)
    study = parse(value)
    plan = preflight(study)
    # Four chat stages * two calls * (1000*.10 + 100*.50)/1M
    # plus two query embeddings * 1024*.02/1M.
    assert plan["ceiling_usd"] == str(Decimal("0.00124096"))
    assert plan["planned_calls"] == plan["planned_counts"] == 10
    assert plan["input_token_envelope"] == 10048
    assert plan["output_token_envelope"] == 800
    value["execution"]["cumulative_caps"].update(usd="0.00124096", calls=10, counts=10,
        input_tokens=10048, output_tokens=800)
    assert preflight(parse(value))["within_caps"]
    value["execution"]["cumulative_caps"]["usd"] = "0.001240959999"
    assert not preflight(parse(value))["within_caps"]


def test_full_schedule_envelopes_and_artifact_capacity_cannot_be_understated() -> None:
    for field, replacement in (("planned_calls", 499), ("max_input_tokens", 999),
                               ("max_output_tokens", 99)):
        value = answer_body()
        value["execution"]["stages"][1][field] = replacement
        with pytest.raises(ValidationError, match="envelope"):
            parse(value)
    value = body()
    value["execution"]["artifact_max_observations"] = 999
    with pytest.raises(ValidationError, match="capacity"):
        parse(value)


def test_long_tier_and_cold_cache_are_conservative() -> None:
    value = body()
    value["execution"]["stages"].append({"name": "cache-probe", "arm": None, "cohort": None,
        "role": "cache_probe", "model": "gpt-6-luna", "planned_calls": 1, "planned_counts": 1,
        "max_input_tokens": 750000, "max_output_tokens": 512, "cache_policy": "30m",
        "caps": dict(value["execution"]["cumulative_caps"], input_tokens=750000)})
    plan = preflight(parse(value))
    assert Decimal(plan["stages"][1]["ceiling_usd"]) == Decimal("0.187884")


def test_duplicates_and_oversize_json_refused(tmp_path: Path) -> None:
    path = tmp_path / "spec.json"
    path.write_bytes(EXAMPLE.read_bytes().replace(b'"example": true', b'"example": true, "example": true'))
    with pytest.raises(ValueError, match="duplicate"):
        load_study(path)
    path.write_bytes(b" " * 2_000_001)
    with pytest.raises(ValueError, match="size"):
        load_study(path)


@pytest.mark.parametrize("kind", ["retrieval_only", "answer_generation", "luna_rerank", "ce_rerank",
                                  "cascade", "selective_rerank", "full_context", "closed_book"])
def test_arm_union_is_typed_and_discriminated(kind: str) -> None:
    retrieval = body()["arms"][0]["retrieval"]
    model = model_binding()
    context = {"max_passages": 5, "evidence_tokens": 512, "policy": "whole-passages-skip-overflow-v1"}
    luna = {"kind": "luna", "model": model, "excerpt_policy_sha256": "4" * 64}
    value: dict[str, Any] = {"kind": kind, "name": "arm"}
    if kind == "retrieval_only":
        value["retrieval"] = retrieval
    elif kind == "answer_generation":
        value.update(retrieval=retrieval, generator=model, context=context)
    elif kind in {"luna_rerank", "ce_rerank"}:
        ce = {"kind": "cross_encoder", "artifact_sha256": "4" * 64, "tokenizer_sha256": "5" * 64,
              "runtime_sha256": "6" * 64, "training_receipt_sha256": None, "candidate_pool_sha256": "7" * 64,
              "truncation_policy_sha256": "8" * 64, "max_length": 384, "query_token_cap": 128, "threads": 2}
        value.update(kind="rerank", retrieval=retrieval, generator=model, context=context,
                     reranker=luna if kind == "luna_rerank" else ce)
    elif kind in {"cascade", "selective_rerank"}:
        policy = ({"kind": "cascade", "first": model, "fallback": dict(model, model="claude-haiku-5-5"),
                   "first_context": context, "fallback_context": context, "confidence_threshold": "0.8",
                   "escalation_rule": "invalid-or-abstain-or-request-or-low-confidence-v1"}
                  if kind == "cascade" else {"kind": "selective_rerank", "reranker": luna,
                   "agreement_rule_sha256": "9" * 64, "generator": model, "context": context})
        value.update(kind="policy", retrieval=retrieval, policy=policy, selection_receipt_sha256="a" * 64)
    elif kind == "full_context":
        value.update(generator=model, context=dict(context, policy="complete-corpus-v1"),
                     corpus_render_sha256="b" * 64, exact_count_receipt=body()["data"]["corpus"])
    else:
        value["generator"] = model
    adapter: TypeAdapter[Arm] = TypeAdapter(Arm)
    assert adapter.validate_json(json.dumps(value)).name == "arm"
    value["invented_field"] = "no"
    with pytest.raises(ValidationError):
        adapter.validate_json(json.dumps(value))


def test_study_v2_retail_and_banking_behavior_unchanged() -> None:
    from policyops_evals.studies.config import StudyV3
    from policyops_evals.studies.config import load_study as load_retail
    from policyops_evals.studies.config import preflight as retail_preflight

    path = Path(__file__).parents[1] / "studies/e03-holdout-luna-haiku-v1.json"
    study = load_retail(path)
    assert isinstance(study, StudyV3)
    assert retail_preflight(study)["admission_ceiling_usd"] == "71.91040000"
    value = study.model_dump(mode="json")
    value["domain"] = "banking_knowledge"
    with pytest.raises(ValidationError, match="banking evaluator/eligibility contract unavailable"):
        StudyV3.model_validate_json(json.dumps(value))
