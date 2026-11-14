"""Comparison-specific decision gates and exact accepted boundary inequalities."""

from __future__ import annotations

from decimal import Decimal
import json
from typing import Any

from pydantic import ValidationError
import pytest

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import registration as reg
from policyops_evals.qa_studies.config import QAStudy

from .test_qa_study_config import answer_body
from .test_qa_study_registration import SCOPE, SOURCE, MemoryRepository, bound


def result_body(study: QAStudy) -> dict[str, Any]:
    comparison = study.analysis.comparisons[0]
    n = comparison.required_questions * study.schedule.repetitions
    return {"comparison": comparison.name, "specification_sha256": study.digest(),
        "registration_sha256": study.registration_sha256,
        "analysis_sha256": sha256_bytes(canonical_bytes(study.analysis.model_dump(mode="json"))),
        "missingness": "strict-non-success", "adjusted_alpha": str(comparison.alpha),
        "adjusted_lower": "0.01", "cost_ratio_upper": "0.80", "candidate_p95_seconds": "30",
        "reference_p95_seconds": "20", "observations": [
            {"arm": a, "scheduled": n, "recorded": n, "failed": 0, "missing": 0,
             "integrity": True, "accounting_settled": True, "held_liability_usd": "0"}
            for a in (comparison.candidate, comparison.reference)],
        "judge": None if study.judge is None else {"selection_receipt_sha256": study.judge.selection_receipt_sha256,
            "complete": True, "kappa": "0.6", "kappa_lower": "0.40001", "false_pass": "0.10"}}


def status(study: QAStudy, repository: MemoryRepository, result: dict[str, Any]) -> reg.Status:
    validated = reg.ComparisonResult.model_validate_json(json.dumps(result))
    return reg.comparison_status(study, validated, repository.repository(), SCOPE, SOURCE)


@pytest.mark.parametrize(("lower", "expected"), [("0", "inconclusive"), ("-0.00001", "inconclusive"),
                                                  ("0.00001", "candidate_superior")])
def test_superiority_lower_bound_is_strict(lower: str, expected: str) -> None:
    study, repository = bound()
    result = result_body(study)
    result["adjusted_lower"] = lower
    assert status(study, repository, result) == expected


@pytest.mark.parametrize(("lower", "ratio", "expected"), [
    ("-0.05", "0.80", "inconclusive"), ("-0.05001", "0.79", "inconclusive"),
    ("-0.04999", "0.80", "candidate_noninferior_and_cheaper"),
    ("-0.04999", "0.80000001", "inconclusive"),
    ("-0.04999", None, "inconclusive")])
def test_compound_quality_exclusive_and_cost_inclusive(lower: str, ratio: str | None, expected: str) -> None:
    study, repository = bound(answer_body(compound=True))
    result = result_body(study)
    result.update(adjusted_lower=lower, cost_ratio_upper=ratio)
    assert status(study, repository, result) == expected


@pytest.mark.parametrize(("candidate", "reference", "expected"), [
    ("30", "20", "candidate_noninferior_and_cheaper"), ("30.00001", "21", "inconclusive"),
    ("30", "19.99999", "inconclusive"), (None, "20", "inconclusive"), ("20", None, "inconclusive")])
def test_compound_latency_boundaries(candidate: str | None, reference: str | None, expected: str) -> None:
    study, repository = bound(answer_body(compound=True))
    result = result_body(study)
    result.update(candidate_p95_seconds=candidate, reference_p95_seconds=reference)
    assert status(study, repository, result) == expected


@pytest.mark.parametrize(("field", "value"), [("integrity", False), ("accounting_settled", False),
                                               ("missing", 1), ("scheduled", 501)])
def test_complete_integrity_and_accounting_are_required(field: str, value: Any) -> None:
    study, repository = bound()
    result = result_body(study)
    observation = result["observations"][0]
    observation[field] = value
    if field == "missing":
        observation["recorded"] -= 1
    elif field == "scheduled":
        observation["recorded"] += 1
    assert status(study, repository, result) == "inconclusive"


def test_held_liability_blocks_decision_and_cannot_be_called_settled() -> None:
    study, repository = bound()
    result = result_body(study)
    result["observations"][0].update(accounting_settled=False, held_liability_usd="0.00000001")
    assert status(study, repository, result) == "inconclusive"
    result["observations"][0]["accounting_settled"] = True
    with pytest.raises(ValidationError, match="liability"):
        reg.ComparisonResult.model_validate_json(json.dumps(result))


@pytest.mark.parametrize(("field", "value"), [("complete", False), ("kappa", "0.59999"),
    ("kappa_lower", "0.4"), ("false_pass", "0.100001"), ("selection_receipt_sha256", "f" * 64)])
def test_judge_gate_boundaries(field: str, value: Any) -> None:
    study, repository = bound(answer_body())
    result = result_body(study)
    result["judge"][field] = value
    assert status(study, repository, result) == "descriptive"


def test_failed_observations_cannot_be_excluded_from_denominator() -> None:
    study, repository = bound()
    result = result_body(study)
    result["observations"][0]["failed"] = 1
    # Complete error observations remain in the strict scheduled denominator.
    assert status(study, repository, result) == "candidate_superior"
    result["missingness"] = "complete-case"
    with pytest.raises(ValidationError):
        reg.ComparisonResult.model_validate_json(json.dumps(result))
    result["missingness"] = "strict-non-success"
    result["observations"][0]["scheduled"] -= 1
    result["observations"][0]["recorded"] -= 1
    assert status(study, repository, result) == "inconclusive"


def test_unrelated_exploratory_arm_does_not_enter_comparison_gate() -> None:
    from .test_qa_study_config import body

    value = body()
    value["arms"].append(dict(value["arms"][0], name="exploratory"))
    value["schedule"]["assignments"].append({"arm": "exploratory", "cohort": "dev"})
    study, repository = bound(value)
    # Registered exploratory run can fail; this result has only the two named arms.
    extra_id = reg.run_id(study, SCOPE, "exploratory")
    repository.configs[extra_id]["exploratory_error"] = "failed"
    assert status(study, repository, result_body(study)) == "candidate_superior"


def test_dev_and_unregistered_are_descriptive() -> None:
    from .test_qa_study_config import body, parse

    study = parse(body())
    assert status(study, MemoryRepository(), result_body(study)) == "descriptive"


@pytest.mark.parametrize("field", ["specification_sha256", "analysis_sha256", "registration_sha256"])
def test_results_must_bind_exact_registration_and_analysis(field: str) -> None:
    study, repository = bound()
    result = result_body(study)
    result[field] = "f" * 64
    with pytest.raises(ValueError, match="binding"):
        status(study, repository, result)


def test_results_cannot_substitute_an_unadjusted_interval() -> None:
    study, repository = bound()
    result = result_body(study)
    result["adjusted_alpha"] = str(Decimal("0.05"))
    with pytest.raises(ValueError, match="binding"):
        status(study, repository, result)
