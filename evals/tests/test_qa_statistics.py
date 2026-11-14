"""Whole-dialogue ratios, exact enumeration, strict missingness and QA gates."""
from collections.abc import Iterator
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction as F
from itertools import product

import pytest

from policyops_evals.qa_studies import statistics as stats
from policyops_evals.qa_studies.config import QAStudy
from policyops_evals.qa_studies.metrics import Measurement, retrieval_metrics
from policyops_evals.qa_studies.registration import ComparisonResult, JudgeResult, comparison_status
from policyops_evals.qa_studies.statistics import QuestionObservation as O
from policyops_evals.studies.statistics import r7

from .test_qa_study_config import answer_body
from .test_qa_study_registration import SCOPE, SOURCE, MemoryRepository, bound


def test_same_seed_identical_and_reordering_invariant() -> None:
    a, b, clusters = [F(1), None, F(1, 2)], [F(0), F(1), F(0)], ["a", "a", "b"]
    first = stats.paired_difference(a, b, clusters, seed=42)
    assert first == stats.paired_difference(a, b, clusters, seed=42)
    assert first == stats.paired_difference(a[::-1], b[::-1], clusters[::-1], seed=42)
    assert first.point == F(1, 6) and first.replicates == 10000
    assert first.low is not None and first.high is not None and first.adjusted_bound is not None
    assert first.adjusted_bound <= first.low <= first.point <= first.high
    # Distinct seeded streams, independently of possible equal interval endpoints.
    frame = ("a", "b", "c")
    assert list(stats._draws(frame, 42, 5)) != list(stats._draws(frame, 43, 5))


def test_exact_small_case_enumeration(monkeypatch: pytest.MonkeyPatch) -> None:
    def exhaustive(frame: tuple[str, ...], seed: int, replicates: int) -> Iterator[tuple[int, ...]]:
        assert frame == ("a", "b") and replicates == 4
        yield from product(range(2), repeat=2)

    monkeypatch.setattr(stats, "_draws", exhaustive)
    # Cluster a: one positive question. Cluster b: three negative questions.
    # Draw aa=1, ab=ba=1/4, bb=0. Exact point is 1/4, NOT mean(1,0)=1/2.
    result = stats.paired_difference([F(1), F(0), F(0), F(0)], [None] * 4, ["a", "b", "b", "b"],
                                     seed=7, replicates=4)
    population = [F(0), F(1, 4), F(1, 4), F(1)]
    assert result.point == F(1, 4)
    assert result.low == F(3, 160) == r7(population, F(1, 40))
    assert result.high == F(151, 160) == r7(population, F(39, 40))
    assert result.adjusted_bound == F(3, 320)


def test_cost_ratio_of_totals_not_mean_of_question_or_dialogue_ratios() -> None:
    result = stats.cluster_ratio([F(1), F(9), F(9)], [F(10), F(10), F(10)], ["a", "b", "b"], seed=0)
    assert result.point == F(19, 30)  # dialogue ratio mean would be .5
    result = stats.cluster_ratio([F(1), F(9)], [F(1), F(100)], ["a", "b"], seed=0, direction="upper")
    assert result.point == F(10, 101)  # mean question ratios would be .545
    assert result.adjusted_bound == 1 and result.low == F(9, 100)


def test_strict_missing_values_stay_in_denominator() -> None:
    result = stats.paired_difference([F(1), None, None], [None, F(1), None], ["a"] * 3, seed=0)
    assert result.point == result.low == result.high == result.adjusted_bound == 0
    assert result.n == 3
    assert stats.paired_difference([None], [None], ["a"], seed=0).point == 0


def test_more_than_128_clusters_and_maximum_question_frame() -> None:
    n = 2000
    result = stats.paired_difference([F(1)] * n, [None] * n, [str(i) for i in range(n)], seed=0, replicates=2)
    assert result.point == result.low == result.high == 1 and result.clusters == n
    result = stats.paired_difference([None] * 10000, [None] * 10000, ["a"] * 10000, seed=0, replicates=1)
    assert result.n == 10000 and result.point == 0


@pytest.mark.parametrize(("n", "clusters", "seed", "replicates"), [
    (10001, 1, 0, 1), (2001, 2001, 0, 1), (1, 1, -1, 1), (1, 1, 2147483648, 1),
    (1, 1, 0, 0), (1, 1, 0, 10001), (0, 0, 0, 1)])
def test_bootstrap_bounds(n: int, clusters: int, seed: int, replicates: int) -> None:
    with pytest.raises(ValueError, match="bounds"):
        stats.paired_difference([F(0)] * n, [None] * n, [str(i % clusters) for i in range(n)],
                                seed=seed, replicates=replicates)


def test_value_frame_and_alpha_refusals() -> None:
    for values in ([F(-1)], [F(2)], [F(1, 10**12 + 1)]):
        with pytest.raises(ValueError, match="bounds"):
            stats.paired_difference(values, [None], ["a"], seed=0)
    with pytest.raises(ValueError, match="mismatch"):
        stats.paired_difference([], [None], ["a"], seed=0)
    with pytest.raises(ValueError, match="alpha"):
        stats.cluster_ratio([F(1)], [F(1)], ["a"], seed=0, alpha=F(1, 10))
    with pytest.raises(ValueError, match="denominator"):
        stats.cluster_ratio([F(1)], [F(-1)], ["a"], seed=0)
    with pytest.raises(ValueError, match="bounds"):
        stats.binary_agreement([True], [True], [""], seed=0)


def test_undefined_ratios_never_drop_replicates() -> None:
    result = stats.cluster_ratio([F(1), F(1)], [F(0), F(1)], ["a", "b"], seed=0, direction="upper")
    assert result.point == 2 and result.undefined_replicates > 0
    assert result.low is result.high is result.adjusted_bound is None
    assert stats.cluster_ratio([F(0)], [F(0)], ["a"], seed=0).point is None


def test_agreement_hand_computed_kappa_and_confusion() -> None:
    # tn=4 fp=1 fn=2 tp=3; observed=.7, expected=.5; kappa=.4.
    gold = [False] * 5 + [True] * 5
    predictions = [False] * 4 + [True] + [False] * 2 + [True] * 3
    result = stats.binary_agreement(gold, predictions, ["doc"] * 10, seed=17)
    assert result.kappa == result.kappa_low == result.kappa_high == pytest.approx(0.4)
    assert result.balanced_accuracy == pytest.approx(0.7)
    assert result.per_class_recall == pytest.approx((0.8, 0.6))
    rate = result.false_pass_rate
    assert rate.point == rate.low == rate.high == pytest.approx(0.2)
    assert result.coverage == 1 and result.n == 10 and result.errors == 0
    assert result.confusion == stats.Confusion(4, 1, 2, 3, 0, 0)


def test_document_cluster_agreement_determinism_and_errors() -> None:
    gold = [False, True] * 4
    predictions: list[bool | None] = [False, True, True, True, False, False, None, None]
    clusters = ["a", "a", "b", "b", "c", "c", "d", "d"]
    result = stats.binary_agreement(gold, predictions, clusters, seed=9)
    assert result == stats.binary_agreement(gold, predictions, clusters, seed=9)
    assert result.per_class_recall == (0.5, 0.5)
    assert result.balanced_accuracy == F(1, 2) and result.coverage == F(3, 4) and result.errors == 2
    # Third prediction category: po=.5, pe=.375 -> kappa=.2.
    assert result.kappa == pytest.approx(0.2)
    assert result.false_pass_rate.point == F(1, 4)
    assert result.kappa_low is not None and result.kappa_high is not None


def test_all_errors_and_single_class_degeneracy() -> None:
    result = stats.binary_agreement([False, True], [None, None], ["a", "a"], seed=0)
    assert result.kappa == 0 and result.balanced_accuracy == 0 and result.errors == 2
    assert result.coverage == 0 and result.per_class_recall == (0.0, 0.0)
    result = stats.binary_agreement([False], [False], ["a"], seed=0)
    assert result.kappa is result.kappa_low is result.kappa_high is None
    assert result.balanced_accuracy is None and result.per_class_recall == (1.0, None)


def compound_fixture() -> tuple[QAStudy, MemoryRepository, list[str], list[str], JudgeResult]:
    body = answer_body(compound=True)
    body["schedule"]["cohorts"][0].update(question_count=20, dialogue_count=1)
    body["analysis"]["comparisons"][0]["required_questions"] = 20
    study, repository = bound(body)
    assert study.judge is not None
    judge = JudgeResult(selection_receipt_sha256=study.judge.selection_receipt_sha256, complete=True,
                        kappa=Decimal("0.6"), kappa_lower=Decimal("0.5"), false_pass=Decimal("0.1"))
    return study, repository, [f"q{i}" for i in range(20)], ["dialogue"] * 20, judge


@pytest.mark.parametrize(("losses", "cost", "latency", "ref_latency", "expected"), [
    (0, "0.8", "30", "20", "candidate_noninferior_and_cheaper"),
    (1, "0.8", "30", "20", "inconclusive"),  # Q lower bound exactly -.05
    (0, "0.800001", "30", "20", "inconclusive"),
    (0, "0.8", "30.000001", "21", "inconclusive"),
    (0, "0.8", "30", "19.999999", "inconclusive"),
    (0, "0.8", "15", "10", "candidate_noninferior_and_cheaper")])
def test_computed_result_decision_boundaries(losses: int, cost: str, latency: str, ref_latency: str,
                                            expected: str) -> None:
    study, repository, ids, clusters, judge = compound_fixture()
    a = [O(F(0) if i < losses else F(1), Measurement(Decimal(cost), Decimal(latency))) for i in range(20)]
    b = [O(F(1), Measurement(Decimal(1), Decimal(ref_latency)))] * 20
    result = stats.comparison_result(study, study.analysis.comparisons[0].name, ids, clusters, a, b,
                                    registration_sha256=study.registration_sha256, judge=judge)
    assert type(result) is ComparisonResult and result.adjusted_lower == -Decimal(losses) / 20
    assert result.cost_ratio_upper == Decimal(cost)
    assert comparison_status(study, result, repository.repository(), SCOPE, SOURCE) == expected


def test_result_failed_missing_integrity_unknown_cost_and_censoring() -> None:
    study, repository, ids, clusters, judge = compound_fixture()
    a: list[O | None] = [O(F(1), Measurement(Decimal("0.8"), Decimal(10)))] * 20
    b = [O(F(0), Measurement(Decimal(1), Decimal(20)))] * 20
    a[0] = None
    a[1] = O(F(1), Measurement(Decimal("0.8"), Decimal(30), "timeout"))
    a[2] = O(F(1), Measurement(None, Decimal(30), "error", Decimal("0.2")))
    a[3] = replace(b[0], integrity=False)
    result = stats.comparison_result(study, study.analysis.comparisons[0].name, ids, clusters, a, b,
                                    registration_sha256=study.registration_sha256, judge=judge)
    assert result.adjusted_lower == Decimal("0.8")  # four non-success slots
    assert result.observations[0].missing == 1 and result.observations[0].failed == 2
    assert not result.observations[0].integrity and not result.observations[0].accounting_settled
    assert result.cost_ratio_upper is None and result.candidate_p95_seconds is None
    assert comparison_status(study, result, repository.repository(), SCOPE, SOURCE) == "inconclusive"


def test_comparison_frame_refusal_and_zero_reference_cost() -> None:
    study, _, ids, clusters, _ = compound_fixture()
    rows = [O(F(0), Measurement(Decimal(0), Decimal(0)))] * 20
    with pytest.raises(ValueError, match="frame"):
        stats.comparison_result(study, study.analysis.comparisons[0].name, ["q"] * 20, clusters, rows, rows,
                                registration_sha256=study.registration_sha256)
    result = stats.comparison_result(study, study.analysis.comparisons[0].name, ids, clusters, rows, rows,
                                    registration_sha256=study.registration_sha256)
    assert result.cost_ratio_upper is None and result.reference_p95_seconds is None


def test_scale_bound_and_undefined_agreement_draws() -> None:
    values = [F(1, i) for i in range(1, 4000)]
    with pytest.raises(ValueError, match="scale bound"):
        stats.cluster_ratio(values, [F(1)] * len(values), ["a"] * len(values), seed=0)
    result = stats.binary_agreement([False, True], [False, True], ["a", "b"], seed=0)
    assert result.kappa == 1
    assert result.kappa_low is result.kappa_high is None  # single-class resamples retained as undefined


def test_default_replicates_above_128_clusters() -> None:
    result = stats.paired_difference([F(1)] * 129, [None] * 129, [str(i) for i in range(129)], seed=0)
    assert result.replicates == 10000 and result.point == result.adjusted_bound == 1


def test_ndcg_metrics_feed_bounded_bootstrap_directly() -> None:
    values = [retrieval_metrics(["x"] * i + ["a", "b"], ["a", "b", "c"]).ndcg_at_10 for i in range(10)]
    result = stats.paired_difference(values, [None] * 10, ["a"] * 10, seed=0)
    assert result.point == sum(values) / 10
    assert result.low == result.high == result.point
