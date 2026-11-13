"""Hand-computed estimands and pinned deterministic task-cluster resampling."""

from decimal import Decimal
from fractions import Fraction as F

import pytest

from policyops_evals.studies import statistics as s


@pytest.mark.parametrize(("success", "n", "k", "expected"), [
    (3, 4, 1, F(3, 4)), (3, 4, 2, F(1, 2)), (3, 4, 4, F(0)),
    (4, 5, 4, F(1, 5)), (4, 4, 4, F(1)),
])
def test_unbiased_all_k_success(success: int, n: int, k: int, expected: F) -> None:
    assert s.reliability(success, n, k) == expected


def test_macro_and_paired_support() -> None:
    candidate = [[True] * 4, [True, True, False, False]]
    reference = [[True, True, False, False]] * 2
    for k, point, delta in ((1, .75, .25), (4, .5, .5)):
        assert s.analyze(["a", "b"], candidate, k, seed=7)["estimate"]["point"] == point
        assert s.paired(["a", "b"], candidate, reference, k, seed=7)["estimate"]["point"] == delta
    vectors = s.draws(2, 7, "support", 100)
    assert {sum((F(1, 2), F(0))[i] for i in draw) / 2 for draw in vectors} == {F(0), F(1, 4), F(1, 2)}


def test_missing_and_all_error_denominators() -> None:
    outcome = [[True, True, False, None]]
    for k, strict, complete in ((1, .5, .66666667), (2, .16666667, .33333333), (4, 0, None)):
        assert s.analyze(["a"], outcome, k, seed=7)["estimate"]["point"] == strict
        result = s.analyze(["a"], outcome, k, seed=7, complete_case=True)
        assert (None if result["estimate"] is None else result["estimate"]["point"]) == complete
    assert s.analyze(["a"], [[None] * 4], 1, seed=7)["estimate"]["point"] == 0
    assert s.analyze(["a"], [[None] * 4], 1, seed=7, complete_case=True)["estimate"] is None
    assert s.analyze([], [], 1, seed=7)["estimate"] is None


def test_complete_case_macro_and_paired_intersection() -> None:
    # Macro = (1 + 1/3)/2, not the pooled 2/4.
    assert s.analyze(["a", "b"], [[True, None, None], [True, False, False]], 1,
                     seed=7, complete_case=True)["estimate"]["point"] == .66666667
    a = [[True, True, False, None], [True, None, None, None]]
    b = [[False, None, True, True], [None, True, None, None]]
    result = s.paired(["a", "b"], a, b, 1, seed=7, complete_case=True)
    assert result["eligible_tasks"] == result["excluded_tasks"] == 1
    assert result["estimate"]["point"] == 0  # common slots 0,2; both 1/2
    assert result["candidate_support"][0]["scored"] == 2


def test_r7_identical_pairs_and_strict_margin() -> None:
    assert s.r7([F(i) for i in range(4)], F(1, 40)) == F(3, 40)
    assert s.r7([F(i) for i in range(4)], F(39, 40)) == F(117, 40)
    values = [[True] * 4, [False] * 4]
    assert s.paired(["a", "b"], values, values, 4, seed=7)["estimate"]["ci"] == [0, 0]
    args = {"registered": True, "complete": True, "integrity": True, "accounting": True, "cheaper": True}
    assert s.decision([F(-1, 10)], Decimal("0.10"), **args) == "inconclusive"
    assert s.decision([F(0)], Decimal("0.10"), **args) == "candidate_noninferior_and_cheaper"
    assert s.decision([F(0)], Decimal("0.10"), **(args | {"complete": False})) == "descriptive"


def test_golden_draw_encoding() -> None:
    assert s.draws(3, 20261112, "golden", 4) == GOLDEN


GOLDEN = ((2, 0, 2), (1, 1, 1), (0, 2, 0), (2, 0, 2))


@pytest.mark.parametrize(("n", "k"), [(0, 1), (4, 5), (33, 1)])
def test_unsupported_support(n: int, k: int) -> None:
    with pytest.raises(ValueError):
        s.reliability(0, n, k)


def test_bounded_workload_refusal() -> None:
    with pytest.raises(ValueError):
        s.draws(129, 7, "scope")
    with pytest.raises(ValueError):
        s.draws(3, 7, "scope", 10001)
    with pytest.raises(ValueError):
        s.interval([F(1)] * 129, [str(i) for i in range(129)], seed=7, kind="strict")
