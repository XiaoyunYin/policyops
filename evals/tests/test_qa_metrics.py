"""Hand-computed retrieval, citation, lexical and resource-accounting metrics."""
from decimal import Decimal, localcontext
from fractions import Fraction as F
from math import log2

import pytest

from policyops_evals.qa_studies.metrics import (
    Citation,
    Measurement,
    answerable_false_abstention_rate,
    citation_metrics,
    cost_per_question,
    latency_percentile,
    lexical_metrics,
    quality_q,
    retrieval_metrics,
    tokenize,
)


def test_multi_qrel_ranked_metrics() -> None:
    m = retrieval_metrics(["x", "a", "y", "b", "z", "c"], ["a", "b", "c", "d"])
    assert (m.recall_at_1, m.recall_at_5, m.recall_at_10) == (F(0), F(1, 2), F(3, 4))
    assert (m.hit_at_1, m.hit_at_5, m.hit_at_10) == (False, True, True)
    assert m.mrr_at_10 == F(1, 2)
    assert m.ndcg_at_10 == pytest.approx(
        (1 / log2(3) + 1 / log2(5) + 1 / log2(7)) / sum(1 / log2(i) for i in range(2, 6)))


def test_rank_cutoff_duplicates_and_frozen_tie_order() -> None:
    m = retrieval_metrics(["a", "a", "b"], ["a", "b", "b"])
    assert m.recall_at_1 == F(1, 2) and m.recall_at_5 == 1
    assert m.ndcg_at_10 == pytest.approx((1 + 1 / log2(4)) / (1 + 1 / log2(3)))
    # Tied scores are resolved upstream; metrics preserve the supplied order.
    assert retrieval_metrics(["x", "a"], ["a"]).mrr_at_10 == F(1, 2)
    assert retrieval_metrics(["a", "x"], ["a"]).mrr_at_10 == 1
    m = retrieval_metrics(["x"] * 10 + ["a"], ["a"])
    assert m.recall_at_10 == m.mrr_at_10 == m.ndcg_at_10 == 0


@pytest.mark.parametrize(("ranked", "gold", "error"), [([], ["a"], False), (["a"], ["a"], True), (["a"], [], False)])
def test_empty_and_error_retrieval(ranked: list[str], gold: list[str], error: bool) -> None:
    m = retrieval_metrics(ranked, gold, error=error)
    assert m.recall_at_1 == m.recall_at_5 == m.recall_at_10 == m.mrr_at_10 == m.ndcg_at_10 == 0
    assert not (m.hit_at_1 or m.hit_at_5 or m.hit_at_10)


def test_unique_valid_citations_and_separate_integrity() -> None:
    m = citation_metrics([Citation("a"), Citation("a"), Citation("x"), Citation("b", offsets_valid=False),
                          Citation("secret", access_valid=False), Citation("", identity_valid=False)], ["a", "b", "c"])
    assert m.precision == F(1, 2) and m.recall == F(1, 3)
    assert m.valid_ids == {"a", "x"}
    assert (m.integrity_failures, m.identity_failures, m.access_failures, m.offset_failures) == (3, 1, 1, 1)
    assert citation_metrics([], ["a"]).precision == citation_metrics([], ["a"]).recall == 0
    assert citation_metrics([Citation("a")], []).recall == 0


@pytest.mark.parametrize(("response", "abstain", "claims", "error", "expected"), [
    ("supported", False, [True, True], False, True), (" ", False, [True], False, False),
    ("supported", True, [True], False, False), ("supported", False, [], False, False),
    ("supported", False, [True, False], False, False), ("supported", False, [True, None], False, False),
    ("supported", False, [True], True, False)])
def test_quality_conjunction(response: str, abstain: bool, claims: list[bool | None],
                             error: bool, expected: bool) -> None:
    assert quality_q(response, abstained=abstain, citations=citation_metrics([Citation("a")], ["a"]),
                     claim_supported=claims, error=error) is expected


def test_quality_requires_gold_and_all_citation_integrity() -> None:
    for cited in ([], [Citation("x")], [Citation("a"), Citation("x", access_valid=False)]):
        assert not quality_q("response", abstained=False, citations=citation_metrics(cited, ["a"]),
                             claim_supported=[True])


def test_false_abstention_denominator() -> None:
    assert answerable_false_abstention_rate([True, True, False, True], [True, False, True, None]) == F(1, 3)
    assert answerable_false_abstention_rate([False], [True]) is None
    with pytest.raises(ValueError):
        answerable_false_abstention_rate([True], [])


def test_fixed_tokenizer_and_lexical_examples() -> None:
    assert tokenize("Stra\u00dfe, CAF\u00c9_42! A-b") == ("strasse", "caf\u00e9", "42", "a", "b")
    m = lexical_metrics("a b a c", "a a b d")
    assert m.token_f1 == F(3, 4) and m.rouge_l == F(1, 2)
    assert lexical_metrics("a b c", "a c").rouge_l == F(4, 5)
    assert lexical_metrics("", "").token_f1 == lexical_metrics("", "").rouge_l == 0
    assert lexical_metrics("a", "a", error=True).token_f1 == 0


def test_cost_failed_calls_and_unknowns_are_not_dropped() -> None:
    rows = [Measurement(Decimal("1"), Decimal("2")), Measurement(Decimal("2"), Decimal("3"), "error")]
    result = cost_per_question(rows)
    assert result.mean_usd == Decimal("1.5") and result.n == 2 and result.failed == 1
    result = cost_per_question([*rows, Measurement(None, Decimal("30"), "timeout", Decimal("4"))])
    assert result.mean_usd is None and result.known_usd == 3 and result.held_liability_usd == 4 and result.n == 3
    with localcontext() as context:
        context.prec = 3
        assert cost_per_question(rows).mean_usd == Decimal("1.5")


def test_latency_nearest_rank_with_ties_and_censoring() -> None:
    rows = [Measurement(Decimal(0), Decimal(i)) for i in range(1, 21)]
    assert latency_percentile(rows, F(1, 2)).seconds == 10
    assert latency_percentile(rows, F(19, 20)).seconds == 19
    rows[-1] = Measurement(None, Decimal(30), "timeout")
    p = latency_percentile(rows, F(19, 20))
    assert p.seconds == 19 and p.censored_count == 1 and p.n == 20
    rows[-2] = Measurement(None, Decimal(30), "error")
    p = latency_percentile(rows, F(19, 20))
    assert p.seconds is None and p.lower_bound_seconds == 30 and p.censored and p.n == 20
    # An unknown low elapsed bound can shift a percentile even below the top tail.
    p = latency_percentile([Measurement(Decimal(0), Decimal(10)), Measurement(None, None, "missing")], F(1, 2))
    assert p.seconds is None and p.lower_bound_seconds == 0
    ties = [Measurement(Decimal(0), Decimal(10))] * 20
    assert latency_percentile(ties, F(19, 20)).seconds == 10


@pytest.mark.parametrize("bad", [Decimal("-1"), Decimal("NaN"), Decimal("Infinity"), Decimal("1000001")])
def test_measurement_refusals(bad: Decimal) -> None:
    with pytest.raises(ValueError):
        Measurement(bad, Decimal(1))


def test_bounds_before_unbounded_work() -> None:
    with pytest.raises(ValueError, match="bounds"):
        retrieval_metrics(["a"] * 10001, ["a"])
    with pytest.raises(ValueError, match="bounds"):
        citation_metrics([Citation("a")] * 10001, ["a"])
    with pytest.raises(ValueError, match="bound"):
        lexical_metrics("a " * 2100, "b " * 2100)
    with pytest.raises(ValueError, match="bound"):
        tokenize("a" * 100001)
    with pytest.raises(ValueError):
        latency_percentile([], F(19, 20))
    with pytest.raises(ValueError):
        cost_per_question([])


def test_citation_qrel_duplicates_and_decimal_representation_bounds() -> None:
    m = citation_metrics([Citation("a"), Citation("b"), Citation("a")], ["a", "a", "b"])
    assert m.precision == m.recall == 1
    for cost in (Decimal("1e-1000000"), Decimal("0e1000000")):
        with pytest.raises(ValueError, match="bounds"):
            Measurement(cost, Decimal(0))
