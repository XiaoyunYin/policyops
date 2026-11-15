"""Pure QA metrics; lexical diagnostics do not measure semantic correctness.

Ties keep the supplied frozen retriever order. Duplicate ranked IDs consume
slots but earn relevance once. Citations use unique valid passage IDs.
Tokenizer v1: casefold then maximal Unicode alphanumeric runs (no underscore).
No stemming, article removal, or punctuation tokens. ROUGE-L uses LCS F1.
Binary nDCG uses log2 discounts and is rounded ties-to-even to 12 decimal places
on a shared rational grid, so it feeds bounded exact bootstrap arithmetic.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Context, Decimal, localcontext
from fractions import Fraction
from math import ceil, log2
import re
from typing import Literal


MAX_QUESTIONS = 10_000
MAX_IDS = 10_000
MAX_TEXT = 100_000
MAX_LCS_CELLS = 4_000_000
TOKENIZER = "unicode-casefold-alphanumeric-v1"


def _ids(values: Sequence[str]) -> None:
    if len(values) > MAX_IDS or any(not v or len(v) > 500 for v in values):
        raise ValueError("passage ID bounds")


@dataclass(frozen=True)
class RetrievalMetrics:
    recall_at_1: Fraction
    recall_at_5: Fraction
    recall_at_10: Fraction
    hit_at_1: bool
    hit_at_5: bool
    hit_at_10: bool
    mrr_at_10: Fraction
    ndcg_at_10: Fraction


def retrieval_metrics(ranked: Sequence[str], gold: Sequence[str], *, error: bool = False) -> RetrievalMetrics:
    """Per-query binary human qrels; empty qrels score zero."""
    _ids(ranked)
    _ids(gold)
    relevant = set(gold)
    seen: set[str] = set()
    gains = []
    for passage in ranked[:10]:
        gains.append(int(not error and passage in relevant and passage not in seen))
        seen.add(passage)
    recalls = [Fraction(sum(gains[:k]), len(relevant)) if relevant else Fraction(0) for k in (1, 5, 10)]
    reciprocal = next((Fraction(1, i + 1) for i, gain in enumerate(gains) if gain), Fraction(0))
    dcg = sum(gain / log2(i + 2) for i, gain in enumerate(gains))
    ideal = sum(1 / log2(i + 2) for i in range(min(10, len(relevant))))
    return RetrievalMetrics(recalls[0], recalls[1], recalls[2], bool(sum(gains[:1])),
        bool(sum(gains[:5])), bool(sum(gains[:10])), reciprocal,
        Fraction(round((dcg / ideal if ideal else 0.0) * 10**12), 10**12))


@dataclass(frozen=True)
class Citation:
    passage_id: str
    identity_valid: bool = True
    access_valid: bool = True
    offsets_valid: bool = True

    @property
    def valid(self) -> bool:
        return bool(self.passage_id) and self.identity_valid and self.access_valid and self.offsets_valid


@dataclass(frozen=True)
class CitationMetrics:
    precision: Fraction
    recall: Fraction
    valid_ids: frozenset[str]
    integrity_failures: int
    identity_failures: int
    access_failures: int
    offset_failures: int


def citation_metrics(citations: Sequence[Citation], gold: Sequence[str]) -> CitationMetrics:
    _ids(gold)
    if len(citations) > MAX_IDS or any(len(c.passage_id) > 500 for c in citations):
        raise ValueError("citation bounds")
    valid = frozenset(c.passage_id for c in citations if c.valid)
    targets = set(gold)
    overlap = len(valid & targets)
    return CitationMetrics(Fraction(overlap, len(valid)) if valid else Fraction(0),
        Fraction(overlap, len(targets)) if targets else Fraction(0), valid,
        sum(not c.valid for c in citations),
        sum(not c.identity_valid or not c.passage_id for c in citations),
        sum(not c.access_valid for c in citations), sum(not c.offsets_valid for c in citations))


def gold_citation(response: str, *, answerable: bool, abstained: bool,
                  citations: CitationMetrics, error: bool = False) -> bool:
    """Deterministic human-gold citation success, independent of judge verdicts."""
    if len(response) > MAX_TEXT:
        raise ValueError("response bound")
    return (answerable and not error and bool(response.strip()) and not abstained
            and citations.integrity_failures == 0 and citations.recall > 0)


def quality_q(response: str, *, abstained: bool, citations: CitationMetrics,
              claim_supported: Sequence[bool | None], error: bool = False) -> bool:
    """Verdicts must cover every substantive claim; None is a judge error."""
    if len(response) > MAX_TEXT or len(claim_supported) > 1000:
        raise ValueError("response/claim bounds")
    return (not error and bool(response.strip()) and not abstained and citations.integrity_failures == 0
            and citations.recall > 0 and bool(claim_supported) and all(v is True for v in claim_supported))


def answerable_false_abstention_rate(answerable: Sequence[bool], abstained: Sequence[bool | None]) -> Fraction | None:
    """Only explicit abstentions count; errors remain in the answerable denominator."""
    if len(answerable) != len(abstained) or len(answerable) > MAX_QUESTIONS:
        raise ValueError("abstention frame bounds")
    n = sum(answerable)
    return Fraction(sum(a and b is True for a, b in zip(answerable, abstained, strict=True)), n) if n else None


def tokenize(text: str) -> tuple[str, ...]:
    if len(text) > MAX_TEXT:
        raise ValueError("text bound")
    return tuple(re.findall(r"[^\W_]+", text.casefold(), flags=re.UNICODE))


@dataclass(frozen=True)
class LexicalMetrics:
    token_f1: Fraction
    rouge_l: Fraction


def lexical_metrics(response: str, reference: str, *, error: bool = False) -> LexicalMetrics:
    a, b = tokenize(response), tokenize(reference)
    if len(a) * len(b) > MAX_LCS_CELLS:
        raise ValueError("ROUGE-L work bound")
    if error or not a or not b:
        return LexicalMetrics(Fraction(0), Fraction(0))
    overlap = sum((Counter(a) & Counter(b)).values())
    if len(a) < len(b):
        a, b = b, a
    row = [0] * (len(b) + 1)
    for token in a:
        diagonal = 0
        for j, other in enumerate(b, 1):
            previous = row[j]
            row[j] = diagonal + 1 if token == other else max(row[j], row[j - 1])
            diagonal = previous
    return LexicalMetrics(Fraction(2 * overlap, len(a) + len(b)), Fraction(2 * row[-1], len(a) + len(b)))


@dataclass(frozen=True)
class Measurement:
    """Policy-only cost; keep judge/preprocessing/experimental spend separate.

    Non-success latency is a right-censored elapsed lower bound.
    Missing cost is unknown even when held liability is zero.
    """
    cost_usd: Decimal | None
    latency_seconds: Decimal | None
    status: Literal["success", "error", "timeout", "missing"] = "success"
    held_liability_usd: Decimal = Decimal(0)

    def __post_init__(self) -> None:
        for value, maximum in ((self.cost_usd, Decimal(1_000_000)),
                               (self.latency_seconds, Decimal(604800)),
                               (self.held_liability_usd, Decimal(1_000_000))):
            if value is not None and (not value.is_finite() or not 0 <= value <= maximum
                                      or len(value.as_tuple().digits) > 21
                                      or not -12 <= int(value.as_tuple().exponent) <= 6):
                raise ValueError("measurement bounds")
        if self.status not in {"success", "error", "timeout", "missing"}:
            raise ValueError("measurement status")
        if self.status == "success" and self.latency_seconds is None:
            raise ValueError("successful measurement requires latency")


@dataclass(frozen=True)
class LatencyPercentile:
    seconds: Decimal | None
    lower_bound_seconds: Decimal
    censored: bool
    n: int
    censored_count: int


def latency_percentile(measurements: Sequence[Measurement], probability: Fraction) -> LatencyPercentile:
    """Nearest rank ceil(p*n), p in (0,1]; no interpolation or omission.

    Censored slots have possible completion time +infinity. If they can change
    this quantile, seconds is None. lower_bound_seconds is the nearest-rank
    quantile of observed elapsed lower bounds (missing = zero).
    """
    if not measurements or len(measurements) > MAX_QUESTIONS or not 0 < probability <= 1:
        raise ValueError("latency percentile bounds")
    rank = ceil(probability * len(measurements)) - 1
    lows = sorted(m.latency_seconds if m.latency_seconds is not None else Decimal(0) for m in measurements)
    complete = sorted(m.latency_seconds for m in measurements
                      if m.status == "success" and m.latency_seconds is not None)
    censored = len(measurements) - len(complete)
    upper = complete[rank] if rank < len(complete) else None
    exact = upper is not None and upper == lows[rank]
    return LatencyPercentile(upper if exact else None, lows[rank], not exact, len(measurements), censored)


@dataclass(frozen=True)
class PolicyLatencyPercentile:
    seconds: Decimal | None
    n: int
    failed_count: int


def policy_latency_percentile(measurements: Sequence[Measurement], probability: Fraction) -> PolicyLatencyPercentile:
    """failure-as-worst-v1: nearest rank over all slots, failures ranked +infinity.

    None means the requested rank falls in the failed tail. Failed elapsed
    times are ignored; this is a policy outcome convention, not censor inference.
    """
    if not measurements or len(measurements) > MAX_QUESTIONS or not 0 < probability <= 1:
        raise ValueError("policy latency percentile bounds")
    rank = ceil(probability * len(measurements)) - 1
    complete = sorted(m.latency_seconds for m in measurements
                      if m.status == "success" and m.latency_seconds is not None)
    return PolicyLatencyPercentile(complete[rank] if rank < len(complete) else None,
                                   len(measurements), len(measurements) - len(complete))


@dataclass(frozen=True)
class CostSummary:
    mean_usd: Decimal | None
    known_usd: Decimal
    held_liability_usd: Decimal
    n: int
    unknown: int
    failed: int


def cost_per_question(measurements: Sequence[Measurement]) -> CostSummary:
    if not measurements or len(measurements) > MAX_QUESTIONS:
        raise ValueError("cost frame bounds")
    with localcontext(Context(prec=50)):
        known = sum((m.cost_usd for m in measurements if m.cost_usd is not None), Decimal(0))
        held = sum((m.held_liability_usd for m in measurements), Decimal(0))
        unknown = sum(m.cost_usd is None for m in measurements)
        return CostSummary(known / len(measurements) if not unknown and held == 0 else None,
                           known, held, len(measurements), unknown, sum(m.status != "success" for m in measurements))
