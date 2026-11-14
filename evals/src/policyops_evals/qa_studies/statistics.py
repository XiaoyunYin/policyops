"""Paired, question-weighted whole-dialogue bootstrap and G6 agreement.

Sorted cluster identities define the frame, shared across arms. Each replicate
draws C clusters with replacement; all questions in each selected cluster are
retained, including repeats, failures and missing scheduled slots. Ratios are
recomputed from totals. Percentiles use exact linear R7 interpolation (as T32),
ordinary .025/.975 and directional alpha or 1-alpha. No RNG/global cache.
Undefined ratios/degenerate kappa draws are retained as undefined: any such
draw makes that interval unavailable rather than dropping a draw.
"""
from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Context, Decimal, localcontext
from fractions import Fraction
import hashlib
from math import lcm
from typing import Literal

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies.config import QAStudy
from policyops_evals.qa_studies.metrics import Measurement, cost_per_question, latency_percentile
from policyops_evals.qa_studies.registration import ComparisonResult, JudgeResult, ObservationSummary
from policyops_evals.studies.statistics import r7


ALGORITHM = "sha256-whole-dialogue-question-weighted-ratio-v1"
REPLICATES = 10_000
MAX_QUESTIONS = 10_000
MAX_CLUSTERS = 2_000
MAX_DRAWS = 20_000_000
MAX_SCALE_BITS = 4096
DEFAULT_ALPHA = Fraction(1, 80)


def _frame(clusters: Sequence[str], seed: int, replicates: int) -> tuple[str, ...]:
    if (not 1 <= len(clusters) <= MAX_QUESTIONS or not 0 <= seed <= 2147483647
            or not 1 <= replicates <= REPLICATES
            or any(not c or len(c) > 500 for c in clusters)):
        raise ValueError("bootstrap frame/seed/replicate bounds")
    frame = tuple(sorted(set(clusters)))
    if len(frame) > MAX_CLUSTERS or len(frame) * replicates > MAX_DRAWS:
        raise ValueError("bootstrap cluster/work bounds")
    return frame


def _draws(frame: tuple[str, ...], seed: int, replicates: int) -> Iterator[tuple[int, ...]]:
    """SHA256(header || uint32be(replicate,draw,rejection)) first 64 bits.

    Header = SHA256(canonical_bytes([algorithm,seed,sorted cluster IDs])).
    Rejection sampling avoids modulo bias. No full draw matrix is retained.
    """
    header = hashlib.sha256(canonical_bytes([ALGORITHM, seed, frame])).digest()
    size = len(frame)
    ceiling = (2**64 // size) * size
    for replicate in range(replicates):
        indices = []
        prefix = header + replicate.to_bytes(4, "big")
        for draw in range(size):
            body = prefix + draw.to_bytes(4, "big")
            for rejection in range(128):
                value = int.from_bytes(hashlib.sha256(body + rejection.to_bytes(4, "big")).digest()[:8], "big")
                if value < ceiling:
                    indices.append(value % size)
                    break
            else:
                raise ValueError("bootstrap rejection bound")
        yield tuple(indices)


@dataclass(frozen=True)
class Estimate:
    point: Fraction | None
    low: Fraction | None
    high: Fraction | None
    adjusted_bound: Fraction | None
    direction: Literal["lower", "upper"]
    alpha: Fraction
    n: int
    clusters: int
    replicates: int
    undefined_replicates: int


def _estimate(point: Fraction | None, samples: Sequence[Fraction | None], *, direction: Literal["lower", "upper"],
              alpha: Fraction, n: int, clusters: int) -> Estimate:
    undefined = sum(v is None for v in samples)
    defined = sorted(v for v in samples if v is not None)
    if undefined or not defined:
        low = high = adjusted = None
    else:
        low, high = r7(defined, Fraction(1, 40)), r7(defined, Fraction(39, 40))
        adjusted = r7(defined, alpha if direction == "lower" else 1 - alpha)
    return Estimate(point, low, high, adjusted, direction, alpha, n, clusters, len(samples), undefined)


def _bounded_fraction(value: Fraction) -> None:
    if not isinstance(value, Fraction) or value.denominator > 10**12 or abs(value) > 1_000_000:
        raise ValueError("ratio value bounds")


def cluster_ratio(numerators: Sequence[Fraction], denominators: Sequence[Fraction], clusters: Sequence[str], *,
                  seed: int, replicates: int = REPLICATES, alpha: Fraction = DEFAULT_ALPHA,
                  direction: Literal["lower", "upper"] = "lower") -> Estimate:
    """Bootstrap ratio of totals; NOT mean of per-cluster ratios.

    Inputs are per scheduled question. Zero denominators are undefined, never
    converted to favorable zero ratios. Work, denominator and integer scale
    bounds apply before any resampling.
    """
    frame = _frame(clusters, seed, replicates)
    if len(numerators) != len(clusters) or len(denominators) != len(clusters):
        raise ValueError("ratio frame mismatch")
    if not 0 < alpha <= Fraction(1, 20) or direction not in {"lower", "upper"}:
        raise ValueError("directional alpha bounds")
    scale = 1
    for value in (*numerators, *denominators):
        _bounded_fraction(value)
        scale = lcm(scale, value.denominator)
        if scale.bit_length() > MAX_SCALE_BITS:
            raise ValueError("ratio integer scale bound")
    if any(d < 0 for d in denominators):
        raise ValueError("negative ratio denominator")
    positions = {c: i for i, c in enumerate(frame)}
    ns, ds = [0] * len(frame), [0] * len(frame)
    for c, numerator, denominator in zip(clusters, numerators, denominators, strict=True):
        i = positions[c]
        ns[i] += numerator.numerator * (scale // numerator.denominator)
        ds[i] += denominator.numerator * (scale // denominator.denominator)
    total_d = sum(ds)
    point = Fraction(sum(ns), total_d) if total_d else None
    samples: list[Fraction | None] = []
    for indices in _draws(frame, seed, replicates):
        denominator_sum = sum(ds[i] for i in indices)
        samples.append(Fraction(sum(ns[i] for i in indices), denominator_sum) if denominator_sum else None)
    return _estimate(point, samples, direction=direction, alpha=alpha, n=len(clusters), clusters=len(frame))


def paired_difference(candidate: Sequence[Fraction | None], reference: Sequence[Fraction | None],
                      clusters: Sequence[str], *, seed: int, replicates: int = REPLICATES,
                      alpha: Fraction = DEFAULT_ALPHA) -> Estimate:
    """None means non-success (zero); all scheduled questions stay in denominator."""
    _frame(clusters, seed, replicates)
    if len(candidate) != len(reference) or len(candidate) != len(clusters):
        raise ValueError("paired frame mismatch")
    for value in (*candidate, *reference):
        if value is not None:
            _bounded_fraction(value)
            if not 0 <= value <= 1:
                raise ValueError("paired score bounds")
    differences = [(a if a is not None else Fraction(0)) - (b if b is not None else Fraction(0))
                   for a, b in zip(candidate, reference, strict=True)]
    return cluster_ratio(differences, [Fraction(1)] * len(clusters), clusters,
                         seed=seed, replicates=replicates, alpha=alpha)


@dataclass(frozen=True)
class QuestionObservation:
    """One aligned scheduled question/repetition, not an opportunistic complete case."""
    value: Fraction | None
    measurement: Measurement
    integrity: bool = True


def _measurements(observations: Sequence[QuestionObservation | None]) -> list[Measurement]:
    return [o.measurement if o is not None else Measurement(None, None, "missing") for o in observations]


def _summary(arm: str, observations: Sequence[QuestionObservation | None]) -> ObservationSummary:
    costs = cost_per_question(_measurements(observations))
    missing = sum(o is None or o.measurement.status == "missing" for o in observations)
    return ObservationSummary(arm=arm, scheduled=len(observations), recorded=len(observations) - missing,
        failed=sum(o is not None and o.measurement.status != "missing"
                   and (o.measurement.status != "success" or o.value is None) for o in observations),
        missing=missing, integrity=all(o is None or o.integrity for o in observations),
        accounting_settled=costs.mean_usd is not None, held_liability_usd=costs.held_liability_usd)


def _decimal(value: Fraction | None, *, upper: bool = False) -> Decimal | None:
    if value is None:
        return None
    with localcontext(Context(prec=50)) as context:
        context.rounding = ROUND_CEILING if upper else ROUND_FLOOR
        return Decimal(value.numerator) / Decimal(value.denominator)


def comparison_result(study: QAStudy, comparison_name: str, question_ids: Sequence[str], clusters: Sequence[str],
                      candidate: Sequence[QuestionObservation | None], reference: Sequence[QuestionObservation | None],
                      *, registration_sha256: str | None, judge: JudgeResult | None = None) -> ComparisonResult:
    """Map registered estimand scores to exactly the decision contract fields.

    Caller supplies a complete, ordered scheduled question/repetition frame.
    IDs must be unique (include repetition in the slot ID). A failed observation
    is forced to zero regardless of its supplied score. Costs include failures.
    Unknown/held costs, undefined cost ratios, or censored p95 cannot pass G2.
    """
    comparison = next((c for c in study.analysis.comparisons if c.name == comparison_name), None)
    if comparison is None:
        raise ValueError("unknown comparison")
    n = len(question_ids)
    if (n != comparison.required_questions * study.schedule.repetitions
            or len(candidate) != n or len(reference) != n or len(clusters) != n
            or len(set(question_ids)) != n or any(not q or len(q) > 500 for q in question_ids)):
        raise ValueError("comparison scheduled frame mismatch")
    # Validate the entire frame and values before the more expensive bootstrap.
    _frame(clusters, study.analysis.bootstrap_seed, study.analysis.bootstrap_replicates)
    scores = [[o.value if o is not None and o.measurement.status == "success" and o.integrity else None
               for o in arm] for arm in (candidate, reference)]
    quality = paired_difference(scores[0], scores[1], clusters, seed=study.analysis.bootstrap_seed,
                                replicates=study.analysis.bootstrap_replicates, alpha=Fraction(comparison.alpha))
    measurements = [_measurements(arm) for arm in (candidate, reference)]
    summaries = (_summary(comparison.candidate, candidate), _summary(comparison.reference, reference))
    cost_upper = None
    if all(s.accounting_settled for s in summaries):
        costs = [[Fraction(m.cost_usd) for m in arm if m.cost_usd is not None] for arm in measurements]
        cost = cluster_ratio(costs[0], costs[1], clusters, seed=study.analysis.bootstrap_seed,
                             replicates=study.analysis.bootstrap_replicates, alpha=Fraction(comparison.alpha),
                             direction="upper")
        if cost.adjusted_bound is not None and cost.adjusted_bound <= 1_000_000:
            cost_upper = _decimal(cost.adjusted_bound, upper=True)
    latencies = [latency_percentile(arm, Fraction(19, 20)).seconds for arm in measurements]
    lower = _decimal(quality.adjusted_bound)
    if lower is None:
        raise ValueError("quality bound undefined")
    return ComparisonResult(comparison=comparison.name, specification_sha256=study.digest(),
        registration_sha256=registration_sha256,
        analysis_sha256=sha256_bytes(canonical_bytes(study.analysis.model_dump(mode="json"))),
        missingness="strict-non-success", adjusted_alpha=comparison.alpha, adjusted_lower=lower,
        cost_ratio_upper=cost_upper, candidate_p95_seconds=latencies[0],
        reference_p95_seconds=latencies[1] if latencies[1] is not None and latencies[1] > 0 else None,
        observations=summaries, judge=judge)


@dataclass(frozen=True)
class Confusion:
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int
    error_negative: int
    error_positive: int


@dataclass(frozen=True)
class RateInterval:
    point: float | None
    low: float | None
    high: float | None


@dataclass(frozen=True)
class AgreementResult:
    kappa: float | None
    kappa_low: float | None
    kappa_high: float | None
    balanced_accuracy: float | None
    per_class_recall: tuple[float | None, float | None]  # (negative, positive)
    false_pass_rate: RateInterval
    coverage: float
    n: int
    errors: int
    confusion: Confusion


def _agreement_values(c: Sequence[int]) -> tuple[
    Fraction | None, Fraction | None, tuple[Fraction | None, Fraction | None], Fraction | None
]:
    tn, fp, fn, tp, en, ep = c
    n = sum(c)
    negative, positive = tn + fp + en, tp + fn + ep
    # Error is a third prediction category with zero gold marginal. It cannot
    # agree with a negative label, unlike coercing None to False.
    expected = negative * (tn + fn) + positive * (tp + fp)
    kappa = Fraction((tn + tp) * n - expected, n * n - expected) if n * n != expected else None
    rn = Fraction(tn, negative) if negative else None
    rp = Fraction(tp, positive) if positive else None
    balanced = (rn + rp) / 2 if rn is not None and rp is not None else None
    false_pass = Fraction(fp, negative) if negative else None
    return kappa, balanced, (rn, rp), false_pass


def binary_agreement(gold: Sequence[bool], predicted: Sequence[bool | None], clusters: Sequence[str], *,
                     seed: int, replicates: int = REPLICATES) -> AgreementResult:
    """G6 agreement, document-cluster CI. None never earns negative credit.

    Class recall denominators include errors. False-pass is FP/all human
    negatives, with errors separately visible. A missing class or degenerate
    kappa is undefined, not zero. Any undefined bootstrap draw makes its CI
    unavailable; no draw is silently dropped. G6 must require complete coverage.
    """
    frame = _frame(clusters, seed, replicates)
    if len(gold) != len(predicted) or len(gold) != len(clusters):
        raise ValueError("agreement frame mismatch")
    if any(type(g) is not bool for g in gold) or any(p is not None and type(p) is not bool for p in predicted):
        raise ValueError("agreement binary labels required")
    positions = {c: i for i, c in enumerate(frame)}
    counts = [[0] * 6 for _ in frame]
    for g, p, c in zip(gold, predicted, clusters, strict=True):
        cell = (5 if g else 4) if p is None else (3 if g and p else 2 if g else 1 if p else 0)
        counts[positions[c]][cell] += 1
    totals = [sum(c[i] for c in counts) for i in range(6)]
    kappa, balanced, recalls, false_pass = _agreement_values(totals)
    ks: list[Fraction | None] = []
    fs: list[Fraction | None] = []
    for indices in _draws(frame, seed, replicates):
        sampled = [sum(counts[j][i] for j in indices) for i in range(6)]
        k, _, _, f = _agreement_values(sampled)
        ks.append(k)
        fs.append(f)
    ki = _estimate(kappa, ks, direction="lower", alpha=DEFAULT_ALPHA, n=len(gold), clusters=len(frame))
    fi = _estimate(false_pass, fs, direction="upper", alpha=DEFAULT_ALPHA, n=len(gold), clusters=len(frame))
    errors = totals[4] + totals[5]
    def number(value: Fraction | None) -> float | None:
        return float(value) if value is not None else None

    # Exact arithmetic through CI construction; ordinary JSON-compatible public
    # agreement values allow G6 to serialize this dataclass with asdict.
    return AgreementResult(number(kappa), number(ki.low), number(ki.high), number(balanced),
        (number(recalls[0]), number(recalls[1])), RateInterval(number(false_pass), number(fi.low), number(fi.high)),
        float(Fraction(len(gold) - errors, len(gold))), len(gold), errors, Confusion(*totals))
