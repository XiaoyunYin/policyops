"""Exact task-macro pass^k and paired, deterministic cluster percentile intervals.

The draw encoding is canonical_bytes (sorted/indented UTF-8 JSON with LF).
Seeds identify resampling only; they do not establish independent hosted calls.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from fractions import Fraction
from functools import lru_cache
import hashlib
from math import comb, lcm
from typing import Any

from policyops_evals.canonical import canonical_bytes, id_list_digest


ALGORITHM = "task-bootstrap-sha256-v1"
REPLICATES = 10000
MAX_WORK = 80_000_000


def reliability(successes: int, trials: int, k: int) -> Fraction:
    if not 0 <= successes <= trials or not 1 <= k <= trials <= 32:
        raise ValueError("invalid pass^k support")
    return Fraction(comb(successes, k), comb(trials, k)) if successes >= k else Fraction(0)


def r7(ordered: Sequence[Fraction], probability: Fraction) -> Fraction:
    if not ordered or not 0 <= probability <= 1:
        raise ValueError("invalid quantile support")
    h = (len(ordered) - 1) * probability
    lower = h.numerator // h.denominator
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (h - lower) * (ordered[upper] - ordered[lower])


def draw_index(size: int, seed: int, scope: str, replicate: int, draw: int) -> int:
    if not 1 <= size <= 128 or not 0 <= seed <= 2147483647:
        raise ValueError("bootstrap bounds")
    ceiling = (2**64 // size) * size
    for rejection in range(128):
        body = [ALGORITHM, seed, scope, replicate, draw, rejection]
        value = int.from_bytes(hashlib.sha256(canonical_bytes(body)).digest()[:8], "big")
        if value < ceiling:
            return value % size
    raise ValueError("bootstrap rejection bound")


@lru_cache(maxsize=8)
def draws(size: int, seed: int, scope: str, replicates: int = REPLICATES) -> tuple[tuple[int, ...], ...]:
    if not 1 <= size <= 128 or not 1 <= replicates <= REPLICATES or size * replicates > MAX_WORK:
        raise ValueError("bootstrap workload bound")
    return tuple(tuple(draw_index(size, seed, scope, b, d) for d in range(size)) for b in range(replicates))


def rounded(value: Fraction) -> float:
    with localcontext() as context:
        context.prec = 80
        return float((Decimal(value.numerator) / Decimal(value.denominator)).quantize(
            Decimal("0.00000001"), rounding=ROUND_HALF_EVEN))


def exact(value: Fraction) -> dict[str, int | float]:
    return {"point": rounded(value), "numerator": value.numerator, "denominator": value.denominator}


def interval(values: Sequence[Fraction], tasks: Sequence[str], *, seed: int,
             kind: str, replicates: int = REPLICATES) -> dict[str, Any] | None:
    if len(values) != len(tasks) or len(set(tasks)) != len(tasks) or len(tasks) > 128:
        raise ValueError("bootstrap task frame")
    if not values:
        return None
    if len(values) * replicates > MAX_WORK:
        raise ValueError("bootstrap workload bound")
    scope = kind + ":" + id_list_digest(tasks)
    denominator = lcm(*(v.denominator for v in values))
    integers = [v.numerator * (denominator // v.denominator) for v in values]
    scale = denominator * len(values)
    if len(set(integers)) == 1:
        low = high = Fraction(integers[0], denominator)
    else:
        samples = sorted(sum(integers[i] for i in indices) for indices in draws(
            len(values), seed, scope, replicates))
        low = r7(samples, Fraction(1, 40)) / scale  # type: ignore[arg-type]
        high = r7(samples, Fraction(39, 40)) / scale  # type: ignore[arg-type]
    return {**exact(Fraction(sum(integers), scale)), "ci": [rounded(low), rounded(high)],
        "ci_exact": [[low.numerator, low.denominator], [high.numerator, high.denominator]],
        "method": ALGORITHM, "quantile": "linear-r7-v1", "confidence": "0.95",
        "seed": seed, "replicates": replicates, "frame_sha256": id_list_digest(tasks),
        "eligible_tasks": len(tasks), "warning": "single_task_degenerate" if len(tasks) == 1 else None}


def task_values(outcomes: Sequence[Sequence[bool | None]], k: int, *, complete_case: bool = False
                ) -> tuple[list[Fraction | None], list[dict[str, int | None]]]:
    values: list[Fraction | None] = []
    support = []
    for slots in outcomes:
        successes = sum(v is True for v in slots)
        scored = sum(v is not None for v in slots)
        n = scored if complete_case else len(slots)
        value = reliability(successes, n, k) if n >= k else None
        values.append(value)
        support.append({"successes": successes, "scheduled": len(slots), "scored": scored,
            "numerator": None if value is None else value.numerator,
            "denominator": None if value is None else value.denominator})
    return values, support


def analyze(tasks: Sequence[str], outcomes: Sequence[Sequence[bool | None]], k: int, *, seed: int,
            complete_case: bool = False, kind: str = "overall") -> dict[str, Any]:
    if len(tasks) != len(outcomes):
        raise ValueError("outcome frame mismatch")
    values, support = task_values(outcomes, k, complete_case=complete_case)
    eligible = [(task, value) for task, value in zip(tasks, values, strict=True) if value is not None]
    return {"estimate": interval([v for _, v in eligible], [t for t, _ in eligible], seed=seed,
        kind=kind + (":complete_case" if complete_case else ":strict")),
        "support": support, "eligible_tasks": len(eligible), "excluded_tasks": len(tasks) - len(eligible),
        "scored_trials": sum(row["scored"] or 0 for row in support)}


def paired(tasks: Sequence[str], candidate: Sequence[Sequence[bool | None]],
           reference: Sequence[Sequence[bool | None]], k: int, *, seed: int,
           complete_case: bool = False, kind: str = "overall") -> dict[str, Any]:
    if len(tasks) != len(candidate) or len(tasks) != len(reference):
        raise ValueError("paired frame mismatch")
    left, right = [], []
    for a, b in zip(candidate, reference, strict=True):
        if len(a) != len(b):
            raise ValueError("paired slot mismatch")
        indices = [i for i in range(len(a)) if a[i] is not None and b[i] is not None]
        left.append([a[i] for i in indices] if complete_case else a)
        right.append([b[i] for i in indices] if complete_case else b)
    av, sa = task_values(left, k, complete_case=complete_case)
    bv, sb = task_values(right, k, complete_case=complete_case)
    for a_support, b_support, a_slots, b_slots in zip(sa, sb, candidate, reference, strict=True):
        a_support["scheduled"] = len(a_slots)
        b_support["scheduled"] = len(b_slots)
    eligible = [(t, a - b) for t, a, b in zip(tasks, av, bv, strict=True) if a is not None and b is not None]
    return {"estimate": interval([v for _, v in eligible], [t for t, _ in eligible], seed=seed,
        kind=kind + (":complete_case" if complete_case else ":strict")),
        "candidate_support": sa, "reference_support": sb,
        "eligible_tasks": len(eligible), "excluded_tasks": len(tasks) - len(eligible)}


def decision(lower_endpoints: Sequence[Fraction], margin: Decimal, *, registered: bool,
             complete: bool, integrity: bool, accounting: bool, cheaper: bool) -> str:
    if not (registered and complete and integrity and accounting and lower_endpoints):
        return "descriptive"
    if all(value > -Fraction(margin) for value in lower_endpoints) and cheaper:
        return "candidate_noninferior_and_cheaper"
    return "inconclusive"
