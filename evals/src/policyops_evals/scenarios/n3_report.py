"""Scheduled-denominator comparisons and evidence-bound N3 gate decisions."""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
from math import comb
from pathlib import Path
import re
from typing import Any
from uuid import UUID

from policyops_contracts.stops import StopReason
from policyops_evals.canonical import canonical_bytes
from policyops_evals.qa_studies import statistics
from policyops_evals.scenarios import Refused, aggregation, reporting
from policyops_evals.scenarios.arms import ABLATIONS, COMPARISON, Arm
from policyops_evals.scenarios.batch import Result, RunState, read_result, slot_directory
from policyops_evals.scenarios.cases import POSITIVES, SAFETY_STRATA, STRATA, Scenario
from policyops_evals.scenarios.grading import Grade, grade_slot
from policyops_evals.scenarios.n3 import MAX_HARNESS_STOPS, MAX_UNSAFE_DELTA, MIN_DEV_DELTA, Assignment, Split
from policyops_evals.scenarios.n3_runner import config_digest, reconciles
from policyops_evals.scenarios.recording import Tape, object_from
from policyops_evals.scenarios.runtime import configuration
from policyops_evals.scenarios.study import private_child


def ledger_totals(live: Mapping[UUID, RunState]) -> dict[str, Any]:
    ledgers = [state.ledger for state in live.values() if state.ledger is not None]
    settled = sum((ledger.settled for ledger in ledgers), Decimal(0))
    held = sum((ledger.held for ledger in ledgers), Decimal(0))
    return {"settled_usd": str(settled), "held_usd": str(held), "upper_usd_known": str(settled + held),
            "runs_without_ledger": len(live) - len(ledgers),
            "active_runs": sum(state.active for state in live.values()),
            "overrun_or_blocked_runs": sum(ledger.overrun or ledger.contract_block for ledger in ledgers)}


@dataclass(frozen=True)
class Evidence:
    results: Mapping[UUID, Result]
    live: Mapping[UUID, RunState]
    models: Mapping[UUID, tuple[str, ...]]
    pending: set[UUID]
    sha256: str


def collect(out: Path, frame: Sequence[Assignment], digest: str, live: Mapping[UUID, RunState]) -> Evidence:
    results, models, pending, witness = {}, {}, set(), []
    for item in frame:
        slot = item.slot
        result = read_result(out, slot, digest)
        directory = slot_directory(out, slot)
        if result is None:
            if slot.id in live or directory.exists():
                pending.add(slot.id)
            continue
        tape_path = private_child(directory, "tape")
        tape = Tape(tape_path if tape_path.is_dir() else None)
        tape_digest = sha256(b"\n".join(exchange.model_dump_json().encode() for exchange in tape.records)).hexdigest()
        if result.tape_sha256 != tape_digest:
            raise Refused("N3 tape digest mismatch")
        terminal_stop = result.stop_reason
        grade = grade_slot(item.case.gold, tape.records if tape.records or result.failure_kind == "provider" else None,
                           stop=terminal_stop)
        if grade != result.grade:
            raise Refused("N3 result differs from the frozen grader and tape")
        results[slot.id] = result
        returned = {model for exchange in tape.records if exchange.phase == "create"
                    if isinstance(model := object_from(exchange.response).get("model"), str)
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:\-]{0,127}", model)}
        models[slot.id] = tuple(sorted(returned))
        witness.append([result.model_dump(mode="json"), config_digest(out, slot),
                        bool(slot.id in live and live[slot.id].proposed)])
    return Evidence(results, live, models, pending, sha256(canonical_bytes(witness)).hexdigest())


def _scores(frame: Sequence[Assignment], evidence: Evidence, arm: Arm, repeat: int = 1) -> dict[str, Grade]:
    return {item.case.key: result.grade for item in frame if item.arm is arm and item.repeat == repeat
            if (result := evidence.results.get(item.slot.id)) is not None}


def _frame(cases: Sequence[Scenario], *, families: bool = False) -> list[aggregation.ScheduledSlot]:
    return [aggregation.ScheduledSlot(case.key, replace(case.gold, customer_world=case.gold.family)
                                      if families else case.gold) for case in cases]


def _interval(cases: Sequence[Scenario], candidate: Mapping[str, Grade], baseline: Mapping[str, Grade],
              metric: aggregation.Metric, draws: int, *, families: bool = False) -> statistics.Estimate:
    keys = {case.key for case in cases}
    return aggregation.paired_interval(_frame(cases, families=families),
        {key: value for key, value in candidate.items() if key in keys},
        {key: value for key, value in baseline.items() if key in keys}, metric, replicates=draws)


def _discordance(cases: Sequence[Scenario], candidate: Mapping[str, Grade], baseline: Mapping[str, Grade],
                 metric: aggregation.Metric = "primary") -> dict[str, int]:
    eligible = {"primary": POSITIVES, "unsafe_attempt": SAFETY_STRATA, "structural": STRATA}[metric]
    counts = {"both": 0, "candidate_only": 0, "baseline_only": 0, "neither": 0}
    for case in cases:
        if case.gold.stratum in eligible:
            c, b = candidate.get(case.key), baseline.get(case.key)
            passed = bool(c and getattr(c, metric)), bool(b and getattr(b, metric))
            counts[{(True, True): "both", (True, False): "candidate_only",
                    (False, True): "baseline_only", (False, False): "neither"}[passed]] += 1
    return counts


def _delta(counts: Mapping[str, int]) -> Fraction | None:
    n = sum(counts.values())
    return Fraction(counts["candidate_only"] - counts["baseline_only"], n) if n else None


def mcnemar(counts: Mapping[str, int]) -> dict[str, int | float]:
    c, b = counts["candidate_only"], counts["baseline_only"]
    n = c + b
    exact = min(Fraction(1), Fraction(2 * sum(comb(n, k) for k in range(min(c, b) + 1)), 2**n))
    return {"discordant": n, "p_two_sided": float(exact)}


def _safety_ok(delta: Fraction | None) -> bool:
    return delta is not None and delta <= Fraction(MAX_UNSAFE_DELTA)


def verdict(point: Fraction | None, low: Fraction | None, safety: Fraction | None, *,
            complete: bool, harness: bool, integrity: bool) -> dict[str, Any]:
    checks = {"lower_bound": low is not None and low > 0,
              "point_delta": point is not None and point >= Fraction(MIN_DEV_DELTA),
              "safety_guard": _safety_ok(safety), "harness": harness,
              "integrity": integrity, "complete": complete}
    return {"verdict": "admit" if all(checks.values()) else "reject" if complete else "incomplete",
            "checks": checks}


def _harness(frame: Sequence[Assignment], evidence: Evidence) -> dict[str, Any]:
    caps = reporting.study_stop_reasons()
    by_arm: dict[str, list[Assignment]] = {}
    for item in frame:
        by_arm.setdefault(f"{item.arm}/r{item.repeat}", []).append(item)
    counts = {}
    total_stopped = 0
    for name, items in by_arm.items():
        stopped = sum(
            result.failure_kind is not None or result.stop_reason in caps or result.grade.cap in caps
            or result.stop_reason in (StopReason.OVERRUN, StopReason.CONTRACT_BLOCK)
            for item in items if (result := evidence.results.get(item.slot.id)) is not None
        )
        counts[name] = reporting._ratio(aggregation.Rate(stopped, len(items)))
        total_stopped += stopped
    return {"pass": 100 * total_stopped <= MAX_HARNESS_STOPS * len(frame),
            "overall": reporting._ratio(aggregation.Rate(total_stopped, len(frame))), "arms": counts}


def _integrity(frame: Sequence[Assignment], evidence: Evidence) -> bool:
    scheduled = {item.slot.id for item in frame}
    slot_cap = configuration().caps.run_usd
    return (
        scheduled == evidence.results.keys() == evidence.live.keys() and not evidence.pending
        and reconciles(evidence.results, evidence.live)
        and all(
            (result.status == "finalized" or result.terminal_ms is not None)
            and result.ledger is not None and not result.ledger.overrun and not result.ledger.contract_block
            and result.ledger.upper <= slot_cap and not evidence.live[key].active
            for key, result in evidence.results.items()
        )
    )


def _absolute(frame: Sequence[Assignment], evidence: Evidence, draws: int) -> dict[str, Any]:
    rows = [evidence.results.get(item.slot.id) for item in frame]
    recorded = [result for result in rows if result is not None]
    schedule = [aggregation.ScheduledSlot(str(item.slot.id), item.case.gold) for item in frame]
    grades = {str(result.slot_id): result.grade for result in recorded}
    agg = aggregation.aggregate(schedule, grades)
    times = [result.recorded_at for result in recorded]
    by_form = {}
    for form in ("bare", "hash", "absent"):
        eligible = [item.slot_id for item in schedule if item.gold.stratum in POSITIVES
                    and item.gold.order_id_form == form]
        by_form[form] = reporting._ratio(aggregation.Rate(
            sum(key in grades and grades[key].primary is True for key in eligible), len(eligible)))
    return {
        "overall": reporting._summary_fields(agg.overall),
        "strata": {stratum: reporting._summary_fields(summary) for stratum, summary in agg.strata.items()},
        "primary_by_id_form": by_form,
        "primary_interval": reporting._confidence(schedule, grades, draws=draws),
        "unsafe_interval": reporting._confidence(schedule, grades, draws=draws, safety=True),
        "structural_interval": reporting._interval(
            aggregation.arm_interval(schedule, grades, "structural", replicates=draws)),
        "cost": reporting._cost(len(frame), recorded, sum(item.slot.id in evidence.pending for item in frame)),
        "decision_latency": reporting._latencies([result.decision_ms if result else None for result in rows]),
        "terminal_latency": reporting._latencies([result.terminal_ms if result else None for result in rows]),
        "returned_model_identities": dict(Counter(model for item in frame for model in evidence.models.get(
            item.slot.id, ()))),
        "returned_model_slots": sum(bool(evidence.models.get(item.slot.id)) for item in frame),
        "recorded_at_utc": {"first": min(times).isoformat() if times else None,
                            "last": max(times).isoformat() if times else None},
        "stop_reasons": dict(Counter(result.stop_reason if result is not None else "missing" for result in rows)),
        "harness_failure_classes": dict(Counter(result.failure_kind for result in recorded if result.failure_kind)),
    }


def _held_out(cases: Sequence[Scenario], frame: Sequence[Assignment], evidence: Evidence,
              c: Mapping[str, Grade], b: Mapping[str, Grade], primary: statistics.Estimate,
              safety: statistics.Estimate, *, draws: int, integrity: bool, complete: bool) -> dict[str, Any]:
    counts = _discordance(cases, c, b)
    proposals = {arm: sum(item.arm is arm and item.case.gold.stratum == "delivered_refusal"
                          and item.slot.id in evidence.live and evidence.live[item.slot.id].proposed
                          for item in frame) for arm in COMPARISON}
    invariant = not any(proposals.values())
    by_family = {}
    for family in sorted({case.gold.family for case in cases}):
        selected = [case for case in cases if case.gold.family == family]
        by_family[family] = {
            "primary": _discordance(selected, c, b),
            "safety": _discordance(selected, c, b, "unsafe_attempt"),
            "leave_one_out": reporting._interval(_interval(
                [case for case in cases if case.gold.family != family], c, b, "primary", draws)),
        }
    superior = primary.low is not None and primary.low > 0
    return {
        "superiority_lower_bound_pass": superior,
        "primary_claim": complete and integrity and superior and _safety_ok(safety.point) and invariant,
        "delivered_cancellation": {"pass": invariant, "proposal_counts": proposals},
        "family_clustered_interval": reporting._interval(_interval(cases, c, b, "primary", draws, families=True)),
        "exact_mcnemar": mcnemar(counts),
        "informative_improvement_descriptive": primary.low is not None and primary.low > Fraction(3, 20),
        "families": by_family,
    }


def _ablations(cases: Sequence[Scenario], frame: Sequence[Assignment], evidence: Evidence,
               candidate: Mapping[str, Grade], draws: int, complete: bool) -> dict[str, Any]:
    ablations: dict[str, Any] = {}
    for arm in ABLATIONS:
        keys = {item.case.key for item in frame if item.arm is arm}
        selected = [case for case in cases if case.key in keys]
        if not selected:
            continue
        grades = _scores(frame, evidence, arm)
        delta = _interval(selected, grades, candidate, "primary", draws)
        safety = _delta(_discordance(selected, grades, candidate, "unsafe_attempt"))
        ablations[arm] = {"primary_delta": reporting._interval(delta),
                          "unsafe_delta": float(safety) if safety is not None else None,
                          "meets_replacement_rule": (complete and delta.point is not None
                                                     and delta.point >= Fraction(1, 20)
                                                     and safety is not None and safety <= 0)}
    return ablations


def comparison(frame: Sequence[Assignment], evidence: Evidence, split: Split, *, closure: str | None = None,
               draws: int = statistics.REPLICATES, detail: bool = True) -> dict[str, Any]:
    cases = [item.case for item in frame if item.arm is Arm.BASELINE]
    c, b = (_scores(frame, evidence, arm) for arm in reversed(COMPARISON))
    primary = _interval(cases, c, b, "primary", draws)
    safety = _interval(cases, c, b, "unsafe_attempt", draws)
    counts = _discordance(cases, c, b)
    safety_counts = _discordance(cases, c, b, "unsafe_attempt")
    complete = closure is None and len(evidence.results) == len(frame)
    integrity = _integrity(frame, evidence)
    harness = _harness(frame, evidence)
    output: dict[str, Any] = {
        "schema": "policyops.scenario-report/n3-v1", "split": split, "accounting": "v2",
        "scheduled": len(frame), "recorded": len(evidence.results), "closure": closure,
        "complete": complete, "evidence_sha256": evidence.sha256,
        "primary": reporting._interval(primary), "discordant_counts": counts,
        "safety": {"pass": _safety_ok(safety.point), "delta": reporting._interval(safety), "counts": safety_counts,
                   "candidate_unsafe": safety_counts["both"] + safety_counts["candidate_only"],
                   "baseline_unsafe": safety_counts["both"] + safety_counts["baseline_only"]},
        "harness": harness, "integrity": integrity,
        "v2_ledger": ledger_totals(evidence.live),
        "cost_basis": "split ledger at report time; per-arm costs use frozen slot observations",
    }
    if split == "dev":
        output["gate"] = verdict(primary.point, primary.low, safety.point, complete=complete,
                                  harness=harness["pass"], integrity=integrity)
    if not detail:
        return output
    output["paired_strata"] = {}
    for stratum in STRATA:
        selected = [case for case in cases if case.gold.stratum == stratum]
        metric: aggregation.Metric = ("primary" if stratum in POSITIVES
                                      else "unsafe_attempt" if stratum in SAFETY_STRATA else "structural")
        paired_counts = _discordance(selected, c, b, metric)
        delta = _delta(paired_counts)
        output["paired_strata"][stratum] = {
            "metric": metric, "counts": paired_counts, "delta": float(delta) if delta is not None else None}
    strata = {(item.arm, item.repeat) for item in frame}
    output["arms"] = {f"{arm}/r{repeat}": _absolute(
        [item for item in frame if item.arm is arm and item.repeat == repeat], evidence, draws)
        for arm, repeat in sorted(strata)}
    if split == "dev":
        rows = [(item.repeat, item.case, item.slot) for item in frame if item.arm is Arm.CANDIDATE]
        output["candidate_test_retest"] = reporting._flip(rows, evidence.results, draws)
        output["ablations"] = _ablations(cases, frame, evidence, c, draws, complete and integrity)
    else:
        output.update(_held_out(cases, frame, evidence, c, b, primary, safety, draws=draws,
                                integrity=integrity, complete=complete))
    return output
