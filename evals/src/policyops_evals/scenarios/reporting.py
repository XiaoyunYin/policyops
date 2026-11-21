"""Bounded offline N2 summaries over the registered schedule."""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from typing import Any, get_args
from uuid import UUID

from policyops.budget.config import Caps
from policyops_contracts.conversation import AgentLimits
from policyops_contracts.stops import StopReason
from policyops_evals.qa_studies import statistics
from policyops_evals.scenarios.aggregation import Rate, ScheduledSlot, Summary, aggregate, arm_interval, paired_interval
from policyops_evals.scenarios.batch import Result, read_result, slot_directory
from policyops_evals.scenarios.cases import POSITIVES, SAFETY_STRATA, STRATA, Scenario
from policyops_evals.scenarios.grading import Failure, Grade
from policyops_evals.scenarios.runtime import LIMITS, MAX_STEPS, Slot, configuration
from policyops_evals.scenarios.study import ACCOUNTING, REPEATS, THRESHOLDS
from policyops_evals.studies.statistics import r7


Schedule = Sequence[tuple[int, Scenario, Slot]]
NAMED_FAILURES = frozenset(get_args(Failure))


def study_stop_reasons() -> frozenset[str]:
    product, study = Caps(), configuration().caps
    graph = AgentLimits(knowledge_steps=16)
    caps = {
        StopReason.USD_CAP: study.run_usd < product.run_usd,
        StopReason.CALL_CAP: min(study.run_calls, LIMITS.model_calls) < min(product.run_calls, graph.model_calls),
        StopReason.COUNT_CAP: study.run_calls < product.run_calls,
        StopReason.INPUT_TOKENS: study.request_max_input < product.request_max_input,
        StopReason.ACTIVE_TIME: study.active_seconds < product.active_seconds,
        StopReason.TOOL_CAP: LIMITS.steps_per_turn < graph.steps_per_turn,
        StopReason.RETRIEVAL_CAP: LIMITS.knowledge_steps < graph.knowledge_steps,
        StopReason.INVALID_CAP: LIMITS.consecutive_invalid < graph.consecutive_invalid,
        "max_output_tokens": min(study.request_max_output, LIMITS.max_output_tokens)
        < min(product.request_max_output, graph.max_output_tokens),
        "investigation.loop_ceiling": MAX_STEPS < 32,
    }
    return frozenset(reason for reason, stricter in caps.items() if stricter)


def _ratio(rate: Rate) -> dict[str, int | float | None]:
    return asdict(rate) | {"value": float(rate.value) if rate.value is not None else None}


def gate(schedule: Schedule, results: Mapping[UUID, Result]) -> dict[str, Any]:
    positive = [results.get(slot.id) for _, case, slot in schedule if case.gold.stratum in POSITIVES]
    successes = sum(item is not None and item.grade.primary is True for item in positive)
    failures = len(positive) - successes
    named = sum(
        item is not None and item.grade.primary is not True and not item.grade.missing
        and item.grade.failure in NAMED_FAILURES
        and (item.failure_kind not in ("infrastructure", "recorder") or item.grade.failure != "no decision")
        for item in positive
    )
    caps = study_stop_reasons()
    harness = sum(
        (item := results.get(slot.id)) is not None
        and (item.stop_reason in caps or item.grade.cap in caps or item.failure_kind is not None
             or item.stop_reason in (StopReason.OVERRUN, StopReason.CONTRACT_BLOCK))
        for _, _, slot in schedule
    )
    finalized = sum(slot.id in results for _, _, slot in schedule)
    low = 100 * successes < THRESHOLDS["primary_min"] * len(positive)
    high = 100 * successes > THRESHOLDS["primary_max"] * len(positive)
    too_many_stops = 100 * harness > THRESHOLDS["harness_stop_max"] * len(schedule)
    named_ok = bool(failures) and 100 * named >= THRESHOLDS["named_failure_min"] * failures
    complete = bool(positive) and finalized == len(schedule)
    slot_cap = configuration().caps.run_usd
    integrity = all(item.ledger is not None and not (item.ledger.overrun or item.ledger.contract_block)
                    and item.ledger.upper <= slot_cap
                    for _, _, slot in schedule if (item := results.get(slot.id)) is not None)
    if not integrity:
        verdict = "accounting_blocked"
    elif not complete:
        verdict = "incomplete"
    elif high or too_many_stops or (low and not named_ok):
        verdict = "return_to_design"
    else:
        verdict = "proceed"
    return {
        "verdict": verdict, "scheduled": len(schedule), "recorded": finalized, "accounting_integrity": integrity,
        "primary_below_minimum": {"rate": _ratio(Rate(successes, len(positive))),
                                  "threshold": THRESHOLDS["primary_min"] / 100, "triggered": low},
        "primary_above_maximum": {"rate": _ratio(Rate(successes, len(positive))),
                                  "threshold": THRESHOLDS["primary_max"] / 100, "triggered": high},
        "named_failure_exception": {"rate": _ratio(Rate(named, failures)),
                                    "threshold": THRESHOLDS["named_failure_min"] / 100,
                                    "met": named_ok, "applied": complete and low and named_ok},
        "harness_stops_above_maximum": {"rate": _ratio(Rate(harness, len(schedule))),
                                        "threshold": THRESHOLDS["harness_stop_max"] / 100, "triggered": too_many_stops},
        "n3_held_out_admission": {"applicable": False, "paired_dev_lower_bound": None, "must_exceed": 0},
    }


def collect(out: Path, schedule: Schedule, digest: str) -> tuple[dict[UUID, Result], set[UUID]]:
    results, pending = {}, set()
    for _, _, slot in schedule:
        result = read_result(out, slot, digest)
        if result is not None:
            results[slot.id] = result
        elif slot_directory(out, slot).exists():
            pending.add(slot.id)
    return results, pending


def _interval(estimate: statistics.Estimate) -> dict[str, int | float | None]:
    return {"point": float(estimate.point) if estimate.point is not None else None,
            "low": float(estimate.low) if estimate.low is not None else None,
            "high": float(estimate.high) if estimate.high is not None else None,
            "clusters": estimate.clusters, "scheduled": estimate.n, "draws": estimate.replicates}


def _confidence(schedule: Sequence[ScheduledSlot], grades: Mapping[str, Grade], *,
                draws: int, safety: bool = False) -> dict[str, int | float | None] | None:
    eligible = SAFETY_STRATA if safety else POSITIVES
    if not any(slot.gold.stratum in eligible for slot in schedule):
        return None
    return _interval(arm_interval(schedule, grades, "unsafe_attempt" if safety else "primary", replicates=draws))


def _latencies(values: Sequence[int | None]) -> dict[str, float | int | None]:
    valid = sorted(Fraction(value) for value in values if value is not None)
    return {
        "measured": len(valid), "scheduled": len(values), "unmeasured": len(values) - len(valid),
        "p50_ms": float(r7(valid, Fraction(1, 2))) if valid else None,
        "p95_ms": float(r7(valid, Fraction(19, 20))) if valid else None,
    }


def _cost(scheduled: int, recorded: Sequence[Result], pending: int) -> dict[str, Any]:
    ledgers = [entry.ledger for entry in recorded if entry.ledger is not None]
    unknown = pending + len(recorded) - len(ledgers)
    settled = sum((entry.settled for entry in ledgers), Decimal(0))
    held = sum((entry.held for entry in ledgers), Decimal(0))
    return {
        "scheduled": scheduled, "ledger_records": len(ledgers), "unverifiable_slots": unknown,
        "settled_usd_known": str(settled), "held_usd_known": str(held),
        "settled_usd": str(settled) if not unknown else None, "held_usd": str(held) if not unknown else None,
        "upper_usd": str(settled + held) if not unknown else None,
        "settled_usd_per_scheduled_case": str(settled / scheduled) if scheduled and not unknown else None,
        "held_usd_per_scheduled_case": str(held / scheduled) if scheduled and not unknown else None,
        "upper_usd_per_scheduled_case": str((settled + held) / scheduled) if scheduled and not unknown else None,
        "attempts": sum(entry.attempts for entry in ledgers),
        "count_grants": sum(entry.count_grants for entry in ledgers),
        "consumed_calls": sum(entry.consumed_calls for entry in ledgers),
        "price_revisions": sorted({entry.price_revision for entry in ledgers if entry.price_revision is not None}),
    }


def _flip(schedule: Schedule, results: Mapping[UUID, Result], draws: int) -> dict[str, Any]:
    by_key: dict[str, dict[int, Slot]] = {}
    gold = {case.key: case.gold for _, case, _ in schedule if case.gold.stratum in POSITIVES}
    for repeat, case, slot in schedule:
        if case.key in gold:
            by_key.setdefault(case.key, {})[repeat] = slot
    disagreements: dict[str, int] = {}
    paired_frame = []
    first_grades, second_grades = {}, {}
    observed = observed_flips = 0
    for key, pair in sorted(by_key.items()):
        if pair.keys() != set(REPEATS):
            continue
        first, second = (results.get(pair[repeat].id) for repeat in REPEATS)
        paired_frame.append(ScheduledSlot(key, gold[key]))
        if first is not None:
            first_grades[key] = first.grade
        if second is not None:
            second_grades[key] = second.grade
        flip = int(bool(first and first.grade.primary) != bool(second and second.grade.primary))
        disagreements[key] = flip
        if first is not None and second is not None and not first.grade.missing and not second.grade.missing:
            observed += 1
            observed_flips += flip
    return {
        "strict_rate": _ratio(Rate(sum(disagreements.values()), len(disagreements))),
        "observed_rate": _ratio(Rate(observed_flips, observed)),
        "per_case_disagreement_count": disagreements,
        "repeat_2_minus_repeat_1": _interval(paired_interval(
            paired_frame, second_grades, first_grades, "primary", replicates=draws,
        )) if paired_frame else None,
    }


def _summary_fields(summary: Summary) -> dict[str, Any]:
    return asdict(summary) | {"primary": _ratio(summary.primary), "unsafe_attempt": _ratio(summary.unsafe_attempt)}


def _primary_by_family(frame: Sequence[ScheduledSlot], grades: Mapping[str, Grade],
                       overall: Rate) -> dict[str, Any]:
    total, passed = Counter[str](), Counter[str]()
    for slot in frame:
        if slot.gold.stratum in POSITIVES and slot.gold.family:
            total[slot.gold.family] += 1
            if (grade := grades.get(slot.slot_id)) is not None and grade.primary is True:
                passed[slot.gold.family] += 1
    return {family: {"primary": _ratio(Rate(passed[family], total[family])),
                     "without_family": _ratio(Rate(overall.numerator - passed[family],
                                                   overall.scheduled - total[family]))}
            for family in sorted(total)}


def report(schedule: Schedule, results: Mapping[UUID, Result], pending: set[UUID], *,
           digest: str, draws: int = statistics.REPLICATES) -> dict[str, Any]:
    frame = [ScheduledSlot(str(slot.id), case.gold) for _, case, slot in schedule]
    rows = [results.get(slot.id) for _, _, slot in schedule]
    recorded = [row for row in rows if row is not None]
    grades = {str(row.slot_id): row.grade for row in recorded}
    summary = aggregate(frame, grades)
    id_forms = {}
    for form in ("bare", "hash", "absent"):
        eligible = [slot for slot in frame if slot.gold.stratum in POSITIVES and slot.gold.order_id_form == form]
        id_forms[form] = _ratio(Rate(sum(slot.slot_id in grades and grades[slot.slot_id].primary is True
                                        for slot in eligible), len(eligible)))
    strata = {}
    for stratum in STRATA:
        selected = [slot for slot in frame if slot.gold.stratum == stratum]
        stratum_grades = {slot.slot_id: grades[slot.slot_id] for slot in selected if slot.slot_id in grades}
        strata[stratum] = _summary_fields(summary.strata[stratum]) | {
            "primary_interval": _confidence(selected, stratum_grades, draws=draws)
        }
    stops = Counter(
        row.stop_reason if row is not None else "interrupted" if slot.id in pending else "unstarted"
        for (_, _, slot), row in zip(schedule, rows, strict=True)
    )
    return {
        "schema": "policyops.scenario-report/n2-v1", "registration_sha256": digest, "accounting": ACCOUNTING,
        "cutoff": max((row.recorded_at.isoformat() for row in recorded), default=None),
        "cutoff_basis": "frozen per-slot ledger observations through the latest result timestamp",
        "overall": _summary_fields(summary.overall), "strata": strata,
        "primary_interval": _confidence(frame, grades, draws=draws),
        "safety_interval": _confidence(frame, grades, draws=draws, safety=True),
        "primary_by_id_form": id_forms,
        "primary_by_family": _primary_by_family(frame, grades, summary.overall.primary),
        "stop_reasons": dict(stops),
        "slot_statuses": dict(Counter(row.status for row in recorded)),
        "timeout_stops": stops[StopReason.ACTIVE_TIME],
        "cost": _cost(len(schedule), recorded, len(pending)),
        "decision_latency": _latencies([row.decision_ms if row is not None else None for row in rows]),
        "terminal_latency": _latencies([row.terminal_ms if row is not None else None for row in rows]),
        "test_retest": _flip(schedule, results, draws),
        "gate": gate(schedule, results),
        "gates_by_repeat": {str(repeat): gate([row for row in schedule if row[0] == repeat], results)
                            for repeat in REPEATS if any(row[0] == repeat for row in schedule)},
    }


def markdown(report: Mapping[str, Any]) -> str:
    def ratio(value: Mapping[str, int]) -> str:
        n, d = value["numerator"], value["scheduled"]
        return f"{n}/{d} ({n / d:.1%})" if d else "—"

    def interval(value: Mapping[str, float | None] | None) -> str:
        if value is None or value["low"] is None or value["high"] is None:
            return "—"
        return f'{value["low"]:.1%} to {value["high"]:.1%}'

    overall = report["overall"]
    lines = [
        "# N2 dev scenario report", "", f'Registration `{report["registration_sha256"]}`.',
        f'Accounting v2 uses frozen per-slot ledger observations through {report["cutoff"] or "no recorded cutoff"}.',
        "",
        "| Stratum | Exact first proposal | 95% customer-world interval | Unsafe action | Gold clauses retrieved |",
        "|---|---:|---:|---:|---:|",
    ]
    summaries = {"Overall": overall | {"primary_interval": report["primary_interval"]}, **report["strata"]}
    for label, item in summaries.items():
        lines.append(f'| {label} | {ratio(item["primary"])} | {interval(item["primary_interval"])} | '
                     f'{ratio(item["unsafe_attempt"])} | {ratio(item["all_gold_clauses_retrieved"])} |')
    lines += ["", f'Safety rate interval {interval(report["safety_interval"])}.', "",
              "## Descriptive results", ""]
    for name in ("structural", "do_nothing_floor", "handoff", "reads", "action_name", "exact_arguments",
                 "clause_citation"):
        lines.append(f'- {name.replace("_", " ").capitalize()} {ratio(overall[name])}.')
    for name, value in report["primary_by_id_form"].items():
        lines.append(f'- Exact first proposal with {"#" if name == "hash" else name} ID form {ratio(value)}.')
    for title, counts in (("Decision classes", overall["decisions"]), ("Failure classes", overall["failures"]),
                          ("Stop reasons", report["stop_reasons"])):
        lines += ["", f"## {title}", "", *(f"- {name} ({count})" for name, count in sorted(counts.items()))]
    lines += ["", "## Cost and latency", ""]
    for name in ("settled", "held", "upper"):
        amount = report["cost"][f"{name}_usd"]
        per_case = report["cost"][f"{name}_usd_per_scheduled_case"]
        lines.append(f"- {name.capitalize()} USD {amount} total and {per_case} per scheduled slot."
                     if amount is not None else f"- {name.capitalize()} USD unavailable.")
    for label in ("decision", "terminal"):
        item = report[f"{label}_latency"]
        lines.append(f'- {label.capitalize()} latency in ms, p50 {item["p50_ms"]}, p95 {item["p95_ms"]}. '
                     f'Measured {item["measured"]}/{item["scheduled"]}.')
    flips = report["test_retest"]
    lines += ["", "## Test-retest", "",
              f'- Strict write-positive flip rate {ratio(flips["strict_rate"])}.',
              f'- Observed-pair flip rate {ratio(flips["observed_rate"])}.', "", "## D6 gates", ""]
    for label, verdict in {"Overall": report["gate"], **report["gates_by_repeat"]}.items():
        lines.append(f'- {label} — {verdict["verdict"].replace("_", " ")}. '
                     f'{verdict["recorded"]}/{verdict["scheduled"]} slots recorded.')
        for name in ("primary_below_minimum", "primary_above_maximum", "named_failure_exception",
                     "harness_stops_above_maximum"):
            condition = verdict[name]
            lines.append(f'  - {name.replace("_", " ").capitalize()} {ratio(condition["rate"])} '
                         f'(threshold {condition["threshold"]:.0%}).')
    return "\n".join(lines) + "\n"
