"""Cross-check N7 raw usage and summarize all scheduled investigations."""

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal
from fractions import Fraction
from itertools import pairwise
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from sqlalchemy import Engine, text

from policyops.budget.config import ChatActor
from policyops.orchestration.minimal import AGENT_NAMESPACE, AGENT_OPERATION
from policyops.persistence.database import workspace_transaction
from policyops.providers.canonical import CanonicalError, strict_loads
from policyops_evals.qa_studies import statistics
from policyops_evals.scenarios import n3_report, n7, reporting, runtime, study
from policyops_evals.scenarios.arms import Arm
from policyops_evals.scenarios.batch import RunState, slot_directory
from policyops_evals.scenarios.cases import POSITIVES, SAFETY_STRATA, Stratum
from policyops_evals.scenarios.grading import Grade
from policyops_evals.scenarios.n3 import Assignment
from policyops_evals.scenarios.n3_runner import reconciles
from policyops_evals.scenarios.recording import Exchange, Tape, object_from


MODEL = "gpt-6-luna"
SERVICE_TIER = "default"
# Independent oracle for pricing.2026-11-05.v1, Luna short tier. The registered 10k
# input cap is below the tier boundary. Rates are USD per million tokens.
RATES = tuple(map(Decimal, ("0.10", "0.01", "0.125", "0.25", "0.50")))
COUNT_CONFIG = runtime.configuration().actors["agent"]
if not isinstance(COUNT_CONFIG, ChatActor):
    raise TypeError("N7 requires a chat actor")
COUNT_HEADROOM_PERCENT = COUNT_CONFIG.count_headroom_percent
COUNT_HEADROOM_MIN = COUNT_CONFIG.count_headroom_min


@dataclass(frozen=True)
class Usage:
    input: int
    read: int
    write_30m: int
    write_12h: int
    output: int
    reasoning: int

    @property
    def write(self) -> int:
        return self.write_30m + self.write_12h

    @property
    def usd(self) -> Decimal:
        counts = (self.input - self.read - self.write, self.read, self.write_30m, self.write_12h, self.output)
        return sum((n * rate for n, rate in zip(counts, RATES, strict=True)), Decimal(0)).scaleb(-6)

    def ledger(self, request_id: str, block: str | None) -> dict[str, object]:
        writes = {ttl: n for ttl, n in (("30m", self.write_30m), ("12h", self.write_12h)) if n}
        result: dict[str, object] = {"v": "policyops.usage/v1", "input_total": self.input, "cache_read": self.read,
                                     "cache_writes": writes, "output": self.output, "reasoning": self.reasoning,
                                     "provider_request_id": request_id}
        if block is not None:
            result["block"] = block
        return result


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**31:
        raise ValueError("invalid raw usage count")
    return value


def raw_usage(raw: str | None) -> tuple[Usage, str] | None:
    if raw is None:
        return None
    try:
        response = strict_loads(raw)
        if response["model"] != MODEL or response["service_tier"] != SERVICE_TIER:
            return None
        request_id = response["id"]
        if not isinstance(request_id, str) or not request_id:
            return None
        usage = response["usage"]
        prompt = _count(usage["input_tokens"])
        output = _count(usage["output_tokens"])
        reasoning = _count(usage["output_tokens_details"]["reasoning_tokens"])
        details = usage["input_tokens_details"]
        reads = _count(details["cached_tokens"])
        writes = _count(details["cache_write_tokens"])
        split = details.get("cache_write_tokens_details")
        short, long = (0, 0) if split is None and not writes else (
            _count(split["ttl_30m_tokens"]), _count(split["ttl_12h_tokens"]))
        if (short + long != writes or reads + writes > prompt or reasoning > output
                or _count(usage["total_tokens"]) != prompt + output or prompt > 272_000):
            return None
    except (CanonicalError, AttributeError, KeyError, TypeError, ValueError):
        return None
    return Usage(prompt, reads, short, long, output, reasoning), request_id


@dataclass(frozen=True)
class Attempt:
    id: UUID
    state: str
    counted: int | None
    block: str | None
    request_id: str | None
    tier: str | None
    actual_usd: Decimal | None
    usage: object


@dataclass(frozen=True)
class RunData:
    proposal_ms: int | None = None
    trimmed_pairs: int | None = None
    trimmed_notices: int | None = None
    started_at: datetime | None = None
    updated_at: datetime | None = None


def fetch(engine: Engine, workspace: UUID, frame: Sequence[Assignment]
          ) -> tuple[dict[UUID, list[Attempt]], dict[UUID, RunData]]:
    by_run = {item.slot.run: item.slot.id for item in frame}
    params = {"workspace": workspace, "runs": list(by_run)}
    with workspace_transaction(engine, workspace) as connection:
        attempts: dict[UUID, list[Attempt]] = defaultdict(list)
        for row in connection.execute(text("""
            SELECT s.run_id, a.id, a.state, a.counted_input_tokens, a.contract_block,
                   a.provider_request_id, a.actual_tier, a.actual_usd, a.usage
            FROM app.usage_attempts a JOIN app.budget_scopes s
                ON a.workspace_id = s.workspace_id AND a.scope_id = s.id
            WHERE s.workspace_id = :workspace AND s.run_id = ANY(:runs)
        """), params):
            attempts[by_run[row[0]]].append(Attempt(*row[1:]))
        records = {}
        for row in connection.execute(text("""
            SELECT r.id, r.created_at, r.updated_at, EXTRACT(EPOCH FROM (p.created_at - r.created_at)) * 1000,
                   CAST(c.payload #>> '{channel_values,state,trimmed_pairs}' AS integer),
                   CAST(c.payload #>> '{channel_values,state,trimmed_notices}' AS integer)
            FROM app.runs r
            LEFT JOIN LATERAL (
                SELECT min(created_at) AS created_at FROM app.action_proposals
                WHERE workspace_id = r.workspace_id AND run_id = r.id
            ) p ON true
            LEFT JOIN checkpoints.threads t ON t.workspace_id = r.workspace_id AND t.run_id = r.id
            LEFT JOIN LATERAL (
                SELECT payload FROM checkpoints.snapshots
                WHERE workspace_id = t.workspace_id AND thread_id = t.thread_id AND checkpoint_ns = ''
                ORDER BY checkpoint_id DESC LIMIT 1
            ) c ON true
            WHERE r.workspace_id = :workspace AND r.id = ANY(:runs)
        """), params):
            run, started, updated, proposal_ms, pairs, notices = row
            records[by_run[run]] = RunData(None if proposal_ms is None else int(proposal_ms),
                                           pairs, notices, started, updated)
    return dict(attempts), records


def attempt_id(run: UUID, index: int) -> UUID:
    return uuid5(uuid5(AGENT_NAMESPACE, f"{run}:{index}"), f"{AGENT_OPERATION}.r0.a0")


@dataclass(frozen=True)
class Call:
    index: int
    elapsed_ms: int | None
    usage: Usage | None


@dataclass(frozen=True)
class Audit:
    calls: tuple[Call, ...]
    count_grants: int
    settled: Decimal
    checked_calls: int
    checks: dict[str, bool]
    blocks: dict[str, int]


def audit(item: Assignment, tape: Sequence[Exchange], rows: Sequence[Attempt], reference: n7.Requests) -> Audit:
    creates = {entry.attempt: entry for entry in tape if entry.phase == "create"}
    counts = {entry.attempt: entry for entry in tape if entry.phase == "count"}
    by_id = {row.id: row for row in rows}
    keys = sorted(creates)
    dispatches = {row.id for row in rows if row.state in {"dispatching", "unresolved", "settled"}}
    # A lost or ambiguous capture cannot stand in for the immutable attempt.
    attempts_bound = ({attempt_id(item.slot.run, index) for index in keys} == dispatches
                      and keys == list(range(len(creates)))
                      and len(creates) + len(counts) == len(tape))
    requests_bound = not tape or (
        0 in counts and n7.request_digest(counts[0].request) == reference.count
        and (0 not in creates or n7.request_digest(creates[0].request) == reference.create))
    cache_off = True
    requested_ttl = True
    ledger_matches = True
    count_bound = True
    checked_calls = 0
    calls = []
    for index in keys:
        entry = creates[index]
        body = object_from(entry.request)
        requests_bound &= (body.get("prompt_cache_options") == n7.CACHE_OPTIONS[item.arm]
                           and "prompt_cache_key" not in body)
        raw = raw_usage(entry.response) if entry.complete and entry.status == 200 else None
        usage, request_id = raw if raw is not None else (None, None)
        calls.append(Call(index + 1, entry.elapsed_ms, usage))
        row = by_id.get(attempt_id(item.slot.run, index))
        counted = counts.get(index)
        count_value = object_from(counted.response).get("input_tokens") if counted is not None else None
        if usage is None or request_id is None or row is None:
            ledger_matches = False
            continue
        if item.arm is Arm.A0:
            cache_off &= usage.read == usage.write == 0
        else:
            requested_ttl &= usage.write_12h == 0
        expected = (row.state == "settled" and row.request_id == request_id and row.tier == "short"
                    and row.actual_usd == usage.usd and row.usage == usage.ledger(request_id, row.block))
        ledger_matches &= expected
        checked_calls += expected
        if (counted is None or counted.index >= entry.index or not counted.complete or counted.status != 200
                or type(count_value) is not int or row.counted != count_value):
            count_bound = False
        else:
            headroom = max((count_value * COUNT_HEADROOM_PERCENT + 99) // 100, COUNT_HEADROOM_MIN)
            count_bound &= (row.block != "count_underestimate"
                            and count_value >= 0 and usage.input <= count_value + headroom)
    blocks = Counter(row.block for row in rows if row.block is not None)
    return Audit(tuple(calls), len(counts), sum((row.actual_usd or Decimal(0) for row in rows), Decimal(0)),
                 checked_calls, {"attempts_bound": attempts_bound, "requests_bound": requests_bound,
                                 "ledger_matches": ledger_matches, "count_bound": count_bound,
                                 "zero_A0_cache": cache_off, "requested_A1_ttl": requested_ttl}, dict(blocks))


def pilot_gate(frame: Sequence[Assignment], audits: Mapping[UUID, Audit], runs: Mapping[UUID, RunData], *,
               complete: bool, integrity: bool) -> dict[str, Any]:
    warm = []
    for item in frame:
        usage = [call.usage for call in audits[item.slot.id].calls]
        if item.arm is Arm.A1:
            warm.append(usage)
    first = [calls[0] if calls else None for calls in warm]
    call1 = bool(first) and all(
        usage is not None and usage.input > 0 and usage.write_12h == 0
        and (usage.read > 0 or 100 * usage.write_30m >= n7.PREFIX_PERCENT * usage.input)
        for usage in first)
    call2 = bool(warm) and all(
        len(calls) >= 2 and calls[0] is not None and calls[1] is not None and calls[0].input > 0
        and 100 * calls[1].read >= n7.PREFIX_PERCENT * calls[0].input
        for calls in warm)
    extensions = [pair for calls in warm for pair in pairwise(calls)]
    later = sum(max(0, len(calls) - 2) for calls in warm)
    deltas = later > 0 and all(
        previous is not None and current is not None and current.write_12h == 0
        and current.write < current.input
        and current.write <= max(0, current.input - previous.input) + n7.DELTA_SLACK_TOKENS
        for previous, current in extensions)
    warm_control_gaps = []
    for previous, item in pairwise(frame):
        if (previous.arm is Arm.A1 and item.arm is Arm.A0
                and any(call.usage is not None and call.usage.read > 0 for call in audits[previous.slot.id].calls)):
            finished = runs[previous.slot.id].updated_at if previous.slot.id in runs else None
            started = runs[item.slot.id].started_at if item.slot.id in runs else None
            if finished is not None and started is not None:
                warm_control_gaps.append(int((started - finished).total_seconds() * 1000))
    after_warm = sum(0 <= gap <= n7.WARM_CONTROL_MAX_GAP_MS for gap in warm_control_gaps)
    off = bool(after_warm) and all(
        audits[item.slot.id].calls
        and all(call.usage is not None and call.usage.read == call.usage.write == 0
                for call in audits[item.slot.id].calls)
        for item in frame if item.arm is Arm.A0)
    checks = {"complete": complete, "ledger_and_tape_integrity": integrity, "A1_call_1_write_or_reuse": call1,
              "A1_call_2_prefix_read": call2, "A1_later_writes_deltas": deltas, "A0_cache_off_after_warm_A1": off}
    return {"verdict": "admit" if all(checks.values()) else "stop", "checks": checks,
            "A1_call_1_cross_investigation_reuse_slots": sum(usage is not None and usage.read > 0 for usage in first),
            "A1_later_creates": later, "A0_slots_after_warm_A1": after_warm,
            "A0_gaps_after_warm_A1_ms": warm_control_gaps}


@dataclass(frozen=True)
class Observation:
    item: Assignment
    grade: Grade | None
    audit: Audit
    run: RunData
    state: RunState | None

    @property
    def horizon_ms(self) -> int:
        value = self.run.proposal_ms
        return n7.HORIZON_MS if value is None else min(value, n7.HORIZON_MS)


def _arm(rows: Sequence[Observation]) -> dict[str, Any]:
    ledger = n3_report.ledger_totals({row.item.slot.id: row.state for row in rows if row.state is not None})
    calls = [call for row in rows for call in row.audit.calls]
    usage = [call.usage for call in calls if call.usage is not None]
    first = [call.usage for call in calls if call.index == 1 and call.usage is not None]
    reads = sum(u.read for u in usage)
    writes_30m, writes_12h = sum(u.write_30m for u in usage), sum(u.write_12h for u in usage)
    proposal = [row.run.proposal_ms for row in rows]
    by_call: dict[int, list[int | None]] = defaultdict(list)
    for call in calls:
        by_call[call.index].append(call.elapsed_ms)
    input_total = sum(u.input for u in usage)
    call1_inputs, call1_reads = sum(u.input for u in first), sum(u.read for u in first)
    settled = sum((row.audit.settled for row in rows), Decimal(0))
    return {
        "scheduled": len(rows), "recorded": sum(row.grade is not None for row in rows),
        "settled_usd_per_scheduled_slot": str(settled / len(rows)), "ledger": ledger,
        "calls_per_scheduled_slot": sum(row.state.ledger.consumed_calls for row in rows
                                        if row.state is not None and row.state.ledger is not None) / len(rows),
        "calls": {"taped_creates": len(calls), "parseable_usage": len(usage),
                  "ledger_verified": sum(row.audit.checked_calls for row in rows)},
        "cache": {"input_tokens": input_total, "read_tokens": reads,
                  "write_tokens": {"30m": writes_30m, "12h": writes_12h},
                  "read_share": reads / input_total if input_total else None,
                  "write_share": (writes_30m + writes_12h) / input_total if input_total else None,
                  "call_1_input_tokens": call1_inputs, "call_1_read_tokens": call1_reads,
                  "call_1_read_share": call1_reads / call1_inputs if call1_inputs else None},
        "evictions": {"slots_with_checkpoint_counts": sum(row.run.trimmed_pairs is not None for row in rows),
                      "pairs": sum(row.run.trimmed_pairs or 0 for row in rows),
                      "notices": sum(row.run.trimmed_notices or 0 for row in rows)},
        "proposal": {"persisted": sum(value is not None for value in proposal),
                     "by_horizon": sum(value is not None and value <= n7.HORIZON_MS for value in proposal),
                     "conditional": reporting._latencies(proposal),
                     "horizon_ms": n7.HORIZON_MS,
                     "mean_time_at_horizon_ms": sum(r.horizon_ms for r in rows) / len(rows)},
        "elapsed_ms_by_create_index": {str(index): reporting._latencies(values)
                                       for index, values in sorted(by_call.items())},
    }


def _estimate(n: Sequence[Fraction], d: Sequence[Fraction], rows: Sequence[Observation], draws: int
              ) -> statistics.Estimate:
    return statistics.cluster_ratio(n, d, [row.item.case.gold.customer_world for row in rows],
                                    seed=n7.BOOTSTRAP_SEED, replicates=draws)


def _discordance(a: Sequence[bool], b: Sequence[bool], a_label: str, b_label: str) -> dict[str, int | float | None]:
    counts = Counter(zip(a, b, strict=True))
    return {"both": counts[True, True], f"{a_label}_only": counts[True, False],
            f"{b_label}_only": counts[False, True], "neither": counts[False, False], "pairs": len(a),
            "disagreement_share": (counts[True, False] + counts[False, True]) / len(a) if a else None}


def _outcome(a0: Sequence[Observation], a1: Sequence[Observation], metric: str, strata: Sequence[Stratum],
             draws: int) -> tuple[dict[str, Any], statistics.Estimate]:
    a, b = [[row for row in arm if row.item.case.gold.stratum in strata] for arm in (a0, a1)]

    def scores(rows: Sequence[Observation]) -> list[bool]:
        return [row.grade is not None and getattr(row.grade, metric) is True for row in rows]

    off, on = scores(a), scores(b)
    estimate = _estimate([Fraction(y - x) for x, y in zip(off, on, strict=True)], [Fraction(1)] * len(a), a, draws)
    within = {}
    for arm, rows in zip(n7.ARMS, (a, b), strict=True):
        repeats = {repeat: {row.item.case.key: value for row, value in zip(rows, scores(rows), strict=True)
                            if row.item.repeat == repeat} for repeat in study.REPEATS}
        keys = sorted(repeats[1].keys() & repeats[2].keys())
        within[arm] = _discordance([repeats[1][key] for key in keys], [repeats[2][key] for key in keys], "r1", "r2")
    return {
        "A1_minus_A0": reporting._interval(estimate),
        "between_arm": _discordance(off, on, "A0", "A1"),
        "within_arm_repeat_disagreement": within,
        "missing_grades": {arm: sum(row.grade is None or row.grade.missing for row in rows)
                           for arm, rows in zip(n7.ARMS, (a, b), strict=True)},
    }, estimate


def comparison(a0: Sequence[Observation], a1: Sequence[Observation], *, complete: bool, draws: int) -> dict[str, Any]:
    off, on = ([Fraction(row.audit.settled) for row in rows] for rows in (a0, a1))
    ones = [Fraction(1)] * len(a0)
    difference = _estimate([y - x for x, y in zip(off, on, strict=True)], ones, a0, draws)
    exact, quality = _outcome(a0, a1, "primary", POSITIVES, draws)
    safety, unsafe = _outcome(a0, a1, "unsafe_attempt", SAFETY_STRATA, draws)
    guardrail = {"exact_lower_bound": quality.n == 192 and quality.low is not None and quality.low > n7.EXACT_MARGIN,
                 "unsafe_point": unsafe.n == 48 and unsafe.point is not None and unsafe.point <= n7.UNSAFE_MARGIN}
    times = [Fraction(y.horizon_ms - x.horizon_ms) for x, y in zip(a0, a1, strict=True)]
    return {
        "settled_cost_ratio_A1_over_A0": reporting._interval(_estimate(on, off, a0, draws)),
        "settled_cost_difference_A1_minus_A0": reporting._interval(difference),
        "proposal_time_difference_at_horizon_ms": reporting._interval(_estimate(times, ones, a0, draws)),
        "pairs_with_both_proposals": sum(x.run.proposal_ms is not None and y.run.proposal_ms is not None
                                         for x, y in zip(a0, a1, strict=True)),
        "exact_first_proposal": exact, "unsafe_attempt": safety,
        "outcome_guardrail": {"checks": guardrail, "verdict": ("pass" if all(guardrail.values()) else "fail")
                              if complete else "incomplete", "descriptive": True},
    }


def report(engine: Engine, workspace: UUID, out: Path, frame: Sequence[Assignment], inputs: n7.Inputs,
           phase: n7.Phase, digest: str, live: Mapping[UUID, RunState], closure: str | None,
           *, draws: int = statistics.REPLICATES) -> dict[str, Any]:
    evidence = n3_report.collect(out, frame, digest, live)
    attempts, records = fetch(engine, workspace, frame)
    observations: dict[Arm, list[Observation]] = {arm: [] for arm in n7.ARMS}
    audits = {}
    slots = []
    problems: Counter[str] = Counter()
    complete = (closure is None and len(evidence.results) == len(frame) and not evidence.pending
                and all(result.terminal_ms is not None for result in evidence.results.values()))
    for item in frame:
        key = item.slot.id
        directory = study.private_child(slot_directory(out, item.slot), "tape")
        tape = Tape(directory if directory.is_dir() else None)
        audit_row = audit(item, tape.records, attempts.get(key, []), inputs.requests[item.arm][item.case.key])
        audits[key] = audit_row
        entry, state = evidence.results.get(key), live.get(key)
        ledger = state.ledger if state else None
        record = records.get(key, RunData())
        observations[item.arm].append(Observation(item, entry.grade if entry else None, audit_row, record, state))
        slots.append({
            "slot": str(key), "case": item.case.key, "repeat": item.repeat, "arm": item.arm,
            "first_proposal_ms": record.proposal_ms, "decision_ms": entry.decision_ms if entry else None,
            "status": entry.status if entry else "pending" if key in evidence.pending else "unstarted",
            "stop_reason": entry.stop_reason if entry else None,
            "settled_usd": str(audit_row.settled), "held_usd": str(ledger.held) if ledger else None,
            "evictions": {"pairs": record.trimmed_pairs, "notices": record.trimmed_notices},
        })
        problems.update(name for name, ok in audit_row.checks.items() if not ok)
        if (ledger is None and (state is not None or tape.records)) or (ledger is not None and (
            ledger.held or ledger.overrun or ledger.contract_block or ledger.settled != audit_row.settled
            or ledger.consumed_calls != audit_row.checked_calls or ledger.count_grants != audit_row.count_grants
            or ledger.attempts != len(attempts.get(key, ()))
        )):
            problems["scope_accounting"] += 1
        if ((state is not None and (state.active or state.proposed != (record.proposal_ms is not None)))
                or (record.proposal_ms is not None and record.proposal_ms < 0)):
            problems["run_state"] += 1
        if entry is not None and (entry.failure_kind == "recorder" or state is None):
            problems["capture"] += 1
    integrity = not problems and not evidence.pending and reconciles(evidence.results, live)
    result: dict[str, Any] = {
        "schema": "policyops.scenario-study/n7-report-v1", "phase": phase, "registration_sha256": digest,
        "panel": inputs.binding["panel"], "registered_arms": inputs.binding["arms"],
        "requested_model": inputs.binding["model"], "analysis": inputs.binding["analysis"],
        "scheduled": len(frame), "recorded": len(evidence.results), "complete": complete, "closure": closure,
        "integrity": integrity, "failed_integrity_checks_by_slot": dict(problems),
        "evidence_sha256": evidence.sha256, "ledger": n3_report.ledger_totals(live),
        "arms": {arm: _arm(rows) for arm, rows in observations.items()},
        "slots": slots,
    }
    if phase == "pilot":
        result["pilot_gate"] = pilot_gate(frame, audits, records, complete=complete, integrity=integrity)
        result["pilot_slots"] = [
            {"slot": str(item.slot.id), "arm": item.arm, "case": item.case.key,
             "checks": audits[item.slot.id].checks, "blocks": audits[item.slot.id].blocks,
             "calls": [asdict(call) for call in audits[item.slot.id].calls]}
            for item in frame
        ]
    else:
        result["cost_claim_admissible"] = complete and integrity
        result["paired"] = comparison(observations[Arm.A0], observations[Arm.A1], complete=complete, draws=draws)
    return result
