"""Derive N10 trial, repeat and optional paired comparison results from JSONL."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta
import hashlib
from io import BytesIO, TextIOWrapper
from itertools import pairwise
import json
import math
from pathlib import Path
import random
import re
from statistics import median
from typing import Any

from scripts.load_sampler import SAMPLE_CADENCE, SERVICES
from scripts.loadgen import GENERATOR_CADENCE, SEND_LAG_LIMIT, Stage, percentile, schedule


def read_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8-sig") as source:
        return [json.loads(line) for line in source if line.strip()]


def elapsed(row: dict[str, Any]) -> float:
    return float(row["done"] - row["intended"])


def stats(samples: Iterable[float]) -> dict[str, Any]:
    values = list(samples)
    result = {
        "n": len(values),
        "p50": percentile(values, 0.5),
        "p95": percentile(values, 0.95),
        "max": max(values, default=None),
    }
    if len(values) >= 1000:
        result["p99"] = percentile(values, 0.99)
    return result


def success(row: dict[str, Any]) -> bool:
    return (
        row.get("done") is not None
        and row.get("error") is None
        and row.get("status") is not None
        and (200 <= row["status"] < 300 or (row.get("endpoint") == "workflow" and row["status"] == 409))
    )


def rates(rows: list[dict[str, Any]], seconds: float) -> dict[str, Any]:
    errors = Counter(
        f"{row.get('status') or '-'} {row.get('rule_id') or '-'} {row['error']}" for row in rows if row.get("error")
    )
    done = [row for row in rows if success(row)]
    valid_completions = [
        row for row in done if row["kind"] != "slot" or row["endpoint"] == "workflow" or elapsed(row) <= 2
    ]
    sent = sum(row.get("sent") is not None for row in rows)
    replies = sum(row.get("status") is not None for row in rows)
    return {
        "offered": len(rows),
        "sent": sent,
        "completed": replies,
        "succeeded": len(valid_completions),
        "offered_rate": len(rows) / seconds,
        "sent_rate": sent / seconds,
        "completed_rate": replies / seconds,
        "goodput": len(valid_completions) / seconds,
        "successful_latency_s": stats(map(elapsed, done)),
        "errors": dict(sorted(errors.items())),
        "statuses": dict(sorted(Counter(str(row["status"]) for row in rows if row.get("status")).items())),
        "rules": dict(sorted(Counter(row["rule_id"] for row in rows if row.get("rule_id")).items())),
    }


def counter_delta(first: dict[str, Any], last: dict[str, Any]) -> dict[str, Any]:
    return {
        name: last[name] - value
        for name, value in first.items()
        if type(value) in (int, float) and type(last.get(name)) in (int, float)
    }


def numbers(mapping: Any, fields: set[str]) -> bool:
    return isinstance(mapping, dict) and all(
        type(mapping.get(key)) in (int, float) and math.isfinite(mapping[key]) for key in fields
    )


DOCKER_NUMBER = r"[0-9]+(?:\.[0-9]+)?"
DOCKER_BYTES = rf"{DOCKER_NUMBER}(?:B|kB|[KMGTPEZY]iB|[MGTPEZY]B)"
DOCKER_STATS = {
    "CPUPerc": rf"{DOCKER_NUMBER}%", "MemPerc": rf"{DOCKER_NUMBER}%", "PIDs": r"[0-9]+",
    **dict.fromkeys(("MemUsage", "NetIO", "BlockIO"), rf"{DOCKER_BYTES} / {DOCKER_BYTES}"),
}


def docker_measurements(item: Any) -> bool:
    return isinstance(item, dict) and all(
        isinstance(value := item.get(key), str) and re.fullmatch(pattern, value) is not None
        and all(math.isfinite(float(number)) for number in re.findall(DOCKER_NUMBER, value))
        for key, pattern in DOCKER_STATS.items()
    )


def sampler_fields(row: dict[str, Any]) -> bool:
    kind = row["kind"]
    if kind == "host":
        return (
            numbers(row.get("cpu_percent"), {"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"})
            and numbers(row.get("memory_kib"), {"MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached",
                                                "SwapTotal", "SwapFree"})
            and numbers(row.get("swap_pages"), {"pswpin", "pswpout"})
        )
    if kind == "postgres":
        activity = row.get("activity")
        return (
            isinstance(activity, list) and all(
                numbers(item, {"count"})
                and all(key in item and (item[key] is None or isinstance(item[key], str))
                        for key in ("application_name", "state", "wait_event_type", "wait_event"))
                for item in activity
            ) and numbers(row.get("due"), {"count", "oldest_s"})
        )
    inspect, stats = row.get("inspect"), row.get("stats")
    return (
        isinstance(inspect, dict) and isinstance(stats, dict) and inspect.keys() == stats.keys() == SERVICES
        and all(
            numbers(item, {"restarts", "memory_limit"}) and isinstance(item.get("oom"), bool)
            and all(isinstance(item.get(key), str) and item[key] for key in ("id", "image", "status"))
            and "health" in item and (item["health"] is None or isinstance(item["health"], str))
            for item in inspect.values()
        ) and all(map(docker_measurements, stats.values()))
    )


def counter_fields(row: dict[str, Any]) -> bool:
    database, tables = row.get("database"), row.get("tables")
    return (
        isinstance(database, dict)
        and numbers(database, {"xact_commit", "xact_rollback", "blks_read", "blks_hit", "tup_returned", "tup_fetched",
                           "tup_inserted", "tup_updated", "tup_deleted", "conflicts", "temp_files", "temp_bytes",
                           "deadlocks", "blk_read_time", "blk_write_time"})
        and "stats_reset" in database and (database["stats_reset"] is None or isinstance(database["stats_reset"], str))
        and isinstance(tables, list) and bool(tables) and all(
            numbers(item, {"seq_scan", "seq_tup_read", "n_tup_ins", "n_tup_upd", "n_tup_del", "n_tup_hot_upd",
                           "n_live_tup", "n_dead_tup"}) and isinstance(item.get("name"), str) and bool(item["name"])
            and all(key in item and (item[key] is None or numbers(item, {key}))
                    for key in ("idx_scan", "idx_tup_fetch")) for item in tables
        ) and len({item["name"] for item in tables}) == len(tables)
    )


def coverage(
    points: Iterable[float], start: float, end: float, cadence: float, tolerance: float, *, bracket: bool = False,
) -> bool:
    samples = sorted(set(point for point in points if math.isfinite(point)))
    inside = [point for point in samples if start <= point <= end]
    if len(inside) < max(2, math.floor((end - start) / cadence) - 1):
        return False
    before = [point for point in samples if point <= start]
    after = [point for point in samples if point >= end]
    if bracket and (not before or not after):
        return False
    window = [before[-1] if bracket else start, *inside, after[0] if bracket else end]
    return all(right - left <= cadence + tolerance for left, right in pairwise(window))


def summarize_sampler(
    rows: list[dict[str, Any]], start: datetime, end: datetime, drain_end: datetime
) -> dict[str, Any]:
    def offset(row: dict[str, Any]) -> float:
        return (datetime.fromisoformat(row["utc"]) - start).total_seconds()

    duration, total = (end - start).total_seconds(), (drain_end - start).total_seconds()
    sources: dict[str, list[dict[str, Any]]] = {kind: [] for kind in SAMPLE_CADENCE}
    incomplete = set()
    for row in rows:
        kind = row["kind"]
        if kind in sources:
            if sampler_fields(row):
                sources[kind].append(row)
            elif 0 <= offset(row) <= total:
                incomplete.add(kind)
    covered = {
        kind: kind not in incomplete and coverage(
            map(offset, observations), 0, total, SAMPLE_CADENCE[kind],
            1.5 if kind == "containers" else 0.5, bracket=True,
        )
        for kind, observations in sources.items()
    }
    postgres = sorted(sources["postgres"], key=offset)
    measured = [row for row in postgres if 0 <= offset(row) <= duration]
    due = [row["due"] for row in measured]
    drained = [
        row["due"]
        for row in postgres
        if total <= offset(row) <= total + SAMPLE_CADENCE["postgres"] + 0.5
    ]
    first, last = due[:30], due[-30:]
    growing = bool(
        len(due) >= 60
        and median(row["count"] for row in last) > median(row["count"] for row in first)
        and median(row["oldest_s"] for row in last) > median(row["oldest_s"] for row in first)
    )
    counters = sorted((row for row in rows if row["kind"] == "pg_counters"), key=offset)
    limit = SAMPLE_CADENCE["containers"] + 1.5
    before = [row for row in counters if -limit <= offset(row) <= 0]
    after = [row for row in counters if duration <= offset(row) <= duration + limit]
    deltas = {}
    if before and after and all(counter_fields(row) for row in (before[-1], after[0])):
        left, right = before[-1], after[0]
        by_name = {row["name"]: row for row in right["tables"]}
        if (left["database"]["stats_reset"] == right["database"]["stats_reset"]
                and by_name.keys() == {row["name"] for row in left["tables"]}):
            deltas = {
                "seconds": offset(right) - offset(left),
                "database": counter_delta(left["database"], right["database"]),
                "tables": {row["name"]: counter_delta(row, by_name[row["name"]]) for row in left["tables"]},
            }
    return {
        "samples": len(measured),
        "coverage_ok": (
            all(covered.values()) and bool(deltas) and any(
                row["kind"] == "sampler_meta" and row["cadence_s"] == SAMPLE_CADENCE for row in rows
            )
        ),
        "coverage": covered,
        "counter_deltas": deltas,
        "due_start": first[0] if first else None,
        "due_end": last[-1] if last else None,
        "due_after_drain": drained[0] if drained else None,
        "growing_due_backlog": growing,
        "abort": [row["reason"] for row in rows if row["kind"] == "abort"],
    }


def reconcile_decisions(raw: list[dict[str, Any]]) -> bool:
    workflows = {
        (row["phase"], row["index"]): row.get("sent") is not None
        for row in raw if row["kind"] == "slot" and row["endpoint"] == "workflow" and "index" in row
    }
    writes = set()
    cases = set()
    expected: Counter[tuple[str, str, str, int | None]] = Counter()
    observed: Counter[tuple[str, str, str, int | None]] = Counter()
    for row in raw:
        if row["kind"] == "write":
            key = (row.get("phase"), row.get("index"))
            case, decisions = row.get("case_id"), row.get("decisions")
            if (key not in workflows or key in writes or not isinstance(case, str) or case in cases
                    or not isinstance(row.get("control"), str) or not isinstance(decisions, list)
                    or not workflows[key]):
                return False
            writes.add(key)
            cases.add(case)
            for index, status in enumerate(decisions):
                if status is not None and (type(status) is not int or not 100 <= status <= 599):
                    return False
                route = "decision_replay" if row["control"] == "replay" and index else "decision"
                expected[row["phase"], case, route, status] += 1
        elif row["kind"] == "http" and row["endpoint"] in {"decision", "decision_replay"}:
            status = row.get("status")
            if (
                "status" not in row or not isinstance(row.get("case_id"), str)
                or (status is not None and (type(status) is not int or not 100 <= status <= 599))
                or not numbers(row, {"sent", "intended", "done"})
                or not row["intended"] <= row["sent"] <= row["done"]
            ):
                return False
            observed[row["phase"], row["case_id"], row["endpoint"], status] += 1
    return writes >= {key for key, sent in workflows.items() if sent} and observed == expected


def reconcile_terminal(measured: list[dict[str, Any]]) -> bool:
    approvals = Counter(
        row["case_id"] for row in measured if row["kind"] == "write"
        and row["control"] != "reject" for status in row["decisions"] if status == 201
    )
    timings: Counter[str] = Counter()
    for row in measured:
        if row.get("endpoint") != "approval_to_terminal":
            continue
        if (
            row["kind"] != "timing" or not isinstance(row.get("case_id"), str) or row.get("choice") != "approve"
            or row.get("status") != 200 or row.get("error") or not numbers(row, {"intended", "sent", "done"})
            or not 0 <= row["intended"] == row["sent"] <= row["done"]
        ):
            return False
        timings[row["case_id"]] += 1
    return all(count == 1 for count in timings.values()) and timings == approvals


def summarize(
    raw: list[dict[str, Any]],
    check: dict[str, Any] | None = None,
    samples: list[dict[str, Any]] | None = None,
    credits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    meta = next(row for row in raw if row["kind"] == "meta")
    stage = meta["stage"]
    specification = Stage(**stage)
    expected_slots = Counter(
        (slot.route, slot.index, slot.offset, specification.phase(slot.offset))
        for slot in schedule(specification, meta["seed"])
    )
    observed_slots = Counter(
        (row["endpoint"], row.get("index"), row["intended"], row["phase"])
        for row in raw if row["kind"] == "slot"
    )
    schedule_ok = expected_slots == observed_slots
    seconds = stage["measured"]
    measured = [row for row in raw if row.get("phase") == "measured"]
    slots = [row for row in measured if row["kind"] == "slot"]
    browse = rates([row for row in slots if row["endpoint"] != "workflow"], seconds)
    workflow_slots = [row for row in raw if row["kind"] == "slot" and row["endpoint"] == "workflow"]
    workflow = rates([row for row in workflow_slots if row["phase"] == "measured"], seconds)
    drops = Counter(
        row["phase"] for row in workflow_slots
        if row.get("sent") is None and row.get("error") in {"missed_slot", "overflow"}
    )
    writes = {row["index"]: row for row in raw if row["kind"] == "write" and "index" in row}
    violations = (check or {}).get("violations", [])
    failed_cases = {finding["case_id"] for finding in violations if "case_id" in finding}
    failed_streams = {finding["stream_id"] for finding in violations if "stream_id" in finding}
    sut_failures = sum(
        row.get("sent") is not None and (
            not success(row) or row.get("index") not in writes
            or writes[row["index"]].get("case_id") in failed_cases
            or writes[row["index"]].get("run_id") in failed_streams
        )
        for row in workflow_slots
    )
    workflow.update(
        generator_misses=drops["measured"], generator_miss_allowance=workflow["offered"] // 100,
        warmup_generator_misses=drops["warmup"], sut_failures=sut_failures,
    )
    per_route: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in measured:
        if row["kind"] in {"slot", "http", "stream", "timing"}:
            per_route[row["endpoint"]].append(row)
    decision_evidence_ok = reconcile_decisions(raw)
    routes = {
        name: rates(values, seconds) for name, values in sorted(per_route.items())
        if decision_evidence_ok or name not in {"decision", "decision_replay"}
    }
    decisions: dict[str, list[float]] = defaultdict(list)
    if decision_evidence_ok:
        for row in per_route["decision"] + per_route["decision_replay"]:
            decisions[str(row["status"]) if row.get("status") is not None else "no_response"].append(elapsed(row))
    decision = stats(value for values in decisions.values() for value in values)
    terminal_evidence_ok = decision_evidence_ok and reconcile_terminal(measured)
    terminal = stats(elapsed(row) for row in per_route["approval_to_terminal"] if terminal_evidence_ok)
    # Continuous W2 sessions begin in warm-up. Retain the unmeasured setup/header observations separately.
    hold_metrics = defaultdict(list)
    for row in raw:
        if row["kind"] == "stream" and str(row.get("stream_id", "")).startswith("hold-"):
            hold_metrics[row["endpoint"]].append(row)
    hold_ends = [row for row in raw if row["kind"] == "stream_end" and not row["workflow"]]
    all_errors = Counter(
        f"{row.get('status') or '-'} {row.get('rule_id') or '-'} {row['error']}" for row in measured if row.get("error")
    )
    problems = [row["reason"] for row in raw if row["kind"] == "abort"]
    problems.extend(row["error"] for row in raw if row.get("correctness") and row["kind"] != "abort")
    dispatch_lags = []
    dispatch_evidence_ok = True
    for row in slots:
        if row.get("sent") is not None:
            dispatch_lags.append(row["sent"] - row["intended"])
        elif numbers(row, {"dispatch_lag"}):
            dispatch_lags.append(row["dispatch_lag"])
        elif row.get("error") in {"missed_slot", "overflow"}:
            dispatch_evidence_ok = False
    lag = percentile(dispatch_lags, 0.99)
    generator = [row for row in raw if row["kind"] == "generator"]
    generator_covered = (
        meta.get("generator_cadence_s") == GENERATOR_CADENCE
        and coverage(
            (row["offset"] for row in generator if math.isfinite(row.get("cpu_percent", math.nan))),
            specification.warmup, specification.arrivals_end, GENERATOR_CADENCE, 0.5,
        )
    )
    peak = max((row["cpu_percent"] for row in generator), default=None)
    loop_lag_peak = max(
        (row["event_loop_lag_max_s"] for row in generator if numbers(row, {"event_loop_lag_max_s"})), default=None,
    )
    validity = (
        schedule_ok and generator_covered and dispatch_evidence_ok and lag is not None and 0 <= lag <= SEND_LAG_LIMIT
        and peak is not None and 0 <= peak <= 50
    )
    ended = next((row for row in raw if row["kind"] == "stage_end"), None)
    started = next((row for row in raw if row["kind"] == "stage_start"), None)
    server = None
    measure_start = datetime.fromisoformat(started["utc"]) + timedelta(seconds=stage["warmup"]) if started else None
    measure_end = measure_start + timedelta(seconds=seconds) if measure_start is not None else None
    credit_window = credit_bracket(credits, meta.get("setup_utc"), ended, measure_start, measure_end)
    credits = credits if credit_window else None
    if measure_start is not None and measure_end is not None and samples:
        server = summarize_sampler(
            samples,
            measure_start,
            measure_end,
            measure_end + timedelta(seconds=stage["drain"]),
        )
    if browse["offered"] == 0 or browse["successful_latency_s"]["p95"] is None:
        browse_pass = False
    else:
        browse_pass = (
            browse["successful_latency_s"]["p95"] <= 0.5
            and browse["succeeded"] / browse["offered"] >= 0.99
            and browse["completed"] / browse["offered"] >= 0.95
        )
    workflow_pass = not workflow["offered"] or (
        workflow["generator_misses"] <= workflow["generator_miss_allowance"]
        and workflow["sent"] + workflow["generator_misses"] == workflow["offered"]
        and decision["p95"] is not None
        and decision["p95"] <= 1
        and terminal["p95"] is not None
        and terminal["p95"] <= 10
    )
    hold_pass = len(hold_ends) == stage["streams"] and not any(
        row.get("error") for values in hold_metrics.values() for row in values
    )
    if not validity:
        outcome = "invalid"
    elif sut_failures:
        outcome = "failed"
    elif not (decision_evidence_ok and terminal_evidence_ok):
        outcome = "invalid"
    elif (
        problems
        or not ended
        or ended["aborted"]
        or (check is not None and not check["ok"])
        or (
            server
            and (
                server["growing_due_backlog"]
                or server["abort"]
                or (server["due_after_drain"] and server["due_after_drain"]["count"])
            )
        )
    ):
        outcome = "failed"
    elif stage["limiter"]:
        outcome = (
            "shedding_observed"
            if any(row.get("status") == 429 and row.get("rule_id") == "api.public_rate_limit" for row in measured)
            and check
            and check["ok"]
            and server
            and server["coverage_ok"]
            else "unverified"
        )
    elif not (browse_pass and workflow_pass and hold_pass):
        outcome = "failed"
    elif (
        check is None
        or not server
        or not server["coverage_ok"]
        or (meta["environment"] == "lightsail" and credits is None)
    ):
        outcome = "unverified"
    else:
        outcome = "passed"

    classification = meta["environment"]
    burn_per_hour = None
    if credits and credit_window:
        credit_delta = credits["before"]["BurstCapacityPercentage"] - credits["after"]["BurstCapacityPercentage"]
        before, after = credit_window
        credited_seconds = (after - before).total_seconds()
        burn_per_hour = credit_delta * 3600 / credited_seconds
        if meta["environment"] == "lightsail":
            classification = (
                "sustained"
                if outcome == "passed"
                and seconds >= 1800
                and credit_delta <= 0
                and measure_start is not None
                and credits_hold(credits.get("samples", []), measure_start, seconds, bracket=credit_window)
                and not stage["streams"]
                and not workflow["offered"]
                else "burst"
            )
    return {
        "meta": meta,
        "outcome": outcome,
        "label": classification,
        "stage_start_utc": started["utc"] if started else None,
        "correctness_failed": bool(
            (check is not None and not check["ok"] and ("complete" not in check or check["violations"]))
            or any(row.get("correctness") for row in raw)
        ),
        "schedule_ok": schedule_ok,
        "generator_coverage": generator_covered,
        "generator_valid": validity,
        "generator_peak_cpu_pct": peak,
        "event_loop_lag_max_s": loop_lag_peak,
        "send_lag_p99_s": lag,
        "login_s": stats(elapsed(row) for row in raw if row["kind"] == "login"),
        "sessions": next((row for row in raw if row["kind"] == "sessions"), None),
        "write_validity": started.get("write_validity") if started else None,
        "browse": browse,
        "workflow": workflow,
        "decision_http_s": decision,
        "decision_evidence_ok": decision_evidence_ok,
        "decision_http_by_status_s": {status: stats(values) for status, values in sorted(decisions.items())},
        "approval_to_terminal_s": terminal,
        "approval_to_terminal_evidence_ok": terminal_evidence_ok,
        "routes": routes,
        "sse_hold": {name: rates(values, seconds) for name, values in hold_metrics.items()},
        "streams": len(hold_ends),
        "reconnects": sum(row["reconnects"] for row in hold_ends),
        "errors": dict(sorted(all_errors.items())),
        "problems": problems,
        "checker": check,
        "server": server,
        "credits": credits,
        "credit_burn_percentage_points_hour": burn_per_hour,
    }


def credit_bracket(
    credits: dict[str, Any] | None, setup: str | None, ended: dict[str, Any] | None,
    measure_start: datetime | None, measure_end: datetime | None,
) -> tuple[datetime, datetime] | None:
    if not credits or not setup or not ended or measure_start is None or measure_end is None:
        return None
    try:
        left, right = credits["before"], credits["after"]
        if not all(
            numbers(point, {"BurstCapacityPercentage", "CPUUtilization"})
            and all(0 <= point[key] <= 100 for key in ("BurstCapacityPercentage", "CPUUtilization"))
            for point in (left, right)
        ):
            return None
        before, after = datetime.fromisoformat(left["utc"]), datetime.fromisoformat(right["utc"])
        if datetime.fromisoformat(setup) <= before <= measure_start < measure_end <= after <= datetime.fromisoformat(
            ended["utc"]
        ) and before.utcoffset() is not None:
            return before, after
    except (KeyError, TypeError, ValueError):
        return None
    return None


def credits_hold(
    samples: list[dict[str, Any]], start: datetime, seconds: float,
    *, bracket: tuple[datetime, datetime] | None = None,
) -> bool:
    end = start + timedelta(seconds=seconds)
    minute = timedelta(seconds=60)
    points = sorted((datetime.fromisoformat(row["utc"]), row["BurstCapacityPercentage"]) for row in samples)
    if bracket is not None:
        points = [point for point in points if bracket[0] <= point[0] <= bracket[1]]
    before = [point for point in points if start - minute <= point[0] <= start]
    after = [point for point in points if end <= point[0] <= end + minute]
    if not before or not after:
        return False
    covering = [point for point in points if before[-1][0] <= point[0] <= after[0][0]]
    return all(t2 - t1 <= minute and v2 >= v1 for (t1, v1), (t2, v2) in pairwise(covering))


def group_key(trial: dict[str, Any]) -> tuple[Any, ...]:
    stage = trial["meta"]["stage"]
    return (
        trial["meta"]["environment"],
        stage["w1"],
        stage["w3"],
        stage["streams"],
        stage["batch"],
        stage["limiter"],
        stage["measured"],
        trial["meta"]["seed"],
    )


def repeats(trials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = defaultdict(list)
    for trial in trials:
        if not trial["meta"]["stage"]["id"].startswith("fix-"):
            groups[group_key(trial)].append(trial)
    result = []
    for key, group in sorted(groups.items()):
        selected = group
        values = [
            trial["browse"]["successful_latency_s"]["p95"]
            for trial in selected
            if trial["generator_valid"] and trial["browse"]["successful_latency_s"]["p95"] is not None
        ]
        by_route: dict[str, list[float]] = defaultdict(list)
        for trial in selected:
            if trial["generator_valid"]:
                for route, row in trial["routes"].items():
                    if (p95 := row["successful_latency_s"]["p95"]) is not None:
                        by_route[route].append(p95)
        result.append(
            {
                "group": key,
                "runs": [trial["meta"]["run"] for trial in selected],
                "outcomes": [trial["outcome"] for trial in selected],
                "n": len(values),
                "median_p95_s": median(values) if values else None,
                "range_p95_s": [min(values), max(values)] if values else None,
                "route_p95_s": {
                    route: {"n": len(values), "median": median(values), "range": [min(values), max(values)]}
                    for route, values in by_route.items()
                },
            }
        )
    return result


def trial_index(trials: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_run = {trial["meta"]["run"]: trial for trial in trials}
    if len(by_run) != len(trials):
        raise ValueError("duplicate run label")
    return by_run


def correctness_failed(trial: dict[str, Any]) -> bool:
    return bool(trial.get("correctness_failed") or (trial["checker"] and not trial["checker"]["ok"]))


def verified(trial: dict[str, Any]) -> bool:
    return bool(
        trial["outcome"] in {"passed", "failed"} and trial["generator_valid"] and not trial["problems"]
        and trial["checker"] and trial["checker"]["ok"] and trial["server"] and trial["server"]["coverage_ok"]
        and not trial["server"].get("abort") and trial["credits"] and not correctness_failed(trial)
    )


def capacity_configuration(trial: dict[str, Any]) -> tuple[Any, ...]:
    meta = trial["meta"]
    return (
        meta.get("target_sha256"), meta.get("dataset_sha256"), meta["seed"],
        tuple(sorted((key, value) for key, value in meta["stage"].items() if key not in {"id", "w1"})),
    )


def capacity(trials: list[dict[str, Any]], plan: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    by_run = trial_index(trials)
    declared = plan is not None
    if plan is None:
        plan = [
            {"run": label, "stage": trial["meta"]["stage"]["id"], "rate": trial["meta"]["stage"]["w1"]}
            for label, trial in sorted(by_run.items(), key=lambda item: item[1]["meta"].get("setup_utc", ""))
        ]
    labels = [attempt["run"] for attempt in plan]
    if len(labels) != len(set(labels)) or not by_run.keys() <= set(labels):
        raise ValueError("attempt plan must list every trial once")
    attempts: dict[str, dict[str, Any]] = {}
    candidates: dict[float, list[str]] = defaultdict(list)
    superseded = {}
    pending_abort = None
    previous_start = None
    continued_after_abort = []
    for item in plan:
        run, stage, rate = item["run"], item["stage"], item["rate"]
        trial = by_run.get(run)
        replacement = item.get("replaces")
        if trial and (stage, rate) != (trial["meta"]["stage"]["id"], trial["meta"]["stage"]["w1"]):
            raise ValueError("observed trial does not match its planned stage and rate")
        if trial and (setup := trial["meta"].get("setup_utc")):
            start = datetime.fromisoformat(setup)
            if previous_start is not None and start <= previous_start:
                raise ValueError("attempt plan contradicts recorded trial order")
            previous_start = start
        replaces_failure = False
        if replacement is not None:
            replaced = attempts.get(replacement)
            if (
                replaced is None or replacement in superseded or not isinstance(item.get("reason"), str)
                or not item["reason"].strip() or (stage, rate) != (replaced["stage"], replaced["rate"])
                or not (replaced["correctness_failed"] or replaced["outcome"] in {"invalid", "unverified"})
            ):
                raise ValueError("replacement requires an earlier failed attempt and explicit authorization")
            original = by_run[replacement]
            dimensions = ("environment", "stage", "profile_sha256", "target_sha256", "seed")
            if trial and verified(trial) and all(
                original["meta"].get(key) is not None and original["meta"][key] == trial["meta"].get(key)
                for key in dimensions
            ):
                superseded[replacement] = run
                replaces_failure = True
        if trial and pending_abort is not None:
            if replaces_failure and replacement == pending_abort:
                pending_abort = None
            else:
                continued_after_abort.append(run)
        incorrect = trial is not None and correctness_failed(trial)
        if incorrect and pending_abort is None:
            pending_abort = run
        attempts[run] = {
            "run": run, "stage": stage, "rate": rate, "outcome": trial["outcome"] if trial else "missing",
            "correctness_failed": incorrect, "replaces": replacement, "reason": item.get("reason"),
        }
        if stage.startswith(("w1-", "repeat-")):
            if trial is None:
                candidates[rate].append(run)
            else:
                env, _w1, w3, streams, batch, limiter, measured, _seed = group_key(trial)
                if env == "lightsail" and not (w3 or streams or batch or limiter) and measured == 180:
                    candidates[rate].append(run)
    for original, retry in superseded.items():
        attempts[original]["replaced_by"] = retry

    passed, failed, disqualified = [], [], []
    configurations = set()
    for rate, group in sorted(candidates.items()):
        current = [attempts[run] for run in group if run not in superseded]
        if any(attempt["correctness_failed"] for attempt in current):
            disqualified.append(rate)
        elif (
            declared and all(attempt["run"] in by_run and verified(by_run[attempt["run"]]) for attempt in current)
            and sum(attempt["stage"].startswith("repeat-") for attempt in current) >= 3
            and any(attempt["stage"].startswith("w1-") for attempt in current)
        ):
            matched = {capacity_configuration(by_run[attempt["run"]]) for attempt in current}
            if len(matched) != 1:
                continue
            configuration = matched.pop()
            if not all(configuration[:2]):
                continue
            outcomes = {attempt["outcome"] for attempt in current}
            if outcomes == {"passed"}:
                passed.append(rate)
                configurations.add(configuration)
            elif outcomes == {"failed"}:
                failed.append(rate)
                configurations.add(configuration)

    floor, ceiling = max(passed, default=None), min(failed, default=None)
    if continued_after_abort:
        kind, floor, ceiling = "correctness_abort_violated", None, None
    elif len(configurations) > 1:
        kind, floor, ceiling = "unconfirmed", None, None
    elif floor is not None and ceiling is not None:
        kind = "inconsistent" if floor >= ceiling else "bracket"
    elif floor in {32, 50}:
        kind = "lower_bound"
    else:
        kind = "unconfirmed"
    return {
        "kind": kind, "passing_rps": floor, "failing_rps": ceiling, "attempts": list(attempts.values()),
        "plan_supplied": declared, "correctness_disqualified_rps": disqualified,
        "correctness_abort_pending": pending_abort, "continued_after_correctness_abort": continued_after_abort,
    }


def paired(pairs: list[tuple[float, float]], seed: int = 10) -> dict[str, Any]:
    if len(pairs) != 5 or any(a <= 0 or b < 0 for a, b in pairs):
        raise ValueError("five complete positive baseline pairs are required")
    deltas = [(a - b) / a for a, b in pairs]
    rng = random.Random(seed)  # noqa: S311 - reproducible bootstrap
    bootstrap = [median(rng.choices(deltas, k=5)) for _ in range(10000)]
    low, high = percentile(bootstrap, 0.025), percentile(bootstrap, 0.975)
    middle = median(deltas)
    return {
        "paired_improvement": deltas,
        "median": middle,
        "bootstrap_ci95": [low, high],
        "claim": all(delta > 0 for delta in deltas) and low is not None and low > 0 and middle >= 0.20,
    }


def show(value: Any) -> str:
    return "—" if value is None else f"{value:.4g}" if isinstance(value, float) else str(value)


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# N10 trial results",
        "",
        "Latencies use nearest ranks. Decision HTTP includes every outcome, including transport errors.",
        "Offered denominators include overflow, missed and aborted slots. Three repeats give no confidence interval.",
        "",
    ]
    for trial in result["trials"]:
        run = trial["meta"]["run"]
        lines.extend(
            [
                f"## {run}",
                "",
                f"**{trial['outcome']}** · {trial['label']}",
                "",
                "| Route | Offered | Sent | Completed | Offered/s | Sent/s | Completed/s | n | p50 | p95 | p99 | Max |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for name, route in {"W1 combined": trial["browse"], **trial["routes"]}.items():
            measurements = route["successful_latency_s"]
            cells = [
                route[key] for key in ("offered", "sent", "completed", "offered_rate", "sent_rate", "completed_rate")
            ]
            cells.extend(measurements.get(key) for key in ("n", "p50", "p95", "p99", "max"))
            lines.append("| " + " | ".join([name, *map(show, cells)]) + " |")
        lines.extend(
            [
                "",
                f"Generator CPU peak {show(trial['generator_peak_cpu_pct'])}% and send-lag p99 "
                f"{show(trial['send_lag_p99_s'])} s. Peak loop wake lag "
                f"{show(trial.get('event_loop_lag_max_s'))} s. SSE reconnects {trial['reconnects']}.",
                f"Decision HTTP p95 {show(trial['decision_http_s']['p95'])} s. "
                f"Approval-to-terminal p95 {show(trial['approval_to_terminal_s']['p95'])} s.",
                "",
            ]
        )
        for status, decision in trial["decision_http_by_status_s"].items():
            lines.append(f"- Decision HTTP {status}. n={decision['n']}, p95 {show(decision['p95'])} s.")
        if trial["streams"]:
            for name, route in trial["sse_hold"].items():
                measurements = route["successful_latency_s"]
                lines.append(
                    f"- SSE {name} across the hold window. n={measurements['n']}, "
                    f"p50 {show(measurements['p50'])} s, p95 {show(measurements['p95'])} s, "
                    f"max {show(measurements['max'])} s."
                )
        if trial["credit_burn_percentage_points_hour"] is not None:
            lines.append(f"- Credit burn {show(trial['credit_burn_percentage_points_hour'])} percentage points/hour.")
        lines.extend(f"- {count} occurrences of `{error}`" for error, count in trial["errors"].items())
        checker = trial.get("checker") or {}
        workflow = trial["workflow"]
        if workflow["offered"] or workflow["warmup_generator_misses"] or workflow["sut_failures"]:
            lines.extend([
                "",
                f"W3 generator misses {workflow['generator_misses']} of {workflow['offered']} measured offers "
                f"(allowed {workflow['generator_miss_allowance']}, "
                f"warm-up misses {workflow['warmup_generator_misses']}). "
                f"Started workflow failures {workflow['sut_failures']} across the stage.",
            ])
        if violations := checker.get("violations"):
            lines.extend(["", "Checker violations", ""])
            for finding in violations:
                subject = " ".join(
                    f"{key.removesuffix('_id')} `{finding[key]}`"
                    for key in ("case_id", "stream_id", "workspace", "endpoint") if key in finding
                )
                suffix = f" ({subject})" if subject else ""
                lines.append(f"- `{finding['error']}`{suffix}.")
        if checker.get("not_dispatched"):
            lines.extend(["", "Undispatched workflows", ""])
            for slot in checker["not_dispatched"]:
                lines.append(f"- Slot {slot['index']} (case `{slot['case_id']}`) `{slot['reason']}`.")
        if checker.get("not_started") or checker.get("cancelled_by_abort"):
            lines.extend(["", "Workflow interruptions", ""])
        for key, status in (("not_started", "not started"), ("cancelled_by_abort", "cancelled_by_abort")):
            for case in checker.get(key, ()):
                offset = case.get("abort_offset")
                abort = f"aborted at offset {offset:.3f} s" if offset is not None else "stage aborted"
                lines.append(f"- Case `{case['case_id']}` {status} ({abort}).")
        lines.append("")
    lines.extend(
        ["## Repeats", "", "| Trials | Outcomes | Valid n | Median W1 p95 | Range |", "|---|---|---:|---:|---|"]
    )
    for item in result["repeats"]:
        lines.append(
            f"| {', '.join(item['runs'])} | {', '.join(item['outcomes'])} | {item['n']} | "
            f"{show(item['median_p95_s'])} | {show(item['range_p95_s'])} |"
        )
    cap = result["capacity"]
    lines.extend(
        [
            "",
            f"Capacity {cap['kind']}. Passing {show(cap['passing_rps'])} rps. Failing {show(cap['failing_rps'])} rps.",
            "",
        ]
    )
    for attempt in cap["attempts"]:
        note = f" Replaces {attempt['replaces']} ({attempt['reason']})." if attempt["replaces"] else ""
        marker = " Correctness failed." if attempt["correctness_failed"] else ""
        lines.append(f"- {attempt['run']} · {attempt['stage']} · {attempt['outcome']}.{marker}{note}")
    if comparison := result.get("paired"):
        arms = comparison["arms"]
        lines.append(
            f"Paired {comparison['metric']} (A {arms['A']}, B {arms['B']}) "
            f"median improvement {show(comparison['median'] * 100)}%. "
            f"Bootstrap 95% interval {show(comparison['bootstrap_ci95'])}. "
            f"Effect claim {show(comparison['claim'])}."
        )
    return "\n".join(lines)


def artifact(path: Path, suffix: str) -> dict[str, Any] | None:
    companion = path.with_suffix(suffix)
    return json.loads(companion.read_bytes()) if companion.is_file() else None


def paired_analysis(trials: list[dict[str, Any]], plan: dict[str, Any]) -> dict[str, Any]:
    arms = plan.get("arms")
    if not isinstance(arms, dict) or set(arms) != {"A", "B"} or not all(
            isinstance(arms[key], str) and arms[key].strip() for key in ("A", "B")) or arms["A"] == arms["B"]:
        raise ValueError("paired plan requires distinct, non-empty arm descriptions for A and B")
    by_run = trial_index(trials)
    pairs = plan["pairs"]
    labels = {label for pair in pairs for label in pair}
    if len(pairs) != 5 or any(len(pair) != 2 for pair in pairs) or len(labels) != 10 or not labels <= by_run.keys():
        raise ValueError("five pairs must identify ten distinct observed runs")
    expected = json.loads(
        (Path(__file__).resolve().parents[1] / "infra/load/fix-AB.json").read_bytes()
    )
    order = [stage["id"] for stage in expected["stages"]]
    metric = plan["metric"]
    lower, upper = plan["credit_band"]
    values = []
    regressions = []
    starts = []
    study = None
    for (a, b), (a_stage, b_stage) in zip(pairs, expected["pair_order"], strict=True):
        baseline, candidate = by_run[a], by_run[b]
        for trial, stage in ((baseline, "fix-" + a_stage), (candidate, "fix-" + b_stage)):
            if not verified(trial) or not trial["stage_start_utc"]:
                raise ValueError("paired candidate requires complete, valid, correct trials with start times")
            start = datetime.fromisoformat(trial["stage_start_utc"])
            if trial["meta"]["stage"]["id"] != stage or start.utcoffset() is None:
                raise ValueError("paired trials must match the predeclared A/B assignment and carry zoned start times")
            starts.append((start, stage))
            meta = trial["meta"]
            configuration = (
                meta["environment"], meta["seed"], meta["target_sha256"], meta["dataset_sha256"],
                {key: value for key, value in meta["stage"].items() if key != "id"},
            )
            if study is None:
                study = configuration
            if configuration != study or not meta["target_sha256"] or not meta["dataset_sha256"]:
                raise ValueError("all ten paired trials must share the host, workload, schedule, seed and dataset")
        if any(
            not all(lower <= trial["credits"][point]["BurstCapacityPercentage"] <= upper
                    for point in ("before", "after"))
            for trial in (baseline, candidate)
        ):
            raise ValueError("paired trials must stay in the predeclared credit band")
        if any(candidate[name]["succeeded"] < baseline[name]["succeeded"] for name in ("browse", "workflow")):
            regressions.append(b)
        if metric == "decision":
            a_value, b_value = (trial["decision_http_s"]["p95"] for trial in (baseline, candidate))
        elif metric == "approval_to_terminal":
            a_value, b_value = (trial["approval_to_terminal_s"]["p95"] for trial in (baseline, candidate))
        else:
            a_value, b_value = (
                trial["routes"][metric]["successful_latency_s"]["p95"] for trial in (baseline, candidate)
            )
        if a_value is None or b_value is None:
            raise ValueError("paired metric requires observations for both runs")
        values.append((a_value, b_value))
    if len({start for start, _ in starts}) != 10 or [stage for _, stage in sorted(starts)] != order:
        raise ValueError("paired trials violate the chronological ABBA order")
    comparison = paired(values)
    return {
        "metric": metric,
        "arms": arms,
        **comparison,
        "pairs": pairs,
        "regressions": regressions,
        "claim": comparison["claim"] and not regressions,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("raw", type=Path, nargs="+")
    cli.add_argument("--output-prefix", type=Path, required=True)
    cli.add_argument("--attempts", type=Path, help="Chronological JSON plan with attempts and authorized retries")
    cli.add_argument("--pairs", type=Path,
                     help="Predeclared JSON with five [baseline, candidate] run IDs, metric, credit band and arms")
    args = cli.parse_args()
    trials = []
    for path in args.raw:
        raw = path.read_bytes()
        with TextIOWrapper(BytesIO(raw), encoding="utf-8-sig") as source:
            rows = [json.loads(line) for line in source if line.strip()]
        check = artifact(path, ".check.json")
        bound = check is not None and check.get("raw_sha256") == hashlib.sha256(raw).hexdigest()
        sampler = path.with_suffix(".sampler.jsonl")
        trials.append(
            {
                **summarize(
                    rows, check if bound else None,
                    read_rows(sampler) if sampler.is_file() else None,
                    artifact(path, ".credits.json"),
                ),
                "checker_bound": bound,
            }
        )
    plan = json.loads(args.attempts.read_bytes()) if args.attempts else None
    aggregate = capacity(trials, plan)
    result: dict[str, Any] = {"trials": trials, "repeats": repeats(trials), "capacity": aggregate}
    if args.pairs:
        result["paired"] = paired_analysis(trials, json.loads(args.pairs.read_bytes()))
    for suffix, content in ((".json", json.dumps(result, indent=2) + "\n"), (".md", markdown(result))):
        with args.output_prefix.with_suffix(suffix).open("x", encoding="utf-8", newline="\n") as output:
            output.write(content)
    return int(bool(aggregate["correctness_abort_pending"] or aggregate["continued_after_correctness_abort"]))


if __name__ == "__main__":
    raise SystemExit(main())
