"""Deterministic sanitized reports from sealed inputs, without execution imports."""

from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path
import re
from typing import Any
from uuid import uuid5

from policyops_evals.canonical import canonical_bytes
from policyops_evals.studies import bundles
from policyops_evals.studies import statistics as stats
from policyops_evals.studies.report_models import AttemptRow, FrozenStudy, Snapshot


VERSION = "policyops.study-reporter/2"
LIMITATIONS = [
    "pass^k estimates all k trials succeeding; it is not pass@k.",
    "Complete-case results are missingness-sensitive diagnostics and cannot select a release.",
    "Intervals resample tasks, carry paired trials together, and are pointwise, not simultaneous.",
    "Hosted seeds do not establish iid trials or deterministic provider outputs.",
    "Small or boundary-degenerate bootstrap intervals do not establish guaranteed power.",
    "NL assertion scores are model-judged and may share model-family bias.",
    "Logical-call timings include counting, inference and settlement; they are not provider-only latency.",
]


def timing_summary(values: list[int], *, missing: int, censored: int = 0) -> dict[str, Any]:
    ordered = [Fraction(v) for v in sorted(values)]
    return {"observed": len(values), "missing": missing, "censored": censored,
        "total_ms": sum(values), "mean_ms": stats.rounded(Fraction(sum(values), len(values))) if values else None,
        "p50_ms": stats.rounded(stats.r7(ordered, Fraction(1, 2))) if values else None,
        "p95_ms": stats.rounded(stats.r7(ordered, Fraction(19, 20))) if values else None}


def amounts(attempts: list[AttemptRow]) -> dict[str, Any]:
    with localcontext() as context:
        context.prec = 80  # bounded 13 integer +18 fractional digits, <=131072 rows
        held = sum((Decimal(a.reserved_usd) for a in attempts
                    if a.state in {"reserved", "dispatching", "unresolved"}), Decimal(0))
        spent = sum((Decimal(a.actual_usd or "0") for a in attempts if a.state == "settled"), Decimal(0))
        upper_bound = spent + held
    return {"settled_usd": format(spent, "f"), "held_usd": format(held, "f"),
        "upper_bound_usd": format(upper_bound, "f"),
        "inferences_consumed": sum(a.state in {"dispatching", "unresolved", "settled"} for a in attempts),
        "inferences_held": sum(a.state == "reserved" for a in attempts),
        "counts_used": sum(a.count_state != "none" for a in attempts),
        "states": dict(sorted(Counter(a.state for a in attempts).items())),
        "unknown_usage_attempts": sum(a.state in {"dispatching", "unresolved", "settled"}
                                      and not a.usage_valid for a in attempts),
        "tokens": {key: sum(getattr(a, key) or 0 for a in attempts if a.usage_valid)
                   for key in ("input_total", "output", "reasoning", "cache_read", "cache_write")},
        "unreported_reasoning_attempts": sum(a.usage_valid and a.reasoning is None for a in attempts)}


def validate(study: FrozenStudy, snapshot: Snapshot) -> list[str]:
    expected = {(v, t, i, seed) for v, t, i, seed in study.schedule}
    observed = {(r.variant, r.task_id, r.trial_index, r.seed) for r in snapshot.trials}
    if expected != observed or len(expected) != len(snapshot.trials):
        raise bundles.BundleRefused("scheduled_row_integrity")
    configs = {v.name: v for v in study.variants}
    if any(r.slot_id != uuid5(uuid5(study.study_id, configs[r.variant].config_sha256),
                             f"{r.task_id}:{r.trial_index}") for r in snapshot.trials):
        raise bundles.BundleRefused("scheduled_identity_integrity")
    strata = {t.task_id: t.stratum for t in study.tasks}
    if any(r.stratum != strata[r.task_id] for r in snapshot.trials):
        raise bundles.BundleRefused("frozen_stratum_integrity")
    if (len({r.slot_id for r in snapshot.trials}) != len(snapshot.trials)
            or len({r.scenario_id for r in snapshot.trials}) != len(snapshot.trials)
            or len({a.id for a in snapshot.attempts}) != len(snapshot.attempts)
            or len({s.id for s in snapshot.scopes}) != len(snapshot.scopes)
            or len({t.call_id for t in snapshot.timings}) != len(snapshot.timings)):
        raise bundles.BundleRefused("duplicate_identity")
    scenarios = {r.scenario_id: r for r in snapshot.trials}
    slots = {r.slot_id for r in snapshot.trials}
    models = {v.name: {a.actor: a.model for a in v.actors} for v in study.variants}
    if any(a.scenario_id not in scenarios or models[scenarios[a.scenario_id].variant][a.actor] != a.model
           for a in snapshot.attempts) or any(t.slot_id not in slots for t in snapshot.timings):
        raise bundles.BundleRefused("foreign_attempt_or_timing")
    discrepancies = []
    attempts_by_scenario: dict[Any, list[AttemptRow]] = defaultdict(list)
    for attempt in snapshot.attempts:
        attempts_by_scenario[attempt.scenario_id].append(attempt)
    study_scopes = [s for s in snapshot.scopes if s.kind == "study" and s.id == study.study_id]
    if len(study_scopes) != 1:
        discrepancies.append("missing_study_scope")
    if not {r.scenario_id for r in snapshot.trials} <= {s.id for s in snapshot.scopes if s.kind == "scenario"}:
        discrepancies.append("missing_scenario_scope")
    for scope in snapshot.scopes:
        attempts = list(snapshot.attempts) if scope.kind == "study" else attempts_by_scenario[scope.id]
        totals = amounts(attempts)
        if (Decimal(scope.spent_usd) != Decimal(totals["settled_usd"])
                or Decimal(scope.held_usd) != Decimal(totals["held_usd"])
                or scope.calls_consumed != totals["inferences_consumed"]
                or scope.calls_held != totals["inferences_held"] or scope.counts_used != totals["counts_used"]):
            discrepancies.append("ledger_scope_mismatch")
        if scope.blocked:
            discrepancies.append("ledger_blocked")
    if any(a.state == "settled" and (not a.usage_valid or a.actual_usd is None) for a in snapshot.attempts):
        discrepancies.append("settled_usage_unavailable")
    if any(a.state in {"reserved", "dispatching", "unresolved"} for a in snapshot.attempts):
        discrepancies.append("held_or_unresolved_liability")
    if any(r.cost_known and r.cost_usd is None for r in snapshot.trials):
        discrepancies.append("trial_cost_unavailable")
    scope_index = {s.id: s for s in snapshot.scopes}
    for row in snapshot.trials:
        trial_scope = scope_index.get(row.scenario_id)
        if trial_scope is not None and (Decimal(row.held_usd) != Decimal(trial_scope.held_usd) or
                (row.cost_known and (Decimal(row.cost_usd or "0") != Decimal(trial_scope.spent_usd)
                                     or Decimal(trial_scope.held_usd) != 0 or trial_scope.calls_held))):
            discrepancies.append("trial_scope_mismatch")
    return sorted(set(discrepancies))


def build(study: FrozenStudy, snapshot: Snapshot, bundle_hash: str, snapshot_hash: str) -> dict[str, Any]:
    discrepancies = validate(study, snapshot)
    rows = [r.model_copy(update={"status": "error", "failure_class": r.failure_class or "infrastructure",
                                 "composite_success": None, "db_success": None, "cost_known": False,
                                 "cost_usd": None})
            if r.status not in {"pending", "running"} and Decimal(r.held_usd) > 0 else r
            for r in snapshot.trials]
    finished = all(r.status not in {"pending", "running"} for r in rows)
    complete = all(r.status in {"success", "failure"} for r in rows)
    variants: list[dict[str, Any]] = []
    metrics: list[dict[str, Any]] = []
    differences: list[dict[str, Any]] = []
    by_key = {(r.variant, r.task_id, r.trial_index): r for r in rows}

    def outcomes(name: str, tasks: list[str], component: str = "composite_success") -> list[list[bool | None]]:
        return [[getattr(by_key[name, task, i], component) for i in range(len(study.seeds))] for task in tasks]

    lower_endpoints = []
    for scope in ("overall", "db_only", "db_nl"):
        tasks = [t.task_id for t in study.tasks if scope == "overall" or t.stratum == scope]
        for k in study.ks:
            for variant in study.variants:
                values = outcomes(variant.name, tasks)
                metrics.append({"variant": variant.name, "scope": scope, "k": k,
                    "strict": stats.analyze(tasks, values, k, seed=study.bootstrap_seed, kind=scope),
                    "complete_case": stats.analyze(tasks, values, k, seed=study.bootstrap_seed,
                                                  kind=scope, complete_case=True),
                    "db_component": stats.analyze(tasks, outcomes(variant.name, tasks, "db_success"), k,
                                                  seed=study.bootstrap_seed, kind=scope)})
            candidate, reference = study.decision.candidate, study.decision.reference
            strict = stats.paired(tasks, outcomes(candidate, tasks), outcomes(reference, tasks), k,
                                  seed=study.bootstrap_seed, kind=scope)
            differences.append({"candidate": candidate, "reference": reference, "scope": scope, "k": k,
                "strict": strict, "complete_case": stats.paired(tasks, outcomes(candidate, tasks),
                    outcomes(reference, tasks), k, seed=study.bootstrap_seed, kind=scope, complete_case=True)})
            if scope == "overall" and k in (study.decision.primary_k, *study.decision.guard_ks):
                pair = strict["estimate"]["ci_exact"][0]
                lower_endpoints.append(Fraction(*pair))
    for variant in study.variants:
        selected = [r for r in rows if r.variant == variant.name]
        scenarios = {r.scenario_id for r in selected}
        slot_ids = {r.slot_id for r in selected}
        actors = []
        for actor in variant.actors:
            attempts = [a for a in snapshot.attempts if a.scenario_id in scenarios and a.actor == actor.actor]
            timing = [t for t in snapshot.timings if t.slot_id in slot_ids
                      and t.actor == actor.actor]
            durations = [t.wall_ms for t in timing if t.wall_ms is not None]
            actors.append({"actor": actor.actor, "requested_model": actor.model, "effort": actor.effort,
                "returned_models": sorted({m for r in selected for m in r.returned_models.get(actor.actor, ())}),
                **amounts(attempts), "timing": timing_summary(durations,
                    missing=max(len(attempts), len(timing)) - len(durations))})
        total = amounts([a for a in snapshot.attempts if a.scenario_id in scenarios])
        success = sum(r.status == "success" for r in selected)
        cost_complete = not discrepancies and all(r.cost_known for r in selected)
        spent = Decimal(total["settled_usd"])
        variants.append({"name": variant.name, "configuration": variant.model_dump(mode="json"),
            "scheduled": len(selected), "scored": sum(r.status in {"success", "failure"} for r in selected),
            "successes": success, "errors": sum(r.status in {"error", "unavailable_result", "integrity_error"}
                                                for r in selected),
            "aborts": sum(r.status == "aborted" for r in selected),
            "pending": sum(r.status in {"pending", "running"} for r in selected),
            "failures": dict(sorted(Counter(r.failure_class for r in selected if r.failure_class).items())),
            "actors": actors, "accounting": total, "cost_complete": cost_complete,
            "usd_per_scheduled": format(spent / len(selected), "f") if cost_complete else None,
            "usd_per_success": format(spent / success, "f") if cost_complete and success else None,
            "trial_latency": timing_summary([r.latency_ms for r in selected
                if r.latency_ms is not None and not r.latency_censored],
                missing=sum(r.latency_ms is None for r in selected),
                censored=sum(r.latency_censored for r in selected))})
    candidate_row = next(v for v in variants if v["name"] == study.decision.candidate)
    reference_row = next(v for v in variants if v["name"] == study.decision.reference)
    cheaper = (candidate_row["cost_complete"] and reference_row["cost_complete"]
               and Decimal(candidate_row["accounting"]["settled_usd"])
               < Decimal(reference_row["accounting"]["settled_usd"]))
    excluded = study.eligibility.excluded
    evaluated = {t.task_id for t in study.tasks}
    with localcontext() as context:
        context.prec = 80
        trial_costs = {s.id: format(Decimal(s.spent_usd) + Decimal(s.held_usd), "f") for s in snapshot.scopes}
    return {"schema_version": "policyops.study-report/v1", "reporter_version": VERSION,
        "bundle_sha256": bundle_hash, "snapshot_sha256": snapshot_hash,
        "registration_sha256": study.registration_sha256, "analysis_spec_sha256": study.analysis_spec_sha256,
        "integrity_status": "valid", "execution_status": "finalized" if finished else "partial",
        "provenance": study.provenance.model_dump(mode="json"),
        "execution": {"seeds": study.seeds, "schedule_sha256": study.schedule_sha256,
            "schedule": study.schedule, "registered_at": None if study.registered_at is None else
            study.registered_at.isoformat(), "snapshot_at": snapshot.created_at.isoformat(),
            "db_version": snapshot.db_version, "protocol": study.protocol,
            "environment": study.environment.model_dump(mode="json"),
            "limits": study.limits.model_dump(mode="json"), "prices": study.prices.model_dump(mode="json")},
        "variants": variants, "metrics": metrics, "paired_differences": differences,
        "accounting": {"discrepancies": discrepancies, **amounts(list(snapshot.attempts))},
        "decision": {**study.decision.model_dump(mode="json"), "status": stats.decision(lower_endpoints,
            Decimal(study.decision.margin), registered=study.registration_sha256 is not None,
            complete=complete, integrity=True, accounting=not discrepancies, cheaper=cheaper)},
        "eligibility": {**study.eligibility.model_dump(mode="json"),
            "per_reason_counts": dict(sorted(Counter(reason for e in excluded for reason in e.reasons).items())),
            "union_exclusions": len(excluded), "overlapping_exclusions": sum(len(e.reasons) > 1 for e in excluded),
            "evaluated_excluded_from_tuning": sum(e.task_id in evaluated for e in excluded),
            "denominator_before": len(rows), "denominator_after": len(rows)},
        "trials": [r.model_dump(mode="json") | {"upper_bound_usd": trial_costs.get(r.scenario_id)} for r in rows],
        "limitations": LIMITATIONS}


def cell(value: Any) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;").replace("|", "&#124;").replace("\r", " ").replace("\n", " ").replace("`", "&#96;")


def estimate(value: dict[str, Any]) -> str:
    e = value["estimate"]
    return "unavailable" if e is None else f'{e["point"]:.8f} [{e["ci"][0]:.8f}, {e["ci"][1]:.8f}]'


def markdown(report: dict[str, Any]) -> bytes:
    lines = ["# Paired study report", "", f'Snapshot: {report["snapshot_sha256"]}', "",
        "| Variant | Scheduled | Scored | Errors | Aborts | Pending | Settled USD | Held USD | "
        "Upper-bound USD | Trial p50 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for v in report["variants"]:
        lines.append("| " + " | ".join(cell(x) for x in (v["name"], v["scheduled"], v["scored"], v["errors"],
            v["aborts"], v["pending"], v["accounting"]["settled_usd"], v["accounting"]["held_usd"],
            v["accounting"]["upper_bound_usd"], v["trial_latency"]["p50_ms"])) + " |")
    lines.extend(["", "| Variant | Stratum | k | Strict pass^k [95% CI] | Complete case [95% CI] | Eligible tasks |",
                  "|---|---|---:|---|---|---:|"])
    for m in report["metrics"]:
        lines.append("| " + " | ".join(cell(x) for x in (m["variant"], m["scope"], m["k"],
            estimate(m["strict"]), estimate(m["complete_case"]), m["complete_case"]["eligible_tasks"])) + " |")
    lines.extend(["", "| Candidate minus reference | Stratum | k | Difference [95% CI] |",
                  "|---|---|---:|---|"])
    for d in report["paired_differences"]:
        lines.append("| " + " | ".join(cell(x) for x in (d["candidate"] + " - " + d["reference"],
            d["scope"], d["k"], estimate(d["strict"]))) + " |")
    lines.extend(["", "Decision: " + cell(report["decision"]["status"]), "", "Limitations:", ""])
    lines.extend("- " + cell(text) for text in report["limitations"])
    return ("\n".join(lines) + "\n").encode("utf-8")


def render(path: Path, *, snapshot: str | None, out: Path) -> dict[str, Any]:
    if snapshot is not None and not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        raise bundles.BundleRefused("snapshot_digest")
    try:
        study, frozen, study_hash, snapshot_hash = bundles.load(path, snapshot)
        report = build(study, frozen, study_hash, snapshot_hash)
    except (bundles.BundleRefused, ValueError):
        # A valid frozen schedule still permits a diagnostic inventory when a
        # declared shard is missing/corrupt. No damaged score or cost is used.
        body, raw = bundles.read(path)
        study = FrozenStudy.model_validate_json(canonical_bytes(body))
        from policyops_evals.canonical import sha256_bytes

        invalid = []
        for variant, task, i, seed in study.schedule:
            config = next(v for v in study.variants if v.name == variant)
            slot = uuid5(uuid5(study.study_id, config.config_sha256), f"{task}:{i}")
            invalid.append({"variant": variant, "task_id": task, "trial_index": i, "seed": seed,
                "slot_id": str(slot), "status": "integrity_error", "failure_class": "artifact_integrity",
                "composite_success": None, "cost_known": False, "latency_ms": None})
        report = {"schema_version": "policyops.study-report/v1", "reporter_version": VERSION,
            "bundle_sha256": sha256_bytes(raw), "snapshot_sha256": snapshot,
            "registration_sha256": study.registration_sha256, "analysis_spec_sha256": study.analysis_spec_sha256,
            "integrity_status": "invalid", "execution_status": "unavailable",
            "provenance": study.provenance.model_dump(mode="json"), "execution": {}, "variants": [],
            "metrics": [], "paired_differences": [], "accounting": {"discrepancies": ["artifact_integrity"]},
            "decision": {"status": "descriptive"}, "eligibility": study.eligibility.model_dump(mode="json"),
            "trials": invalid,
            "limitations": ["Declared snapshot failed integrity validation; all scores unavailable."]}
    # The report embeds the normalized tables; only the sealed INPUT tables
    # are sharded at 512 rows/4 MB. The aggregate report has a 64 MB ceiling.
    bundles.write(out / "report.json", canonical_bytes(report), byte_limit=bundles.MAX_BYTES)
    bundles.write(out / "report.md", markdown(report))
    return report
