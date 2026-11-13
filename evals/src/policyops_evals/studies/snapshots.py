"""Normalize trusted SQL exports through a narrow public-value allowlist."""

from decimal import Decimal
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from policyops.budget.pricing import Usage
from policyops_evals.harness.timing import receipts
from policyops_evals.studies.report_models import FrozenStudy, Snapshot


FAILURES = {"trial_failed": "application", "scoring_unavailable": "judge_unavailable",
    "trial_deadline": "deadline", "study_interrupted": "interruption", "abandoned_claim": "interruption",
    "unclaimed_closed": "interruption", "cleanup_unconfirmed": "infrastructure",
    "actor_limit_or_contract": "budget", "agent_limit": "budget", "trial_setup_or_artifact": "infrastructure"}
FAILURES.update(judge_unavailable="judge_unavailable", simulator_failed="simulator")


def money(value: Any) -> str:
    return format(Decimal(str(value)), "f")


def normalize(study: FrozenStudy, raw: dict[str, Any]) -> Snapshot:
    runs = {uuid5(study.study_id, v.config_sha256): v.name for v in study.variants}
    observed: dict[tuple[str, str, int], dict[str, Any]] = {}
    for row in raw["trials"]:
        variant = runs.get(row["evaluation_run_id"])
        key = (variant or "", row["task_id"], row["trial_index"])
        if variant is None or key in observed:
            raise ValueError("foreign/duplicate SQL row")
        observed[key] = row
    strata = {t.task_id: t.stratum for t in study.tasks}
    scopes = {row["id"]: row for row in raw["scopes"]}
    trials, timings = [], []
    for variant, task, index, seed in study.schedule:
        row = observed.pop((variant, task, index), None)
        config = next(v for v in study.variants if v.name == variant)
        run_id = uuid5(study.study_id, config.config_sha256)
        slot_id = uuid5(run_id, f"{task}:{index}")
        if row is not None and (row["seed"] != seed or row["id"] != slot_id):
            raise ValueError("wrong seed/slot SQL row")
        # Early crash: absent schedule persistence still contributes a pending slot.
        scenario = row["scenario_scope"] if row else uuid5(slot_id, "unpersisted-scenario")
        scope = scopes.get(scenario)
        components = (row or {}).get("components") or {}
        if not isinstance(components, dict):
            components = {}
        status = "pending"
        failure = None
        if row:
            outcome = row.get("outcome")
            status = outcome or {"scheduled": "pending", "running": "running",
                                 "finalized": "unavailable_result"}[row["state"]]
            if status == "budget_exceeded":
                status = "error"
            failure = FAILURES.get(str(row.get("error_class")), "application") if row.get("error_class") else None
        environment = components.get("environment") or {}
        db_success = (environment.get("db_check") or {}).get("db_match")
        db_success = db_success if type(db_success) is bool else None
        composite = components.get("composite")
        if status in {"success", "failure"}:
            valid = isinstance(composite, dict)
            if isinstance(composite, dict):
                try:
                    reward = Decimal(str(composite["reward"]))
                    valid = (reward.is_finite() and 0 <= reward <= 1 and row is not None
                             and reward == Decimal(str(row["reward"])) and (reward == 1) == (status == "success"))
                except (KeyError, ValueError, ArithmeticError):
                    valid = False
            if strata[task] == "db_nl":
                assertions = composite.get("nl_assertions") if isinstance(composite, dict) else None
                valid = (valid and isinstance(assertions, list) and bool(assertions)
                         and all(type(a.get("met")) is bool for a in assertions if isinstance(a, dict))
                         and all(isinstance(a, dict) for a in assertions))
            if not valid or db_success is None:
                status, failure = "error", "judge_unavailable" if strata[task] == "db_nl" else "application"
        known = scope is not None and not scope["held_usd"] and not scope["calls_held"]
        trials.append({"variant": variant, "task_id": task, "trial_index": index, "seed": seed,
            "slot_id": str(slot_id), "scenario_id": str(scenario), "stratum": strata[task],
            "status": status, "failure_class": failure, "db_success": db_success,
            "composite_success": (status == "success") if status in {"success", "failure"} else None,
            "cost_known": known, "cost_usd": money(scope["spent_usd"]) if known and scope is not None else None,
            "held_usd": money(scope["held_usd"]) if scope else "0",
            "latency_ms": (row or {}).get("latency_ms"),
            "latency_censored": status in {"aborted", "running"} or failure in {"deadline", "interruption"},
            "artifact_sha256": (row or {}).get("artifact_sha256"),
            "result_sha256": (row or {}).get("result_sha256"),
            "started_at": (row or {}).get("started_at"), "finished_at": (row or {}).get("finished_at"),
            "returned_models": components.get("models_returned") or {}})
        receipt_rows = components.get("timings") or []
        invocation_id = (row or {}).get("invocation_scope")
        if invocation_id is not None:
            invocation_id = UUID(str(invocation_id))
            root = Path(os.environ["POLICYOPS_TEMP_DIR"]).resolve()
            invocation = root / "benchmarks" / str(invocation_id)
            if invocation.resolve() != invocation or invocation.is_symlink() or invocation.is_junction():
                raise ValueError("timing invocation alias")
            recovered = receipts(invocation, slot_id)
            if recovered:
                receipt_rows = recovered
        for timing in receipt_rows:
            if timing.get("slot_id") != str(slot_id):
                raise ValueError("timing binding mismatch")
            timings.append(timing)
    if observed:
        raise ValueError("foreign scheduled rows")
    attempts = []
    seen: set[UUID] = set()
    for row in raw["attempts"]:
        if row["id"] in seen:
            raise ValueError("duplicate attempt")
        seen.add(row["id"])
        usage = None
        try:
            body = row.get("usage") or {}
            usage = Usage(input_total=body["input_total"], output=body["output"],
                cache_read=body.get("cache_read", 0), cache_writes=body.get("cache_writes", {}),
                reasoning=body.get("reasoning"))
        except (KeyError, TypeError, ValueError):
            pass
        attempts.append({"id": str(row["id"]), "scenario_id": str(row["scenario_scope_id"]),
            **{key: row[key] for key in ("actor", "model", "state", "count_state")},
            "actual_usd": None if row["actual_usd"] is None else money(row["actual_usd"]),
            "reserved_usd": money(row["reserved_usd"]), "usage_valid": usage is not None,
            "input_total": None if usage is None else usage.input_total,
            "output": None if usage is None else usage.output, "reasoning": None if usage is None else usage.reasoning,
            "cache_read": None if usage is None else usage.cache_read,
            "cache_write": None if usage is None else sum(usage.cache_writes.values())})
    body = {"created_at": raw["created_at"].isoformat(), "db_version": raw["db_version"], "trials": trials,
        "attempts": attempts, "timings": timings, "scopes": [{"id": str(r["id"]), "kind": r["kind"],
            **{key: money(r[key]) if isinstance(r[key], Decimal) else r[key] for key in
               ("spent_usd", "held_usd", "calls_consumed", "calls_held", "counts_used")},
            "blocked": bool(r["overrun"] or r["contract_block"])} for r in raw["scopes"]]}
    # Explicit datetime encoding before strict JSON validation; no exception text escapes.
    return Snapshot.model_validate_json(json.dumps(body, default=lambda v: v.isoformat()))
