"""Serialized durable dev runner over the pinned upstream build/run/score path."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import platform
import subprocess
import time
from typing import Any
from uuid import UUID, uuid4, uuid5

import httpx2
from pydantic import SecretStr

from policyops.budget.ledger import Ledger
from policyops.orchestration.ports import _AgentModelPort
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import (
    EvaluationClaimToken,
    EvaluationRepository,
    EvaluationRun,
    EvaluationTrial,
    Slot,
    environment_repository,
)
from policyops.providers.calls import CallReport, Providers
from policyops.providers.contract import require_clean_environment
from policyops_contracts.model import ModelRequest
from policyops_evals import upstream
from policyops_evals.build import SOURCE, default_manifest_dir, tree_for
from policyops_evals.canonical import canonical_bytes, load_manifest, sha256_bytes
from policyops_evals.corpus import write_contained
from policyops_evals.harness.timing import CallTimings
from policyops_evals.studies.config import ACTORS, ROOT, Study, StudyV2, Variant, load_study, preflight
from policyops_evals.studies.termination import closed_termination
from policyops_evals.upstream_runtime import installed_package_parity, prepare


class StudyRefused(ValueError):
    pass


@dataclass(frozen=True)
class TrialInputs:
    task: Any
    env_kwargs: dict[str, Any] | None = None


@dataclass(frozen=True)
class RecordedAgentPort(_AgentModelPort):
    """Observer on the exact T20/T11 port; the inherited identity checks remain.

    Bounded by AgentLimits.model_calls. Reports contain normalized results only.
    """

    reports: list[CallReport] = field(default_factory=list)
    timings: CallTimings | None = None

    async def complete(self, request: ModelRequest, *, key: UUID, operation: str, deadline: float) -> CallReport:
        from contextlib import nullcontext

        with self.timings.observe("agent", key) if self.timings else nullcontext():
            report = await super().complete(request, key=key, operation=operation, deadline=deadline)
        self.reports.append(report)
        return report


def source_provenance() -> dict[str, Any]:
    def git(*args: str) -> bytes:
        return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, timeout=15).stdout

    diff = git("diff", "HEAD", "--binary")
    extra = []
    for raw in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if raw:
            path = raw.decode("utf-8")
            extra.append((path, sha256_bytes((ROOT / path).read_bytes())))
    return {"source_head": git("rev-parse", "HEAD").decode().strip(),
        "dirty": bool(diff or extra), "dirty_sha256": sha256_bytes(diff + canonical_bytes(extra)),
        "lock_sha256": {name: sha256_bytes((ROOT / name).read_bytes()) for name in ("uv.lock", "evals/uv.lock")},
        "os": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
        "logical_cpus": os.cpu_count(), "python": platform.python_version()}


def source_binding(provenance: dict[str, Any]) -> dict[str, Any]:
    return {key: provenance.get(key) for key in ("source_head", "dirty_sha256", "lock_sha256")}


def output_directory(run_id: UUID) -> Path:
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    root = Path(raw)
    if not raw or not root.is_absolute():
        raise StudyRefused("absolute_temporary_root_required")
    resolved = root.resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise StudyRefused("temporary_root_inside_repository")
    # Check each existing ancestor: aliases into the checkout or outside the
    # selected root are rejected before mkdir/write, including benchmarks/.
    target = root / "benchmarks" / str(run_id)
    for path in (root, root / "benchmarks", target):
        actual = path.resolve()
        if path.is_symlink() or path.is_junction() or (actual != resolved and resolved not in actual.parents):
            raise StudyRefused("output_alias_refused")
    if target.exists():
        raise StudyRefused("output_already_exists")
    target.mkdir(parents=True)
    return target


def artifact(directory: Path, name: str, body: Any) -> str:
    data = canonical_bytes(body)
    if len(data) > 4_000_000:
        raise StudyRefused("artifact_bounds")
    # write_contained uses an exclusive temporary file and atomic replace and
    # refuses symlink/junction output ancestors.
    write_contained(directory, name, data)
    return sha256_bytes(data)


def persisted_components(details: dict[str, Any]) -> str:
    """Keep SQL components small; full scorer output/attempt usage lives in the
    hashed private result artifact, including when judge reasoning is lengthy.
    """
    body: dict[str, Any] = {key: details[key] for key in (
        "models_requested", "models_returned", "call_statuses", "usage",
        "failure_type", "trajectory_sha256", "partial_trajectory_sha256", "agent_snapshot_sha256", "finished_at",
        "manifest_artifact_sha256", "parity_artifact_sha256", "timings", "provider_failures")
        if key in details}
    environment = details.get("environment")
    if environment is not None:
        body["environment"] = {"reward": environment.get("reward"),
            "db_check": {"db_match": (environment.get("db_check") or {}).get("db_match")}}
    composite = details.get("composite")
    body["composite"] = None if composite is None else {"reward": composite.get("reward"),
        "nl_assertions": [{"met": row["met"], "assertion_sha256": sha256_bytes(row["nl_assertion"].encode())}
                           for row in composite.get("nl_assertions") or []]}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def load_inputs(study: Study) -> tuple[dict[str, TrialInputs], dict[str, Any]]:
    raw = os.environ.get("POLICYOPS_EVAL_ACQUIRED")
    if not raw:
        raise StudyRefused("verified_acquisition_required")
    acquired = Path(raw)
    tree = tree_for(acquired, default_manifest_dir())
    inventory = json.loads((acquired / "inventory.json").read_bytes())
    parity = installed_package_parity({i["path"]: i["sha256"] for i in inventory["files"]},
                                      (tree.root / "LICENSE").read_bytes())
    prepare(tree.root)
    from tau2.data_model.tasks import Task

    # Only selected allowlisted dev tasks are constructed; hidden Task objects
    # remain in trusted evaluator composition, never the agent configuration.
    selected = {row["id"]: TrialInputs(Task.model_validate(row))
                for row in tree.json(upstream.RETAIL_TASKS) if row["id"] in study.tasks}
    if set(selected) != set(study.tasks):
        raise StudyRefused("selected_task_missing")
    return selected, {"installed_parity": parity,
        "dataset_sha256": load_manifest(default_manifest_dir() / SOURCE)["manifest_sha256"]}


class ScriptedTransport(httpx2.AsyncBaseTransport):
    """Explicit offline mode: bounded text-only SDK responses, no network client."""

    def __init__(self, study: Study) -> None:
        self.outputs = list(study.scripted_outputs)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(await request.aread())
        if request.url.path.endswith("input_tokens"):
            response: dict[str, Any] = {"object": "response.input_tokens", "input_tokens": 900}
        else:
            if not self.outputs:
                raise StudyRefused("script_exhausted")
            text = self.outputs.pop(0)
            response = {"id": "resp_scripted_" + uuid4().hex, "object": "response", "model": body["model"],
                "status": "completed", "service_tier": "default",
                "usage": {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                          "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 940},
                "output": [{"type": "message", "role": "assistant",
                    "content": [{"type": "output_text", "text": text, "annotations": []}]}]}
        return httpx2.Response(200, json=response, request=request)


def provider_factory(study: Study) -> Callable[[], Providers]:
    if study.provider_mode == "scripted":
        if any(getattr(v.actors, a).model != "gpt-6-luna" for v in study.variants for a in ACTORS):
            raise StudyRefused("scripted_mode_supports_luna_only")
        transport = ScriptedTransport(study)
        return lambda: Providers({"openai": SecretStr("synthetic-offline-study-credential")}, lambda _: transport)
    # Called only after paid opt-in and a ledger-backed preflight. No .env.
    needed = {study.configuration(v).reservation(a).provider for v in study.variants for a in ACTORS}
    credentials: dict[str, SecretStr] = {}
    for provider in sorted(needed):
        if provider not in {"openai", "anthropic"}:
            raise StudyRefused("unsupported_provider")
        require_clean_environment(provider)  # type: ignore[arg-type]
        value = os.environ.get("OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY")
        if not value:
            raise StudyRefused("provider_credential_missing")
        credentials[provider] = SecretStr(value)
    return lambda: Providers(credentials, lambda _: httpx2.AsyncHTTPTransport(trust_env=False))


def execute_trial(study: Study, variant: Variant, slot: Slot, ledger: Ledger, token: EvaluationClaimToken,
                  providers: Callable[[], Providers], inputs: TrialInputs, directory: Path) -> dict[str, Any]:
    from tau2.data_model.simulation import TextRunConfig
    from tau2.runner.build import build_text_orchestrator

    from policyops_evals.harness.actors import ActorBindings, ActorCeilings, ActorRefused
    from policyops_evals.harness.adapter import FACTORY_NAME, TrialBudget, TrialSlot, register, trial
    from policyops_evals.harness.inprocess import InProcessAgentBridge, OwnedLoop
    from policyops_evals.studies.scoring import JudgeRefused, score

    deadline = time.monotonic() + study.limits.trial_seconds
    loop = OwnedLoop()
    bridge: InProcessAgentBridge | None = None
    orchestrator: Any = None
    simulation: Any = None
    result: dict[str, Any] = {"outcome": "error", "reward": None, "error_class": "trial_failed",
                              "simulation_termination": "unknown"}
    actors: ActorBindings | None = None
    timings = CallTimings(directory, slot.id)
    agent = RecordedAgentPort(ledger, token.binding, providers,
        ledger.configuration.reservation("agent").config_sha256, timings=timings)
    try:
        actors = ActorBindings(ledger, token.binding, providers, loop=loop, deadline=deadline,
            ceilings=ActorCeilings(variant.actors.simulator.logical_calls, variant.actors.judge.logical_calls),
            upstream_seed=slot.seed, timings=timings)
        bridge = InProcessAgentBridge(ledger.configuration, agent,
            loop=loop, limits=study.agent_limits(variant))
        register()
        with actors.install():
            config = TextRunConfig(domain="retail", agent=FACTORY_NAME, user="user_simulator",
                llm_agent=variant.actors.agent.model, llm_args_agent={"reasoning_effort": variant.actors.agent.effort},
                llm_user=variant.actors.simulator.model,
                llm_args_user={"reasoning_effort": variant.actors.simulator.effort}, seed=slot.seed,
                max_steps=2 * (variant.actors.agent.logical_calls + variant.actors.simulator.logical_calls) + 2,
                max_errors=study.limits.tool_error_limit, timeout=float(study.limits.trial_seconds),
                max_concurrency=1, num_trials=1)
            with trial(TrialSlot(slot.id, "retail", bridge, TrialBudget(deadline, time.monotonic, 0, 2))):
                orchestrator = build_text_orchestrator(config, inputs.task, seed=slot.seed, simulation_id=str(slot.id))
            simulation = orchestrator.run()
            if time.monotonic() >= deadline:
                raise StudyRefused("trial_deadline")
            evaluated = score(simulation, inputs.task, actors=actors, env_kwargs=inputs.env_kwargs)
            result["environment"] = evaluated.environment.model_dump(mode="json")
            result["composite"] = None if evaluated.composite is None else evaluated.composite.model_dump(mode="json")
            if evaluated.composite is None:
                result["error_class"] = "scoring_unavailable"
            else:
                reward = Decimal(str(evaluated.composite.reward))
                result.update(outcome="success" if reward == 1 else "failure", reward=str(reward), error_class=None)
            if time.monotonic() >= deadline:
                result.update(outcome="error", reward=None, error_class="trial_deadline", stop=True)
    except (KeyboardInterrupt, SystemExit):
        result.update(outcome="aborted", error_class="study_interrupted", stop=True)
    except Exception as error:
        # Only a class name and fixed code, never raw upstream/provider content.
        result["failure_type"] = type(error).__name__[:100]
        if isinstance(study, StudyV2):
            if isinstance(error, ActorRefused) and error.actor is not None:
                result["error_class"] = "simulator_failed" if error.actor == "simulator" else "judge_unavailable"
            elif isinstance(error, JudgeRefused):
                result["error_class"] = "judge_unavailable"
    finally:
        if orchestrator is not None:
            try:
                orchestrator.agent.stop()
            except Exception:
                result.update(outcome="error", reward=None, error_class="cleanup_unconfirmed", stop=True)
        try:
            if bridge is not None and bridge._connection is not None:
                bridge.close(bridge._connection.session_id, seconds=2)
        except BaseException:
            result.update(outcome="error", reward=None, error_class="cleanup_unconfirmed", stop=True)
        try:
            loop.close(seconds=2)
        except BaseException:
            result.update(outcome="error", reward=None, error_class="cleanup_unconfirmed", stop=True)
        if loop.cleanup_unconfirmed or (bridge is not None and bridge.cleanup_unconfirmed):
            result.update(outcome="error", reward=None, error_class="cleanup_unconfirmed", stop=True)
    if simulation is not None:
        result["simulation_termination"] = closed_termination(getattr(simulation, "termination_reason", None))
        result["trajectory_sha256"] = artifact(directory, f"{slot.id}-trajectory.json",
                                                simulation.model_dump(mode="json"))
    elif orchestrator is not None:
        result["simulation_termination"] = closed_termination(getattr(orchestrator, "termination_reason", None))
        # Upstream may throw before returning a SimulationRun. Preserve whatever
        # messages were accepted before failure, in the private artifact only.
        messages = getattr(orchestrator, "messages", [])
        result["partial_trajectory_sha256"] = artifact(directory, f"{slot.id}-partial.json",
            [m.model_dump(mode="json") for m in messages])
    result["models_requested"] = {a: getattr(variant.actors, a).model for a in ACTORS}
    # Agent normalized reports are persisted by its snapshot; actor reports never
    # expose SDK raw_data. Confirmed model IDs are also in the usage ledger intent.
    reports = [("agent", report) for report in agent.reports]
    if actors is not None:
        reports.extend(actors.reports)
    result["models_returned"] = {name: sorted({r.result.returned_model for a, r in reports
        if a == name and r.result is not None and r.result.returned_model is not None}) for name in ACTORS}
    result["call_statuses"] = {name: [r.status for a, r in reports if a == name] for name in ACTORS}
    result["provider_failures"] = provider_failures(reports)
    if any(r.status in {"budget", "contract_gap"} or r.cleanup_unconfirmed for _, r in reports):
        result.update(outcome="budget_exceeded" if any(r.status == "budget" for _, r in reports) else "error",
                      reward=None, error_class="actor_limit_or_contract", stop=True)
    if bridge is not None and bridge._agent is not None:
        snapshot = bridge._agent.snapshot()
        result["agent_snapshot_sha256"] = artifact(directory, f"{slot.id}-agent.json", {
            "schema_version": "policyops.study-agent/v1",
            "snapshot": snapshot.model_dump(mode="json"),
            "provider_failures": [f for f in result["provider_failures"] if f["actor"] == "agent"]})
        if snapshot.terminal in {"budget", "model_calls_exhausted", "steps_per_turn_exhausted"}:
            result.update(outcome="budget_exceeded", reward=None, error_class="agent_limit")
    result["finished_at"] = datetime.now(UTC).isoformat()
    result["timings"] = timings.rows
    return result


def provider_failures(reports: list[tuple[str, CallReport]]) -> list[dict[str, str]]:
    """Payload-free per-attempt diagnostics for every actor, counts included."""
    return [{"actor": actor, "attempt_id": str(attempt.attempt_id),
             "phase": "inference" if attempt.dispatch_granted else "count",
             "reason_code": attempt.failure_code}
            for actor, report in reports for attempt in report.attempts if attempt.failure_code is not None]


def run_study(study: Study, repository: EvaluationRepository, store: EvalLedgerStore, *, allow_paid: bool = False,
              resume: bool = False, inputs: Mapping[str, TrialInputs] | None = None,
              make_providers: Callable[[Study], Callable[[], Providers]] = provider_factory,
              make_ledger: Callable[[Variant, EvaluationClaimToken], Ledger] | None = None,
              close_unclaimed: bool = False) -> dict[str, Any]:
    if isinstance(study, StudyV2):
        from policyops_evals.studies.runner_v2 import run

        return run(study, repository, store, allow_paid=allow_paid, resume=resume, inputs=inputs,
                   make_providers=make_providers, make_ledger=make_ledger, close_unclaimed=close_unclaimed)
    if close_unclaimed:
        raise StudyRefused("close_unclaimed_requires_v2")
    if study.provider_mode != "scripted" and not allow_paid:
        raise StudyRefused("paid_opt_in_required_before_credentials")
    initial = preflight(study)
    if not initial["within_caps"]:
        raise StudyRefused("preflight_refused")
    caps = study.limits.caps()
    source = source_provenance()
    study_id = store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    invocation_id = uuid4()
    directory: Path | None = None
    with repository.study_lock(study_id) as lease:
        runs: dict[str, UUID] = {}
        slots: dict[str, list[Slot]] = {}
        for variant in study.variants:
            digest = study.variant_digest(variant)
            run_id = repository.ensure_run(EvaluationRun(id=uuid5(study_id, digest), study_scope=study_id,
                dataset="tau2-retail", dataset_revision=upstream.COMMIT, split_id="dev", config_sha256=digest,
                config_json=json.dumps({"study": study.model_dump(mode="json"), "variant": variant.name,
                                        "source": source_binding(source)}),
                created_at=datetime.now(UTC)))
            existing = repository.slots(run_id)
            if existing and not resume:
                raise StudyRefused("existing_study_requires_resume")
            runs[variant.name] = run_id
            for task in study.tasks:
                for index, seed in enumerate(study.seeds):
                    scenario = store.ensure_scenario(study_id, task, index, digest, caps)
                    repository.schedule(Slot(uuid5(run_id, f"{task}:{index}"), run_id, study_id, digest,
                                              task, index, seed, scenario, "scheduled"))
            for slot in repository.slots(run_id):
                if slot.state == "running":
                    repository.abort(slot, lease)
            slots[variant.name] = repository.slots(run_id)
        remaining = {name: tuple((s.task_id, s.trial_index, s.seed) for s in items if s.state == "scheduled")
                     for name, items in slots.items()}
        planning = preflight(study, snapshot=store.scope(study_id), remaining=remaining)
        if not planning["within_caps"] or planning["prior"] != "ledger_snapshot":
            raise StudyRefused("ledger_preflight_refused")
        directory = output_directory(invocation_id)
        provenance = {**source, "started_at": datetime.now(UTC).isoformat(),
            "study": study.model_dump(mode="json"), "preflight": planning, "invocation_id": str(invocation_id)}
        manifest_hash = artifact(directory, "manifest.json", provenance)
        parity_hash = None
        if inputs is None:
            inputs, parity = load_inputs(study)
            parity_hash = artifact(directory, "parity.json", parity)
        store.ensure_invocation(study_id, invocation_id, caps)
        # Credential reads and transport construction occur only beyond all
        # opt-in, immutable-study and persisted-admission gates.
        providers = make_providers(study)
        stop = False
        for variant in study.variants:
            for slot in slots[variant.name]:
                if slot.state == "finalized":
                    continue
                if stop:
                    repository.abort(slot, lease, reason="study_interrupted")
                    continue
                token = repository.claim(slot, invocation_id, lease)
                if token is None:
                    raise StudyRefused("claim_unavailable")
                start = time.monotonic()
                try:
                    ledger = make_ledger(variant, token) if make_ledger is not None else Ledger(
                        EvalLedgerStore(repository.engine, env="evaluation", claim_token=token),
                        study.configuration(variant))
                    details = execute_trial(study, variant, slot, ledger, token, providers,
                                            inputs[slot.task_id], directory)
                except (KeyboardInterrupt, SystemExit):
                    details = {"outcome": "aborted", "reward": None, "error_class": "study_interrupted", "stop": True}
                except Exception as error:
                    details = {"outcome": "error", "reward": None, "error_class": "trial_setup_or_artifact",
                               "failure_type": type(error).__name__, "stop": True}
                usage = repository.usage(slot.scenario_id)
                details["manifest_artifact_sha256"] = manifest_hash
                details["parity_artifact_sha256"] = parity_hash
                details["usage"] = {key: str(value) if isinstance(value, Decimal) else value
                                    for key, value in usage.items()}
                details["actor_attempts"] = repository.actor_attempts(slot.scenario_id)
                details["simulation_termination"] = closed_termination(details.get("simulation_termination"))
                stop = bool(details.get("stop") or usage["held_usd"] or usage["overrun"] or usage["contract_block"])
                artifact_hash = artifact(directory, f"{slot.id}-result.json", details)
                known = not usage["held_usd"] and not usage["calls_held"]
                terminal = EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id, task_id=slot.task_id,
                    trial_index=slot.trial_index, seed=slot.seed, outcome=details["outcome"],
                    reward=None if details["reward"] is None else Decimal(details["reward"]),
                    components_json=persisted_components(details), error_class=details["error_class"],
                    cost_status="known" if known else "unknown", cost_usd=usage["spent_usd"] if known else None,
                    latency_ms=int((time.monotonic() - start) * 1000), artifact_sha256=artifact_hash,
                    created_at=datetime.now(UTC))
                repository.finalize(terminal, token, lease)
            repository.finish_run(runs[variant.name], lease)
        rows = [row | {"variant": name} for name, run in runs.items() for row in repository.results(run)]
        total = len(study.tasks) * len(study.seeds) * len(study.variants)
        successes = sum(row["outcome"] == "success" for row in rows)
        complete = sum(row["outcome"] in {"success", "failure"} for row in rows)
        position = store.scope(study_id)
        if position is None:
            raise StudyRefused("study_snapshot_unavailable")
        summary = {"scheduled": total, "recorded": len(rows), "successes": successes,
            "execution_complete": len(rows) == total and complete == total,
            "strict_success_lower_bound": successes / total,
            "complete_case_success": successes / complete if complete else None,
            "trials": [{key: str(value) if isinstance(value, (UUID, Decimal)) else value
                        for key, value in row.items() if key in {"id", "variant", "task_id", "trial_index", "seed",
                            "outcome", "reward", "error_class", "artifact_sha256", "cost_status", "cost_usd",
                            "result_sha256"}}
                       for row in rows],
            "study_usage": {"spent_usd": str(position.spent_usd), "held_usd": str(position.held_usd),
                "inferences_consumed": position.calls_consumed, "inferences_held": position.calls_held,
                "counts_used": position.counts_used, "overrun": position.overrun,
                "contract_block": position.contract_block},
            "failures_by_class": {str(code): sum(row["error_class"] == code for row in rows)
                for code in sorted({r["error_class"] for r in rows if r["error_class"] is not None})},
            "finished_at": datetime.now(UTC).isoformat(), "output": str(directory)}
        artifact(directory, "summary.json", summary)
        return summary


def command(study_path: Path, *, run: bool, allow_paid: bool = False, resume: bool = False,
            register: bool = False, close_unclaimed: bool = False) -> dict[str, Any]:
    study = load_study(study_path)
    if isinstance(study, StudyV2):
        from policyops_evals.studies.runner_v2 import command as v2_command

        return v2_command(study, run=run, allow_paid=allow_paid, resume=resume,
                          register=register, close_unclaimed=close_unclaimed)
    if register or close_unclaimed:
        raise StudyRefused("registration_closure_require_v2")
    if run and study.provider_mode != "scripted" and not allow_paid:
        raise StudyRefused("paid_opt_in_required_before_credentials")
    repository = environment_repository()
    try:
        if not run:
            source = source_provenance()
            store = None if repository is None else EvalLedgerStore(repository.engine, env="evaluation")
            snapshot = None if store is None else store.study_by_key(study.study_key)
            remaining = None
            if snapshot is not None and repository is not None and store is not None:
                caps = study.limits.caps()
                store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd,
                                   cap_calls=caps.study_calls)  # immutable replay check
                remaining = {}
                for variant in study.variants:
                    run_id = uuid5(snapshot.id, study.variant_digest(variant))
                    config = repository.run_configuration(run_id)
                    if config is not None and config.get("source") != source_binding(source):
                        raise StudyRefused("immutable_source_conflict")
                    slots = repository.slots(run_id)
                    remaining[variant.name] = tuple((s.task_id, s.trial_index, s.seed) for s in slots
                        if s.state == "scheduled") if slots else tuple((t, i, seed) for t in study.tasks
                            for i, seed in enumerate(study.seeds))
            return preflight(study, snapshot=snapshot, remaining=remaining) | {"source": source}
        if repository is None:
            raise StudyRefused("evaluation_database_required")
        return run_study(study, repository, EvalLedgerStore(repository.engine, env="evaluation"),
                         allow_paid=allow_paid, resume=resume)
    finally:
        if repository is not None:
            repository.engine.dispose()
