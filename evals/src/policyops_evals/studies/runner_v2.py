"""Paired serial v2 execution; imports are deliberately outside the report path."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any
from uuid import UUID, uuid4, uuid5

from policyops.budget.ledger import Ledger
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationClaimToken, EvaluationRepository, EvaluationTrial, Slot
from policyops.providers.calls import Providers
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.studies import bundles, registration, runner, snapshots
from policyops_evals.studies.config import ROOT, Study, StudyV2, Variant, preflight


def source_provenance() -> dict[str, Any]:
    source = runner.source_provenance()
    # Exclude the registration reference from dirty study-file bytes too. This
    # avoids a second self-reference through git's dirty digest. Every other
    # source byte/path (including the specification itself) remains bound.
    def git(*args: str) -> bytes:
        return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, timeout=15).stdout

    paths = set(git("diff", "HEAD", "--name-only", "-z").split(b"\0"))
    paths.update(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"))
    inventory: list[tuple[str, str | None]] = []
    for raw in sorted(paths - {b""}):
        path = raw.decode("utf-8")
        target = ROOT / path
        if not target.exists():
            inventory.append((path, None))
            continue
        data = target.read_bytes()
        if path.endswith(".json") and len(data) <= 60000:
            try:
                body = json.loads(data)
                if (isinstance(body, dict)
                        and body.get("schema_version") in {"policyops.study/v2", "policyops.study/v3"}):
                    body.pop("preregistration_sha256", None)
                    data = canonical_bytes(body)
            except ValueError:
                pass
        inventory.append((path, sha256_bytes(data)))
    source["dirty_sha256"] = sha256_bytes(canonical_bytes(inventory))
    return source


def bundle_directory(study_id: UUID) -> Path:
    directory = Path(os.environ.get("POLICYOPS_TEMP_DIR", "")) / "benchmarks/studies" / str(study_id)
    bundles.output_path(directory / "study.json")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def raw_inventory(directory: Path, invocation: Path) -> None:
    """Private evidence links only; scheduled trials never come from discovery."""
    entries: list[dict[str, Any]] = []
    total = 0
    for path in sorted(invocation.iterdir()):
        if len(entries) >= 16384 or not path.is_file() or path.is_symlink() or path.is_junction():
            raise bundles.BundleRefused("raw_inventory_bounds")
        size = path.stat().st_size
        total += size
        if size > bundles.MAX_FILE or total > bundles.MAX_BYTES:
            raise bundles.BundleRefused("raw_inventory_bounds")
        raw = path.read_bytes()
        entries.append({"path": f"{invocation.name}/{path.name}", "bytes": len(raw),
                        "sha256": sha256_bytes(raw)})
    bundles.write(directory / f"private-inventory-{invocation.name}.json",
        canonical_bytes({"schema_version": "policyops.private-inventory/v1", "base": "benchmarks", "files": entries}))


def run(study: StudyV2, repository: EvaluationRepository, store: EvalLedgerStore, *, allow_paid: bool,
        resume: bool, inputs: Mapping[str, runner.TrialInputs] | None,
        make_providers: Callable[[Study], Callable[[], Providers]],
        make_ledger: Callable[[Variant, EvaluationClaimToken], Ledger] | None, close_unclaimed: bool) -> dict[str, Any]:
    study.validate_data()
    registration.validate_implementation(study)
    if study.provider_mode == "live" and not allow_paid and not close_unclaimed:
        raise runner.StudyRefused("paid_opt_in_required_before_credentials")
    if close_unclaimed and not resume:
        raise runner.StudyRefused("closure_requires_resume")
    if not preflight(study)["within_caps"]:
        raise runner.StudyRefused("preflight_refused")
    source = source_provenance()
    caps = study.limits.caps()
    study_id = store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    invocation_id = uuid4()
    with repository.study_lock(study_id) as lease:
        receipt = registration.registered(study, repository, study_id, source)
        runs = {}
        for variant in study.variants:
            record = registration.run_record(study, variant, study_id, source, receipt)
            runs[variant.name] = repository.ensure_run(record)
            if repository.slots(record.id) and not resume:
                raise runner.StudyRefused("existing_study_requires_resume")
        directory = bundle_directory(study_id)
        frozen_path = directory / "study.json"
        if frozen_path.exists():
            from policyops_evals.studies.report_models import FrozenStudy

            frozen = FrozenStudy.model_validate_json(bundles.read(frozen_path)[1])
            if frozen.config_sha256 != study.digest():
                raise runner.StudyRefused("frozen_study_conflict")
        else:
            if close_unclaimed:
                raise runner.StudyRefused("frozen_study_required_for_closure")
            if inputs is None:
                inputs, _ = runner.load_inputs(study)
            strata = {task: "db_nl" if item.task.evaluation_criteria.nl_assertions else "db_only"
                      for task, item in inputs.items()}
            frozen = registration.freeze(study, study_id, source, strata, receipt)
            bundles.write(frozen_path, canonical_bytes(frozen.model_dump(mode="json")))
        # Freeze complete order/metadata before the first claim, and reconstruct
        # any missing scheduled claims left by a crash during setup.
        for variant in study.variants:
            digest = study.variant_digest(variant)
            for task in study.tasks:
                for i, seed in enumerate(study.seeds):
                    scenario = store.ensure_scenario(study_id, task, i, digest, caps)
                    repository.schedule(Slot(uuid5(runs[variant.name], f"{task}:{i}"), runs[variant.name],
                        study_id, digest, task, i, seed, scenario, "scheduled"))
        slots = {name: repository.slots(run_id) for name, run_id in runs.items()}
        for slot in (s for items in slots.values() for s in items):
            if slot.state == "running":
                repository.abort(slot, lease)
            elif slot.state == "scheduled" and close_unclaimed:
                repository.abort(slot, lease, reason="unclaimed_closed")
        slots = {name: repository.slots(run_id) for name, run_id in runs.items()}
        remaining = {name: tuple((s.task_id, s.trial_index, s.seed) for s in items if s.state == "scheduled")
                     for name, items in slots.items()}
        planning = preflight(study, snapshot=store.scope(study_id), remaining=remaining)

        def checkpoint() -> str:
            frozen_snapshot = snapshots.normalize(frozen, repository.export_study(study_id, lease))
            return bundles.seal(directory, frozen, frozen_snapshot)

        checkpoint()
        if not close_unclaimed and any(remaining.values()):
            if not planning["within_caps"]:
                raise runner.StudyRefused("ledger_preflight_refused")
            if inputs is None:
                inputs, _ = runner.load_inputs(study)
            current_strata = {task: "db_nl" if item.task.evaluation_criteria.nl_assertions else "db_only"
                             for task, item in inputs.items()}
            if any(current_strata[t.task_id] != t.stratum for t in frozen.tasks):
                raise runner.StudyRefused("frozen_stratum_conflict")
            invocation = runner.output_directory(invocation_id)
            runner.artifact(invocation, "manifest.json", {"study": study.model_dump(mode="json"),
                "source": source, "preflight": planning, "started_at": datetime.now(UTC).isoformat()})
            store.ensure_invocation(study_id, invocation_id, caps)
            providers = make_providers(study)
            lookup = {(name, s.task_id, s.trial_index): s for name, items in slots.items() for s in items}
            variants = {v.name: v for v in study.variants}
            primary: BaseException | None = None
            try:
                for name, task, i, _ in study.schedule():
                    slot = lookup[name, task, i]
                    if slot.state != "scheduled":
                        continue
                    try:
                        token = repository.claim(slot, invocation_id, lease)
                        if token is None:
                            raise runner.StudyRefused("claim_unavailable")
                        start = time.monotonic()
                        try:
                            ledger = make_ledger(variants[name], token) if make_ledger else Ledger(
                                EvalLedgerStore(repository.engine, env="evaluation", claim_token=token),
                                study.configuration(variants[name]))
                            details = runner.execute_trial(study, variants[name], slot, ledger, token, providers,
                                                           inputs[task], invocation)
                        except (KeyboardInterrupt, SystemExit):
                            details = {"outcome": "aborted", "reward": None,
                                       "error_class": "study_interrupted", "stop": True}
                        except Exception:
                            details = {"outcome": "error", "reward": None,
                                       "error_class": "trial_setup_or_artifact", "stop": True}
                        usage = repository.usage(slot.scenario_id)
                        details["usage"] = {k: str(v) if isinstance(v, Decimal) else v for k, v in usage.items()}
                        details["actor_attempts"] = repository.actor_attempts(slot.scenario_id)
                        digest = runner.artifact(invocation, f"{slot.id}-result.json", details)
                        known = not usage["held_usd"] and not usage["calls_held"]
                        terminal = EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id, task_id=task,
                            trial_index=i, seed=slot.seed, outcome=details["outcome"],
                            reward=None if details["reward"] is None else Decimal(details["reward"]),
                            components_json=runner.persisted_components(details), error_class=details["error_class"],
                            cost_status="known" if known else "unknown", cost_usd=usage["spent_usd"] if known else None,
                            latency_ms=int((time.monotonic() - start) * 1000), artifact_sha256=digest,
                            created_at=datetime.now(UTC))
                        repository.finalize(terminal, token, lease)
                        if details.get("stop") or usage["held_usd"] or usage["overrun"] or usage["contract_block"]:
                            break  # v2 preserves never-claimed slots for resume
                    except (KeyboardInterrupt, SystemExit):
                        repository.abort(slot, lease, reason="study_interrupted")
                        break
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    raw_inventory(directory, invocation)
                    snapshot_digest = checkpoint()
                except BaseException:
                    if primary is None:
                        raise
                    primary.add_note("private inventory/checkpoint export unconfirmed")
        else:
            snapshot_digest = checkpoint()
        for run_id in runs.values():
            repository.finish_run(run_id, lease)
        from policyops_evals.studies.reports import render

        report = render(frozen_path, snapshot=snapshot_digest, out=directory / ("report-" + snapshot_digest))
        return {"scheduled": len(frozen.schedule), "execution_complete": report["execution_status"] == "finalized",
            "snapshot_sha256": snapshot_digest, "output": str(directory), "decision": report["decision"]}


def command(study: StudyV2, *, run: bool, allow_paid: bool, resume: bool,
            register: bool, close_unclaimed: bool) -> dict[str, Any]:
    registration.validate_implementation(study)
    if run and study.provider_mode == "live" and not allow_paid and not close_unclaimed:
        raise runner.StudyRefused("paid_opt_in_required_before_credentials")
    source = source_provenance()
    if not run and not register:
        # Preflight without registration never writes a run/scope. DB reads are
        # optional; credentials/providers/upstream payloads remain untouched.
        repository = runner.environment_repository()  # type: ignore[attr-defined]
        try:
            store = None if repository is None else EvalLedgerStore(repository.engine, env="evaluation")
            scope = None if store is None else store.study_by_key(study.study_key)
            remaining = None
            if scope is not None and repository is not None:
                if repository.study_manifest(scope.id) != study.digest():
                    raise runner.StudyRefused("immutable_study_conflict")
                remaining = {}
                for variant in study.variants:
                    run_id = uuid5(scope.id, study.variant_digest(variant))
                    config = repository.run_configuration(run_id)
                    if config is not None and config.get("source") != runner.source_binding(source):
                        raise runner.StudyRefused("immutable_source_conflict")
                    rows = repository.slots(run_id)
                    existing = {(s.task_id, s.trial_index): s for s in rows}
                    remaining[variant.name] = tuple((t, i, seed) for t in study.tasks
                        for i, seed in enumerate(study.seeds)
                        if (t, i) not in existing or existing[t, i].state == "scheduled")
            payload = registration.registration_payload(study, source)
            return preflight(study, snapshot=scope, remaining=remaining) | {
                "order_sha256": sha256_bytes(canonical_bytes(study.schedule())), "source": source,
                "registration_payload_sha256": sha256_bytes(canonical_bytes(payload)),
                "prices": registration.prices(study)}
        finally:
            if repository is not None:
                repository.engine.dispose()
    repository = runner.environment_repository()  # type: ignore[attr-defined]
    if repository is None:
        raise runner.StudyRefused("evaluation_database_required")
    try:
        store = EvalLedgerStore(repository.engine, env="evaluation")
        if register:
            caps = study.limits.caps()
            study_id = store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd,
                                         cap_calls=caps.study_calls)
            with repository.study_lock(study_id) as lease:
                receipt = registration.register(study, repository, study_id, source, lease)
                bundles.write(bundle_directory(study_id) / ("registration-" + receipt["sha256"] + ".json"),
                              canonical_bytes(receipt))
            return {"registered": True, "receipt": receipt, "authorizes_paid_execution": False}
        return runner.run_study(study, repository, store, allow_paid=allow_paid,
                                resume=resume, close_unclaimed=close_unclaimed)
    finally:
        repository.engine.dispose()
