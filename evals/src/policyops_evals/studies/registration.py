"""Pre-execution freeze helpers (never used by the offline report renderer)."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from policyops.orchestration.minimal import prompt_sha256
from policyops.persistence.evaluation import EvaluationRepository, EvaluationRun, StudyLock
from policyops_contracts.wire import WIRE_VERSION, OpenSessionBody
from policyops_evals import upstream
from policyops_evals.build import RETAIL_SPLIT, default_manifest_dir
from policyops_evals.calibration import CALIBRATION
from policyops_evals.canonical import canonical_bytes, load_manifest, sha256_bytes
from policyops_evals.studies.config import ACTORS, StudyV2, Variant
from policyops_evals.studies.report_models import FrozenStudy


def implementation_bindings() -> dict[str, str]:
    return {"prompt_sha256": prompt_sha256(knowledge_tool=False, opening=True),
        "tool_sha256": sha256_bytes((Path(__file__).parents[1] / "harness/tools.py").read_bytes()),
        "schema_sha256": sha256_bytes(canonical_bytes({"wire": WIRE_VERSION,
                                                       "open": OpenSessionBody.model_json_schema()}))}


def validate_implementation(study: StudyV2) -> None:
    expected = implementation_bindings()
    if any(any(getattr(variant, key) != value for key, value in expected.items()) for variant in study.variants):
        raise ValueError("frozen implementation digest mismatch")


def prices(study: StudyV2) -> dict[str, Any]:
    snapshot = study.configuration(study.variants[0]).registry.snapshot
    models = sorted({getattr(v.actors, actor).model for v in study.variants for actor in ACTORS})
    return {"revision": snapshot.revision, "models": [{"model": name, "provider": snapshot.models[name].provider,
        "tiers": [{"name": t.name, "max_prompt_tokens": t.max_prompt_tokens,
            "input": str(t.input), "output": str(t.output), "cache_read": str(t.cache_read),
            "cache_writes": {k: str(v) for k, v in t.cache_writes.items()}}
            for t in snapshot.models[name].tiers]} for name in models]}


def registration_payload(study: StudyV2, source: dict[str, Any]) -> dict[str, Any]:
    specification = study.model_dump(mode="json", exclude={"preregistration_sha256"})
    return {"schema_version": "policyops.study-registration/v1", "specification": specification,
        "source": {k: source[k] for k in ("source_head", "dirty_sha256", "lock_sha256")},
        "schedule_sha256": sha256_bytes(canonical_bytes(study.schedule())),
        "price_snapshot_sha256": sha256_bytes(canonical_bytes(prices(study)))}


def run_record(study: StudyV2, variant: Variant, study_id: UUID, source: dict[str, Any],
               receipt: dict[str, Any] | None = None) -> EvaluationRun:
    digest = study.variant_digest(variant)
    config = {"study": study.model_dump(mode="json"), "variant": variant.name,
        "source": {k: source[k] for k in ("source_head", "dirty_sha256", "lock_sha256")}}
    if receipt is not None:
        config["registration"] = receipt
    return EvaluationRun(id=uuid5(study_id, digest), study_scope=study_id, dataset="tau2-retail",
        dataset_revision=upstream.COMMIT, split_id=study.split_id, config_sha256=digest,
        config_json=canonical_bytes(config).decode(), created_at=datetime.now(UTC))


def register(study: StudyV2, repository: EvaluationRepository, study_id: UUID,
             source: dict[str, Any], lease: StudyLock) -> dict[str, Any]:
    study.validate_data()
    validate_implementation(study)
    payload = registration_payload(study, source)
    digest = sha256_bytes(canonical_bytes(payload))
    if study.preregistration_sha256 != digest:
        raise ValueError("declared preregistration digest mismatch")
    return repository.register([run_record(study, v, study_id, source) for v in study.variants],
                               payload, digest, lease)


def registered(study: StudyV2, repository: EvaluationRepository, study_id: UUID,
               source: dict[str, Any]) -> dict[str, Any] | None:
    payload = registration_payload(study, source)
    digest = sha256_bytes(canonical_bytes(payload))
    receipt = None
    for variant in study.variants:
        config = repository.run_configuration(uuid5(study_id, study.variant_digest(variant)))
        current = None if config is None else config.get("registration")
        if current is None:
            if study.purpose == "holdout" or study.preregistration_sha256 is not None:
                raise ValueError("committed registration required before execution")
            continue
        if (digest != study.preregistration_sha256 or current.get("payload") != payload
                or current.get("sha256") != digest or not current.get("created_at")
                or (receipt is not None and receipt != current)):
            raise ValueError("registration binding mismatch")
        receipt = current
    if receipt is not None and not repository.registration_precedes_claims(
            study_id, datetime.fromisoformat(receipt["created_at"])):
        raise ValueError("registration_after_claim")
    return receipt


def freeze(study: StudyV2, study_id: UUID, source: dict[str, Any], strata: dict[str, str],
           receipt: dict[str, Any] | None) -> FrozenStudy:
    calibration = load_manifest(default_manifest_dir() / CALIBRATION)
    split = load_manifest(default_manifest_dir() / RETAIL_SPLIT)["splits"][study.split_id]
    variants = []
    for variant in study.variants:
        config = study.configuration(variant)
        actors = []
        for name in ACTORS:
            actor = getattr(variant.actors, name)
            tier = config.price(name).tier_for(actor.max_input)
            actors.append({"actor": name, "model": actor.model, "effort": actor.effort,
                "max_input": actor.max_input, "max_output": actor.max_output, "logical_calls": actor.logical_calls,
                "planning_input": actor.planning_input, "planning_output": actor.planning_output,
                "input_usd_per_million": str(tier.input), "output_usd_per_million": str(tier.output)})
        variants.append({"name": variant.name, "config_sha256": study.variant_digest(variant), "actors": actors,
            **{k: getattr(variant, k) for k in implementation_bindings()}})
    body = {"study_id": str(study_id), "config_sha256": study.digest(), "purpose": study.purpose,
        "limits": study.limits.model_dump(mode="json"), "prices": prices(study),
        "specification": study.model_dump(mode="json"), "registration": receipt,
        "tasks": [{"task_id": t, "stratum": strata[t]} for t in study.tasks], "seeds": study.seeds,
        "variants": variants, "schedule": study.schedule(),
        "schedule_sha256": sha256_bytes(canonical_bytes(study.schedule())), "ks": study.statistics.ks,
        "bootstrap_seed": study.statistics.bootstrap_seed,
        "analysis_spec_sha256": sha256_bytes(canonical_bytes({"statistics": study.statistics.model_dump(mode="json"),
            "decision": study.decision.model_dump(mode="json")})),
        "registration_sha256": None if receipt is None else receipt["sha256"],
        "registered_at": None if receipt is None else receipt["created_at"],
        "provenance": {"dataset_sha256": study.dataset_sha256, "split_sha256": study.split_sha256,
            "task_list_sha256": study.task_list_sha256, "calibration_sha256": study.calibration_sha256,
            "source_head": source["source_head"], "dirty_sha256": source["dirty_sha256"],
            "app_lock_sha256": source["lock_sha256"]["uv.lock"],
            "evals_lock_sha256": source["lock_sha256"]["evals/uv.lock"], "upstream_commit": upstream.COMMIT,
            "price_revision": study.price_revision,
            "price_snapshot_sha256": sha256_bytes(canonical_bytes(prices(study)))},
        "eligibility": {"original_frame_count": split["count"], "original_frame_sha256": split["digest"],
            "allowlist_sha256": study.eligibility.allowlist_sha256,
            "tuning_task_ids": study.eligibility.tuning_task_ids, "excluded": calibration["excluded"],
            "example_prompt_sha256": study.eligibility.example_prompt_sha256},
        "environment": {"os": next((name for name in ("windows", "linux", "darwin")
            if str(source.get("os", "")).lower().startswith(name)), "unknown"),
            "architecture": source.get("machine", "unknown"), "logical_cpus": source.get("logical_cpus"),
            "ram_bytes": source.get("ram_bytes"), "python": source.get("python", "0.0.0")},
        "decision": {"candidate": study.decision.candidate, "reference": study.decision.reference,
            "margin": str(study.decision.margin), "guard_ks": [4 for _ in study.decision.guard_metrics]}}
    return FrozenStudy.model_validate_json(canonical_bytes(body))
