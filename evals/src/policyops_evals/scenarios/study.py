"""Immutable N2 study inputs, schedule and evaluation registration receipt."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from uuid import UUID, uuid5

from policyops.orchestration import investigation_prompt
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository, registration_digest
from policyops.persistence.records import EvaluationRun
from policyops.retrieval.parse import CHUNK_CONFIG
from policyops.runtime.investigation import graph_digest
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_evals.canonical import canonical_bytes
from policyops_evals.qa_studies import statistics
from policyops_evals.qa_studies.registration import source_provenance
from policyops_evals.retail_sim.fixture import DB_PATH, MAX_FIXTURE_BYTES
from policyops_evals.scenarios import Refused, aggregation, generator, grading, read_bounded, runtime, templates_v1
from policyops_evals.scenarios.cases import STRATA, Scenario


STUDY_KEY = "policyops-n2"
PILOT_SLOTS = 16
REPEATS = (1, 2)
MAX_FAILURE_STREAK = 3
WALL_SECONDS = 14 * 3600
ACCOUNTING = "v2"
THRESHOLDS = {
    "primary_min": 15, "primary_max": 85, "harness_stop_max": 10, "named_failure_min": 80,
}
GATES = {
    **THRESHOLDS,
    "harness_stop_basis": "stricter-than-product limits, infrastructure and recorder errors",
    "n3_held_out_paired_dev_lower_bound_strictly_above": 0,
}
MANIFEST_SHA256 = {
    "dev.visible.jsonl": "b420d710fc44d256e080ea6640c1494d3ee8fe463a97be397a304287ad576311",
    "dev.gold.jsonl": "e52dce38e21c8221663cc25af248fb05e2261e5021bbc88d4e8e89ed36ebc29d",
    "held-out.visible.jsonl": "eb9ab0a8145215e61a078df3e9ea10cd40ac60b8a1b8cfe4973a04d19f8f8ed8",
    "held-out.gold.jsonl": "1be3c31600596758489a10644ca029d1e38e26c54f67194a2c7b778738c110ab",
}


def atomic_write(path: Path, data: bytes) -> None:
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def private_root(path: Path) -> Path:
    target = path.resolve()
    if any((part / ".git").exists() for part in (target, *target.parents)):
        raise Refused("scenario output must be outside all checkouts")
    return target


def private_child(root: Path, name: str) -> Path:
    path = root / name
    if path.resolve() != path:
        raise Refused("scenario output contains a linked path")
    return path


def require_dev(split: str) -> None:
    if split != "dev":
        raise Refused("held-out execution is sealed until N3")


def assigned_slot(study_id: UUID, workspace: UUID, split: str, repeat: int, case_key: str) -> runtime.Slot:
    require_dev(split)
    if repeat not in REPEATS or not case_key:
        raise Refused("invalid scenario slot binding")
    return runtime.Slot(workspace, uuid5(study_id, f"{split}/{repeat}/{case_key}"))


def interleave(cases: Sequence[Scenario]) -> tuple[Scenario, ...]:
    strata = [[case for case in cases if case.gold.stratum == stratum] for stratum in STRATA]
    if sum(map(len, strata)) != len(cases):
        raise Refused("a scheduled case has no registered stratum")
    return tuple(group[index] for index in range(max(map(len, strata))) for group in strata if index < len(group))


def checked_manifests(directory: Path, expected: Mapping[str, str]) -> dict[str, str]:
    found = {}
    for name, pinned in expected.items():
        digest = sha256(read_bounded(directory / name, 1 << 20)).hexdigest()
        if digest != pinned:
            raise Refused(f"manifest digest mismatch for {name}")
        found[name] = digest
    return found


@dataclass(frozen=True)
class Inputs:
    dev: tuple[Scenario, ...]
    binding: dict[str, Any]


def load_inputs(manifests: Path, fixture_root: Path, policy_file: Path) -> Inputs:
    pinned = checked_manifests(manifests, MANIFEST_SHA256)
    fixture = read_bounded(fixture_root / DB_PATH, MAX_FIXTURE_BYTES)
    policy = read_bounded(policy_file, 64 * 1024)
    if sha256(fixture).hexdigest() != FIXTURE_SHA256 or sha256(policy).hexdigest() != RETAIL_POLICY.sha256:
        raise Refused("fixture or policy digest mismatch")
    generation = generator.generate(fixture, policy)
    if {name: sha256(raw).hexdigest() for name, raw in generation.manifests().items()} != pinned:
        raise Refused("generated manifests differ from the frozen manifests")
    dev = interleave(generation.cases["dev"])
    config = runtime.configuration()
    reservation = config.reservation("agent")
    source = source_provenance(generator.REPO)
    return Inputs(dev, {
        "schema": "policyops.scenario-study/n2-v1",
        "source": {
            "revision": source["source_head"],
            "dirty_sha256": source["dirty_sha256"],
            "locks": {name: source["lock_sha256"][name] for name in ("uv.lock", "evals/uv.lock")},
        },
        "generator_sha256": sha256(Path(generator.__file__).read_bytes()).hexdigest(),
        "templates_sha256": sha256(Path(templates_v1.__file__).read_bytes()).hexdigest(),
        "fixture": {"revision": RETAIL_POLICY.source_commit, "sha256": FIXTURE_SHA256},
        "policy_sha256": RETAIL_POLICY.sha256,
        "manifests": pinned,
        "schedule": {"dev": [case.key for case in dev], "repeats": list(REPEATS), "pilot": PILOT_SLOTS,
                     "held_out": {"cases": len(generation.cases["held-out"]), "runnable": False}},
        "model": {"sha256": reservation.config_sha256, "name": reservation.model,
                  "price_revision": reservation.price_revision, "effort": "low", "cache": reservation.cache_mode,
                  "retries": 0, "repairs": 0},
        "prompt_sha256": investigation_prompt.digest(),
        "graph_sha256": graph_digest(),
        "caps": {"agent": runtime.LIMITS.model_dump(mode="json"), "nodes": runtime.MAX_STEPS,
                 "input_tokens": reservation.max_input, "output_tokens": reservation.max_output,
                 "ledger_calls": config.caps.run_calls, "count_grants": config.caps.run_calls,
                 "slot_usd": str(config.caps.run_usd), "active_seconds": config.caps.active_seconds,
                 "wall_seconds": WALL_SECONDS, "failure_streak": MAX_FAILURE_STREAK},
        "retrieval": {"scope": runtime.SCOPE.model_dump(mode="json"), "chunks": CHUNK_CONFIG,
                      "configuration": runtime.RETRIEVAL.model_dump(mode="json")},
        "grader": {"version": grading.VERSION, "sha256": sha256(Path(grading.__file__).read_bytes()).hexdigest()},
        "accounting": ACCOUNTING,
        "aggregation": {"sha256": sha256(Path(aggregation.__file__).read_bytes()).hexdigest(),
                        "bootstrap": statistics.ALGORITHM, "cluster": "customer-world", "interval": "95% R7",
                        "helpers": ["qa_studies.statistics.cluster_ratio", "qa_studies.statistics.paired_difference"],
                        "seed": aggregation.BOOTSTRAP_SEED, "draws": statistics.REPLICATES},
        "gates": GATES,
    })


def registration_payload(inputs: Inputs, workspace: UUID, generation: UUID, tokenizer: str,
                         out: Path) -> dict[str, Any]:
    return inputs.binding | {"workspace": str(workspace), "corpus_generation": str(generation),
                             "tokenizer_sha256": tokenizer, "output_sha256": sha256(os.fsencode(out)).hexdigest()}


def registration_id(study_id: UUID) -> UUID:
    return uuid5(study_id, "n2-registration")


def validate_receipt(receipt: object, binding: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "sha256", "created_at"}:
        raise Refused("registration receipt missing or invalid")
    if receipt["payload"] != binding or receipt["sha256"] != registration_digest(binding):
        raise Refused("registered scenario inputs changed")
    try:
        registered_at = datetime.fromisoformat(receipt["created_at"])
    except (TypeError, ValueError):
        raise Refused("invalid registration timestamp") from None
    if registered_at.utcoffset() != timedelta(0):
        raise Refused("registration requires a UTC database timestamp")
    return receipt


def register(repository: EvaluationRepository, payload: dict[str, Any], scheduled: int) -> dict[str, Any]:
    digest = registration_digest(payload)
    config = runtime.configuration()
    slots = scheduled * len(REPEATS)
    study_id = EvalLedgerStore(repository.engine, env="local").ensure_study(
        STUDY_KEY, digest, cap_usd=slots * config.caps.run_usd, cap_calls=slots * config.caps.run_calls)
    run = EvaluationRun(id=registration_id(study_id), study_scope=study_id, dataset="tau2-retail",
                        dataset_revision=RETAIL_POLICY.source_commit, split_id="n2",
                        config_sha256=digest, config_json='{"study":"n2"}', created_at=datetime.now(UTC))
    with repository.study_lock(study_id) as lock:
        receipt = validate_receipt(repository.register([run], payload, digest, lock), payload)
    return {"study_id": str(study_id), "receipt": receipt}


def write_registration(out: Path, document: dict[str, Any]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    path = private_child(out, "registration.json")
    if path.exists() and json.loads(read_bounded(path, 64 * 1024)) != document:
        raise Refused("private output already belongs to a different registration")
    atomic_write(path, canonical_bytes(document))


def read_registration(out: Path, inputs: Inputs) -> tuple[UUID, dict[str, Any]]:
    document = json.loads(read_bounded(private_child(out, "registration.json"), 64 * 1024))
    if not isinstance(document, dict) or set(document) != {"study_id", "receipt"}:
        raise Refused("private registration file is invalid")
    receipt = document["receipt"]
    payload = receipt.get("payload") if isinstance(receipt, dict) else None
    if not isinstance(payload, dict):
        raise Refused("private registration file is invalid")
    current = registration_payload(inputs, UUID(payload["workspace"]), UUID(payload["corpus_generation"]),
                                   payload["tokenizer_sha256"], out)
    return UUID(document["study_id"]), validate_receipt(receipt, current)
