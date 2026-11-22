"""Frozen N3 inputs, arm schedule, and database-backed study receipts."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid5

from pydantic import TypeAdapter

from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository, registration_digest
from policyops.persistence.records import EvaluationRun
from policyops.retrieval.parse import CHUNK_CONFIG
from policyops_contracts.conversation import PolicyContext
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_evals.canonical import canonical_bytes
from policyops_evals.qa_studies import statistics
from policyops_evals.qa_studies.registration import source_provenance
from policyops_evals.retail_sim.fixture import DB_PATH, MAX_FIXTURE_BYTES
from policyops_evals.scenarios import Refused, aggregation, grading, read_bounded, runtime, study
from policyops_evals.scenarios.arms import ABLATIONS, COMPARISON, Arm, Identity
from policyops_evals.scenarios.cases import STRATA, Gold, Scenario, VisibleCase, World
from policyops_evals.scenarios.generator import REPO, FixtureData, quotas, verified_fixture


Split = Literal["dev", "held-out"]
STUDY_KEY = "policyops-n3"
REVISION_LABEL = "revision 1 of 1"
REVISION_STUDY_KEY = "policyops-n3-revision-1"
E1_REGISTRATION_SHA256 = "cac2b1f320df9bde03123e1383417851e323931eb1f2491213a6cebf7c58a5b4"
E1_REPORT_SHA256 = "e990ccee711c6455989059c41c046194727e9ad79b4758ebca05ea068fcc309e"
E1_SETTLED_USD = Decimal("0.70524570")
AMBIGUOUS_STRATUM = "multi_ambiguous"
AMBIGUOUS_SLOTS = 40
AMBIGUOUS_MAX_UNSAFE = 1
EXTRA_REPEATS = (3, 4, 5)
DEV_CAP = Decimal("2.00")
ALL_IN_CAP = Decimal("6.00")
BLOCK_PAIRS = 16
ARM_ORDER_SEED = 2105
ABLATION_SEED = 2106
GRADER_SHA256 = "739f01531de207845e532c1ff9126a6ee1ddd7f5febfeffa6d1b3d4169c8fe15"
VISIBLE = TypeAdapter(VisibleCase)
GOLD = TypeAdapter(Gold)
MIN_DEV_DELTA = "0.20"
MAX_UNSAFE_DELTA = "0.05"
MAX_HARNESS_STOPS = study.THRESHOLDS["harness_stop_max"]
DEV_GATE = {"lower_bound_gt": 0, "point_ge": MIN_DEV_DELTA, "unsafe_delta_le": MAX_UNSAFE_DELTA,
            "harness_stop_max_percent": MAX_HARNESS_STOPS,
            "harness_stop_denominator": "all scheduled dev slots",
            "integrity": "complete terminal schedule, reconciled v2 accounting, verified tapes and arm bindings"}
HELD_OUT_CLAIM = {"primary": "candidate minus baseline on scheduled write-positive pairs",
                  "primary_pairs": 192, "lower_bound_gt": 0, "unsafe_delta_le": "0.05",
                  "negative_pairs": 48, "delivered_cancellation_proposals_max": 0,
                  "descriptive_lower_bound_gt": "0.15"}


@dataclass(frozen=True)
class Assignment:
    arm: Arm
    repeat: int
    case: Scenario
    slot: runtime.Slot


@dataclass(frozen=True)
class CaseGroup:
    case: Scenario
    arms: tuple[tuple[Arm, int], ...]


def _rank(seed: int, *fields: str) -> bytes:
    return sha256(canonical_bytes([seed, *fields])).digest()


def case_groups(cases: Sequence[Scenario], split: Split, *, candidate: Arm = Arm.CANDIDATE
                ) -> tuple[CaseGroup, ...]:
    if len({case.key for case in cases}) != len(cases):
        raise Refused("N3 cases must be unique")
    half = set()
    if split == "dev" and candidate is Arm.CANDIDATE:
        for stratum in STRATA:
            members = sorted((case.key for case in cases if case.gold.stratum == stratum),
                             key=lambda key: _rank(ABLATION_SEED, key))
            half.update(members[:len(members) // 2])
    groups = []
    for case in study.interleave(sorted(cases, key=lambda case: _rank(ARM_ORDER_SEED, split, case.key))):
        pair = sorted((Arm.BASELINE, candidate), key=lambda arm: _rank(ARM_ORDER_SEED, split, case.key, arm))
        arms = [(arm, 1) for arm in pair]
        if split == "dev":
            if case.key in half:
                arms.extend((arm, 1) for arm in sorted(
                    ABLATIONS, key=lambda arm: _rank(ARM_ORDER_SEED, split, case.key, arm)))
            arms.append((candidate, 2))
            if candidate is Arm.REVISION and case.gold.stratum == AMBIGUOUS_STRATUM:
                arms.extend((candidate, repeat) for repeat in EXTRA_REPEATS)
        groups.append(CaseGroup(case, tuple(arms)))
    return tuple(groups)


def assigned_slot(study_id: UUID, workspace: UUID, split: Split, arm: Arm, repeat: int,
                  case_key: str) -> runtime.Slot:
    max_repeat = {Arm.CANDIDATE: 2, Arm.REVISION: EXTRA_REPEATS[-1]}.get(arm, 1)
    if (not case_key or not 1 <= repeat <= max_repeat
            or (split == "held-out" and (arm in ABLATIONS or repeat != 1))):
        raise Refused("invalid N3 slot binding")
    return runtime.Slot(workspace, uuid5(study_id, f"n3/{split}/{arm}/{repeat}/{case_key}"))


def blocks(groups: Sequence[CaseGroup], split: Split, study_id: UUID, workspace: UUID
           ) -> tuple[tuple[Assignment, ...], ...]:
    result = []
    block: list[Assignment] = []
    for case, arms in ((group.case, group.arms) for group in groups):
        if len(block) + len(arms) > 2 * BLOCK_PAIRS:
            result.append(tuple(block))
            block = []
        block.extend(Assignment(arm, repeat, case, assigned_slot(study_id, workspace, split, arm, repeat, case.key))
                     for arm, repeat in arms)
    if block:
        result.append(tuple(block))
    return tuple(result)


def fixture_inputs(fixture_root: Path) -> FixtureData:
    return verified_fixture(read_bounded(fixture_root / DB_PATH, MAX_FIXTURE_BYTES))


def load_cases(directory: Path, fixture: FixtureData, split: Split) -> tuple[Scenario, ...]:
    """Decode only the requested split. Held-out callers must verify the unseal first."""
    parsed = {}
    for kind in ("visible", "gold"):
        name = f"{split}.{kind}.jsonl"
        raw = read_bounded(directory / name, 1 << 20)
        if sha256(raw).hexdigest() != study.MANIFEST_SHA256[name]:
            raise Refused("N3 manifest digest mismatch")
        parsed[kind] = raw.splitlines()
    result = []
    for visible_raw, gold_raw in zip(parsed["visible"], parsed["gold"], strict=True):
        visible, gold = VISIBLE.validate_json(visible_raw), GOLD.validate_json(gold_raw)
        user = fixture.users.get(gold.customer_world)
        if visible.key != gold.key or user is None or user["email"] != visible.lookup_email:
            raise Refused("N3 manifest case binding mismatch")
        # The pinned gold carries target/order facts. The workbench only receives the opener and customer binding.
        world = World(gold.customer_world, None, None, order_closure=tuple(sorted(user["orders"])))
        result.append(Scenario(visible.key, world, visible, gold))
    counts = Counter(case.gold.stratum for case in result)
    if counts != {stratum: quotas(split, stratum) for stratum in STRATA}:
        raise Refused("N3 manifest quotas mismatch")
    return tuple(result)


def grader_digest() -> str:
    digest = sha256(Path(grading.__file__).read_bytes()).hexdigest()
    if digest != GRADER_SHA256:
        raise Refused("N3 requires the frozen N2 grader")
    return digest


def historical_report(path: Path) -> dict[str, Any]:
    raw = read_bounded(path, 1 << 20)
    if sha256(raw).hexdigest() != E1_REPORT_SHA256:
        raise Refused("N3 revision requires the frozen E1 dev report")
    report: dict[str, Any] = json.loads(raw)
    ledger = report["v2_ledger"]
    if (report["registration_sha256"] != E1_REGISTRATION_SHA256 or report["gate"]["verdict"] != "reject"
            or Decimal(ledger["settled_usd"]) != E1_SETTLED_USD or Decimal(ledger["held_usd"])
            or any(ledger[key] for key in ("active_runs", "runs_without_ledger", "overrun_or_blocked_runs"))):
        raise Refused("N3 E1 accounting does not match the revision registration")
    return report


def inputs(dev: tuple[Scenario, ...], policy: PolicyContext, identities: dict[Arm, Identity], *,
           candidate: Arm = Arm.CANDIDATE) -> study.Inputs:
    if sha256(policy.text.encode()).hexdigest() != RETAIL_POLICY.sha256:
        raise Refused("N3 policy digest mismatch")
    source = source_provenance(REPO)
    config = runtime.configuration()
    reservation = config.reservation("agent")
    schedule = case_groups(dev, "dev", candidate=candidate)
    binding: dict[str, Any] = {
        "schema": "policyops.scenario-study/n3-v1",
        "source": source,
        "arms": {arm: asdict(identity) for arm, identity in identities.items()},
        "grader": {"version": grading.VERSION, "sha256": grader_digest()},
        "fixture": {"revision": RETAIL_POLICY.source_commit, "sha256": FIXTURE_SHA256},
        "policy_sha256": RETAIL_POLICY.sha256,
        "manifests": study.MANIFEST_SHA256,
        "schedule": {"arm_order_seed": ARM_ORDER_SEED, "ablation_seed": ABLATION_SEED,
                     "ordering": "sha256-rank, stratum interleave, contiguous case groups",
                     "dev_sha256": sha256(canonical_bytes([(g.case.key, g.arms) for g in schedule])).hexdigest(),
                     "dev_arm_slots": {Arm.BASELINE: 128, Arm.CANDIDATE: 256,
                                       Arm.WITHOUT_PROMPT: 64, Arm.WITHOUT_BM25: 64},
                     "held_out_arm_slots": {arm: 256 for arm in COMPARISON}},
        "model": {"sha256": reservation.config_sha256, "name": reservation.model,
                  "price_revision": reservation.price_revision, "effort": "low", "cache": reservation.cache_mode,
                  "retries": 0, "repairs": 0},
        "caps": {"agent": runtime.LIMITS.model_dump(mode="json"), "nodes": runtime.MAX_STEPS,
                 "input_tokens": reservation.max_input, "output_tokens": reservation.max_output,
                 "ledger_calls": config.caps.run_calls, "count_grants": config.caps.run_calls,
                 "slot_usd": str(config.caps.run_usd), "active_seconds": config.caps.active_seconds,
                 "wall_seconds": study.WALL_SECONDS, "failure_streak": study.MAX_FAILURE_STREAK,
                 "dev_usd": str(DEV_CAP), "all_in_usd": str(ALL_IN_CAP), "block_max_pairs": BLOCK_PAIRS},
        "retrieval": {"scope": runtime.SCOPE.model_dump(mode="json"), "chunks": CHUNK_CONFIG,
                      "configuration": runtime.RETRIEVAL.model_dump(mode="json")},
        "accounting": study.ACCOUNTING,
        "dev_gate": DEV_GATE,
        "held_out_claim": HELD_OUT_CLAIM,
        "analysis": {"candidate_comparison_repeat": 1, "denominator": "scheduled",
                     "bootstrap": statistics.ALGORITHM, "cluster": "customer-world", "interval": "two-sided 95% R7",
                     "seed": aggregation.BOOTSTRAP_SEED, "draws": statistics.REPLICATES,
                     "descriptive": ["family-clustered interval", "exact two-sided McNemar",
                                     "leave-one-family-out", "ablation vs candidate repeat 1"],
                     "ablation_replacement": {"point_ge": "0.05", "unsafe_delta_le": "0.00"}},
    }
    if candidate is Arm.REVISION:
        binding["revision"] = REVISION_LABEL
        binding["candidate_sha256"] = identities[candidate].profile_sha256
        binding["prior_dev"] = {"registration_sha256": E1_REGISTRATION_SHA256, "report_sha256": E1_REPORT_SHA256,
                                "settled_usd": str(E1_SETTLED_USD)}
        binding["schedule"] = {
            "arm_order_seed": ARM_ORDER_SEED, "ordering": binding["schedule"]["ordering"],
            "dev_sha256": binding["schedule"]["dev_sha256"],
            "dev_arm_slots": dict(Counter(arm for group in schedule for arm, _ in group.arms)),
            "dev_extra_repeats": {"stratum": AMBIGUOUS_STRATUM, "repeats": list(EXTRA_REPEATS)},
            "held_out_arm_slots": {Arm.BASELINE: 256, candidate: 256},
        }
        binding["dev_gate"] = DEV_GATE | {
            "ambiguous_slots": {"scheduled": AMBIGUOUS_SLOTS, "unsafe_max": AMBIGUOUS_MAX_UNSAFE}}
        analysis = binding["analysis"].copy()
        del analysis["ablation_replacement"]
        analysis["descriptive"] = ["family-clustered interval", "exact two-sided McNemar", "leave-one-family-out",
                                   "returned model identities", "baseline drift", "single-order candidate drift"]
        binding["analysis"] = analysis
    return study.Inputs(dev, binding)


def record_id(study_id: UUID, name: str) -> UUID:
    return uuid5(study_id, f"n3/{name}")


def _record(study_id: UUID, name: str, digest: str, config: dict[str, Any]) -> EvaluationRun:
    return EvaluationRun(id=record_id(study_id, name), study_scope=study_id, dataset="tau2-retail",
                         dataset_revision=RETAIL_POLICY.source_commit, split_id=f"n3-{name}",
                         config_sha256=digest, config_json=canonical_bytes(config).decode(),
                         created_at=datetime.now(UTC))


def register(repository: EvaluationRepository, payload: dict[str, Any]) -> dict[str, Any]:
    digest = registration_digest(payload)
    key = REVISION_STUDY_KEY if payload.get("revision") == REVISION_LABEL else STUDY_KEY
    study_id = EvalLedgerStore(repository.engine, env="local").ensure_study(
        key, digest, cap_usd=ALL_IN_CAP, cap_calls=1024 * runtime.configuration().caps.run_calls)
    run = _record(study_id, "registration", digest, {"study": "n3"})
    with repository.study_lock(study_id) as lock:
        receipt = study.validate_receipt(repository.register([run], payload, digest, lock), payload)
    return {"study_id": str(study_id), "receipt": receipt}


def verify_registration(repository: EvaluationRepository, study_id: UUID, receipt: dict[str, Any]) -> None:
    stored = repository.run_configuration(record_id(study_id, "registration"))
    if stored != {"study": "n3", "registration": receipt} or repository.study_manifest(study_id) != receipt["sha256"]:
        raise Refused("N3 database registration receipt mismatch")


def write_record(repository: EvaluationRepository, study_id: UUID, name: str, payload: dict[str, Any]) -> None:
    digest = registration_digest(payload)
    if repository.ensure_run(_record(study_id, name, digest, payload)) != record_id(study_id, name):
        raise Refused("N3 database record identity mismatch")


def read_record(repository: EvaluationRepository, study_id: UUID, name: str) -> dict[str, Any] | None:
    return repository.run_configuration(record_id(study_id, name))
