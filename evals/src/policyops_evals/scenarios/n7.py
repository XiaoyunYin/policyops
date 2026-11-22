"""Dev-only cache arms, request bindings and independent pilot/study receipts."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from typing import Any, Literal
from uuid import UUID, uuid5

from sqlalchemy import Engine

from policyops.budget.prices import SNAPSHOT_2026_11_05
from policyops.orchestration import investigation_prompt as prompt
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository, registration_digest
from policyops.persistence.records import EvaluationRun
from policyops.providers.canonical import CanonicalError, strict_loads
from policyops.providers.canonical import canonical_bytes as wire_bytes
from policyops.providers.serialize import prepare
from policyops.providers.tokenizer import Tokenizer
from policyops.retrieval.parse import CHUNK_CONFIG
from policyops_contracts.conversation import PolicyContext, UserMessage
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_evals.canonical import canonical_bytes
from policyops_evals.qa_studies import statistics
from policyops_evals.qa_studies.registration import source_provenance
from policyops_evals.scenarios import Refused, grading, lock, n3, runtime, study
from policyops_evals.scenarios.arms import Arm, Identity, _unavailable, identities
from policyops_evals.scenarios.cases import POSITIVES, SAFETY_STRATA, STRATA, Scenario
from policyops_evals.scenarios.generator import REPO
from policyops_evals.scenarios.recording import Exchange, Redactor, digest


Phase = Literal["pilot", "study"]
ARMS = (Arm.A0, Arm.A1)
MODES = {Arm.A0: "none", Arm.A1: "30m"}
CACHE_OPTIONS = {Arm.A0: {"mode": "explicit"}, Arm.A1: {"mode": "implicit", "ttl": "30m"}}
PROFILE = Arm.REVISION.profile
CAPS = {"pilot": Decimal("0.10"), "study": Decimal("1.50")}
ARM_CAPS = {arm: runtime.configuration(mode).caps.run_usd for arm, mode in MODES.items()}
ORDER_SEED = 7041
BOOTSTRAP_SEED = 7042
HORIZON_MS = runtime.ACTIVE_SECONDS * 1000
PREFIX_PERCENT = 90
DELTA_SLACK_TOKENS = 128
WARM_CONTROL_MAX_GAP_MS = 120_000
EXACT_MARGIN = Decimal("-0.10")
UNSAFE_MARGIN = Decimal("0.05")
MESSAGE = UUID(int=0)


@dataclass(frozen=True)
class Pair:
    case: Scenario
    repeat: int
    order: tuple[Arm, Arm]


def _arm_preference(case: Scenario, repeat: int) -> int:
    ranks = [int.from_bytes(n3._rank(ORDER_SEED, str(repeat), case.key, arm)) for arm in ARMS]
    return ranks[1] - ranks[0]


def schedule(dev: Sequence[Scenario], phase: Phase) -> tuple[Pair, ...]:
    if len(dev) != 128 or len({case.key for case in dev}) != 128:
        raise Refused("N7 requires the complete registered dev panel")
    ranked = sorted(dev, key=lambda case: n3._rank(ORDER_SEED, "dev", case.key))
    if phase == "pilot":
        # Exercise three write-positive strata with the same layout and no prewarming.
        selected = {next(case.key for case in ranked if case.gold.stratum == stratum) for stratum in POSITIVES[:3]}
        cases = [case for case in ranked if case.key in selected]
        a1_first_pilot = min(cases, key=lambda case: _arm_preference(case, 1)).key
        return tuple(Pair(case, 1, ARMS[::-1] if case.key == a1_first_pilot else ARMS)
                     for case in study.interleave(cases))
    result: list[Pair] = []
    for repeat in study.REPEATS:
        a1_first: set[str] = set()
        for stratum in STRATA:
            members = [case for case in ranked if case.gold.stratum == stratum]
            # Rank the preference for A1 first, then take half in each stratum.
            members.sort(key=lambda case: _arm_preference(case, repeat))
            a1_first.update(case.key for case in members[:len(members) // 2])
        result.extend(Pair(case, repeat, ARMS[::-1] if case.key in a1_first else ARMS)
                      for case in study.interleave(ranked))
    return tuple(result)


def blocks(pairs: Sequence[Pair], study_id: UUID, workspace: UUID) -> tuple[tuple[n3.Assignment, ...], ...]:
    return tuple(tuple(
        n3.Assignment(arm, pair.repeat, pair.case, runtime.Slot(
            workspace, uuid5(study_id, f"n7/dev/{arm}/{pair.repeat}/{pair.case.key}")))
        for pair in pairs[start:start + n3.BLOCK_PAIRS] for arm in pair.order
    ) for start in range(0, len(pairs), n3.BLOCK_PAIRS))


@dataclass(frozen=True)
class Requests:
    create: str
    count: str
    instructions: str
    tools: str
    input: str


def request_bindings(dev: Sequence[Scenario], policy: PolicyContext) -> dict[Arm, dict[str, Requests]]:
    result: dict[Arm, dict[str, Requests]] = {arm: {} for arm in ARMS}
    configs = {arm: runtime.configuration(mode) for arm, mode in MODES.items()}
    redactor = Redactor({MESSAGE: "message"})
    for case in sorted(dev, key=lambda item: item.key):
        opener = UserMessage(text=f"[seeded; {MESSAGE}] {case.visible.message}")
        request = prompt.request(policy, runtime.LIMITS, (opener,), profile=PROFILE)
        prepared = {arm: prepare(request, configs[arm], "agent", detailed_tool_errors=True) for arm in ARMS}
        bodies = {arm: item.params() for arm, item in prepared.items()}
        if (any(bodies[arm].pop("prompt_cache_options", None) != CACHE_OPTIONS[arm] for arm in ARMS)
                or bodies[Arm.A0] != bodies[Arm.A1] or "prompt_cache_key" in bodies[Arm.A0]
                or prepared[Arm.A0].count_body != prepared[Arm.A1].count_body):
            raise Refused("N7 requests must differ only in cache options")
        for arm, item in prepared.items():
            raw, count = redactor.body(item.body), redactor.body(item.count_body)
            if raw is None or count is None:
                raise Refused("N7 reference request could not be recorded")
            raw = wire_bytes(strict_loads(raw)).decode()
            count_sha = request_digest(count)
            if count_sha is None:
                raise Refused("N7 count request is malformed")
            exchange = Exchange(index=0, attempt=0, phase="create", request=raw, request_sha256=digest(raw))
            components = lock.exchange_digests(exchange)
            result[arm][case.key] = Requests(components.request_sha256, count_sha,
                                             components.instructions, components.tools, components.input)
    return result


def inputs(dev: tuple[Scenario, ...], engine: Engine, policy: PolicyContext, tokenizer: Tokenizer) -> Inputs:
    frozen = lock.read_lock()
    lock.verify_identities(frozen, engine, policy, tokenizer)
    identity = identities(engine, policy, tokenizer, arms=(Arm.REVISION,))[Arm.REVISION]
    if (frozen.profiles[PROFILE].status != "evaluated-admitted"
            or sha256(policy.text.encode()).hexdigest() != RETAIL_POLICY.sha256):
        raise Refused("N7 requires the admitted policy and profile")
    requests = request_bindings(dev, policy)
    arms = {}
    for arm, mode in MODES.items():
        config = runtime.configuration(mode)
        agent = config.reservation("agent")
        spec = runtime.scenario_spec(env="local", engine=engine, policy=policy, tokenizer=tokenizer,
                                     retail=_unavailable, providers=_unavailable, profile=PROFILE, cache_mode=mode)
        if (spec.graph_sha256, spec.prompt_sha256) != (identity.graph_sha256, identity.prompt_sha256):
            raise Refused("N7 must preserve the admitted graph and prompt")
        arms[arm] = {"cache_options": CACHE_OPTIONS[arm], "cache_mode": mode,
                     "config_sha256": spec.config_sha256, "actor_sha256": agent.config_sha256,
                     "first_requests_sha256": registration_digest({
                         key: asdict(value) for key, value in requests[arm].items()}),
                     "slot_worst_usd": str(ARM_CAPS[arm]), "call_worst_usd": str(agent.worst_usd)}
    if (arms[Arm.A0]["config_sha256"] != identity.config_sha256
            or arms[Arm.A0]["config_sha256"] == arms[Arm.A1]["config_sha256"]):
        raise Refused("N7 runtime config bindings are invalid")
    price = SNAPSHOT_2026_11_05.price("gpt-6-luna")
    binding = {
        "schema": "policyops.scenario-study/n7-v1",
        "source": source_provenance(REPO),
        "split": "dev",
        "panel": "previously used dev scenarios; descriptive",
        "profile": asdict(identity),
        "arms": arms,
        "manifests": lock.DEV_MANIFESTS,
        "fixture": {"revision": RETAIL_POLICY.source_commit, "sha256": FIXTURE_SHA256},
        "policy_sha256": RETAIL_POLICY.sha256,
        "grader": {"version": grading.VERSION, "sha256": n3.grader_digest()},
        "model": {"name": price.model, "effort": "low", "price_revision": SNAPSHOT_2026_11_05.revision,
                  "service_tier": "default", "retries": 0, "repairs": 0},
        "retrieval": {"scope": runtime.SCOPE.model_dump(mode="json"), "chunks": CHUNK_CONFIG,
                      "configuration": runtime.RETRIEVAL.model_dump(mode="json")},
        "caps": {"agent": runtime.LIMITS.model_dump(mode="json"), "nodes": runtime.MAX_STEPS,
                 "input_tokens": 10_000, "output_tokens": runtime.LIMITS.max_output_tokens,
                 "count_grants": runtime.MODEL_CALLS, "active_seconds": runtime.ACTIVE_SECONDS,
                 "wall_seconds": study.WALL_SECONDS, "failure_streak": study.MAX_FAILURE_STREAK,
                 "block_pairs": n3.BLOCK_PAIRS},
        "accounting": study.ACCOUNTING,
        "analysis": {"bootstrap": statistics.ALGORITHM, "seed": BOOTSTRAP_SEED, "draws": statistics.REPLICATES,
                     "cluster": "customer-world", "interval": "two-sided 95% R7", "denominator": "scheduled",
                     "proposal_horizon_ms": HORIZON_MS, "exact_lower_bound_gt": str(EXACT_MARGIN),
                     "unsafe_point_le": str(UNSAFE_MARGIN),
                     "eligible_strata": {"exact": list(POSITIVES), "unsafe": list(SAFETY_STRATA)}},
        "pilot_gate": {"whole_prefix_percent": PREFIX_PERCENT, "delta_slack_tokens": DELTA_SLACK_TOKENS,
                       "later_calls_required": 1, "warm_control_max_gap_ms": WARM_CONTROL_MAX_GAP_MS},
    }
    return Inputs(dev, identity, binding, requests)


@dataclass(frozen=True)
class Inputs:
    dev: tuple[Scenario, ...]
    identity: Identity
    binding: dict[str, Any]
    requests: dict[Arm, dict[str, Requests]]

    def for_phase(self, phase: Phase, pairs: Sequence[Pair], *, pilot_sha256: str | None = None) -> study.Inputs:
        if (phase == "study") != (pilot_sha256 is not None):
            raise Refused("N7 study must bind its separate pilot registration")
        order = [(pair.case.key, pair.repeat, pair.order) for pair in pairs]
        return study.Inputs(self.dev, self.binding | {
            "phase": phase, "pilot_registration_sha256": pilot_sha256,
            "schedule": {"seed": ORDER_SEED, "sha256": sha256(canonical_bytes(order)).hexdigest(),
                         "pairs": len(pairs), "slots": 2 * len(pairs)},
            "aggregate_cap_usd": str(CAPS[phase]),
        })


def request_digest(raw: str | None) -> str | None:
    """Canonicalize the redacted SDK body to compare it to the registered reference."""
    if raw is None:
        return None
    try:
        return sha256(wire_bytes(strict_loads(raw))).hexdigest()
    except CanonicalError:
        return None


def record_id(study_id: UUID, name: str) -> UUID:
    return uuid5(study_id, f"n7/{name}")


def _record(study_id: UUID, phase: Phase, name: str, digest: str, config: dict[str, Any]) -> EvaluationRun:
    return EvaluationRun(id=record_id(study_id, name), study_scope=study_id, dataset="tau2-retail",
                         dataset_revision=RETAIL_POLICY.source_commit, split_id=f"n7-{phase}",
                         config_sha256=digest, config_json=canonical_bytes(config).decode(),
                         created_at=datetime.now(UTC))


def register(repository: EvaluationRepository, phase: Phase, payload: dict[str, Any]) -> dict[str, Any]:
    digest = registration_digest(payload)
    study_id = EvalLedgerStore(repository.engine, env="local").ensure_study(
        f"policyops-n7-{phase}", digest, cap_usd=CAPS[phase],
        cap_calls=payload["schedule"]["slots"] * runtime.MODEL_CALLS)
    run = _record(study_id, phase, "registration", digest, {"study": "n7", "phase": phase})
    with repository.study_lock(study_id) as guard:
        receipt = study.validate_receipt(repository.register([run], payload, digest, guard), payload)
    return {"study_id": str(study_id), "receipt": receipt}


def verify_registration(repository: EvaluationRepository, study_id: UUID, phase: Phase,
                        receipt: dict[str, Any]) -> None:
    if (repository.run_configuration(record_id(study_id, "registration"))
            != {"study": "n7", "phase": phase, "registration": receipt}
            or repository.study_manifest(study_id) != receipt["sha256"]):
        raise Refused("N7 database registration receipt mismatch")


def close(repository: EvaluationRepository, study_id: UUID, phase: Phase, digest: str, reason: str) -> None:
    payload = {"registration_sha256": digest, "reason": reason}
    run = _record(study_id, phase, "closure", registration_digest(payload), payload)
    if repository.ensure_run(run) != run.id:
        raise Refused("N7 closure identity mismatch")
