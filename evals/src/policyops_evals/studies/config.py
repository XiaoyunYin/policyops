"""Bounded immutable dev studies and all-actor offline admission planning."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, model_validator

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.budget.ledger import Scope
from policyops.budget.preflight import ChatBound, Manifest
from policyops.budget.preflight import preflight as budget_preflight
from policyops.orchestration.minimal import prompt_sha256
from policyops_contracts import WireModel
from policyops_contracts.conversation import AgentLimits
from policyops_contracts.wire import WIRE_VERSION
from policyops_evals import upstream
from policyops_evals.build import RETAIL_SPLIT, SOURCE, default_manifest_dir, load_committed
from policyops_evals.calibration import CALIBRATION, validate_calibration
from policyops_evals.canonical import canonical_bytes, id_list_digest, load_manifest, sha256_bytes
from policyops_evals.projection import Purpose, SplitGuard


Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
ActorName = Literal["agent", "simulator", "judge"]
ACTORS: tuple[ActorName, ...] = ("agent", "simulator", "judge")
ROOT = Path(__file__).resolve().parents[4]


class ActorConfig(WireModel):
    model: Name
    effort: Name
    max_input: Annotated[int, Field(ge=1, le=32000)]
    max_output: Annotated[int, Field(ge=64, le=2048)]
    logical_calls: Annotated[int, Field(ge=1, le=64)]
    planning_input: Annotated[int, Field(ge=0, le=1_024_000)]
    planning_output: Annotated[int, Field(ge=0, le=131072)]


class Actors(WireModel):
    agent: ActorConfig
    simulator: ActorConfig
    judge: ActorConfig


class Variant(WireModel):
    name: Name
    agent_kind: Literal["minimal"]
    actors: Actors


class Limits(WireModel):
    # Absent in legacy specifications: preserve their canonical bytes/digests.
    max_unresolved_attempts: Annotated[int | None, Field(ge=0, le=1000, exclude_if=lambda v: v is None)] = None
    scenario_usd: Decimal
    invocation_usd: Decimal
    study_usd: Decimal
    scenario_calls: Annotated[int, Field(ge=1, le=1000)]
    invocation_calls: Annotated[int, Field(ge=1, le=100000)]
    study_calls: Annotated[int, Field(ge=1, le=100000)]
    scenario_counts: Annotated[int, Field(ge=1, le=1000)]
    invocation_counts: Annotated[int, Field(ge=1, le=100000)]
    study_counts: Annotated[int, Field(ge=1, le=100000)]
    trial_seconds: Annotated[int, Field(ge=1, le=900)]
    # The ledger has no aggregate token counter. Only its conservative product
    # bound is accepted, so a smaller claimed token limit cannot be misleading.
    study_input_tokens: Annotated[int, Field(ge=1)]
    study_output_tokens: Annotated[int, Field(ge=1)]

    def caps(self) -> Caps:
        if (self.scenario_calls != self.scenario_counts or self.invocation_calls != self.invocation_counts
                or self.study_calls != self.study_counts):
            raise ValueError("count caps must equal inference caps in ledger v2")
        return replace(Caps(), scenario_usd=self.scenario_usd, invocation_usd=self.invocation_usd,
            study_usd=self.study_usd, scenario_calls=self.scenario_calls, invocation_calls=self.invocation_calls,
            study_calls=self.study_calls, active_seconds=self.trial_seconds)


class Study(WireModel):
    schema_version: Literal["policyops.study/v1"]
    study_key: Name
    purpose: Literal["dev"]
    dataset_sha256: Digest
    split_sha256: Digest
    calibration_sha256: Digest
    task_list_sha256: Digest
    tasks: Annotated[tuple[Name, ...], Field(min_length=1, max_length=64)]
    seeds: Annotated[tuple[Annotated[int, Field(ge=0, le=2147483647)], ...], Field(min_length=1, max_length=4)]
    variants: Annotated[tuple[Variant, ...], Field(min_length=1, max_length=4)]
    provider_mode: Literal["live", "scripted"]
    retries: Literal[0]
    repairs: Literal[0]
    cache_mode: Literal["none"]
    price_revision: Name
    limits: Limits
    scripted_outputs: Annotated[tuple[Annotated[str, Field(max_length=32000)], ...], Field(max_length=256)] = ()

    @model_validator(mode="after")
    def consistent(self) -> Study:
        if self.schema_version == "policyops.study/v1" and self.limits.max_unresolved_attempts is not None:
            raise ValueError("bounded continuation requires the paired study runner")
        if (len(set(self.tasks)) != len(self.tasks) or len(set(self.seeds)) != len(self.seeds)
                or len({v.name for v in self.variants}) != len(self.variants)):
            raise ValueError("duplicate study identities")
        if id_list_digest(self.tasks) != self.task_list_sha256:
            raise ValueError("task_list_sha256 mismatch")
        if self.provider_mode == "live" and self.scripted_outputs:
            raise ValueError("live studies cannot contain scripted responses")
        caps = self.limits.caps()
        for variant in self.variants:
            config = self.configuration(variant)
            if config.registry.snapshot.revision != self.price_revision:
                raise ValueError("unknown price revision")
            if (caps.study_calls * max(getattr(variant.actors, a).max_input for a in ACTORS)
                    > self.limits.study_input_tokens or
                    caps.study_calls * max(getattr(variant.actors, a).max_output for a in ACTORS)
                    > self.limits.study_output_tokens):
                raise ValueError("aggregate token caps smaller than enforced ledger product")
        return self

    def configuration(self, variant: Variant) -> Configuration:
        actors = dict(DEFAULT_ACTORS)
        for name in ACTORS:
            actor = getattr(variant.actors, name)
            actors[name] = ChatActor(name, actor.model, actor.effort, max_input=actor.max_input,
                                     max_output=actor.max_output)
        request_input = max(getattr(variant.actors, name).max_input for name in ACTORS)
        return Configuration(actors=actors, caps=replace(self.limits.caps(), request_max_input=request_input))

    def agent_limits(self, variant: Variant) -> AgentLimits:
        """Legacy schemas retain their recorded implicit limits; v3 requires every field."""
        return AgentLimits(model_calls=variant.actors.agent.logical_calls,
                           max_output_tokens=variant.actors.agent.max_output)

    def digest(self) -> str:
        return sha256_bytes(canonical_bytes(self.model_dump(mode="json")))

    def variant_digest(self, variant: Variant) -> str:
        return sha256_bytes(canonical_bytes({"study": self.digest(), "variant": variant.model_dump(mode="json"),
            "prompt_sha256": prompt_sha256(knowledge_tool=False, opening=True), "wire": WIRE_VERSION,
            "upstream_commit": upstream.COMMIT}))

    def validate_data(self) -> None:
        manifests = load_committed(default_manifest_dir())
        calibration = load_manifest(default_manifest_dir() / CALIBRATION)
        validate_calibration(calibration, manifests)
        if (self.dataset_sha256 != manifests[SOURCE]["manifest_sha256"]
                or self.split_sha256 != manifests[RETAIL_SPLIT]["manifest_sha256"]
                or self.calibration_sha256 != calibration["manifest_sha256"]):
            raise ValueError("dataset/split/calibration digest mismatch")
        guard = SplitGuard({"retail": manifests[RETAIL_SPLIT]})
        for task in self.tasks:
            guard.require("retail", task, Purpose.DEV_EVALUATION)
            if task not in calibration["allowlist"]["task_ids"]:
                raise ValueError("task outside reviewed calibration allowlist")


class Pairing(WireModel):
    schedule_version: Literal["paired-v1"]
    order_seed: Annotated[int, Field(ge=0, le=2147483647)]
    experimental_dimension: Literal["agent.model", "agent.effort"]


class Statistics(WireModel):
    ks: Annotated[tuple[Annotated[int, Field(ge=1, le=32)], ...], Field(min_length=1, max_length=8)]
    confidence: Literal["0.95"]
    bootstrap_replicates: Literal[10000]
    bootstrap_seed: Annotated[int, Field(ge=0, le=2147483647)]
    algorithm: Literal["task-bootstrap-sha256-v1"]
    quantile: Literal["linear-r7-v1"]


class Decision(WireModel):
    candidate: Name
    reference: Name
    metric: Literal["pass^1"]
    guard_metrics: tuple[Literal["pass^4"], ...]
    margin: Decimal
    direction: Literal["candidate-minus-reference"]


class Eligibility(WireModel):
    allowlist_sha256: Digest
    source_sha256: dict[Name, Digest]
    tuning_task_ids: Annotated[tuple[Name, ...], Field(max_length=64)]
    example_prompt_sha256: Digest


class VariantV2(Variant):
    prompt_sha256: Digest
    tool_sha256: Digest
    schema_sha256: Digest


class StudyV2(Study):
    """V1 remains a separate schema. Evaluation membership is not tuning eligibility."""

    schema_version: Literal["policyops.study/v2"]  # type: ignore[assignment]
    purpose: Literal["dev", "holdout"]  # type: ignore[assignment]
    domain: Literal["retail", "banking_knowledge"]
    split_id: Literal["dev", "holdout"]
    tasks: Annotated[tuple[Name, ...], Field(min_length=1, max_length=128)]
    seeds: Annotated[tuple[Annotated[int, Field(ge=0, le=2147483647)], ...], Field(min_length=1, max_length=32)]
    variants: Annotated[tuple[VariantV2, ...], Field(min_length=2, max_length=4)]
    pairing: Pairing
    statistics: Statistics
    decision: Decision
    eligibility: Eligibility
    preregistration_sha256: Digest | None

    @model_validator(mode="after")
    def paired(self) -> StudyV2:
        if self.domain != "retail":
            raise ValueError("banking evaluator/eligibility contract unavailable")
        if self.purpose != self.split_id:
            raise ValueError("purpose/split mismatch")
        if self.purpose == "holdout" and (len(self.seeds) != 4 or self.preregistration_sha256 is None):
            raise ValueError("holdout requires four seeds and preregistration digest")
        ks = self.statistics.ks
        if len(set(ks)) != len(ks) or any(k > len(self.seeds) for k in ks):
            raise ValueError("unsupported k")
        names = {v.name for v in self.variants}
        if (self.decision.candidate not in names or self.decision.reference not in names
                or self.decision.candidate == self.decision.reference
                or not self.decision.margin.is_finite() or not 0 < self.decision.margin < 1
                or 1 not in ks or (self.decision.guard_metrics and 4 not in ks)
                or len(set(self.decision.guard_metrics)) != len(self.decision.guard_metrics)):
            raise ValueError("invalid frozen decision")
        if len(self.tasks) * len(self.seeds) * len(self.variants) > 16384:
            raise ValueError("scheduled workload bound")
        # Overall plus the partitioned strata visit <=2*T task clusters. Each
        # arm has strict/complete-case/DB analyses and the pair has two analyses.
        work = 10000 * 2 * len(self.tasks) * len(ks) * (3 * len(self.variants) + 2)
        if work > 80_000_000:
            raise ValueError("bootstrap workload bound")
        first = self.variants[0].model_dump(mode="json")
        for variant in self.variants[1:]:
            other = variant.model_dump(mode="json")
            left, right = json.loads(json.dumps(first)), json.loads(json.dumps(other))
            for body in (left, right):
                body.pop("name")
                body["actors"]["agent"].pop(self.pairing.experimental_dimension.split(".")[1])
            if left != right:
                raise ValueError("undeclared paired variant difference")
        if len(set(self.eligibility.tuning_task_ids)) != len(self.eligibility.tuning_task_ids):
            raise ValueError("duplicate tuning identity")
        return self

    def validate_data(self) -> None:
        manifests = load_committed(default_manifest_dir())
        calibration = load_manifest(default_manifest_dir() / CALIBRATION)
        validate_calibration(calibration, manifests)
        if (self.dataset_sha256 != manifests[SOURCE]["manifest_sha256"]
                or self.split_sha256 != manifests[RETAIL_SPLIT]["manifest_sha256"]
                or self.calibration_sha256 != calibration["manifest_sha256"]
                or self.eligibility.allowlist_sha256 != calibration["allowlist"]["digest"]
                or self.eligibility.source_sha256 != calibration["sources"]
                or not set(self.eligibility.tuning_task_ids) <= set(calibration["allowlist"]["task_ids"])):
            raise ValueError("frozen eligibility/data mismatch")
        frame = manifests[RETAIL_SPLIT]["splits"][self.split_id]["task_ids"]
        if not set(self.tasks) <= set(frame):
            raise ValueError("task outside official frame")
        if self.purpose == "holdout" and list(self.tasks) != frame:
            raise ValueError("holdout must preserve all official IDs and order")

    def schedule(self) -> tuple[tuple[str, str, int, int], ...]:
        """Seeded rotation: each arm visits every position equally per full cycle."""
        offset = int(sha256_bytes(canonical_bytes(["paired-v1", self.pairing.order_seed]))[:16], 16)
        names = [v.name for v in self.variants]
        rows: list[tuple[str, str, int, int]] = []
        for t, task in enumerate(self.tasks):
            for i, seed in enumerate(self.seeds):
                rotation = (offset + t * len(self.seeds) + i) % len(names)
                rows.extend((name, task, i, seed) for name in names[rotation:] + names[:rotation])
        return tuple(rows)


class VariantV3(VariantV2):
    agent_protocol: Literal["single-tool-drop-text/v1"]
    agent_limits: AgentLimits

    @model_validator(mode="after")
    def explicit_limits(self) -> VariantV3:
        if self.agent_limits.model_fields_set != set(AgentLimits.model_fields):
            raise ValueError("v3 requires every agent limit explicitly")
        if (self.agent_limits.model_calls != self.actors.agent.logical_calls
                or self.agent_limits.max_output_tokens != self.actors.agent.max_output
                or self.agent_limits.knowledge_steps != 0
                or self.agent_limits.transcript_messages > 255):
            raise ValueError("v3 agent limits disagree with the retail opening-mode actor")
        return self


class StudyV3(StudyV2):
    schema_version: Literal["policyops.study/v3"]  # type: ignore[assignment]
    variants: Annotated[tuple[VariantV3, ...], Field(min_length=2, max_length=4)]
    notes: Annotated[str, StringConstraints(min_length=1, max_length=2000)]

    def agent_limits(self, variant: Variant) -> AgentLimits:
        if not isinstance(variant, VariantV3):
            raise ValueError("v3 variant required")
        return variant.agent_limits


def load_study(path: Path) -> Study:
    with path.open("rb") as handle:
        data = handle.read(60001)
    if len(data) > 60000:
        raise ValueError("study config exceeds 60000 bytes")
    # Bounded nesting before parsing, plus duplicate/non-finite rejection.
    depth, quoted, escaped = 0, False, False
    for c in data:
        if quoted:
            if escaped:
                escaped = False
            elif c == 92:
                escaped = True
            elif c == 34:
                quoted = False
        elif c == 34:
            quoted = True
        elif c in (91, 123):
            depth += 1
            if depth > 12:
                raise ValueError("study nesting bound")
        elif c in (93, 125):
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate study key")
            result[key] = value
        return result

    # WireModel JSON mode accepts exact Decimal strings while retaining strict
    # integer/bool and extra-field rejection. Re-encode the checked parse.
    parsed = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(
        ValueError("nonfinite study number")))
    schemas: dict[str, type[Study]] = {
        "policyops.study/v1": Study, "policyops.study/v2": StudyV2, "policyops.study/v3": StudyV3}
    kind = schemas.get(str(parsed.get("schema_version")), Study) if isinstance(parsed, dict) else Study
    result = kind.model_validate_json(json.dumps(parsed))
    result.validate_data()
    return result


def preflight(study: Study, *, snapshot: Scope | None = None,
              remaining: dict[str, tuple[tuple[str, int, int], ...]] | None = None) -> dict[str, Any]:
    """Planning assumptions and worst-case reservations; never paid authorization.

    Remaining slots may be nonrectangular after restart. Use one synthetic task
    ID per remaining slot in the pure T10 planner and retain the original digest.
    """
    rows: list[dict[str, Any]] = []
    full_schedule = {v.name: tuple((t, i, seed) for t in study.tasks for i, seed in enumerate(study.seeds))
                     for v in study.variants}
    total_calls, liability, estimate = 0, Decimal(0), Decimal(0)
    per_scenario_ok = True
    caps = study.limits.caps()
    remaining_work: dict[str, Any] = {}
    for variant in study.variants:
        configuration = study.configuration(variant)
        slots = tuple((task, i, seed) for task in study.tasks for i, seed in enumerate(study.seeds)) \
            if remaining is None else remaining[variant.name]
        remaining_work[variant.name] = slots
        if not slots:
            continue
        request_input = max(getattr(variant.actors, name).max_input for name in ACTORS)
        actor_caps = replace(caps, request_max_input=request_input)
        bounds = tuple(ChatBound(actor=name, model=getattr(variant.actors, name).model,
            effort=getattr(variant.actors, name).effort, max_input=getattr(variant.actors, name).max_input,
            max_output=getattr(variant.actors, name).max_output,
            logical_calls=getattr(variant.actors, name).logical_calls,
            max_repairs=0, retries_per_request=0) for name in ACTORS)
        manifest = Manifest(v="policyops.eval-budget-manifest/v1", name=study.study_key, version="v1",
            code_revision="recorded_at_execution", dataset="tau2-retail", dataset_revision=upstream.COMMIT,
            split_id="dev", prompt_revision="minimal-v1-opening", price_revision=study.price_revision,
            tasks=tuple(f"slot-{i}" for i in range(len(slots))), trials_per_task=1, actors=bounds)
        plan = budget_preflight(manifest, actor_caps, registry=configuration.registry)
        per_scenario_ok &= all(c.ok for c in plan.checks if c.scope == "scenario")
        total_calls += plan.total_calls
        liability += plan.new_study_usd
        for name in ACTORS:
            actor = getattr(variant.actors, name)
            price = configuration.price(name)
            tiers = price.tiers_up_to(actor.max_input)
            planning = (Decimal(actor.planning_input) * max(t.input for t in tiers)
                        + Decimal(actor.planning_output) * max(t.output or Decimal(0) for t in tiers)) / 1_000_000
            estimate += planning * len(slots)
            rows.append({"variant": variant.name, "actor": name, "model": actor.model, "slots": len(slots),
                "logical_calls_per_slot": actor.logical_calls,
                "reservation_usd": str(configuration.reservation(name).worst_usd),
                "planning_input_per_slot": actor.planning_input, "planning_output_per_slot": actor.planning_output})
    cap_match = snapshot is None or (snapshot.kind == "study" and snapshot.cap_usd == caps.study_usd
        and snapshot.cap_calls == caps.study_calls and snapshot.cap_counts == caps.study_calls)
    prior_usd = Decimal(0) if snapshot is None else snapshot.spent_usd + snapshot.held_usd
    prior_calls = 0 if snapshot is None else snapshot.calls_consumed + snapshot.calls_held
    prior_counts = 0 if snapshot is None else snapshot.counts_used
    blocked = snapshot is not None and (snapshot.overrun or snapshot.contract_block is not None)
    if (isinstance(study, StudyV2) and not study.limits.max_unresolved_attempts and snapshot is not None
            and (snapshot.held_usd or snapshot.calls_held)):
        blocked = True  # abandoned/unknown billing must be reconciled, never discarded to resume
    ok = (cap_match and not blocked and per_scenario_ok and liability <= caps.invocation_usd
        and total_calls <= caps.invocation_calls and prior_usd + liability <= caps.study_usd
        and prior_calls + total_calls <= caps.study_calls and prior_counts + total_calls <= caps.study_calls)
    return {"schema_version": "policyops.study-preflight/v1", "manifest_sha256": study.digest(),
        "full_schedule_sha256": sha256_bytes(canonical_bytes(full_schedule)),
        "remaining_work_sha256": sha256_bytes(canonical_bytes(remaining_work)), "actors": rows,
        "scheduled_slots": len(study.tasks) * len(study.seeds) * len(study.variants),
        "remaining_slots": sum(len(v) for v in remaining_work.values()),
        "planning_estimate_usd": str(estimate), "admission_ceiling_usd": str(liability),
        "inference_ceiling": total_calls, "count_ceiling": total_calls, "physical_requests_ceiling": 2 * total_calls,
        "study_input_token_ceiling": study.limits.study_input_tokens,
        "study_output_token_ceiling": study.limits.study_output_tokens,
        "price_revision": study.price_revision, "study_cap_usd": str(caps.study_usd),
        "prior": "unverified" if snapshot is None else "ledger_snapshot",
        "prior_spent_and_held_usd": None if snapshot is None else str(prior_usd),
        "within_caps": ok, "authorizes_paid_execution": False,
        "assumptions": "Planning tokens are declared estimates; admission reserves every actor's maximum, "
                       "including judge calls on tasks without assertions. No provider seed determinism is claimed."}
