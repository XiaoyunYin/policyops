"""Frozen report input allowlist. No live registry, task, DB or provider imports."""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from policyops_contracts import WireModel
from policyops_contracts.scalars import UtcDatetime


Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,99}$")]
Count = Annotated[int, Field(ge=0, le=10**12)]
Money = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,12})(\.[0-9]{1,18})?$")]
Actor = Literal["agent", "simulator", "judge"]
Model = Literal["gpt-6-luna", "claude-haiku-5-5"]
Failure = Literal["application", "budget", "infrastructure", "simulator", "judge_unavailable",
                  "deadline", "interruption", "artifact_integrity"]


class TaskMeta(WireModel):
    task_id: Name
    stratum: Literal["db_only", "db_nl"]


class FrozenActor(WireModel):
    actor: Actor
    model: Model
    effort: Literal["none", "low"]
    max_input: Annotated[int, Field(ge=1, le=16000)]
    max_output: Annotated[int, Field(ge=64, le=2048)]
    logical_calls: Annotated[int, Field(ge=1, le=64)]
    planning_input: Count
    planning_output: Count
    input_usd_per_million: Money
    output_usd_per_million: Money

    @model_validator(mode="after")
    def registry(self) -> FrozenActor:
        if self.model == "claude-haiku-5-5" and self.effort != "low":
            raise ValueError("effort outside frozen registry")
        return self


class FrozenVariant(WireModel):
    name: Name
    config_sha256: Digest
    prompt_sha256: Digest
    tool_sha256: Digest
    schema_sha256: Digest
    actors: tuple[FrozenActor, ...]

    @model_validator(mode="after")
    def actor_set(self) -> FrozenVariant:
        if len(self.actors) != 3 or {a.actor for a in self.actors} != {"agent", "simulator", "judge"}:
            raise ValueError("invalid frozen actor set")
        return self


class Provenance(WireModel):
    dataset_sha256: Digest
    split_sha256: Digest
    task_list_sha256: Digest
    calibration_sha256: Digest
    source_head: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    dirty_sha256: Digest
    app_lock_sha256: Digest
    evals_lock_sha256: Digest
    upstream_commit: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    price_revision: Name
    price_snapshot_sha256: Digest
    scorer_version: Literal["tau2-all-validated-v1"] = "tau2-all-validated-v1"


class Exclusion(WireModel):
    task_id: Name
    reasons: tuple[Literal["near_holdout_scenario", "open_upstream_issue", "reference_action_error"], ...]


class FrozenEligibility(WireModel):
    original_frame_count: Count
    original_frame_sha256: Digest
    allowlist_sha256: Digest
    tuning_task_ids: tuple[Name, ...]
    excluded: tuple[Exclusion, ...]
    example_prompt_sha256: Digest


class FrozenDecision(WireModel):
    candidate: Name
    reference: Name
    margin: Money
    primary_k: Literal[1] = 1
    guard_ks: tuple[Literal[4], ...]


class Environment(WireModel):
    os: Literal["windows", "linux", "darwin", "unknown"]
    architecture: Literal["AMD64", "x86_64", "arm64", "aarch64", "unknown"]
    logical_cpus: Annotated[int, Field(ge=1, le=65536)] | None
    ram_bytes: Count | None
    python: Annotated[str, StringConstraints(pattern=r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")]


class FrozenCaps(WireModel):
    scenario_usd: Money
    invocation_usd: Money
    study_usd: Money
    scenario_calls: Count
    invocation_calls: Count
    study_calls: Count
    scenario_counts: Count
    invocation_counts: Count
    study_counts: Count
    trial_seconds: Count
    study_input_tokens: Count
    study_output_tokens: Count


class FrozenTier(WireModel):
    name: Literal["short", "long"]
    max_prompt_tokens: Count | None
    input: Money
    output: Money
    cache_read: Money
    cache_writes: dict[Literal["30m", "12h", "5m", "1h"], Money]


class FrozenModelPrice(WireModel):
    model: Model
    provider: Literal["openai", "anthropic"]
    tiers: Annotated[tuple[FrozenTier, ...], Field(min_length=1, max_length=4)]


class FrozenPrices(WireModel):
    revision: Name
    models: Annotated[tuple[FrozenModelPrice, ...], Field(min_length=1, max_length=4)]


class FrozenStudy(WireModel):
    schema_version: Literal["policyops.frozen-study/v1"] = "policyops.frozen-study/v1"
    study_id: UUID
    config_sha256: Digest
    purpose: Literal["dev", "holdout"]
    tasks: Annotated[tuple[TaskMeta, ...], Field(min_length=1, max_length=128)]
    seeds: Annotated[tuple[int, ...], Field(min_length=1, max_length=32)]
    variants: Annotated[tuple[FrozenVariant, ...], Field(min_length=2, max_length=4)]
    schedule: Annotated[tuple[tuple[Name, Name, int, int], ...], Field(max_length=16384)]
    schedule_sha256: Digest
    ks: Annotated[tuple[int, ...], Field(min_length=1, max_length=8)]
    bootstrap_seed: Annotated[int, Field(ge=0, le=2147483647)]
    analysis_spec_sha256: Digest
    registration_sha256: Digest | None
    registered_at: UtcDatetime | None
    provenance: Provenance
    eligibility: FrozenEligibility
    decision: FrozenDecision
    environment: Environment
    limits: FrozenCaps
    prices: FrozenPrices
    # Private immutable specifications/receipts are verified, never copied into
    # report values. In particular scripted responses remain private here.
    specification: dict[str, Any]
    registration: dict[str, Any] | None
    protocol: Literal["paired-minimal-agent-no-retries-v2"] = "paired-minimal-agent-no-retries-v2"

    @model_validator(mode="after")
    def bounds(self) -> FrozenStudy:
        from policyops_evals.canonical import canonical_bytes, id_list_digest, sha256_bytes

        tasks = [t.task_id for t in self.tasks]
        names = [v.name for v in self.variants]
        expected = {(v, t, i, seed) for v in names for t in tasks for i, seed in enumerate(self.seeds)}
        if (len(set(tasks)) != len(tasks) or len(set(names)) != len(names)
                or len(set(self.seeds)) != len(self.seeds) or len(expected) != len(self.schedule)
                or set(self.schedule) != expected
                or sha256_bytes(canonical_bytes(self.schedule)) != self.schedule_sha256
                or id_list_digest(tasks) != self.provenance.task_list_sha256
                or len(set(self.ks)) != len(self.ks) or any(not 1 <= k <= len(self.seeds) for k in self.ks)
                or 2 * len(tasks) * len(self.ks) * (3 * len(names) + 2) * 10000 > 80_000_000):
            raise ValueError("invalid frozen frame/workload")
        if sha256_bytes(canonical_bytes(self.prices.model_dump(mode="json"))) != self.provenance.price_snapshot_sha256:
            raise ValueError("frozen price snapshot mismatch")
        spec = self.specification
        if (sha256_bytes(canonical_bytes(spec)) != self.config_sha256
                or spec.get("schema_version") != "policyops.study/v2" or spec.get("tasks") != tasks
                or spec.get("seeds") != list(self.seeds) or spec.get("purpose") != self.purpose
                or spec.get("limits") != self.limits.model_dump(mode="json")):
            raise ValueError("frozen specification mismatch")
        if any(spec.get(key) != getattr(self.provenance, key) for key in (
                "dataset_sha256", "split_sha256", "calibration_sha256", "task_list_sha256", "price_revision")):
            raise ValueError("frozen provenance mismatch")
        analysis = {"statistics": spec.get("statistics"), "decision": spec.get("decision")}
        if sha256_bytes(canonical_bytes(analysis)) != self.analysis_spec_sha256:
            raise ValueError("frozen analysis mismatch")
        statistics, decision = analysis["statistics"], analysis["decision"]
        if (not isinstance(statistics, dict) or not isinstance(decision, dict)
                or statistics.get("ks") != list(self.ks) or statistics.get("bootstrap_seed") != self.bootstrap_seed
                or statistics.get("bootstrap_replicates") != 10000 or statistics.get("confidence") != "0.95"
                or statistics.get("algorithm") != "task-bootstrap-sha256-v1"
                or statistics.get("quantile") != "linear-r7-v1" or decision.get("metric") != "pass^1"
                or decision.get("direction") != "candidate-minus-reference"
                or decision.get("candidate") != self.decision.candidate
                or decision.get("reference") != self.decision.reference
                or decision.get("margin") != self.decision.margin
                or decision.get("guard_metrics") != [f"pass^{k}" for k in self.decision.guard_ks]):
            raise ValueError("frozen analysis fields mismatch")
        variants = spec.get("variants", [])
        if (not isinstance(variants, list) or not all(isinstance(v, dict) for v in variants)
                or [v.get("name") for v in variants] != names):
            raise ValueError("frozen variants mismatch")
        for variant, original in zip(self.variants, variants, strict=True):
            if not isinstance(original.get("actors"), dict):
                raise ValueError("frozen actors mismatch")
            for actor in variant.actors:
                expected_actor = {key: getattr(actor, key) for key in ("model", "effort", "max_input", "max_output",
                                                               "logical_calls", "planning_input", "planning_output")}
                if original.get("actors", {}).get(actor.actor) != expected_actor:
                    raise ValueError("frozen actor configuration mismatch")
            if any(original.get(key) != getattr(variant, key)
                   for key in ("prompt_sha256", "tool_sha256", "schema_sha256")):
                raise ValueError("frozen implementation mismatch")
            digest = sha256_bytes(canonical_bytes({"study": self.config_sha256, "variant": original,
                "prompt_sha256": variant.prompt_sha256, "wire": "policyops.wire/v1",
                "upstream_commit": self.provenance.upstream_commit}))
            if digest != variant.config_sha256:
                raise ValueError("frozen variant digest mismatch")
        if spec.get("preregistration_sha256") != self.registration_sha256:
            raise ValueError("frozen registration reference mismatch")
        if self.registration_sha256 is not None:
            receipt = self.registration or {}
            payload = receipt.get("payload", {})
            if not isinstance(payload, dict):
                raise ValueError("frozen registration payload invalid")
            without_reference = {key: value for key, value in spec.items() if key != "preregistration_sha256"}
            if (sha256_bytes(canonical_bytes(payload)) != self.registration_sha256
                    or receipt.get("sha256") != self.registration_sha256
                    or payload.get("schema_version") != "policyops.study-registration/v1"
                    or spec.get("preregistration_sha256") != self.registration_sha256
                    or payload.get("specification") != without_reference
                    or payload.get("schedule_sha256") != self.schedule_sha256
                    or payload.get("price_snapshot_sha256") != self.provenance.price_snapshot_sha256):
                raise ValueError("frozen registration mismatch")
            expected_source = {"source_head": self.provenance.source_head,
                "dirty_sha256": self.provenance.dirty_sha256,
                "lock_sha256": {"uv.lock": self.provenance.app_lock_sha256,
                                "evals/uv.lock": self.provenance.evals_lock_sha256}}
            from datetime import datetime

            if (payload.get("source") != expected_source
                    or datetime.fromisoformat(str(receipt.get("created_at"))) != self.registered_at):
                raise ValueError("frozen registration source/time mismatch")
        if (self.decision.candidate not in names or self.decision.reference not in names
                or self.decision.candidate == self.decision.reference or 1 not in self.ks
                or any(k not in self.ks for k in self.decision.guard_ks)
                or not 0 < Decimal(self.decision.margin) < 1
                or (self.registration_sha256 is None) != (self.registered_at is None)):
            raise ValueError("invalid frozen decision")
        if self.purpose == "holdout" and (len(tasks) != 50 or len(self.seeds) != 4
                or self.registration_sha256 is None
                or self.eligibility.original_frame_sha256 != id_list_digest(tasks)):
            raise ValueError("invalid frozen holdout")
        return self


class TrialRow(WireModel):
    variant: Name
    task_id: Name
    trial_index: Annotated[int, Field(ge=0, le=31)]
    seed: int
    slot_id: UUID
    scenario_id: UUID
    stratum: Literal["db_only", "db_nl"]
    status: Literal["success", "failure", "error", "aborted", "pending", "running", "unavailable_result",
                    "integrity_error"]
    failure_class: Failure | None = None
    db_success: bool | None = None
    composite_success: bool | None = None
    cost_usd: Money | None = None
    held_usd: Money
    cost_known: bool
    latency_ms: Count | None = None
    latency_censored: bool = False
    artifact_sha256: Digest | None = None
    result_sha256: Digest | None = None
    started_at: UtcDatetime | None = None
    finished_at: UtcDatetime | None = None
    returned_models: dict[Actor, tuple[Model, ...]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def scored(self) -> TrialRow:
        if (self.status in {"success", "failure"}) != (self.composite_success is not None):
            raise ValueError("inconsistent scored result")
        if self.status == "success" and self.composite_success is not True:
            raise ValueError("inconsistent success")
        if self.status == "failure" and self.composite_success is not False:
            raise ValueError("inconsistent failure")
        return self


class AttemptRow(WireModel):
    id: UUID
    scenario_id: UUID
    actor: Actor
    model: Model
    state: Literal["reserved", "dispatching", "released", "settled", "unresolved"]
    count_state: Literal["none", "claimed", "admitted", "rejected", "failed"]
    actual_usd: Money | None
    reserved_usd: Money
    input_total: Count | None = None
    output: Count | None = None
    reasoning: Count | None = None
    cache_read: Count | None = None
    cache_write: Count | None = None
    usage_valid: bool

    @model_validator(mode="after")
    def usage_consistent(self) -> AttemptRow:
        if self.usage_valid and (self.input_total is None or self.output is None or self.cache_read is None
                or self.cache_write is None or self.cache_read + self.cache_write > self.input_total
                or (self.reasoning is not None and self.reasoning > self.output)):
            raise ValueError("contradictory frozen usage")
        if (self.state == "settled") != (self.actual_usd is not None):
            raise ValueError("inconsistent settlement")
        return self


class ScopeRow(WireModel):
    id: UUID
    kind: Literal["study", "scenario"]
    spent_usd: Money
    held_usd: Money
    calls_consumed: Count
    calls_held: Count
    counts_used: Count
    blocked: bool


class TimingRow(WireModel):
    slot_id: UUID
    call_id: UUID
    actor: Actor
    started_at: UtcDatetime
    finished_at: UtcDatetime | None
    wall_ms: Count | None


class Snapshot(WireModel):
    schema_version: Literal["policyops.study-snapshot/v1"] = "policyops.study-snapshot/v1"
    created_at: UtcDatetime
    trials: Annotated[tuple[TrialRow, ...], Field(max_length=16384)]
    attempts: Annotated[tuple[AttemptRow, ...], Field(max_length=131072)]
    scopes: Annotated[tuple[ScopeRow, ...], Field(max_length=16385)]
    timings: Annotated[tuple[TimingRow, ...], Field(max_length=131072)]
    db_version: Annotated[str, StringConstraints(pattern=r"^[0-9.]{1,20}$")]
