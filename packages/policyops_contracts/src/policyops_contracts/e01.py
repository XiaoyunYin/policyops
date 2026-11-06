"""E01 retrieval-selection study contracts (T15a; offline machinery only).

A **manifest** enumerates every slot of one study before any work: phase, arm, task, trial, whether it is a declared
optional confirmation, whether it has a provider path, and its common budget envelope. Its status is always `proposed`
here: no study has run and no gate is frozen. A **trajectory record** is the export of one slot's stored retrieval
steps (authoritative identities only, never labels, instructions or query text) plus its outcome status. A **report**
holds the derived metrics as exact decimal strings.

Strict headline metrics count every non-completed scheduled slot with empty delivered and candidate sets. Observed
progress (all slots, actual sets) and complete-case (completed slots only) are diagnostics. Banking required documents
are task-level labels for a whole trajectory and are joined only on the evaluator side; query-level
Recall/MRR/R-precision are task-pool proxies, never per-turn relevance. Intervals are task-cluster bootstrap aids for
dev selection, not confirmatory significance. There are no floats anywhere: ratios and USD are exact decimal strings.
"""

from __future__ import annotations

from decimal import Decimal
import hashlib
import json
from typing import Annotated, Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.retrieval import MAX_EVIDENCE_ITEMS, RetrievalConfig, RetrievalMode, Step
from policyops_contracts.scalars import Sha256Hex, Slug


Phase = Literal["acquisition", "replay", "confirmation", "retail_control"]
ArmId = Literal["A0", "A1", "A2", "A3", "R0", "R1"]
OutcomeStatus = Literal["completed", "budget_stop", "interrupted", "infra_error", "simulator_error",
                        "retrieval_error"]
SlotPlan = Literal["scheduled", "declared_optional"]
EnvelopeGroup = Literal["banking_insitu", "replay_provider", "retail"]
Variant = Literal["strict", "observed_progress", "complete_case"]
TaskId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_\-]{1,64}$")]
Stem = Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f/]+$")]
UsdText = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,6})(\.[0-9]{1,12})?$")]
_DECIMAL_TEXT = r"^-?(0|[1-9][0-9]{0,6})(\.[0-9]{1,12})?$"


def _within(low: int, high: int) -> object:
    def check(value: str) -> str:
        if not low <= Decimal(value) <= high:
            raise ValueError(f"a value from {low} to {high}")
        if value.startswith("-") and Decimal(value) == 0:
            raise ValueError("no negative zero")
        return value
    return check


# Coverage, rates and the margin are within [0, 1]; a paired difference is within [-1, 1].
UnitText = Annotated[str, StringConstraints(pattern=_DECIMAL_TEXT), AfterValidator(_within(0, 1))]
DeltaText = Annotated[str, StringConstraints(pattern=_DECIMAL_TEXT), AfterValidator(_within(-1, 1))]
Trial = Annotated[int, Field(ge=0, le=15)]
MAX_SLOTS = 4096
MAX_TASKS = 128
MAX_STEPS_PER_TRAJECTORY = 64
MAX_CANDIDATES = 100


E01_SLOT_NAMESPACE = uuid5(NAMESPACE_URL, "policyops:e01-slot/v1")


def slot_id_for(study_id: UUID, phase: str, arm_id: str, task_id: str, trial: int) -> UUID:
    """The stable slot identity: `uuid5(E01_SLOT_NAMESPACE, "{study}:{phase}:{arm}:{task}:{trial}")`."""
    return uuid5(E01_SLOT_NAMESPACE, f"{study_id}:{phase}:{arm_id}:{task_id}:{trial}")


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


# -- the plan --------------------------------------------------------------------------------------------------------

# The admission policy of each phase: the arms it may hold, their plan and their provider path / common envelope
# (None: the no-provider path). Comparable arms of one phase therefore always share one envelope; a phase need not be
# present (coherent partial studies stay valid), but a present one must follow this policy.
_PHASE_POLICY: dict[str, tuple[str, frozenset[str], str, dict[str, str | None]]] = {
    "acquisition": ("banking_knowledge", frozenset({"A2"}), "scheduled", {"A2": "banking_insitu"}),
    "replay": ("banking_knowledge", frozenset({"A0", "A1", "A2", "A3"}), "scheduled",
               {"A0": None, "A1": "replay_provider", "A2": "replay_provider", "A3": "replay_provider"}),
    "confirmation": ("banking_knowledge", frozenset({"A0", "A1", "A3"}), "declared_optional",
                     {"A0": "banking_insitu", "A1": "banking_insitu", "A3": "banking_insitu"}),
    "retail_control": ("retail", frozenset({"R0", "R1"}), "scheduled", {"R0": "retail", "R1": "retail"}),
}
_PURPOSE_DOMAIN = {"dev_selection": "banking_knowledge", "retail_dev_control": "retail"}

_ARM_SHAPE: dict[str, tuple[RetrievalMode, bool]] = {
    "A0": ("lexical", False), "A1": ("dense", False), "A2": ("hybrid", False), "A3": ("hybrid", True),
    "R0": ("full_policy", False), "R1": ("hybrid", False),
}


class E01Arm(WireModel):
    """One arm: its exact retrieval configuration and that configuration's digest (checked)."""

    arm_id: ArmId
    config: RetrievalConfig
    config_sha256: Sha256Hex

    @model_validator(mode="after")
    def _shape(self) -> Self:
        mode, reranked = _ARM_SHAPE[self.arm_id]
        if self.config.mode != mode or (self.config.rerank is not None) != reranked:
            raise ValueError(f"arm {self.arm_id} is {mode} {'with' if reranked else 'without'} rerank")
        if self.arm_id == "A1" and self.config.dense_policy != "refuse":
            raise ValueError("the dense arm refuses rather than falling back to lexical")
        if self.config_sha256 != self.config.sha256():
            raise ValueError("config_sha256 is not the configuration's digest")
        return self


class Bounds(WireModel):
    """Per-trajectory actor bounds, identical for every comparable arm."""

    simulator_turns: Annotated[int, Field(ge=1, le=64)]
    investigator_calls: Annotated[int, Field(ge=1, le=64)]
    retrieval_steps: Annotated[int, Field(ge=1, le=MAX_STEPS_PER_TRAJECTORY)]


class Envelope(WireModel):
    """One common outer per-slot ledger ceiling for a group of comparable arms (reservation maxima, not spend). A
    provider envelope's USD cap is positive (ledger caps require it); a no-provider slot has no envelope at all."""

    group: EnvelopeGroup
    cap_calls: Annotated[int, Field(ge=1, le=10_000)]
    cap_usd: UsdText
    chat_calls: Annotated[int, Field(ge=0, le=10_000)]
    embedding_batches: Annotated[int, Field(ge=0, le=10_000)]
    max_input_tokens_per_chat_call: Annotated[int, Field(ge=1, le=128_000)]
    max_output_tokens_per_chat_call: Annotated[int, Field(ge=1, le=128_000)]
    max_input_tokens_per_embedding_batch: Annotated[int, Field(ge=1, le=300_000)]

    @model_validator(mode="after")
    def _positive(self) -> Self:
        if Decimal(self.cap_usd) <= 0:
            raise ValueError("a provider envelope's USD cap is positive")
        if self.cap_calls != self.chat_calls + self.embedding_batches:
            raise ValueError("the call cap is the chat calls plus the embedding batches")
        return self


class ActorReservation(WireModel):
    actor: Literal["agent", "simulator", "judge", "reranker", "embedding"]
    model: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    config_sha256: Sha256Hex
    worst_usd: UsdText

    @model_validator(mode="after")
    def _positive(self) -> Self:
        if Decimal(self.worst_usd) <= 0:
            raise ValueError("an actor's worst-case reservation is positive")
        return self


class SlotSpec(WireModel):
    slot_id: UUID
    phase: Phase
    arm_id: ArmId
    task_id: TaskId
    trial: Trial
    plan: SlotPlan
    provider_path: bool
    envelope: EnvelopeGroup | None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.provider_path != (self.envelope is not None):
            raise ValueError("exactly the provider-path slots have an envelope")
        if self.plan != "scheduled" and self.phase != "confirmation":
            raise ValueError("only confirmation slots can be declared optional")
        return self


class E01Manifest(WireModel):
    """The immutable, finite slot enumeration of one study. `status` is `proposed` for every T15a artifact."""

    v: Literal["policyops.e01-manifest/v1"] = "policyops.e01-manifest/v1"
    study_id: UUID
    status: Literal["proposed"] = "proposed"
    purpose: Literal["dev_selection", "retail_dev_control"]
    domain: Literal["banking_knowledge", "retail"]
    split_manifest_sha256: Sha256Hex
    dev_task_ids_digest: Sha256Hex
    task_ids: Annotated[tuple[TaskId, ...], Field(min_length=1, max_length=MAX_TASKS)]
    trials: Annotated[int, Field(ge=1, le=16)]
    seeds: Annotated[tuple[int, ...], Field(min_length=1, max_length=16)]
    arms: Annotated[tuple[E01Arm, ...], Field(min_length=1, max_length=6)]
    bounds: Bounds
    envelopes: Annotated[tuple[Envelope, ...], Field(max_length=3)]
    actors: Annotated[tuple[ActorReservation, ...], Field(min_length=1, max_length=5)]
    price_revision: Slug
    margin: UnitText
    selection_rule: Literal["policyops.e01-selection/v1"] = "policyops.e01-selection/v1"
    bootstrap_seed: Annotated[int, Field(ge=0, le=2**63 - 1)]
    bootstrap_resamples: Annotated[int, Field(ge=100, le=100_000)] = 10_000
    slots: Annotated[tuple[SlotSpec, ...], Field(min_length=1, max_length=MAX_SLOTS)]

    @model_validator(mode="after")
    def _closed(self) -> Self:
        if len(self.seeds) != self.trials:
            raise ValueError("one seed per trial")
        if len(set(self.task_ids)) != len(self.task_ids) or list(self.task_ids) != sorted(self.task_ids):
            raise ValueError("task IDs are sorted and unique")
        if len({a.arm_id for a in self.arms}) != len(self.arms):
            raise ValueError("arm IDs are unique")
        if len({e.group for e in self.envelopes}) != len(self.envelopes):
            raise ValueError("one envelope per group")
        ids = [s.slot_id for s in self.slots]
        keys = [(s.phase, s.arm_id, s.task_id, s.trial) for s in self.slots]
        if len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
            raise ValueError("slot identities are unique")
        arms, tasks, groups = {a.arm_id for a in self.arms}, set(self.task_ids), {e.group for e in self.envelopes}
        for slot in self.slots:
            if slot.slot_id != slot_id_for(self.study_id, slot.phase, slot.arm_id, slot.task_id, slot.trial):
                raise ValueError("a slot ID is not its derived identity")
            if slot.arm_id not in arms or slot.task_id not in tasks or slot.trial >= self.trials:
                raise ValueError("every slot names a declared arm, task and trial")
            if slot.envelope is not None and slot.envelope not in groups:
                raise ValueError("every slot envelope is declared")
        # Closed cohorts: each declared (phase, arm) covers exactly every task x trial, with one plan, provider path
        # and envelope, so a comparison can never pair an incomplete or different trial frame.
        frame = {(t, i) for t in self.task_ids for i in range(self.trials)}
        cohorts: dict[tuple[str, str], list[SlotSpec]] = {}
        for slot in self.slots:
            cohorts.setdefault((slot.phase, slot.arm_id), []).append(slot)
        if _PURPOSE_DOMAIN[self.purpose] != self.domain:
            raise ValueError("the purpose does not match the domain")
        for (phase, arm_id), members in cohorts.items():
            if {(s.task_id, s.trial) for s in members} != frame:
                raise ValueError(f"the {phase}/{arm_id} cohort does not cover every task and trial")
            domain, allowed, plan, envelopes = _PHASE_POLICY[phase]
            if domain != self.domain or arm_id not in allowed:
                raise ValueError(f"{phase}/{arm_id} is not an admissible cohort of a {self.domain} study")
            expected = envelopes[arm_id]
            for slot in members:
                if (slot.plan, slot.provider_path, slot.envelope) != (plan, expected is not None, expected):
                    raise ValueError(f"the {phase}/{arm_id} cohort does not follow its plan and common envelope")
        return self

    def digest(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


class E01Selection(WireModel):
    """The one immutable confirmation decision of a study, taken after the replay screen: which declared optional arms
    become scheduled. Every other declared optional slot is `not_selected` (reported, never a failed measurement)."""

    v: Literal["policyops.e01-selection/v1"] = "policyops.e01-selection/v1"
    manifest_sha256: Sha256Hex
    replay_report_sha256: Sha256Hex
    confirmation_arms: Annotated[tuple[ArmId, ...], Field(max_length=2)]

    @model_validator(mode="after")
    def _legal(self) -> Self:
        arms = list(self.confirmation_arms)
        if len(set(arms)) != len(arms) or arms != sorted(arms):
            raise ValueError("confirmation arms are sorted and unique")
        if not set(arms) <= {"A0", "A1", "A3"} or sum(a in ("A0", "A1") for a in arms) > 1:
            raise ValueError("at most one simpler arm (A0 or A1) and A3 can be confirmed")
        return self

    def digest(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


# -- exported records ------------------------------------------------------------------------------------------------

class DeliveredDocument(WireModel):
    evidence_number: Annotated[int, Field(ge=1, le=MAX_EVIDENCE_ITEMS)]
    document_id: UUID
    document_version_id: UUID
    stem: Stem


class CandidateDocument(WireModel):
    rank: Annotated[int, Field(ge=1, le=MAX_CANDIDATES)]
    document_id: UUID
    stem: Stem


class RetrievalStepRecord(WireModel):
    """One stored step, exported only after the immutable trace, intent, bodies, spans and generation membership were
    verified and every document UUID was mapped through the workspace's own document rows."""

    step: Step
    trace_id: UUID
    payload_sha256: Sha256Hex
    request_sha256: Sha256Hex
    query_sha256: Sha256Hex
    config_sha256: Sha256Hex  # the immutable intent's configuration digest (binds the step to its arm)
    generation_id: UUID
    generation_current_at_export: bool
    mode: RetrievalMode
    delivered: Annotated[tuple[DeliveredDocument, ...], Field(max_length=MAX_EVIDENCE_ITEMS)] = ()
    candidates: Annotated[tuple[CandidateDocument, ...], Field(max_length=MAX_CANDIDATES)] = ()
    ranked: Annotated[tuple[Stem, ...], Field(max_length=MAX_CANDIDATES)] = ()  # the order delivery used
    evidence_tokens: Annotated[int, Field(ge=0, le=16000)]
    rerank_status: Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,32}$")] | None = None


class ActorCalls(WireModel):
    simulator: Annotated[int, Field(ge=0, le=10_000)] = 0
    investigator: Annotated[int, Field(ge=0, le=10_000)] = 0
    reranker: Annotated[int, Field(ge=0, le=10_000)] = 0
    embedding: Annotated[int, Field(ge=0, le=10_000)] = 0


class TrajectoryRecord(WireModel):
    """One slot's outcome. Never carries labels, instructions, reference actions or query text.

    `calls`, `spent_usd` and `held_usd` are None (unknown) unless the slot's own ledger scope supplied them: a stored
    trace (or a winning trace replayed by a paid losing writer) is never per-invocation cost authority, so an export
    never invents zero work or infers study cost from traces."""

    v: Literal["policyops.e01-trajectory/v1"] = "policyops.e01-trajectory/v1"
    manifest_sha256: Sha256Hex
    slot_id: UUID
    phase: Phase
    arm_id: ArmId
    task_id: TaskId
    trial: Trial
    status: OutcomeStatus
    steps: Annotated[tuple[RetrievalStepRecord, ...], Field(max_length=MAX_STEPS_PER_TRAJECTORY)] = ()
    calls: ActorCalls | None = None
    spent_usd: UsdText | None = None
    held_usd: UsdText | None = None

    def digest(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


# -- the report ------------------------------------------------------------------------------------------------------

class Interval(WireModel):
    """Paired task-cluster bootstrap: B resamples of clusters with replacement (trials stay inside their task), each
    draw the exact mean difference; the bounds are the type-7 (linear interpolation) empirical quantiles at 2.5% and
    97.5% of the sorted draws (h = (B - 1) p). Computed with exact fractions; rendered ROUND_HALF_EVEN to 12 places."""

    estimate: DeltaText
    lower: DeltaText
    upper: DeltaText
    resamples: Annotated[int, Field(ge=0, le=100_000)]
    clusters: Literal["task", "group"]


class ArmMetrics(WireModel):
    """Coverage values are None (undefined), never a synthetic 0, when the variant includes no slot (for example
    complete-case with no completed slot); `included_slots` then says 0."""

    arm_id: ArmId
    phase: Phase
    variant: Variant
    scheduled_slots: Annotated[int, Field(ge=0, le=MAX_SLOTS)]
    included_slots: Annotated[int, Field(ge=0, le=MAX_SLOTS)]
    status_counts: Annotated[tuple[tuple[OutcomeStatus, int], ...], Field(max_length=6)]
    task_macro_coverage: UnitText | None
    document_macro_coverage: UnitText | None
    all_required_rate: UnitText | None
    candidate_task_macro_coverage: UnitText | None
    query_recall_at_10: UnitText | None = None
    query_recall_at_10_ceiling: UnitText | None = None
    query_recall_at_20: UnitText | None = None
    query_recall_at_20_ceiling: UnitText | None = None
    query_mrr_at_10: UnitText | None = None
    query_r_precision: UnitText | None = None
    delivered_documents: Annotated[int, Field(ge=0)]
    retrieval_steps: Annotated[int, Field(ge=0)]
    evidence_tokens: Annotated[int, Field(ge=0)]
    spent_usd: UsdText | None  # summed over slots with known ledger cost; None when no slot has known cost
    held_usd: UsdText | None
    cost_unknown_slots: Annotated[int, Field(ge=0, le=MAX_SLOTS)]


class PairedComparison(WireModel):
    arm_id: ArmId
    baseline_arm_id: ArmId
    phase: Phase
    metric: Literal["strict_task_macro_coverage"] = "strict_task_macro_coverage"
    task_cluster: Interval
    group_sensitivity: Interval | None = None


class E01Report(WireModel):
    v: Literal["policyops.e01-report/v1"] = "policyops.e01-report/v1"
    manifest_sha256: Sha256Hex
    records_sha256: Sha256Hex
    labels_sha256: Sha256Hex
    arms: Annotated[tuple[ArmMetrics, ...], Field(max_length=64)]
    comparisons: Annotated[tuple[PairedComparison, ...], Field(max_length=16)] = ()
    not_scheduled_slots: Annotated[int, Field(ge=0, le=MAX_SLOTS)] = 0
    interpretation: Literal["dev selection aid; task-level labels; not per-turn relevance; not confirmatory"] = (
        "dev selection aid; task-level labels; not per-turn relevance; not confirmatory")
