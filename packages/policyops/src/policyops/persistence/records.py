"""Strict, frozen inputs and outputs of the repositories (no arbitrary dictionaries cross this boundary)."""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.retail_service import MutationRequest, Receipt
from policyops_contracts.scalars import PositiveVersion, Sha256Hex, ShortText, Slug, UserId, UtcDatetime


MembershipRole = Literal["analyst", "reviewer", "admin", "auditor"]
CaseStatus = Literal["open", "in_progress", "resolved", "closed"]
RunMode = Literal["workbench", "evaluation"]
Actor = Literal["agent", "simulator", "judge", "reranker", "embedding"]
CostStatus = Literal["known", "estimated", "unknown"]
DedupeKey = Annotated[str, StringConstraints(min_length=1, max_length=200)]
USD_LIMIT = Decimal(1_000_000)
USD_MAX_SCALE = 18


def exact_usd(value: Decimal | None, name: str) -> None:
    """Finite, 0 <= value < 10^6, at most 18 fractional digits; checked, never rounded (the DB checks the same)."""
    if value is None:
        return
    if not value.is_finite() or value < 0 or value >= USD_LIMIT:
        raise ValueError(f"{name} must be a finite amount in [0, 1000000)")
    exponent = value.as_tuple().exponent
    if isinstance(exponent, int) and exponent < -USD_MAX_SCALE:
        raise ValueError(f"{name} has more than {USD_MAX_SCALE} fractional digits")


class Workspace(WireModel):
    id: UUID
    slug: Slug
    name: ShortText
    created_at: UtcDatetime


class Principal(WireModel):
    id: UUID
    issuer: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    subject: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    display_name: ShortText
    created_at: UtcDatetime


class Membership(WireModel):
    id: UUID
    workspace_id: UUID
    principal_id: UUID
    role: MembershipRole
    created_at: UtcDatetime
    revoked_at: UtcDatetime | None = None
    version: PositiveVersion = 1


class NewCase(WireModel):
    id: UUID
    workspace_id: UUID
    scenario: Slug
    customer_user_id: UserId | None
    created_by: UUID | None
    created_at: UtcDatetime


class CaseRecord(NewCase):
    status: CaseStatus
    updated_at: UtcDatetime
    version: PositiveVersion


class NewRun(WireModel):
    id: UUID
    workspace_id: UUID
    case_id: UUID
    case_version: PositiveVersion
    mode: RunMode
    graph_sha256: Sha256Hex
    prompt_sha256: Sha256Hex
    config_sha256: Sha256Hex
    deadline_at: UtcDatetime
    created_at: UtcDatetime

    @model_validator(mode="after")
    def _deadline(self) -> Self:
        if self.deadline_at <= self.created_at:
            raise ValueError("deadline must be after creation")
        return self


ExecutionState = Literal["pending", "dispatched", "succeeded", "failed", "unknown", "reconciled"]
OPEN_EXECUTION_STATES = frozenset({"pending", "dispatched", "unknown"})
ExecutionOutcome = Literal["committed", "upstream_rejected", "effect_mismatch", "money_unrepresentable",
                           "version_conflict", "fenced", "precheck_refused", "cancelled_before_dispatch"]


class ExecutionRecord(WireModel):
    """One `app.tool_executions` row (T19). `request` is the stored, immutable `MutationRequest`."""

    id: UUID
    workspace_id: UUID
    case_id: UUID
    run_id: UUID
    operation_id: UUID
    proposal_id: UUID
    proposal_version: PositiveVersion
    action_digest: Sha256Hex
    approval_id: UUID
    consent_id: UUID
    argument_digest: Sha256Hex
    tool: str
    target_kind: Literal["order", "user"]
    target_id: str
    operation_sha256: Sha256Hex
    request: MutationRequest
    authorization_not_after: UtcDatetime
    state: ExecutionState
    attempts: Annotated[int, Field(ge=0, le=100)]
    reconcile_attempts: Annotated[int, Field(ge=0, le=100)]
    outcome: ExecutionOutcome | None
    resolved_by: Literal["response", "lookup", "fence", "precheck", "cancel"] | None
    last_code: Slug | None
    receipt: Receipt | None
    claim_id: UUID | None
    lease_owner: UUID | None
    lease_expires_at: UtcDatetime | None
    dispatched_at: UtcDatetime | None
    next_attempt_at: UtcDatetime | None
    created_at: UtcDatetime
    updated_at: UtcDatetime
    version: PositiveVersion

    @property
    def terminal(self) -> bool:
        return self.state not in OPEN_EXECUTION_STATES


class NewJob(WireModel):
    id: UUID
    workspace_id: UUID
    run_id: UUID
    dedupe_key: DedupeKey
    kind: Slug
    run_generation: Annotated[int, Field(ge=0)]
    max_attempts: Annotated[int, Field(ge=1, le=100)]
    available_at: UtcDatetime
    deadline_at: UtcDatetime
    created_at: UtcDatetime

    @model_validator(mode="after")
    def _deadline(self) -> Self:
        if self.deadline_at <= self.available_at:
            raise ValueError("a job's deadline must be after the time it becomes available")
        return self


class UsageEvent(WireModel):
    id: UUID
    workspace_id: UUID
    reservation_id: UUID | None = None
    run_id: UUID | None = None
    actor: Actor
    provider: Slug
    model: ShortText
    provider_request_id: DedupeKey
    uncached_input_tokens: Annotated[int, Field(ge=0)]
    cache_read_tokens: Annotated[int, Field(ge=0)]
    cache_write_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]
    reasoning_tokens: Annotated[int, Field(ge=0)]
    price_revision: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    cost_status: CostStatus
    cost_usd: Decimal | None
    created_at: UtcDatetime

    @model_validator(mode="after")
    def _cost(self) -> Self:
        if self.reasoning_tokens > self.output_tokens:
            raise ValueError("reasoning tokens are part of, so cannot exceed, output tokens")
        if (self.cost_status == "unknown") != (self.cost_usd is None):
            raise ValueError("an unknown cost is NULL, and only an unknown cost")
        exact_usd(self.cost_usd, "cost_usd")
        return self


class AuditEvent(WireModel):
    id: UUID
    workspace_id: UUID
    actor_kind: Literal["principal", "system", "worker"]
    actor_principal_id: UUID | None
    action: Slug
    target_type: Slug
    target_id: UUID
    before_sha256: Sha256Hex | None = None
    after_sha256: Sha256Hex | None = None
    reason: Annotated[str, StringConstraints(min_length=1, max_length=500)] | None = None
    correlation_id: UUID
    occurred_at: UtcDatetime

    @model_validator(mode="after")
    def _actor(self) -> Self:
        if (self.actor_kind == "principal") != (self.actor_principal_id is not None):
            raise ValueError("principal actions, and only they, name the principal")
        return self


class EvaluationRun(WireModel):
    id: UUID
    dataset: Slug
    dataset_revision: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    split_id: Slug
    config_sha256: Sha256Hex
    config_json: Annotated[str, StringConstraints(min_length=2, max_length=60000)]
    created_at: UtcDatetime


class EvaluationTrial(WireModel):
    id: UUID
    evaluation_run_id: UUID
    task_id: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    trial_index: Annotated[int, Field(ge=0, le=1000)]
    seed: int
    outcome: Literal["success", "failure", "error", "budget_exceeded", "aborted"]
    reward: Decimal | None
    components_json: Annotated[str, StringConstraints(min_length=2, max_length=60000)]
    error_class: Slug | None = None
    cost_status: CostStatus
    cost_usd: Decimal | None
    latency_ms: Annotated[int, Field(ge=0)] | None = None
    artifact_sha256: Sha256Hex | None = None
    created_at: UtcDatetime

    @model_validator(mode="after")
    def _values(self) -> Self:
        if (self.cost_status == "unknown") != (self.cost_usd is None):
            raise ValueError("an unknown cost is NULL, and only an unknown cost")
        exact_usd(self.cost_usd, "cost_usd")
        if self.reward is not None:
            exponent = self.reward.as_tuple().exponent
            if (not self.reward.is_finite() or not 0 <= self.reward <= 1
                    or (isinstance(exponent, int) and exponent < -USD_MAX_SCALE)):
                raise ValueError("reward must be an exact value in [0, 1] with at most 18 fractional digits")
        return self
