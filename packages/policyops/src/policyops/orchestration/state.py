"""Versioned, bounded investigation checkpoint state and node payloads.

The dispatcher deliberately has no implicit default or historical upgrader. A future
version needs an explicit, tested migration before it can be read by a worker.
"""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from policyops_contracts.agent import AgentStep
from policyops_contracts.base import WireModel
from policyops_contracts.conversation import AgentToolCall, Entry, PendingToolOutcome
from policyops_contracts.grounding import GroundedAnswer
from policyops_contracts.proposal import EvidenceRef
from policyops_contracts.scalars import PositiveVersion, Sha256Hex


class CheckpointStateVersionError(ValueError):
    """The saved application state cannot be interpreted by this worker."""


class InvestigationAction(WireModel):
    """A selected next node, without provider continuation or execution authority."""

    kind: Literal["retrieve", "read", "propose", "finalize"]
    call: AgentToolCall | None = None
    step: AgentStep | None = None
    query: Annotated[str, Field(min_length=1, max_length=8000)] | None = None
    answer: GroundedAnswer | None = None


class AwaitingApproval(WireModel):
    kind: Literal["awaiting_approval"] = "awaiting_approval"
    proposal_id: UUID
    proposal_version: PositiveVersion


class InvestigationCompleted(WireModel):
    kind: Literal["answered", "abstained", "handoff"]
    message_id: UUID


class InvestigationFailed(WireModel):
    kind: Literal["loop_ceiling", "tool_error", "provider_error", "provider_cancelled", "budget_exceeded",
                  "deadline", "checkpoint_incompatible", "provider_result_unavailable"]


Terminal = Annotated[AwaitingApproval | InvestigationCompleted | InvestigationFailed, Field(discriminator="kind")]


class InvestigationState(WireModel):
    state_version: Literal[1]
    workspace_id: UUID
    case_id: UUID
    run_id: UUID
    graph_sha256: Sha256Hex
    prompt_sha256: Sha256Hex
    config_sha256: Sha256Hex
    input_message_ids: Annotated[tuple[UUID, ...], Field(max_length=256)] = ()
    current_node: Literal["investigate", "retrieve", "read", "propose", "finalize"] = "investigate"
    next_action: InvestigationAction | None = None
    step_count: Annotated[int, Field(ge=0, le=64)] = 0
    max_steps: Annotated[int, Field(ge=1, le=64)] = 32
    model_calls: Annotated[int, Field(ge=0, le=64)] = 0
    invalid_count: Annotated[int, Field(ge=0, le=4)] = 0
    tool_steps: Annotated[int, Field(ge=0, le=32)] = 0
    retrieval_index: Annotated[int, Field(ge=0, le=16)] = 0
    retrieved_steps: Annotated[tuple[Annotated[int, Field(ge=0, le=15)], ...], Field(max_length=16)] = ()
    recorded_evidence: Annotated[tuple[EvidenceRef, ...], Field(max_length=32)] = ()
    transcript: Annotated[tuple[Entry, ...], Field(max_length=256)] = ()
    previous_step: AgentStep | None = None
    pending_tool: PendingToolOutcome | None = None
    policy_sha256: Sha256Hex | None = None
    retrieval_sha256: Sha256Hex | None = None
    actor_sha256: Sha256Hex | None = None
    final_text: Annotated[str, Field(min_length=1, max_length=4000)] | None = None
    terminal: Terminal | None = None
    cleanup_unconfirmed: bool = False

    @model_validator(mode="after")
    def distinct_identities(self) -> Self:
        if (len(set(self.retrieved_steps)) != len(self.retrieved_steps)
                or len(set(self.input_message_ids)) != len(self.input_message_ids)
                or len({ref.evidence_id for ref in self.recorded_evidence}) != len(self.recorded_evidence)):
            raise ValueError("investigation identities must be distinct")
        return self


def state_from_json(value: object) -> InvestigationState:
    """Dispatch only an explicit integer version. Intake bounding lives in checkpoint_json."""
    from policyops.persistence.checkpoint_json import json_bytes

    raw = json_bytes(value, limit=262144)
    if type(value) is not dict or type(value.get("state_version")) is not int or value["state_version"] != 1:
        raise CheckpointStateVersionError("unsupported investigation state version")
    return InvestigationState.model_validate_json(raw)
