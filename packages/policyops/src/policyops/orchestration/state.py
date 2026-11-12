"""Versioned investigation checkpoint state. Slice B adds the node-specific payloads.

The dispatcher deliberately has no implicit default or historical upgrader. A future
version needs an explicit, tested migration before it can be read by a worker.
"""

from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field

from policyops_contracts.base import WireModel
from policyops_contracts.scalars import PositiveVersion, Sha256Hex


class CheckpointStateVersionError(ValueError):
    """The saved application state cannot be interpreted by this worker."""


class InvestigationAction(WireModel):
    """A selected next node, without provider continuation or execution authority."""

    kind: Literal["retrieve", "read", "propose", "finalize"]


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
    terminal: Terminal | None = None
    cleanup_unconfirmed: bool = False


def state_from_json(value: object) -> InvestigationState:
    """Dispatch only an explicit integer version. Intake bounding lives in checkpoint_json."""
    from policyops.persistence.checkpoint_json import json_bytes

    raw = json_bytes(value, limit=262144)
    if type(value) is not dict or type(value.get("state_version")) is not int or value["state_version"] != 1:
        raise CheckpointStateVersionError("unsupported investigation state version")
    return InvestigationState.model_validate_json(raw)
