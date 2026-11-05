"""Versioned run event envelope with bounded, typed payloads.

Payloads have no free-form text fields: they carry identifiers, digests,
enumerated codes and timestamps, never tool arguments, prompts or customer text.
That keeps what the schema can express narrow; it does not by itself prove the
producer is honest, so emitters remain responsible for provenance, and viewers
still need authorization checks. `event_version` changes when a payload's
meaning changes; consumers reject versions they do not know.
"""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.errors import ErrorCode
from policyops_contracts.retail import TOOL_KINDS, ToolKind, ToolName
from policyops_contracts.scalars import PositiveVersion, RunScope, Sequence, Sha256Hex, Slug, UtcDatetime


RunState = Literal["queued", "running", "waiting_input", "waiting_approval", "reconciling",
                   "succeeded", "failed", "cancelled", "budget_exceeded"]


class RunStateChanged(WireModel):
    type: Literal["run.state_changed"] = "run.state_changed"
    previous: RunState | None
    current: RunState


class MessagePosted(WireModel):
    type: Literal["case.message_posted"] = "case.message_posted"
    message_id: UUID
    message_sequence: Sequence
    source: Literal["seeded", "simulated_customer", "operator_entered_customer", "staff_note", "agent"]


class ToolCallRequested(WireModel):
    type: Literal["tool.requested"] = "tool.requested"
    tool: ToolName
    kind: ToolKind
    call_sha256: Sha256Hex

    @model_validator(mode="after")
    def _kind_matches_tool(self) -> Self:
        if self.kind != TOOL_KINDS[self.tool]:
            raise ValueError(f"{self.tool.value} is a {TOOL_KINDS[self.tool].value} tool")
        return self


class ToolCallFinished(WireModel):
    type: Literal["tool.finished"] = "tool.finished"
    tool: ToolName
    outcome: Literal["ok", "denied", "escalated", "error", "unknown"]
    rule_id: Slug | None = None


class ProposalPresented(WireModel):
    type: Literal["proposal.presented"] = "proposal.presented"
    proposal_id: UUID
    proposal_version: PositiveVersion
    action_digest: Sha256Hex
    expires_at: UtcDatetime


class ConsentRecorded(WireModel):
    type: Literal["consent.recorded"] = "consent.recorded"
    consent_id: UUID
    proposal_id: UUID
    action_digest: Sha256Hex


class ClarificationRequested(WireModel):
    type: Literal["consent.clarification_requested"] = "consent.clarification_requested"
    proposal_id: UUID
    reason: Literal["ambiguous_reply", "declined", "stale_presentation", "expired"]


class ApprovalDecided(WireModel):
    type: Literal["approval.decided"] = "approval.decided"
    approval_id: UUID
    proposal_id: UUID
    decision: Literal["approve", "reject"]


class EscalationRequested(WireModel):
    type: Literal["escalation.requested"] = "escalation.requested"
    rule_id: Slug


class ErrorRaised(WireModel):
    """Replayable error marker: code and identifiers only (the free-form detail stays in the response)."""

    type: Literal["error.raised"] = "error.raised"
    code: ErrorCode
    rule_id: Slug | None = None
    correlation_id: UUID
    retryable: bool


EventPayload = Annotated[
    RunStateChanged | MessagePosted | ToolCallRequested | ToolCallFinished | ProposalPresented | ConsentRecorded
    | ClarificationRequested | ApprovalDecided | EscalationRequested | ErrorRaised,
    Field(discriminator="type"),
]


class EventEnvelope(WireModel):
    schema_version: Literal["policyops.run-event/v1"] = "policyops.run-event/v1"
    event_id: UUID
    scope: RunScope
    sequence: Sequence
    event_version: Literal[1] = 1
    occurred_at: UtcDatetime
    payload: EventPayload

    @field_validator("event_version", mode="before")
    @classmethod
    def _integer_version(cls, value: object) -> object:
        # Literal matching would accept true and 1.0 for 1 (measured even in strict mode): only an integer is a
        # version. This enforces the intended contract; valid integer 1 is unchanged on the wire.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("event_version must be an integer")
        return value
