"""Case messages, proposal presentations, customer consent and staff approval.

Message provenance is immutable and explicit: simulated-customer turns come
from the opt-in simulator (no entering principal); operator-entered customer
turns and staff notes name the principal who typed them. Customer consent cites
one customer message that follows the presentation of the exact proposal
version and is classified as an explicit affirmation; staff approval is a
separate record by a reviewer, who may not be the operator who entered that
consent message. Each is valid for at most 15 minutes and never past the
proposal's expiry (cross-record checks live in policyops.domain).
"""

from typing import Literal, Self
from uuid import UUID

from pydantic import model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.digest import text_sha256
from policyops_contracts.scalars import (
    CaseScope,
    MessageText,
    PositiveVersion,
    RunScope,
    SafeDetail,
    Sequence,
    Sha256Hex,
    UtcDatetime,
)
from policyops_contracts.timing import within_ttl


MessageSource = Literal["seeded", "simulated_customer", "operator_entered_customer", "staff_note", "agent"]
CustomerSource = Literal["simulated_customer", "operator_entered_customer"]
ENTERED_BY_PRINCIPAL = frozenset({"operator_entered_customer", "staff_note"})


class CaseMessage(WireModel):
    schema_version: Literal["policyops.case-message/v1"] = "policyops.case-message/v1"
    message_id: UUID
    scope: CaseScope
    sequence: Sequence
    source: MessageSource
    entered_by: UUID | None
    text: MessageText
    text_sha256: Sha256Hex
    created_at: UtcDatetime

    @model_validator(mode="after")
    def _provenance(self) -> Self:
        if (self.source in ENTERED_BY_PRINCIPAL) != (self.entered_by is not None):
            raise ValueError("operator-entered customer turns and staff notes, and only they, name their author")
        if self.text_sha256 != text_sha256(self.text):
            raise ValueError("message digest mismatch")
        return self


class ProposalPresentationRecord(WireModel):
    """The agent message (by sequence) that displayed one proposal version's presentation text."""

    scope: RunScope
    proposal_id: UUID
    proposal_version: PositiveVersion
    action_digest: Sha256Hex
    presentation_sha256: Sha256Hex
    message_id: UUID
    message_sequence: Sequence
    presented_at: UtcDatetime


class CustomerConsent(WireModel):
    schema_version: Literal["policyops.customer-consent/v1"] = "policyops.customer-consent/v1"
    consent_id: UUID
    scope: RunScope
    proposal_id: UUID
    proposal_version: PositiveVersion
    action_digest: Sha256Hex
    presentation_sha256: Sha256Hex
    presented_message_sequence: Sequence
    customer_message_id: UUID
    customer_message_sequence: Sequence
    customer_message_sha256: Sha256Hex
    message_source: CustomerSource
    entered_by: UUID | None
    basis: Literal["explicit_affirmation", "simulator_confirmation_event"]
    confirmed_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def _bounded(self) -> Self:
        if self.customer_message_sequence <= self.presented_message_sequence:
            raise ValueError("consent must come from a customer message after the presentation")
        if (self.message_source == "operator_entered_customer") != (self.entered_by is not None):
            raise ValueError("operator-entered consent, and only it, names the entering principal")
        if self.basis == "simulator_confirmation_event" and self.message_source != "simulated_customer":
            raise ValueError("simulator confirmation events come only from the simulated customer")
        if not within_ttl(self.confirmed_at, self.expires_at):
            raise ValueError("consent expiry must be within 15 minutes of confirmation")
        return self


class SimulatorConfirmationEvent(WireModel):
    """Constrained decision a simulated customer may emit about one displayed proposal."""

    proposal_id: UUID
    proposal_version: PositiveVersion
    action_digest: Sha256Hex
    decision: Literal["confirm", "decline"]


class ApprovalDecision(WireModel):
    schema_version: Literal["policyops.approval-decision/v1"] = "policyops.approval-decision/v1"
    approval_id: UUID
    scope: RunScope
    proposal_id: UUID
    proposal_version: PositiveVersion
    action_digest: Sha256Hex
    consent_id: UUID
    principal_id: UUID
    role: Literal["reviewer"]
    decision: Literal["approve", "reject"]
    reason: SafeDetail
    decided_at: UtcDatetime
    expires_at: UtcDatetime

    @model_validator(mode="after")
    def _bounded(self) -> Self:
        if not within_ttl(self.decided_at, self.expires_at):
            raise ValueError("approval expiry must be within 15 minutes of the decision")
        return self
