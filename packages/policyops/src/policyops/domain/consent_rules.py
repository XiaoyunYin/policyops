"""Deterministic customer-reply classification and consent recording.

Only an explicit affirmation from a small fixed set counts as consent, and only
when it is a customer message (simulated or operator-entered) that follows the
presentation of the exact proposal version still in force, in chronological order
(proposal <= presentation <= customer message <= now). Evidence dated in the
future is never consent, and a consent record is current only from its
confirmation time until its expiry. Anything hedged,
conditional, combined with another request or otherwise unclear asks again; no
model judges a reply. Staff notes, agent messages and approvals never count.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import re
from uuid import UUID

from policyops_contracts.consent import (
    CaseMessage,
    CustomerConsent,
    ProposalPresentationRecord,
    SimulatorConfirmationEvent,
)
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.timing import expiry_after


RIGHT_SINGLE_QUOTE = chr(0x2019)  # typographic apostrophe, normalized like "'"


class Reply(StrEnum):
    AFFIRM = "affirm"
    DECLINE = "decline"
    UNCLEAR = "unclear"


# Exact normalized replies; deliberately small. "cancel"-like words are excluded because they are ambiguous next
# to a cancellation proposal, and single letters are excluded as too easy to type by accident.
AFFIRMATIONS = frozenset({
    "yes", "yes please", "yes proceed", "yes please proceed", "yes go ahead", "yes i confirm", "yes confirmed",
    "i confirm", "confirmed", "yes do it",
})
DECLINES = frozenset({"no", "no thanks", "no thank you", "do not proceed", "dont proceed"})


def normalize(text: str) -> str:
    folded = text.casefold().replace(RIGHT_SINGLE_QUOTE, "'").replace("'", "")
    folded = re.sub(r"[,.!]+", " ", folded)
    return re.sub(r"\s+", " ", folded).strip()


def classify_reply(text: str) -> Reply:
    normalized = normalize(text)
    if normalized in AFFIRMATIONS:
        return Reply.AFFIRM
    if normalized in DECLINES:
        return Reply.DECLINE
    return Reply.UNCLEAR


@dataclass(frozen=True)
class Consented:
    consent: CustomerConsent


@dataclass(frozen=True)
class AskAgain:
    reason: str  # "ambiguous_reply" | "declined" | "stale_presentation" | "expired"


@dataclass(frozen=True)
class NotConsent:
    reason: str


ConsentOutcome = Consented | AskAgain | NotConsent


def _presented(proposal: ActionProposal, presentation: ProposalPresentationRecord) -> bool:
    return (presentation.scope == proposal.scope and presentation.proposal_id == proposal.proposal_id
            and presentation.proposal_version == proposal.proposal_version
            and presentation.action_digest == proposal.action_digest
            and presentation.presentation_sha256 == proposal.presentation.text_sha256)


def _common_checks(proposal: ActionProposal, presentation: ProposalPresentationRecord, message: CaseMessage,
                   now: datetime) -> ConsentOutcome | None:
    if not _presented(proposal, presentation):
        return AskAgain("stale_presentation")
    if (message.scope.workspace_id, message.scope.case_id) != (proposal.scope.workspace_id, proposal.scope.case_id):
        return NotConsent("message belongs to another case")
    if message.source not in ("simulated_customer", "operator_entered_customer"):
        return NotConsent(f"{message.source} messages cannot give customer consent")
    if presentation.presented_at < proposal.created_at:
        return NotConsent("presentation is dated before the proposal existed")
    if presentation.presented_at > now or message.created_at > now:
        return NotConsent("evidence is dated after the current time")
    if message.sequence <= presentation.message_sequence or message.created_at < presentation.presented_at:
        return AskAgain("stale_presentation")
    if not (proposal.created_at <= now < proposal.expires_at):
        return AskAgain("expired")
    return None


def _consent(consent_id: UUID, proposal: ActionProposal, presentation: ProposalPresentationRecord,
             message: CaseMessage, basis: str, now: datetime) -> Consented:
    return Consented(CustomerConsent.model_validate({
        "consent_id": consent_id, "scope": proposal.scope.model_dump(), "proposal_id": proposal.proposal_id,
        "proposal_version": proposal.proposal_version, "action_digest": proposal.action_digest,
        "presentation_sha256": proposal.presentation.text_sha256,
        "presented_message_sequence": presentation.message_sequence, "customer_message_id": message.message_id,
        "customer_message_sequence": message.sequence, "customer_message_sha256": message.text_sha256,
        "message_source": message.source, "entered_by": message.entered_by, "basis": basis,
        "confirmed_at": now, "expires_at": min(proposal.expires_at, expiry_after(now)),
    }))


def record_reply(*, consent_id: UUID, proposal: ActionProposal, presentation: ProposalPresentationRecord,
                 message: CaseMessage, now: datetime) -> ConsentOutcome:
    """Turn one customer reply to a presented proposal into consent, a clarification or nothing."""
    failure = _common_checks(proposal, presentation, message, now)
    if failure is not None:
        return failure
    reply = classify_reply(message.text)
    if reply is Reply.DECLINE:
        return AskAgain("declined")
    if reply is Reply.UNCLEAR:
        return AskAgain("ambiguous_reply")
    return _consent(consent_id, proposal, presentation, message, "explicit_affirmation", now)


def record_simulator_event(*, consent_id: UUID, proposal: ActionProposal, presentation: ProposalPresentationRecord,
                           message: CaseMessage, event: SimulatorConfirmationEvent, now: datetime) -> ConsentOutcome:
    """Consent from the simulated customer's constrained confirmation event for this exact proposal."""
    failure = _common_checks(proposal, presentation, message, now)
    if failure is not None:
        return failure
    if message.source != "simulated_customer":
        return NotConsent("confirmation events come only from the simulated customer")
    if (event.proposal_id, event.proposal_version, event.action_digest) != (
            proposal.proposal_id, proposal.proposal_version, proposal.action_digest):
        return AskAgain("stale_presentation")
    if event.decision == "decline":
        return AskAgain("declined")
    return _consent(consent_id, proposal, presentation, message, "simulator_confirmation_event", now)


def consent_is_current(consent: CustomerConsent, proposal: ActionProposal, now: datetime) -> bool:
    return (consent.scope == proposal.scope and consent.proposal_id == proposal.proposal_id
            and consent.proposal_version == proposal.proposal_version
            and consent.action_digest == proposal.action_digest
            and consent.presentation_sha256 == proposal.presentation.text_sha256
            and proposal.created_at <= consent.confirmed_at <= now < consent.expires_at <= proposal.expires_at)
