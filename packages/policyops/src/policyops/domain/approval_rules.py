"""Staff approval decisions, separate from customer consent.

A decision needs the reviewer role (admin alone is not enough), a current
consent for the same proposal version and digest, and a principal different
from whoever typed an operator-entered consent message. It expires at the
earliest of 15 minutes, the consent expiry and the proposal expiry.

`ready_to_execute` checks the records' mutual consistency and chronology at one
instant (consent confirmed, then decided, both no later than now). It does
not prove that they are persisted or that business state is unchanged; the
gateway repeats membership, version and receipt checks at execution (T17-T19).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from policyops.domain.consent_rules import consent_is_current
from policyops.domain.roles import Role
from policyops_contracts.consent import ApprovalDecision, CustomerConsent
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.timing import expiry_after


@dataclass(frozen=True)
class Decided:
    decision: ApprovalDecision


@dataclass(frozen=True)
class Refused:
    code: str  # ErrorCode value
    reason: str


def decide(*, approval_id: UUID, proposal: ActionProposal, consent: CustomerConsent, principal_id: UUID,
           roles: frozenset[Role], decision: Literal["approve", "reject"], reason: str,
           now: datetime) -> Decided | Refused:
    if Role.REVIEWER not in roles:
        return Refused("forbidden", "only a reviewer can decide proposals")
    if not consent_is_current(consent, proposal, now):
        return Refused("consent_required", "no current customer consent for this proposal version")
    if consent.entered_by is not None and consent.entered_by == principal_id:
        return Refused("separation_of_duties", "the operator who entered the consent message cannot approve it")
    expires_at = min(proposal.expires_at, consent.expires_at, expiry_after(now))
    return Decided(ApprovalDecision.model_validate({
        "approval_id": approval_id, "scope": proposal.scope.model_dump(), "proposal_id": proposal.proposal_id,
        "proposal_version": proposal.proposal_version, "action_digest": proposal.action_digest,
        "consent_id": consent.consent_id, "principal_id": principal_id, "role": "reviewer", "decision": decision,
        "reason": reason, "decided_at": now, "expires_at": expires_at,
    }))


def ready_to_execute(proposal: ActionProposal, consent: CustomerConsent, approval: ApprovalDecision,
                     now: datetime) -> bool:
    return (consent_is_current(consent, proposal, now) and approval.decision == "approve"
            and approval.scope == proposal.scope and approval.proposal_id == proposal.proposal_id
            and approval.proposal_version == proposal.proposal_version
            and approval.action_digest == proposal.action_digest and approval.consent_id == consent.consent_id
            and (consent.entered_by is None or consent.entered_by != approval.principal_id)
            and consent.confirmed_at <= approval.decided_at <= now < approval.expires_at
            and approval.expires_at <= min(proposal.expires_at, consent.expires_at))
