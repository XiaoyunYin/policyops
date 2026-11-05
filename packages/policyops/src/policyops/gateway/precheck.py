"""The execution precheck (T17): the deterministic gate that T19 calls immediately before a dispatch.

`precheck` takes **references only**, the proposal ID and version and the consent and approval IDs. Every authority
record is loaded through the scope-bound `DecisionStore`, which reads persisted records. No model-provided
snapshot, role set, consent or approval is accepted. Each loaded record is re-validated from its serialized form,
so a constructed object that skipped validation, or a proposal whose digest does not match its contents, is
refused.

The orchestration does I/O: it reads the persisted records, the current facts (`facts.collect`) and the approver's
current membership. The evaluation on the collected facts is pure. In order, it requires:
1. a decision store. None exists before T18, so the default refuses (`approval_required`); there is no bypass flag;
2. a proposal for this run's scope, bound customer and pinned policy;
3. a consent and an approval, bound to it (`ready_to_execute`), with a coherent chronology at the current time;
4. a durable lookup authentication of the bound customer in this run;
5. re-evaluation on freshly collected coherent facts. A denial or escalation is returned as itself, so approval
   never overrides an invalid policy. An allowed result with a different effect, resource-version set or rule set
   is `stale_version`: the proposal needs a new version and a new decision;
6. after those reads, so that a change during them counts:
   - the approver's **current** reviewer role;
   - every evidence reference still current (`EvidencePort`). A proposal with evidence is refused without a port,
     before any read;
7. the time checks again, last.

It returns the exact `MutationRequest` (the sealed call, the effect, the resource versions, and the proposal digest
as `intent_sha256`) and `authorization_not_after`, the earliest of the approval, consent and proposal expiries. It
assigns no operation ID and dispatches nothing. **It is not a guarantee against a concurrent write after it
returns.** The service's expected-version check under its case lock, and the client's expiry cap, stay
authoritative at commit (T16), and T19 repeats expiry and fencing at execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from policyops.domain.approval_rules import ready_to_execute
from policyops.domain.consent_rules import consent_is_current
from policyops.domain.retail_rules import Allowed, Denied, Escalated, evaluate_write
from policyops.domain.roles import Action, Role, is_allowed
from policyops.domain.session import CustomerSession
from policyops.gateway.facts import FactsRefused, collect
from policyops.gateway.ports import (
    DecisionStore,
    EvidencePort,
    GatewayScope,
    HistoryPort,
    IncompleteHistory,
    MembershipPort,
    RetailPort,
    SessionStore,
    check_retail_binding,
)
from policyops_contracts.clock import Clock
from policyops_contracts.consent import ApprovalDecision, CustomerConsent
from policyops_contracts.errors import ErrorCode
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail_service import MutationRequest


@dataclass(frozen=True)
class AuthorityRefs:
    proposal_id: UUID
    proposal_version: int
    consent_id: UUID
    approval_id: UUID


@dataclass(frozen=True)
class Cleared:
    request: MutationRequest
    authorization_not_after: datetime
    proposal: ActionProposal
    case_version: int


@dataclass(frozen=True)
class PrecheckRefused:
    code: ErrorCode
    detail: str
    rule_id: str | None = None
    retryable: bool = False


def _revalidated[Model: BaseModel](record: object, model: type[Model]) -> Model | None:
    if type(record) is not model:
        return None
    try:
        return model.model_validate_json(record.model_dump_json(warnings=False))
    except Exception:  # any record that cannot be re-validated from its serialized form is no authority
        return None


def _authority(proposal: ActionProposal, consent: CustomerConsent, approval: ApprovalDecision,
               now: datetime) -> PrecheckRefused | None:
    if ready_to_execute(proposal, consent, approval, now):
        return None
    if approval.decision != "approve":
        return PrecheckRefused(ErrorCode.APPROVAL_REQUIRED, "approval_not_granted")
    if consent.entered_by is not None and consent.entered_by == approval.principal_id:
        return PrecheckRefused(ErrorCode.SEPARATION_OF_DUTIES, "approver_entered_consent")
    if not consent_is_current(consent, proposal, now):
        if now >= consent.expires_at or now >= proposal.expires_at:
            return PrecheckRefused(ErrorCode.EXPIRED, "consent_expired")
        return PrecheckRefused(ErrorCode.CONSENT_REQUIRED, "consent_not_current")
    if now >= approval.expires_at:
        return PrecheckRefused(ErrorCode.EXPIRED, "approval_expired")
    return PrecheckRefused(ErrorCode.APPROVAL_REQUIRED, "approval_not_bound")


def precheck(scope: GatewayScope, refs: AuthorityRefs, *, retail: RetailPort, sessions: SessionStore,
             membership: MembershipPort, clock: Clock, decisions: DecisionStore | None = None,
             history: HistoryPort | None = None, evidence: EvidencePort | None = None) -> Cleared | PrecheckRefused:
    check_retail_binding(scope, retail)  # before any request
    if decisions is None:
        return PrecheckRefused(ErrorCode.APPROVAL_REQUIRED, "no_decision_store")
    run = scope.run
    proposal = _revalidated(decisions.proposal(run, refs.proposal_id, refs.proposal_version), ActionProposal)
    if proposal is None or (proposal.proposal_id, proposal.proposal_version) != (refs.proposal_id,
                                                                                 refs.proposal_version):
        return PrecheckRefused(ErrorCode.APPROVAL_REQUIRED, "proposal_not_found")
    if proposal.scope != run or proposal.customer_user_id != scope.customer_user_id:
        return PrecheckRefused(ErrorCode.CUSTOMER_MISMATCH, "proposal_out_of_scope", rule_id="scope.single_customer")
    if proposal.policy != RETAIL_POLICY:
        return PrecheckRefused(ErrorCode.STALE_VERSION, "policy_changed")
    consent = _revalidated(decisions.consent(run, refs.consent_id), CustomerConsent)
    if consent is None or consent.consent_id != refs.consent_id:
        return PrecheckRefused(ErrorCode.CONSENT_REQUIRED, "consent_not_found", rule_id="consent.explicit_yes")
    approval = _revalidated(decisions.approval(run, refs.approval_id), ApprovalDecision)
    if approval is None or approval.approval_id != refs.approval_id:
        return PrecheckRefused(ErrorCode.APPROVAL_REQUIRED, "approval_not_found")
    refused = _authority(proposal, consent, approval, clock.now())
    if refused is not None:
        return refused
    authentication = sessions.load(run)
    if authentication is None:
        return PrecheckRefused(ErrorCode.CUSTOMER_NOT_AUTHENTICATED, "customer_not_authenticated",
                               rule_id="auth.lookup_required")
    try:
        session = CustomerSession(binding=scope.binding, run=run, authentication=authentication)
    except ValueError:
        return PrecheckRefused(ErrorCode.CUSTOMER_MISMATCH, "stored_authentication_mismatch",
                               rule_id="scope.single_customer")
    if proposal.evidence and evidence is None:  # nothing could confirm the evidence: refuse before any read
        return PrecheckRefused(ErrorCode.STALE_VERSION, "evidence_not_current")
    collected = collect(retail, scope, proposal.action, history if history is not None else IncompleteHistory())
    if isinstance(collected, FactsRefused):
        return PrecheckRefused(collected.code, collected.detail, rule_id=collected.rule_id,
                               retryable=collected.retryable)
    outcome = evaluate_write(proposal.action, session, collected.facts)
    if isinstance(outcome, Denied):
        return PrecheckRefused(outcome.code, outcome.detail, rule_id=outcome.rule_id)
    if isinstance(outcome, Escalated):
        return PrecheckRefused(ErrorCode.POLICY_UNSUPPORTED, outcome.detail, rule_id=outcome.rule_id)
    if not isinstance(outcome, Allowed):  # pragma: no cover - the outcome union is exhaustive
        raise TypeError("unexpected evaluation outcome")
    if (outcome.effect, outcome.resource_versions, outcome.rule_ids) != (
            proposal.effect, proposal.resource_versions, proposal.rule_ids):
        return PrecheckRefused(ErrorCode.STALE_VERSION, "facts_changed_since_proposal")
    roles = membership.roles(run.workspace_id, approval.principal_id)
    if Role.REVIEWER not in roles or not is_allowed(roles, Action.DECIDE_PROPOSAL):
        return PrecheckRefused(ErrorCode.FORBIDDEN, "approver_not_current_reviewer")
    # Evidence is checked after the reads (it may change while they run), then the time once more.
    if evidence is not None and not all(evidence.is_current(run.workspace_id, reference)
                                        for reference in proposal.evidence):
        return PrecheckRefused(ErrorCode.STALE_VERSION, "evidence_not_current")
    refused = _authority(proposal, consent, approval, clock.now())  # time passed while reading
    if refused is not None:
        return refused
    request = MutationRequest(call=proposal.action, expected_effect=proposal.effect,
                              expected_versions=proposal.resource_versions, intent_sha256=proposal.action_digest)
    return Cleared(request=request, authorization_not_after=min(approval.expires_at, consent.expires_at,
                                                                proposal.expires_at),
                   proposal=proposal, case_version=collected.case_version)
