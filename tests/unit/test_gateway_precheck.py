"""The execution precheck loads trusted records by reference and re-evaluates current facts (T17, offline).

The decision store, membership and complete-history ports here are explicitly injected test fakes. Before T18
there is no production decision store, and the default precheck refuses (tested separately).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from policyops.domain.retail_rules import propose
from policyops.domain.roles import Role
from policyops.domain.session import Authenticated, CustomerSession, apply_lookup
from policyops.gateway.ports import EvidencePort, ScopeMismatch
from policyops.gateway.precheck import Cleared, PrecheckRefused, precheck
from policyops.gateway.steps import parse_result
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.clock import FixedClock
from policyops_contracts.consent import ApprovalDecision, CustomerConsent
from policyops_contracts.errors import ErrorCode
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.proposal import ActionProposal, EvidenceRef, ProposalBody
from policyops_contracts.retail import FindUserIdByEmail, OrderSnapshot
from policyops_contracts.scalars import RunScope
from policyops_testing.gateway_cases import (
    CONSENTED,
    DECIDED,
    PROPOSED,
    REFS,
    SCOPE,
    FakeRetail,
    MemoryDecisions,
    MemorySessions,
    Setup,
    TestOnlyCompleteHistory,
    TripwireRetail,
    W,
    authenticated_sessions,
    authority,
    cancel,
    gateway_for,
    items,
    payment,
    state,
    usd,
)


CHECKED = DECIDED + timedelta(minutes=1)


class Membership:
    def __init__(self, roles: frozenset[Role] = frozenset({Role.REVIEWER}), retail: FakeRetail | None = None) -> None:
        self._roles, self._retail = roles, retail
        self.reads_before: list[int] = []

    def roles(self, workspace_id: UUID, principal_id: UUID) -> frozenset[Role]:
        self.reads_before.append(len(self._retail.calls) if self._retail is not None else -1)
        return self._roles if principal_id == W.reviewer else frozenset()


class Evidence:
    def __init__(self, current: bool) -> None:
        self.current = current

    def is_current(self, workspace_id: UUID, reference: EvidenceRef) -> bool:
        return self.current


class Clocks:
    """Returns the given instants in turn (the last one repeats)."""

    def __init__(self, *instants: datetime) -> None:
        self._instants = list(instants)

    def now(self) -> datetime:
        return self._instants.pop(0) if len(self._instants) > 1 else self._instants[0]


def sealed(raw: Any = None, setup: Setup | None = None, *, evidence: tuple[EvidenceRef, ...] = (),
           session: CustomerSession | None = None) -> ActionProposal:
    gateway, _, _ = gateway_for(setup or Setup())
    step = parse_result(raw if raw is not None else cancel())
    assert isinstance(step, ToolCallStep)
    result = gateway.step(step, previous=None, sequence=2)
    assert result.collected is not None, result.observation
    proposal = propose(proposal_id=REFS.proposal_id, proposal_version=1, session=session or W.session(),
                       call=step.call, facts=result.collected.facts, evidence=evidence,  # type: ignore[arg-type]
                       rationale="The customer asked for this change.", now=PROPOSED)
    assert isinstance(proposal, ActionProposal), proposal
    return proposal


def check(proposal: ActionProposal | Any, consent: Any = None, approval: Any = None, *,
          retail: FakeRetail | None = None, setup: Setup | None = None, membership: Membership | None = None,
          clock: Any = None, sessions: MemorySessions | None = None, evidence: EvidencePort | None = None,
          decisions: Any = "default") -> Cleared | PrecheckRefused:
    setup = setup or Setup()
    if consent is None or approval is None:
        consent, approval = authority(proposal)
    retail = retail or FakeRetail(state(status=setup.status, gift_balance=setup.gift_balance))
    return precheck(SCOPE, REFS, retail=retail, sessions=sessions or authenticated_sessions(),
                    membership=membership or Membership(), clock=clock or FixedClock(CHECKED),
                    decisions=MemoryDecisions(proposal, consent, approval) if decisions == "default" else decisions,
                    history=TestOnlyCompleteHistory(setup.history or ()), evidence=evidence)


def refused(result: Cleared | PrecheckRefused) -> tuple[str, str]:
    assert isinstance(result, PrecheckRefused), result
    return str(result.code), result.detail


# -- clearing --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [cancel(), payment(), items()])
def test_precheck_clears_only_a_bound_current_decision(raw: Any) -> None:
    proposal = sealed(raw)
    consent, approval = authority(proposal)
    retail = FakeRetail(state())
    result = check(proposal, consent, approval, retail=retail)
    assert isinstance(result, Cleared), result
    request = result.request
    assert (request.call, request.expected_effect, request.expected_versions, request.intent_sha256) == (
        proposal.action, proposal.effect, proposal.resource_versions, proposal.action_digest)
    assert result.authorization_not_after == min(approval.expires_at, consent.expires_at, proposal.expires_at)
    assert not hasattr(result, "operation_id") and not hasattr(retail, "mutate")
    assert all(type(call).__name__.startswith("Get") for call in retail.calls)


# -- trusted authority inputs ------------------------------------------------------------------------------------

def test_without_a_decision_store_the_default_refuses_before_contact() -> None:
    result = precheck(SCOPE, REFS, retail=TripwireRetail(state()), sessions=authenticated_sessions(),
                      membership=Membership(), clock=FixedClock(CHECKED))
    assert refused(result) == ("approval_required", "no_decision_store")


def test_a_foreign_client_is_refused_before_any_record_or_contact() -> None:
    decisions = MemoryDecisions(None, None, None)
    with pytest.raises(ScopeMismatch):
        precheck(SCOPE, REFS, retail=TripwireRetail(state(), case_id=UUID(int=92)),
                 sessions=authenticated_sessions(), membership=Membership(), clock=FixedClock(CHECKED),
                 decisions=decisions)
    assert decisions.asked == []


def _forged_proposals(proposal: ActionProposal) -> dict[str, Any]:
    dumped = proposal.model_dump()
    other_effect = proposal.effect.model_copy(update={"reason": "ordered by mistake"})
    return {
        "constructed-changed-effect": ActionProposal.model_construct(**{**dict(proposal), "effect": other_effect}),
        "constructed-changed-presentation": ActionProposal.model_construct(**{
            **dict(proposal), "presentation": proposal.presentation.model_copy(update={"text": "Refund everything"})}),
        "constructed-changed-digest": ActionProposal.model_construct(**{**dict(proposal), "action_digest": "f" * 64}),
        "body-not-proposal": ProposalBody.model_validate({k: v for k, v in dumped.items() if k != "action_digest"}),
        "dict": dumped,
    }


@pytest.mark.parametrize("name", ["constructed-changed-effect", "constructed-changed-presentation",
                                  "constructed-changed-digest", "body-not-proposal", "dict"])
def test_a_forged_or_untyped_proposal_record_is_not_authority(name: str) -> None:
    proposal = sealed()
    consent, approval = authority(proposal)
    assert refused(check(_forged_proposals(proposal)[name], consent, approval)) == ("approval_required",
                                                                                   "proposal_not_found")


def test_a_forged_consent_or_approval_record_is_not_authority() -> None:
    proposal = sealed()
    consent, approval = authority(proposal)
    forged_consent = CustomerConsent.model_construct(**{**dict(consent), "confirmed_at": "yesterday"})
    assert refused(check(proposal, forged_consent, approval)) == ("consent_required", "consent_not_found")
    forged_approval = ApprovalDecision.model_construct(**{**dict(approval), "role": "admin"})
    assert refused(check(proposal, consent, forged_approval)) == ("approval_required", "approval_not_found")


def test_a_proposal_of_another_run_or_policy_is_refused() -> None:
    other_run = RunScope(workspace_id=W.workspace, case_id=W.case, run_id=UUID(int=55))
    lookup = apply_lookup(CustomerSession(binding=W.binding(), run=other_run), FindUserIdByEmail(
        email="example.user@example.invalid"), W.user_id, step_sequence=1, now=W.now - timedelta(minutes=4))
    assert isinstance(lookup, Authenticated)
    foreign = sealed(session=lookup.session)
    assert refused(check(foreign)) == ("customer_mismatch", "proposal_out_of_scope")
    proposal = sealed()
    body = {k: v for k, v in proposal.model_dump().items() if k != "action_digest"}
    other_policy = ActionProposal.seal(ProposalBody.model_validate(
        {**body, "policy": {**RETAIL_POLICY.model_dump(), "sha256": "1" * 64}}))
    consent, approval = authority(other_policy)
    assert refused(check(other_policy, consent, approval)) == ("stale_version", "policy_changed")


def test_consent_and_approval_must_bind_the_exact_proposal_version_and_digest() -> None:
    proposal = sealed()
    other = sealed(cancel("ordered by mistake"))
    consent, approval = authority(other)
    assert refused(check(proposal, consent, approval))[0] in ("consent_required", "approval_required")
    own_consent, _ = authority(proposal)
    assert refused(check(proposal, own_consent, approval)) == ("approval_required", "approval_not_bound")


def test_the_consent_typist_cannot_be_the_approver() -> None:
    proposal = sealed()
    consent, approval = authority(proposal, entered_by=W.reviewer, approver=W.analyst)
    same = approval.model_copy(update={"principal_id": W.reviewer})
    same = ApprovalDecision.model_validate(same.model_dump())
    assert refused(check(proposal, consent, same)) == ("separation_of_duties", "approver_entered_consent")


def test_a_rejection_is_not_approval() -> None:
    proposal = sealed()
    consent, approval = authority(proposal)
    rejected = ApprovalDecision.model_validate({**approval.model_dump(), "decision": "reject"})
    assert refused(check(proposal, consent, rejected)) == ("approval_required", "approval_not_granted")


@pytest.mark.parametrize("roles", [frozenset(), frozenset({Role.ADMIN}), frozenset({Role.ANALYST, Role.AUDITOR})])
def test_an_approver_who_is_no_longer_a_reviewer_is_refused(roles: frozenset[Role]) -> None:
    proposal = sealed()
    assert refused(check(proposal, membership=Membership(roles))) == ("forbidden", "approver_not_current_reviewer")


def test_membership_is_read_after_the_facts_so_a_revocation_during_reads_counts() -> None:
    proposal = sealed()
    retail = FakeRetail(state())
    membership = Membership(retail=retail)
    assert isinstance(check(proposal, retail=retail, membership=membership), Cleared)
    assert membership.reads_before == [2]  # user and order were already read


@pytest.mark.parametrize(("at", "expected"), [
    (W.now + timedelta(minutes=30), ("expired", "consent_expired")),
    (CONSENTED - timedelta(seconds=1), ("consent_required", "consent_not_current")),
    (DECIDED - timedelta(seconds=1), ("approval_required", "approval_not_bound")),
])
def test_expired_or_future_dated_records_are_refused(at: datetime, expected: tuple[str, str]) -> None:
    assert refused(check(sealed(), clock=FixedClock(at))) == expected


def test_expiry_during_the_reads_is_refused_after_collecting() -> None:
    proposal = sealed()
    consent, approval = authority(proposal)
    clock = Clocks(CHECKED, approval.expires_at)
    retail = FakeRetail(state())
    assert refused(check(proposal, consent, approval, clock=clock, retail=retail))[0] == "expired"
    assert len(retail.calls) == 2


def test_a_run_without_a_durable_lookup_is_refused() -> None:
    assert refused(check(sealed(), sessions=MemorySessions())) == ("customer_not_authenticated",
                                                                  "customer_not_authenticated")


def test_evidence_must_still_be_current() -> None:
    reference = EvidenceRef(evidence_id=UUID(int=60), document_version_id=UUID(int=61), content_sha256="a" * 64)
    proposal = sealed(evidence=(reference,))
    assert refused(check(proposal)) == ("stale_version", "evidence_not_current")
    assert refused(check(proposal, evidence=Evidence(False))) == ("stale_version", "evidence_not_current")
    assert isinstance(check(proposal, evidence=Evidence(True)), Cleared)


class EvidenceDuringReads:
    """Current until the retail port has been read, then revoked (or never revoked: the positive control)."""

    def __init__(self, retail: FakeRetail, *, revoke: bool) -> None:
        self.retail, self.revoke = retail, revoke
        self.reads_before: list[int] = []

    def is_current(self, workspace_id: UUID, reference: EvidenceRef) -> bool:
        self.reads_before.append(len(self.retail.calls))
        return not (self.revoke and self.retail.calls)


@pytest.mark.parametrize("revoke", [True, False])
def test_evidence_revoked_while_the_facts_are_read_is_refused(revoke: bool) -> None:
    reference = EvidenceRef(evidence_id=UUID(int=60), document_version_id=UUID(int=61), content_sha256="a" * 64)
    proposal = sealed(evidence=(reference,))
    retail = FakeRetail(state())
    evidence = EvidenceDuringReads(retail, revoke=revoke)
    result = check(proposal, retail=retail, evidence=evidence)
    if revoke:
        assert refused(result) == ("stale_version", "evidence_not_current")
    else:
        assert isinstance(result, Cleared)
    assert evidence.reads_before == [2]  # consulted once, after the user and order reads


# -- approval never overrides current policy ---------------------------------------------------------------------

def test_an_approved_cancel_of_an_order_that_is_no_longer_pending_is_denied() -> None:
    proposal = sealed()
    result = check(proposal, setup=Setup(status="delivered"))
    assert isinstance(result, PrecheckRefused)
    assert (result.code, result.rule_id) == (ErrorCode.POLICY_DENIED, "cancel.pending_only")


def test_an_approved_gift_card_payment_whose_balance_fell_is_denied() -> None:
    proposal = sealed(payment(W.gift))
    result = check(proposal, setup=Setup(gift_balance=100))
    assert isinstance(result, PrecheckRefused)
    assert (result.code, result.rule_id) == (ErrorCode.POLICY_DENIED, "payment.gift_card_covers_total")


def test_changed_resource_versions_make_the_proposal_stale() -> None:
    proposal = sealed()
    changed = state()
    changed.order = OrderSnapshot.model_validate({**changed.order.model_dump(), "version": 8})
    assert refused(check(proposal, retail=FakeRetail(changed))) == ("stale_version",
                                                                   "facts_changed_since_proposal")
    customer = state()
    customer.customer = customer.customer.model_copy(update={"version": 4})
    assert refused(check(proposal, retail=FakeRetail(customer))) == ("stale_version",
                                                                    "facts_changed_since_proposal")


def test_a_changed_effect_under_an_unchanged_version_is_still_stale() -> None:
    proposal = sealed()  # cancel: refunds the single payment of 44.99
    changed = state()
    payment_record = changed.order.payment_history[0].model_copy(update={"amount": usd(100)})
    # The same order version 7: only the comparison of the effect catches it.
    changed.order = changed.order.model_copy(update={"payment_history": (payment_record,)})
    assert changed.order.version == 7
    assert refused(check(proposal, retail=FakeRetail(changed))) == ("stale_version", "facts_changed_since_proposal")


def test_inconsistent_facts_at_precheck_are_retryable_and_never_evaluated() -> None:
    proposal = sealed()
    result = check(proposal, retail=FakeRetail(state(), bump_each_read=True))
    assert isinstance(result, PrecheckRefused)
    assert (result.code, result.detail, result.retryable) == (ErrorCode.UNAVAILABLE, "facts_inconsistent", True)
