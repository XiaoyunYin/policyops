"""T18 decision ordering on already loaded records (`services.decisions.evaluate`, pure).

Each refusal is checked at its position in the order: authorization first (before any replay), then the digest
binding, then the existing decision (an identical request by the same reviewer replays the original; anything else
conflicts), and only for a new decision the run, status, policy, expiry, consent and `approval_rules.decide` checks.
The database transaction around it (locks, clock after locks, insert, event, audit, commit) is covered by the
PostgreSQL integration tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from policyops.domain.consent_rules import Consented, record_reply
from policyops.domain.examples import World
from policyops.domain.retail_rules import propose
from policyops.domain.roles import Role
from policyops.services import decisions
from policyops.services.decisions import NewDecision, Refusal, Replay
from policyops.services.proposal_views import DecisionRequest
from policyops_contracts.consent import ApprovalDecision, CaseMessage, CustomerConsent, ProposalPresentationRecord
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.policy import PolicyRef
from policyops_contracts.proposal import ActionProposal, ProposalBody
from policyops_contracts.retail import CancelPendingOrder


REVIEWER = frozenset({Role.REVIEWER})


def sealed(world: World) -> ActionProposal:
    result = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(),
                     call=CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                     facts=world.facts(), evidence=(), rationale="Customer asked to cancel.", now=world.now)
    assert isinstance(result, ActionProposal)
    return result


def consent_of(world: World, proposal: ActionProposal, *, entered_by: UUID | None = None) -> CustomerConsent:
    source: Any = "operator_entered_customer" if entered_by is not None else "simulated_customer"
    shown = ProposalPresentationRecord(
        scope=world.run_scope, proposal_id=proposal.proposal_id, proposal_version=proposal.proposal_version,
        action_digest=proposal.action_digest, presentation_sha256=proposal.presentation.text_sha256,
        message_id=UUID(int=700), message_sequence=10, presented_at=world.now + timedelta(seconds=5))
    reply = CaseMessage(message_id=UUID(int=811), scope=world.case_scope, sequence=11, source=source,
                        entered_by=entered_by, text="yes", text_sha256=text_sha256("yes"),
                        created_at=world.now + timedelta(seconds=30))
    outcome = record_reply(consent_id=UUID(int=900), proposal=proposal, presentation=shown, message=reply,
                           now=world.now + timedelta(seconds=40))
    assert isinstance(outcome, Consented)
    return outcome.consent


def ask(proposal: ActionProposal, **overrides: Any) -> DecisionRequest:
    return DecisionRequest.model_validate({"proposal_version": proposal.proposal_version,
                                           "action_digest": proposal.action_digest, "decision": "approve",
                                           "reason": "Order and policy checked.", **overrides})


def run(world: World, *, proposal: ActionProposal | None = None, roles: frozenset[Role] = REVIEWER,
        principal: UUID | None = None, terminal: bool = False, status: str = "presented",
        existing: ApprovalDecision | None = None, consent: CustomerConsent | str | None = "default",
        request: DecisionRequest | None = None, now: datetime | None = None) -> Replay | NewDecision | Refusal:
    current = proposal or sealed(world)
    granted = consent_of(world, current) if consent == "default" else consent
    assert not isinstance(granted, str)
    return decisions.evaluate(principal_id=principal or world.reviewer, roles=roles, run_terminal=terminal,
                              row_status=status, proposal=current, existing=existing, consent=granted,
                              request=request or ask(current), approval_id=UUID(int=950),
                              now=now or world.now + timedelta(minutes=1))


def decided(world: World) -> ApprovalDecision:
    outcome = run(world)
    assert isinstance(outcome, NewDecision)
    return outcome.decision


def refusal(outcome: object) -> tuple[int, ErrorCode, str]:
    assert isinstance(outcome, Refusal), outcome
    return outcome.status, outcome.code, outcome.rule_id


def test_a_current_reviewer_with_current_consent_decides_with_the_bound_expiry(world: World) -> None:
    proposal = sealed(world)
    consent = consent_of(world, proposal)
    decision = decided(world)
    assert (decision.proposal_id, decision.proposal_version, decision.action_digest, decision.consent_id,
            decision.principal_id, decision.decision) == (proposal.proposal_id, 1, proposal.action_digest,
                                                          consent.consent_id, world.reviewer, "approve")
    assert decision.expires_at == min(proposal.expires_at, consent.expires_at,
                                      world.now + timedelta(minutes=1) + timedelta(minutes=15))


@pytest.mark.parametrize(("roles", "rule"), [
    (frozenset(), "auth.membership"),
    (frozenset({Role.ANALYST}), "auth.role"),
    (frozenset({Role.ADMIN}), "auth.role"),  # admin alone is not a reviewer
    (frozenset({Role.AUDITOR}), "auth.role"),
])
def test_only_a_current_reviewer_can_decide(world: World, roles: frozenset[Role], rule: str) -> None:
    assert refusal(run(world, roles=roles)) == (403, ErrorCode.FORBIDDEN, rule)


def test_authorization_precedes_any_replay(world: World) -> None:
    existing = decided(world)
    assert isinstance(run(world, existing=existing), Replay)
    assert refusal(run(world, existing=existing, roles=frozenset())) == (403, ErrorCode.FORBIDDEN, "auth.membership")


def test_the_digest_binding_is_checked_before_replay(world: World) -> None:
    proposal = sealed(world)
    existing = decided(world)
    forged = ask(proposal, action_digest="0" * 64)
    assert refusal(run(world, existing=existing, request=forged)) == (409, ErrorCode.CONFLICT,
                                                                      "api.proposal_digest_mismatch")
    assert refusal(run(world, request=forged)) == (409, ErrorCode.CONFLICT, "api.proposal_digest_mismatch")


def test_only_an_identical_request_by_the_same_reviewer_replays(world: World) -> None:
    proposal = sealed(world)
    existing = decided(world)
    replay = run(world, existing=existing)
    assert isinstance(replay, Replay) and replay.decision == existing
    already = (409, ErrorCode.CONFLICT, "api.proposal_already_decided")
    assert refusal(run(world, existing=existing, principal=UUID(int=103))) == already
    assert refusal(run(world, existing=existing, request=ask(proposal, reason="Different."))) == already
    assert refusal(run(world, existing=existing, request=ask(proposal, decision="reject"))) == already


def test_ended_superseded_or_expired_versions_still_replay_but_refuse_new_decisions(world: World) -> None:
    proposal = sealed(world)
    existing = decided(world)
    late = proposal.expires_at + timedelta(minutes=1)
    for case in ({"terminal": True}, {"status": "superseded"}, {"status": "expired"}, {"now": late}):
        assert isinstance(run(world, existing=existing, **case), Replay), case
    assert refusal(run(world, terminal=True)) == (409, ErrorCode.CONFLICT, "api.run_terminal")
    assert refusal(run(world, status="superseded")) == (409, ErrorCode.STALE_VERSION, "api.proposal_superseded")
    assert refusal(run(world, status="expired")) == (409, ErrorCode.EXPIRED, "api.proposal_expired")
    assert refusal(run(world, status="created")) == (409, ErrorCode.CONSENT_REQUIRED, "api.proposal_not_presented")
    assert refusal(run(world, now=proposal.expires_at)) == (409, ErrorCode.EXPIRED, "api.proposal_expired")


def test_a_proposal_under_another_policy_is_refused(world: World) -> None:
    original = sealed(world)
    other = PolicyRef(source_commit="0" * 40, path=original.policy.path, sha256="1" * 64)
    body = ProposalBody.model_validate({**original.model_dump(exclude={"action_digest"}),
                                        "policy": other.model_dump()})
    changed = ActionProposal.seal(body)
    assert refusal(run(world, proposal=changed, consent=consent_of(world, changed))) == (
        409, ErrorCode.STALE_VERSION, "api.policy_changed")


def test_consent_is_required_for_approval_and_rejection(world: World) -> None:
    proposal = sealed(world)
    for kind in ("approve", "reject"):
        assert refusal(run(world, consent=None, request=ask(proposal, decision=kind))) == (
            409, ErrorCode.CONSENT_REQUIRED, "api.consent_required")
    consent = consent_of(world, proposal)
    # A consent recorded by the domain expires with the proposal (its expiry is capped at the proposal's), so that
    # instant is reported as the proposal's expiry, which is checked first.
    assert consent.expires_at == proposal.expires_at
    assert refusal(run(world, now=consent.expires_at)) == (409, ErrorCode.EXPIRED, "api.proposal_expired")
    # A controlled record that expires earlier (still a valid contract) isolates the consent-expiry check.
    shorter = CustomerConsent.model_validate({**consent.model_dump(), "expires_at": world.now + timedelta(minutes=2)})
    assert refusal(run(world, consent=shorter, now=world.now + timedelta(minutes=3))) == (
        409, ErrorCode.EXPIRED, "api.consent_expired")
    rejected = run(world, request=ask(proposal, decision="reject"))
    assert isinstance(rejected, NewDecision) and rejected.decision.decision == "reject"


def test_the_operator_who_entered_the_consent_cannot_decide_it(world: World) -> None:
    proposal = sealed(world)
    typed = consent_of(world, proposal, entered_by=world.reviewer)
    assert refusal(run(world, consent=typed)) == (403, ErrorCode.SEPARATION_OF_DUTIES, "api.separation_of_duties")
    other = run(world, consent=typed, principal=UUID(int=103))
    assert isinstance(other, NewDecision)


def test_the_decision_digest_is_the_canonical_record_digest(world: World) -> None:
    decision = decided(world)
    assert decisions.decision_digest(decision) == decisions.decision_digest(
        ApprovalDecision.model_validate_json(decision.model_dump_json()))
