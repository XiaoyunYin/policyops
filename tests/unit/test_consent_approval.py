"""Customer consent (deterministic affirmation) and separate staff approval."""

from datetime import datetime, timedelta
import json
from typing import Any
from uuid import UUID

from pydantic import ValidationError
import pytest

from policyops.domain.approval_rules import Decided, Refused, decide, ready_to_execute
from policyops.domain.consent_rules import (
    AskAgain,
    Consented,
    NotConsent,
    Reply,
    classify_reply,
    consent_is_current,
    record_reply,
    record_simulator_event,
)
from policyops.domain.examples import World
from policyops.domain.retail_rules import propose
from policyops.domain.roles import Role
from policyops_contracts.consent import (
    CaseMessage,
    CustomerConsent,
    ProposalPresentationRecord,
    SimulatorConfirmationEvent,
)
from policyops_contracts.digest import text_sha256
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import CancelPendingOrder


def proposal(world: World, *, version: int = 1, reason: Any = "no longer needed") -> ActionProposal:
    result = propose(proposal_id=UUID(int=500), proposal_version=version, session=world.session(),
                     call=CancelPendingOrder(order_id=world.order_id, reason=reason), facts=world.facts(),
                     evidence=(), rationale="Customer asked to cancel.", now=world.now)
    assert isinstance(result, ActionProposal)
    return result


def presented(world: World, proposal: ActionProposal, *, sequence: int = 10) -> ProposalPresentationRecord:
    return ProposalPresentationRecord(
        scope=world.run_scope, proposal_id=proposal.proposal_id, proposal_version=proposal.proposal_version,
        action_digest=proposal.action_digest, presentation_sha256=proposal.presentation.text_sha256,
        message_id=UUID(int=700), message_sequence=sequence, presented_at=world.now + timedelta(seconds=5))


def message(world: World, text: str, *, sequence: int = 11, source: Any = "simulated_customer",
            entered_by: UUID | None = None, at: datetime | None = None) -> CaseMessage:
    return CaseMessage(message_id=UUID(int=800 + sequence), scope=world.case_scope, sequence=sequence, source=source,
                       entered_by=entered_by, text=text, text_sha256=text_sha256(text),
                       created_at=at or world.now + timedelta(seconds=30))


@pytest.mark.parametrize(("text", "expected"), [
    ("yes", Reply.AFFIRM), ("Yes, please.", Reply.AFFIRM), ("YES!!", Reply.AFFIRM), ("  yes   proceed ", Reply.AFFIRM),
    ("I confirm", Reply.AFFIRM), ("no", Reply.DECLINE), ("Don't proceed.", Reply.DECLINE),
    ("yes but change the address first", Reply.UNCLEAR), ("yes?", Reply.UNCLEAR), ("sure", Reply.UNCLEAR),
    ("ok", Reply.UNCLEAR), ("yeah", Reply.UNCLEAR), ("y", Reply.UNCLEAR), ("cancel", Reply.UNCLEAR),
    ("yes, and also cancel my other order", Reply.UNCLEAR), ("not yes", Reply.UNCLEAR),
])
def test_reply_classification_is_strict(text: str, expected: Reply) -> None:
    assert classify_reply(text) is expected


def test_typographic_apostrophes_normalize_like_ascii() -> None:
    assert classify_reply("Don" + chr(0x2019) + "t proceed") is Reply.DECLINE


def test_explicit_yes_after_presentation_is_consent_bounded_by_expiry(world: World) -> None:
    current = proposal(world)
    outcome = record_reply(consent_id=UUID(int=900), proposal=current, presentation=presented(world, current),
                           message=message(world, "Yes, please."), now=world.now + timedelta(minutes=1))
    assert isinstance(outcome, Consented)
    consent = outcome.consent
    assert consent.action_digest == current.action_digest and consent.basis == "explicit_affirmation"
    assert consent.expires_at == current.expires_at  # earlier than now + 15 minutes
    assert consent_is_current(consent, current, world.now + timedelta(minutes=2))
    assert not consent_is_current(consent, current, current.expires_at)


@pytest.mark.parametrize(("case", "expected"), [
    ("ambiguous", AskAgain("ambiguous_reply")),
    ("declined", AskAgain("declined")),
    ("before_presentation", AskAgain("stale_presentation")),
    ("older_version_presented", AskAgain("stale_presentation")),
    ("expired", AskAgain("expired")),
    ("staff_note", NotConsent("staff_note messages cannot give customer consent")),
    ("agent", NotConsent("agent messages cannot give customer consent")),
    ("other_case", NotConsent("message belongs to another case")),
])
def test_anything_but_a_current_explicit_customer_yes_is_not_consent(world: World, case: str, expected: Any) -> None:
    current = proposal(world, version=2)
    shown = presented(world, current)
    reply, now = message(world, "yes"), world.now + timedelta(minutes=1)
    if case == "ambiguous":
        reply = message(world, "yes, but use my other card")
    elif case == "declined":
        reply = message(world, "no thanks")
    elif case == "before_presentation":
        reply = message(world, "yes", sequence=9)
    elif case == "older_version_presented":
        shown = presented(world, proposal(world, version=1))
    elif case == "expired":
        now = current.expires_at
    elif case == "staff_note":
        reply = message(world, "yes", source="staff_note", entered_by=world.analyst)
    elif case == "agent":
        reply = message(world, "yes", source="agent")
    elif case == "other_case":
        reply = CaseMessage.model_validate({**reply.model_dump(), "scope": {"workspace_id": world.workspace,
                                                                            "case_id": UUID(int=77)}})
    assert record_reply(consent_id=UUID(int=900), proposal=current, presentation=shown, message=reply,
                        now=now) == expected


def test_new_proposal_version_or_state_change_invalidates_consent(world: World) -> None:
    first = proposal(world)
    outcome = record_reply(consent_id=UUID(int=900), proposal=first, presentation=presented(world, first),
                           message=message(world, "yes"), now=world.now + timedelta(minutes=1))
    assert isinstance(outcome, Consented)
    changed_reason = proposal(world, reason="ordered by mistake")
    newer_version = proposal(world, version=2)
    changed_state = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(),
                            call=CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                            facts=world.facts(order=world.order().model_copy(update={"version": 8})),
                            evidence=(), rationale="Customer asked to cancel.", now=world.now)
    assert isinstance(changed_state, ActionProposal)
    for other in (changed_reason, newer_version, changed_state):
        assert other.action_digest != first.action_digest
        assert not consent_is_current(outcome.consent, other, world.now + timedelta(minutes=2))


def test_simulator_confirmation_event_must_name_the_exact_proposal(world: World) -> None:
    current = proposal(world)
    shown, reply = presented(world, current), message(world, "That sounds right.")
    event = SimulatorConfirmationEvent(proposal_id=current.proposal_id, proposal_version=1,
                                       action_digest=current.action_digest, decision="confirm")
    now = world.now + timedelta(minutes=1)
    result = record_simulator_event(consent_id=UUID(int=901), proposal=current, presentation=shown, message=reply,
                                    event=event, now=now)
    assert isinstance(result, Consented) and result.consent.basis == "simulator_confirmation_event"
    stale = event.model_copy(update={"action_digest": "0" * 64})
    assert record_simulator_event(consent_id=UUID(int=901), proposal=current, presentation=shown, message=reply,
                                  event=stale, now=now) == AskAgain("stale_presentation")
    operator = message(world, "yes", source="operator_entered_customer", entered_by=world.analyst)
    assert isinstance(record_simulator_event(consent_id=UUID(int=901), proposal=current, presentation=shown,
                                             message=operator, event=event, now=now), NotConsent)


def operator_consent(world: World, current: ActionProposal) -> CustomerConsent:
    outcome = record_reply(consent_id=UUID(int=902), proposal=current, presentation=presented(world, current),
                           message=message(world, "yes", source="operator_entered_customer",
                                           entered_by=world.analyst), now=world.now + timedelta(minutes=1))
    assert isinstance(outcome, Consented) and outcome.consent.entered_by == world.analyst
    return outcome.consent


def test_reviewer_approval_is_separate_from_and_cannot_be_given_by_the_consent_typist(world: World) -> None:
    current = proposal(world)
    consent = operator_consent(world, current)
    now = world.now + timedelta(minutes=2)
    same = decide(approval_id=UUID(int=950), proposal=current, consent=consent, principal_id=world.analyst,
                  roles=frozenset({Role.REVIEWER, Role.ANALYST}), decision="approve", reason="Looks right.", now=now)
    assert same == Refused("separation_of_duties", same.reason) if isinstance(same, Refused) else False
    admin = decide(approval_id=UUID(int=950), proposal=current, consent=consent, principal_id=world.reviewer,
                   roles=frozenset({Role.ADMIN}), decision="approve", reason="Looks right.", now=now)
    assert isinstance(admin, Refused) and admin.code == "forbidden"
    approved = decide(approval_id=UUID(int=950), proposal=current, consent=consent, principal_id=world.reviewer,
                      roles=frozenset({Role.REVIEWER}), decision="approve", reason="Looks right.", now=now)
    assert isinstance(approved, Decided)
    approval = approved.decision
    assert approval.expires_at == min(current.expires_at, consent.expires_at)
    assert ready_to_execute(current, consent, approval, now)
    assert not ready_to_execute(current, consent, approval, approval.expires_at)
    newer = proposal(world, version=2)
    assert not ready_to_execute(newer, consent, approval, now)
    rejected = decide(approval_id=UUID(int=951), proposal=current, consent=consent, principal_id=world.reviewer,
                      roles=frozenset({Role.REVIEWER}), decision="reject", reason="Wrong order.", now=now)
    assert isinstance(rejected, Decided) and not ready_to_execute(current, consent, rejected.decision, now)


def test_approval_requires_current_consent(world: World) -> None:
    current = proposal(world)
    consent = operator_consent(world, current)
    late = decide(approval_id=UUID(int=950), proposal=current, consent=consent, principal_id=world.reviewer,
                  roles=frozenset({Role.REVIEWER}), decision="approve", reason="ok", now=current.expires_at)
    assert isinstance(late, Refused) and late.code == "consent_required"


@pytest.mark.parametrize("payload", [
    {"source": "operator_entered_customer", "entered_by": None},
    {"source": "simulated_customer", "entered_by": str(UUID(int=101))},
    {"source": "staff_note", "entered_by": None},
    {"text_sha256": "0" * 64},
    {"created_at": "2026-01-01T12:00:00"},
    {"text": "line\u0000break"},
])
def test_message_provenance_is_validated(world: World, payload: dict[str, Any]) -> None:
    base = json.loads(message(world, "yes").model_dump_json())
    with pytest.raises(ValidationError):
        CaseMessage.model_validate_json(json.dumps({**base, **payload}))


def test_consent_and_approval_records_cap_lifetime_at_fifteen_minutes(world: World) -> None:
    current = proposal(world)
    consent = operator_consent(world, current)
    data = json.loads(consent.model_dump_json())
    with pytest.raises(ValidationError):
        CustomerConsent.model_validate_json(json.dumps({**data, "expires_at": "2026-01-01T12:16:01Z"}))
    with pytest.raises(ValidationError):
        CustomerConsent.model_validate_json(json.dumps({**data, "customer_message_sequence": 10}))
