"""Regressions for T04 review round 1 (F1-F5, N1)."""

from datetime import UTC, datetime, timedelta
from decimal import ROUND_DOWN, ROUND_UP, Decimal, localcontext
import hashlib
import json
from typing import Any
from uuid import UUID

from pydantic import ValidationError
import pytest

from policyops.domain.approval_rules import Decided, decide, ready_to_execute
from policyops.domain.consent_rules import AskAgain, Consented, NotConsent, consent_is_current, record_reply
from policyops.domain.examples import World, build_examples
from policyops.domain.retail_rules import Escalated, evaluate_write, propose
from policyops.domain.roles import Role
from policyops_contracts.consent import CaseMessage, CustomerConsent, ProposalPresentationRecord
from policyops_contracts.digest import text_sha256
from policyops_contracts.events import EventEnvelope, ToolCallRequested
from policyops_contracts.money import Money, MoneyError, money_from_upstream
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import (
    TOOL_KINDS,
    CancelPendingOrder,
    ExchangeDeliveredOrderItems,
    ItemsEffect,
    PaymentChangeEffect,
    PaymentMethodSnapshot,
    ReturnEffect,
    ToolKind,
    ToolName,
    UserSnapshot,
    VariantSnapshot,
)
from policyops_contracts.timing import MAX_UTC


# ---- F1: chronology and overflow --------------------------------------------------------------


def _proposal(world: World, now: datetime | None = None) -> ActionProposal:
    result = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(),
                     call=CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                     facts=world.facts(), evidence=(), rationale="Customer asked to cancel.", now=now or world.now)
    assert isinstance(result, ActionProposal), result
    return result


def _presented(world: World, proposal: ActionProposal, at: datetime) -> ProposalPresentationRecord:
    return ProposalPresentationRecord(
        scope=world.run_scope, proposal_id=proposal.proposal_id, proposal_version=1,
        action_digest=proposal.action_digest, presentation_sha256=proposal.presentation.text_sha256,
        message_id=UUID(int=700), message_sequence=10, presented_at=at)


def _reply(world: World, at: datetime, text: str = "yes") -> CaseMessage:
    return CaseMessage(message_id=UUID(int=811), scope=world.case_scope, sequence=11, source="simulated_customer",
                       entered_by=None, text=text, text_sha256=text_sha256(text), created_at=at)


def test_future_or_pre_proposal_evidence_never_becomes_consent(world: World) -> None:
    proposal = _proposal(world)
    now = world.now + timedelta(minutes=1)
    cases = {
        "future message": (_presented(world, proposal, world.now), _reply(world, world.now + timedelta(days=1))),
        "future presentation and message": (_presented(world, proposal, now + timedelta(seconds=10)),
                                            _reply(world, now + timedelta(seconds=20))),
        "presentation before proposal": (_presented(world, proposal, world.now - timedelta(seconds=1)),
                                         _reply(world, world.now + timedelta(seconds=5))),
    }
    for name, (presentation, message) in cases.items():
        outcome = record_reply(consent_id=UUID(int=900), proposal=proposal, presentation=presentation,
                               message=message, now=now)
        assert isinstance(outcome, NotConsent), name
    before_presentation = record_reply(consent_id=UUID(int=900), proposal=proposal,
                                       presentation=_presented(world, proposal, world.now + timedelta(seconds=30)),
                                       message=_reply(world, world.now + timedelta(seconds=20)), now=now)
    assert before_presentation == AskAgain("stale_presentation")


def test_boundary_equalities_are_accepted(world: World) -> None:
    proposal = _proposal(world)
    at = world.now  # presentation at creation, reply at that instant, decided at that instant
    outcome = record_reply(consent_id=UUID(int=900), proposal=proposal, presentation=_presented(world, proposal, at),
                           message=_reply(world, at), now=at)
    assert isinstance(outcome, Consented)
    consent = outcome.consent
    assert consent_is_current(consent, proposal, at)
    approved = decide(approval_id=UUID(int=950), proposal=proposal, consent=consent, principal_id=world.reviewer,
                      roles=frozenset({Role.REVIEWER}), decision="approve", reason="ok", now=at)
    assert isinstance(approved, Decided) and ready_to_execute(proposal, consent, approved.decision, at)


def test_not_yet_issued_consent_or_approval_is_not_current(world: World) -> None:
    proposal = _proposal(world)
    outcome = record_reply(consent_id=UUID(int=900), proposal=proposal,
                           presentation=_presented(world, proposal, world.now),
                           message=_reply(world, world.now + timedelta(minutes=5)),
                           now=world.now + timedelta(minutes=5))
    assert isinstance(outcome, Consented)
    consent = outcome.consent
    assert not consent_is_current(consent, proposal, world.now + timedelta(minutes=4))
    approved = decide(approval_id=UUID(int=950), proposal=proposal, consent=consent, principal_id=world.reviewer,
                      roles=frozenset({Role.REVIEWER}), decision="approve", reason="ok",
                      now=world.now + timedelta(minutes=6))
    assert isinstance(approved, Decided)
    approval = approved.decision
    assert not ready_to_execute(proposal, consent, approval, world.now + timedelta(minutes=5, seconds=30))
    assert ready_to_execute(proposal, consent, approval, world.now + timedelta(minutes=6))
    early = approval.model_copy(update={"decided_at": consent.confirmed_at - timedelta(seconds=1)})
    assert not ready_to_execute(proposal, consent, early, world.now + timedelta(minutes=7))


def test_maximal_dates_return_results_instead_of_overflowing() -> None:
    world = World()
    near_max = MAX_UTC - timedelta(minutes=5)
    proposal = _proposal(world, near_max)
    assert proposal.expires_at == MAX_UTC
    outcome = record_reply(consent_id=UUID(int=900), proposal=proposal,
                           presentation=_presented(world, proposal, near_max),
                           message=_reply(world, near_max), now=near_max)
    assert isinstance(outcome, Consented) and outcome.consent.expires_at == MAX_UTC
    approved = decide(approval_id=UUID(int=950), proposal=proposal, consent=outcome.consent,
                      principal_id=world.reviewer, roles=frozenset({Role.REVIEWER}), decision="approve",
                      reason="ok", now=near_max)
    assert isinstance(approved, Decided)
    at_max = propose(proposal_id=UUID(int=501), proposal_version=1, session=world.session(),
                     call=CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                     facts=world.facts(), evidence=(), rationale="r", now=MAX_UTC)
    assert not isinstance(at_max, ActionProposal)
    data = json.loads(outcome.consent.model_dump_json())
    with pytest.raises(ValidationError):  # not OverflowError
        CustomerConsent.model_validate_json(json.dumps({**data, "confirmed_at": MAX_UTC.isoformat(),
                                                        "expires_at": MAX_UTC.isoformat()}))


# ---- F2: derivable effect invariants, checked on resealed records ------------------------------


def _reseal(data: dict[str, Any]) -> str:
    body = {key: value for key, value in data.items() if key != "action_digest"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return json.dumps({**body, "action_digest": hashlib.sha256(canonical).hexdigest()})


def _exchange_example() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(build_examples()["action-proposal.exchange.json"])
    ActionProposal.model_validate_json(_reseal(data))  # the unmodified example reseals cleanly
    return data


@pytest.mark.parametrize("edit", [
    lambda d: d["effect"].update(status_before="pending", status_after="pending (item modified)"),
    lambda d: d["effect"].update(status_after="pending (item modified)"),
    lambda d: d["effect"]["price_difference"].update(
        amount_minor=d["effect"]["price_difference"]["amount_minor"] + 123),
    lambda d: d["effect"]["changes"][0].update(new_item_id=d["effect"]["changes"][0]["item_id"]),
])
def test_contradictory_item_effects_cannot_be_resealed(edit: Any) -> None:
    data = _exchange_example()
    edit(data)
    with pytest.raises(ValidationError):
        ItemsEffect.model_validate_json(json.dumps(data["effect"]))
    with pytest.raises(ValidationError):
        ActionProposal.model_validate_json(_reseal(data))


def test_duplicate_item_pairs_keep_multiplicity_and_order(world: World) -> None:
    order = world.order(status="delivered", items=(world.item_a, world.item_a))
    call = ExchangeDeliveredOrderItems(order_id=world.order_id, item_ids=(world.item_a, world.item_a),
                                       new_item_ids=(world.item_c, world.item_b), payment_method_id=world.card)
    result = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(), call=call,
                     facts=world.facts(order=order), evidence=(), rationale="r", now=world.now)
    assert isinstance(result, ActionProposal) and isinstance(result.effect, ItemsEffect)
    assert [line.new_item_id for line in result.effect.changes] == [world.item_c, world.item_b]
    assert result.effect.price_difference.amount_minor == (3000 - 1999) + (2500 - 1999)


def test_other_effect_invariants(world: World) -> None:
    usd = Money
    with pytest.raises(ValidationError):
        ReturnEffect.model_validate({"order_id": world.order_id, "items": ({"item_id": world.item_a,
                                                                            "price": usd(amount_minor=1999)},),
                                     "returned_items_price_total": usd(amount_minor=2000),
                                     "refund_payment_method_id": world.gift})
    base = {"order_id": world.order_id, "from_payment_method_id": world.card, "to_payment_method_id": world.paypal,
            "amount": usd(amount_minor=100), "refund_timing": "5 to 7 business days"}
    PaymentChangeEffect.model_validate(base)
    for bad in ({**base, "to_payment_method_id": world.card}, {**base, "refund_timing": "immediately"},
                {**base, "amount": usd(amount_minor=-1)}):
        with pytest.raises(ValidationError):
            PaymentChangeEffect.model_validate(bad)


# ---- F3: money is independent of the ambient decimal context ----------------------------------


@pytest.mark.parametrize("prec", [1, 2, 3, 28])
@pytest.mark.parametrize("rounding", [ROUND_DOWN, ROUND_UP])
def test_money_conversion_ignores_decimal_context(prec: int, rounding: str) -> None:
    with localcontext() as context:
        context.prec, context.rounding = prec, rounding
        assert money_from_upstream(1.23).amount_minor == 123
        assert money_from_upstream(54.04).amount_minor == 5404
        assert money_from_upstream(-12.5).amount_minor == -1250
        assert money_from_upstream(9999999999.99).amount_minor == 999999999999
        assert Money(amount_minor=123456789).to_decimal() == Decimal("1234567.89")
        for bad in (1.234, 0.1 + 0.2, 1e16, 1e-5):
            with pytest.raises(MoneyError):
                money_from_upstream(bad)


# ---- F4: conflicting snapshots escalate; IDs are unique ----------------------------------------


def _items_call(world: World) -> ExchangeDeliveredOrderItems:
    return ExchangeDeliveredOrderItems(order_id=world.order_id, item_ids=(world.item_a, world.item_b),
                                       new_item_ids=(world.item_c, world.item_c), payment_method_id=world.card)


def test_mixed_product_versions_or_duplicate_variants_escalate(world: World) -> None:
    order = world.order(status="delivered")
    variants = world.variants()
    mixed = (variants[0], variants[1].model_copy(update={"product_version": 12}), variants[2])
    duplicate = (variants[0], variants[0].model_copy(update={"price": Money(amount_minor=1)}), *variants[1:])
    identical = (variants[0], variants[0], *variants[1:])
    for facts in (mixed, duplicate, identical):
        outcome = evaluate_write(_items_call(world), world.session(), world.facts(order=order, variants=facts))
        assert isinstance(outcome, Escalated) and outcome.rule_id == "ids.product_item_distinct", outcome


def test_variant_order_does_not_change_the_proposal(world: World) -> None:
    order = world.order(status="delivered")
    forward = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(), call=_items_call(world),
                      facts=world.facts(order=order), evidence=(), rationale="r", now=world.now)
    backward = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(),
                       call=_items_call(world), facts=world.facts(order=order, variants=world.variants()[::-1]),
                       evidence=(), rationale="r", now=world.now)
    assert isinstance(forward, ActionProposal) and isinstance(backward, ActionProposal)
    assert forward.action_digest == backward.action_digest


def test_duplicate_payment_method_ids_are_rejected(world: World) -> None:
    customer = world.customer()
    methods = (*customer.payment_methods,
               PaymentMethodSnapshot(payment_method_id=world.gift, kind="gift_card",
                                     gift_card_balance=Money(amount_minor=1)))
    with pytest.raises(ValidationError):
        UserSnapshot.model_validate({**customer.model_dump(), "payment_methods": methods})


def test_variant_snapshot_identity_is_preserved_for_distinct_products(world: World) -> None:
    other = VariantSnapshot(product_id=world.other_product, item_id=world.item_x, available=True,
                            price=Money(amount_minor=100), product_version=4)
    assert other in world.variants()


# ---- F5: event tool kind matches the tool ------------------------------------------------------


def test_tool_events_cannot_mislabel_kind() -> None:
    for tool in ToolName:
        ToolCallRequested(tool=tool, kind=TOOL_KINDS[tool], call_sha256="0" * 64)
        for kind in ToolKind:
            if kind != TOOL_KINDS[tool]:
                with pytest.raises(ValidationError):
                    ToolCallRequested(tool=tool, kind=kind, call_sha256="0" * 64)
    with pytest.raises(ValidationError):
        ToolCallRequested.model_validate_json(json.dumps(
            {"tool": "cancel_pending_order", "kind": "read", "call_sha256": "0" * 64}))


# ---- N1: replayable events have no free-form text -----------------------------------------------


def test_event_payload_strings_are_all_constrained() -> None:
    schema = EventEnvelope.model_json_schema()
    unconstrained: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            if node.get("type") == "string" and not ({"enum", "const", "pattern", "format"} & set(node)):
                unconstrained.append(path)
            for key, value in node.items():
                walk(value, f"{path}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}/{index}")

    walk(schema, "")
    assert unconstrained == []
    assert set(schema["$defs"]["ErrorRaised"]["properties"]) == {"type", "code", "rule_id", "correlation_id",
                                                                  "retryable"}


def test_utc_constant() -> None:
    assert MAX_UTC.tzinfo is UTC
    assert datetime.max.replace(tzinfo=UTC) == MAX_UTC
