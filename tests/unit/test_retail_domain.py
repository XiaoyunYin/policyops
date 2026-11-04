"""Retail write preconditions, exact effects and proposal binding (synthetic world)."""

from datetime import timedelta
import json
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter, ValidationError
import pytest

from policyops.domain.examples import World
from policyops.domain.retail_rules import Allowed, Denied, Escalated, evaluate_write, propose
from policyops_contracts.digest import canonical_bytes
from policyops_contracts.errors import ErrorCode
from policyops_contracts.policy import RULES_BY_ID
from policyops_contracts.proposal import ActionProposal, ProposalBody
from policyops_contracts.retail import (
    CancelPendingOrder,
    ExchangeDeliveredOrderItems,
    ItemsEffect,
    ModifyPendingOrderAddress,
    ModifyPendingOrderItems,
    ModifyPendingOrderPayment,
    ModifyUserAddress,
    ReturnDeliveredOrderItems,
    ReturnEffect,
    WriteToolCall,
)


def items_call(world: World, *, new: tuple[str, ...] = ("1000000003",), old: tuple[str, ...] = ("1000000001",),
               method: str | None = None, exchange: bool = False) -> WriteToolCall:
    cls = ExchangeDeliveredOrderItems if exchange else ModifyPendingOrderItems
    return cls(order_id=world.order_id, item_ids=old, new_item_ids=new, payment_method_id=method or world.card)


def proposal_for(world: World, call: WriteToolCall, **facts: Any) -> ActionProposal:
    result = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(), call=call,
                     facts=world.facts(**facts), evidence=(), rationale="Customer asked for this change.",
                     now=world.now)
    assert isinstance(result, ActionProposal), result
    return result


def test_cancel_effect_refunds_original_payment_with_policy_timing(world: World) -> None:
    proposal = proposal_for(world, CancelPendingOrder(order_id=world.order_id, reason="ordered by mistake"))
    assert proposal.effect.model_dump(mode="json")["refunds"] == [
        {"payment_method_id": world.card, "amount": {"amount_minor": 4499, "currency": "USD"},
         "timing": "5 to 7 business days"}]
    gift_paid = proposal_for(world, CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                             order=world.order(paid_with=world.gift))
    assert gift_paid.effect.model_dump()["refunds"][0]["timing"] == "immediately"
    assert "Its status becomes 'cancelled'." in proposal.presentation.text


def test_item_modification_preserves_pairs_multiplicity_and_states_policy_reminders(world: World) -> None:
    order = world.order(items=(world.item_a, world.item_a, world.item_b))
    same_option = items_call(world, old=(world.item_a, world.item_b), new=(world.item_c, world.item_b))
    denied = evaluate_write(same_option, world.session(), world.facts(order=order))
    assert isinstance(denied, Denied) and denied.rule_id == "items.same_product_other_option"
    # Several old items to one replacement variant: the pinned simulator applies that variant to each.
    call = items_call(world, old=(world.item_a, world.item_a), new=(world.item_c, world.item_c))
    proposal = proposal_for(world, call, order=order)
    effect = proposal.effect
    assert isinstance(effect, ItemsEffect)
    assert [(line.item_id, line.new_item_id) for line in effect.changes] == [
        (world.item_a, world.item_c), (world.item_a, world.item_c)]
    assert effect.price_difference.amount_minor == 2 * (3000 - 1999)
    assert effect.status_after == "pending (item modified)"
    assert "is charged to" in proposal.presentation.text
    text = proposal.presentation.text
    assert "This can be done only once for this order" in text
    assert "includes every item you want to modify" in text
    assert ("product", world.product, 11) in [(v.kind, v.resource_id, v.version) for v in proposal.resource_versions]
    assert "items.once_and_all_items" in proposal.rule_ids and "orders.modify_exchange_once" in proposal.rule_ids


def test_pending_modification_with_distinct_replacements_escalates(world: World) -> None:
    # Pinned tau2 applies the final replacement variant's price/options to every modified item.
    order = world.order(items=(world.item_a, world.item_a, world.item_b))
    distinct_cases = (((world.item_a, world.item_a), (world.item_c, world.item_b)),
                      ((world.item_a, world.item_b), (world.item_b, world.item_c)))
    for old, new in distinct_cases:
        outcome = evaluate_write(items_call(world, old=old, new=new), world.session(), world.facts(order=order))
        assert isinstance(outcome, Escalated), outcome
        assert outcome.rule_id == "items.same_product_other_option" and "distinct replacement" in outcome.detail
    exchange = evaluate_write(items_call(world, old=(world.item_a, world.item_a), new=(world.item_c, world.item_b),
                                         exchange=True), world.session(),
                              world.facts(order=world.order(status="delivered", items=(world.item_a, world.item_a))))
    assert isinstance(exchange, Allowed)


def test_exchange_presentation_records_a_quote_not_a_payment(world: World) -> None:
    delivered = world.order(status="delivered")
    for method in (world.gift, world.card):
        proposal = proposal_for(world, items_call(world, exchange=True, method=method), order=delivered)
        text = proposal.presentation.text
        assert "owed by the customer" in text and "No charge or refund is made by this request." in text
        assert "is charged to" not in text and "is refunded to" not in text


def test_exchange_and_return_effects(world: World) -> None:
    delivered = world.order(status="delivered")
    exchange = proposal_for(world, items_call(world, exchange=True, method=world.gift), order=delivered)
    assert isinstance(exchange.effect, ItemsEffect) and exchange.effect.status_after == "exchange requested"
    assert "includes every item you want to exchange" in exchange.presentation.text
    returned = proposal_for(world, ReturnDeliveredOrderItems(order_id=world.order_id, item_ids=(world.item_b,),
                                                             payment_method_id=world.gift), order=delivered)
    assert isinstance(returned.effect, ReturnEffect)
    assert returned.effect.returned_items_price_total.amount_minor == 2500
    assert "Purchase price of these items: $25.00." in returned.presentation.text


def test_address_payment_and_profile_effects(world: World) -> None:
    new = world.address("2 New Street")
    address = proposal_for(world, ModifyPendingOrderAddress(order_id=world.order_id, **new.model_dump()))
    assert address.effect.model_dump()["address_after"]["address1"] == "2 New Street"
    payment = proposal_for(world, ModifyPendingOrderPayment(order_id=world.order_id, payment_method_id=world.paypal))
    assert payment.effect.model_dump()["refund_timing"] == "5 to 7 business days"
    profile = proposal_for(world, ModifyUserAddress(user_id=world.user_id, **new.model_dump()))
    assert [v.kind for v in profile.resource_versions] == ["user"]


@pytest.mark.parametrize(("call", "facts", "rule_id", "code"), [
    (lambda w: CancelPendingOrder(order_id=w.order_id, reason="no longer needed"),
     lambda w: {"order": w.order(status="processed")}, "status.actionable", ErrorCode.POLICY_DENIED),
    (lambda w: CancelPendingOrder(order_id=w.order_id, reason="no longer needed"),
     lambda w: {"order": w.order(status="delivered")}, "cancel.pending_only", ErrorCode.POLICY_DENIED),
    (lambda w: CancelPendingOrder(order_id=w.order_id, reason="no longer needed"),
     lambda w: {"order": w.order(user_id=w.other_user)}, "scope.single_customer", ErrorCode.CUSTOMER_MISMATCH),
    (lambda w: ModifyPendingOrderPayment(order_id=w.order_id, payment_method_id=w.card),
     lambda w: {}, "payment.single_different_method", ErrorCode.POLICY_DENIED),
    (lambda w: ModifyPendingOrderPayment(order_id=w.order_id, payment_method_id=w.gift),
     lambda w: {"customer": w.customer(gift_balance=4498)}, "payment.gift_card_covers_total",
     ErrorCode.POLICY_DENIED),
    (lambda w: ModifyPendingOrderPayment(order_id=w.order_id, payment_method_id="credit_card_0000099"),
     lambda w: {}, "payment.single_different_method", ErrorCode.CUSTOMER_MISMATCH),
    (lambda w: items_call(w, method=w.gift), lambda w: {"customer": w.customer(gift_balance=1000)},
     "items.price_difference_method", ErrorCode.POLICY_DENIED),
    (lambda w: items_call(w, new=("1000000009",)), lambda w: {}, "items.same_product_other_option",
     ErrorCode.POLICY_DENIED),
    (lambda w: items_call(w, new=("1000000001",), old=("1000000001",)), lambda w: {},
     "items.same_product_other_option", ErrorCode.POLICY_DENIED),
    (lambda w: items_call(w), lambda w: {"variants": w.variants(available=False)},
     "items.same_product_other_option", ErrorCode.POLICY_DENIED),
    (lambda w: items_call(w, old=("1000000001", "1000000001"), new=("1000000003", "1000000003")), lambda w: {},
     "items.same_product_other_option", ErrorCode.POLICY_DENIED),
    (lambda w: items_call(w), lambda w: {"history": w.history("modify_pending_order_items")},
     "orders.modify_exchange_once", ErrorCode.POLICY_DENIED),
    (lambda w: ModifyPendingOrderAddress(order_id=w.order_id, **w.address("9 Elm").model_dump()),
     lambda w: {"history": w.history("modify_pending_order_address")}, "orders.modify_exchange_once",
     ErrorCode.POLICY_DENIED),
    (lambda w: items_call(w), lambda w: {"order": w.order(status="pending (item modified)")},
     "status.actionable", ErrorCode.POLICY_DENIED),
    (lambda w: items_call(w, exchange=True), lambda w: {}, "exchange.delivered_only_all_items",
     ErrorCode.POLICY_DENIED),
    (lambda w: ReturnDeliveredOrderItems(order_id=w.order_id, item_ids=("1000000001",), payment_method_id=w.paypal),
     lambda w: {"order": w.order(status="delivered")}, "return.refund_destination", ErrorCode.POLICY_DENIED),
    (lambda w: ReturnDeliveredOrderItems(order_id=w.order_id, item_ids=("1000000003",), payment_method_id=w.card),
     lambda w: {"order": w.order(status="delivered")}, "return.order_and_items", ErrorCode.POLICY_DENIED),
    (lambda w: ModifyUserAddress(user_id=w.other_user, **w.address().model_dump()), lambda w: {},
     "scope.single_customer", ErrorCode.CUSTOMER_MISMATCH),
])
def test_policy_preconditions_deny(world: World, call: Any, facts: Any, rule_id: str, code: ErrorCode) -> None:
    outcome = evaluate_write(call(world), world.session(), world.facts(**facts(world)))
    assert isinstance(outcome, Denied), outcome
    assert (outcome.code, outcome.rule_id) == (code, rule_id)
    assert rule_id in RULES_BY_ID


def test_address_then_items_on_one_order_is_allowed(world: World) -> None:
    # Matches the dev reference workflows (address change, then item change, each once per order).
    outcome = evaluate_write(items_call(world), world.session(),
                             world.facts(history=world.history("modify_pending_order_address")))
    assert isinstance(outcome, Allowed)


@pytest.mark.parametrize("facts", [
    lambda w: {"history": w.history(complete=False)},
    lambda w: {"history": None},
    lambda w: {"order": None},
    lambda w: {"order": w.order(payments=2)},
    lambda w: {"variants": ()},
])
def test_missing_or_unexpected_facts_escalate_instead_of_certifying(world: World, facts: Any) -> None:
    call = items_call(world) if "variants" in facts(world) else ModifyPendingOrderPayment(
        order_id=world.order_id, payment_method_id=world.paypal)
    outcome = evaluate_write(call, world.session(), world.facts(**facts(world)))
    assert isinstance(outcome, Escalated), outcome
    assert outcome.rule_id in RULES_BY_ID


def test_unauthenticated_session_cannot_obtain_a_proposal(world: World) -> None:
    outcome = evaluate_write(CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                             world.session(authenticated=False), world.facts())
    assert isinstance(outcome, Denied) and outcome.code is ErrorCode.CUSTOMER_NOT_AUTHENTICATED


def test_proposal_round_trips_and_is_deeply_immutable(world: World) -> None:
    proposal = proposal_for(world, items_call(world))
    assert ActionProposal.model_validate_json(proposal.model_dump_json()) == proposal
    with pytest.raises(ValidationError):
        proposal.rationale = "changed"  # type: ignore[misc]
    assert isinstance(proposal.action.model_dump()["item_ids"], tuple)
    with pytest.raises(AttributeError):
        proposal.resource_versions.append(proposal.resource_versions[0])  # type: ignore[attr-defined]


def _tampered(proposal: ActionProposal, edit: Any) -> dict[str, Any]:
    data: dict[str, Any] = proposal.model_dump(mode="json")
    edit(data)
    return data


def test_any_bound_field_change_breaks_or_changes_the_digest(world: World) -> None:
    proposal = proposal_for(world, items_call(world))
    edits = [
        lambda d: d["action"].update(payment_method_id=world.paypal),
        lambda d: d["effect"]["changes"][0]["price_after"].update(amount_minor=1),
        lambda d: d["scope"].update(run_id=str(UUID(int=9))),
        lambda d: d.update(proposal_version=2),
        lambda d: d["policy"].update(sha256="0" * 64),
        lambda d: d["resource_versions"][0].update(version=99),
        lambda d: d.update(expires_at="2026-01-01T12:10:00Z"),
        lambda d: d.update(customer_user_id="example_user_0003"),
    ]
    for edit in edits:
        with pytest.raises(ValidationError):
            ActionProposal.model_validate_json(_json(_tampered(proposal, edit)))


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data)


def test_pair_order_and_multiplicity_are_part_of_the_digest(world: World) -> None:
    order = world.order(items=(world.item_a, world.item_b))
    forward = proposal_for(world, items_call(world, old=(world.item_a, world.item_b),
                                             new=(world.item_c, world.item_c)), order=order)
    reverse = proposal_for(world, items_call(world, old=(world.item_b, world.item_a),
                                             new=(world.item_c, world.item_c)), order=order)
    assert forward.action_digest != reverse.action_digest
    assert canonical_bytes(forward.action).count(world.item_c.encode()) == 2


def test_expiry_is_capped_at_fifteen_minutes_and_must_be_utc(world: World) -> None:
    proposal = proposal_for(world, CancelPendingOrder(order_id=world.order_id, reason="no longer needed"))
    assert proposal.expires_at - proposal.created_at == timedelta(minutes=15)
    data = proposal.model_dump(mode="json")
    for created, expires in (("2026-01-01T12:00:00Z", "2026-01-01T12:15:01Z"),
                             ("2026-01-01T12:00:00", "2026-01-01T12:10:00"),
                             ("2026-01-01T12:00:00+01:00", "2026-01-01T12:10:00+01:00")):
        with pytest.raises(ValidationError):
            ProposalBody.model_validate_json(_json({**{k: v for k, v in data.items() if k != "action_digest"},
                                                    "created_at": created, "expires_at": expires}))


def test_write_call_union_rejects_unknown_tools_and_extra_fields(world: World) -> None:
    adapter: TypeAdapter[WriteToolCall] = TypeAdapter(WriteToolCall)
    good = {"tool": "cancel_pending_order", "order_id": world.order_id, "reason": "no longer needed"}
    adapter.validate_json(_json(good))
    for bad in ({**good, "reason": "changed my mind"}, {**good, "approved": True},
                {**good, "tool": "get_order_details"}, {**good, "order_id": "W0000001"},
                {"tool": "modify_pending_order_items", "order_id": world.order_id, "item_ids": ["1000000001"],
                 "new_item_ids": [], "payment_method_id": world.card}):
        with pytest.raises(ValidationError):
            adapter.validate_json(_json(bad))
