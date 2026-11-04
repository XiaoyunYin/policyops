"""Deterministic retail write preconditions, exact effects and proposal sealing.

`evaluate_write` checks one typed write call against versioned snapshots of the
bound customer, the order, the variants involved and the order's recorded
operation history, and computes the exact effect to display. Outcomes name the
rule (see policyops_contracts.policy) that allowed, denied or escalated:

* denied: a pinned-policy precondition fails (wrong status, foreign resource,
  insufficient gift card balance, same item, repeated one-shot tool, ...);
* escalated: the facts needed to decide are missing, the case is outside
  what the policy specifies (incomplete operation history, unexpected payment
  history, unknown payment method), or the pinned simulator is known not to
  produce the previewed effect (item modifications with distinct replacement
  variants); escalation never certifies the action.

Known pinned-source behaviour the preview does not claim to match exactly:
modify_pending_order_items records the unrounded float difference as the payment
amount; exchange_delivered_order_items only records the request (sorted item
lists, payment method, rounded difference) without any payment or refund. The
preview is the expected effect on supplied facts, not proof the upstream call
will reproduce it; parity is checked before commit in T16.

Money is exact minor units throughout. This is a pure contract-level preview:
it derives the exact effect to display and evaluates source-traced
preconditions on the snapshots it is given. It performs no simulator mutation,
persists nothing, stores no operation history and is not runtime
authorization; fetching current snapshots, recording executions and rechecking
before an idempotent execution belong to the gateway and executor (T16-T19).
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from policyops.domain.session import CustomerSession
from policyops_contracts.digest import canonical_bytes, sha256_hex
from policyops_contracts.errors import ErrorCode
from policyops_contracts.money import ZERO, Money
from policyops_contracts.policy import RETAIL_POLICY, RETAIL_RULES
from policyops_contracts.proposal import ActionProposal, EvidenceRef, ProposalBody, presentation_for
from policyops_contracts.retail import (
    CancelEffect,
    CancelPendingOrder,
    Effect,
    ExchangeDeliveredOrderItems,
    ItemChangeLine,
    ItemsEffect,
    ModifyPendingOrderAddress,
    ModifyPendingOrderItems,
    ModifyPendingOrderPayment,
    ModifyUserAddress,
    OrderAddressEffect,
    OrderOperationHistory,
    OrderSnapshot,
    PaymentChangeEffect,
    PaymentMethodSnapshot,
    RefundLine,
    ResourceVersion,
    ReturnDeliveredOrderItems,
    ReturnEffect,
    ReturnLine,
    ToolName,
    UserAddressEffect,
    UserSnapshot,
    VariantSnapshot,
    WriteToolCall,
)
from policyops_contracts.scalars import RunScope
from policyops_contracts.timing import expiry_after


ResourceKind = Literal["user", "order", "product"]
ONCE_PER_ORDER = frozenset({ToolName.MODIFY_PENDING_ORDER_ADDRESS, ToolName.MODIFY_PENDING_ORDER_PAYMENT,
                            ToolName.MODIFY_PENDING_ORDER_ITEMS, ToolName.EXCHANGE_DELIVERED_ORDER_ITEMS})


@dataclass(frozen=True)
class RetailFacts:
    customer: UserSnapshot
    order: OrderSnapshot | None = None
    variants: tuple[VariantSnapshot, ...] = ()
    history: OrderOperationHistory | None = None


@dataclass(frozen=True)
class Allowed:
    effect: Effect
    rule_ids: tuple[str, ...]
    resource_versions: tuple[ResourceVersion, ...]


@dataclass(frozen=True)
class Denied:
    code: ErrorCode
    rule_id: str
    detail: str


@dataclass(frozen=True)
class Escalated:
    rule_id: str
    detail: str


Outcome = Allowed | Denied | Escalated


class _Stop(Exception):
    def __init__(self, outcome: Denied | Escalated) -> None:
        self.outcome = outcome


def _deny(rule_id: str, detail: str, code: ErrorCode = ErrorCode.POLICY_DENIED) -> _Stop:
    return _Stop(Denied(code, rule_id, detail))


def _escalate(rule_id: str, detail: str) -> _Stop:
    return _Stop(Escalated(rule_id, detail))


def rules_for(tool: ToolName) -> tuple[str, ...]:
    return tuple(sorted({"auth.lookup_required", *(rule.rule_id for rule in RETAIL_RULES if tool in rule.tools)}))


def _timing(method: PaymentMethodSnapshot) -> Literal["immediately", "5 to 7 business days"]:
    return "immediately" if method.kind == "gift_card" else "5 to 7 business days"


class _Context:
    def __init__(self, session: CustomerSession, facts: RetailFacts) -> None:
        if not session.authenticated:
            raise _deny("auth.lookup_required", "customer not authenticated", ErrorCode.CUSTOMER_NOT_AUTHENTICATED)
        if facts.customer.user_id != session.binding.user_id:
            raise _deny("scope.single_customer", "facts describe another customer", ErrorCode.CUSTOMER_MISMATCH)
        self.facts = facts
        self.customer = facts.customer
        # UserSnapshot rejects duplicate payment-method IDs, so this mapping loses nothing.
        self.methods = {method.payment_method_id: method for method in facts.customer.payment_methods}
        self.variants: dict[str, VariantSnapshot] = {}
        product_versions: dict[str, int] = {}
        for variant in facts.variants:
            if variant.item_id in self.variants:
                raise _escalate("ids.product_item_distinct", f"conflicting snapshots of item {variant.item_id}")
            if product_versions.setdefault(variant.product_id, variant.product_version) != variant.product_version:
                raise _escalate("ids.product_item_distinct",
                                f"snapshots of product {variant.product_id} come from different versions")
            self.variants[variant.item_id] = variant
        self.versions: dict[tuple[ResourceKind, str], int] = {("user", facts.customer.user_id): facts.customer.version}

    def method(self, payment_method_id: str, rule_id: str) -> PaymentMethodSnapshot:
        method = self.methods.get(payment_method_id)
        if method is None:
            raise _deny(rule_id, "the payment method is not one of the customer's", ErrorCode.CUSTOMER_MISMATCH)
        return method

    def order(self, order_id: str, tool: str) -> OrderSnapshot:
        order = self.facts.order
        if order is None or order.order_id != order_id:
            raise _escalate("status.actionable", "no current snapshot of the order was supplied")
        if order.user_id != self.customer.user_id:
            raise _deny("scope.single_customer", "the order belongs to another customer", ErrorCode.CUSTOMER_MISMATCH)
        if order.status not in ("pending", "delivered"):
            raise _deny("status.actionable", f"order status is {order.status!r}")
        if tool in ONCE_PER_ORDER:
            history = self.facts.history
            if history is None or history.order_id != order_id or not history.complete:
                raise _escalate("orders.modify_exchange_once", "the order's operation history is not known complete")
            if tool in history.successful_tools:
                raise _deny("orders.modify_exchange_once", f"{tool} already succeeded for this order")
        self.versions[("order", order.order_id)] = order.version
        return order

    def single_payment(self, order: OrderSnapshot, rule_id: str) -> PaymentMethodSnapshot:
        payments = order.payment_history
        if len(payments) != 1 or payments[0].transaction_type != "payment":
            raise _escalate(rule_id, "the order's payment history is not exactly one payment")
        method = self.methods.get(payments[0].payment_method_id)
        if method is None:
            raise _escalate(rule_id, "the original payment method is not in the customer's profile")
        return method

    def item_changes(self, order: OrderSnapshot, call: ModifyPendingOrderItems | ExchangeDeliveredOrderItems,
                     rule_prefix: str) -> tuple[tuple[ItemChangeLine, ...], Money]:
        _require_items(order, call.item_ids, f"{rule_prefix}.same_product_other_option")
        variants = self.variants
        lines, difference = [], ZERO
        for item_id, new_item_id in zip(call.item_ids, call.new_item_ids, strict=True):
            old = next(item for item in order.items if item.item_id == item_id)
            rule = f"{rule_prefix}.same_product_other_option"
            if new_item_id == item_id:
                raise _deny(rule, f"item {item_id} would be replaced by the same option")
            new = variants.get(new_item_id)
            if new is None:
                raise _escalate(rule, f"no snapshot of item {new_item_id} was supplied")
            if new.product_id != old.product_id:
                raise _deny(rule, f"item {new_item_id} is not a variant of product {old.product_id}")
            if not new.available:
                raise _deny(rule, f"item {new_item_id} is not available")
            self.versions[("product", new.product_id)] = new.product_version
            lines.append(ItemChangeLine(item_id=item_id, new_item_id=new_item_id, product_id=old.product_id,
                                        price_before=old.price, price_after=new.price))
            difference = difference + new.price - old.price
        return tuple(lines), difference


def _require_items(order: OrderSnapshot, item_ids: tuple[str, ...], rule_id: str) -> None:
    held = Counter(item.item_id for item in order.items)
    for item_id, count in Counter(item_ids).items():
        if count > held[item_id]:
            raise _deny(rule_id, f"the order does not contain item {item_id} x{count}")


def _gift_card_covers(method: PaymentMethodSnapshot, amount: Money, rule_id: str) -> None:
    if method.kind == "gift_card" and amount.amount_minor > 0:
        balance = method.gift_card_balance
        if balance is None or balance.amount_minor < amount.amount_minor:
            raise _deny(rule_id, "the gift card balance does not cover the amount")


def _effect(call: WriteToolCall, context: _Context) -> Effect:
    if isinstance(call, CancelPendingOrder):
        order = context.order(call.order_id, call.tool)
        if order.status != "pending":
            raise _deny("cancel.pending_only", f"order status is {order.status!r}")
        original = context.single_payment(order, "cancel.effect")
        payment = order.payment_history[0]
        return CancelEffect(order_id=order.order_id, reason=call.reason, refunds=(RefundLine(
            payment_method_id=payment.payment_method_id, amount=payment.amount, timing=_timing(original)),))
    if isinstance(call, ModifyPendingOrderAddress):
        order = context.order(call.order_id, call.tool)
        if order.status != "pending":
            raise _deny("modify.pending_only", f"order status is {order.status!r}")
        return OrderAddressEffect(order_id=order.order_id, address_before=order.address, address_after=call.address())
    if isinstance(call, ModifyPendingOrderPayment):
        order = context.order(call.order_id, call.tool)
        if order.status != "pending":
            raise _deny("modify.pending_only", f"order status is {order.status!r}")
        original = context.single_payment(order, "payment.single_different_method")
        new = context.method(call.payment_method_id, "payment.single_different_method")
        if new.payment_method_id == original.payment_method_id:
            raise _deny("payment.single_different_method", "the new payment method equals the original")
        amount = order.payment_history[0].amount
        _gift_card_covers(new, amount, "payment.gift_card_covers_total")
        return PaymentChangeEffect(order_id=order.order_id, from_payment_method_id=original.payment_method_id,
                                   to_payment_method_id=new.payment_method_id, amount=amount,
                                   refund_timing=_timing(original))
    if isinstance(call, ModifyPendingOrderItems | ExchangeDeliveredOrderItems):
        modify = isinstance(call, ModifyPendingOrderItems)
        order = context.order(call.order_id, call.tool)
        required: Literal["pending", "delivered"] = "pending" if modify else "delivered"
        if order.status != required:
            raise _deny("modify.pending_only" if modify else "exchange.delivered_only_all_items",
                        f"order status is {order.status!r}")
        prefix = "items" if modify else "exchange"
        changes, difference = context.item_changes(order, call, prefix)
        # Checked after the per-item policy checks, so policy denials take precedence.
        if modify and len(set(call.new_item_ids)) > 1:
            # Pinned tau2 19f13ea3 modify_pending_order_items assigns the final loop variant's price and
            # options to every modified item, so a per-item preview would not match the simulator's result.
            raise _escalate("items.same_product_other_option",
                            "modifications with distinct replacement variants are not supported by the pinned "
                            "simulator (and the tool is one-shot per order); hand off to a human agent")
        method = context.method(call.payment_method_id, f"{prefix}.price_difference_method")
        _gift_card_covers(method, difference, f"{prefix}.price_difference_method")
        return ItemsEffect(kind=call.tool, order_id=order.order_id,
                           changes=changes, price_difference=difference, payment_method_id=method.payment_method_id,
                           status_before=required,
                           status_after="pending (item modified)" if modify else "exchange requested")
    if isinstance(call, ReturnDeliveredOrderItems):
        order = context.order(call.order_id, call.tool)
        if order.status != "delivered":
            raise _deny("return.delivered_only", f"order status is {order.status!r}")
        _require_items(order, call.item_ids, "return.order_and_items")
        method = context.method(call.payment_method_id, "return.refund_destination")
        if method.kind != "gift_card" and method.payment_method_id != order.payment_history[0].payment_method_id:
            raise _deny("return.refund_destination", "refunds go to the original method or an existing gift card")
        lines = tuple(ReturnLine(item_id=item_id, price=next(item for item in order.items
                                                              if item.item_id == item_id).price)
                      for item_id in call.item_ids)
        total = ZERO
        for line in lines:
            total = total + line.price
        return ReturnEffect(order_id=order.order_id, items=lines, returned_items_price_total=total,
                            refund_payment_method_id=method.payment_method_id)
    if isinstance(call, ModifyUserAddress):
        if call.user_id != context.customer.user_id:
            raise _deny("scope.single_customer", "only the authenticated customer's address",
                        ErrorCode.CUSTOMER_MISMATCH)
        return UserAddressEffect(user_id=call.user_id, address_before=context.customer.address,
                                 address_after=call.address())
    raise TypeError(f"unknown write call {type(call).__name__}")  # pragma: no cover


def evaluate_write(call: WriteToolCall, session: CustomerSession, facts: RetailFacts) -> Outcome:
    try:
        context = _Context(session, facts)
        effect = _effect(call, context)
    except _Stop as stop:
        return stop.outcome
    versions = tuple(ResourceVersion(kind=kind, resource_id=resource_id, version=version)
                     for (kind, resource_id), version in sorted(context.versions.items()))
    return Allowed(effect=effect, rule_ids=rules_for(ToolName(call.tool)), resource_versions=versions)


def intent_digest(scope: RunScope, customer_user_id: str, call: WriteToolCall) -> str:
    """Same logical intent across proposal versions: tenant, case, customer, tool and target resource."""
    target = call.user_id if isinstance(call, ModifyUserAddress) else call.order_id
    material = "\n".join([str(scope.workspace_id), str(scope.case_id), customer_user_id, str(call.tool), target])
    return sha256_hex(material.encode("utf-8"))


def propose(*, proposal_id: UUID, proposal_version: int, session: CustomerSession, call: WriteToolCall,
            facts: RetailFacts, evidence: tuple[EvidenceRef, ...], rationale: str,
            now: datetime) -> ActionProposal | Denied | Escalated:
    outcome = evaluate_write(call, session, facts)
    if not isinstance(outcome, Allowed):
        return outcome
    expires_at = expiry_after(now)
    if expires_at <= now:
        return Denied(ErrorCode.INVALID_INPUT, "status.actionable",
                      "the clock is at the end of the representable range")
    body = ProposalBody.model_validate({
        "proposal_id": proposal_id, "proposal_version": proposal_version,
        "intent_digest": intent_digest(session.run, session.binding.user_id, call),
        "scope": session.run.model_dump(), "customer_user_id": session.binding.user_id,
        "action": call.model_dump(), "effect": outcome.effect.model_dump(),
        "presentation": presentation_for(outcome.effect).model_dump(), "policy": RETAIL_POLICY.model_dump(),
        "rule_ids": outcome.rule_ids,
        "resource_versions": tuple(item.model_dump() for item in outcome.resource_versions),
        "evidence": tuple(item.model_dump() for item in sorted(evidence, key=lambda item: str(item.evidence_id))),
        "rationale": rationale, "created_at": now, "expires_at": expires_at,
    })
    return ActionProposal.seal(body)


def call_digest(call: WriteToolCall) -> str:
    return sha256_hex(canonical_bytes(call))
