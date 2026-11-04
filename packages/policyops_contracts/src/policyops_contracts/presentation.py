"""Server-rendered confirmation text for each displayed effect.

The text shown to the customer (and to the staff reviewer) is a deterministic
function of the typed effect, so consent and approval bind to exactly what was
displayed. For item modifications and exchanges it states the one-time nature
and asks the customer to confirm the list contains every item, as the pinned
policy requires; that reminder is part of the server text, not a model flag.
"""

from policyops_contracts.money import Money
from policyops_contracts.retail import (
    Address,
    CancelEffect,
    Effect,
    ItemsEffect,
    OrderAddressEffect,
    PaymentChangeEffect,
    ReturnEffect,
    UserAddressEffect,
)


CONFIRM_PROMPT = "Reply yes to proceed, or tell me what to change."


def render_address(address: Address) -> str:
    street = ", ".join(part for part in (address.address1, address.address2) if part)
    return f"{street}, {address.city}, {address.state} {address.zip}, {address.country}"


def _settlement(difference: Money, payment_method_id: str) -> str:
    """Modification: the pinned simulator records a payment or refund on this method."""
    if difference.amount_minor > 0:
        return f"The price difference of {difference.display()} is charged to {payment_method_id}."
    if difference.amount_minor < 0:
        return f"The price difference of {(-difference).display()} is refunded to {payment_method_id}."
    return f"There is no price difference; {payment_method_id} is recorded for the change."


def _exchange_quote(difference: Money, payment_method_id: str) -> str:
    """Exchange: the pinned simulator only records the request and the quoted difference; nothing is paid now."""
    if difference.amount_minor > 0:
        quote = f"a price difference of {difference.display()} owed by the customer"
    elif difference.amount_minor < 0:
        quote = f"a price difference of {(-difference).display()} owed to the customer"
    else:
        quote = "no price difference"
    return (f"The exchange request records {quote}, with {payment_method_id} as the payment method for it. "
            "No charge or refund is made by this request.")


def _items(effect: ItemsEffect) -> list[str]:
    lines = [f"- item {line.item_id} ({line.price_before.display()}) -> item {line.new_item_id} "
             f"({line.price_after.display()}), product {line.product_id}" for line in effect.changes]
    if effect.kind == "modify_pending_order_items":
        head = f"Modify the following items in pending order {effect.order_id}:"
        once = ("This can be done only once for this order. Afterwards its status is 'pending (item modified)' "
                "and the order can no longer be modified or cancelled.")
        check = "Please confirm that this list includes every item you want to modify."
    else:
        head = f"Exchange the following items in delivered order {effect.order_id}:"
        once = ("An exchange can be requested only once for this order. Its status becomes 'exchange requested', "
                "return instructions are sent by email, and no new order is placed.")
        check = "Please confirm that this list includes every item you want to exchange."
    settlement = (_settlement if effect.kind == "modify_pending_order_items" else _exchange_quote)(
        effect.price_difference, effect.payment_method_id)
    return [head, *lines, settlement, once, check]


def render_effect(effect: Effect) -> str:
    if isinstance(effect, CancelEffect):
        refunds = [f"- {line.amount.display()} to {line.payment_method_id}, {line.timing}" for line in effect.refunds]
        body = [f"Cancel pending order {effect.order_id} (reason: {effect.reason}). Its status becomes 'cancelled'.",
                "Refunds:", *refunds]
    elif isinstance(effect, OrderAddressEffect):
        body = [f"Change the shipping address of pending order {effect.order_id}",
                f"from: {render_address(effect.address_before)}",
                f"to: {render_address(effect.address_after)}",
                "The order stays 'pending'."]
    elif isinstance(effect, PaymentChangeEffect):
        body = [f"Pay pending order {effect.order_id} ({effect.amount.display()}) with "
                f"{effect.to_payment_method_id} instead of {effect.from_payment_method_id}.",
                f"{effect.from_payment_method_id} is refunded {effect.refund_timing}. The order stays 'pending'."]
    elif isinstance(effect, ItemsEffect):
        body = _items(effect)
    elif isinstance(effect, ReturnEffect):
        body = [f"Return the following items from delivered order {effect.order_id}:",
                *[f"- item {line.item_id} ({line.price.display()})" for line in effect.items],
                f"Purchase price of these items: {effect.returned_items_price_total.display()}. "
                f"The refund goes to {effect.refund_payment_method_id}.",
                "The order status becomes 'return requested' and return instructions are sent by email."]
    elif isinstance(effect, UserAddressEffect):
        body = [f"Change the default address of user {effect.user_id}",
                f"from: {render_address(effect.address_before)}",
                f"to: {render_address(effect.address_after)}"]
    else:  # pragma: no cover - the Effect union is exhaustive
        raise TypeError(f"unknown effect {type(effect).__name__}")
    return "\n".join([*body, CONFIRM_PROMPT])
