"""Project a mutation's *actual* effect from the upstream state before and after it, tool by tool.

Nothing here trusts the tool's return value or its status. The projector:
1. diffs the whole state and refuses any changed path outside the tool's allowlist (the catalog never changes);
2. converts every changed amount and balance with `money_from_upstream` (no epsilon, no quantization);
3. rebuilds the typed `Effect` the change actually represents, using the approved call for pairing and
   multiplicity, and the catalog for each target's price and options.
The caller compares the result with the approved expected effect by equality.

Tool-specific semantics follow the pinned upstream:
- `modify_pending_order_items` changes item IDs, prices and options per position, appends one payment or refund line
  and changes a gift-card balance. Each target must carry *its own* variant's price and options; an aggregate that
  matches is not enough (upstream reuses the last variant).
- `exchange_delivered_order_items` records a request only: sorted old and new item IDs, the method and the price
  difference. Items, payments and balances stay unchanged; pairing comes from the approved call.
- `return_delivered_order_items` records sorted items and the refund method; upstream computes no refund amount.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from policyops_contracts.money import Money, MoneyError, money_from_upstream
from policyops_contracts.retail import (
    Address,
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
    PaymentChangeEffect,
    RefundLine,
    ReturnDeliveredOrderItems,
    ReturnEffect,
    ReturnLine,
    UserAddressEffect,
    WriteToolCall,
)


class EffectMismatch(ValueError):
    """The candidate state is not exactly the approved kind of change. `code` is a fixed reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class MoneyUnrepresentable(ValueError):
    """A changed amount or balance is not an exact two-decimal value."""


Path = tuple[str, ...]


def changed_paths(before: Any, after: Any, prefix: Path = ()) -> Iterator[Path]:
    """Every path whose value differs. A list that changes length is one changed path (the list itself)."""
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        for key in sorted(set(before) | set(after)):
            if key not in before or key not in after:
                yield (*prefix, str(key))
            else:
                yield from changed_paths(before[key], after[key], (*prefix, str(key)))
    elif isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        for index, (left, right) in enumerate(zip(before, after, strict=True)):
            yield from changed_paths(left, right, (*prefix, str(index)))
    elif type(before) is not type(after) or before != after:
        yield prefix


def _money(value: object) -> Money:
    try:
        return money_from_upstream(value)
    except MoneyError:
        raise MoneyUnrepresentable("an amount is not exact") from None


def _address(raw: Mapping[str, Any]) -> Address:
    try:
        return Address(**{k: raw[k] for k in ("address1", "address2", "city", "state", "country", "zip")})
    except (ValueError, KeyError):
        raise EffectMismatch("address_not_representable") from None


def _require_only(paths: Sequence[Path], allowed: Sequence[Path]) -> None:
    for path in paths:
        if not any(path[:len(rule)] == rule for rule in allowed):
            raise EffectMismatch("unexpected_change")


def _balances(before: Mapping[str, Any], after: Mapping[str, Any], user_id: str) -> dict[str, int]:
    """Exact gift-card balance deltas (minor units) for the user's methods that changed."""
    deltas = {}
    methods_before = before["users"][user_id]["payment_methods"]
    methods_after = after["users"][user_id]["payment_methods"]
    for method_id, method in methods_after.items():
        old = methods_before.get(method_id)
        if old is None or method.get("source") != old.get("source"):
            raise EffectMismatch("payment_methods_changed")
        if method.get("source") == "gift_card":
            delta = _money(method["balance"]).amount_minor - _money(old["balance"]).amount_minor
            if delta:
                deltas[method_id] = delta
        elif method != old:
            raise EffectMismatch("payment_methods_changed")
    return deltas


def _appended(order_before: Mapping[str, Any], order_after: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    history_before, history_after = order_before["payment_history"], order_after["payment_history"]
    if history_after[:len(history_before)] != history_before:
        raise EffectMismatch("payment_history_rewritten")
    return list(history_after[len(history_before):])


def _timing(method_id: str) -> str:
    return "immediately" if method_id.startswith("gift_card_") else "5 to 7 business days"


def _variant(state: Mapping[str, Any], product_id: str, item_id: str) -> Mapping[str, Any]:
    variant = state["products"].get(product_id, {}).get("variants", {}).get(item_id)
    if variant is None:
        raise EffectMismatch("variant_not_in_catalog")
    return variant  # type: ignore[no-any-return]


def _positions(items: Sequence[Mapping[str, Any]], wanted: Sequence[str]) -> list[int]:
    """Distinct positions for the listed item IDs, first unassigned match each (multiplicity preserved)."""
    used: set[int] = set()
    positions = []
    for item_id in wanted:
        index = next((i for i, item in enumerate(items) if item["item_id"] == item_id and i not in used), None)
        if index is None:
            raise EffectMismatch("item_not_in_order")
        used.add(index)
        positions.append(index)
    return positions


def project(call: WriteToolCall, before: Mapping[str, Any], after: Mapping[str, Any], customer_id: str) -> Effect:
    """The typed effect the change from `before` to `after` actually is (JSON-mode dumps of the upstream DB)."""
    paths = list(changed_paths(before, after))
    if any(path[:1] == ("products",) for path in paths) or set(before) != set(after):
        raise EffectMismatch("catalog_changed")
    if isinstance(call, ModifyUserAddress):
        _require_only(paths, [("users", call.user_id, "address")])
        return UserAddressEffect(user_id=call.user_id,
                                 address_before=_address(before["users"][call.user_id]["address"]),
                                 address_after=_address(after["users"][call.user_id]["address"]))
    oid = call.order_id
    order_before, order_after = before["orders"][oid], after["orders"][oid]
    order_path = ("orders", oid)
    gift_cards = [("users", customer_id, "payment_methods", m, "balance")
                  for m, v in before["users"][customer_id]["payment_methods"].items() if v.get("source") == "gift_card"]
    if isinstance(call, CancelPendingOrder):
        _require_only(paths, [(*order_path, "status"), (*order_path, "cancel_reason"),
                              (*order_path, "payment_history"), *gift_cards])
        if (order_before["status"], order_after["status"]) != ("pending", "cancelled") or \
                order_after.get("cancel_reason") != call.reason:
            raise EffectMismatch("status_mismatch")
        appended = _appended(order_before, order_after)
        prior = order_before["payment_history"]
        if len(appended) != len(prior):
            raise EffectMismatch("refund_lines_mismatch")
        refunds = []
        expected_deltas: Counter[str] = Counter()
        for paid, refund in zip(prior, appended, strict=True):
            if refund["transaction_type"] != "refund" or refund["payment_method_id"] != paid["payment_method_id"] \
                    or _money(refund["amount"]) != _money(paid["amount"]):
                raise EffectMismatch("refund_lines_mismatch")
            method = refund["payment_method_id"]
            refunds.append(RefundLine(payment_method_id=method, amount=_money(refund["amount"]),
                                      timing=_timing(method)))  # type: ignore[arg-type]
            if method.startswith("gift_card_"):
                expected_deltas[method] += _money(refund["amount"]).amount_minor
        if _balances(before, after, customer_id) != {k: v for k, v in expected_deltas.items() if v}:
            raise EffectMismatch("balance_mismatch")
        return CancelEffect(order_id=oid, reason=call.reason, refunds=tuple(refunds))
    if isinstance(call, ModifyPendingOrderAddress):
        _require_only(paths, [(*order_path, "address")])
        if order_after["status"] != "pending":
            raise EffectMismatch("status_mismatch")  # OrderAddressEffect covers a plain pending order only
        return OrderAddressEffect(order_id=oid, address_before=_address(order_before["address"]),
                                  address_after=_address(order_after["address"]))
    if isinstance(call, ModifyPendingOrderPayment):
        _require_only(paths, [(*order_path, "payment_history"), *gift_cards])
        prior, appended = order_before["payment_history"], _appended(order_before, order_after)
        if order_after["status"] != "pending" or len(prior) != 1 or len(appended) != 2:
            raise EffectMismatch("payment_lines_mismatch")
        amount = _money(prior[0]["amount"])
        old_method = prior[0]["payment_method_id"]
        pay, refund = appended
        if (pay["transaction_type"], pay["payment_method_id"], _money(pay["amount"])) != \
                ("payment", call.payment_method_id, amount) or \
                (refund["transaction_type"], refund["payment_method_id"], _money(refund["amount"])) != \
                ("refund", old_method, amount):
            raise EffectMismatch("payment_lines_mismatch")
        expected = Counter[str]()
        if call.payment_method_id.startswith("gift_card_"):
            expected[call.payment_method_id] -= amount.amount_minor
        if old_method.startswith("gift_card_"):
            expected[old_method] += amount.amount_minor
        if _balances(before, after, customer_id) != {k: v for k, v in expected.items() if v}:
            raise EffectMismatch("balance_mismatch")
        try:
            return PaymentChangeEffect(order_id=oid, from_payment_method_id=old_method,
                                       to_payment_method_id=call.payment_method_id, amount=amount,
                                       refund_timing=_timing(old_method))  # type: ignore[arg-type]
        except ValueError:
            raise EffectMismatch("effect_not_representable") from None
    if isinstance(call, ModifyPendingOrderItems):
        return _modify_items(call, before, after, paths, order_path, gift_cards, customer_id)
    if isinstance(call, ExchangeDeliveredOrderItems):
        return _exchange(call, before, after, paths, order_path)
    if isinstance(call, ReturnDeliveredOrderItems):
        _require_only(paths, [(*order_path, "status"), (*order_path, "return_items"),
                              (*order_path, "return_payment_method_id")])
        if (order_before["status"], order_after["status"]) != ("delivered", "return requested") or \
                order_after.get("return_items") != sorted(call.item_ids) or \
                order_after.get("return_payment_method_id") != call.payment_method_id:
            raise EffectMismatch("return_request_mismatch")
        positions = _positions(order_before["items"], call.item_ids)
        lines = tuple(ReturnLine(item_id=call.item_ids[n], price=_money(order_before["items"][p]["price"]))
                      for n, p in enumerate(positions))
        total = Money(amount_minor=sum(line.price.amount_minor for line in lines))
        return ReturnEffect(order_id=oid, items=lines, returned_items_price_total=total,
                            refund_payment_method_id=call.payment_method_id)
    raise EffectMismatch("unsupported_tool")  # pragma: no cover - the union is exhaustive


def _modify_items(call: ModifyPendingOrderItems, before: Mapping[str, Any], after: Mapping[str, Any],
                  paths: Sequence[Path], order_path: Path, gift_cards: Sequence[Path], customer_id: str) -> Effect:
    order_before, order_after = before["orders"][call.order_id], after["orders"][call.order_id]
    positions = _positions(order_before["items"], call.item_ids)
    # Per target position only the fields upstream legitimately rewrites: the item ID, the price and the options.
    # Any other item field (its name, its product) changing is not the approved change.
    item_fields = [(*order_path, "items", str(p), field) for p in positions for field in ("item_id", "price",
                                                                                           "options")]
    _require_only(paths, [*item_fields, (*order_path, "payment_history"), (*order_path, "status"), *gift_cards])
    if (order_before["status"], order_after["status"]) != ("pending", "pending (item modified)") or \
            len(order_after["items"]) != len(order_before["items"]):
        raise EffectMismatch("status_mismatch")
    lines = []
    for old_id, new_id, position in zip(call.item_ids, call.new_item_ids, positions, strict=True):
        old, new = order_before["items"][position], order_after["items"][position]
        variant = _variant(before, old["product_id"], new_id)
        if new["item_id"] != new_id or new["product_id"] != old["product_id"] or new["options"] != variant["options"] \
                or _money(new["price"]) != _money(variant["price"]):
            raise EffectMismatch("item_target_mismatch")  # e.g. the price/options of another target
        try:
            lines.append(ItemChangeLine(item_id=old_id, new_item_id=new_id, product_id=old["product_id"],
                                        price_before=_money(old["price"]), price_after=_money(variant["price"])))
        except ValueError:
            raise EffectMismatch("effect_not_representable") from None
    difference = sum(line.price_after.amount_minor - line.price_before.amount_minor for line in lines)
    appended = _appended(order_before, order_after)
    if len(appended) != 1:
        raise EffectMismatch("payment_lines_mismatch")
    (line,) = appended
    kind = "payment" if difference > 0 else "refund"
    if (line["transaction_type"], line["payment_method_id"]) != (kind, call.payment_method_id) or \
            _money(line["amount"]).amount_minor != abs(difference):
        raise EffectMismatch("payment_lines_mismatch")
    expected = {call.payment_method_id: -difference} if call.payment_method_id.startswith("gift_card_") and \
        difference else {}
    if _balances(before, after, customer_id) != expected:
        raise EffectMismatch("balance_mismatch")
    return ItemsEffect(kind="modify_pending_order_items", order_id=call.order_id, changes=tuple(lines),
                       price_difference=Money(amount_minor=difference), payment_method_id=call.payment_method_id,
                       status_before="pending", status_after="pending (item modified)")


EXCHANGE_FIELDS = ("status", "exchange_items", "exchange_new_items", "exchange_payment_method_id",
                   "exchange_price_difference")


def _exchange(call: ExchangeDeliveredOrderItems, before: Mapping[str, Any], after: Mapping[str, Any],
              paths: Sequence[Path], order_path: Path) -> Effect:
    order_before, order_after = before["orders"][call.order_id], after["orders"][call.order_id]
    _require_only(paths, [(*order_path, field) for field in EXCHANGE_FIELDS])  # items, payments, balances unchanged
    if (order_before["status"], order_after["status"]) != ("delivered", "exchange requested") or \
            order_after.get("exchange_items") != sorted(call.item_ids) or \
            order_after.get("exchange_new_items") != sorted(call.new_item_ids) or \
            order_after.get("exchange_payment_method_id") != call.payment_method_id:
        raise EffectMismatch("exchange_request_mismatch")
    _positions(order_before["items"], call.item_ids)  # every listed item, with multiplicity, is in the order
    lines = []
    for old_id, new_id in zip(call.item_ids, call.new_item_ids, strict=True):
        old = next(item for item in order_before["items"] if item["item_id"] == old_id)  # upstream's first match
        variant = _variant(before, old["product_id"], new_id)
        try:
            lines.append(ItemChangeLine(item_id=old_id, new_item_id=new_id, product_id=old["product_id"],
                                        price_before=_money(old["price"]), price_after=_money(variant["price"])))
        except ValueError:
            raise EffectMismatch("effect_not_representable") from None
    difference = sum(line.price_after.amount_minor - line.price_before.amount_minor for line in lines)
    if _money(order_after["exchange_price_difference"]).amount_minor != difference:
        raise EffectMismatch("exchange_difference_mismatch")
    return ItemsEffect(kind="exchange_delivered_order_items", order_id=call.order_id, changes=tuple(lines),
                       price_difference=Money(amount_minor=difference), payment_method_id=call.payment_method_id,
                       status_before="delivered", status_after="exchange requested")
