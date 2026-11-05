"""Run one upstream retail tool on an isolated candidate and classify the result. No I/O, no database.

Writes: the committed state is decoded twice, once as the untouched `before` view and once as the candidate that the
upstream method mutates. A business error from upstream, an effect that is not the approved one, or an amount that is
not exact discards the whole candidate. Only an exact match yields new state bytes.

Scope (the case's bound customer): a write or read naming an order, user or payment method that is not the
customer's is refused as `not_in_scope` before upstream runs, with the same answer whether it exists or not. User
lookups return only the bound customer. The catalog is shared and immutable (version 1 within the fixture).

CPU is bounded structurally, not preempted: the fixture is fixed (about 2.9 MB, codec cap 8 MiB), request bodies
are capped at 64 KiB before parsing, call lists are at most 50 items, and the calculator only accepts the typed,
size- and depth-bounded grammar of `policyops_contracts.retail.Calculate`. Database lock and statement timeouts do
not interrupt this synchronous work.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
from typing import Any, Literal

from policyops_contracts.money import MoneyError, money_from_upstream
from policyops_contracts.retail import (
    Address,
    Calculate,
    Effect,
    ExchangeDeliveredOrderItems,
    ModifyPendingOrderItems,
    ModifyUserAddress,
    PaymentRecord,
    WriteToolCall,
)
from policyops_contracts.retail_service import (
    CalculationOutput,
    ExchangeRequestDetail,
    FulfillmentDetail,
    OptionValue,
    OrderDetail,
    OrderItemDetail,
    OrderOutput,
    PaymentMethodDetail,
    ProductOutput,
    ProductType,
    ProductTypesOutput,
    ReadCall,
    ReadOutput,
    ReturnRequestDetail,
    UserDetail,
    UserIdOutput,
    UserOutput,
    VariantDetail,
    VariantOutput,
)
from policyops_evals.retail_sim import codec
from policyops_evals.retail_sim.effects import EffectMismatch, MoneyUnrepresentable, project
from policyops_evals.retail_sim.fixture import Upstream


Resource = tuple[Literal["user", "order", "product"], str]
CATALOG_VERSION = 1


class NotInScope(Exception):
    """The request names something outside the case's customer. Answered without revealing whether it exists."""


class ReadRejected(Exception):
    """Upstream refused the read (for example an unknown product)."""


@dataclass(frozen=True)
class Attempt:
    outcome: Literal["committed", "upstream_rejected", "effect_mismatch", "money_unrepresentable"]
    code: str | None
    state: bytes | None = None
    effect: Effect | None = None
    changed: frozenset[Resource] = frozenset()


def _arguments(call: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = call.model_dump(mode="json", exclude={"tool"})
    return arguments


def check_scope(state: Mapping[str, Any], call: WriteToolCall, customer_id: str) -> None:
    user = state["users"].get(customer_id)
    if user is None:
        raise NotInScope
    if isinstance(call, ModifyUserAddress):
        if call.user_id != customer_id:
            raise NotInScope
        return
    order = state["orders"].get(call.order_id)
    if order is None or order["user_id"] != customer_id:
        raise NotInScope
    method = getattr(call, "payment_method_id", None)
    if method is not None and method not in user["payment_methods"]:
        raise NotInScope


def core_versions(call: WriteToolCall, customer_id: str) -> frozenset[Resource]:
    """The user and order versions every write must name (the catalog is checked separately)."""
    if isinstance(call, ModifyUserAddress):
        return frozenset({("user", call.user_id)})
    return frozenset({("order", call.order_id), ("user", customer_id)})


def unresolved_items(state: Mapping[str, Any], call: WriteToolCall) -> bool:
    """True when the call names an item that is not in the order (upstream will reject it)."""
    if not isinstance(call, ModifyPendingOrderItems | ExchangeDeliveredOrderItems):
        return False
    present = {item["item_id"] for item in state["orders"][call.order_id]["items"]}
    return any(item_id not in present for item_id in call.item_ids)


def required_versions(state: Mapping[str, Any], call: WriteToolCall, customer_id: str) -> frozenset[Resource]:
    """Exactly the resources the tool reads or changes; the request must name each once with its current version."""
    if isinstance(call, ModifyUserAddress):
        return frozenset({("user", call.user_id)})
    needed: set[Resource] = {("order", call.order_id), ("user", customer_id)}
    if isinstance(call, ModifyPendingOrderItems | ExchangeDeliveredOrderItems):
        items = state["orders"][call.order_id]["items"]
        for item_id in call.item_ids:
            match = next((item for item in items if item["item_id"] == item_id), None)
            if match is not None:
                needed.add(("product", match["product_id"]))
    return frozenset(needed)


def changed_resources(before: Mapping[str, Any], after: Mapping[str, Any]) -> frozenset[Resource]:
    changed: set[Resource] = set()
    for kind, table in (("user", "users"), ("order", "orders")):
        for key, value in after[table].items():
            if before[table].get(key) != value:
                changed.add((kind, key))  # type: ignore[arg-type]
    return frozenset(changed)


def mutate(upstream: Upstream, raw: bytes, call: WriteToolCall, expected: Effect, customer_id: str) -> Attempt:
    before_db = codec.decode(raw, upstream.retail_db)
    before = codec.dump(before_db)
    check_scope(before, call, customer_id)
    candidate = codec.decode(raw, upstream.retail_db)  # a fresh, isolated copy; discarded unless it commits
    try:
        getattr(upstream.retail_tools(candidate), call.tool)(**_arguments(call))
    except ValueError:
        return Attempt("upstream_rejected", "upstream_rejected")
    after = codec.dump(candidate)
    try:
        actual = project(call, before, after, customer_id)
    except MoneyUnrepresentable:
        return Attempt("money_unrepresentable", "money_unrepresentable")
    except EffectMismatch as mismatch:
        return Attempt("effect_mismatch", mismatch.code)
    if actual != expected:
        return Attempt("effect_mismatch", "differs_from_expected")
    try:
        state = codec.encode(candidate)
    except codec.StateTooLarge:
        return Attempt("effect_mismatch", "state_too_large")
    return Attempt("committed", None, state, actual, changed_resources(before, after))


# -- reads ------------------------------------------------------------------------------------------------------

def _money(value: object) -> Any:
    try:
        return money_from_upstream(value)
    except MoneyError:
        raise ReadRejected("an amount is not exact") from None


def _address(raw: Mapping[str, Any]) -> Address:
    return Address(**{k: raw[k] for k in ("address1", "address2", "city", "state", "country", "zip")})


def _options(raw: Mapping[str, str]) -> tuple[OptionValue, ...]:
    return tuple(OptionValue(name=name, value=value) for name, value in sorted(raw.items()))


def user_detail(state: Mapping[str, Any], user: Mapping[str, Any], version: int) -> UserDetail:
    """The customer's own user, with only the order IDs that are really theirs (checked against each order)."""
    methods = []
    for method_id, method in user["payment_methods"].items():
        kind = method["source"]
        methods.append(PaymentMethodDetail(
            payment_method_id=method_id, kind=kind,
            gift_card_balance=_money(method["balance"]) if kind == "gift_card" else None,
            brand=method.get("brand") if kind == "credit_card" else None,
            last_four=method.get("last_four") if kind == "credit_card" else None))
    owned = tuple(oid for oid in user["orders"]
                  if oid in state["orders"] and state["orders"][oid]["user_id"] == user["user_id"])
    return UserDetail(user_id=user["user_id"], version=version, first_name=user["name"]["first_name"],
                      last_name=user["name"]["last_name"], email=user["email"], address=_address(user["address"]),
                      payment_methods=tuple(methods), order_ids=owned)


def order_detail(order: Mapping[str, Any], version: int) -> OrderDetail:
    exchange = None
    if order.get("exchange_items") is not None:
        exchange = ExchangeRequestDetail(item_ids=tuple(order["exchange_items"]),
                                         new_item_ids=tuple(order["exchange_new_items"] or ()),
                                         payment_method_id=order["exchange_payment_method_id"],
                                         price_difference=_money(order["exchange_price_difference"]))
    returned = None
    if order.get("return_items") is not None:
        returned = ReturnRequestDetail(item_ids=tuple(order["return_items"]),
                                       payment_method_id=order["return_payment_method_id"])
    return OrderDetail(
        order_id=order["order_id"], user_id=order["user_id"], version=version, status=order["status"],
        address=_address(order["address"]),
        items=tuple(OrderItemDetail(item_id=i["item_id"], product_id=i["product_id"], name=i["name"],
                                    price=_money(i["price"]), options=_options(i["options"]))
                    for i in order["items"]),
        fulfillments=tuple(FulfillmentDetail(tracking_ids=tuple(f["tracking_id"]), item_ids=tuple(f["item_ids"]))
                           for f in order["fulfillments"]),
        payment_history=tuple(PaymentRecord(transaction_type=p["transaction_type"],
                                            payment_method_id=p["payment_method_id"], amount=_money(p["amount"]))
                              for p in order["payment_history"]),
        cancel_reason=order.get("cancel_reason"), exchange_request=exchange, return_request=returned)


def variant_detail(product_id: str, product_name: str, variant: Mapping[str, Any]) -> VariantDetail:
    return VariantDetail(product_id=product_id, product_name=product_name, item_id=variant["item_id"],
                         available=variant["available"], price=_money(variant["price"]),
                         options=_options(variant["options"]), product_version=CATALOG_VERSION)


def read(upstream: Upstream, raw: bytes, call: ReadCall, customer_id: str,
         version: Callable[[Resource], int]) -> tuple[ReadOutput, frozenset[Resource]]:
    """Run one read on a decoded copy (nothing is persisted). Returns the output and the resources it shows."""
    db = codec.decode(raw, upstream.retail_db)
    state = codec.dump(db)
    tools = upstream.retail_tools(db)
    try:
        if call.tool in ("find_user_id_by_email", "find_user_id_by_name_zip"):
            found = getattr(tools, call.tool)(**_arguments(call))
            if found != customer_id:
                raise NotInScope
            return UserIdOutput(user_id=found), frozenset()
        if call.tool == "get_user_details":
            if call.user_id != customer_id:
                raise NotInScope
            resource: Resource = ("user", customer_id)
            return UserOutput(user=user_detail(state, state["users"][customer_id], version(resource))), \
                frozenset({resource})
        if call.tool == "get_order_details":
            order = state["orders"].get(call.order_id)
            if order is None or order["user_id"] != customer_id:
                raise NotInScope
            resource = ("order", call.order_id)
            return OrderOutput(order=order_detail(order, version(resource))), frozenset({resource})
        if call.tool == "get_product_details":
            product = tools.get_product_details(call.product_id).model_dump(mode="json")
            variants = tuple(variant_detail(product["product_id"], product["name"], v)
                             for v in product["variants"].values())
            return ProductOutput(product_id=product["product_id"], name=product["name"], variants=variants), \
                frozenset({("product", product["product_id"])})
        if call.tool == "get_item_details":
            variant = tools.get_item_details(call.item_id).model_dump(mode="json")
            product_id = next(pid for pid, product in state["products"].items()
                              if variant["item_id"] in product["variants"])
            return VariantOutput(variant=variant_detail(product_id, state["products"][product_id]["name"],
                                                        variant)), frozenset({("product", product_id)})
        if call.tool == "list_all_product_types":
            listed = json.loads(tools.list_all_product_types())
            return ProductTypesOutput(types=tuple(ProductType(name=name, product_id=pid)
                                                  for name, pid in sorted(listed.items()))), frozenset()
        if not isinstance(call, Calculate):  # pragma: no cover - the read union is exhaustive
            raise ReadRejected("unsupported_read")
        return CalculationOutput(value=tools.calculate(call.expression)), frozenset()
    except ValueError:
        raise ReadRejected("upstream_rejected") from None
