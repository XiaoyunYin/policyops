"""Typed retail tool calls, state snapshots and displayed effects.

Tool names and argument names follow the pinned upstream retail toolkit
(tau2 commit 19f13ea3). Order statuses use the executable upstream spellings,
including "pending (item modified)"; the policy prose spells it
"pending (items modifed)", and the code's value is the one the simulator
produces. Item lists keep multiplicity and order: upstream pairs item_ids[i]
with new_item_ids[i] and allows duplicates.
"""

import ast
from enum import StrEnum
import math
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.money import Money
from policyops_contracts.scalars import (
    ItemId,
    OrderId,
    PaymentMethodId,
    PositiveVersion,
    ProductId,
    UserId,
)


OrderStatus = Literal[
    "pending", "processed", "delivered", "cancelled",
    "pending (item modified)", "exchange requested", "return requested",
]
CancelReason = Literal["no longer needed", "ordered by mistake"]
PaymentKind = Literal["credit_card", "paypal", "gift_card"]
AddressLine = Annotated[str, StringConstraints(min_length=0, max_length=100, pattern=r"^[^\x00-\x1f\x7f]*$")]
RequiredLine = Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$")]
Email = Annotated[str, StringConstraints(max_length=254, pattern=r"^[^@\s]{1,64}@[^@\s]{1,189}\.[A-Za-z]{2,}$")]
Zip = Annotated[str, StringConstraints(pattern=r"^\d{5}$")]
ItemList = Annotated[tuple[ItemId, ...], Field(min_length=1, max_length=50)]
HANDOFF_MESSAGE = "YOU ARE BEING TRANSFERRED TO A HUMAN AGENT. PLEASE HOLD ON."


class ToolName(StrEnum):
    FIND_USER_ID_BY_EMAIL = "find_user_id_by_email"
    FIND_USER_ID_BY_NAME_ZIP = "find_user_id_by_name_zip"
    GET_USER_DETAILS = "get_user_details"
    GET_ORDER_DETAILS = "get_order_details"
    GET_PRODUCT_DETAILS = "get_product_details"
    GET_ITEM_DETAILS = "get_item_details"
    LIST_ALL_PRODUCT_TYPES = "list_all_product_types"
    CALCULATE = "calculate"
    TRANSFER_TO_HUMAN_AGENTS = "transfer_to_human_agents"
    CANCEL_PENDING_ORDER = "cancel_pending_order"
    MODIFY_PENDING_ORDER_ADDRESS = "modify_pending_order_address"
    MODIFY_PENDING_ORDER_PAYMENT = "modify_pending_order_payment"
    MODIFY_PENDING_ORDER_ITEMS = "modify_pending_order_items"
    RETURN_DELIVERED_ORDER_ITEMS = "return_delivered_order_items"
    EXCHANGE_DELIVERED_ORDER_ITEMS = "exchange_delivered_order_items"
    MODIFY_USER_ADDRESS = "modify_user_address"


class ToolKind(StrEnum):
    READ = "read"
    WRITE = "write"
    GENERIC = "generic"


LOOKUP_TOOLS = frozenset({ToolName.FIND_USER_ID_BY_EMAIL, ToolName.FIND_USER_ID_BY_NAME_ZIP})
WRITE_TOOLS = frozenset({
    ToolName.CANCEL_PENDING_ORDER, ToolName.MODIFY_PENDING_ORDER_ADDRESS, ToolName.MODIFY_PENDING_ORDER_PAYMENT,
    ToolName.MODIFY_PENDING_ORDER_ITEMS, ToolName.RETURN_DELIVERED_ORDER_ITEMS,
    ToolName.EXCHANGE_DELIVERED_ORDER_ITEMS, ToolName.MODIFY_USER_ADDRESS,
})
GENERIC_TOOLS = frozenset({ToolName.CALCULATE, ToolName.TRANSFER_TO_HUMAN_AGENTS})
TOOL_KINDS = {
    name: ToolKind.WRITE if name in WRITE_TOOLS else ToolKind.GENERIC if name in GENERIC_TOOLS else ToolKind.READ
    for name in ToolName
}


class Address(WireModel):
    address1: RequiredLine
    address2: AddressLine
    city: RequiredLine
    state: RequiredLine
    country: RequiredLine
    zip: Zip


# --- Tool calls (one model per upstream tool; `tool` discriminates) -------------------------------


class FindUserIdByEmail(WireModel):
    tool: Literal["find_user_id_by_email"] = "find_user_id_by_email"
    email: Email


class FindUserIdByNameZip(WireModel):
    tool: Literal["find_user_id_by_name_zip"] = "find_user_id_by_name_zip"
    first_name: RequiredLine
    last_name: RequiredLine
    zip: Zip


class GetUserDetails(WireModel):
    tool: Literal["get_user_details"] = "get_user_details"
    user_id: UserId


class GetOrderDetails(WireModel):
    tool: Literal["get_order_details"] = "get_order_details"
    order_id: OrderId


class GetProductDetails(WireModel):
    tool: Literal["get_product_details"] = "get_product_details"
    product_id: ProductId


class GetItemDetails(WireModel):
    tool: Literal["get_item_details"] = "get_item_details"
    item_id: ItemId


class ListAllProductTypes(WireModel):
    tool: Literal["list_all_product_types"] = "list_all_product_types"


_CALC_OPERATORS = (ast.Add, ast.Sub, ast.Mult, ast.Div)
_CALC_MAX_NODES = 64
_CALC_MAX_DEPTH = 12
_CALC_MAX_LITERAL = 10**9


def _check_calculation(expression: str) -> str:
    """Validate the calculator grammar without evaluating anything.

    Upstream `calculate` evaluates the expression after only a character check,
    which admits ** and //. Only + - * /, unary signs, parentheses and finite
    numeric literals of bounded magnitude are accepted here, with bounded size
    and nesting. A result is never exact-money evidence.
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ValueError("not an arithmetic expression") from exc
    nodes = 0

    def visit(node: ast.AST, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _CALC_MAX_NODES or depth > _CALC_MAX_DEPTH:
            raise ValueError("expression is too large")
        if isinstance(node, ast.BinOp) and isinstance(node.op, _CALC_OPERATORS):
            visit(node.left, depth + 1)
            visit(node.right, depth + 1)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
            visit(node.operand, depth + 1)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, int | float)
              and not isinstance(node.value, bool)):
            if not math.isfinite(node.value) or abs(node.value) > _CALC_MAX_LITERAL:
                raise ValueError("numeric literal out of range")
        else:
            raise ValueError(f"unsupported calculator element {type(node).__name__}")

    visit(tree.body, 1)
    return expression


class Calculate(WireModel):
    tool: Literal["calculate"] = "calculate"
    expression: Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r"^[0-9+\-*/(). ]+$"),
                          AfterValidator(_check_calculation)]


class TransferToHumanAgents(WireModel):
    tool: Literal["transfer_to_human_agents"] = "transfer_to_human_agents"
    summary: Annotated[str, StringConstraints(min_length=1, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f\x7f]+$")]


class CancelPendingOrder(WireModel):
    tool: Literal["cancel_pending_order"] = "cancel_pending_order"
    order_id: OrderId
    reason: CancelReason


class ModifyPendingOrderAddress(WireModel):
    tool: Literal["modify_pending_order_address"] = "modify_pending_order_address"
    order_id: OrderId
    address1: RequiredLine
    address2: AddressLine
    city: RequiredLine
    state: RequiredLine
    country: RequiredLine
    zip: Zip

    def address(self) -> Address:
        return Address(address1=self.address1, address2=self.address2, city=self.city, state=self.state,
                       country=self.country, zip=self.zip)


class ModifyPendingOrderPayment(WireModel):
    tool: Literal["modify_pending_order_payment"] = "modify_pending_order_payment"
    order_id: OrderId
    payment_method_id: PaymentMethodId


class _PairedItems(WireModel):
    order_id: OrderId
    item_ids: ItemList
    new_item_ids: ItemList
    payment_method_id: PaymentMethodId

    @model_validator(mode="after")
    def _pairs(self) -> "_PairedItems":
        if len(self.item_ids) != len(self.new_item_ids):
            raise ValueError("item_ids and new_item_ids must pair one to one")
        return self


class ModifyPendingOrderItems(_PairedItems):
    tool: Literal["modify_pending_order_items"] = "modify_pending_order_items"


class ExchangeDeliveredOrderItems(_PairedItems):
    tool: Literal["exchange_delivered_order_items"] = "exchange_delivered_order_items"


class ReturnDeliveredOrderItems(WireModel):
    tool: Literal["return_delivered_order_items"] = "return_delivered_order_items"
    order_id: OrderId
    item_ids: ItemList
    payment_method_id: PaymentMethodId


class ModifyUserAddress(WireModel):
    tool: Literal["modify_user_address"] = "modify_user_address"
    user_id: UserId
    address1: RequiredLine
    address2: AddressLine
    city: RequiredLine
    state: RequiredLine
    country: RequiredLine
    zip: Zip

    def address(self) -> Address:
        return Address(address1=self.address1, address2=self.address2, city=self.city, state=self.state,
                       country=self.country, zip=self.zip)


ReadToolCall = Annotated[
    FindUserIdByEmail | FindUserIdByNameZip | GetUserDetails | GetOrderDetails | GetProductDetails
    | GetItemDetails | ListAllProductTypes | Calculate,
    Field(discriminator="tool"),
]
WriteToolCall = Annotated[
    CancelPendingOrder | ModifyPendingOrderAddress | ModifyPendingOrderPayment | ModifyPendingOrderItems
    | ReturnDeliveredOrderItems | ExchangeDeliveredOrderItems | ModifyUserAddress,
    Field(discriminator="tool"),
]
ToolCall = Annotated[
    FindUserIdByEmail | FindUserIdByNameZip | GetUserDetails | GetOrderDetails | GetProductDetails
    | GetItemDetails | ListAllProductTypes | Calculate | TransferToHumanAgents
    | CancelPendingOrder | ModifyPendingOrderAddress | ModifyPendingOrderPayment | ModifyPendingOrderItems
    | ReturnDeliveredOrderItems | ExchangeDeliveredOrderItems | ModifyUserAddress,
    Field(discriminator="tool"),
]


# --- Versioned state snapshots (exact money; produced by the simulator adapter, T16) ---------------


class ResourceVersion(WireModel):
    kind: Literal["user", "order", "product"]
    resource_id: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    version: PositiveVersion


class PaymentMethodSnapshot(WireModel):
    payment_method_id: PaymentMethodId
    kind: PaymentKind
    gift_card_balance: Money | None = None

    @model_validator(mode="after")
    def _balance_only_for_gift_cards(self) -> "PaymentMethodSnapshot":
        if (self.kind == "gift_card") != (self.gift_card_balance is not None):
            raise ValueError("exactly gift cards carry a balance")
        if not self.payment_method_id.startswith(self.kind):
            raise ValueError("payment method id prefix must match its kind")
        return self


class UserSnapshot(WireModel):
    user_id: UserId
    version: PositiveVersion
    address: Address
    payment_methods: Annotated[tuple[PaymentMethodSnapshot, ...], Field(max_length=50)]

    @model_validator(mode="after")
    def _unique_methods(self) -> "UserSnapshot":
        ids = [method.payment_method_id for method in self.payment_methods]
        if len(ids) != len(set(ids)):
            raise ValueError("payment method IDs must be unique within a user snapshot")
        return self


class OrderItemSnapshot(WireModel):
    item_id: ItemId
    product_id: ProductId
    price: Money


class PaymentRecord(WireModel):
    transaction_type: Literal["payment", "refund"]
    payment_method_id: PaymentMethodId
    amount: Money


class OrderSnapshot(WireModel):
    order_id: OrderId
    user_id: UserId
    version: PositiveVersion
    status: OrderStatus
    address: Address
    items: Annotated[tuple[OrderItemSnapshot, ...], Field(min_length=1, max_length=50)]
    payment_history: Annotated[tuple[PaymentRecord, ...], Field(min_length=1, max_length=50)]


class OrderOperationHistory(WireModel):
    """Successful write executions recorded for one order (from execution receipts, T19).

    `complete` is true only when the source can vouch that no other successful
    write on this order exists. Order status alone does not prove that, so rules
    that limit repetition escalate when history is incomplete.
    """

    order_id: OrderId
    complete: bool
    successful_tools: Annotated[tuple[ToolName, ...], Field(max_length=50)]


class VariantSnapshot(WireModel):
    product_id: ProductId
    item_id: ItemId
    available: bool
    price: Money
    product_version: PositiveVersion


# --- Displayed effects (computed by policyops.domain; the exact content shown for consent) --------


class RefundLine(WireModel):
    payment_method_id: PaymentMethodId
    amount: Money
    timing: Literal["immediately", "5 to 7 business days"]


class ItemChangeLine(WireModel):
    item_id: ItemId
    new_item_id: ItemId
    product_id: ProductId
    price_before: Money
    price_after: Money

    @model_validator(mode="after")
    def _different_option(self) -> "ItemChangeLine":
        if self.item_id == self.new_item_id:
            raise ValueError("an item change must name a different item")
        return self


class CancelEffect(WireModel):
    kind: Literal["cancel_pending_order"] = "cancel_pending_order"
    order_id: OrderId
    reason: CancelReason
    status_before: Literal["pending"] = "pending"
    status_after: Literal["cancelled"] = "cancelled"
    refunds: Annotated[tuple[RefundLine, ...], Field(min_length=1, max_length=50)]

    @model_validator(mode="after")
    def _refunds_non_negative(self) -> "CancelEffect":
        if any(line.amount.amount_minor < 0 for line in self.refunds):
            raise ValueError("refund amounts cannot be negative")
        return self


class OrderAddressEffect(WireModel):
    kind: Literal["modify_pending_order_address"] = "modify_pending_order_address"
    order_id: OrderId
    address_before: Address
    address_after: Address
    status_after: Literal["pending"] = "pending"


class PaymentChangeEffect(WireModel):
    kind: Literal["modify_pending_order_payment"] = "modify_pending_order_payment"
    order_id: OrderId
    from_payment_method_id: PaymentMethodId
    to_payment_method_id: PaymentMethodId
    amount: Money
    refund_timing: Literal["immediately", "5 to 7 business days"]
    status_after: Literal["pending"] = "pending"

    @model_validator(mode="after")
    def _different_method(self) -> "PaymentChangeEffect":
        if self.from_payment_method_id == self.to_payment_method_id:
            raise ValueError("the new payment method must differ from the original")
        if self.amount.amount_minor < 0:
            raise ValueError("the order amount cannot be negative")
        if (self.refund_timing == "immediately") != self.from_payment_method_id.startswith("gift_card_"):
            raise ValueError("refund timing must follow the original payment method's kind")
        return self


class ItemsEffect(WireModel):
    kind: Literal["modify_pending_order_items", "exchange_delivered_order_items"]
    order_id: OrderId
    changes: Annotated[tuple[ItemChangeLine, ...], Field(min_length=1, max_length=50)]
    price_difference: Money
    payment_method_id: PaymentMethodId
    status_before: Literal["pending", "delivered"]
    status_after: Literal["pending (item modified)", "exchange requested"]
    one_time_action: Literal[True] = True

    @model_validator(mode="after")
    def _derivable(self) -> "ItemsEffect":
        expected = {"modify_pending_order_items": ("pending", "pending (item modified)"),
                    "exchange_delivered_order_items": ("delivered", "exchange requested")}[self.kind]
        if (self.status_before, self.status_after) != expected:
            raise ValueError(f"{self.kind} must go from {expected[0]!r} to {expected[1]!r}")
        difference = sum(line.price_after.amount_minor - line.price_before.amount_minor for line in self.changes)
        if self.price_difference.amount_minor != difference:
            raise ValueError("price_difference must equal the sum of the listed price changes")
        return self


class ReturnLine(WireModel):
    item_id: ItemId
    price: Money


class ReturnEffect(WireModel):
    kind: Literal["return_delivered_order_items"] = "return_delivered_order_items"
    order_id: OrderId
    items: Annotated[tuple[ReturnLine, ...], Field(min_length=1, max_length=50)]
    # Upstream computes no refund amount for returns; this is the purchase price of the listed items.
    returned_items_price_total: Money
    refund_payment_method_id: PaymentMethodId
    status_before: Literal["delivered"] = "delivered"
    status_after: Literal["return requested"] = "return requested"

    @model_validator(mode="after")
    def _total(self) -> "ReturnEffect":
        if self.returned_items_price_total.amount_minor != sum(line.price.amount_minor for line in self.items):
            raise ValueError("returned_items_price_total must equal the sum of the listed item prices")
        return self


class UserAddressEffect(WireModel):
    kind: Literal["modify_user_address"] = "modify_user_address"
    user_id: UserId
    address_before: Address
    address_after: Address


Effect = Annotated[
    CancelEffect | OrderAddressEffect | PaymentChangeEffect | ItemsEffect | ReturnEffect | UserAddressEffect,
    Field(discriminator="kind"),
]
