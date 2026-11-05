"""The retail-simulator RPC contract (T16): typed bodies and results shared by the evals-owned service and the
application client.

Identity is explicit and versioned:
- The **operation fingerprint** (`operation_sha256`) is a stable digest over the semantically relevant, immutable
  request and context: tenant, case, customer, fixture, operation ID, the typed tool call, the expected effect, the
  expected resource versions and `intent_sha256`. The service computes it; the body never carries its own digest.
  Retries of one operation have the same fingerprint, so a stored outcome replays; any difference conflicts.
- The **transport context** (signed by the caller) binds the complete canonical body digest, method, path, scope,
  nonce and times. Those are excluded from the operation fingerprint, so a retry with a fresh nonce is still the
  same operation.
- A **fence** body carries the *expected original* operation fingerprint, which is a different value from the
  fence request's own signed body digest.

Resource versions are positive integers. The catalog has version 1 within one immutable fixture identity; the
fixture digest is bound separately at initialization and in every context.
"""

import hashlib
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.money import Money
from policyops_contracts.retail import (
    Address,
    Calculate,
    CancelReason,
    Effect,
    Email,
    FindUserIdByEmail,
    FindUserIdByNameZip,
    GetItemDetails,
    GetOrderDetails,
    GetProductDetails,
    GetUserDetails,
    ListAllProductTypes,
    OrderItemSnapshot,
    OrderSnapshot,
    OrderStatus,
    PaymentKind,
    PaymentMethodSnapshot,
    PaymentRecord,
    ResourceVersion,
    UserSnapshot,
    VariantSnapshot,
    WriteToolCall,
)
from policyops_contracts.scalars import (
    ItemId,
    OrderId,
    PaymentMethodId,
    PositiveVersion,
    ProductId,
    Sha256Hex,
    ShortText,
    UserId,
    UtcDatetime,
)


RETAIL_SERVICE_VERSION = "policyops.retail-service/v1"
FIXTURE_ID: Literal["tau2-retail-19f13ea3"] = "tau2-retail-19f13ea3"
FIXTURE_SHA256 = "413a65160adbdb5fde0ffc0015c49b6d70250b10c18128de169b597af7766765"
MAX_BODY_BYTES = 64 * 1024

VersionList = Annotated[tuple[ResourceVersion, ...], Field(max_length=64)]
ReadCall = Annotated[
    FindUserIdByEmail | FindUserIdByNameZip | GetUserDetails | GetOrderDetails | GetProductDetails
    | GetItemDetails | ListAllProductTypes | Calculate,
    Field(discriminator="tool"),
]


class CaseInitialization(WireModel):
    """Create the case's isolated state once. Repeating the same body is a replay; anything else conflicts."""

    fixture_id: Literal["tau2-retail-19f13ea3"]
    fixture_sha256: Sha256Hex
    customer_id: UserId


class CaseState(WireModel):
    fixture_id: Literal["tau2-retail-19f13ea3"]
    fixture_sha256: Sha256Hex
    customer_id: UserId
    case_version: PositiveVersion
    created: bool


class ReadRequest(WireModel):
    call: ReadCall


# --- Read details (D13): descriptive, authoritative and bounded; projected explicitly into the minimal snapshots --

def _no_controls(value: str) -> str:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("control characters are not allowed")
    return value


Label = Annotated[str, StringConstraints(min_length=1, max_length=100), AfterValidator(_no_controls)]
ItemIds = Annotated[tuple[ItemId, ...], Field(max_length=50)]


class OptionValue(WireModel):
    """One variant option (for example `color` = `blue`); a variant's options are sorted by name."""

    name: Label
    value: Label


Options = Annotated[tuple[OptionValue, ...], Field(max_length=16)]


def _sorted_unique(options: tuple[OptionValue, ...]) -> None:
    names = [option.name for option in options]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ValueError("options are unique and sorted by name")


class VariantDetail(WireModel):
    product_id: ProductId
    product_name: ShortText
    item_id: ItemId
    available: bool
    price: Money
    options: Options
    product_version: PositiveVersion

    @model_validator(mode="after")
    def _options(self) -> "VariantDetail":
        _sorted_unique(self.options)
        return self

    def to_snapshot(self) -> VariantSnapshot:
        return VariantSnapshot(product_id=self.product_id, item_id=self.item_id, available=self.available,
                               price=self.price, product_version=self.product_version)


class OrderItemDetail(WireModel):
    item_id: ItemId
    product_id: ProductId
    name: ShortText
    price: Money
    options: Options

    @model_validator(mode="after")
    def _options(self) -> "OrderItemDetail":
        _sorted_unique(self.options)
        return self


class FulfillmentDetail(WireModel):
    tracking_ids: Annotated[tuple[Label, ...], Field(max_length=20)]
    item_ids: ItemIds


class ExchangeRequestDetail(WireModel):
    """A *recorded* exchange request: upstream changes no item, payment or balance until it is processed."""

    item_ids: ItemIds
    new_item_ids: ItemIds
    payment_method_id: PaymentMethodId
    price_difference: Money


class ReturnRequestDetail(WireModel):
    """A *recorded* return request; upstream computes no refund amount and moves no money."""

    item_ids: ItemIds
    payment_method_id: PaymentMethodId


class OrderDetail(WireModel):
    order_id: OrderId
    user_id: UserId
    version: PositiveVersion
    status: OrderStatus
    address: Address
    items: Annotated[tuple[OrderItemDetail, ...], Field(min_length=1, max_length=50)]
    fulfillments: Annotated[tuple[FulfillmentDetail, ...], Field(max_length=20)]
    payment_history: Annotated[tuple[PaymentRecord, ...], Field(min_length=1, max_length=50)]
    cancel_reason: CancelReason | None = None
    exchange_request: ExchangeRequestDetail | None = None
    return_request: ReturnRequestDetail | None = None

    def to_snapshot(self) -> OrderSnapshot:
        return OrderSnapshot(order_id=self.order_id, user_id=self.user_id, version=self.version, status=self.status,
                             address=self.address,
                             items=tuple(OrderItemSnapshot(item_id=i.item_id, product_id=i.product_id, price=i.price)
                                         for i in self.items),
                             payment_history=self.payment_history)


class PaymentMethodDetail(WireModel):
    payment_method_id: PaymentMethodId
    kind: PaymentKind
    gift_card_balance: Money | None = None
    brand: Label | None = None
    last_four: Annotated[str, StringConstraints(pattern=r"^\d{4}$")] | None = None

    def to_snapshot(self) -> PaymentMethodSnapshot:
        return PaymentMethodSnapshot(payment_method_id=self.payment_method_id, kind=self.kind,
                                     gift_card_balance=self.gift_card_balance)


class UserDetail(WireModel):
    """The case's own customer: name, contact, address, methods and *their* order IDs only."""

    user_id: UserId
    version: PositiveVersion
    first_name: Label
    last_name: Label
    email: Email
    address: Address
    payment_methods: Annotated[tuple[PaymentMethodDetail, ...], Field(max_length=50)]
    order_ids: Annotated[tuple[OrderId, ...], Field(max_length=200)]

    def to_snapshot(self) -> UserSnapshot:
        return UserSnapshot(user_id=self.user_id, version=self.version, address=self.address,
                            payment_methods=tuple(method.to_snapshot() for method in self.payment_methods))


class UserIdOutput(WireModel):
    kind: Literal["user_id"] = "user_id"
    user_id: UserId


class UserOutput(WireModel):
    kind: Literal["user"] = "user"
    user: UserDetail


class OrderOutput(WireModel):
    kind: Literal["order"] = "order"
    order: OrderDetail


class ProductOutput(WireModel):
    kind: Literal["product"] = "product"
    product_id: ProductId
    name: ShortText
    variants: Annotated[tuple[VariantDetail, ...], Field(max_length=200)]


class VariantOutput(WireModel):
    kind: Literal["variant"] = "variant"
    variant: VariantDetail


class ProductType(WireModel):
    name: ShortText
    product_id: ProductId


class ProductTypesOutput(WireModel):
    kind: Literal["product_types"] = "product_types"
    types: Annotated[tuple[ProductType, ...], Field(max_length=200)]


class CalculationOutput(WireModel):
    """Upstream's rounded float rendering. A calculator result is never exact-money evidence."""

    kind: Literal["calculation"] = "calculation"
    value: Annotated[str, Field(max_length=64)]


ReadOutput = Annotated[
    UserIdOutput | UserOutput | OrderOutput | ProductOutput | VariantOutput | ProductTypesOutput | CalculationOutput,
    Field(discriminator="kind"),
]


class ReadResult(WireModel):
    output: ReadOutput
    case_version: PositiveVersion
    resource_versions: VersionList


class MutationRequest(WireModel):
    """One write. `expected_versions` must name exactly the resources the tool reads or changes (the service derives
    that set per tool); `intent_sha256` is the caller's opaque proposal/approval context digest."""

    call: WriteToolCall
    expected_effect: Effect
    expected_versions: VersionList
    intent_sha256: Sha256Hex

    @model_validator(mode="after")
    def _effect_matches_call(self) -> "MutationRequest":
        if self.expected_effect.kind != self.call.tool:
            raise ValueError("the expected effect must be for the called tool")
        keys = [(v.kind, v.resource_id) for v in self.expected_versions]
        if len(keys) != len(set(keys)):
            raise ValueError("expected_versions must not repeat a resource")
        return self


Outcome = Literal["committed", "upstream_rejected", "effect_mismatch", "money_unrepresentable", "version_conflict",
                  "fenced"]


class Receipt(WireModel):
    """The immutable success record of one committed mutation."""

    operation_id: Annotated[str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    operation_sha256: Sha256Hex
    tool: Literal["cancel_pending_order", "modify_pending_order_address", "modify_pending_order_payment",
                  "modify_pending_order_items", "return_delivered_order_items", "exchange_delivered_order_items",
                  "modify_user_address"]
    actual_effect: Effect
    case_version_before: PositiveVersion
    case_version_after: PositiveVersion
    resource_versions_after: VersionList
    state_sha256_after: Sha256Hex
    committed_at: UtcDatetime

    @model_validator(mode="after")
    def _one_step(self) -> "Receipt":
        if self.case_version_after != self.case_version_before + 1:
            raise ValueError("a committed mutation advances the case version by exactly one")
        return self


class OperationResult(WireModel):
    """A stored outcome. Only `committed` carries a receipt; every other outcome changed nothing."""

    operation_id: Annotated[str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    operation_sha256: Sha256Hex
    outcome: Outcome
    receipt: Receipt | None = None
    replayed: bool

    @model_validator(mode="after")
    def _receipt_iff_committed(self) -> "OperationResult":
        if (self.outcome == "committed") != (self.receipt is not None):
            raise ValueError("a receipt exists exactly for a committed operation")
        return self


class FenceRequest(WireModel):
    """Make an absent operation permanently not executed. `operation_sha256` is the expected *original* operation
    fingerprint; a later original with that fingerprint replays the fence, any other conflicts."""

    operation_sha256: Sha256Hex


class LookupResult(WireModel):
    """`unknown` is not `not executed`: only a fence makes absence definitive."""

    state: Literal["found", "unknown"]
    result: OperationResult | None = None

    @model_validator(mode="after")
    def _result_iff_found(self) -> "LookupResult":
        if (self.state == "found") != (self.result is not None):
            raise ValueError("a lookup result exists exactly when found")
        return self


class ServiceContext(WireModel):
    """The signed transport context of one request (HMAC-SHA256 over its canonical JSON). It binds this exact request
    (method, path, the complete body digest), the case scope and a fresh nonce; it is service identity, never staff
    approval or customer consent."""

    v: Literal["policyops.retail-auth/v1"]
    iss: Literal["policyops-gateway"]
    aud: Literal["retail-simulator"]
    tenant_id: UUID
    case_id: UUID
    customer_id: UserId
    fixture_sha256: Sha256Hex
    scope: Literal["read", "write"]
    method: Literal["GET", "POST", "PUT"]
    path: Annotated[str, Field(pattern=r"^/v1/cases/[0-9a-f-]{36}(?:/[a-z]+(?:/[0-9a-f-]{36}(?:/fence)?)?)?$",
                               max_length=200)]
    body_sha256: Sha256Hex
    iat: Annotated[int, Field(ge=0, le=2**40)]
    exp: Annotated[int, Field(ge=0, le=2**40)]
    jti: UUID

    @model_validator(mode="after")
    def _short_lived(self) -> "ServiceContext":
        if not 0 < self.exp - self.iat <= 60:
            raise ValueError("a context is valid for at most 60 seconds")
        if f"/v1/cases/{self.case_id}" != self.path[:len("/v1/cases/") + 36]:
            raise ValueError("the path names another case")
        return self


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def operation_fingerprint(*, tenant_id: UUID, case_id: UUID, customer_id: str, fixture_sha256: str,
                          operation_id: UUID, request: MutationRequest) -> str:
    """The stable identity of one operation (`policyops.retail-operation/v1`). Nonce, times, signature and the
    transport body digest are not part of it; the expected versions are order-independent."""
    body = request.model_dump(mode="json")
    body["expected_versions"] = sorted(body["expected_versions"], key=lambda v: (v["kind"], v["resource_id"]))
    document = {"v": "policyops.retail-operation/v1", "tenant_id": str(tenant_id), "case_id": str(case_id),
                "customer_id": customer_id, "fixture_sha256": fixture_sha256, "operation_id": str(operation_id),
                "request": body}
    return hashlib.sha256(canonical_json(document)).hexdigest()


__all__ = [
    "FIXTURE_ID", "FIXTURE_SHA256", "MAX_BODY_BYTES", "RETAIL_SERVICE_VERSION", "CalculationOutput",
    "CaseInitialization",
    "CaseState", "FenceRequest", "LookupResult", "MutationRequest", "OperationResult", "OrderOutput",
    "Outcome", "ProductOutput", "ProductType", "ProductTypesOutput", "ReadCall", "ReadOutput", "ReadRequest",
    "ReadResult", "Receipt", "ServiceContext", "UserIdOutput", "UserOutput", "VariantOutput",
    "canonical_json", "operation_fingerprint",
]
