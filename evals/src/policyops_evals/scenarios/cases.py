"""The two S1 cases, from the pinned public retail database."""

from dataclasses import dataclass
import hashlib
import json
from typing import Literal

from policyops_contracts.retail import CancelPendingOrder
from policyops_contracts.retail_service import FIXTURE_SHA256


@dataclass(frozen=True)
class World:
    customer_id: str
    order_id: str
    status: Literal["pending", "delivered"]
    sole_payment: str | None = None


@dataclass(frozen=True)
class VisibleCase:
    lookup_email: str
    message: str


@dataclass(frozen=True)
class Gold:
    disposition: Literal["propose", "refuse"]
    action: CancelPendingOrder | None
    required_reads: tuple[str, ...]
    clauses: tuple[str, ...]


@dataclass(frozen=True)
class Scenario:
    key: str
    world: World
    visible: VisibleCase
    gold: Gold

    def verify(self, fixture_bytes: bytes) -> None:
        if hashlib.sha256(fixture_bytes).hexdigest() != FIXTURE_SHA256:
            raise ValueError("retail fixture digest mismatch")
        data = json.loads(fixture_bytes)
        order = data["orders"][self.world.order_id]
        user = data["users"][self.world.customer_id]
        if (order["user_id"] != self.world.customer_id or order["status"] != self.world.status
                or user["email"] != self.visible.lookup_email):
            raise ValueError("scenario fixture facts changed")
        if self.world.sole_payment is not None and [
            item["payment_method_id"] for item in order["payment_history"] if item["transaction_type"] == "payment"
        ] != [self.world.sole_payment]:
            raise ValueError("scenario does not have the expected sole payment")


READS = ("identity", "order")
SCENARIOS = (
    Scenario(
        "pending-cancellation",
        World("james_johnson_9321", "#W1006327", "pending", "credit_card_4998749"),
        VisibleCase("james.johnson7869@example.com",
                    "My account email is james.johnson7869@example.com. "
                    "Please cancel order #W1006327 because I no longer need it."),
        Gold("propose", CancelPendingOrder(tool="cancel_pending_order", order_id="#W1006327",
                                           reason="no longer needed"), READS, ("cancel.pending_only",)),
    ),
    Scenario(
        "delivered-cancellation",
        World("ava_moore_2033", "#W4817420", "delivered"),
        VisibleCase("ava.moore6020@example.com",
                    "My account email is ava.moore6020@example.com. "
                    "Please cancel order #W4817420 because I no longer need it."),
        Gold("refuse", None, READS, ("cancel.pending_only",)),
    ),
)
