"""Synthetic retail world and the committed contract examples.

Everything here is fictional: IDs follow the upstream formats but do not occur
in the pinned retail DB, and no upstream task text, reference action or outcome
is used. Tests build on `World`; `python -m policyops.domain.examples --check DIR`
verifies the committed example JSON documents.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from policyops.domain.retail_rules import RetailFacts
from policyops.domain.session import Authenticated, CustomerSession, apply_lookup
from policyops_contracts.money import Money
from policyops_contracts.retail import (
    Address,
    FindUserIdByEmail,
    OrderItemSnapshot,
    OrderOperationHistory,
    OrderSnapshot,
    PaymentMethodSnapshot,
    PaymentRecord,
    ToolName,
    UserSnapshot,
    VariantSnapshot,
)
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding


def usd(cents: int) -> Money:
    return Money(amount_minor=cents)


class World:
    workspace = UUID(int=1)
    case = UUID(int=2)
    run = UUID(int=3)
    analyst = UUID(int=101)
    reviewer = UUID(int=102)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    user_id = "example_user_0001"
    other_user = "other_user_0002"
    order_id = "#W0000001"
    product = "9000000001"
    other_product = "9000000002"
    item_a, item_b, item_c, item_x = "1000000001", "1000000002", "1000000003", "1000000009"
    card, gift, paypal = "credit_card_0000001", "gift_card_0000001", "paypal_0000001"

    @property
    def case_scope(self) -> CaseScope:
        return CaseScope(workspace_id=self.workspace, case_id=self.case)

    @property
    def run_scope(self) -> RunScope:
        return RunScope(workspace_id=self.workspace, case_id=self.case, run_id=self.run)

    def address(self, line: str = "1 Example Way") -> Address:
        return Address(address1=line, address2="", city="Exampleton", state="CA", country="USA", zip="00001")

    def customer(self, *, gift_balance: int = 5000, user_id: str | None = None) -> UserSnapshot:
        return UserSnapshot(user_id=user_id or self.user_id, version=3, address=self.address(), payment_methods=(
            PaymentMethodSnapshot(payment_method_id=self.card, kind="credit_card"),
            PaymentMethodSnapshot(payment_method_id=self.gift, kind="gift_card", gift_card_balance=usd(gift_balance)),
            PaymentMethodSnapshot(payment_method_id=self.paypal, kind="paypal"),
        ))

    def order(self, *, status: Any = "pending", items: tuple[str, ...] = ("1000000001", "1000000002"),
              paid_with: str | None = None, user_id: str | None = None, payments: int = 1) -> OrderSnapshot:
        prices = {self.item_a: 1999, self.item_b: 2500, self.item_c: 3000}
        lines = tuple(OrderItemSnapshot(item_id=item, product_id=self.product, price=usd(prices[item]))
                      for item in items)
        total = sum(line.price.amount_minor for line in lines)
        history = tuple(PaymentRecord(transaction_type="payment", payment_method_id=paid_with or self.card,
                                      amount=usd(total)) for _ in range(payments))
        return OrderSnapshot(order_id=self.order_id, user_id=user_id or self.user_id, version=7, status=status,
                             address=self.address(), items=lines, payment_history=history)

    def variants(self, *, available: bool = True) -> tuple[VariantSnapshot, ...]:
        return (
            VariantSnapshot(product_id=self.product, item_id=self.item_c, available=available, price=usd(3000),
                            product_version=11),
            VariantSnapshot(product_id=self.product, item_id=self.item_b, available=True, price=usd(2500),
                            product_version=11),
            VariantSnapshot(product_id=self.other_product, item_id=self.item_x, available=True, price=usd(100),
                            product_version=4),
        )

    def history(self, *tools: str, complete: bool = True) -> OrderOperationHistory:
        return OrderOperationHistory.model_validate(
            {"order_id": self.order_id, "complete": complete,
             "successful_tools": tuple(ToolName(tool) for tool in tools)})

    def facts(self, **overrides: Any) -> RetailFacts:
        base = RetailFacts(customer=self.customer(), order=self.order(), variants=self.variants(),
                           history=self.history())
        return replace(base, **overrides)

    def binding(self) -> CaseCustomerBinding:
        return CaseCustomerBinding(scope=self.case_scope, seed_id="retail-demo-9999", user_id=self.user_id,
                                   bound_at=self.now - timedelta(minutes=5))

    def session(self, *, authenticated: bool = True) -> CustomerSession:
        session = CustomerSession(binding=self.binding(), run=self.run_scope)
        if not authenticated:
            return session
        outcome = apply_lookup(session, FindUserIdByEmail(email="example.user@example.invalid"), self.user_id,
                               step_sequence=1, now=self.now - timedelta(minutes=4))
        if not isinstance(outcome, Authenticated):
            raise RuntimeError("synthetic lookup did not authenticate")
        return outcome.session


def build_examples() -> dict[str, bytes]:
    """Canonical JSON documents for one fictional exchange flow, plus small standalone examples."""
    from policyops.domain.approval_rules import Decided, decide
    from policyops.domain.consent_rules import Consented, record_reply
    from policyops.domain.retail_rules import propose
    from policyops.domain.roles import Role
    from policyops_contracts.agent import MessageStep, ToolCallStep
    from policyops_contracts.consent import CaseMessage, ProposalPresentationRecord
    from policyops_contracts.digest import text_sha256
    from policyops_contracts.errors import ErrorCode, ErrorEnvelope
    from policyops_contracts.events import EventEnvelope, ProposalPresented
    from policyops_contracts.proposal import ActionProposal
    from policyops_contracts.retail import HANDOFF_MESSAGE, ExchangeDeliveredOrderItems, TransferToHumanAgents
    from policyops_contracts.seeds import DemoSeed

    world = World()
    session = world.session()
    call = ExchangeDeliveredOrderItems(order_id=world.order_id, item_ids=(world.item_a,), new_item_ids=(world.item_c,),
                                       payment_method_id=world.gift)
    proposal = propose(proposal_id=UUID(int=500), proposal_version=1, session=session, call=call,
                       facts=world.facts(order=world.order(status="delivered")), evidence=(),
                       rationale="The customer asked to exchange one item for another option of the same product.",
                       now=world.now)
    if not isinstance(proposal, ActionProposal):
        raise RuntimeError(f"example proposal was not allowed: {proposal}")
    presented_at = world.now + timedelta(seconds=5)
    presentation = ProposalPresentationRecord(
        scope=world.run_scope, proposal_id=proposal.proposal_id, proposal_version=proposal.proposal_version,
        action_digest=proposal.action_digest, presentation_sha256=proposal.presentation.text_sha256,
        message_id=UUID(int=700), message_sequence=10, presented_at=presented_at)
    reply = CaseMessage(message_id=UUID(int=811), scope=world.case_scope, sequence=11,
                        source="operator_entered_customer", entered_by=world.analyst, text="Yes, please.",
                        text_sha256=text_sha256("Yes, please."), created_at=world.now + timedelta(seconds=30))
    consented = record_reply(consent_id=UUID(int=900), proposal=proposal, presentation=presentation, message=reply,
                             now=world.now + timedelta(minutes=1))
    if not isinstance(consented, Consented):
        raise RuntimeError(f"example consent failed: {consented}")
    decided = decide(approval_id=UUID(int=950), proposal=proposal, consent=consented.consent,
                     principal_id=world.reviewer, roles=frozenset({Role.REVIEWER}), decision="approve",
                     reason="Exchange matches the customer's request.", now=world.now + timedelta(minutes=2))
    if not isinstance(decided, Decided):
        raise RuntimeError(f"example approval failed: {decided}")
    event = EventEnvelope(event_id=UUID(int=1000), scope=world.run_scope, sequence=21, occurred_at=presented_at,
                          payload=ProposalPresented(proposal_id=proposal.proposal_id, proposal_version=1,
                                                    action_digest=proposal.action_digest,
                                                    expires_at=proposal.expires_at))
    error = ErrorEnvelope(code=ErrorCode.CONSENT_AMBIGUOUS,
                          detail="Please reply yes to proceed, or say what to change.",
                          rule_id="consent.explicit_yes", correlation_id=UUID(int=1100), retryable=False)
    documents = {
        "action-proposal.exchange": proposal, "proposal-presentation": presentation,
        "case-message.operator-entered-yes": reply, "customer-consent": consented.consent,
        "approval-decision": decided.decision, "run-event.proposal-presented": event,
        "error.consent-ambiguous": error, "case-customer-binding": world.binding(),
        "customer-authentication": session.authentication,
        "agent-step.transfer": ToolCallStep(call=TransferToHumanAgents(summary="Customer asked about a store "
                                                                             "credit program that is out of scope.")),
        "agent-step.handoff": MessageStep(text=HANDOFF_MESSAGE),
        "demo-seed": DemoSeed(seed_id="retail-demo-9999", label="Retail demo 9999", domain="retail",
                              upstream_task_id="9999", kind="mutation", allowlist_sha256="0" * 64),
    }
    return {f"{name}.json": (json.dumps(json.loads(model.model_dump_json()), indent=2, sort_keys=True) + "\n").encode()
            for name, model in sorted(documents.items()) if model is not None}


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Write or check the committed contract examples.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    generated = build_examples()
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, data in generated.items():
            (args.out / name).write_bytes(data)
        return 0
    present = {path.name: path.read_bytes() for path in args.check.glob("*.json")}
    if present != generated:
        print("examples differ from a fresh build", file=sys.stderr)
        return 1
    print(f"{len(generated)} examples match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
