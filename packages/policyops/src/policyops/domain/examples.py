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


def _retail_service_examples(world: World) -> dict[str, Any]:
    """A fictional retail-simulator mutation, its committed result and a lookup of an absent operation (T16)."""
    from policyops_contracts.money import Money
    from policyops_contracts.retail import ItemChangeLine, ItemsEffect, ModifyPendingOrderItems, ResourceVersion
    from policyops_contracts.retail_service import (
        LookupResult,
        MutationRequest,
        OperationResult,
        Receipt,
        operation_fingerprint,
    )

    method = "credit_card_0000001"
    call = ModifyPendingOrderItems(order_id=world.order_id, item_ids=(world.item_a,), new_item_ids=(world.item_c,),
                                   payment_method_id=method)
    effect = ItemsEffect(kind="modify_pending_order_items", order_id=world.order_id, changes=(ItemChangeLine(
        item_id=world.item_a, new_item_id=world.item_c, product_id=world.product,
        price_before=Money(amount_minor=1999), price_after=Money(amount_minor=3000)),),
        price_difference=Money(amount_minor=1001), payment_method_id=method, status_before="pending",
        status_after="pending (item modified)")
    request = MutationRequest(call=call, expected_effect=effect, intent_sha256="d" * 64, expected_versions=(
        ResourceVersion(kind="order", resource_id=world.order_id, version=1),
        ResourceVersion(kind="user", resource_id=world.user_id, version=1),
        ResourceVersion(kind="product", resource_id=world.product, version=1)))
    operation = UUID(int=1200)
    sha = operation_fingerprint(tenant_id=UUID(int=1), case_id=UUID(int=2), customer_id=world.user_id,
                                fixture_sha256="0" * 64, operation_id=operation, request=request)
    receipt = Receipt(operation_id=str(operation), operation_sha256=sha, tool=call.tool, actual_effect=effect,
                      case_version_before=1, case_version_after=2,
                      resource_versions_after=(ResourceVersion(kind="order", resource_id=world.order_id, version=2),
                                               ResourceVersion(kind="product", resource_id=world.product,
                                                               version=1),
                                               ResourceVersion(kind="user", resource_id=world.user_id, version=1)),
                      state_sha256_after="e" * 64, committed_at=world.now)
    return {"retail-service-mutation-request.modify-items": request,
            "retail-service-operation-result.committed": OperationResult(
                operation_id=str(operation), operation_sha256=sha, outcome="committed", receipt=receipt,
                replayed=False),
            "retail-service-lookup-result.unknown": LookupResult(state="unknown")}


def _gateway_examples(proposal: Any) -> dict[str, Any]:
    """What the agent sees after a gateway step (T17): a computed, non-actionable preview and a policy refusal."""
    from policyops_contracts.errors import ErrorCode
    from policyops_contracts.gateway import ProposalPreview, ToolError

    return {
        "tool-observation.proposal-preview": ProposalPreview(tool=proposal.action.tool,
                                                             presentation=proposal.presentation.text),
        "tool-observation.policy-denied": ToolError(code=ErrorCode.POLICY_DENIED, rule_id="cancel.pending_only",
                                                    detail="order status is 'delivered'", retryable=False),
    }


def _retrieval_examples(world: World) -> dict[str, Any]:
    """A fictional hybrid retrieval step (T13) and its result: synthetic IDs, scores and text only."""
    from policyops_contracts.retrieval import (
        BranchDocument,
        EvidenceChunk,
        FusedDocument,
        RetrievalConfig,
        RetrievalQuery,
        RetrievalResult,
        RetrievalScope,
    )

    query = RetrievalQuery(text="Can a refund go to a gift card?", run_id=world.run, step=3,
                           scope=RetrievalScope(corpus_key="example-policy"), config=RetrievalConfig(mode="hybrid"))
    document, version, chunk = UUID(int=7001), UUID(int=7002), UUID(int=7003)
    text = "Refunds go to the original payment method or an existing gift card."
    heading = "Returns"
    evidence_text = f"[E1] example:policy/returns version 1 | {heading} | chars 0-{len(text)}\n{text}"
    result = RetrievalResult(
        trace_id=UUID(int=7004), run_id=world.run, step=3, generation_id=UUID(int=7005), generation_current=True,
        replayed=False, mode="hybrid", lexical_status="ok", dense_status="ok",
        lexical=(BranchDocument(document_id=document, rank=1, score="0.1", chunk_ids=(chunk,)),),
        dense=(BranchDocument(document_id=document, rank=1, score="0.2928932188134524", chunk_ids=(chunk,)),),
        fused=(FusedDocument(document_id=document, rank=1, rrf="2/61", lexical_rank=1, dense_rank=1),),
        evidence=(EvidenceChunk(evidence_id="E1", chunk_id=chunk, document_id=document, document_version_id=version,
                                source_uri="example:policy/returns", version_number=1, heading=heading, start=0,
                                end=len(text), text=text),),
        evidence_text=evidence_text, evidence_tokens=31, config_sha256=query.config.sha256(),
        request_sha256=query.request_sha256(), payload_sha256="0" * 64, provider_requests=0)
    return {"retrieval-query.hybrid": query, "retrieval-result.hybrid": result}


def _grounding_examples(world: World) -> dict[str, Any]:
    """A fictional reranked step request, a model's grounded answer and its validated result (T14): synthetic IDs
    and text only. The validated example shows the shape; it is not the output of a real validation."""
    import hashlib

    from policyops_contracts.grounding import (
        Assertion,
        AssertionCheck,
        CitationBundle,
        CitationCheck,
        CitationClaim,
        CitedQuote,
        GroundedAnswer,
        ValidatedAnswer,
    )
    from policyops_contracts.retrieval import RerankConfig, RetrievalConfig, RetrievalQuery, RetrievalScope

    query = RetrievalQuery(text="Can a refund go to a gift card?", run_id=world.run, step=4,
                           scope=RetrievalScope(corpus_key="example-policy"),
                           config=RetrievalConfig(mode="hybrid", rerank=RerankConfig(documents=10)))
    quote = "an existing gift card"
    text = "Refunds go to the original payment method or an existing gift card."
    start = text.index(quote)
    answer = GroundedAnswer(v="policyops.grounded-answer/v1", outcome="answer", abstention=None, assertions=(
        Assertion(text="A refund can go to an existing gift card.", policy_dependent=True, citations=(
            CitedQuote(step=3, evidence_id="E1", quote=quote, start=start, end=start + len(quote)),)),))
    trace, chunk, document, version, generation = (UUID(int=7004), UUID(int=7003), UUID(int=7001), UUID(int=7002),
                                                   UUID(int=7005))
    claim = CitationClaim(
        step=3, evidence_id="E1", trace_id=trace, trace_payload_sha256="0" * 64, request_sha256="0" * 64,
        generation_id=generation, chunk_id=chunk, document_id=document, document_version_id=version,
        version_sha256="0" * 64, chunk_text_sha256=hashlib.sha256(text.encode()).hexdigest(), span_start=start,
        span_end=start + len(quote), quote=quote, quote_sha256=hashlib.sha256(quote.encode()).hexdigest())
    validated = ValidatedAnswer(
        outcome="grounded", assertions=(AssertionCheck(assertion=0, policy_dependent=True,
                                                       status="cited_identity_verified", verified_citations=1),),
        citations=(CitationCheck(assertion=0, citation=0, step=3, evidence_id="E1", status="verified",
                                 trace_id=trace, chunk_id=chunk, document_id=document, document_version_id=version,
                                 generation_id=generation, span_start=start, span_end=start + len(quote)),),
        generation_id=generation, generation_current=True,
        bundle=CitationBundle(run_id=world.run, corpus_key="example-policy", claims=(claim,)))
    return {"retrieval-query.hybrid-rerank": query, "grounded-answer.answer": answer,
            "validated-answer.grounded": validated}


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
    from policyops_contracts.evidence import EvidenceManifest
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
    junit, stdout = "c" * 64, ("commands/unit.stdout.txt", "commands/unit.stderr.txt")
    evidence = EvidenceManifest.model_validate({
        "run_id": "example-run-1", "task_id": "T05", "purpose": "Synthetic harness run with one failing step",
        "seed": 20261104, "started_at": world.now, "finished_at": world.now + timedelta(minutes=3),
        "code": {"git_head": "1" * 40, "git_tree": "2" * 40},
        "environment": ({"name": "POLICYOPS_TEST_SEED", "value": "20261104"},),
        "artifacts": ({"path": stdout[0], "role": "log", "sha256": "a" * 64, "size": 120},
                      {"path": stdout[1], "role": "log", "sha256": "b" * 64, "size": 0},
                      {"path": "reports/unit-junit.xml", "role": "report", "sha256": junit, "size": 2048}),
        "commands": ({"step": "unit", "argv": ("pytest", "-q"), "exit_code": 1,
                      "started_at": world.now + timedelta(seconds=10), "finished_at": world.now + timedelta(minutes=2),
                      "outputs": stdout},),
        "failures": ({"step": "unit", "kind": "nonzero_exit", "detail": "exited with code 1", "artifacts": stdout},),
        "metrics": ({"name": "tests-passed", "value": "41", "unit": "tests",
                     "derivation": "count of passed test cases in reports/unit-junit.xml", "sources": (junit,)},),
    })
    documents = {
        "action-proposal.exchange": proposal, "proposal-presentation": presentation,
        "case-message.operator-entered-yes": reply, "customer-consent": consented.consent,
        "approval-decision": decided.decision, "run-event.proposal-presented": event,
        "error.consent-ambiguous": error, "evidence-manifest.failed-run": evidence,
        "case-customer-binding": world.binding(),
        "customer-authentication": session.authentication,
        "agent-step.transfer": ToolCallStep(call=TransferToHumanAgents(summary="Customer asked about a store "
                                                                             "credit program that is out of scope.")),
        "agent-step.handoff": MessageStep(text=HANDOFF_MESSAGE),
        **_gateway_examples(proposal),
        "demo-seed": DemoSeed(seed_id="retail-demo-9999", label="Retail demo 9999", domain="retail",
                              upstream_task_id="9999", kind="mutation", allowlist_sha256="0" * 64),
        **_retail_service_examples(world),
        **_retrieval_examples(world),
        **_grounding_examples(world),
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
