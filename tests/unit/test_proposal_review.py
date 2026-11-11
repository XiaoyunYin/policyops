"""T18 pure review helpers: the presentation guard, derived review state, the exact detail view, the decision request
and the canonical (untrusted) list cursors. No database: the transactional services are covered by the PostgreSQL
integration tests."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
import pytest

from policyops.auth.service import AuthError
from policyops.domain.consent_rules import Consented, record_reply
from policyops.domain.examples import World
from policyops.domain.retail_rules import propose
from policyops.persistence.repositories import ProposalRow
from policyops.services import proposal_views as views
from policyops_contracts.consent import ApprovalDecision, CaseMessage, CustomerConsent, ProposalPresentationRecord
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import CancelPendingOrder, ModifyPendingOrderItems


def cancel_proposal(world: World) -> ActionProposal:
    result = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(),
                     call=CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                     facts=world.facts(), evidence=(), rationale="Customer asked to cancel.", now=world.now)
    assert isinstance(result, ActionProposal)
    return result


def presentation(world: World, proposal: ActionProposal) -> ProposalPresentationRecord:
    return ProposalPresentationRecord(
        scope=world.run_scope, proposal_id=proposal.proposal_id, proposal_version=proposal.proposal_version,
        action_digest=proposal.action_digest, presentation_sha256=proposal.presentation.text_sha256,
        message_id=UUID(int=700), message_sequence=10, presented_at=world.now + timedelta(seconds=5))


def customer_message(world: World, text: str = "yes") -> CaseMessage:
    return CaseMessage(message_id=UUID(int=811), scope=world.case_scope, sequence=11, source="simulated_customer",
                       entered_by=None, text=text, text_sha256=text_sha256(text),
                       created_at=world.now + timedelta(seconds=30))


def consent_for(world: World, proposal: ActionProposal) -> CustomerConsent:
    outcome = record_reply(consent_id=UUID(int=900), proposal=proposal, presentation=presentation(world, proposal),
                           message=customer_message(world), now=world.now + timedelta(seconds=40))
    assert isinstance(outcome, Consented)
    return outcome.consent


def row_for(proposal: ActionProposal, status: str = "presented") -> ProposalRow:
    return ProposalRow(row_id=UUID(int=600), workspace_id=proposal.scope.workspace_id, case_id=proposal.scope.case_id,
                       run_id=proposal.scope.run_id, proposal_id=proposal.proposal_id,
                       proposal_version=proposal.proposal_version, action_digest=proposal.action_digest,
                       intent_digest=proposal.intent_digest, status=status, created_at=proposal.created_at,
                       expires_at=proposal.expires_at, presented_at=proposal.created_at + timedelta(seconds=5))


def decision_for(world: World, proposal: ActionProposal, consent: CustomerConsent, kind: Any = "approve",
                 *, at: datetime | None = None) -> ApprovalDecision:
    decided = at or world.now + timedelta(minutes=1)
    return ApprovalDecision(approval_id=UUID(int=950), scope=proposal.scope, proposal_id=proposal.proposal_id,
                            proposal_version=proposal.proposal_version, action_digest=proposal.action_digest,
                            consent_id=consent.consent_id, principal_id=world.reviewer, role="reviewer",
                            decision=kind, reason="Checked the order.", decided_at=decided,
                            expires_at=min(consent.expires_at, decided + timedelta(minutes=5)))


# -- the presentation guard ---------------------------------------------------------------------------------------

def test_an_actual_domain_proposal_can_be_too_long_for_one_case_message(world: World) -> None:
    """Coherent fictional facts (50 identical pending-order lines, each changed to one valid replacement) give a valid
    sealed proposal whose exact presentation exceeds the 4000-character message bound: it is not presentable."""
    lines = (world.item_a,) * 50
    facts = world.facts(order=world.order(items=lines))
    result = propose(proposal_id=uuid4(), proposal_version=1, session=world.session(),
                     call=ModifyPendingOrderItems(order_id=world.order_id, item_ids=lines,
                                                  new_item_ids=(world.item_c,) * 50, payment_method_id=world.card),
                     facts=facts, evidence=(), rationale="Customer asked to change every line.", now=world.now)
    assert isinstance(result, ActionProposal)
    assert len(result.presentation.text) > 4000
    assert not views.presentable(result.presentation.text)
    assert views.presentable(cancel_proposal(world).presentation.text)


@pytest.mark.parametrize(("text", "expected"), [
    ("x" * 4000, True), ("x" * 4001, False), ("", False), ("line\nnext\tcell", True), ("bell\x07", False),
    ("\x7f", False), ("é" * 4000, True),
])
def test_the_guard_is_the_shared_message_text_bound(text: str, expected: bool) -> None:
    """Controlled generated boundaries (not domain output): exactly the MessageText bound CaseMessage uses."""
    assert views.presentable(text) is expected
    if expected:
        CaseMessage(message_id=uuid4(), scope=World().case_scope, sequence=1, source="agent", entered_by=None,
                    text=text, text_sha256=text_sha256(text), created_at=World.now)


# -- derived review state -------------------------------------------------------------------------------------------

def test_review_states_follow_the_persisted_records_and_the_clock(world: World) -> None:
    proposal = cancel_proposal(world)
    consent = consent_for(world, proposal)
    approved = decision_for(world, proposal, consent)
    rejected = decision_for(world, proposal, consent, "reject")
    inside, late = world.now + timedelta(minutes=2), proposal.expires_at

    def state(status: str = "presented", presented: bool = True, current: CustomerConsent | None = consent,
              decision: ApprovalDecision | None = None, now: datetime = inside) -> str:
        return views.review_state(row_status=status, presented=presented, consent=current, decision=decision,
                                  expires_at=proposal.expires_at, now=now)

    assert state("created", presented=False, current=None) == "awaiting_presentation"
    assert state(current=None) == "awaiting_consent"
    assert state(now=world.now + timedelta(seconds=35)) == "awaiting_consent"  # before the consent was confirmed
    assert state() == "awaiting_decision"
    assert state(decision=approved) == "approved"
    assert state(decision=approved, now=approved.expires_at) == "approval_expired"
    assert state(decision=rejected) == "rejected"
    assert state(now=late) == "expired"
    assert state("expired") == "expired"
    # A superseded version has no authority, whatever was decided on it.
    assert state("superseded", decision=approved) == "superseded"
    assert state("superseded") == "superseded"


# -- the exact detail view ------------------------------------------------------------------------------------------

def test_the_detail_view_carries_the_sealed_body_unchanged(world: World) -> None:
    proposal = cancel_proposal(world)
    consent = consent_for(world, proposal)
    now = world.now + timedelta(minutes=2)
    detail = views.detail_view(row=row_for(proposal), proposal=proposal, presentation=presentation(world, proposal),
                               consent=consent, consent_message=customer_message(world), decision=None, now=now)
    dumped = detail.model_dump(mode="json")
    assert dumped["proposal"] == proposal.model_dump(mode="json")
    assert ActionProposal.model_validate_json(json.dumps(dumped["proposal"])).action_digest == proposal.action_digest
    assert dumped["state"] == "awaiting_decision"
    assert dumped["consent"]["customer_message_text"] == "yes"
    assert dumped["server_time"] == now.isoformat().replace("+00:00", "Z")
    # Exact money in the effect: integer minor units, never floats.
    refunds = dumped["proposal"]["effect"]["refunds"]
    assert refunds and all(isinstance(line["amount"]["amount_minor"], int) for line in refunds)


# -- the decision request -------------------------------------------------------------------------------------------

def request(**overrides: Any) -> dict[str, Any]:
    return {"proposal_version": 1, "action_digest": "a" * 64, "decision": "approve", "reason": "Checked.",
            **overrides}


def test_the_decision_request_is_strict() -> None:
    assert views.DecisionRequest.model_validate_json(json.dumps(request())).proposal_version == 1
    for bad in (request(extra=True), request(proposal_version="1"), request(proposal_version=1.0),
                request(proposal_version=0), request(decision="maybe"), request(reason=""),
                request(reason="x" * 501), request(action_digest="A" * 64)):
        with pytest.raises(ValidationError):
            views.DecisionRequest.model_validate_json(json.dumps(bad))


# -- cursors --------------------------------------------------------------------------------------------------------

def test_cursors_are_canonical_positions_bound_to_one_workspace_and_list() -> None:
    workspace, other = UUID(int=1), UUID(int=99)
    at = World.now
    token = views.encode_cursor(views.ProposalCursor(w=workspace, lst="inbox", c=at, i=UUID(int=5)))
    assert views.decode_cursor(token, workspace, "inbox") == (at, UUID(int=5))
    case_key = views.case_list_key(UUID(int=2))
    for value, ws, key in ((token, other, "inbox"), (token, workspace, case_key), (token + "=", workspace, "inbox"),
                           ("not-base64!", workspace, "inbox"), ("x" * 401, workspace, "inbox")):
        with pytest.raises(AuthError) as refused:
            views.decode_cursor(value, ws, key)
        assert (refused.value.status, refused.value.rule_id) == (422, "api.invalid_cursor")
    # A validly encoded, changed position is accepted: it is untrusted pagination data, never authority.
    moved = views.encode_cursor(views.ProposalCursor(w=workspace, lst="inbox", c=at + timedelta(days=1),
                                                     i=UUID(int=6)))
    assert views.decode_cursor(moved, workspace, "inbox") == (at + timedelta(days=1), UUID(int=6))


def test_summary_view_names_the_sealed_tool(world: World) -> None:
    proposal = cancel_proposal(world)
    summary = views.summary_view(row_for(proposal), proposal, "awaiting_decision")
    assert (summary.tool, summary.action_digest, summary.state) == ("cancel_pending_order", proposal.action_digest,
                                                                    "awaiting_decision")


# -- ProposalService.create intake and pre-write refusals (actual service, real domain, fake persistence) ---------

class TripwireEngine:
    """Any transaction is a test failure: intake refusals must happen before any database work."""

    def begin(self) -> Any:
        raise AssertionError("an intake refusal opened a transaction")


class FixedLease:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def now(self, connection: Any) -> datetime:
        del connection
        return self.at


class FakePersistence:
    """Stands in for the transaction and the persisted context; records every write the service attempts."""

    def __init__(self, world: World, active: list[ProposalRow] | None = None) -> None:
        self.world, self.active = world, active or []
        self.writes: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from contextlib import contextmanager
        from types import SimpleNamespace

        from policyops.services import proposals as module

        world, writes = self.world, self.writes

        @contextmanager
        def transaction(engine: Any, workspace_id: UUID) -> Any:
            del engine, workspace_id
            yield object()

        monkeypatch.setattr(module, "workspace_transaction", transaction)
        monkeypatch.setattr(module, "evidence_status", lambda connection, refs, run_id: "current")
        monkeypatch.setattr(module, "run_store", SimpleNamespace(
            get_run=lambda connection, run_id, lock: SimpleNamespace(id=world.run, case_id=world.case,
                                                                     terminal=False)))
        monkeypatch.setattr(module, "customer_authentications", SimpleNamespace(
            load=lambda connection, scope: world.session().authentication))
        monkeypatch.setattr(module, "repo", SimpleNamespace(
            lock_case=lambda connection, case_id: SimpleNamespace(id=world.case, customer_user_id=world.user_id),
            active_intent_rows=lambda connection, case_id, intent: list(self.active),
            latest_proposal_version=lambda connection, proposal_id: 1,
            set_proposal_status=lambda *args: writes.append("supersede"),
            insert_proposal=lambda connection, row_id, proposal: writes.append("insert"),
            append_audit=lambda connection, event: writes.append(f"audit:{event.action}")))


def create(world: World, engine: Any, *, call: Any = None, facts: Any = None, evidence: Any = (),
           rationale: Any = "Customer asked to cancel.") -> Any:
    from policyops.gateway.facts import Collected
    from policyops.gateway.ports import GatewayScope
    from policyops.services.proposals import ProposalService
    from policyops_contracts.retail_service import FIXTURE_SHA256

    service = ProposalService(app_engine=engine, clock=FixedLease(world.now))
    scope = GatewayScope(run=world.run_scope, binding=world.binding(), fixture_sha256=FIXTURE_SHA256)
    collected = Collected(facts=facts or world.facts(), case_version=5, resource_versions=(), collections=1, reads=3)
    return service.create(scope, call or CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                          collected, evidence=evidence, rationale=rationale)


def evidence_ref(n: int) -> Any:
    from policyops_contracts.proposal import EvidenceRef

    return EvidenceRef(evidence_id=UUID(int=n), document_version_id=UUID(int=1000 + n), content_sha256="a" * 64)


@pytest.mark.parametrize("case", ["duplicate_evidence", "empty", "too_long", "control", "lone_surrogate",
                                  "not_text", "too_much_evidence", "unserializable_call", "foreign_call_field",
                                  "unserializable_evidence", "foreign_evidence_field"])
def test_invalid_creation_input_is_a_fixed_refusal_before_any_transaction(world: World, case: str) -> None:
    """Includes exact contract types built with `model_construct` (validation skipped) whose fields cannot even be
    serialized: a lone surrogate or a foreign object. They are refused like any other invalid input."""
    from policyops.services.proposals import ProposalRefused
    from policyops_contracts.proposal import EvidenceRef

    order = world.order_id
    cases: dict[str, dict[str, Any]] = {
        "duplicate_evidence": {"evidence": (evidence_ref(1), evidence_ref(1))},
        "empty": {"rationale": ""},
        "too_long": {"rationale": "x" * 1001},
        "control": {"rationale": "bell\x07"},
        "lone_surrogate": {"rationale": "half\ud800"},
        "not_text": {"rationale": b"bytes"},
        "too_much_evidence": {"evidence": tuple(evidence_ref(n) for n in range(33))},
        "unserializable_call": {"call": CancelPendingOrder.model_construct(
            order_id=order, reason="half\ud800")},  # type: ignore[arg-type]
        "foreign_call_field": {"call": CancelPendingOrder.model_construct(
            order_id=object(), reason="no longer needed")},  # type: ignore[arg-type]
        "unserializable_evidence": {"evidence": (EvidenceRef.model_construct(
            evidence_id=UUID(int=1), document_version_id=UUID(int=2), content_sha256="\udfff"),)},
        "foreign_evidence_field": {"evidence": (EvidenceRef.model_construct(
            evidence_id=object(), document_version_id=UUID(int=2), content_sha256="a" * 64),)},  # type: ignore[arg-type]
    }
    result = create(world, TripwireEngine(), **cases[case])
    assert isinstance(result, ProposalRefused)
    assert (result.code, result.rule_id) == (ErrorCode.INVALID_INPUT, "proposal.input_invalid")


def test_constructed_but_valid_input_is_revalidated_and_created(world: World,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the constructed refusals above: `model_construct` objects with valid values pass intake."""
    from policyops.services.proposals import Created
    from policyops_contracts.proposal import EvidenceRef

    store = FakePersistence(world)
    store.install(monkeypatch)
    call = CancelPendingOrder.model_construct(order_id=world.order_id, reason="no longer needed")
    ref = EvidenceRef.model_construct(evidence_id=UUID(int=1), document_version_id=UUID(int=1001),
                                      content_sha256="a" * 64)
    result = create(world, object(), call=call, evidence=(ref,))
    assert isinstance(result, Created) and result.proposal.evidence == (evidence_ref(1),)
    assert store.writes == ["insert", "audit:proposal.create"]


def test_valid_boundaries_create_and_audit_once(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.services.proposals import Created

    store = FakePersistence(world)
    store.install(monkeypatch)
    boundary = "line one\n\t" + "x" * 990
    assert len(boundary) == 1000
    result = create(world, object(), rationale=boundary, evidence=(evidence_ref(2), evidence_ref(1)))
    assert isinstance(result, Created)
    assert result.proposal.rationale == boundary
    assert [str(item.evidence_id) for item in result.proposal.evidence] == sorted(str(UUID(int=n)) for n in (1, 2))
    assert store.writes == ["insert", "audit:proposal.create"]


def test_a_remaining_contract_failure_is_a_fixed_refusal_with_no_writes(world: World,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulated: `propose` raising a real contract ValidationError (the intake already rules out the known ones)."""
    from policyops.services import proposals as module
    from policyops.services.proposals import ProposalRefused
    from policyops_contracts.proposal import ProposalBody

    store = FakePersistence(world, active=[row_for(cancel_proposal(world))])
    store.install(monkeypatch)

    def failing(**kwargs: Any) -> Any:
        del kwargs
        return ProposalBody.model_validate({})  # raises ValidationError

    monkeypatch.setattr(module, "propose", failing)
    result = create(world, object())
    assert isinstance(result, ProposalRefused) and result.rule_id == "proposal.input_invalid"
    assert result.detail == "the proposal does not satisfy its contract"
    assert store.writes == []  # no supersede, insert or audit


def test_an_unpresentable_proposal_supersedes_and_inserts_nothing(world: World,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.services.proposals import ProposalRefused

    store = FakePersistence(world, active=[row_for(cancel_proposal(world))])
    store.install(monkeypatch)
    lines = (world.item_a,) * 50
    result = create(world, object(), facts=world.facts(order=world.order(items=lines)),
                    call=ModifyPendingOrderItems(order_id=world.order_id, item_ids=lines,
                                                 new_item_ids=(world.item_c,) * 50, payment_method_id=world.card))
    assert isinstance(result, ProposalRefused) and result.rule_id == "presentation.message_limit"
    assert store.writes == []


def test_present_repeats_the_message_bound_for_a_stored_body(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """A body stored without create's guard (older or directly seeded): `present` refuses it after its locks, writing
    no message, presentation, event or audit. Real domain output; persistence is faked."""
    from contextlib import contextmanager
    from types import SimpleNamespace

    from policyops.services import proposals as module
    from policyops.services.proposals import ProposalRefused, ProposalService

    lines = (world.item_a,) * 50
    sealed = propose(proposal_id=uuid4(), proposal_version=1, session=world.session(),
                     call=ModifyPendingOrderItems(order_id=world.order_id, item_ids=lines,
                                                  new_item_ids=(world.item_c,) * 50, payment_method_id=world.card),
                     facts=world.facts(order=world.order(items=lines)), evidence=(), rationale="Seeded directly.",
                     now=world.now)
    assert isinstance(sealed, ActionProposal) and len(sealed.presentation.text) > 4000
    writes: list[str] = []

    @contextmanager
    def transaction(engine: Any, workspace_id: UUID) -> Any:
        del engine, workspace_id
        yield object()

    def write(name: str) -> Any:
        return lambda *args, **kwargs: writes.append(name)

    monkeypatch.setattr(module, "workspace_transaction", transaction)
    monkeypatch.setattr(module, "run_store", SimpleNamespace(
        get_run=lambda connection, run_id, lock: SimpleNamespace(id=world.run, case_id=world.case, terminal=False),
        append_event=write("event")))
    monkeypatch.setattr(module, "repo", SimpleNamespace(
        lock_case=lambda connection, case_id: SimpleNamespace(id=world.case, workspace_id=world.workspace),
        proposal_row=lambda connection, proposal_id, version, lock: row_for(sealed, "created"),
        get_proposal=lambda connection, proposal_id, version: sealed,
        append_message=write("message"), bump_case_version=write("case_version"), mark_presented=write("present"),
        append_audit=write("audit")))
    service = ProposalService(app_engine=object(), clock=FixedLease(world.now + timedelta(seconds=5)))  # type: ignore[arg-type]
    result = service.present(world.run_scope, sealed.proposal_id, 1)
    assert isinstance(result, ProposalRefused)
    assert (result.code, result.rule_id) == (ErrorCode.POLICY_UNSUPPORTED, "presentation.message_limit")
    assert writes == []
