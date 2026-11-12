"""T22 delivery rules and capability boundaries, with no database or remote calls."""

from contextlib import nullcontext
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
import pytest

from policyops.domain.examples import World, build_examples
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs as jobs
from policyops.persistence import runs as store
from policyops.persistence.database import ImmutableRecord
from policyops.persistence.records import ExecutionRecord
from policyops.runtime.clock import FixedLeaseClock, UnsafeTestHook
from policyops.runtime.review import ProjectOutcome, ReviewRuntime
from policyops.services import review_outcomes as projection
from policyops.services.execution import Executor
from policyops.services.proposals import ProposalService
from policyops_contracts.clock import FixedClock
from policyops_contracts.consent import SimulatorConfirmationEvent
from policyops_contracts.events import ReviewOutcome, ReviewReason
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail_service import MutationRequest, Receipt
from tests.unit.test_review_runtime import job
from tests.unit.test_runs_unit import run_record


def truth(**changes: Any) -> tuple[ExecutionRecord, ActionProposal]:
    proposal = ActionProposal.model_validate_json(build_examples()["action-proposal.exchange.json"])
    operation = uuid4()
    request = MutationRequest(call=proposal.action, expected_effect=proposal.effect,
                              intent_sha256=proposal.action_digest, expected_versions=proposal.resource_versions)
    receipt = Receipt(operation_id=str(operation), operation_sha256="a"*64, tool=proposal.action.tool,
        actual_effect=proposal.effect, case_version_before=1, case_version_after=2,
        resource_versions_after=proposal.resource_versions, state_sha256_after="b"*64, committed_at=World.now)
    row = dict(id=uuid4(), workspace_id=proposal.scope.workspace_id, case_id=proposal.scope.case_id,
        run_id=proposal.scope.run_id, operation_id=operation, proposal_id=proposal.proposal_id,
        proposal_version=proposal.proposal_version, action_digest=proposal.action_digest, approval_id=uuid4(),
        consent_id=uuid4(), argument_digest="c"*64, tool=str(proposal.action.tool), target_kind="order",
        target_id=World.order_id, operation_sha256="a"*64, request=request, authorization_not_after=proposal.expires_at,
        state="succeeded", attempts=1, reconcile_attempts=0, outcome="committed", resolved_by="response",
        last_code=None, receipt=receipt, claim_id=None, lease_owner=None, lease_expires_at=None,
        dispatched_at=World.now, next_attempt_at=None, created_at=World.now, updated_at=World.now, version=4)
    return ExecutionRecord.model_validate(row | changes), proposal


@pytest.mark.parametrize("state,outcome,expected,final", [
    ("succeeded", "committed", "succeeded", "succeeded"),
    ("reconciled", "fenced", "reconciled", "succeeded"),
    ("failed", "upstream_rejected", "refused", "failed"),
    ("failed", "effect_mismatch", "refused", "failed"),
    ("failed", "money_unrepresentable", "refused", "failed"),
    ("failed", "version_conflict", "refused", "failed"),
    ("failed", "precheck_refused", "refused", "failed"),
    ("failed", "cancelled_before_dispatch", "refused", "failed"),
    ("unknown", None, "unknown", "reconciling"),
])
def test_outcome_table_is_factual_bounded_and_deterministic(state: str, outcome: str | None,
                                                          expected: str, final: str) -> None:
    row, proposal = truth()
    if state != "succeeded":
        row = ExecutionRecord.model_validate(row.model_dump() | {"state": state, "outcome": outcome, "receipt": None})
    value = projection.execution_projection(row, proposal)
    assert value == projection.execution_projection(row, proposal)
    assert value.event.outcome == expected and value.state == final and len(value.text) <= 4000
    assert value.event.observed_ledger_version == row.version
    if expected == "succeeded":
        assert row.receipt is not None and row.receipt.operation_id in value.text
        assert value.event.receipt_sha256 is not None
        assert value.event.receipt_sha256 in value.text
    elif expected == "unknown":
        assert "unconfirmed" in value.text and "reconciliation" in value.text
        assert not any(word in value.text.lower() for word in ("success", "completed", "committed"))
    assert projection.outcome_message_id(row.workspace_id, row.run_id, row.id, row.version+1) != value.event.message_id


@pytest.mark.parametrize("fault", ["missing_receipt", "receipt_operation", "receipt_hash", "receipt_tool",
                                  "proposal", "backoff", "pending", "state_outcome"])
def test_unprojectable_or_unbound_truth_fails_closed(fault: str) -> None:
    row, proposal = truth()
    assert row.receipt is not None
    changes: dict[str, Any] = {}
    if fault == "missing_receipt":
        changes["receipt"] = None
    elif fault.startswith("receipt_"):
        field, value = {"receipt_operation": ("operation_id", str(uuid4())),
                        "receipt_hash": ("operation_sha256", "f"*64),
                        "receipt_tool": ("tool", "cancel_pending_order")}[fault]
        changes["receipt"] = row.receipt.model_copy(update={field: value})
    elif fault == "proposal":
        changes["proposal_id"] = uuid4()
    elif fault == "backoff":
        changes = dict(state="unknown", outcome=None, receipt=None, next_attempt_at=World.now+timedelta(seconds=1))
    elif fault == "pending":
        changes = dict(state="pending", outcome=None, receipt=None)
    else:
        changes = dict(state="failed", outcome="committed")
    with pytest.raises(ImmutableRecord):
        projection.execution_projection(ExecutionRecord.model_validate(row.model_dump() | changes), proposal)


@pytest.mark.parametrize("state,next_attempt,expected", [
    ("pending", True, False), ("dispatched", True, False), ("unknown", True, False),
    ("unknown", False, True), ("succeeded", False, True), ("failed", False, True), ("reconciled", False, True)])
def test_changed_enqueues_only_terminal_or_capped_unknown_in_its_transaction(
        monkeypatch: pytest.MonkeyPatch, state: str, next_attempt: bool, expected: bool) -> None:
    row, _ = truth()
    row = row.model_copy(update={"state": state, "next_attempt_at": World.now if next_attempt else None})
    conn: Any = object()
    calls: list[Any] = []
    monkeypatch.setattr(store, "append_event", lambda *args: None)
    monkeypatch.setattr(repo, "append_audit", lambda *args: None)
    monkeypatch.setattr(jobs, "enqueue_outcome", lambda connection, record: calls.append((connection, record)))
    Executor._changed(object(), conn, run_record(), row, World.now, "execution.recorded")  # type: ignore[arg-type]
    assert calls == ([(conn, row)] if expected else [])


@pytest.mark.parametrize("env", [None, "local", "deployment", "production", "TEST"])
def test_simulator_event_requires_explicit_test_environment_before_io(env: str | None) -> None:
    event = SimulatorConfirmationEvent(proposal_id=uuid4(), proposal_version=1,
                                       action_digest="a"*64, decision="confirm")
    service = ProposalService(app_engine=None, clock=FixedLeaseClock(FixedClock(World.now)))  # type: ignore[arg-type]
    with pytest.raises(UnsafeTestHook):
        service.record_customer_reply(World().run_scope, uuid4(), simulator_event=event, env=env)


def test_explicit_test_environment_allows_simulator_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.domain.consent_rules import NotConsent
    from policyops.services import proposals as module

    event = SimulatorConfirmationEvent(proposal_id=uuid4(), proposal_version=1,
                                       action_digest="a"*64, decision="confirm")
    outcome = NotConsent("fixture")
    seen: list[object] = []
    monkeypatch.setattr(module, "workspace_transaction", lambda *args: nullcontext(object()))

    def record(*args: Any, simulator_event: Any) -> NotConsent:
        seen.append(simulator_event)
        return outcome

    monkeypatch.setattr(module, "_record_customer_reply_tx", record)
    service = ProposalService(app_engine=None, clock=FixedLeaseClock(FixedClock(World.now)))  # type: ignore[arg-type]
    assert service.record_customer_reply(World().run_scope, uuid4(), simulator_event=event, env="test") == outcome
    assert seen == [event]


@pytest.mark.parametrize("changes", [
    {"reason": "invented"}, {"outcome": "completed"}, {"customer_text": "yes"},
    {"operation_id": None}, {"decision_id": None}, {"observed_ledger_version": 0},
    {"receipt_sha256": "a"*64}, {"reason": ReviewReason.COMMITTED},
])
def test_outcome_event_is_closed_and_unknown_cannot_claim_success(changes: dict[str, Any]) -> None:
    row, proposal = truth(state="unknown", outcome=None, receipt=None)
    value = projection.execution_projection(row, proposal).event
    with pytest.raises(ValidationError):
        ReviewOutcome.model_validate(value.model_dump() | changes)


def test_openapi_exports_the_sse_data_contract_and_review_outcome() -> None:
    from policyops.api.openapi import document, schema_app

    api = document(schema_app())
    schemas = api["components"]["schemas"]
    assert "EventEnvelope" in schemas and "RunEventReviewOutcome" in schemas
    assert schemas["RunEventReviewOutcome"]["additionalProperties"] is False
    stream = api["paths"]["/api/v1/runs/{run_id}/events"]["get"]["responses"]["200"]["content"]["text/event-stream"]
    assert stream["schema"] == {"type": "string"}
    assert stream["x-event-schema"] == {"$ref": "#/components/schemas/EventEnvelope"}


def test_outcome_execute_is_projection_only_and_works_after_run_deadline(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.runtime import review as module

    row, _ = truth()
    run = run_record().model_copy(update={"state": "cancelled", "deadline_at": World.now-timedelta(seconds=1)})
    work = job(review_trigger="outcome", decision_id=row.approval_id, execution_id=row.id, execution_version=4)
    conn: Any = object()
    monkeypatch.setattr(module, "workspace_transaction", lambda *args: nullcontext(conn))
    monkeypatch.setattr(jobs, "check_claim", lambda *args: (run, work, World.now))
    checked: list[bool] = []
    monkeypatch.setattr(jobs, "check_projection", lambda *args: checked.append(True))
    # Ports are absent; touching scope resolution/reservation/model/retail would fail.
    runtime = ReviewRuntime(SimpleNamespace(engine=None, clock=None))  # type: ignore[arg-type]
    token = store.ClaimToken(workspace_id=run.workspace_id, run_id=run.id, job_id=work.id,
                             claim_id=uuid4(), owner=uuid4(), generation=run.generation, attempt=1)
    assert isinstance(runtime.execute(token), ProjectOutcome) and checked == [True]
