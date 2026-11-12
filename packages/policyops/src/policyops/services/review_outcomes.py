"""Deterministic, version-keyed projections of durable review and execution truth."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
from uuid import UUID, uuid4, uuid5

from sqlalchemy import Connection

from policyops.persistence import executions as ledger
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs as jobs
from policyops.persistence import runs as store
from policyops.persistence.database import ImmutableRecord
from policyops.persistence.records import ExecutionRecord
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import (
    ErrorRaised,
    MessagePosted,
    ReviewOutcome,
    ReviewReason,
    RunState,
    RunStateChanged,
)
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.scalars import CaseScope


MESSAGE_NAMESPACE = UUID("a87ad882-c9f7-5cc8-bc4c-d2eca7a9b5ef")
OUTCOME_NAMESPACE = UUID("c5d62058-a328-5ee8-a408-c5740ce9474e")


class RefusalReason(StrEnum):
    REVIEW_REJECTED = "review_rejected"
    PROPOSAL_EXPIRED = "proposal_expired"
    PROPOSAL_STALE = "proposal_stale"
    RUN_DEADLINE = "run_deadline_exceeded"
    RUN_TERMINAL = "run_terminal"
    INITIATOR_REVOKED = "initiator_not_authorized"
    PRECHECK_REFUSED = "precheck_refused"
    RECORD_INVALID = "review_record_invalid"
    RETRIES_EXHAUSTED = "review_retries_exhausted"


def refusal_message_id(workspace_id: UUID, run_id: UUID, job_id: UUID) -> UUID:
    return uuid5(MESSAGE_NAMESPACE, f"{workspace_id}:{run_id}:{job_id}:refused")


def refusal_text(reason: RefusalReason) -> str:
    return f"Action refused ({reason.value}). No action was executed by this run."


def outcome_message_id(workspace_id: UUID, run_id: UUID, execution_id: UUID, version: int) -> UUID:
    return uuid5(OUTCOME_NAMESPACE, f"{workspace_id}:{run_id}:{execution_id}:{version}")


@dataclass(frozen=True)
class Projection:
    text: str
    event: ReviewOutcome
    state: RunState


def execution_projection(execution: ExecutionRecord, proposal: ActionProposal) -> Projection:
    """Use validated immutable identifiers and receipt fields only; no mutable run state or free-form codes."""
    if (proposal.scope.workspace_id, proposal.scope.case_id, proposal.scope.run_id,
            proposal.proposal_id, proposal.proposal_version, proposal.action_digest, str(proposal.action.tool)) != (
            execution.workspace_id, execution.case_id, execution.run_id, execution.proposal_id,
            execution.proposal_version, execution.action_digest, execution.tool):
        raise ImmutableRecord("outcome proposal binding changed")
    if (execution.request.call, execution.request.expected_effect, execution.request.intent_sha256) != (
            proposal.action, proposal.effect, proposal.action_digest):
        raise ImmutableRecord("outcome request does not match proposal")
    identity = outcome_message_id(execution.workspace_id, execution.run_id, execution.id, execution.version)
    outcome: ReviewOutcome
    fields = dict(proposal_id=execution.proposal_id, proposal_version=execution.proposal_version,
                  decision_id=execution.approval_id, execution_id=execution.id, operation_id=execution.operation_id,
                  message_id=identity, observed_ledger_version=execution.version)
    receipt = execution.receipt
    if execution.state == "succeeded" and execution.outcome == "committed":
        if receipt is None or (receipt.operation_id, receipt.operation_sha256, receipt.tool, receipt.actual_effect) != (
                str(execution.operation_id), execution.operation_sha256, execution.tool,
                execution.request.expected_effect):
            raise ImmutableRecord("success has no valid bound receipt")
        sha = hashlib.sha256(receipt.model_dump_json().encode()).hexdigest()
        outcome = ReviewOutcome.model_validate(fields | {"outcome": "succeeded", "reason": ReviewReason.COMMITTED,
                                                        "receipt_sha256": sha})
        text = (f"Action committed: {receipt.tool}. Operation {receipt.operation_id}; receipt SHA-256 {sha}; "
                f"remote case version {receipt.case_version_before} -> {receipt.case_version_after}; "
                f"committed at {receipt.committed_at.isoformat()}.")
        state: RunState = "succeeded"
    elif execution.state == "reconciled" and execution.outcome == "fenced" and receipt is None:
        outcome = ReviewOutcome.model_validate(fields | {"outcome": "reconciled", "reason": ReviewReason.FENCED})
        text = f"Operation {execution.operation_id} fenced. No business effect committed."
        state = "succeeded"
    elif execution.state == "unknown" and execution.next_attempt_at is None and receipt is None:
        if execution.outcome is not None:
            raise ImmutableRecord("unknown execution has a stored outcome")
        outcome = ReviewOutcome.model_validate(fields | {"outcome": "unknown", "reason": ReviewReason.UNCONFIRMED})
        text = f"Operation {execution.operation_id}: outcome unconfirmed; requires reconciliation."
        state = "reconciling"
    elif execution.state == "failed" and receipt is None and execution.outcome in (
            "upstream_rejected", "effect_mismatch", "money_unrepresentable", "version_conflict",
            "precheck_refused", "cancelled_before_dispatch"):
        reason = ReviewReason(execution.outcome)
        outcome = ReviewOutcome.model_validate(fields | {"outcome": "refused", "reason": reason})
        text = f"Action refused ({reason.value}). Operation {execution.operation_id}; no business effect committed."
        state = "failed"
    else:
        raise ImmutableRecord("execution has no valid projectable truth")
    if len(text) > 4000:
        raise ImmutableRecord("outcome summary exceeds message limit")
    return Projection(text, outcome, state)


def finish_outcome(connection: Connection, run: store.Run, job: store.Job, now: datetime) -> None:
    """Caller holds case -> run -> job and the projection fence; T19 writes truth under this same run lock."""
    binding = jobs.binding_of(job)
    if not isinstance(binding, jobs.OutcomeBinding):
        raise ImmutableRecord("not an outcome job")
    execution = ledger.get(connection, binding.execution_id)
    proposal = repo.get_proposal(connection, binding.proposal_id, binding.proposal_version)
    if execution is None or proposal is None or (
            execution.workspace_id, execution.case_id, execution.run_id, execution.proposal_id,
            execution.proposal_version, execution.approval_id) != (
            run.workspace_id, run.case_id, run.id, binding.proposal_id, binding.proposal_version,
            binding.decision_id) or execution.version < binding.execution_version:
        raise ImmutableRecord("outcome job does not bind current ledger truth")
    projection = execution_projection(execution, proposal)
    scope = CaseScope(workspace_id=run.workspace_id, case_id=run.case_id)
    identity = projection.event.message_id
    message = repo.message_by_id(connection, scope, identity)
    if message is not None:
        if message.source != "agent" or message.entered_by is not None or message.text != projection.text:
            raise ImmutableRecord("outcome summary changed")
    else:
        message = repo.append_message(connection, message_id=identity, scope=scope, source="agent", entered_by=None,
                                      text_value=projection.text, created_at=now)
        repo.bump_case_version(connection, run.case_id, now)
        store.append_event(connection, run, MessagePosted(message_id=identity, message_sequence=message.sequence,
                                                         source="agent"), now)
        store.append_event(connection, run, projection.event, now)
        if not run.terminal and run.state != projection.state:
            updated = store.set_state(connection, run, projection.state, now)
            store.append_event(connection, updated, RunStateChanged(previous=run.state, current=projection.state), now)
    store.end_job(connection, job, state="done", now=now)


def finish_refusal(connection: Connection, run: store.Run, job: store.Job, reason: RefusalReason,
                   now: datetime, *, dead: bool = False) -> None:
    """Caller holds case -> run -> job locks and has checked there is no execution for the decision."""
    scope = CaseScope(workspace_id=run.workspace_id, case_id=run.case_id)
    identity = refusal_message_id(run.workspace_id, run.id, job.id)
    message = repo.message_by_id(connection, scope, identity)
    text = refusal_text(reason)
    if message is not None:
        if message.source != "agent" or message.text != text:
            raise ImmutableRecord("review refusal summary changed")
    else:
        message = repo.append_message(connection, message_id=identity, scope=scope, source="agent", entered_by=None,
                                      text_value=text, created_at=now)
        repo.bump_case_version(connection, run.case_id, now)
        store.append_event(connection, run, MessagePosted(message_id=identity, message_sequence=message.sequence,
                                                         source="agent"), now)
        store.append_event(connection, run, ErrorRaised(code=ErrorCode.CONFLICT, rule_id=f"review.{reason.value}",
                                                        correlation_id=uuid4(), retryable=False), now)
        binding = jobs.binding_of(job)
        store.append_event(connection, run, ReviewOutcome(
            proposal_id=binding.proposal_id, proposal_version=binding.proposal_version,
            decision_id=binding.decision_id if isinstance(binding, jobs.DecisionBinding) else None,
            outcome="refused", reason=ReviewReason(reason.value), message_id=identity), now)
    if not run.terminal:
        failed = store.set_state(connection, run, "failed", now, bump_generation=True)
        store.append_event(connection, failed, RunStateChanged(previous=run.state, current="failed"), now)
    store.end_job(connection, job, state="dead" if dead else "done", now=now, error_code=reason.value)
