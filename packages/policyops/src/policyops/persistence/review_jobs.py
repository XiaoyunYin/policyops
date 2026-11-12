"""Closed review bindings and idempotent enqueue, separate from ordinary NewJob hashing."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import Field, TypeAdapter
from sqlalchemy import Connection, text

from policyops.persistence import runs as store
from policyops.persistence.database import IdempotencyConflict, ImmutableRecord
from policyops.persistence.records import ExecutionRecord
from policyops.runtime.clock import LeaseClock
from policyops_contracts.base import WireModel
from policyops_contracts.consent import ApprovalDecision
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.scalars import UtcDatetime


REVIEW_KIND = "run.review"
DELIVERY_TIMEOUT = timedelta(hours=24)
MAX_ATTEMPTS = 10
LEASE = timedelta(seconds=30)
Version = Annotated[int, Field(ge=1, le=2**63 - 1)]


class ProposalBinding(WireModel):
    proposal_id: UUID
    proposal_version: Version


class DecisionBinding(ProposalBinding):
    review_trigger: Literal["decision"] = "decision"
    decision_id: UUID


class ExpiryBinding(ProposalBinding):
    review_trigger: Literal["expiry"] = "expiry"


class OutcomeBinding(ProposalBinding):
    review_trigger: Literal["outcome"] = "outcome"
    decision_id: UUID
    execution_id: UUID
    execution_version: Version


ReviewJobBinding = Annotated[DecisionBinding | ExpiryBinding | OutcomeBinding, Field(discriminator="review_trigger")]
BINDING = TypeAdapter(ReviewJobBinding)
REFERENCE_COLUMNS = ("review_trigger", "proposal_id", "proposal_version", "decision_id",
                     "execution_id", "execution_version")


def binding_of(job: store.Job) -> DecisionBinding | ExpiryBinding | OutcomeBinding:
    if job.kind != REVIEW_KIND:
        raise ImmutableRecord("not a review job")
    return BINDING.validate_python({column: getattr(job, column) for column in REFERENCE_COLUMNS
                                   if getattr(job, column) is not None})


class NewReviewJob(WireModel):
    workspace_id: UUID
    run_id: UUID
    binding: ReviewJobBinding
    available_at: UtcDatetime
    created_at: UtcDatetime

    @property
    def key(self) -> str:
        binding = self.binding
        if isinstance(binding, OutcomeBinding):
            return f"review:outcome:{binding.execution_id}:{binding.execution_version}"
        prefix = f"review:{binding.review_trigger}:{binding.proposal_id}:{binding.proposal_version}"
        return f"{prefix}:{binding.decision_id}" if isinstance(binding, DecisionBinding) else prefix


def enqueue(connection: Connection, request: NewReviewJob) -> UUID:
    """Source times and binding are immutable; retries do not renew scheduling or reactivate tombstones."""
    digest = hashlib.sha256(json.dumps(request.model_dump(mode="json"), sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    refs = {column: None for column in REFERENCE_COLUMNS} | request.binding.model_dump()
    params = {"id": uuid4(), "w": request.workspace_id, "r": request.run_id, "key": request.key,
              "sha": digest, "available": request.available_at, "created": request.created_at,
              "deadline": request.available_at + DELIVERY_TIMEOUT, "max": MAX_ATTEMPTS, **refs}
    row = connection.execute(text(
        "INSERT INTO app.jobs (id, workspace_id, run_id, dedupe_key, request_sha256, kind, run_generation, state, "
        "max_attempts, available_at, deadline_at, created_at, updated_at, review_trigger, proposal_id, "
        "proposal_version, decision_id, execution_id, execution_version) VALUES "
        "(:id, :w, :r, :key, :sha, 'run.review', 0, 'queued', :max, :available, :deadline, :created, :created, "
        ":review_trigger, :proposal_id, :proposal_version, :decision_id, :execution_id, :execution_version) "
        "ON CONFLICT (workspace_id, dedupe_key) DO NOTHING RETURNING id"), params).first()
    if row is not None:
        return row[0]  # type: ignore[no-any-return]
    existing = connection.execute(text("SELECT id, request_sha256 FROM app.jobs WHERE workspace_id = :w "
                                       "AND dedupe_key = :key"), params).one()
    if existing.request_sha256 != digest:
        raise IdempotencyConflict("review job intent changed")
    return existing.id  # type: ignore[no-any-return]


def enqueue_decision(connection: Connection, decision: ApprovalDecision) -> UUID:
    return enqueue(connection, NewReviewJob(workspace_id=decision.scope.workspace_id, run_id=decision.scope.run_id,
        binding=DecisionBinding(proposal_id=decision.proposal_id, proposal_version=decision.proposal_version,
                                decision_id=decision.approval_id),
        available_at=decision.decided_at, created_at=decision.decided_at))


def enqueue_expiry(connection: Connection, run: store.Run, proposal: ActionProposal, presented_at: datetime) -> UUID:
    return enqueue(connection, NewReviewJob(workspace_id=run.workspace_id, run_id=run.id,
        binding=ExpiryBinding(proposal_id=proposal.proposal_id, proposal_version=proposal.proposal_version),
        available_at=proposal.expires_at, created_at=presented_at))


def enqueue_outcome(connection: Connection, execution: ExecutionRecord) -> UUID:
    if not execution.terminal and not (execution.state == "unknown" and execution.next_attempt_at is None):
        raise ImmutableRecord("execution has no deliverable outcome")
    return enqueue(connection, NewReviewJob(workspace_id=execution.workspace_id, run_id=execution.run_id,
        binding=OutcomeBinding(proposal_id=execution.proposal_id, proposal_version=execution.proposal_version,
            decision_id=execution.approval_id, execution_id=execution.id, execution_version=execution.version),
        available_at=execution.updated_at, created_at=execution.updated_at))


def check_projection(connection: Connection, token: store.ClaimToken, clock: LeaseClock
                     ) -> tuple[store.Run, store.Job, datetime]:
    """Projection-only capability: outcome binding, current claim and independent delivery deadline.

    This permits terminal/expired runs. T19 reserve independently requires a DecisionBinding,
    so even a live projection claim on a reconciling run cannot authorize a reservation.
    """
    run, job, now = check_claim(connection, token, clock)
    if not isinstance(binding_of(job), OutcomeBinding):
        raise store.Fenced("not_outcome_projection")
    return run, job, now


def check_claim(connection: Connection, token: store.ClaimToken, clock: LeaseClock
                ) -> tuple[store.Run, store.Job, datetime]:
    """Completion fence permits terminal/expired runs, but grants no reservation authority."""
    run = store.get_run(connection, token.run_id, lock=True)
    job = store.get_job(connection, token.job_id, lock=True)
    now = clock.now(connection)
    if run is None or job is None or (run.workspace_id, job.workspace_id, job.run_id) != (
            token.workspace_id, token.workspace_id, run.id):
        raise store.Fenced("review_binding_changed")
    binding_of(job)
    if (job.state, job.claim_id, job.lease_owner, run.generation, job.attempts) != (
            "leased", token.claim_id, token.owner, token.generation, token.attempt):
        raise store.Fenced("claim_lost")
    if job.lease_expires_at is None or job.lease_expires_at <= now:
        raise store.Fenced("lease_expired")
    if job.deadline_at <= now:
        raise store.Fenced("deadline_exceeded")
    return run, job, now
