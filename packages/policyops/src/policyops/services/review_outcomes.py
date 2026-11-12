"""Deterministic refusal summaries. Execution outcome projection is added separately."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4, uuid5

from sqlalchemy import Connection

from policyops.persistence import repositories as repo
from policyops.persistence import runs as store
from policyops.persistence.database import ImmutableRecord
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import ErrorRaised, MessagePosted, RunStateChanged
from policyops_contracts.scalars import CaseScope


MESSAGE_NAMESPACE = UUID("a87ad882-c9f7-5cc8-bc4c-d2eca7a9b5ef")


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
    if not run.terminal:
        failed = store.set_state(connection, run, "failed", now, bump_generation=True)
        store.append_event(connection, failed, RunStateChanged(previous=run.state, current="failed"), now)
    store.end_job(connection, job, state="dead" if dead else "done", now=now, error_code=reason.value)
