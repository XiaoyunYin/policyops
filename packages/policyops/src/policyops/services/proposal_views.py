"""Pure typed views, the review-state derivation, the presentation guard, the decision request and list cursors
(T18). Kept apart from the transactional services so they can be tested without a database.

`review_state` derives what a reviewer sees from persisted records and one clock reading; it never writes. Expiry is
computed from timestamps (no background job writes `expired`), and `approved` means only that a bound, unexpired staff
decision exists: nothing has been executed (that is T19's).

Cursors are the canonical encoding of a typed position issued for one workspace and one list. They are untrusted
pagination data, not capabilities: a validly encoded changed position is accepted and simply pages from there, and
row-level security plus explicit workspace filters still bound every row. Anything else is a fixed 422.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, TypeAdapter, ValidationError

from policyops.auth.service import AuthError
from policyops.persistence.repositories import ProposalRow
from policyops_contracts.base import WireModel
from policyops_contracts.consent import ApprovalDecision, CaseMessage, CustomerConsent, ProposalPresentationRecord
from policyops_contracts.errors import ErrorCode
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.scalars import MessageText, PositiveVersion, SafeDetail, Sha256Hex, UtcDatetime


MAX_PROPOSAL_PAGE = 100
MAX_CURSOR_LENGTH = 400
ReviewState = Literal["awaiting_presentation", "awaiting_consent", "awaiting_decision", "approved",
                      "approval_expired", "rejected", "superseded", "expired"]
_MESSAGE_TEXT: TypeAdapter[str] = TypeAdapter(MessageText)


def invalid(detail: str, rule_id: str) -> AuthError:
    return AuthError(422, ErrorCode.INVALID_INPUT, detail, rule_id)


# -- the presentation guard ---------------------------------------------------------------------------------------

def presentable(text_value: str) -> bool:
    """Whether the exact presentation text fits one case message (the same `MessageText` bound `CaseMessage` and the
    `app.case_messages` column enforce: 1..4000 characters, no control characters except newline and tab). An
    exact presentation is never truncated, split or re-rendered."""
    try:
        _MESSAGE_TEXT.validate_python(text_value, strict=True)
    except ValidationError:
        return False
    return True


# -- review state ---------------------------------------------------------------------------------------------------

def review_state(*, row_status: str, presented: bool, consent: CustomerConsent | None,
                 decision: ApprovalDecision | None, expires_at: datetime, now: datetime) -> ReviewState:
    """A superseded version has no authority, whatever was decided on it; its decision stays visible as history."""
    if row_status == "superseded":
        return "superseded"
    if decision is not None:
        if decision.decision == "reject":
            return "rejected"
        return "approved" if now < decision.expires_at else "approval_expired"
    if row_status == "expired" or now >= expires_at:
        return "expired"
    if row_status == "created" or not presented:
        return "awaiting_presentation"
    if consent is None or not (consent.confirmed_at <= now < consent.expires_at):
        return "awaiting_consent"
    return "awaiting_decision"


# -- request --------------------------------------------------------------------------------------------------------

class DecisionRequest(BaseModel):
    """A reviewer's decision on one exact proposal version. The digest is the immutable binding: it must equal the
    sealed proposal's `action_digest`. Integers are strict (no strings or floats); unknown fields are refused."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_version: Annotated[StrictInt, Field(ge=1, le=2**53)]
    action_digest: Sha256Hex
    decision: Literal["approve", "reject"]
    reason: SafeDetail


# -- views (response bodies, also the OpenAPI/TypeScript contract) --------------------------------------------------

class ProposalSummaryView(WireModel):
    proposal_id: UUID
    proposal_version: PositiveVersion
    case_id: UUID
    run_id: UUID
    tool: str
    action_digest: Sha256Hex
    state: ReviewState
    created_at: UtcDatetime
    expires_at: UtcDatetime


class PresentationView(WireModel):
    message_id: UUID
    message_sequence: PositiveVersion
    presented_at: UtcDatetime


class ConsentView(WireModel):
    consent_id: UUID
    customer_message_id: UUID
    customer_message_sequence: PositiveVersion
    customer_message_text: MessageText
    message_source: Literal["simulated_customer", "operator_entered_customer"]
    entered_by: UUID | None
    basis: Literal["explicit_affirmation", "simulator_confirmation_event"]
    confirmed_at: UtcDatetime
    expires_at: UtcDatetime


class ProposalDetailView(WireModel):
    """One version, exactly as sealed (`proposal`), with its presentation, consent, decision and derived state.
    Resource versions are those read when the proposal was created; they are rechecked at execution, not here."""

    proposal: ActionProposal
    row_status: Literal["created", "presented", "superseded", "expired"]
    state: ReviewState
    presentation: PresentationView | None
    consent: ConsentView | None
    decision: ApprovalDecision | None
    server_time: UtcDatetime


class ProposalPage(WireModel):
    items: list[ProposalSummaryView]
    next_cursor: str | None


def summary_view(row: ProposalRow, proposal: ActionProposal, state: ReviewState) -> ProposalSummaryView:
    return ProposalSummaryView(proposal_id=row.proposal_id, proposal_version=row.proposal_version,
                               case_id=row.case_id, run_id=row.run_id, tool=str(proposal.action.tool),
                               action_digest=row.action_digest, state=state, created_at=row.created_at,
                               expires_at=row.expires_at)


def detail_view(*, row: ProposalRow, proposal: ActionProposal, presentation: ProposalPresentationRecord | None,
                consent: CustomerConsent | None, consent_message: CaseMessage | None,
                decision: ApprovalDecision | None, now: datetime) -> ProposalDetailView:
    state = review_state(row_status=row.status, presented=presentation is not None, consent=consent,
                         decision=decision, expires_at=proposal.expires_at, now=now)
    consent_view = None
    if consent is not None and consent_message is not None:
        consent_view = ConsentView(
            consent_id=consent.consent_id, customer_message_id=consent.customer_message_id,
            customer_message_sequence=consent.customer_message_sequence, customer_message_text=consent_message.text,
            message_source=consent.message_source, entered_by=consent.entered_by, basis=consent.basis,
            confirmed_at=consent.confirmed_at, expires_at=consent.expires_at)
    presentation_view = None if presentation is None else PresentationView(
        message_id=presentation.message_id, message_sequence=presentation.message_sequence,
        presented_at=presentation.presented_at)
    return ProposalDetailView(proposal=proposal, row_status=row.status, state=state,  # type: ignore[arg-type]
                              presentation=presentation_view, consent=consent_view, decision=decision,
                              server_time=now)


# -- cursors --------------------------------------------------------------------------------------------------------

class ProposalCursor(WireModel):
    """Position after the last row of a page, bound to the workspace and list it was issued for."""

    v: Literal["policyops.proposal-cursor/v1"] = "policyops.proposal-cursor/v1"
    w: UUID
    lst: Annotated[str, Field(pattern=r"^(inbox|case:[0-9a-f-]{36})$")]
    c: UtcDatetime
    i: UUID


def encode_cursor(cursor: ProposalCursor) -> str:
    return base64.urlsafe_b64encode(cursor.model_dump_json().encode()).rstrip(b"=").decode()


def decode_cursor(value: str, workspace_id: UUID, list_key: str) -> tuple[datetime, UUID]:
    """Only the canonical encoding of a cursor issued for this workspace and list (otherwise a fixed 422)."""
    refused = invalid("The cursor is not valid for this list.", "api.invalid_cursor")
    if not 1 <= len(value) <= MAX_CURSOR_LENGTH or not value.isascii():
        raise refused
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        cursor = ProposalCursor.model_validate_json(raw)
    except (ValidationError, ValueError, binascii.Error):
        raise refused from None
    if encode_cursor(cursor) != value or cursor.w != workspace_id or cursor.lst != list_key:
        raise refused
    return cursor.c, cursor.i


def case_list_key(case_id: UUID) -> str:
    return f"case:{case_id}"
