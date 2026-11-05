"""Case and message operations behind the HTTP API (T08): reads, and three idempotent writes.

Every write takes the shared idempotent path (`policyops.services.writes.idempotent_write`: key lock, role recheck,
case visibility, replay or 409, then the mutation and the stored response in one transaction). Status and message
writes then lock the case row, recheck the role again after that wait, check the strong `If-Match` version, mutate
and append one actor-attributed audit row.

A status change to the current status is a no-op: no version change and no audit row (the response is still
recorded for the key). Appending a message advances the case version under the same lock as sequence allocation.
Callers authorize before calling (`policyops.api.auth.require_action` or `AuthService.authorize`).
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import Connection, Engine

from policyops.auth.service import AuthError, Authorized
from policyops.domain.case_status import CaseStatus, TransitionRefused, plan_transition
from policyops.domain.roles import Action
from policyops.persistence import idempotency as idem
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.persistence.records import CaseRecord, NewCase
from policyops.services.writes import WriteResult, audit, idempotent_write, not_found, recheck
from policyops_contracts.base import WireModel
from policyops_contracts.clock import Clock
from policyops_contracts.consent import CaseMessage, MessageSource
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.scalars import CaseScope, MessageText, PositiveVersion, Sequence, Sha256Hex, Slug, UtcDatetime


SCENARIO: Literal["retail"] = "retail"
MAX_CASE_PAGE = 100
MAX_MESSAGE_PAGE = 200
MAX_CURSOR_LENGTH = 400
StaffMessageSource = Literal["staff_note", "operator_entered_customer"]
SOURCE_ACTION: dict[str, Action] = {"staff_note": Action.POST_STAFF_NOTE,
                                    "operator_entered_customer": Action.ENTER_CUSTOMER_TURN}


def etag(version: int) -> str:
    return f'"{version}"'


def invalid(detail: str, rule_id: str) -> AuthError:
    return AuthError(422, ErrorCode.INVALID_INPUT, detail, rule_id)


# -- response bodies (also the OpenAPI/TypeScript contract) -------------------------------------------------

class CaseView(WireModel):
    case_id: UUID
    scenario: Slug  # as stored: the API creates only retail cases, trusted seed paths may create others
    status: CaseStatus
    customer_bound: bool
    created_at: UtcDatetime
    updated_at: UtcDatetime
    version: PositiveVersion


class MessageView(WireModel):
    message_id: UUID
    case_id: UUID
    sequence: Sequence
    source: MessageSource
    entered_by: UUID | None
    text: MessageText
    text_sha256: Sha256Hex
    created_at: UtcDatetime


class CasePage(WireModel):
    items: list[CaseView]
    next_cursor: str | None


class MessagePage(WireModel):
    items: list[MessageView]
    next_after_sequence: Sequence | None


class MessagePosted(WireModel):
    message: MessageView
    case: CaseView


def case_view(case: CaseRecord) -> CaseView:
    return CaseView(case_id=case.id, scenario=case.scenario, status=CaseStatus(case.status),
                    customer_bound=case.customer_user_id is not None, created_at=case.created_at,
                    updated_at=case.updated_at, version=case.version)


def message_view(message: CaseMessage) -> MessageView:
    return MessageView(message_id=message.message_id, case_id=message.scope.case_id, sequence=message.sequence,
                       source=message.source, entered_by=message.entered_by, text=message.text,
                       text_sha256=message.text_sha256, created_at=message.created_at)


# -- cursors (untrusted pagination data, never an authorization token) ---------------------------------------

class CaseCursor(WireModel):
    """Position after the last case of a page, bound to the workspace and status filter it was issued for."""

    v: Literal["policyops.case-cursor/v1"] = "policyops.case-cursor/v1"
    w: UUID
    s: CaseStatus | None
    c: UtcDatetime
    i: UUID


def encode_cursor(cursor: CaseCursor) -> str:
    return base64.urlsafe_b64encode(cursor.model_dump_json().encode()).rstrip(b"=").decode()


def decode_cursor(value: str, workspace_id: UUID, status: CaseStatus | None) -> tuple[datetime, UUID]:
    """Strictly typed, and only the canonical encoding of a cursor issued for this workspace and filter."""
    refused = invalid("The cursor is not valid for this list.", "api.invalid_cursor")
    if not 1 <= len(value) <= MAX_CURSOR_LENGTH or not value.isascii():
        raise refused
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        cursor = CaseCursor.model_validate_json(raw)
    except (ValidationError, ValueError, binascii.Error):
        raise refused from None
    if encode_cursor(cursor) != value or cursor.w != workspace_id or cursor.s != status:
        raise refused
    return cursor.c, cursor.i


@dataclass
class CaseService:
    app_engine: Engine
    clock: Clock

    # -- reads -----------------------------------------------------------------------------------------------

    def list_cases(self, authorized: Authorized, *, status: CaseStatus | None, cursor: str | None,
                   limit: int) -> CasePage:
        if not 1 <= limit <= MAX_CASE_PAGE:
            raise invalid(f"limit must be between 1 and {MAX_CASE_PAGE}.", "api.invalid_limit")
        before = decode_cursor(cursor, authorized.workspace_id, status) if cursor is not None else None
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            rows = repo.case_page(connection, status=status.value if status else None, before=before,
                                  limit=limit + 1)
        page, more = rows[:limit], len(rows) > limit
        next_cursor = encode_cursor(CaseCursor(w=authorized.workspace_id, s=status, c=page[-1].created_at,
                                               i=page[-1].id)) if more else None
        return CasePage(items=[case_view(case) for case in page], next_cursor=next_cursor)

    def get_case(self, authorized: Authorized, case_id: UUID) -> CaseView:
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            case = repo.get_case(connection, case_id)
        if case is None:
            raise not_found()
        return case_view(case)

    def list_messages(self, authorized: Authorized, case_id: UUID, *, after_sequence: int,
                      limit: int) -> MessagePage:
        if not 1 <= limit <= MAX_MESSAGE_PAGE or after_sequence < 0:
            raise invalid(f"limit must be 1 to {MAX_MESSAGE_PAGE} and after_sequence non-negative.",
                          "api.invalid_limit")
        scope = CaseScope(workspace_id=authorized.workspace_id, case_id=case_id)
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            if repo.get_case(connection, case_id) is None:
                raise not_found()
            messages = repo.list_messages(connection, scope, after_sequence=after_sequence, limit=limit)
        return MessagePage(items=[message_view(message) for message in messages],
                           next_after_sequence=messages[-1].sequence if len(messages) == limit else None)

    # -- writes ----------------------------------------------------------------------------------------------

    def _write(self, authorized: Authorized, *, key: str, intent: idem.Intent, action: Action,
               target_case: UUID | None, mutate: Callable[[Connection], WriteResult]) -> WriteResult:
        def visible(connection: Connection) -> bool:
            return repo.get_case(connection, target_case) is not None  # type: ignore[arg-type]

        return idempotent_write(self.app_engine, authorized, key=key, intent=intent, action=action,
                                visible=visible if target_case is not None else None, missing="case",
                                mutate=mutate, now=lambda _connection: self.clock.now())

    def _recheck(self, connection: Connection, authorized: Authorized, action: Action) -> None:
        recheck(connection, authorized, action)

    def _audit(self, connection: Connection, authorized: Authorized, *, action: str, target_type: str,
               target_id: UUID, before: str | None, after: str | None) -> None:
        audit(connection, authorized, action=action, target_type=target_type, target_id=target_id, before=before,
              after=after, occurred_at=self.clock.now())

    def create_case(self, authorized: Authorized, *, key: str) -> WriteResult:
        def mutate(connection: Connection) -> WriteResult:
            case = repo.create_case(connection, NewCase(
                id=uuid4(), workspace_id=authorized.workspace_id, scenario=SCENARIO, customer_user_id=None,
                created_by=authorized.session.principal_id, created_at=self.clock.now()))
            self._audit(connection, authorized, action="case.created", target_type="case", target_id=case.id,
                        before=None, after=text_sha256(case.status))
            return WriteResult(201, case_view(case).model_dump(mode="json"), etag(case.version), case.id, None,
                               replayed=False)

        return self._write(authorized, key=key, intent=idem.CreateCaseIntent(scenario=SCENARIO),
                           action=Action.CREATE_CASE, target_case=None, mutate=mutate)

    def _locked_case(self, connection: Connection, authorized: Authorized, case_id: UUID, action: Action,
                     expected_version: int) -> CaseRecord:
        case = repo.lock_case(connection, case_id)
        if case is None:
            raise not_found()
        self._recheck(connection, authorized, action)  # after waiting for the case lock
        if case.version != expected_version:
            raise AuthError(409, ErrorCode.STALE_VERSION, "The case changed; reload it and retry.",
                            "api.stale_version")
        return case

    def change_status(self, authorized: Authorized, *, key: str, case_id: UUID, expected_version: int,
                      status: CaseStatus) -> WriteResult:
        def mutate(connection: Connection) -> WriteResult:
            case = self._locked_case(connection, authorized, case_id, Action.UPDATE_CASE_STATUS, expected_version)
            try:
                changes = plan_transition(CaseStatus(case.status), status)
            except TransitionRefused as exc:
                raise AuthError(409, ErrorCode.CONFLICT, str(exc).capitalize() + ".", "api.status_transition") \
                    from None
            if changes:
                updated = repo.set_case_status(connection, case_id, expected_version=case.version,
                                               status=status.value, now=self.clock.now())
                self._audit(connection, authorized, action="case.status_changed", target_type="case",
                            target_id=case_id, before=text_sha256(case.status), after=text_sha256(status.value))
                case = updated
            return WriteResult(200, case_view(case).model_dump(mode="json"), etag(case.version), case_id, None,
                               replayed=False)

        intent = idem.StatusIntent(case_id=case_id, expected_version=expected_version, status=status.value)
        return self._write(authorized, key=key, intent=intent, action=Action.UPDATE_CASE_STATUS,
                           target_case=case_id, mutate=mutate)

    def post_message(self, authorized: Authorized, *, key: str, case_id: UUID, expected_version: int,
                     source: StaffMessageSource, text_value: str) -> WriteResult:
        action = SOURCE_ACTION[source]

        def mutate(connection: Connection) -> WriteResult:
            self._locked_case(connection, authorized, case_id, action, expected_version)
            now = self.clock.now()
            message = repo.append_message(
                connection, message_id=uuid4(), scope=CaseScope(workspace_id=authorized.workspace_id,
                                                                case_id=case_id),
                source=source, entered_by=authorized.session.principal_id, text_value=text_value, created_at=now)
            case = repo.bump_case_version(connection, case_id, now)
            self._audit(connection, authorized, action="case.message_posted", target_type="case_message",
                        target_id=message.message_id, before=None, after=message.text_sha256)
            posted = MessagePosted(message=message_view(message), case=case_view(case))
            return WriteResult(201, posted.model_dump(mode="json"), etag(case.version), case_id,
                               message.message_id, replayed=False)

        intent = idem.MessageIntent(case_id=case_id, expected_version=expected_version, source=source,
                                    text=text_value)
        return self._write(authorized, key=key, intent=intent, action=action, target_case=case_id, mutate=mutate)
