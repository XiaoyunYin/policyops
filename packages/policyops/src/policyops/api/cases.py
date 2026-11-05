"""Case and message routes (T08), under /api/v1.

* `GET /cases?status=&cursor=&limit=`: the selected workspace's queue, newest first by the immutable
  `(created_at, id)`; `next_cursor` continues after the last item. The status filter is evaluated per page
  against live rows, so a case that changes status between pages can be skipped or appear on a later page of
  another filter; there is no snapshot across pages.
* `POST /cases`: create an unbound retail case (`Idempotency-Key`).
* `GET /cases/{id}`: one case, with its version as a strong `ETag`.
* `PATCH /cases/{id}`: change the status (`Idempotency-Key`, `If-Match`).
* `GET /cases/{id}/messages?after_sequence=&limit=`: messages in sequence order after a position.
* `POST /cases/{id}/messages`: append a staff note or an operator-entered customer turn (`Idempotency-Key`,
  `If-Match`); appending advances the case version.

Order of refusals (FastAPI 0.162 behavior, covered by tests): `BodyLimit` refuses a malformed, duplicate or
oversized Content-Length (400/413) before the app runs, and FastAPI refuses an undecodable body (400) or malformed
JSON (422) while reading it, both before authorization. Authorization (session, CSRF/Origin on writes, selected
workspace, current role) then runs before the body is validated against its model and before any header parsing,
idempotency lookup, replay or service work; the service rechecks the role after each lock wait. A message's
source-specific permission needs the validated body, so it is checked after body validation, still before the
service. Response bodies are canonical JSON (sorted keys), so a replay is byte-identical to the original
response. Header refusals: a missing `Idempotency-Key` is 400 (as in the IETF httpapi Idempotency-Key draft), a
missing `If-Match` 428, malformed values 422; all use `INVALID_INPUT` with distinct `rule_id`s.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import AfterValidator, BaseModel

from policyops.api import docs
from policyops.api.auth import NO_STORE, Model, Runtime, Session, require_action
from policyops.auth.service import AuthError, Authorized, forbidden
from policyops.domain.case_status import CaseStatus
from policyops.domain.roles import Action, is_allowed
from policyops.services.cases import (
    MAX_CASE_PAGE,
    MAX_CURSOR_LENGTH,
    MAX_MESSAGE_PAGE,
    SOURCE_ACTION,
    CasePage,
    CaseService,
    CaseView,
    MessagePage,
    MessagePosted,
    StaffMessageSource,
    WriteResult,
    etag,
    invalid,
)
from policyops_contracts.errors import ErrorCode
from policyops_contracts.scalars import MessageText


IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._~-]{8,128}")
STRONG_VERSION = re.compile(r'"([1-9][0-9]{0,15})"')
MAX_VERSION = 2**53
DEFAULT_PAGE = 50


def _utf8(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("text must be valid Unicode") from None
    return value


class CreateCaseIn(Model):
    scenario: Literal["retail"]


class StatusIn(Model):
    status: Literal["open", "in_progress", "resolved", "closed"]


class MessageIn(Model):
    source: StaffMessageSource
    text: Annotated[MessageText, AfterValidator(_utf8)]


def case_service(auth: Runtime) -> CaseService:
    return CaseService(app_engine=auth.app_engine, clock=auth.service.clock)


Cases = Annotated[CaseService, Depends(case_service)]


def message_author(session: Session, auth: Runtime) -> Authorized:
    """A member whose role may post some message source; the body's source is checked against it next."""
    authorized = auth.service.authorize(session, Action.VIEW_CASE)
    if not any(is_allowed(authorized.roles, action) for action in SOURCE_ACTION.values()):
        raise forbidden("Your role does not allow this action.", "auth.role")
    return authorized


def idempotency_key(request: Request) -> str:
    values = request.headers.getlist("idempotency-key")
    if not values:
        raise AuthError(400, ErrorCode.INVALID_INPUT, "An Idempotency-Key header is required.",
                        "api.idempotency_key_required")
    if len(values) != 1 or not IDEMPOTENCY_KEY.fullmatch(values[0]):
        raise invalid("The Idempotency-Key header is not valid.", "api.invalid_idempotency_key")
    return values[0]


def expected_version(request: Request) -> int:
    values = request.headers.getlist("if-match")
    if not values:
        raise AuthError(428, ErrorCode.INVALID_INPUT, "An If-Match header with the case ETag is required.",
                        "api.precondition_required")
    match = STRONG_VERSION.fullmatch(values[0]) if len(values) == 1 else None
    if match is None or int(match.group(1)) > MAX_VERSION:
        raise invalid("If-Match must be one strong case ETag.", "api.invalid_precondition")
    return int(match.group(1))


def canonical(body: Any, *, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    content = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return Response(content, status_code=status, media_type="application/json", headers={**NO_STORE,
                                                                                          **(headers or {})})


def view(model: BaseModel, *, headers: dict[str, str] | None = None) -> Response:
    return canonical(model.model_dump(mode="json"), headers=headers)


def written(result: WriteResult, *, location: str | None = None) -> Response:
    headers = {"ETag": result.etag} if result.etag else {}
    if location is not None:
        headers["Location"] = location
    if result.replayed:
        headers["Idempotent-Replayed"] = "true"
    return canonical(result.body, status=result.status, headers=headers)


WRITE_HEADERS = {"ETag": docs.ETAG_HEADER, "Idempotent-Replayed": docs.REPLAYED_HEADER}


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/cases", response_model=CasePage,
                **docs.operation(session=True, errors=(401, 403, 422)))
    def list_cases(authorized: Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))], service: Cases,
                   status: CaseStatus | None = None,
                   cursor: Annotated[str | None, Query(min_length=1, max_length=MAX_CURSOR_LENGTH)] = None,
                   limit: Annotated[int, Query(ge=1, le=MAX_CASE_PAGE)] = DEFAULT_PAGE) -> Response:
        return view(service.list_cases(authorized, status=status, cursor=cursor, limit=limit))

    @router.post("/cases", status_code=201, response_model=CaseView,
                 **docs.operation(csrf=True, headers=[docs.IDEMPOTENCY_KEY], errors=(400, 401, 403, 409, 422),
                                  success={201: {"description": "Created (or the replayed original).",
                                                 "headers": {**WRITE_HEADERS, "Location": docs.LOCATION_HEADER}}}))
    def create_case(request: Request, body: CreateCaseIn,
                    authorized: Annotated[Authorized, Depends(require_action(Action.CREATE_CASE))],
                    service: Cases) -> Response:
        del body  # the only scenario; validated so the intent is explicit
        result = service.create_case(authorized, key=idempotency_key(request))
        return written(result, location=f"/api/v1/cases/{result.case_id}")

    @router.get("/cases/{case_id}", response_model=CaseView,
                **docs.operation(session=True, errors=(401, 403, 404, 422),
                                 success={200: {"description": "The case.", "headers": {"ETag": docs.ETAG_HEADER}}}))
    def get_case(case_id: UUID, authorized: Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))],
                 service: Cases) -> Response:
        case = service.get_case(authorized, case_id)
        return view(case, headers={"ETag": etag(case.version)})

    @router.patch("/cases/{case_id}", response_model=CaseView,
                  **docs.operation(csrf=True, headers=[docs.IDEMPOTENCY_KEY, docs.IF_MATCH],
                                   errors=(400, 401, 403, 404, 409, 422, 428),
                                   success={200: {"description": "The case after the change (or the replayed "
                                                  "original).", "headers": WRITE_HEADERS}}))
    def change_status(case_id: UUID, request: Request, body: StatusIn,
                      authorized: Annotated[Authorized, Depends(require_action(Action.UPDATE_CASE_STATUS))],
                      service: Cases) -> Response:
        key, version = idempotency_key(request), expected_version(request)
        return written(service.change_status(authorized, key=key, case_id=case_id, expected_version=version,
                                             status=CaseStatus(body.status)))

    @router.get("/cases/{case_id}/messages", response_model=MessagePage,
                **docs.operation(session=True, errors=(401, 403, 404, 422)))
    def list_messages(case_id: UUID, authorized: Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))],
                      service: Cases, after_sequence: Annotated[int, Query(ge=0, le=MAX_VERSION)] = 0,
                      limit: Annotated[int, Query(ge=1, le=MAX_MESSAGE_PAGE)] = DEFAULT_PAGE) -> Response:
        return view(service.list_messages(authorized, case_id, after_sequence=after_sequence, limit=limit))

    @router.post("/cases/{case_id}/messages", status_code=201, response_model=MessagePosted,
                 **docs.operation(csrf=True, headers=[docs.IDEMPOTENCY_KEY, docs.IF_MATCH],
                                  errors=(400, 401, 403, 404, 409, 422, 428),
                                  success={201: {"description": "The appended message and the case at its new "
                                                 "version (or the replayed original).", "headers": WRITE_HEADERS}}))
    def post_message(case_id: UUID, request: Request, body: MessageIn,
                     authorized: Annotated[Authorized, Depends(message_author)], service: Cases) -> Response:
        if not is_allowed(authorized.roles, SOURCE_ACTION[body.source]):
            raise forbidden("Your role does not allow this action.", "auth.role")
        key, version = idempotency_key(request), expected_version(request)
        return written(service.post_message(authorized, key=key, case_id=case_id, expected_version=version,
                                            source=body.source, text_value=body.text))

    return router
