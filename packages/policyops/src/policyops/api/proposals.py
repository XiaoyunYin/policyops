"""Proposal review routes (T18), under /api/v1.

* `GET /approvals?cursor=&limit=`: the reviewer inbox (DECIDE_PROPOSAL): presented versions with a consent current
  now and no decision, oldest first by the immutable `(created_at, id)`.
* `GET /cases/{id}/proposals?cursor=&limit=`: every version in the case with its derived state (VIEW_CASE); the
  bounded, paginated history.
* `GET /proposals/{id}?version=`: one version (the latest by default), exactly as sealed, with its presentation,
  consent, decision, derived state and the server time (VIEW_CASE). No `ETag` or conditional read is offered: the
  derived parts change while the sealed version does not; the immutable binding is the decision's `action_digest`.
* `POST /proposals/{id}/decision`: approve or reject one exact version (DECIDE_PROPOSAL, CSRF and Origin). The body is
  the immutable `ApprovalDecision`, as canonical JSON: 201 when new, 200 (with `Idempotent-Replayed: true`) for an
  identical request by the same reviewer, with the original bytes. There is no `Idempotency-Key`: the natural key
  `(proposal_id, proposal_version)` and exact equality are the idempotency rule. A failure raised by COMMIT is 503
  `api.decision_outcome_unknown` with `retryable: true`; resending the identical request replays the original if it
  committed.

No route creates, presents, consents to or executes a proposal. The clock is the run API's lease clock (the database
clock in production), read after locks.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response

from policyops.api import docs
from policyops.api.auth import NO_STORE, Runtime, require_action
from policyops.api.cases import canonical, view
from policyops.auth.service import Authorized
from policyops.domain.roles import Action
from policyops.runtime.clock import LeaseClock
from policyops.services.decisions import DecisionCommitUnknown, DecisionService
from policyops.services.proposal_views import (
    MAX_CURSOR_LENGTH,
    MAX_PROPOSAL_PAGE,
    DecisionRequest,
    ProposalDetailView,
    ProposalPage,
)
from policyops.services.proposals import ProposalService
from policyops_contracts.consent import ApprovalDecision
from policyops_contracts.errors import ErrorCode, ErrorEnvelope


DEFAULT_PAGE = 50
MAX_VERSION = 2**53


def _clock(request: Request) -> LeaseClock:
    clock: LeaseClock = request.app.state.runs.service.clock  # the run API's validated lease clock
    return clock


def proposal_service(request: Request, auth: Runtime) -> ProposalService:
    return ProposalService(app_engine=auth.app_engine, clock=_clock(request))


def decision_service(request: Request, auth: Runtime) -> DecisionService:
    return DecisionService(app_engine=auth.app_engine, clock=_clock(request))


Proposals = Annotated[ProposalService, Depends(proposal_service)]
Decisions = Annotated[DecisionService, Depends(decision_service)]


def _documented(errors: tuple[int, ...], **kwargs: Any) -> dict[str, Any]:
    operation = docs.operation(errors=errors, **kwargs)
    responses = operation["responses"]
    if 409 in responses:
        responses[409] = {**responses[409], "description": "Conflict: digest mismatch, already decided, superseded, "
                          "not presented, policy changed, expired proposal or consent, ended run, or no current "
                          "customer confirmation."}
    if 503 in responses:
        responses[503] = {**responses[503], "description": "The decision's commit outcome is unknown (retryable: "
                          "resend the identical request, which replays the original if it committed)."}
    return operation


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/approvals", response_model=ProposalPage, **_documented((401, 403, 422), session=True))
    def list_approvals(authorized: Annotated[Authorized, Depends(require_action(Action.DECIDE_PROPOSAL))],
                       service: Proposals,
                       cursor: Annotated[str | None, Query(min_length=1, max_length=MAX_CURSOR_LENGTH)] = None,
                       limit: Annotated[int, Query(ge=1, le=MAX_PROPOSAL_PAGE)] = DEFAULT_PAGE) -> Response:
        return view(service.inbox(authorized, cursor=cursor, limit=limit))

    @router.get("/cases/{case_id}/proposals", response_model=ProposalPage,
                **_documented((401, 403, 404, 422), session=True))
    def list_case_proposals(case_id: UUID,
                            authorized: Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))],
                            service: Proposals,
                            cursor: Annotated[str | None, Query(min_length=1, max_length=MAX_CURSOR_LENGTH)] = None,
                            limit: Annotated[int, Query(ge=1, le=MAX_PROPOSAL_PAGE)] = DEFAULT_PAGE) -> Response:
        return view(service.case_proposals(authorized, case_id, cursor=cursor, limit=limit))

    @router.get("/proposals/{proposal_id}", response_model=ProposalDetailView,
                **_documented((401, 403, 404, 422), session=True))
    def get_proposal(proposal_id: UUID,
                     authorized: Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))],
                     service: Proposals,
                     version: Annotated[int | None, Query(ge=1, le=MAX_VERSION)] = None) -> Response:
        return view(service.detail(authorized, proposal_id, version))

    @router.post("/proposals/{proposal_id}/decision", status_code=201, response_model=ApprovalDecision,
                 **_documented((401, 403, 404, 409, 422, 503), csrf=True, success={
                     201: {"description": "Decided: the immutable decision record."},
                     200: {"description": "An identical earlier decision by the same reviewer: the original record.",
                           "headers": {"Idempotent-Replayed": docs.REPLAYED_HEADER},
                           "content": {"application/json": {"schema": {
                               "$ref": "#/components/schemas/ApprovalDecision"}}}}}))
    def decide(proposal_id: UUID, body: DecisionRequest,
               authorized: Annotated[Authorized, Depends(require_action(Action.DECIDE_PROPOSAL))],
               service: Decisions) -> Response:
        try:
            result = service.decide(authorized, proposal_id, body)
        except DecisionCommitUnknown:
            envelope = ErrorEnvelope(code=ErrorCode.UNAVAILABLE, detail="The decision's outcome is unknown; resend "
                                     "the identical request.", rule_id="api.decision_outcome_unknown",
                                     correlation_id=uuid4(), retryable=True)
            return JSONResponse(envelope.model_dump(mode="json"), status_code=503, headers=NO_STORE)
        payload = result.decision.model_dump(mode="json")
        if result.replayed:
            return canonical(payload, status=200, headers={"Idempotent-Replayed": "true"})
        return canonical(payload, status=201)

    return router
