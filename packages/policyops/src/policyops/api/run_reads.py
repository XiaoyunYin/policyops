"""Read-only workbench resources; expected context and VIEW_CASE on every route."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from policyops.api import docs
from policyops.api.auth import require_action
from policyops.api.cases import view
from policyops.api.runs import Runs
from policyops.auth.service import Authorized
from policyops.domain.roles import Action
from policyops.services.run_reads import CitationPage, EvidenceView, RunPage, RunReads, RunSnapshot


Viewer = Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))]
Cursor = Annotated[str | None, Query(max_length=400)]
Limit = Annotated[int, Query(ge=1, le=100)]


def reads(runs: Runs) -> RunReads:
    return RunReads(runs.service.app_engine, runs.service.clock)


Reads = Annotated[RunReads, Depends(reads)]


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/cases/{case_id}/runs", response_model=RunPage,
                **docs.operation(session=True, context=True, errors=(401, 403, 404, 422)))
    def list_case_runs(case_id: UUID, authorized: Viewer, service: Reads,
                       cursor: Cursor = None, limit: Limit = 25) -> Response:
        return view(service.runs(authorized, case_id, cursor=cursor, limit=limit))

    @router.get("/runs/{run_id}/snapshot", response_model=RunSnapshot,
                **docs.operation(session=True, context=True, errors=(401, 403, 404, 409, 422)))
    def run_snapshot(run_id: UUID, authorized: Viewer, service: Reads,
                     tail: Annotated[int, Query(ge=0, le=100)] = 100) -> Response:
        return view(service.snapshot(authorized, run_id, tail=tail))

    @router.get("/runs/{run_id}/citations", response_model=CitationPage,
                **docs.operation(session=True, context=True, errors=(401, 403, 404, 422)))
    def list_run_citations(run_id: UUID, authorized: Viewer, service: Reads,
                           cursor: Cursor = None, limit: Limit = 25) -> Response:
        return view(service.citations(authorized, run_id, cursor=cursor, limit=limit))

    @router.get("/evidence/{citation_id}", response_model=EvidenceView,
                **docs.operation(session=True, context=True, errors=(401, 403, 404, 409, 422)))
    def historical_evidence(citation_id: UUID, run_id: UUID, authorized: Viewer, service: Reads) -> Response:
        return view(service.evidence(authorized, run_id, citation_id))

    return router
