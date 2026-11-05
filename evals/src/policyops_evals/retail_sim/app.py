"""The retail-simulator HTTP surface (internal port only).

Order of work for every request:
1. Read the body as a stream, refusing more than 64 KiB before anything is parsed (chunked bodies and missing or
   wrong `Content-Length` included). A request must carry exactly one `Authorization` header and no query string.
2. Verify the signed context for this exact method, path and body digest (`auth.verify`), then record its nonce.
3. Parse the body strictly (duplicate keys refused; strict typed models) and call the store.
Errors are `ErrorEnvelope`s with fixed codes; no exception text, request content or upstream message is returned.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import json
import time
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import OperationalError
from starlette.concurrency import run_in_threadpool

from policyops_contracts.errors import ErrorCode, ErrorEnvelope
from policyops_contracts.retail_service import (
    MAX_BODY_BYTES,
    CaseInitialization,
    FenceRequest,
    MutationRequest,
    ReadRequest,
    ServiceContext,
)
from policyops_evals.retail_sim import auth
from policyops_evals.retail_sim.store import Store, StoreError


FAULTS = ("reject_429_before", "fail_503_before", "delay_before", "commit_then_503")
CODES = {400: ErrorCode.INVALID_INPUT, 401: ErrorCode.UNAUTHENTICATED, 403: ErrorCode.FORBIDDEN,
         404: ErrorCode.NOT_FOUND, 409: ErrorCode.CONFLICT, 413: ErrorCode.INVALID_INPUT,
         422: ErrorCode.PROTOCOL_VIOLATION, 429: ErrorCode.RATE_LIMITED, 503: ErrorCode.UNAVAILABLE}


class HttpError(Exception):
    def __init__(self, status: int, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.headers = status, detail, headers or {}


def error(status: int, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    envelope = ErrorEnvelope(code=CODES.get(status, ErrorCode.INTERNAL), detail=detail, correlation_id=uuid4(),
                             retryable=status in (429, 503))
    return JSONResponse(envelope.model_dump(mode="json"), status_code=status, headers=headers)


def strict_model[M: BaseModel](raw: bytes, model: type[M]) -> M:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({key for key, _ in items}) != len(items):
            raise ValueError("duplicate key")
        return dict(items)
    def constant(name: str) -> Any:
        raise ValueError(name)
    try:
        json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        return model.model_validate_json(raw)
    except (ValueError, UnicodeDecodeError, ValidationError):
        raise HttpError(400, "invalid_body") from None


def create_app(store: Store, key: auth.Key, *, faults_enabled: bool = False,
               clock: Callable[[], float] = time.time) -> FastAPI:
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    async def body_of(request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
            raise HttpError(413, "body_too_large")
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise HttpError(413, "body_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def authorized(request: Request, scope: str) -> tuple[ServiceContext, bytes]:
        body = await body_of(request)
        headers = request.headers.getlist("authorization")
        if len(headers) != 1:
            raise HttpError(401, "one_authorization_header_required")
        try:
            context = auth.verify(headers[0], key, method=request.method, path=request.url.path,
                                  query=request.url.query, body=body, scope=scope, now=int(clock()))
        except auth.Unauthenticated as refused:
            raise HttpError(401, refused.code) from None
        except auth.ScopeDenied as refused:
            raise HttpError(403, refused.code) from None
        await run_in_threadpool(store.use_nonce, context)
        return context, body

    @app.exception_handler(HttpError)
    async def _http(request: Request, exc: HttpError) -> JSONResponse:
        return error(exc.status, exc.detail, exc.headers)

    @app.exception_handler(StoreError)
    async def _store(request: Request, exc: StoreError) -> JSONResponse:
        return error(exc.status, exc.code)

    @app.exception_handler(OperationalError)
    async def _db(request: Request, exc: OperationalError) -> JSONResponse:
        return error(503, "store_unavailable")  # lock or statement timeout, or a lost connection: not a known outcome

    def fault_header(name: str) -> dict[str, str]:
        return {"X-PolicyOps-Fault": name}

    async def before(context: ServiceContext) -> None:
        if not faults_enabled:
            return
        if await run_in_threadpool(store.take_fault, context, "reject_429_before"):
            raise HttpError(429, "injected_fault", fault_header("reject_429_before"))
        if await run_in_threadpool(store.take_fault, context, "fail_503_before"):
            raise HttpError(503, "injected_fault", fault_header("fail_503_before"))
        if await run_in_threadpool(store.take_fault, context, "delay_before"):
            await asyncio.sleep(0.5)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "fixture_sha256": store.fixture.sha256}

    @app.put("/v1/cases/{case_id}")
    async def initialize(case_id: UUID, request: Request) -> Response:
        context, body = await authorized(request, "write")
        result = await run_in_threadpool(store.initialize, context, strict_model(body, CaseInitialization))
        return JSONResponse(result.model_dump(mode="json"), status_code=201 if result.created else 200)

    @app.post("/v1/cases/{case_id}/reads")
    async def read(case_id: UUID, request: Request) -> Response:
        context, body = await authorized(request, "read")
        result = await run_in_threadpool(store.read, context, strict_model(body, ReadRequest))
        return JSONResponse(result.model_dump(mode="json"))

    @app.put("/v1/cases/{case_id}/operations/{operation_id}")
    async def mutate(case_id: UUID, operation_id: UUID, request: Request) -> Response:
        context, body = await authorized(request, "write")
        mutation = strict_model(body, MutationRequest)
        await before(context)
        result = await run_in_threadpool(store.mutate, context, operation_id, mutation)
        if faults_enabled and result.outcome == "committed" and not result.replayed and \
                await run_in_threadpool(store.take_fault, context, "commit_then_503"):
            raise HttpError(503, "injected_fault", fault_header("commit_then_503"))  # committed; response lost
        return JSONResponse(result.model_dump(mode="json"))

    @app.get("/v1/cases/{case_id}/operations/{operation_id}")
    async def lookup(case_id: UUID, operation_id: UUID, request: Request) -> Response:
        context, _ = await authorized(request, "read")
        result = await run_in_threadpool(store.lookup, context, operation_id)
        return JSONResponse(result.model_dump(mode="json"))

    @app.post("/v1/cases/{case_id}/operations/{operation_id}/fence")
    async def fence(case_id: UUID, operation_id: UUID, request: Request) -> Response:
        context, body = await authorized(request, "write")
        result = await run_in_threadpool(store.fence, context, operation_id, strict_model(body, FenceRequest))
        return JSONResponse(result.model_dump(mode="json"))

    if faults_enabled:
        @app.put("/v1/cases/{case_id}/faults")
        async def arm(case_id: UUID, request: Request) -> Response:
            context, body = await authorized(request, "write")
            plan = strict_model(body, FaultPlan)
            await run_in_threadpool(store.arm_fault, context, plan.fault, plan.count)
            return Response(status_code=204, headers=fault_header("armed"))

    return app


class FaultPlan(BaseModel):
    model_config = {"extra": "forbid", "strict": True, "frozen": True}
    fault: str
    count: int

    def model_post_init(self, _: Any) -> None:
        if self.fault not in FAULTS or not 1 <= self.count <= 3:
            raise ValueError("unknown fault or count outside 1-3")
