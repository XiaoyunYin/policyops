"""Connection-scoped webhook, kept off the browser API surface."""

from fastapi import APIRouter, Request, Response
from starlette.concurrency import run_in_threadpool

from policyops.services.helpdesk_inbound import Inbound


def build_router(inbound: Inbound) -> APIRouter:
    router = APIRouter()

    @router.post("/integrations/zammad/{connection_id}/events", include_in_schema=False)
    async def events(connection_id: str, request: Request) -> Response:
        headers = request.headers.raw
        signatures = [value for name, value in headers if name.lower() == b"x-hub-signature"]
        deliveries = [value for name, value in headers if name.lower() == b"x-zammad-delivery"]
        status = await run_in_threadpool(inbound.receive, connection_id, await request.body(), signatures, deliveries)
        return Response(status_code=status, headers={"Cache-Control": "no-store"})

    return router
