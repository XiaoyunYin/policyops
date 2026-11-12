"""Pure ASGI instrumentation: route templates only, no headers, bodies, targets or query strings."""

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from policyops.telemetry import annotate, enabled, span


class HttpTelemetry:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not enabled():
            await self.app(scope, receive, send)
            return
        with span("http.request", http_method=scope.get("method", "")):
            async def observed_send(message: Message) -> None:
                if message["type"] == "http.response.start":
                    # The pinned FastAPI keeps the original APIRoute in scope["route"].
                    # Its inclusion context supplies the selected template with all prefixes.
                    # Never reconstruct a template from request paths or path parameter values.
                    route = scope.get("fastapi", {}).get("effective_route_context") or scope.get("route")
                    status = message["status"]
                    annotate(http_route=getattr(route, "path_format", ""), http_status=status,
                             outcome="error" if status >= 500 else "refused" if status >= 400 else "completed")
                await send(message)
            await self.app(scope, receive, observed_send)
