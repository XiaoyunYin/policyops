"""Bound the request body actually received (T08).

A pure ASGI middleware in front of the application. A malformed or repeated `Content-Length` is refused (400) and
a declared length over the limit is refused (413) before anything is read. Because a client can omit the header
(chunked transfer) or understate it, the body is then read here, before the application runs, keeping at most
`max_bytes`: the chunk that would pass the limit is not retained, reading stops and 413 is answered. A body
within the limit is handed to the application as one complete message; later `receive` calls (for disconnects)
go to the server. No exception crosses the framework's middleware, so the refusal cannot be rewritten on the
way (an exception raised from `receive` under Starlette's BaseHTTPMiddleware reaches FastAPI wrapped in an
ExceptionGroup and becomes a 400). Refusals use the standard error envelope and never echo the body.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from policyops.api.auth import error_response
from policyops.auth.service import AuthError
from policyops_contracts.errors import ErrorCode


MAX_BODY_BYTES = 64 * 1024
UNREADABLE = AuthError(400, ErrorCode.INVALID_INPUT, "The request could not be read.", "api.http_400")
TOO_LARGE = AuthError(413, ErrorCode.INVALID_INPUT, "The request body is larger than 64 KiB.", "api.http_413")


class BodyLimit:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = [value for name, value in scope["headers"] if name == b"content-length"]
        if len(declared) > 1 or (declared and not (declared[0].isdigit() and len(declared[0]) <= 19)):
            await error_response(UNREADABLE)(scope, receive, send)
            return
        if declared and int(declared[0]) > self.max_bytes:
            await error_response(TOO_LARGE)(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":  # the client went away before finishing the body
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                await error_response(TOO_LARGE)(scope, receive, send)
                return
            body += chunk
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)
