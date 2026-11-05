"""OpenAPI documentation for requirements our own dependencies enforce (T08).

FastAPI documents only what it discovers from declared parameters. The session cookie, the CSRF token with an
exact Origin, `Idempotency-Key` and `If-Match` are read from the request by PolicyOps dependencies, so each route
states them through `operation(...)`, together with every error status it can return as an `ErrorEnvelope`.
Declaring 422 explicitly also keeps FastAPI from documenting its default `HTTPValidationError` body, which this
API never returns (`policyops.api.openapi` refuses a document that still mentions it).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from policyops_contracts.errors import ErrorEnvelope


SESSION_SCHEME = "session"
CSRF_SCHEME = "csrf"
# Every operation can answer these: `BodyLimit` runs for every request (400 for a malformed or duplicate
# Content-Length, 413 for an oversized body) and any route can fail unexpectedly (500).
ALWAYS = (400, 413, 500)
ERROR_DESCRIPTIONS = {
    400: "Malformed or duplicate Content-Length, a request body that is not valid UTF-8, or (on writes) a "
         "missing Idempotency-Key header.",
    401: "No valid session (sign in again).",
    403: "Forbidden: workspace not selected, no membership, role, CSRF token or Origin refused.",
    404: "Not found in the selected workspace.",
    409: "Conflict: stale version, refused status transition, or Idempotency-Key reused for another request.",
    413: "The request body is larger than 64 KiB.",
    422: "The request is not valid: malformed JSON, or a body, path, query or header value that fails "
         "validation (no input is echoed).",
    428: "A required precondition (If-Match) is missing.",
    500: "Unexpected failure (no internals are disclosed).",
    503: "The identity provider is unavailable.",
}

IDEMPOTENCY_KEY: dict[str, Any] = {
    "name": "Idempotency-Key", "in": "header", "required": True,
    "description": "Client-chosen key, unique per intended write. A retry with the same key and request replays "
                   "the original response; the same key with a different request is a 409.",
    "schema": {"type": "string", "pattern": "^[A-Za-z0-9._~-]{8,128}$"},
}
IF_MATCH: dict[str, Any] = {
    "name": "If-Match", "in": "header", "required": True,
    "description": "The strong ETag of the case version this change is based on, for example \"3\".",
    "schema": {"type": "string", "pattern": '^"[1-9][0-9]{0,15}"$'},
}
ETAG_HEADER = {"description": "Strong ETag of the case version.", "schema": {"type": "string"}}
REPLAYED_HEADER = {"description": "Present and \"true\" when this is a replay of the original response.",
                   "schema": {"type": "string", "enum": ["true"]}}
LOCATION_HEADER = {"description": "URL of the created case.", "schema": {"type": "string"}}
REDIRECT_HEADER = {"description": "Redirect target.", "schema": {"type": "string"}}
SET_COOKIE_HEADER = {"description": "Session, CSRF or login-binding cookies.", "schema": {"type": "string"}}

SECURITY_SCHEMES: dict[str, Any] = {
    SESSION_SCHEME: {
        "type": "apiKey", "in": "cookie", "name": "__Host-policyops_session",
        "description": "Opaque HttpOnly session cookie set by the login callback (named policyops_session_local "
                       "on plain-HTTP local origins).",
    },
    CSRF_SCHEME: {
        "type": "apiKey", "in": "header", "name": "X-CSRF-Token",
        "description": "Synchronizer token from the JavaScript-readable CSRF cookie. Unsafe methods also need an "
                       "exact Origin (or, without one, a Referer on the public origin).",
    },
}


def operation(*, session: bool = False, csrf: bool = False, headers: Iterable[dict[str, Any]] = (),
              errors: Iterable[int] = (), success: dict[int, dict[str, Any]] | None = None,
              error_headers: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Route-decorator keyword arguments (`responses`, `openapi_extra`) documenting enforced requirements;
    `error_headers` names response headers some error statuses carry (such as a cookie being cleared)."""
    responses: dict[int | str, dict[str, Any]] = {status: dict(entry) for status, entry in (success or {}).items()}
    for status in sorted({*errors, *ALWAYS}):
        responses[status] = {"model": ErrorEnvelope, "description": ERROR_DESCRIPTIONS[status]}
        if status in (error_headers or {}):
            responses[status]["headers"] = (error_headers or {})[status]
    extra: dict[str, Any] = {}
    if csrf:
        extra["security"] = [{SESSION_SCHEME: [], CSRF_SCHEME: []}]
    elif session:
        extra["security"] = [{SESSION_SCHEME: []}]
    if parameters := list(headers):
        extra["parameters"] = parameters
    return {"responses": responses, "openapi_extra": extra}
