"""Service authentication: one short-lived HMAC-SHA256 context per request (`ServiceContext`).

Wire form: `Authorization: Bearer <b64url(claims JSON)>.<b64url(HMAC-SHA256(key, claims JSON))>`. The signature is
checked in constant time before the claims are parsed; the claims are strict typed JSON (duplicate keys, unknown
claims and non-finite numbers refused). The verifier then requires:
- `iss`/`aud`/`v` as fixed, a lifetime of at most 60 s, `iat` no more than 5 s in the future and `exp` not past;
- the request's own method, path (no query string) and complete body digest;
- the scope the route needs (`read` may only read and look up; writes and fences need `write`).
The nonce (`jti`) is single-use per tenant and case; the store records it in the request's first transaction. A
tenant or case never comes from any other header.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
from typing import Any

from pydantic import ValidationError

from policyops_contracts.retail_service import ServiceContext


MIN_KEY_BYTES = 32
MAX_TOKEN_BYTES = 4096
SKEW_SECONDS = 5


class Unauthenticated(Exception):
    """401: no valid signed context. `code` is fixed and carries no request data."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ScopeDenied(Exception):
    """403: a valid context that does not cover this request."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Key:
    secret: bytes

    def __post_init__(self) -> None:
        if len(self.secret) < MIN_KEY_BYTES:
            raise ValueError("the service key needs at least 32 bytes")

    def __repr__(self) -> str:
        return "Key(<redacted>)"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    if not text or len(text) > MAX_TOKEN_BYTES:
        raise Unauthenticated("token_malformed")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise Unauthenticated("token_malformed") from None


def _strict_object(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)

    def constant(name: str) -> Any:
        raise ValueError(name)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeDecodeError):
        raise Unauthenticated("claims_malformed") from None


def sign(context: ServiceContext, key: Key) -> str:
    claims = json.dumps(context.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    return f"{_b64(claims)}.{_b64(hmac.new(key.secret, claims, hashlib.sha256).digest())}"


def verify(authorization: str | None, key: Key, *, method: str, path: str, query: str, body: bytes,
           scope: str, now: int) -> ServiceContext:
    """The checked context of this exact request, or Unauthenticated / ScopeDenied."""
    if authorization is None or not authorization.startswith("Bearer ") or len(authorization) > MAX_TOKEN_BYTES:
        raise Unauthenticated("no_bearer")
    parts = authorization[len("Bearer "):].split(".")
    if len(parts) != 2:
        raise Unauthenticated("token_malformed")
    claims, signature = _unb64(parts[0]), _unb64(parts[1])
    if not hmac.compare_digest(hmac.new(key.secret, claims, hashlib.sha256).digest(), signature):
        raise Unauthenticated("bad_signature")
    data = _strict_object(claims)
    try:
        context = ServiceContext.model_validate_json(json.dumps(data))
    except ValidationError:
        raise Unauthenticated("claims_invalid") from None
    if context.iat > now + SKEW_SECONDS:
        raise Unauthenticated("not_yet_valid")
    if context.exp <= now:
        raise Unauthenticated("expired")
    if query:
        raise ScopeDenied("query_not_allowed")
    if context.method != method or context.path != path:
        raise ScopeDenied("request_not_covered")
    if not hmac.compare_digest(context.body_sha256, hashlib.sha256(body).hexdigest()):
        raise ScopeDenied("body_not_covered")
    if scope == "write" and context.scope != "write":
        raise ScopeDenied("write_scope_required")
    return context
