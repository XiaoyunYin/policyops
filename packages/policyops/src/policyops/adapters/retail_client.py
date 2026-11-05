"""Typed, authenticated client for the evals-owned retail-simulator (T16). Used by the later gateway (T17/T19).

* One fixed origin (`http://127.0.0.1:<port>` style, no path); `trust_env=False`, no redirects, no proxy, and
  **no automatic retries** for anything: the caller decides whether to retry, always with the same operation ID.
* Every request carries a fresh signed `ServiceContext` (HMAC-SHA256) binding its method, path and complete body
  digest, the tenant, case, customer and fixture, and a single-use nonce.
* Responses are requested and accepted uncompressed only (`Accept-Encoding: identity`; any other
  `Content-Encoding` is refused before decoding) and read as raw bytes under a size cap, so the cap bounds the actual
  work. Every body is parsed strictly: duplicate keys at any depth and non-finite numbers are refused before typed
  validation. A result is accepted only if it is *this* operation's:
  the operation ID and the locally computed operation fingerprint (which covers tenant, case, customer, fixture,
  call, expected effect, versions and intent) must match, and a receipt must name the same tool and effect.
* A definite refusal (`Refused`) needs a strictly valid `ErrorEnvelope` whose code matches its status, is not
  retryable, and is one of the service's fixed refusal statuses; its detail is reported only if it is one of the
  service's fixed codes. Anything else, including 408, 429, 5xx, a malformed or inconsistent envelope, an oversized
  or encoded body, a timeout, a transport error or a result for another identity, is `Unknown`: never a success and
  never a known failure. `lookup` can then reconcile and `fence` can make an
  absent operation definitively not executed.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import time
from typing import TypeVar
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, ValidationError

from policyops_contracts.errors import ErrorCode, ErrorEnvelope
from policyops_contracts.retail_service import (
    FIXTURE_ID,
    FIXTURE_SHA256,
    CaseInitialization,
    CaseState,
    FenceRequest,
    LookupResult,
    MutationRequest,
    OperationResult,
    ReadCall,
    ReadRequest,
    ReadResult,
    ServiceContext,
    canonical_json,
    operation_fingerprint,
)


MAX_RESPONSE_BYTES = 1024 * 1024
# The statuses the service uses for a definite refusal that executed nothing, and the envelope code each must carry.
REFUSALS = {400: ErrorCode.INVALID_INPUT, 401: ErrorCode.UNAUTHENTICATED, 403: ErrorCode.FORBIDDEN,
            404: ErrorCode.NOT_FOUND, 409: ErrorCode.CONFLICT, 413: ErrorCode.INVALID_INPUT,
            422: ErrorCode.PROTOCOL_VIOLATION}
# The service's fixed refusal details; any other detail is not repeated (it is reported as the envelope code).
SERVICE_CODES = frozenset({
    "bad_signature", "body_not_covered", "body_too_large", "case_identity_conflict", "case_not_found",
    "claims_invalid", "claims_malformed", "context_expired_before_apply", "expected_versions_mismatch", "expired",
    "identity_mismatch", "invalid_body", "no_bearer", "nonce_replayed", "not_found", "not_yet_valid",
    "one_authorization_header_required", "operation_conflict", "query_not_allowed", "request_not_covered",
    "token_malformed", "unknown_customer", "unsupported_read", "untracked_resource_changed", "upstream_rejected",
    "write_scope_required"})
ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]{1,253}(?::\d{1,5})?$")
Model = TypeVar("Model", bound=BaseModel)


@dataclass(frozen=True)
class Unknown:
    """The outcome is not known (lost response, timeout, overload, malformed or foreign result). Reconcile with
    `lookup`, or `fence` to make absence definitive; never treat it as success or as a known failure."""

    reason: str


class AuthorizationExpired(Exception):
    """The caller's `authorization_not_after` has passed; nothing was sent."""


class Refused(Exception):
    """A definite refusal that executed nothing (validation, authentication, scope, conflict). `code` is fixed."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"{status} {code}")
        self.status, self.code = status, code


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class RetailClient:
    def __init__(self, origin: str, key: bytes, *, tenant_id: UUID, case_id: UUID, customer_id: str,
                 fixture_sha256: str = FIXTURE_SHA256, timeout_seconds: float = 10.0,
                 transport: httpx.BaseTransport | None = None, clock: Callable[[], float] = time.time) -> None:
        if not ORIGIN.fullmatch(origin):
            raise ValueError("the retail-simulator origin is a scheme, host and optional port only")
        if len(key) < 32:
            raise ValueError("the service key needs at least 32 bytes")
        if not 0 < timeout_seconds <= 60:
            raise ValueError("the timeout must be within 60 seconds")
        self._key, self._clock = key, clock
        self.tenant_id, self.case_id, self.customer_id, self.fixture_sha256 = \
            tenant_id, case_id, customer_id, fixture_sha256
        self._http = httpx.Client(
            base_url=origin, trust_env=False, follow_redirects=False, timeout=httpx.Timeout(timeout_seconds),
            transport=transport or httpx.HTTPTransport(trust_env=False, retries=0, proxy=None))

    def close(self) -> None:
        self._http.close()

    def __repr__(self) -> str:
        return f"RetailClient(case={self.case_id}, key=<redacted>)"

    # -- signing and transport -------------------------------------------------------------------------------

    def _token(self, method: str, path: str, body: bytes, scope: str, not_after: float | None = None) -> str:
        now = int(self._clock())
        expires = now + 30 if not_after is None else min(now + 30, int(not_after))
        if expires <= now:
            raise AuthorizationExpired("the authorization has expired; nothing was sent")
        context = ServiceContext(
            v="policyops.retail-auth/v1", iss="policyops-gateway", aud="retail-simulator", tenant_id=self.tenant_id,
            case_id=self.case_id, customer_id=self.customer_id, fixture_sha256=self.fixture_sha256,
            scope=scope, method=method, path=path, body_sha256=hashlib.sha256(body).hexdigest(),  # type: ignore[arg-type]
            iat=now, exp=expires, jti=uuid4())
        claims = json.dumps(context.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
        return f"{_b64(claims)}.{_b64(hmac.new(self._key, claims, hashlib.sha256).digest())}"

    def _send(self, method: str, path: str, scope: str, body: BaseModel | None,
              not_after: float | None = None) -> httpx.Response | Unknown:
        raw = b"" if body is None else canonical_json(body.model_dump(mode="json"))
        headers = {"authorization": f"Bearer {self._token(method, path, raw, scope, not_after)}",
                   "content-type": "application/json", "accept-encoding": "identity"}
        try:
            with self._http.stream(method, path, content=raw, headers=headers) as response:
                if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
                    return Unknown("encoded_response")  # refused before any decoding
                data = bytearray()
                try:
                    for chunk in response.iter_raw(64 * 1024):  # raw bytes: the cap bounds the actual work
                        data += chunk
                        if len(data) > MAX_RESPONSE_BYTES:
                            return Unknown("response_too_large")
                except httpx.StreamConsumed:
                    # Only an in-memory transport hands over a body it already loaded (a network response
                    # streams); the encoding was refused above, and the same cap applies.
                    data = bytearray(response.content)
                    if len(data) > MAX_RESPONSE_BYTES:
                        return Unknown("response_too_large")
                return httpx.Response(response.status_code, content=bytes(data))
        except httpx.TimeoutException:
            return Unknown("timeout")
        except httpx.HTTPError:
            return Unknown("transport_error")

    @staticmethod
    def _strict(content: bytes) -> bool:
        """True when the body is JSON without duplicate keys (at any depth) or non-finite numbers."""
        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            if len({key for key, _ in items}) != len(items):
                raise ValueError("duplicate key")
            return dict(items)

        def constant(name: str) -> object:
            raise ValueError(name)
        try:
            json.loads(content.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        except (ValueError, UnicodeDecodeError):
            return False
        return True

    @classmethod
    def _parse(cls, response: httpx.Response, model: type[Model]) -> Model | Unknown:
        status = response.status_code
        if status >= 400:
            expected = REFUSALS.get(status)
            if expected is None or not cls._strict(response.content):
                return Unknown(f"http_{status}")  # 408, 429, 5xx, any other status, or a malformed body
            try:
                envelope = ErrorEnvelope.model_validate_json(response.content)
            except ValidationError:
                return Unknown(f"http_{status}")
            if envelope.code != expected or envelope.retryable:
                return Unknown(f"http_{status}")  # an inconsistent envelope is not a definite refusal
            raise Refused(status, envelope.detail if envelope.detail in SERVICE_CODES else envelope.code.value)
        if status != 200 and status != 201:
            return Unknown(f"http_{status}")
        if not cls._strict(response.content):
            return Unknown("malformed_response")
        try:
            return model.model_validate_json(response.content)
        except ValidationError:
            return Unknown("malformed_response")

    def _path(self, *parts: str) -> str:
        return "/".join(("", "v1", "cases", str(self.case_id), *parts))

    # -- operations -------------------------------------------------------------------------------------------

    def initialize(self) -> CaseState | Unknown:
        body = CaseInitialization(fixture_id=FIXTURE_ID, fixture_sha256=self.fixture_sha256,
                                  customer_id=self.customer_id)
        sent = self._send("PUT", self._path(), "write", body)
        if isinstance(sent, Unknown):
            return sent
        state = self._parse(sent, CaseState)
        if isinstance(state, CaseState) and (state.customer_id, state.fixture_sha256) != \
                (self.customer_id, self.fixture_sha256):
            return Unknown("foreign_case_state")
        return state

    def read(self, call: ReadCall) -> ReadResult | Unknown:
        sent = self._send("POST", self._path("reads"), "read", ReadRequest(call=call))
        return sent if isinstance(sent, Unknown) else self._parse(sent, ReadResult)

    def fingerprint(self, operation_id: UUID, request: MutationRequest) -> str:
        return operation_fingerprint(tenant_id=self.tenant_id, case_id=self.case_id, customer_id=self.customer_id,
                                     fixture_sha256=self.fixture_sha256, operation_id=operation_id, request=request)

    def _own(self, result: OperationResult | Unknown, operation_id: UUID, fingerprint: str,
             request: MutationRequest | None) -> OperationResult | Unknown:
        if isinstance(result, Unknown):
            return result
        if result.operation_id != str(operation_id) or result.operation_sha256 != fingerprint:
            return Unknown("foreign_result")
        receipt = result.receipt
        if receipt is not None and (receipt.operation_id != str(operation_id) or receipt.operation_sha256 != fingerprint
                                    or (request is not None and (receipt.tool != request.call.tool
                                                                 or receipt.actual_effect != request.expected_effect))):
            return Unknown("foreign_receipt")
        return result

    def mutate(self, operation_id: UUID, request: MutationRequest, *,
               authorization_not_after: float | None = None) -> OperationResult | Unknown:
        """One attempt, no retry. A retry must use the same `operation_id` and `request`. The signed context never
        outlives `authorization_not_after` (a Unix time, e.g. the approval's expiry); once it has passed, nothing
        is sent. The expiry is transport context only and is not part of the operation fingerprint."""
        sent = self._send("PUT", self._path("operations", str(operation_id)), "write", request,
                          authorization_not_after)
        if isinstance(sent, Unknown):
            return sent
        return self._own(self._parse(sent, OperationResult), operation_id, self.fingerprint(operation_id, request),
                         request)

    def lookup(self, operation_id: UUID, request: MutationRequest) -> LookupResult | Unknown:
        sent = self._send("GET", self._path("operations", str(operation_id)), "read", None)
        if isinstance(sent, Unknown):
            return sent
        found = self._parse(sent, LookupResult)
        if isinstance(found, LookupResult) and found.result is not None:
            owned = self._own(found.result, operation_id, self.fingerprint(operation_id, request), request)
            if isinstance(owned, Unknown):
                return owned
        return found

    def fence(self, operation_id: UUID, request: MutationRequest, *,
              authorization_not_after: float | None = None) -> OperationResult | Unknown:
        """Make the operation definitively not executed if it is absent; returns its stored outcome otherwise."""
        fingerprint = self.fingerprint(operation_id, request)
        sent = self._send("POST", self._path("operations", str(operation_id), "fence"), "write",
                          FenceRequest(operation_sha256=fingerprint), authorization_not_after)
        if isinstance(sent, Unknown):
            return sent
        return self._own(self._parse(sent, OperationResult), operation_id, fingerprint, request)
