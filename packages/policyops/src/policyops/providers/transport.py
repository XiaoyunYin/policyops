"""The bounded HTTP boundary under the SDKs (T11): every byte that could leave goes through `BoundedTransport`.

Each physical attempt and each count gets a fresh SDK client over a fresh `httpx2.AsyncClient` with
`trust_env=False` and `follow_redirects=False`. Its transport permits **exactly one** request, and only if it is the
expected one:
- method `POST`, `https`, the fixed host and path, and no query;
- exactly the fixed `Host`, `Content-Type: application/json` and a `Content-Length` equal to the body's length,
  with no header name sent twice;
- only allowlisted header names, plus the expected version headers and exactly the expected credential (compared in
  constant time, never logged or stored);
- a body that, parsed strictly and re-encoded canonically, is byte-for-byte the prepared body.

Anything else is refused before the inner transport is reached. A second request, such as an SDK retry, is refused
too. The SDK's own retries are already 0.

The response is uncompressed (`Accept-Encoding: identity`; any other `Content-Encoding` is refused before decoding)
and its stream is bounded by the expected request's immutable `ResponseBounds`:
- chat (the default, `CHAT_BOUNDS`): at most 1 MiB in total, and no line longer than 64 KiB, every line of every
  chunk checked (which covers SSE lines);
- embeddings (`EMBEDDING_BOUNDS`, T12): at most 4 MiB in total and no per-line bound. That is for a non-SSE JSON
  body only: a 64 x 1536 vector response is commonly a single line far above 64 KiB.

Every opened stream is closed when the caller exits, and `closed` counts the closes so tests can prove it. `sent`
tells the caller whether the request may have reached the network. `refusal` holds a fixed code, never content.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
import hmac
from typing import Any

import anthropic
import httpx2
import openai
from pydantic import SecretStr

from policyops.providers.canonical import CanonicalError, canonical_bytes, strict_loads
from policyops.providers.contract import ALLOWED_HEADER_PREFIX, ALLOWED_HEADERS, ENDPOINTS, Provider


CLEANUP_SECONDS = 2.0
MAX_RESPONSE_BYTES = 1 << 20
MAX_LINE_BYTES = 64 << 10
MAX_EMBEDDING_RESPONSE_BYTES = 4 << 20
TIMEOUT = httpx2.Timeout(60.0, connect=5.0)


class TransportRefused(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ResponseTooLarge(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ResponseBounds:
    """How many decoded response bytes a request may receive: in total, and per line (`None`: no line bound, for a
    non-SSE JSON body only). Validated once, here; immutable."""

    total_bytes: int
    line_bytes: int | None

    def __post_init__(self) -> None:
        values = (self.total_bytes,) if self.line_bytes is None else (self.total_bytes, self.line_bytes)
        for value in values:
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_EMBEDDING_RESPONSE_BYTES:
                raise ValueError("a response bound is a positive integer of at most 4 MiB")
        if self.line_bytes is not None and self.line_bytes > self.total_bytes:
            raise ValueError("a line bound cannot exceed the total bound")


CHAT_BOUNDS = ResponseBounds(MAX_RESPONSE_BYTES, MAX_LINE_BYTES)
EMBEDDING_BOUNDS = ResponseBounds(MAX_EMBEDDING_RESPONSE_BYTES, None)


@dataclass(frozen=True)
class Expected:
    provider: Provider
    path: str
    body: bytes
    bounds: ResponseBounds = CHAT_BOUNDS

    def __post_init__(self) -> None:
        if not isinstance(self.bounds, ResponseBounds):
            raise TypeError("bounds must be a ResponseBounds")


class _BoundedStream(httpx2.AsyncByteStream):
    def __init__(self, inner: httpx2.AsyncByteStream, owner: BoundedTransport) -> None:
        self.inner = inner
        self.owner = owner

    async def __aiter__(self) -> AsyncIterator[bytes]:
        bounds = self.owner.expected.bounds
        total = since_newline = 0
        async for chunk in self.inner:
            total += len(chunk)
            if total > bounds.total_bytes:
                raise ResponseTooLarge("response_too_large")
            if bounds.line_bytes is not None:
                segments = chunk.split(b"\n")
                # Every line in the chunk is checked: the first continues the previous chunk's open line.
                lengths = [since_newline + len(segments[0]), *(len(segment) for segment in segments[1:])]
                if max(lengths) > bounds.line_bytes:
                    raise ResponseTooLarge("line_too_long")
                since_newline = lengths[-1]
            yield chunk

    async def aclose(self) -> None:
        # Bounded here, at the one place every closer goes through: the SDK's own generator `finally`, our cleanup
        # and httpx itself. A close that does not finish in time is recorded as unconfirmed, never as closed.
        try:
            async with asyncio.timeout(CLEANUP_SECONDS):
                await self.inner.aclose()
        except Exception:  # a failed or timed-out close
            self.owner.cleanup_unconfirmed = True
        else:
            self.owner.closed += 1


class BoundedTransport(httpx2.AsyncBaseTransport):
    def __init__(self, inner: httpx2.AsyncBaseTransport, expected: Expected, credential: SecretStr,
                 *, signed_headers: dict[str, SecretStr] | None = None) -> None:
        self.inner = inner
        self.expected = expected
        self.credential = credential
        self._signed_headers = signed_headers
        self.sent = False
        self.refusal: str | None = None
        self.opened = 0
        self.closed = 0
        self.cleanup_unconfirmed = False

    def _refuse(self, code: str) -> TransportRefused:
        self.refusal = code
        return TransportRefused(code)

    def _auth_ok(self, request: httpx2.Request) -> bool:
        if self.expected.provider == "bedrock":
            if not self._signed_headers or not {"authorization", "x-amz-date"} <= self._signed_headers.keys():
                return False
            return all(len(request.headers.get_list(name)) == 1 and hmac.compare_digest(
                request.headers[name].encode(), value.get_secret_value().encode())
                       for name, value in self._signed_headers.items())
        endpoint = ENDPOINTS[self.expected.provider]
        values = request.headers.get_list(endpoint.auth_header)
        expected = f"Bearer {self.credential.get_secret_value()}"  # both installed SDKs send a bearer credential
        return len(values) == 1 and hmac.compare_digest(values[0].encode(), expected.encode())

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if self.sent or self.refusal is not None:
            raise self._refuse("second_request")
        endpoint = ENDPOINTS[self.expected.provider]
        url = request.url
        if (request.method != "POST" or url.scheme != "https" or url.host != endpoint.host or url.port is not None
                or url.path != self.expected.path or url.query
                or (self.expected.provider == "bedrock" and self.expected.path != endpoint.create_path)):
            raise self._refuse("endpoint_mismatch")
        allowed = ALLOWED_HEADERS | {endpoint.auth_header} | set(endpoint.version_headers)
        if self.expected.provider == "bedrock":
            allowed |= set(self._signed_headers or {})
        names = [name.decode("latin-1").lower() for name, _value in request.headers.raw]
        if len(names) != len(set(names)):
            raise self._refuse("duplicate_header")
        for lower in names:
            if lower not in allowed and not lower.startswith(ALLOWED_HEADER_PREFIX):
                raise self._refuse("header_not_allowed")
        for name, value in endpoint.version_headers.items():
            if request.headers.get_list(name) != [value]:
                raise self._refuse("version_header_mismatch")
        if not self._auth_ok(request):
            raise self._refuse("credential_mismatch")
        body = await request.aread()
        # The fixed authority and an unambiguous JSON body: the hashed bytes must mean what is framed and sent.
        if request.headers.get("host") != endpoint.host:
            raise self._refuse("host_mismatch")
        if request.headers.get("content-type") != "application/json":
            raise self._refuse("content_type_mismatch")
        if request.headers.get("content-length") != str(len(body)):
            raise self._refuse("content_length_mismatch")
        try:
            same = canonical_bytes(strict_loads(body)) == self.expected.body
            if self.expected.provider == "bedrock":
                same = same and body == self.expected.body  # SigV4 signs the exact payload bytes
        except CanonicalError:
            same = False
        if not same:
            raise self._refuse("body_mismatch")
        # Uncompressed bodies only, so the response bound below counts the bytes that are actually decoded.
        request.headers["accept-encoding"] = "identity"
        self.sent = True
        response = await self.inner.handle_async_request(request)
        self.opened += 1
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            if await bounded_close(response.aclose):
                self.closed += 1
            else:
                self.cleanup_unconfirmed = True
            raise ResponseTooLarge("content_encoding")
        stream = response.stream
        if not isinstance(stream, httpx2.AsyncByteStream):
            raise self._refuse("response_stream_type")
        return httpx2.Response(response.status_code, headers=response.headers, stream=_BoundedStream(stream, self),
                               extensions=response.extensions, request=request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def http_client(transport: BoundedTransport, timeout: httpx2.Timeout) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=transport, trust_env=False, follow_redirects=False, timeout=timeout)


def sdk_client(provider: Provider, http: httpx2.AsyncClient, credential: SecretStr,
               timeout: httpx2.Timeout = TIMEOUT) -> Any:
    """The SDK client over an HTTP client the caller already owns (and closes, even if this constructor fails)."""
    if provider == "openai":
        return openai.AsyncOpenAI(api_key=credential.get_secret_value(), organization=None, project=None,
                                  webhook_secret=None, base_url=ENDPOINTS["openai"].base_url, timeout=timeout,
                                  max_retries=0, http_client=http)
    return anthropic.AsyncAnthropic(api_key=credential.get_secret_value(), auth_token=None, webhook_key=None,
                                    base_url=ENDPOINTS["anthropic"].base_url, timeout=timeout, max_retries=0,
                                    open_telemetry=False, http_client=http)


async def bounded_close(close: Any) -> bool:
    """Await one close step for at most CLEANUP_SECONDS. True only if it finished; an uncertain cleanup is
    reported, never presented as closed. It never replaces the caller's outcome (including a cancellation)."""
    try:
        async with asyncio.timeout(CLEANUP_SECONDS):
            await close()
    except Exception:  # a failed or timed-out close: reported as unconfirmed
        return False
    return True
