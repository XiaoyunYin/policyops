"""One embedding request (T12): the exact canonical request, one physical send, a bounded parse and the accounting
classification. No ledger, retries or persistence here; `embedding_calls.py` owns those.

## The request

`prepare` turns 1-64 exact input texts into one `PreparedEmbedding`:
- the body `{"model", "input", "dimensions", "encoding_format": "float"}` from the server's `EmbeddingActor`;
- `request_sha256` over the canonical envelope (contract version, method, host, path, version headers, body), as for
  chat requests.

Inputs are bounded before anything else (count, code points, bytes, aggregate bytes, NUL, strict UTF-8).

## One send

`fetch` sends that request once through the real SDK (`client.embeddings.with_raw_response.create`, no SDK retries)
over a `BoundedTransport` with `EMBEDDING_BOUNDS`: 4 MiB, no line bound, uncompressed, exactly the prepared bytes. It
returns the raw body bytes and never calls the SDK's parser, so no base64 decoding or SDK object is involved. It owns
the inner transport from the moment it asks the factory for it: an ambient-setting refusal is checked first, and a
constructor failure or a cancellation still closes it (bounded).

A complete body is handed to the caller's `observe` callback the moment it is known, **before** any cleanup is
awaited: a recording layer under the bounded transport keeps the (identity-encoded, at most 4 MiB) bytes of a 2xx JSON
response and marks them complete at the end of the stream. So if a timeout or cancellation lands while the SDK or
`fetch` is closing streams or clients, the caller still has the complete body (and the bill in it), with the cleanup
reported unconfirmed; the interruption itself is re-raised.

## The bounded parse

`parse` keeps the shared `canonical.strict_loads` untouched and uses its own bounded parser:
1. **Precheck** on the UTF-8 text (already at most 4 MiB): one cursor walks the text with anchored matches only
   (a complete string literal with valid escapes, a bracket, or a run of anything else), so every character is
   scanned at most once and an unterminated string fails in one linear pass. It stops as soon as there are more than
   `MAX_STRINGS` strings, a string longer than `MAX_STRING_CHARS`, more than `MAX_CONTAINERS` containers or nesting
   deeper than `MAX_DEPTH`. JSON whitespace (space, TAB, LF, CR) is fine between tokens.
2. **json.loads** with hooks: a numeric literal longer than 24 characters, `NaN` and `Infinity` become an `INVALID`
   marker instead of a value, and a duplicated object key marks that key `DUPLICATE`. A bad value is therefore
   confined to its own subtree, and the document is marked **tainted**.
3. **Billing first**: `model`, `usage.prompt_tokens` and `usage.total_tokens` are read from the root. They must be
   present, unique and of the right type (a strict `int`, never `bool`, `INVALID` or `DUPLICATE`); otherwise the
   billing is unknown. A duplicate is never resolved by choosing one of its values.
4. **Vectors second**: a tainted document has no usable vectors, wherever the bad value was. Otherwise the list, its
   `object` fields, unique contiguous `int` indexes and exactly 1536 numbers per vector are checked. Each number is
   converted to the nearest float32 (an overflow is refused), a vector that is all zero after that rounding is
   refused, and each finite norm is kept as a diagnostic only. A vector failure never discards valid billing.

## Classification (the accounting outcome)

| Response | Outcome | Ledger | Cache |
|---|---|---|---|
| unparseable, or billing absent or malformed | `unknown` | unresolved, hold kept, no block | none |
| `prompt_tokens != total_tokens` | `usage_contradiction` | unresolved + block, both counts as diagnostic | none |
| returned model is not the requested model | `model_mismatch` | unresolved + block | none |
| consistent usage, but not the local count | `count_mismatch` | settle the actual bill + block | none |
| billing valid, a vector invalid | `vectors_invalid` | settle, no block | none |
| everything valid | `published` | settle | the vectors |
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math
import re
import struct
from typing import Any, Literal

import httpx2
import openai
from pydantic import SecretStr

from policyops.budget.config import Configuration, EmbeddingActor
from policyops.budget.ledger import Diagnostic
from policyops.budget.pricing import Usage
from policyops.providers.canonical import canonical_bytes, sha256_hex
from policyops.providers.contract import ContractGap, require_clean_environment
from policyops.providers.embedding_contract import (
    EMBEDDING_CONTRACT_VERSION,
    EMBEDDINGS_PATH,
    ENCODING_FORMAT,
    ENDPOINT,
)
from policyops.providers.transport import (
    EMBEDDING_BOUNDS,
    TIMEOUT,
    BoundedTransport,
    Expected,
    ResponseTooLarge,
    TransportRefused,
    bounded_close,
    http_client,
    sdk_client,
)


MAX_INPUTS = 64
MAX_INPUT_CHARS = 32_768
MAX_INPUT_BYTES = 65_536
MAX_REQUEST_BYTES = 262_144
MAX_NUMBER_CHARS = 24
MAX_STRINGS = 1024
MAX_STRING_CHARS = 4096
MAX_CONTAINERS = 256
MAX_DEPTH = 8
FLOAT32_MAX = 3.4028234663852886e38
REQUEST_ID = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
MODEL_TEXT = re.compile(r"[A-Za-z0-9_.:-]{1,100}")

# The precheck's tokens, always matched *anchored* at the cursor: a complete JSON string literal with valid escapes
# (possessive, so a failed attempt scans the string once and never backtracks), one bracket, or a run of anything
# else outside strings.
_TOKEN = re.compile(r'(?P<string>"(?:[^"\\\x00-\x1f]++|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*+")'
                    r'|(?P<bracket>[\[\]{}])|(?P<other>[^"\[\]{}]++)')


def input_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digests_sha256(digests: Sequence[str]) -> str:
    """The identity of an ordered list of input digests (full digests, never prefixes)."""
    return sha256_hex(canonical_bytes({"v": "policyops.embedding-inputs/v1", "inputs": list(digests)}))


@dataclass(frozen=True)
class PreparedEmbedding:
    model: str
    dimensions: int
    inputs: tuple[str, ...]
    input_sha256s: tuple[str, ...]
    body: bytes
    request_sha256: str

    def params(self) -> dict[str, Any]:
        """The SDK keyword arguments; the SDK sends exactly these fields, so the wire body equals `body`."""
        return {"model": self.model, "input": list(self.inputs), "dimensions": self.dimensions,
                "encoding_format": ENCODING_FORMAT}


def check_inputs(texts: Sequence[str], max_inputs: int = MAX_INPUTS) -> None:
    if not 1 <= len(texts) <= max_inputs:
        raise ContractGap(f"an embedding request has 1-{max_inputs} inputs")
    total = 0
    for index, text in enumerate(texts):
        if not isinstance(text, str) or not 1 <= len(text) <= MAX_INPUT_CHARS:
            raise ContractGap(f"embedding input {index} must have 1-{MAX_INPUT_CHARS} characters")
        if "\x00" in text:
            raise ContractGap(f"embedding input {index} contains NUL")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise ContractGap(f"embedding input {index} is not valid UTF-8 text") from None
        if size > MAX_INPUT_BYTES:
            raise ContractGap(f"embedding input {index} is larger than {MAX_INPUT_BYTES} bytes")
        total += size
    if total > MAX_REQUEST_BYTES:
        raise ContractGap(f"an embedding request is at most {MAX_REQUEST_BYTES} bytes of input")


def prepare(texts: Sequence[str], configuration: Configuration) -> PreparedEmbedding:
    actor = configuration.actors["embedding"]
    if not isinstance(actor, EmbeddingActor):
        raise ContractGap("the embedding actor has no embedding configuration")
    configuration.registry.embedding(actor.model, dimensions=actor.dimensions)
    check_inputs(texts, min(MAX_INPUTS, actor.max_inputs))
    inputs = tuple(texts)
    body = {"model": actor.model, "input": list(inputs), "dimensions": actor.dimensions,
            "encoding_format": ENCODING_FORMAT}
    envelope = canonical_bytes({"contract": EMBEDDING_CONTRACT_VERSION, "provider": "openai", "method": "POST",
                                "host": ENDPOINT.host, "path": EMBEDDINGS_PATH, "query": {},
                                "version_headers": dict(ENDPOINT.version_headers), "body": body})
    return PreparedEmbedding(actor.model, actor.dimensions, inputs, tuple(input_sha256(t) for t in inputs),
                             canonical_bytes(body), sha256_hex(envelope))


# -- one send ----------------------------------------------------------------------------------------------------

class _RecordingStream(httpx2.AsyncByteStream):
    def __init__(self, inner: httpx2.AsyncByteStream, owner: _Recorder) -> None:
        self.inner, self.owner = inner, owner

    async def __aiter__(self) -> Any:
        async for chunk in self.inner:
            self.owner.append(chunk)
            yield chunk
        self.owner.complete = True  # the whole body passed through (the bounded layer above checked its size)

    async def aclose(self) -> None:
        await self.inner.aclose()


class _Recorder(httpx2.AsyncBaseTransport):
    """Keeps the bytes of the one response as they stream, so a complete body survives an interrupted cleanup."""

    def __init__(self, inner: httpx2.AsyncBaseTransport) -> None:
        self.inner = inner
        self.status: int | None = None
        self.content_type = ""
        self.request_id: str | None = None
        self.chunks: list[bytes] = []
        self.size = 0
        self.complete = False

    def append(self, chunk: bytes) -> None:
        self.size += len(chunk)
        if self.size <= EMBEDDING_BOUNDS.total_bytes:
            self.chunks.append(chunk)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        response = await self.inner.handle_async_request(request)
        self.status = response.status_code
        self.content_type = response.headers.get("content-type", "")
        self.request_id = response.headers.get("x-request-id")
        stream = response.stream
        if not isinstance(stream, httpx2.AsyncByteStream):
            return response  # the bounded layer above refuses it
        return httpx2.Response(response.status_code, headers=response.headers, stream=_RecordingStream(stream, self),
                               extensions=response.extensions, request=request)

    def body(self) -> Fetched | None:
        """The complete body of a 2xx JSON response within the bound, or None."""
        if not self.complete or self.status is None or not 200 <= self.status < 300 \
                or self.size > EMBEDDING_BOUNDS.total_bytes or not _json(self.content_type):
            return None
        request_id = self.request_id if self.request_id and REQUEST_ID.fullmatch(self.request_id) else None
        return Fetched(sent=True, raw=b"".join(self.chunks), provider_request_id=request_id)

    async def aclose(self) -> None:
        await self.inner.aclose()


def _json(content_type: str) -> bool:
    return content_type.split(";")[0].strip().lower() == "application/json"


@dataclass
class Fetched:
    sent: bool
    raw: bytes | None = None
    provider_request_id: str | None = None
    status: int | None = None
    error: str | None = None
    cleanup_confirmed: bool = True


def _failure(transport: BoundedTransport, error: BaseException) -> Fetched:
    cause = error.__cause__
    if isinstance(error, TransportRefused) or isinstance(cause, TransportRefused):
        return Fetched(sent=transport.sent, error=f"refused.{transport.refusal or 'unknown'}")
    if isinstance(error, ResponseTooLarge) or isinstance(cause, ResponseTooLarge):
        code = error.code if isinstance(error, ResponseTooLarge) else getattr(cause, "code", "too_large")
        return Fetched(sent=transport.sent, error=code)
    if isinstance(error, openai.APIStatusError):
        return Fetched(sent=transport.sent, status=error.status_code, error=f"http_{error.status_code}")
    if isinstance(error, openai.APITimeoutError):
        return Fetched(sent=transport.sent, error="timeout")
    if isinstance(error, openai.APIConnectionError):
        return Fetched(sent=transport.sent, error="connection")
    return Fetched(sent=transport.sent, error="provider_error")


async def fetch(prepared: PreparedEmbedding, factory: Callable[[], httpx2.AsyncBaseTransport],
                credential: SecretStr, timeout: httpx2.Timeout = TIMEOUT, *,
                observe: Callable[[Fetched], None] | None = None) -> Fetched:
    """One physical request. The raw body is returned (and observed as soon as it is complete) for `classify`;
    nothing is interpreted here."""
    require_clean_environment("openai")  # before anything is acquired
    inner = factory()
    try:
        recorder = _Recorder(inner)
        transport = BoundedTransport(recorder, Expected("openai", EMBEDDINGS_PATH, prepared.body, EMBEDDING_BOUNDS),
                                     credential)
        http = http_client(transport, timeout)
    except BaseException:
        await bounded_close(inner.aclose)  # nothing else owns it yet
        raise
    observed = False
    try:
        client = sdk_client("openai", http, credential, timeout)
        raw = await client.embeddings.with_raw_response.create(**prepared.params())
        response = raw.http_response
        request_id = response.headers.get("x-request-id")
        fetched = Fetched(sent=transport.sent, raw=response.content,
                          provider_request_id=request_id if request_id and REQUEST_ID.fullmatch(request_id) else None)
        if not _json(response.headers.get("content-type", "")):
            fetched = Fetched(sent=transport.sent, error="response_not_json")
        elif observe is not None:
            fetched.cleanup_confirmed = False  # not known until the close below finishes (set again after it)
            observe(fetched)  # synchronously, before any cleanup is awaited
            observed = True
    except (openai.APIError, TransportRefused, ResponseTooLarge) as error:
        fetched = _failure(transport, error)
    except BaseException:
        # Interrupted inside the SDK (for example while it closed the response): a body that had completely
        # arrived is still handed over, so its bill is not lost.
        body = recorder.body()
        if body is not None and observe is not None and not observed:
            body.cleanup_confirmed = False
            observe(body)
        raise
    finally:
        # The HTTP client owns the transport (and so the inner transport) from here: it is closed also when the SDK
        # constructor failed or the call was cancelled.
        closed = await bounded_close(http.aclose)
    fetched.cleanup_confirmed = closed and not transport.cleanup_unconfirmed
    return fetched


# -- the bounded parse -------------------------------------------------------------------------------------------

class _Marker:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name


INVALID = _Marker("INVALID")  # an oversized numeric literal, NaN or Infinity
DUPLICATE = _Marker("DUPLICATE")  # the value of a key that appeared more than once in its object


class Unparseable(ValueError):
    """The body is not bounded, strict JSON; nothing in it is used."""


def precheck(text: str) -> None:
    """One cursor, anchored matches only: linear in the text, and at most about MAX_STRINGS + 2 * MAX_CONTAINERS
    iterations before it either finishes or refuses."""
    strings = containers = depth = 0
    position, end = 0, len(text)
    while position < end:
        token = _TOKEN.match(text, position)
        if token is None:
            raise Unparseable("an unterminated or invalid string")  # a quote that does not start a valid string
        kind = token.lastgroup
        if kind == "string":
            strings += 1
            if strings > MAX_STRINGS or token.end() - token.start() > MAX_STRING_CHARS + 2:
                raise Unparseable("too many or too long strings")
        elif kind == "bracket":
            if token.group() in "[{":
                containers += 1
                depth += 1
                if containers > MAX_CONTAINERS or depth > MAX_DEPTH:
                    raise Unparseable("too many or too deeply nested containers")
            else:
                depth -= 1
        position = token.end()


@dataclass
class Document:
    """A parsed body; `tainted` when any duplicate key or invalid value occurred anywhere in it."""

    root: Any
    tainted: bool


def loads(raw: bytes) -> Document:
    """Bounded, strict JSON with confined bad values (see the module docstring)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Unparseable("not UTF-8") from None
    precheck(text)
    tainted = False

    def mark(marker: _Marker) -> _Marker:
        nonlocal tainted
        tainted = True
        return marker

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            result[key] = mark(DUPLICATE) if key in result else value
        return result

    def number(convert: Callable[[str], Any]) -> Callable[[str], Any]:
        return lambda literal: mark(INVALID) if len(literal) > MAX_NUMBER_CHARS else convert(literal)

    try:
        root = json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: mark(INVALID),
                          parse_float=number(float), parse_int=number(int))
    except (ValueError, RecursionError) as error:
        raise Unparseable("not valid JSON") from error
    return Document(root, tainted)


def _count(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value < 2**31 else None


@dataclass(frozen=True)
class Billing:
    returned_model: str
    prompt_tokens: int
    total_tokens: int


def billing_of(root: Any) -> Billing | None:
    if not isinstance(root, dict):
        return None
    model, usage = root.get("model"), root.get("usage")
    if not isinstance(model, str) or not isinstance(usage, dict):
        return None
    prompt, total = _count(usage.get("prompt_tokens")), _count(usage.get("total_tokens"))
    if prompt is None or total is None:
        return None
    return Billing(model if MODEL_TEXT.fullmatch(model) else "other", prompt, total)


_PACK = struct.Struct("<1536f")


def _vector(values: Any, dimensions: int) -> tuple[tuple[float, ...], float] | None:
    if not isinstance(values, list) or len(values) != dimensions or dimensions != _PACK.size // 4:
        return None
    numbers = []
    for value in values:
        if type(value) not in (float, int) or not math.isfinite(value) or abs(value) > FLOAT32_MAX:
            return None
        numbers.append(float(value))
    try:
        rounded = _PACK.unpack(_PACK.pack(*numbers))
    except (OverflowError, struct.error):
        return None
    if not any(rounded):
        return None  # all zero after float32 rounding
    norm = math.sqrt(math.fsum(v * v for v in rounded))
    return (rounded, norm) if math.isfinite(norm) else None


Vectors = tuple[tuple[tuple[float, ...], ...], tuple[float, ...]]


def vectors_of(root: Any, count: int, dimensions: int) -> Vectors | None:
    if not isinstance(root, dict) or root.get("object") != "list":
        return None
    data = root.get("data")
    if not isinstance(data, list) or len(data) != count:
        return None
    by_index: dict[int, tuple[tuple[float, ...], float]] = {}
    for item in data:
        if not isinstance(item, dict) or item.get("object") != "embedding":
            return None
        index = item.get("index")
        if type(index) is not int or not 0 <= index < count or index in by_index:
            return None
        vector = _vector(item.get("embedding"), dimensions)
        if vector is None:
            return None
        by_index[index] = vector
    ordered = [by_index[i] for i in range(count)]  # unique and in range, so contiguous 0..count-1
    return tuple(v for v, _ in ordered), tuple(n for _, n in ordered)


Outcome = Literal["unknown", "usage_contradiction", "model_mismatch", "count_mismatch", "vectors_invalid",
                  "published"]
BLOCKS: Mapping[str, str] = {"usage_contradiction": "embedding_usage_contradiction",
                             "model_mismatch": "embedding_model_mismatch",
                             "count_mismatch": "embedding_count_mismatch"}


@dataclass(frozen=True)
class Classified:
    outcome: Outcome
    billing: Billing | None
    response_sha256: str
    vectors: tuple[tuple[float, ...], ...] | None = None
    norms: tuple[float, ...] | None = None

    @property
    def settles(self) -> bool:
        return self.outcome in ("count_mismatch", "vectors_invalid", "published")

    @property
    def block(self) -> str | None:
        return BLOCKS.get(self.outcome)


def usage_of(billing: Billing) -> Usage:
    """The priced usage: embedding input tokens only (`reasoning` unreported, so the canonical usage is v2)."""
    return Usage(input_total=billing.prompt_tokens, cache_read=0, cache_writes={}, output=0, reasoning=None)


def diagnostic_of(outcome: str, billing: Billing) -> Diagnostic:
    return Diagnostic((BLOCKS[outcome],), {"input_tokens": billing.prompt_tokens, "total": billing.total_tokens})


def classify(raw: bytes, prepared: PreparedEmbedding, local_tokens: int) -> Classified:
    """The six-row accounting table. Pure; the raw bytes are only hashed and parsed, never stored."""
    digest = hashlib.sha256(raw).hexdigest()
    try:
        document = loads(raw)
    except Unparseable:
        return Classified("unknown", None, digest)
    billing = billing_of(document.root)
    if billing is None:
        return Classified("unknown", None, digest)
    if billing.prompt_tokens != billing.total_tokens:
        return Classified("usage_contradiction", billing, digest)
    if billing.returned_model != prepared.model:
        return Classified("model_mismatch", billing, digest)
    if billing.prompt_tokens != local_tokens:
        return Classified("count_mismatch", billing, digest)
    parsed = None if document.tainted else vectors_of(document.root, len(prepared.inputs), prepared.dimensions)
    if parsed is None:
        return Classified("vectors_invalid", billing, digest)
    return Classified("published", billing, digest, parsed[0], parsed[1])
