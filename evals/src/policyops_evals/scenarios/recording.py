"""Bounded OpenAI Responses cassettes at the transport seam, before SDK normalization."""

from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from time import monotonic
from typing import Any, Literal
from uuid import UUID, uuid5

import httpx2
from pydantic import BaseModel, ConfigDict

from policyops.providers.results import REQUEST_ID
from policyops.providers.transport import MAX_RESPONSE_BYTES
from policyops_contracts.retail import WRITE_TOOLS, ToolName


MAX_BODY_BYTES = MAX_RESPONSE_BYTES
MAX_EXCHANGES = 16  # a count and an inference for each of eight calls, with zero retries or repairs
Phase = Literal["count", "create"]
Secret = re.compile(
    r"""(?ix)
    (?:postgres(?:ql)?|mysql|redis)(?:\+[a-z0-9_-]+)?://[^\s"'<>\\]+
    |\b(?:bearer\s+|password\s*=\s*|api[_-]?key\s*=\s*)[^\s"',;<>\\]+
    |\bsk-[a-z0-9_-]{8,}
    """
)
SENSITIVE_KEYS = frozenset({"authorization", "headers", "apikey", "password", "accesstoken", "refreshtoken",
                            "clientsecret", "credential", "credentials", "dsn"})
JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
JSON_FIELD = re.compile(rf'\s*({JSON_STRING.pattern})\s*:\s*')
JSON_COMMA = re.compile(r"\s*,")
DECODER = json.JSONDecoder()
CONSEQUENTIAL = frozenset(name.value for name in WRITE_TOOLS | {ToolName.TRANSFER_TO_HUMAN_AGENTS})


def phase_of(request: httpx2.Request) -> Phase:
    if request.url.path == "/v1/responses/input_tokens":
        return "count"
    if request.url.path == "/v1/responses":
        return "create"
    raise ValueError("unexpected scenario transport endpoint")


def object_from(raw: str | bytes | None) -> dict[str, Any]:
    try:
        value = json.loads(raw) if raw is not None else None
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class Redactor:
    ids: Mapping[UUID, str] = field(default_factory=dict)
    secrets: tuple[str, ...] = field(default=(), repr=False)

    def body(self, raw: bytes) -> str | None:
        if len(raw) > MAX_BODY_BYTES:
            return None
        try:
            text = raw.decode()
            json.loads(text)  # the non-streaming profile never retains arbitrary non-JSON response bodies
        except (ValueError, RecursionError):
            return None
        text = self._json(text, depth=0)
        for identifier, label in self.ids.items():
            text = text.replace(str(identifier), f"[{label}]")
        return text if len(text.encode()) <= MAX_BODY_BYTES else None

    def _json(self, text: str, *, depth: int) -> str:
        """Change only sensitive values and keep JSON spelling and duplicate keys everywhere else."""
        parts: list[str] = []
        offset = 0
        while match := JSON_STRING.search(text, offset):
            start, end = match.span()
            value: str = json.loads(match[0])
            parts.append(text[offset:start])
            tail = end
            while tail < len(text) and text[tail].isspace():
                tail += 1
            if tail < len(text) and text[tail] == ":":
                if value.lower().replace("_", "").replace("-", "") in SENSITIVE_KEYS:
                    first = tail + 1
                    while text[first].isspace():
                        first += 1
                    _, offset = DECODER.raw_decode(text, first)
                    parts.append(text[start:first] + "null")
                    continue
                sanitized = value
            else:
                sanitized = self._value(value, depth=depth)
            parts.append(match[0] if sanitized == value else json.dumps(sanitized, ensure_ascii=True))
            offset = end
        parts.append(text[offset:])
        return "".join(parts)

    def _value(self, value: str, *, depth: int) -> str:
        for secret in sorted(filter(None, self.secrets), key=len, reverse=True):
            value = value.replace(secret, "[redacted]")
        if depth < 4 and value.lstrip().startswith(("{", "[")):
            try:
                json.loads(value)
            except (ValueError, RecursionError):
                pass  # malformed function arguments remain available to the grader
            else:
                return self._json(value, depth=depth + 1)
        return Secret.sub("[redacted]", value)


def digest(body: str | None) -> str | None:
    return None if body is None else sha256(body.encode()).hexdigest()


class Exchange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int
    attempt: int
    phase: Phase
    request: str | None
    request_sha256: str | None
    response: str | None = None
    response_sha256: str | None = None
    status: int | None = None
    elapsed_ms: int | None = None
    complete: bool = False


class Tape:
    """One file per exchange. Persist the request before dispatch and replace it after reading the response."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self.records: list[Exchange] = []
        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)
            paths = sorted(directory.glob("[0-9][0-9].json"))
            if len(paths) > MAX_EXCHANGES:
                raise ValueError("cassette exchange limit")
            for index, path in enumerate(paths):
                if path.name != f"{index:02}.json" or path.stat().st_size > 12 * MAX_BODY_BYTES:
                    raise ValueError("invalid cassette exchange")
                exchange = Exchange.model_validate_json(path.read_bytes())
                if (exchange.index != index or digest(exchange.request) != exchange.request_sha256
                        or digest(exchange.response) != exchange.response_sha256):
                    raise ValueError("cassette integrity failure")
                self.records.append(exchange)

    def save(self, exchange: Exchange) -> None:
        if exchange.index >= MAX_EXCHANGES:
            raise ValueError("cassette exchange limit")
        if self.directory is not None:
            target = self.directory / f"{exchange.index:02}.json"
            with NamedTemporaryFile(mode="wb", dir=self.directory, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(exchange.model_dump_json().encode())
            try:
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        if exchange.index == len(self.records):
            self.records.append(exchange)
        else:
            self.records[exchange.index] = exchange


class _Capture(httpx2.AsyncByteStream):
    def __init__(self, stream: httpx2.AsyncByteStream, done: Callable[[bytes | None, bool], None]) -> None:
        self.stream = stream
        self.done = done
        self.finished = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        data: bytearray | None = bytearray()
        complete = False
        try:
            async for chunk in self.stream:
                if data is not None:
                    if len(data) + len(chunk) <= MAX_BODY_BYTES:
                        data.extend(chunk)
                    else:
                        data = None
                yield chunk
            complete = True
        finally:
            self.finish(bytes(data) if data is not None else None, complete)

    def finish(self, body: bytes | None, complete: bool) -> None:
        if not self.finished:
            self.finished = True
            self.done(body, complete)

    async def aclose(self) -> None:
        try:
            await self.stream.aclose()
        finally:
            self.finish(None, False)


class Recorder(httpx2.AsyncBaseTransport):
    def __init__(self, inner: httpx2.AsyncBaseTransport, tape: Tape, redactor: Redactor) -> None:
        self.inner, self.tape, self.redactor = inner, tape, redactor

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        phase = phase_of(request)
        canonical = self.redactor.body(await request.aread())
        attempt = sum(item.phase == "count" for item in self.tape.records) - int(phase == "create")
        exchange = Exchange(index=len(self.tape.records), attempt=attempt, phase=phase,
                            request=canonical, request_sha256=digest(canonical))
        self.tape.save(exchange)
        started = monotonic()
        try:
            response = await self.inner.handle_async_request(request)
        except BaseException:
            self.tape.save(exchange.model_copy(update={"elapsed_ms": int((monotonic() - started) * 1000)}))
            raise

        def finish(body: bytes | None, complete: bool) -> None:
            redacted = self.redactor.body(body) if body is not None else None
            self.tape.save(exchange.model_copy(update={
                "response": redacted, "response_sha256": digest(redacted), "complete": complete,
                "status": response.status_code, "elapsed_ms": int((monotonic() - started) * 1000),
            }))

        if response.headers.get("content-encoding", "identity").lower() != "identity":
            finish(None, False)
        elif response.is_stream_consumed:
            finish(response.content, True)
        elif isinstance(response.stream, httpx2.AsyncByteStream):
            response.stream = _Capture(response.stream, finish)
        return response

    async def aclose(self) -> None:
        await self.inner.aclose()


@dataclass(frozen=True)
class ConsequentialCall:
    name: str
    arguments: object
    call_id: object
    exchange_index: int
    only_call: bool


def first_consequential_call(records: list[Exchange]) -> ConsequentialCall | None:
    for item in records:
        if item.phase != "create" or not item.complete or item.status != 200:
            continue
        response = object_from(item.response)
        output = response.get("output")
        if not isinstance(output, list):
            continue
        for raw in output:
            if not isinstance(raw, dict):
                continue
            name = raw.get("name")
            if isinstance(name, str) and name in CONSEQUENTIAL:
                only = (response.get("status") == "completed" and raw.get("type") == "function_call"
                        and all(part is raw or (isinstance(part, dict) and part.get("type") == "reasoning")
                                for part in output))
                return ConsequentialCall(name, raw.get("arguments"), raw.get("call_id"), item.index, only)
    return None


class ReplayMismatch(RuntimeError):
    pass


def _replay_response_id(body: str, run_id: UUID) -> str:
    """Rebind the top-level billing identity without re-encoding model output."""
    start = body.lstrip()
    if not start.startswith("{"):
        return body
    position = len(body) - len(start) + 1
    while field := JSON_FIELD.match(body, position):
        try:
            value, end = DECODER.raw_decode(body, field.end())
        except (ValueError, RecursionError):
            break
        if json.loads(field[1]) == "id" and isinstance(value, str) and REQUEST_ID.fullmatch(value):
            replay_id = uuid5(run_id, f"openai-response:{value}")
            return body[:field.end()] + f'"resp_{replay_id.hex}"' + body[end:]
        separator = JSON_COMMA.match(body, end)
        if separator is None:
            break
        position = separator.end()
    return body


@dataclass
class Replay:
    records: tuple[Exchange, ...]
    redactor: Redactor
    run_id: UUID
    index: int = 0
    failure: str | None = None

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        if self.failure is not None:
            raise ReplayMismatch(self.failure)
        if self.index >= len(self.records):
            self.failure = "unexpected replay request"
        else:
            item = self.records[self.index]
            body = self.redactor.body(request.content)
            if body is None or phase_of(request) != item.phase or digest(body) != item.request_sha256:
                self.failure = "replay request digest mismatch"
            elif not item.complete or item.response is None or item.status is None:
                self.failure = "recorded response is unavailable"
            else:
                # The ledger settles each provider response ID once per workspace, across runs.
                response = (_replay_response_id(item.response, self.run_id)
                            if item.phase == "create" and item.status == 200 else item.response)
                self.index += 1
                return httpx2.Response(item.status, content=response.encode(),
                                       headers={"content-type": "application/json"})
        raise ReplayMismatch(self.failure)

    def verify(self) -> None:
        # The SDK may turn the mismatch into a transport failure. Check again after the worker stops.
        if self.failure is not None or self.index != len(self.records):
            raise ReplayMismatch(self.failure or "unused replay responses")
