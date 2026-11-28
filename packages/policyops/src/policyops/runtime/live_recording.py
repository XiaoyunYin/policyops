"""Bounded, local-only transport tapes for the fictional live-agent case."""

from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from time import monotonic
from typing import Literal
from uuid import UUID

import httpx2
from pydantic import BaseModel, ConfigDict, Field

from policyops.providers.calls import Providers
from policyops.providers.contract import Provider
from policyops.providers.transport import MAX_RESPONSE_BYTES
from policyops.runtime.spec import StepContext


MAX_EXCHANGES = 16  # At most eight count/create pairs per run, with no provider retries.
MAX_TOOLS = 7
MAX_CLAIMS = 3
PHASES = {"/v1/responses/input_tokens": "count", "/v1/responses": "create"}
SENSITIVE = frozenset({"authorization", "proxyauthorization", "headers", "apikey", "password", "secret",
                       "accesstoken", "refreshtoken", "clientsecret", "credential", "credentials", "dsn", "cookie",
                       "setcookie", "xapikey", "token"})
SECRET_PATTERN = re.compile(
    r"""(?ix)(?:postgres(?:ql)?|mysql|redis)(?:\+[a-z0-9_-]+)?://[^\s"'<>\\]+
    |\b(?:bearer\s+|password\s*=\s*|api[_-]?key\s*=\s*)[^\s"',;<>\\]+
    |\bsk-[a-z0-9_-]{8,}"""
)
JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
DECODER = json.JSONDecoder()


@dataclass(frozen=True)
class Redactor:
    secret: str = field(repr=False)

    def body(self, raw: bytes | None) -> str | None:
        if raw is None or len(raw) > MAX_RESPONSE_BYTES:
            return None
        try:
            original = raw.decode("utf-8")
            json.loads(original)
            cleaned = self._json(original, depth=0)
            return cleaned if len(cleaned.encode("utf-8")) <= MAX_RESPONSE_BYTES else None
        except (ValueError, RecursionError):
            return None

    def _json(self, text: str, *, depth: int) -> str:
        # Keep JSON spelling and duplicate fields for diagnosis, including inside function arguments.
        parts: list[str] = []
        offset = 0
        while match := JSON_STRING.search(text, offset):
            start, end = match.span()
            value = json.loads(match[0])
            parts.append(text[offset:start])
            tail = end
            while tail < len(text) and text[tail].isspace():
                tail += 1
            if tail < len(text) and text[tail] == ":" and re.sub("[^a-z]", "", value.lower()) in SENSITIVE:
                first = tail + 1
                while text[first].isspace():
                    first += 1
                _, offset = DECODER.raw_decode(text, first)
                parts.append(match[0] + ":null")
                continue
            cleaned = value.replace(self.secret, "[redacted]") if self.secret else value
            cleaned = SECRET_PATTERN.sub("[redacted]", cleaned)
            if depth < 4 and cleaned.lstrip().startswith(("{", "[")):
                try:
                    json.loads(cleaned)
                except (ValueError, RecursionError):
                    pass
                else:
                    cleaned = self._json(cleaned, depth=depth + 1)
            parts.append(match[0] if cleaned == value else json.dumps(cleaned))
            offset = end
        parts.append(text[offset:])
        return "".join(parts)


def digest(body: str | None) -> str | None:
    return sha256(body.encode()).hexdigest() if body is not None else None


class Exchange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    index: int = Field(ge=0, lt=MAX_EXCHANGES)
    phase: Literal["count", "create"]
    started_at: datetime
    request: str | None
    request_sha256: str | None
    response: str | None = None
    response_sha256: str | None = None
    status: int | None = None
    elapsed_ms: int | None = None
    complete: bool = False


class ToolTime(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    node: Literal["read", "retrieve", "propose"]
    elapsed_ms: int = Field(ge=0)


def _save(target: Path, payload: BaseModel) -> None:
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(mode="wb", dir=target.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(payload.model_dump_json().encode())
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class Tape:
    def __init__(self, directory: Path, redactor: Redactor) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.directory, self.redactor = directory, redactor
        self.exchanges = self.tools = 0

    def begin(self, request: httpx2.Request, raw: bytes) -> Exchange:
        body = self.redactor.body(raw)
        exchange = Exchange.model_validate(dict(index=self.exchanges, phase=PHASES[request.url.path],
            started_at=datetime.now(UTC), request=body, request_sha256=digest(body)))
        self.save(exchange)
        self.exchanges += 1
        return exchange

    def save(self, exchange: Exchange) -> None:
        _save(self.directory / f"{exchange.index:02}.json", exchange)

    def tool(self, node: str, elapsed_ms: int) -> None:
        if self.tools >= MAX_TOOLS:
            raise ValueError("live tape tool limit")
        timing = ToolTime.model_validate(dict(node=node, elapsed_ms=elapsed_ms))
        with suppress(OSError):
            _save(self.directory / f"tool-{self.tools:02}.json", timing)
        self.tools += 1


class Capture(httpx2.AsyncByteStream):
    def __init__(self, stream: httpx2.AsyncByteStream, finish: Callable[[bytes | None, bool], None]) -> None:
        self.stream, self.finish = stream, finish

    async def __aiter__(self) -> AsyncIterator[bytes]:
        body: bytearray | None = bytearray()
        complete = False
        try:
            async for chunk in self.stream:
                if body is not None:
                    if len(body) + len(chunk) <= MAX_RESPONSE_BYTES:
                        body.extend(chunk)
                    else:
                        body = None
                yield chunk
            complete = True
        finally:
            self.finish(bytes(body) if body is not None and complete else None, complete)

    async def aclose(self) -> None:
        try:
            await self.stream.aclose()
        finally:
            self.finish(None, False)


class Recorder(httpx2.AsyncBaseTransport):
    def __init__(self, inner: httpx2.AsyncBaseTransport, tape: Tape) -> None:
        self.inner, self.tape = inner, tape

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        exchange = self.tape.begin(request, await request.aread())
        started = monotonic()
        try:
            response = await self.inner.handle_async_request(request)
        except BaseException:
            with suppress(OSError):
                self.tape.save(exchange.model_copy(update={"elapsed_ms": int((monotonic() - started) * 1000)}))
            raise
        finished = False

        def finish(raw: bytes | None, complete: bool) -> None:
            nonlocal finished
            if finished:
                return
            finished = True
            elapsed = int((monotonic() - started) * 1000)
            body = self.tape.redactor.body(raw)
            with suppress(OSError):
                self.tape.save(exchange.model_copy(update={"status": response.status_code, "elapsed_ms": elapsed,
                    "complete": complete, "response": body, "response_sha256": digest(body)}))

        if response.headers.get("content-encoding", "identity").lower() != "identity":
            finish(None, False)
        elif response.is_stream_consumed:
            finish(response.content, True)
        elif isinstance(response.stream, httpx2.AsyncByteStream):
            response.stream = Capture(response.stream, finish)
        return response

    async def aclose(self) -> None:
        await self.inner.aclose()


def tape_root(path: Path, checkout: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("live tape root must be an external absolute directory")
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(checkout.resolve()) or not resolved.is_dir():
        raise ValueError("live tape root must be an external absolute directory")
    return resolved


def bind_recording(root: Path, providers: Providers, context: StepContext
                   ) -> tuple[Providers, Callable[[str, int], None]]:
    run = root / str(context.run_id)
    run.mkdir(mode=0o700, exist_ok=True)
    if run.is_symlink():
        raise ValueError("live tape run directory must not be a symlink")
    tape = Tape(run / str(context.claim_token.claim_id), Redactor(providers.credentials["openai"].get_secret_value()))

    def transport(provider: Provider) -> httpx2.AsyncBaseTransport:
        if provider != "openai":
            raise ValueError("unsupported live tape provider")
        return Recorder(providers.transport(provider), tape)

    return replace(providers, transport=transport), tape.tool


def measurements(root: Path, run_id: UUID) -> tuple[list[Exchange], list[ToolTime]]:
    run = root / str(run_id)
    exchanges: list[Exchange] = []
    tools: list[ToolTime] = []
    if run.is_symlink():
        raise ValueError("live tape run directory must not be a symlink")
    for index, claim in enumerate(run.iterdir() if run.exists() else ()):
        if (index >= MAX_CLAIMS or claim.is_symlink() or not claim.is_dir()
                or claim.resolve().parent != run.resolve()):
            raise ValueError("invalid live tape directory")
        for entry, path in enumerate(claim.glob("*.json")):
            if entry >= MAX_EXCHANGES + MAX_TOOLS:
                raise ValueError("live tape record limit")
            if path.is_symlink() or path.stat().st_size > 12 * MAX_RESPONSE_BYTES:
                raise ValueError("invalid live tape record")
            if path.name.startswith("tool-"):
                tools.append(ToolTime.model_validate_json(path.read_bytes()))
            else:
                exchange = Exchange.model_validate_json(path.read_bytes())
                if (digest(exchange.request) != exchange.request_sha256
                        or digest(exchange.response) != exchange.response_sha256):
                    raise ValueError("live tape integrity failure")
                exchanges.append(exchange)
    return sorted(exchanges, key=lambda e: (e.started_at, e.index)), tools
