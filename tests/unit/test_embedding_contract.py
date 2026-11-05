"""T12 embedding request contract over the real SDK (openai 3.40.0) and a scripted `httpx2` transport: the exact
canonical request on the wire, the explicit embedding response bounds, transport ownership on every failure path,
and a complete body that survives an interrupted cleanup. Also the job and vector DTO bounds. No network or key."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
import gzip
import json
from typing import Any

import httpx2
from pydantic import SecretStr, ValidationError
import pytest

from policyops.budget.config import Configuration
from policyops.providers import embeddings as emb
from policyops.providers.canonical import canonical_bytes, strict_loads
from policyops.providers.contract import ENDPOINTS, ContractGap
from policyops.providers.embedding_contract import EMBEDDINGS_PATH, ENDPOINT, request_config_sha256
from policyops_contracts.embedding import EmbeddedInput, EmbeddingJob


KEY = SecretStr("synthetic-test-credential-0000")


def vector(seed: int = 0) -> list[float]:
    return [((i * 7 + seed) % 13 - 6) / 100.0 for i in range(1536)]


def body_for(count: int, *, tokens: int = 7, **extra: Any) -> dict[str, Any]:
    return {"object": "list", "model": "text-embedding-3-small", "usage": {"prompt_tokens": tokens,
                                                                         "total_tokens": tokens},
            "data": [{"object": "embedding", "index": i, "embedding": vector(i)} for i in range(count)], **extra}


class Chunks(httpx2.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, stall: bool = False, close_wait: asyncio.Event | None = None,
                 closing: asyncio.Event | None = None) -> None:
        self.chunks, self.stall, self.close_wait, self.closing = chunks, stall, close_wait, closing
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk
        if self.stall:
            await asyncio.Event().wait()

    async def aclose(self) -> None:
        if self.closing is not None:
            self.closing.set()
        if self.close_wait is not None:
            await self.close_wait.wait()
        self.closed = True


class Script(httpx2.AsyncBaseTransport):
    def __init__(self, respond: Callable[[httpx2.Request], httpx2.Response], *,
                 close_wait: asyncio.Event | None = None, closing: asyncio.Event | None = None) -> None:
        self.respond, self.close_wait, self.closing = respond, close_wait, closing
        self.requests: list[httpx2.Request] = []
        self.bodies: list[bytes] = []
        self.closed = 0

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        self.bodies.append(await request.aread())
        return self.respond(request)

    async def aclose(self) -> None:
        if self.closing is not None:
            self.closing.set()
        if self.close_wait is not None:
            await self.close_wait.wait()
        self.closed += 1


def answer(data: bytes, *, status: int = 200, content_type: str = "application/json", stream: Chunks | None = None,
           headers: dict[str, str] | None = None) -> Callable[[httpx2.Request], httpx2.Response]:
    return lambda request: httpx2.Response(status, headers={"content-type": content_type, **(headers or {})},
                                           stream=stream or Chunks([data]), request=request)


def prepared(count: int = 2) -> emb.PreparedEmbedding:
    return emb.prepare([f"input number {i}" for i in range(count)], Configuration())


def fetch(p: emb.PreparedEmbedding, script: Script, **kwargs: Any) -> emb.Fetched:
    return asyncio.run(emb.fetch(p, lambda: script, KEY, **kwargs))


# -- the canonical request -----------------------------------------------------------------------------------------

def test_the_body_is_exact_and_the_fingerprint_binds_the_whole_request() -> None:
    p = prepared()
    assert strict_loads(p.body) == {"model": "text-embedding-3-small", "input": ["input number 0", "input number 1"],
                                    "dimensions": 1536, "encoding_format": "float"}
    assert p.body == canonical_bytes(strict_loads(p.body))
    assert p.request_sha256 == prepared().request_sha256
    assert emb.prepare(["input number 1", "input number 0"], Configuration()).request_sha256 != p.request_sha256
    assert ENDPOINT is ENDPOINTS["openai"] and EMBEDDINGS_PATH == "/v1/embeddings"
    assert request_config_sha256("text-embedding-3-small", 1536) != request_config_sha256("text-embedding-3-small",
                                                                                          512)


@pytest.mark.parametrize(("texts", "message"), [
    ([], "1-64 inputs"), (["x"] * 65, "1-64 inputs"), ([""], "characters"), (["a\x00b"], "NUL"),
    (["\ud800"], "UTF-8"), (["x" * 32_769], "characters"), (["€" * 21_846], "larger than"),
    (["a" * 32_768] * 8 + ["b"], "at most 262144 bytes"),
])
def test_request_bounds_refuse_before_anything_is_sent(texts: list[str], message: str) -> None:
    with pytest.raises(ContractGap, match=message):
        emb.prepare(texts, Configuration())
    assert len(emb.prepare(["a" * 32_768] * 8, Configuration()).inputs) == 8  # exactly 262144 bytes


def test_the_sdk_sends_exactly_the_canonical_bytes_once() -> None:
    p = prepared()
    script = Script(answer(json.dumps(body_for(2)).encode(), headers={"x-request-id": "req_abc123"}))
    fetched = fetch(p, script)
    (request,) = script.requests
    assert request.method == "POST" and str(request.url) == "https://api.openai.com/v1/embeddings"
    assert canonical_bytes(strict_loads(script.bodies[0])) == p.body
    assert request.headers["authorization"] == f"Bearer {KEY.get_secret_value()}"
    assert fetched.raw is not None and fetched.provider_request_id == "req_abc123" and fetched.cleanup_confirmed
    assert emb.classify(fetched.raw, p, 7).outcome == "published"


# -- response bounds over the real SDK ------------------------------------------------------------------------------

def test_the_maximum_batch_passes_as_one_long_line_and_pretty_printed() -> None:
    p = emb.prepare([f"i{i}" for i in range(64)], Configuration())
    compact = json.dumps(body_for(64), separators=(",", ":")).encode()
    assert compact.count(b"\n") == 0 and len(compact) > 64 << 10
    assert fetch(p, Script(answer(compact))).raw == compact
    worst = body_for(64)
    for item in worst["data"]:
        item["embedding"] = [float("-0.0" + "1" * 21 + "e-1")] * 1536  # 24-character literals once printed
    pretty = json.dumps(worst, indent=2).encode()  # a synthetic two-space layout (numbers 8 spaces deep)
    assert len(pretty) < 4 << 20
    assert fetch(p, Script(answer(pretty))).raw == pretty


@pytest.mark.parametrize("chunks", [[b" " * ((4 << 20) + 1)], [b" " * (2 << 20), b" " * ((2 << 20) + 1)]])
def test_more_than_4_mib_is_refused_in_one_chunk_or_across_chunks(chunks: list[bytes]) -> None:
    stream = Chunks(chunks)
    fetched = fetch(prepared(), Script(answer(b"", stream=stream)))
    assert (fetched.raw, fetched.error) == (None, "response_too_large") and stream.closed


def test_a_compressed_or_non_json_response_is_refused() -> None:
    stream = Chunks([gzip.compress(json.dumps(body_for(2)).encode())])
    fetched = fetch(prepared(), Script(answer(b"", stream=stream, headers={"content-encoding": "gzip"})))
    assert (fetched.raw, fetched.error) == (None, "content_encoding") and stream.closed
    sse = fetch(prepared(), Script(answer(b"data: {}\n\n", content_type="text/event-stream")))
    assert (sse.raw, sse.error) == (None, "response_not_json")


def test_an_http_error_is_classified_without_a_body() -> None:
    fetched = fetch(prepared(), Script(answer(b'{"error": {"type": "invalid_request_error"}}', status=400)))
    assert (fetched.raw, fetched.status, fetched.error) == (None, 400, "http_400")


def test_a_stalled_body_is_cut_by_the_callers_deadline_and_closed() -> None:
    stream = Chunks([b'{"object": "list"'], stall=True)
    script = Script(answer(b"", stream=stream))
    arrived: list[emb.Fetched] = []

    async def run() -> None:
        async with asyncio.timeout(0.5):
            await emb.fetch(prepared(), lambda: script, KEY, observe=arrived.append)

    with pytest.raises(TimeoutError):
        asyncio.run(run())
    assert arrived == [] and stream.closed and script.closed == 1  # no complete body, so nothing to account


# -- ownership of the transport --------------------------------------------------------------------------------------

def test_ambient_settings_are_refused_before_the_transport_is_acquired(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid")
    acquired: list[Script] = []

    def factory() -> Script:
        acquired.append(Script(answer(b"{}")))
        return acquired[-1]

    with pytest.raises(ContractGap, match="OPENAI_BASE_URL"):
        asyncio.run(emb.fetch(prepared(), factory, KEY))
    assert acquired == []


@pytest.mark.parametrize("broken", ["http_client", "sdk_client"])
def test_a_constructor_failure_still_closes_the_acquired_transport(broken: str,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("constructor failed")

    monkeypatch.setattr(emb, broken, fail)
    script = Script(answer(b"{}"))
    with pytest.raises(RuntimeError, match="constructor failed"):
        fetch(prepared(), script)
    assert script.closed == 1 and script.requests == []


# -- a complete body survives an interrupted cleanup -----------------------------------------------------------------

def interrupted(where: str) -> tuple[list[emb.Fetched], Script, Chunks]:
    """The complete valid body arrives; then the cleanup waits forever and the task is cancelled during it."""
    closing, never = asyncio.Event(), asyncio.Event()
    data = json.dumps(body_for(2)).encode()
    stream = Chunks([data], close_wait=never if where == "stream" else None,
                    closing=closing if where == "stream" else None)
    script = Script(answer(b"", stream=stream, headers={"x-request-id": "req_late1"}),
                    close_wait=never if where == "client" else None, closing=closing if where == "client" else None)
    arrived: list[emb.Fetched] = []

    async def run() -> None:
        task = asyncio.create_task(emb.fetch(prepared(), lambda: script, KEY, observe=arrived.append))
        await closing.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    return arrived, script, stream


@pytest.mark.parametrize("where", ["client", "stream"])
def test_a_cancellation_during_cleanup_still_hands_over_the_complete_body(where: str) -> None:
    arrived, script, _ = interrupted(where)
    (body,) = arrived
    assert body.raw == json.dumps(body_for(2)).encode() and body.provider_request_id == "req_late1"
    assert len(script.requests) == 1  # one physical request, never a second
    assert emb.classify(body.raw, prepared(), 7).outcome == "published"


# -- packing -----------------------------------------------------------------------------------------------------------

def spaced(index: int, extra: int = 0) -> str:
    """32,768 code points of 32,768 + `extra` (0 or 1) UTF-8 bytes, few tokens: long whitespace runs within the
    1,024-byte piece bound; the extra byte comes from one two-byte letter, so the code-point bound still holds."""
    text = (" " * 1000 + "a") * 32 + "b" * (735 - extra) + "é" * extra + str(index)
    assert (len(text), len(text.encode("utf-8"))) == (32_768, 32_768 + extra)
    return text


@pytest.mark.parametrize(("texts", "sizes"), [
    ([spaced(i) for i in range(8)], [8]),  # exactly 262,144 bytes: one request
    ([spaced(i) for i in range(9)], [8, 1]),  # the reviewer's trigger: split, never a refused request
    ([spaced(0, extra=1)] + [spaced(i) for i in range(1, 8)], [7, 1]),  # 262,145 bytes: split before the 8th
])
def test_packing_splits_on_the_aggregate_input_byte_limit(texts: list[str], sizes: list[int]) -> None:
    from uuid import uuid4

    from policyops.providers import embedding_calls, tokenizer
    from policyops_contracts.embedding import EmbeddingJob

    configuration = Configuration()
    job = EmbeddingJob(purpose="ingest", subject_key="bytes", inputs=tuple(texts))
    prepared_job = embedding_calls.prepare_job(job, configuration, tokenizer.load(), deadline=1e12)
    assert sum(i.local_tokens for i in prepared_job.inputs) < 8192  # the byte limit, not tokens, decides
    plans = embedding_calls.pack(prepared_job, configuration)(uuid4(), frozenset())
    assert [len(plan.positions) for plan in plans] == sizes
    for plan in plans:
        batch = [texts[p] for p in plan.positions]
        assert sum(len(t.encode("utf-8")) for t in batch) <= emb.MAX_REQUEST_BYTES
        assert emb.prepare(batch, configuration).request_sha256 == plan.request_sha256  # a legal request
    assert [p for plan in plans for p in plan.positions] == list(range(len(texts)))  # order kept


# -- DTOs --------------------------------------------------------------------------------------------------------------

def test_job_bounds() -> None:
    assert EmbeddingJob(purpose="ingest", subject_key="g-1", inputs=("a", "b")).inputs == ("a", "b")
    for bad in ({"purpose": "Bad"}, {"subject_key": ""}, {"inputs": ("",)}, {"inputs": ("a\x00",)},
                {"inputs": ("\ud800",)}, {"inputs": ("€" * 21_846,)}, {"inputs": ("x",) * 10_001},
                {"input_format": "other"}):
        with pytest.raises(ValidationError):
            EmbeddingJob.model_validate({"purpose": "ingest", "subject_key": "g-1", "inputs": ("a",)} | bad)


@pytest.mark.parametrize("value", [True, "0.1", float("nan"), float("inf")])
def test_a_vector_is_exactly_1536_strict_finite_floats(value: Any) -> None:
    good = {"position": 0, "input_sha256": "a" * 64, "vector": tuple(vector())}
    assert len(EmbeddedInput.model_validate(good).vector) == 1536
    for bad in (tuple(vector())[:1535], (*vector(), 0.1), (value, *vector()[1:])):
        with pytest.raises(ValidationError):
            EmbeddedInput.model_validate(good | {"vector": bad})
