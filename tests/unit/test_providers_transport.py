"""T11 adapters over the real SDK clients (openai 3.40.0, anthropic 2.3.0) and a scripted `httpx2` mock transport:
the exact bytes that would leave, the single permitted request, header and credential checks, bounded responses,
streaming terminal handling, and cancellation cleanup. No network, no real key, no provider account.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
import gzip
import json
import time
from typing import Any

import httpx2
import openai
from pydantic import SecretStr
import pytest

from policyops.budget.config import Configuration
from policyops.providers.adapters import CountFailed, count, invoke
from policyops.providers.canonical import canonical_bytes, fresh, strict_loads
from policyops.providers.contract import ContractGap
from policyops.providers.serialize import PreparedRequest, prepare
from policyops.providers.tools import retail_tool_spec
from policyops.providers.transport import BoundedTransport, Expected, TransportRefused
from policyops_contracts.model import Message, ModelRequest, OutputSpec, TextPart
from policyops_contracts.retail import ReturnDeliveredOrderItems


KEY = SecretStr("synthetic-test-credential-0000")
RETURN = retail_tool_spec(ReturnDeliveredOrderItems, "Return delivered items.")
ANSWER = json.dumps({"type": "object", "properties": {"decision": {"type": "string", "enum": ["approve", "deny"]}},
                     "required": ["decision"], "additionalProperties": False})


def prepared(actor: str = "agent", **changes: Any) -> PreparedRequest:
    body: dict[str, Any] = {"instructions": "Follow the retail policy.",
                            "messages": (Message(role="user", parts=(TextPart(text="Return #W0000001."),)),),
                            "tools": (RETURN,), "max_output_tokens": 256} | changes
    return prepare(ModelRequest(**body), Configuration(), actor)


class Chunks(httpx2.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, delay: float = 0.0, forever: bytes | None = None) -> None:
        self.chunks, self.delay, self.forever = chunks, delay, forever
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk
        while self.forever is not None:
            await asyncio.sleep(self.delay)
            yield self.forever

    async def aclose(self) -> None:
        self.closed = True


class Script(httpx2.AsyncBaseTransport):
    """Answers each request with the next scripted response and records what arrived."""

    def __init__(self, *responses: Callable[[httpx2.Request], httpx2.Response]) -> None:
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []
        self.bodies: list[bytes] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        self.bodies.append(await request.aread())
        assert self.responses, "an unscripted request reached the transport"
        return self.responses.pop(0)(request)


def reply(data: Any, status: int = 200, **headers: str) -> Callable[[httpx2.Request], httpx2.Response]:
    body = json.dumps(data).encode()
    return lambda request: httpx2.Response(status, headers={"content-type": "application/json", **headers},
                                           stream=Chunks([body]), request=request)


def sse(events: list[tuple[str, dict[str, Any]]], stream: Chunks | None = None
        ) -> Callable[[httpx2.Request], httpx2.Response]:
    text = "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()
    chunks = stream or Chunks([text])
    return lambda request: httpx2.Response(200, headers={"content-type": "text/event-stream"}, stream=chunks,
                                           request=request)


USAGE = {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
         "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8}, "total_tokens": 940}


def openai_response(output: list[dict[str, Any]], **changes: Any) -> dict[str, Any]:
    return {"id": "resp_1", "object": "response", "model": "gpt-6-luna", "status": "completed",
            "service_tier": "default", "output": output, "usage": USAGE} | changes


def anthropic_message(content: list[dict[str, Any]], **changes: Any) -> dict[str, Any]:
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-5-5", "content": content,
            "stop_reason": "end_turn", "usage": {"input_tokens": 700, "cache_read_input_tokens": 0,
                                                 "cache_creation_input_tokens": 0, "output_tokens": 30,
                                                 "service_tier": "standard"}} | changes


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def wire_headers(request: httpx2.Request) -> set[str]:
    return {name.lower() for name in request.headers}


# -- the exact request -------------------------------------------------------------------------------------------

def test_openai_sends_exactly_the_prepared_request_once() -> None:
    p = prepared(output=OutputSpec(name="answer", answer_schema_json=ANSWER), tools=())
    script = Script(reply(openai_response([{"type": "message", "role": "assistant", "content": [
        {"type": "output_text", "text": '{"decision": "approve"}', "annotations": []}]}])))
    invocation = run(invoke(p, script, KEY, cache_mode="none"))
    (request,) = script.requests
    assert (request.method, request.url.host, request.url.path) == ("POST", "api.openai.com", "/v1/responses")
    assert canonical_bytes(strict_loads(script.bodies[0])) == p.body
    assert request.headers["accept-encoding"] == "identity"
    assert not {name for name in wire_headers(request) if name.startswith("openai-")}
    assert invocation.result.outcome == "structured" and invocation.result.structured_json == '{"decision":"approve"}'
    assert invocation.evidence.usage is not None and invocation.sent


def test_anthropic_sends_the_pinned_version_and_returns_a_validated_tool_call() -> None:
    p = prepared("judge")
    arguments = {"order_id": "#W0000001", "item_ids": ["1000000001"], "payment_method_id": "credit_card_0000001"}
    script = Script(reply(anthropic_message([{"type": "tool_use", "id": "toolu_1", "name": RETURN.name,
                                              "input": arguments}], stop_reason="tool_use")))
    invocation = run(invoke(p, script, KEY, cache_mode="none"))
    (request,) = script.requests
    assert request.url.path == "/v1/messages" and request.headers["anthropic-version"] == "2026-10-21"
    assert "x-api-key" not in wire_headers(request)  # anthropic 2.3.0 sends a bearer credential
    assert request.headers["authorization"] == f"Bearer {KEY.get_secret_value()}"
    assert canonical_bytes(strict_loads(script.bodies[0])) == p.body
    result = invocation.result
    assert result.outcome == "completed" and len(result.tool_calls) == 1
    assert json.loads(result.tool_calls[0].arguments_json) == arguments


def test_counts_send_the_complete_projection_and_return_the_counted_tokens() -> None:
    for actor, path, payload in (("agent", "/v1/responses/input_tokens",
                                  {"object": "response.input_tokens", "input_tokens": 1234}),
                                 ("judge", "/v1/messages/count_tokens", {"input_tokens": 987})):
        p = prepared(actor)
        script = Script(reply(payload))
        counted = run(count(p, script, KEY))
        assert (counted.tokens, counted.cleanup_confirmed) == (payload["input_tokens"], True)
        assert script.requests[0].url.path == path
        assert canonical_bytes(strict_loads(script.bodies[0])) == p.count_body
        assert set(fresh(p.count_body)) >= {"tools", "model"}
    with pytest.raises(CountFailed, match="count_malformed"):
        run(count(prepared(), Script(reply({"input_tokens": True})), KEY))
    with pytest.raises(CountFailed, match="http_500"):
        run(count(prepared(), Script(reply({"error": {}}, status=500)), KEY))


# -- the boundary refuses -----------------------------------------------------------------------------------------

def client_over(transport: BoundedTransport, **options: Any) -> openai.AsyncOpenAI:
    return openai.AsyncOpenAI(api_key=KEY.get_secret_value(), base_url="https://api.openai.com/v1", max_retries=0,
                              http_client=httpx2.AsyncClient(transport=transport, trust_env=False), **options)


def guarded(p: PreparedRequest, inner: Script, credential: SecretStr = KEY) -> BoundedTransport:
    return BoundedTransport(inner, Expected("openai", p.path, p.body), credential)


@pytest.mark.parametrize(("options", "code"), [
    ({"default_headers": {"X-Injected": "canary"}}, "header_not_allowed"),
    ({"default_headers": {"traceparent": "00-canary"}}, "header_not_allowed"),
    ({"organization": "org-canary"}, "header_not_allowed"),
])
def test_ambient_headers_never_reach_the_wire(options: dict[str, Any], code: str) -> None:
    p = prepared()
    inner = Script()
    transport = guarded(p, inner)
    with pytest.raises((TransportRefused, openai.APIConnectionError)):
        run(client_over(transport, **options).responses.create(**p.params()))
    assert transport.refusal == code and inner.requests == [] and not transport.sent


def test_a_changed_body_a_wrong_credential_or_a_second_request_is_refused() -> None:
    p, other = prepared(), prepared(max_output_tokens=255)
    for transport, params, code in ((guarded(p, Script()), other.params(), "body_mismatch"),
                                    (guarded(p, Script(), SecretStr("synthetic-other-credential-0000")), p.params(),
                                     "credential_mismatch")):
        with pytest.raises((TransportRefused, openai.APIConnectionError)):
            run(client_over(transport).responses.create(**params))
        assert transport.refusal == code and transport.inner.requests == []  # type: ignore[attr-defined]
    inner = Script(reply(openai_response([])))
    transport = guarded(p, inner)

    async def twice() -> None:
        client = client_over(transport)
        await client.responses.with_raw_response.create(**p.params())
        with pytest.raises((TransportRefused, openai.APIConnectionError)):
            await client.responses.with_raw_response.create(**p.params())

    run(twice())
    assert len(inner.requests) == 1 and transport.refusal == "second_request"


def test_disallowed_ambient_sdk_settings_refuse_before_any_request(monkeypatch: pytest.MonkeyPatch) -> None:
    inner = Script()
    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", "X-Canary: 1")
    with pytest.raises(ContractGap, match="OPENAI_CUSTOM_HEADERS"):
        run(invoke(prepared(), inner, KEY, cache_mode="none"))
    monkeypatch.delenv("OPENAI_CUSTOM_HEADERS")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "canary")
    with pytest.raises(ContractGap, match="ANTHROPIC_AUTH_TOKEN"):
        run(invoke(prepared("judge"), inner, KEY, cache_mode="none"))
    assert inner.requests == []


@pytest.mark.parametrize(("make", "code"), [
    (lambda r: httpx2.Response(200, headers={"content-encoding": "gzip", "content-type": "application/json"},
                               stream=Chunks([gzip.compress(b"{" + b" " * 2_097_150 + b"}")]), request=r),
     "content_encoding"),
    (lambda r: httpx2.Response(200, headers={"content-type": "application/json"},
                               stream=Chunks([b"A" * 65_537 + b"\nx\n"]), request=r), "line_too_long"),
    (lambda r: httpx2.Response(200, headers={"content-type": "application/json"},
                               stream=Chunks([(b" " * 60_000 + b"\n") * 20]), request=r), "response_too_large"),
])
def test_responses_are_bounded_by_their_decoded_bytes_and_every_line(make: Any, code: str) -> None:
    invocation = run(invoke(prepared(), Script(make), KEY, cache_mode="none"))
    assert (invocation.result, invocation.error, invocation.sent) == (None, code, True)


def test_rate_limits_report_status_and_retry_after() -> None:
    invocation = run(invoke(prepared(), Script(reply({"error": {"type": "rate_limit"}}, 429, **{"retry-after": "2"})),
                            KEY, cache_mode="none"))
    assert (invocation.status, invocation.retry_after, invocation.result) == (429, 2.0, None)


# -- streaming ------------------------------------------------------------------------------------------------------

def test_openai_streams_end_only_at_the_terminal_event() -> None:
    p = prepared(stream=True, tools=())
    done = openai_response([{"type": "message", "role": "assistant",
                             "content": [{"type": "output_text", "text": "Hello.", "annotations": []}]}])
    events = [("response.created", {"type": "response.created", "sequence_number": 0,
                                    "response": done | {"status": "in_progress", "output": []}}),
              ("response.output_text.delta", {"type": "response.output_text.delta", "sequence_number": 1,
                                              "item_id": "m", "output_index": 0, "content_index": 0,
                                              "delta": "Hel", "logprobs": []})]
    stream = Chunks([])
    cut = run(invoke(p, Script(sse(events, None)), KEY, cache_mode="none"))
    assert (cut.result, cut.evidence, cut.error) == (None, None, "stream_without_final_response")
    finished = [*events, ("response.completed", {"type": "response.completed", "sequence_number": 2,
                                                 "response": done})]
    invocation = run(invoke(p, Script(sse(finished)), KEY, cache_mode="none"))
    assert invocation.result.outcome == "completed" and invocation.result.text == "Hello."
    del stream


def anthropic_events(*outputs: int, error_after: bool = False) -> list[tuple[str, dict[str, Any]]]:
    start = anthropic_message([], stop_reason=None) | {"usage": {"input_tokens": 700, "cache_read_input_tokens": 0,
                                                                 "cache_creation_input_tokens": 0, "output_tokens": 1,
                                                                 "service_tier": "standard"}}
    events: list[tuple[str, dict[str, Any]]] = [
        ("message_start", {"type": "message_start", "message": start}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": "Done."}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0})]
    for output in outputs:
        events.append(("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                                         "usage": {"output_tokens": output}}))
    if error_after:
        events.append(("error", {"type": "error", "error": {"type": "overloaded_error", "message": "x"}}))
    else:
        events.append(("message_stop", {"type": "message_stop"}))
    return events


def test_anthropic_stream_usage_is_cumulative_and_a_late_error_leaves_no_evidence() -> None:
    p = prepared("judge", stream=True, tools=())
    invocation = run(invoke(p, Script(sse(anthropic_events(30, 80, 120))), KEY, cache_mode="none"))
    assert invocation.result.text == "Done."
    assert invocation.evidence.usage.output == 120 and invocation.evidence.usage.input_total == 700  # never 230
    late = run(invoke(p, Script(sse(anthropic_events(30, error_after=True))), KEY, cache_mode="none"))
    assert late.result is None and late.evidence is None


def test_a_trickling_stream_is_cut_by_the_absolute_deadline_and_closed() -> None:
    p = prepared(stream=True, tools=())
    stream = Chunks([b"event: response.created\ndata: "], delay=0.01, forever=b"x")

    async def bounded() -> float:
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            async with asyncio.timeout_at(started + 0.5):
                await invoke(p, Script(sse([], stream)), KEY, cache_mode="none")
        return time.monotonic() - started

    elapsed = run(bounded())
    assert elapsed < 3.0 and stream.closed


@pytest.mark.parametrize(("headers", "code"), [
    ({"host": "evil.example"}, "host_mismatch"),
    ({"content-type": "text/plain"}, "content_type_mismatch"),
    ({"content-length": "1"}, "content_length_mismatch"),
])
def test_authority_and_framing_are_fixed_before_the_inner_transport(headers: dict[str, str], code: str) -> None:
    p = prepared()
    inner = Script()
    transport = guarded(p, inner)
    base = {"host": "api.openai.com", "content-type": "application/json", "content-length": str(len(p.body)),
            "authorization": f"Bearer {KEY.get_secret_value()}"}

    async def send() -> None:
        async with httpx2.AsyncClient(transport=transport, trust_env=False) as client:
            await client.post("https://api.openai.com/v1/responses", content=p.body, headers=base | headers)

    with pytest.raises(TransportRefused, match=code):
        run(send())
    assert inner.requests == [] and not transport.sent


def test_a_duplicated_header_is_refused_before_the_inner_transport() -> None:
    p = prepared()
    inner = Script()
    transport = guarded(p, inner)
    raw = [(b"host", b"api.openai.com"), (b"content-type", b"application/json"),
           (b"content-length", str(len(p.body)).encode()),
           (b"authorization", f"Bearer {KEY.get_secret_value()}".encode()),
           (b"authorization", f"Bearer {KEY.get_secret_value()}".encode())]
    request = httpx2.Request("POST", "https://api.openai.com/v1/responses", headers=raw, content=p.body)
    with pytest.raises(TransportRefused, match="duplicate_header"):
        run(transport.handle_async_request(request))
    assert inner.requests == []


class Tracked(Script):
    def __init__(self, *responses: Callable[[httpx2.Request], httpx2.Response]) -> None:
        super().__init__(*responses)
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def test_an_sdk_constructor_failure_still_closes_the_owned_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("constructor failed")

    monkeypatch.setattr(openai, "AsyncOpenAI", broken)
    inner = Tracked()
    with pytest.raises(RuntimeError, match="constructor failed"):
        run(invoke(prepared(), inner, KEY, cache_mode="none"))
    assert inner.closed and inner.requests == []  # closed through the owned httpx2 client
    counted = Tracked()
    with pytest.raises(RuntimeError, match="constructor failed"):
        run(count(prepared(), counted, KEY))
    assert counted.closed


class HangingClose(Chunks):
    async def aclose(self) -> None:
        await asyncio.sleep(3600)


def test_a_hanging_stream_close_is_bounded_and_reported_unconfirmed() -> None:
    p = prepared(stream=True, tools=())
    done = openai_response([{"type": "message", "role": "assistant",
                             "content": [{"type": "output_text", "text": "Hello.", "annotations": []}]}])
    event = {"type": "response.completed", "sequence_number": 0, "response": done}
    text = f"event: response.completed\ndata: {json.dumps(event)}\n\n"
    stream = HangingClose([text.encode()])
    started = time.monotonic()
    invocation = run(invoke(p, Script(sse([], stream)), KEY, cache_mode="none"))
    assert time.monotonic() - started < 10
    assert invocation.result.outcome == "completed"  # the primary outcome is kept ...
    assert invocation.cleanup_confirmed is False  # ... and the cleanup is not claimed


def test_a_hanging_close_cannot_hold_a_deadline_cancellation_forever() -> None:
    p = prepared(stream=True, tools=())
    stream = HangingClose([b"event: response.created\ndata: "], delay=0.01, forever=b"x")

    async def bounded() -> float:
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            async with asyncio.timeout_at(started + 0.3):
                await invoke(p, Script(sse([], stream)), KEY, cache_mode="none")
        return time.monotonic() - started

    assert run(bounded()) < 10  # the deadline, plus at most two bounded close steps


# -- C2: evidence survives unrepresentable results (F1), consistent totals (F2), linear regex (F3) ---------------

KNOWN_USAGE = dict(USAGE)


def pretty(data: Any) -> Callable[[httpx2.Request], httpx2.Response]:
    """Indented JSON: each value on its own line, so long text stays within the per-line bound."""
    body = json.dumps(data, indent=1).encode()
    return lambda request: httpx2.Response(200, headers={"content-type": "application/json"},
                                           stream=Chunks([body]), request=request)


def text_output(*texts: str) -> list[dict[str, Any]]:
    return [{"type": "message", "role": "assistant",
             "content": [{"type": "output_text", "text": text, "annotations": []} for text in texts]}]


NOTE = json.dumps({"type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"],
                   "additionalProperties": False})


@pytest.mark.parametrize(("case", "build", "outcome", "code", "known"), [
    ("control", lambda: openai_response(text_output("Hello.")), "completed", None, True),
    ("overlong_unconfirmed_model", lambda: openai_response(text_output("Hello."), model="m" * 300),
     "contract_gap", "model_unconfirmed", False),
    ("overlong_stop_reason", lambda: openai_response([], status="incomplete",
                                                     incomplete_details={"reason": "r" * 300}),
     "truncated", "stop_reason_unrecognised", True),
    ("unpaired_surrogate", lambda: openai_response(text_output("bad \ud800 text")), "invalid_output",
     "text_not_unicode", True),
])
def test_an_unrepresentable_result_never_loses_its_evidence(case: str, build: Any, outcome: str, code: str | None,
                                                            known: bool) -> None:
    invocation = run(invoke(prepared(tools=()), Script(reply(build())), KEY, cache_mode="none"))
    assert invocation.result is not None and invocation.evidence is not None, case
    assert (invocation.result.outcome, invocation.result.reason_code) == (outcome, code), case
    assert (invocation.evidence.usage is not None) is known, case
    assert invocation.result.text in (None, "Hello.") and not invocation.result.tool_calls


def test_an_oversized_structured_answer_is_invalid_with_its_bill_known() -> None:
    p = prepared(output=OutputSpec(name="note", answer_schema_json=NOTE), tools=())
    pieces = ['{"note": "' + "x" * 30_000, "x" * 30_000, "x" * 10_000 + '"}']
    invocation = run(invoke(p, Script(pretty(openai_response(text_output(*pieces)))), KEY, cache_mode="none"))
    assert (invocation.result.outcome, invocation.result.reason_code) == ("invalid_output", "structured_too_large")
    assert invocation.evidence.usage is not None and invocation.result.structured_json is None


@pytest.mark.parametrize(("total", "code"), [(99_999, "usage_inconsistent"), (None, "usage_malformed"),
                                             (True, "usage_malformed")])
def test_openai_totals_must_be_consistent(total: Any, code: str) -> None:
    usage = {"input_tokens": 100, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "output_tokens": 10, "output_tokens_details": {"reasoning_tokens": 0}}
    if total is not None:
        usage["total_tokens"] = total
    invocation = run(invoke(prepared(tools=()), Script(reply(openai_response(text_output("Hi."), usage=usage))),
                            KEY, cache_mode="none"))
    assert invocation.evidence.usage is None and invocation.evidence.block == code
    assert invocation.result.outcome == "contract_gap" and invocation.result.text is None


def test_a_backtracking_pattern_cannot_stall_the_deadline() -> None:
    hostile = json.dumps({"type": "object", "properties": {"a": {"type": "string", "pattern": "^(a+)+$",
                                                                  "maxLength": 64}},
                          "required": ["a"], "additionalProperties": False})
    p = prepared(output=OutputSpec(name="answer", answer_schema_json=hostile), tools=())

    async def bounded() -> tuple[Any, float]:
        started = time.monotonic()
        async with asyncio.timeout(5):
            invocation = await invoke(p, Script(reply(openai_response(text_output(json.dumps({"a": "a" * 32 + "!"}))))),
                                      KEY, cache_mode="none")
        return invocation, time.monotonic() - started

    invocation, elapsed = run(bounded())
    assert elapsed < 2 and invocation.result.reason_code == "output_schema"  # matched in linear time, refused
    benign = run(invoke(p, Script(reply(openai_response(text_output('{"a": "aaaa"}')))), KEY, cache_mode="none"))
    assert benign.result.outcome == "structured"



# -- C3: malformed containers keep their evidence (F1), cumulative stream counters (F4) --------------------------

@pytest.mark.parametrize(("actor", "build"), [
    ("agent", lambda: openai_response([]) | {"output": 1}),
    ("agent", lambda: openai_response([{"type": "message", "role": "assistant", "content": 1}])),
    ("judge", lambda: anthropic_message([]) | {"content": 1}),
    ("judge", lambda: anthropic_message([]) | {"content": [1]}),
])
def test_a_malformed_container_is_a_payload_free_failure_with_its_bill_known(actor: str, build: Any) -> None:
    invocation = run(invoke(prepared(actor, tools=()), Script(reply(build())), KEY, cache_mode="none"))
    assert invocation.result is not None and invocation.evidence is not None
    assert (invocation.result.outcome, invocation.result.reason_code) == ("failed", "response_malformed")
    assert invocation.result.text is None and not invocation.result.tool_calls
    assert invocation.evidence.usage is not None and invocation.evidence.block is None  # the exact bill settles


def test_a_malformed_container_with_an_unconfirmed_model_still_blocks() -> None:
    invocation = run(invoke(prepared(tools=()), Script(reply(openai_response([], model="other") | {"output": 1})), KEY,
                            cache_mode="none"))
    assert invocation.evidence.usage is None and invocation.evidence.block == "model_unconfirmed"
    assert invocation.result.outcome == "contract_gap"


def anthropic_stream_events(*deltas: dict[str, Any], start_output: int = 1) -> list[tuple[str, dict[str, Any]]]:
    start = anthropic_message([], stop_reason=None) | {"usage": {"input_tokens": 700, "cache_read_input_tokens": 0,
                                                                 "cache_creation_input_tokens": 0,
                                                                 "output_tokens": start_output,
                                                                 "service_tier": "standard"}}
    events: list[tuple[str, dict[str, Any]]] = [
        ("message_start", {"type": "message_start", "message": start}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": "Done."}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0})]
    events += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": usage})
               for usage in deltas]
    events.append(("message_stop", {"type": "message_stop"}))
    return events


@pytest.mark.parametrize(("deltas", "output"), [
    (({"output_tokens": 30}, {"output_tokens": 80}, {"output_tokens": 120}), 120),  # increasing
    (({"output_tokens": 120}, {"output_tokens": 120}), 120),  # equal
    (({"output_tokens": 120, "input_tokens": 700},), 120),  # an unchanged input counter repeated
])
def test_consistent_cumulative_stream_usage_is_exact(deltas: tuple[dict[str, Any], ...], output: int) -> None:
    p = prepared("judge", stream=True, tools=())
    invocation = run(invoke(p, Script(sse(anthropic_stream_events(*deltas))), KEY, cache_mode="none"))
    assert invocation.evidence.usage is not None and invocation.evidence.usage.output == output
    assert invocation.result.outcome == "completed"


@pytest.mark.parametrize("deltas", [
    ({"output_tokens": 120}, {"output_tokens": 30}),  # decreasing: never resolved by taking the last value
    ({"output_tokens": 30}, {"output_tokens": True}),  # malformed
    ({"output_tokens": 30, "input_tokens": 600},),  # an input counter going down
    ({"output_tokens": 30, "cache_creation": 5},),  # a malformed split
])
def test_contradictory_cumulative_stream_usage_is_unknown_and_blocked(deltas: tuple[dict[str, Any], ...]) -> None:
    p = prepared("judge", stream=True, tools=())
    invocation = run(invoke(p, Script(sse(anthropic_stream_events(*deltas))), KEY, cache_mode="none"))
    assert invocation.evidence.usage is None and invocation.evidence.block == "usage_inconsistent"
    assert invocation.result.outcome == "contract_gap" and invocation.result.text is None



# -- C4: a malformed cache split stays inconsistent (sticky), never an exception ---------------------------------

def split_stream(start_split: Any, *delta_splits: Any) -> list[tuple[str, dict[str, Any]]]:
    events = anthropic_stream_events(*({"output_tokens": 30, "cache_creation": split} for split in delta_splits))
    events[0][1]["message"]["usage"]["cache_creation"] = start_split
    return events


@pytest.mark.parametrize(("start", "deltas"), [
    ({"ephemeral_5m_input_tokens": "bad", "ephemeral_1h_input_tokens": 0},
     ({"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0},)),  # malformed, then valid
    ({"ephemeral_5m_input_tokens": "bad", "ephemeral_1h_input_tokens": 0},
     ({"ephemeral_5m_input_tokens": "bad", "ephemeral_1h_input_tokens": 0},)),  # bad, then bad
    ({"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0},
     ({"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": True},)),  # valid, then a bool
])
def test_a_malformed_cumulative_split_is_inconsistent_and_sticky(start: Any, deltas: tuple[Any, ...]) -> None:
    p = prepared("judge", stream=True, tools=())
    invocation = run(invoke(p, Script(sse(split_stream(start, *deltas))), KEY, cache_mode="none"))
    assert invocation.evidence is not None and invocation.evidence.usage is None
    assert invocation.evidence.block == "usage_inconsistent" and invocation.result.outcome == "contract_gap"


def test_a_consistent_cumulative_split_stays_exact() -> None:
    zero = {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0}
    p = prepared("judge", stream=True, tools=())
    invocation = run(invoke(p, Script(sse(split_stream(zero, zero, zero))), KEY, cache_mode="none"))
    assert invocation.evidence.usage is not None and invocation.evidence.block is None
