"""One physical count or inference attempt through the official async SDKs (T11). No retries, ledger or deadline
here: `calls.py` owns those.

`count` returns the provider's counted input tokens for the prepared count projection, or raises `CountFailed`.

`invoke` returns an `Invocation`:
- the parsed result and usage evidence, when a final response arrived;
- otherwise the failure class (HTTP status, Retry-After, a timeout, a cut stream, a transport refusal), plus whether
  the request may have been sent.

Non-streaming responses are read as **raw JSON** (`with_raw_response`) and parsed strictly with exact decimals.

**Streaming:**
- OpenAI: the terminal `response.completed` / `response.incomplete` / `response.failed` event carries the full
  response. An `error` event, or no terminal event, means no final evidence.
- Anthropic: the result is accumulated from the raw events. `message_delta` usage is **cumulative**: the last value
  of each field is kept, never summed. Tool input comes from the `input_json_delta` text, parsed exactly at the end.
  An `error` event after HTTP 200 means no final evidence.
- Deltas only accumulate; nothing is a result before the terminal event. Event count, text and tool-argument size
  are bounded, and every stream is closed on exit, including cancellation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import anthropic
import httpx2
import openai
from pydantic import SecretStr, ValidationError

from policyops.budget.ledger import Diagnostic
from policyops.providers.canonical import CanonicalError, strict_loads
from policyops.providers.contract import require_clean_environment
from policyops.providers.results import (
    UNKNOWN,
    Evidence,
    anthropic_evidence,
    anthropic_result,
    openai_evidence,
    openai_result,
)
from policyops.providers.serialize import PreparedRequest
from policyops.providers.transport import (
    TIMEOUT,
    BoundedTransport,
    Expected,
    ResponseTooLarge,
    TransportRefused,
    bounded_close,
    http_client,
    sdk_client,
)
from policyops_contracts.model import ModelResult
from policyops_contracts.provider_failures import failure_code


MAX_EVENTS = 10_000
MAX_STREAM_TEXT = 256 << 10
MAX_STREAM_ARGUMENTS = 64 << 10
API_ERRORS = (openai.APIError, anthropic.APIError)


class CountFailed(RuntimeError):
    def __init__(self, code: str, cleanup_confirmed: bool = True) -> None:
        super().__init__(code)
        self.code = code
        self.cleanup_confirmed = cleanup_confirmed

    @property
    def failure_code(self) -> str | None:
        return failure_code(self.code)


@dataclass(frozen=True)
class Counted:
    tokens: int
    cleanup_confirmed: bool  # False if the client close did not finish within its bound


@dataclass
class Invocation:
    sent: bool
    result: ModelResult | None = None
    evidence: Evidence | None = None
    status: int | None = None
    retry_after: float | None = None
    error: str | None = None
    cleanup_confirmed: bool = True  # False if a stream or client close did not finish within its bound

    @property
    def failure_code(self) -> str | None:
        return failure_code(self.error or (self.result.reason_code if self.result else None))


@dataclass
class _Accumulated:
    message: dict[str, Any] = field(default_factory=dict)
    blocks: dict[int, dict[str, Any]] = field(default_factory=dict)
    arguments: dict[int, list[str]] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)
    text_bytes: int = 0
    argument_bytes: int = 0
    stop_reason: Any = None
    stopped: bool = False
    usage_inconsistent: bool = False


BILLING_COUNTERS = ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens")
SPLIT_COUNTERS = ("ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens")


def _strict_count(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 0 <= value < 2**31


def _observe(acc: _Accumulated, usage: Mapping[str, Any]) -> None:
    """Merge one cumulative usage observation. Every billing counter present must be a strict count and never
    decrease from an earlier observation; equal or growing values are fine (the last is the total). A decrease or a
    malformed counter marks the usage inconsistent: it is then unknown, never summed, maxed or resolved by
    picking one value."""
    for key in BILLING_COUNTERS:
        if key not in usage or usage[key] is None:
            continue
        value, earlier = usage[key], acc.usage.get(key)
        if not _strict_count(value) or (earlier is not None and (not _strict_count(earlier) or value < earlier)):
            acc.usage_inconsistent = True
        acc.usage[key] = value
    if "cache_creation" in usage and usage["cache_creation"] is not None:
        split, earlier_split = usage["cache_creation"], acc.usage.get("cache_creation")
        if not isinstance(split, dict):
            acc.usage_inconsistent = True
        else:
            for key in SPLIT_COUNTERS:
                value = split.get(key)
                before = earlier_split.get(key) if isinstance(earlier_split, dict) else None
                if value is None:
                    continue
                if not _strict_count(value) or (before is not None and (not _strict_count(before) or value < before)):
                    acc.usage_inconsistent = True  # sticky: a later valid value never clears it
        acc.usage["cache_creation"] = split
    for key, value in usage.items():  # the non-counter fields (tier, speed, geo): the latest observation
        if key not in BILLING_COUNTERS and key != "cache_creation" and value is not None:
            acc.usage[key] = value


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _retry_after(headers: Mapping[str, str] | httpx2.Headers | None) -> float | None:
    if headers is None:
        return None
    for name, divisor in (("retry-after-ms", 1000.0), ("retry-after", 1.0)):
        value = headers.get(name)
        if value is None:
            continue
        try:
            seconds = float(value) / divisor
        except ValueError:
            return None
        return seconds if 0 <= seconds <= 3600 else None
    return None


def _failure(transport: BoundedTransport, error: BaseException) -> Invocation:
    if isinstance(error, TransportRefused) or isinstance(error.__cause__, TransportRefused):
        return Invocation(sent=transport.sent, error=f"refused.{transport.refusal or 'unknown'}")
    if isinstance(error, ResponseTooLarge) or isinstance(error.__cause__, ResponseTooLarge):
        code = error.code if isinstance(error, ResponseTooLarge) else getattr(error.__cause__, "code", "too_large")
        return Invocation(sent=transport.sent, error=code)
    if isinstance(error, openai.APIStatusError | anthropic.APIStatusError):
        return Invocation(sent=transport.sent, status=error.status_code,
                          retry_after=_retry_after(error.response.headers), error=f"http_{error.status_code}")
    if isinstance(error, openai.APITimeoutError | anthropic.APITimeoutError):
        return Invocation(sent=transport.sent, error="timeout")
    if isinstance(error, openai.APIConnectionError | anthropic.APIConnectionError):
        return Invocation(sent=transport.sent, error="connection")
    return Invocation(sent=transport.sent, error="provider_error")


def _transport(prepared: PreparedRequest, inner: httpx2.AsyncBaseTransport, credential: SecretStr,
               *, count: bool) -> BoundedTransport:
    path = prepared.count_path if count else prepared.path
    return BoundedTransport(inner, Expected(prepared.provider, path,
                                            prepared.count_body if count else prepared.body), credential)


async def count(prepared: PreparedRequest, inner: httpx2.AsyncBaseTransport, credential: SecretStr,
                timeout: httpx2.Timeout = TIMEOUT) -> Counted:
    require_clean_environment(prepared.provider)  # before anything is allocated
    transport = _transport(prepared, inner, credential, count=True)
    http = http_client(transport, timeout)
    closed = [True]
    code: str | None
    try:
        client = sdk_client(prepared.provider, http, credential, timeout)
        if prepared.provider == "openai":
            raw = await client.responses.input_tokens.with_raw_response.count(**prepared.count_params())
        else:
            raw = await client.messages.with_raw_response.count_tokens(**prepared.count_params())
        data = strict_loads(raw.http_response.content)
    except CanonicalError:
        code = "count_not_json"
    except (*API_ERRORS, TransportRefused, ResponseTooLarge) as error:
        code = _failure(transport, error).error or "count_error"
    else:
        code = None
    finally:
        # The owned HTTP client, also when the SDK constructor failed.
        closed[0] = await bounded_close(http.aclose) and not transport.cleanup_unconfirmed
    if code is not None:
        raise CountFailed(code, closed[0])
    tokens = data.get("input_tokens") if isinstance(data, dict) else None
    if isinstance(tokens, bool) or not isinstance(tokens, int) or not 0 <= tokens < 2**31:
        raise CountFailed("count_malformed", closed[0])
    return Counted(tokens, closed[0])


RESULT_ERRORS = (ValidationError, ValueError, UnicodeError, TypeError, KeyError, AttributeError)


def _evidence(prepared: PreparedRequest, data: Mapping[str, Any], cache_mode: str,
              usage_inconsistent: bool = False) -> tuple[ModelResult, Evidence]:
    """The usage evidence first, then the result, each behind its own net. An evidence failure keeps the hold and
    blocks (`usage_malformed`, diagnostic `evidence_unparseable`); a result that cannot be represented becomes a
    payload-free `failed` and keeps the evidence, so a known bill still settles."""
    try:
        if prepared.provider == "openai":
            evidence = openai_evidence(data, prepared, cache_mode)
        else:
            evidence = anthropic_evidence(data, prepared, usage_inconsistent=usage_inconsistent)
    except (TypeError, KeyError, AttributeError, ValueError):
        evidence = Evidence(None, UNKNOWN, None, None, "usage_malformed",
                            Diagnostic(("usage_malformed", "evidence_unparseable")))
    try:
        result = (openai_result if prepared.provider == "openai" else anthropic_result)(data, prepared, evidence)
    except RESULT_ERRORS:
        result = ModelResult(outcome="failed", provider=prepared.provider, requested_model=prepared.model,
                             returned_model=evidence.returned_model, provider_request_id=evidence.provider_request_id,
                             reason_code="result_unrepresentable", usage=evidence.reported)
    if evidence.block is not None:
        result = as_contract_gap(result, evidence.block)
    return result, evidence


def as_contract_gap(result: ModelResult, code: str) -> ModelResult:
    """The request contract was broken (or the bill cannot be priced): the usage is still accounted for, but no text,
    tool call or structured payload is handed on, and progress stops."""
    return ModelResult(outcome="contract_gap", provider=result.provider, requested_model=result.requested_model,
                       returned_model=result.returned_model, provider_request_id=result.provider_request_id,
                       reason_code=code, stop_reason=result.stop_reason, usage=result.usage)


async def _openai_stream(stream: Any) -> dict[str, Any] | None:
    events = 0
    async for event in stream:
        events += 1
        if events > MAX_EVENTS:
            raise ResponseTooLarge("too_many_events")
        data = event.to_dict(warnings=False)  # no serializer warning (it would echo provider values)
        kind = data.get("type")
        if kind in ("response.completed", "response.incomplete", "response.failed"):
            response = data.get("response")
            return response if isinstance(response, dict) else None
        if kind == "error":
            return None
    return None


def _anthropic_event(acc: _Accumulated, data: Mapping[str, Any]) -> None:
    kind = data.get("type")
    if kind == "message_start" and isinstance(data.get("message"), dict):
        acc.message = dict(data["message"])
        start = acc.message.get("usage")
        if start is not None and not isinstance(start, dict):
            acc.usage_inconsistent = True
        else:
            _observe(acc, start or {})
    elif kind == "content_block_start" and isinstance(data.get("index"), int):
        block = data.get("content_block")
        acc.blocks[data["index"]] = dict(block) if isinstance(block, dict) else {"type": "unknown"}
    elif kind == "content_block_delta" and isinstance(data.get("index"), int):
        delta = _object(data.get("delta"))
        block = acc.blocks.setdefault(data["index"], {"type": "unknown"})
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            acc.text_bytes += len(delta["text"].encode())
            if acc.text_bytes > MAX_STREAM_TEXT:
                raise ResponseTooLarge("text_too_large")
            block["text"] = block.get("text", "") + delta["text"]
        elif delta.get("type") == "input_json_delta" and isinstance(delta.get("partial_json"), str):
            acc.argument_bytes += len(delta["partial_json"].encode())
            if acc.argument_bytes > MAX_STREAM_ARGUMENTS:
                raise ResponseTooLarge("tool_arguments_too_large")
            acc.arguments.setdefault(data["index"], []).append(delta["partial_json"])
        elif delta.get("type") in ("thinking_delta", "signature_delta"):
            block["type"] = "thinking"  # a contract gap; its content is not kept
    elif kind == "message_delta":
        delta = _object(data.get("delta"))
        if "stop_reason" in delta:
            acc.stop_reason = delta["stop_reason"]
        raw = data.get("usage")
        if raw is not None and not isinstance(raw, dict):
            acc.usage_inconsistent = True
        else:
            _observe(acc, raw or {})  # cumulative: checked, never summed
    elif kind == "message_stop":
        acc.stopped = True


async def _anthropic_stream(stream: Any) -> tuple[dict[str, Any] | None, bool]:
    acc = _Accumulated()
    events = 0
    async for event in stream:
        events += 1
        if events > MAX_EVENTS:
            raise ResponseTooLarge("too_many_events")
        data = event.to_dict(warnings=False)  # no serializer warning (it would echo provider values)
        if data.get("type") == "error":
            return None, acc.usage_inconsistent
        try:
            _anthropic_event(acc, data)
        except (TypeError, ValueError, KeyError, AttributeError):
            acc.usage_inconsistent = True  # an event we cannot read safely: the usage is unknown, never a guess
        if acc.stopped:
            break
    if not acc.stopped or not acc.message:
        return None, acc.usage_inconsistent
    content = []
    for index in sorted(acc.blocks):
        block = dict(acc.blocks[index])
        block.pop("text", None) if block.get("type") == "thinking" else None
        if block.get("type") == "tool_use":
            text = "".join(acc.arguments.get(index, [])) or "{}"
            try:
                block["input"] = strict_loads(text)
            except CanonicalError:
                block["input"] = None  # malformed tool input: an invalid output, never a guess
        content.append(block)
    message = dict(acc.message)
    message.update(content=content, stop_reason=acc.stop_reason, usage=acc.usage)
    return message, acc.usage_inconsistent


async def invoke(prepared: PreparedRequest, inner: httpx2.AsyncBaseTransport, credential: SecretStr, *,
                 cache_mode: str, timeout: httpx2.Timeout = TIMEOUT) -> Invocation:
    require_clean_environment(prepared.provider)  # before anything is allocated
    transport = _transport(prepared, inner, credential, count=False)
    http = http_client(transport, timeout)
    stream_closed = True
    try:
        outcome = await _send(prepared, transport, http, credential, timeout, cache_mode)
        stream_closed = outcome.cleanup_confirmed
    finally:
        http_closed = await bounded_close(http.aclose)  # also when the SDK constructor failed
    outcome.cleanup_confirmed = stream_closed and http_closed and not transport.cleanup_unconfirmed
    return outcome


async def _send(prepared: PreparedRequest, transport: BoundedTransport, http: httpx2.AsyncClient,
                credential: SecretStr, timeout: httpx2.Timeout, cache_mode: str) -> Invocation:
    closed = True
    inconsistent = False
    try:
        client = sdk_client(prepared.provider, http, credential, timeout)
        resource = client.responses if prepared.provider == "openai" else client.messages
        if not prepared.stream:
            raw = await resource.with_raw_response.create(**prepared.params())
            data = strict_loads(raw.http_response.content)
        else:
            stream = await resource.create(**prepared.params())
            try:
                if prepared.provider == "openai":
                    data = await _openai_stream(stream)
                else:
                    data, inconsistent = await _anthropic_stream(stream)
            finally:
                closed = await bounded_close(stream.close)
            if data is None:
                return Invocation(sent=transport.sent, error="stream_without_final_response", cleanup_confirmed=closed)
    except CanonicalError:
        return Invocation(sent=transport.sent, error="response_not_json", cleanup_confirmed=closed)
    except (*API_ERRORS, TransportRefused, ResponseTooLarge) as error:
        failure = _failure(transport, error)
        failure.cleanup_confirmed = closed
        return failure
    if not isinstance(data, dict):
        return Invocation(sent=transport.sent, error="response_not_object", cleanup_confirmed=closed)
    result, evidence = _evidence(prepared, data, cache_mode, inconsistent)
    return Invocation(sent=transport.sent, result=result, evidence=evidence, cleanup_confirmed=closed)
