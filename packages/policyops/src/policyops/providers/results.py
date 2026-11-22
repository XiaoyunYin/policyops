"""Provider responses → priced usage evidence and a provider-neutral result (T11). Pure: no I/O.

## Usage evidence

`*_evidence` decides what the ledger may do:
- **`usage` is set** only when every count is reported, consistent and fully priced (TTL attribution, the standard
  tier and the model are confirmed). Then the call settles, with the exact bill, whatever the result's outcome:
  a refused, truncated or invalid answer still costs what it cost.
- **A known contract mismatch with an exact price** sets `block` as well; the bill settles and progress stops. An
  example is OpenAI cache activity under cache `none`.
- **Missing or unpriceable evidence** leaves `usage` as None. The attempt stays unresolved with its hold, and
  nothing is invented.
  - Missing usage alone sets no block.
  - Malformed counts, an unknown TTL split, a non-standard tier, speed or geo, or an unconfirmed model set a block,
    with a small allowlisted `Diagnostic`.

Provider differences that matter:
- **OpenAI** `input_tokens` **includes** cached tokens; the reads and writes are its parts.
- **Anthropic** `input_tokens` **excludes** both the cache reads and the cache creation, so the whole prompt is
  their sum. The 5m/1h split must account for the creation total, which acts as its checksum.

## Results

The outcomes are `refused`, `truncated`, `failed`, `completed` (text or tool calls) and `structured` (a parsed object
that passed the full local domain schema). They also include `invalid_output` (bad JSON, unknown or duplicate tool
calls, or schema failures) and `contract_gap` (for example a thinking block despite `thinking: disabled`).
Text and arguments are bounded. Nothing here authorizes a tool.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any

from policyops.budget.ledger import Diagnostic
from policyops.budget.pricing import InvalidUsage, Usage
from policyops.providers.canonical import CanonicalError, output_bytes, strict_loads
from policyops.providers.contract import ALLOWED_INFERENCE_GEO, CONFIRMED_MODEL_IDS, EXPECTED_SERVICE_TIER
from policyops.providers.schema import CheckedSchema, validation_errors
from policyops.providers.serialize import PreparedRequest
from policyops.providers.tool_diagnostics import argument_issue
from policyops.providers.tools import refused_arguments
from policyops_contracts.model import ModelResult, Outcome, ReportedUsage, ToolCall
from policyops_contracts.tool_diagnostics import ToolArgumentIssue


MAX_TEXT = 262_144
MAX_ARGUMENTS = 65_536
MAX_TOOL_CALLS = 16
REQUEST_ID = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
SAFE_ID = re.compile(r"[\x21-\x7e]{1,200}")  # printable ASCII, bounded: kept for the record only, never confirmed
STOP_REASONS = frozenset({"completed", "max_output_tokens", "max_messages", "content_filter", "steered", "end_turn",
                          "max_tokens", "stop_sequence", "tool_use", "pause_turn", "refusal",
                          "model_context_window_exceeded"})
MAX_JSON = 65_536


@dataclass(frozen=True)
class Evidence:
    usage: Usage | None
    reported: ReportedUsage
    provider_request_id: str | None
    returned_model: str | None
    block: str | None = None
    diagnostic: Diagnostic | None = None


def _items(value: object) -> list[Any] | None:
    """A JSON array as a list; None for anything else (a number, a string, an object): never iterated blindly."""
    return value if isinstance(value, list) else None


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**31:
        return None
    return value


def _safe_model(value: object) -> str | None:
    return value if isinstance(value, str) and SAFE_ID.fullmatch(value) else None


def _unicode(text: str) -> bool:
    """False for text a JSON decoder accepted but that is not valid Unicode (an unpaired surrogate)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _request_id(value: object) -> str | None:
    return value if isinstance(value, str) and REQUEST_ID.fullmatch(value) else None


def _reported(usage: Usage) -> ReportedUsage:
    return ReportedUsage(state="known", input_total=usage.input_total, cache_read=usage.cache_read,
                         cache_writes=tuple(sorted(usage.cache_writes.items())),  # type: ignore[arg-type]
                         output=usage.output, reasoning=usage.reasoning)


UNKNOWN = ReportedUsage(state="unknown")


def _unpriced(rid: str | None, model: str | None, code: str, counts: Mapping[str, int | None]) -> Evidence:
    return Evidence(None, UNKNOWN, rid, model, code, Diagnostic((code,), counts))


def _model_confirmed(requested: str, returned: object) -> bool:
    # Only an explicitly confirmed returned ID is priced as the requested model (`contract.CONFIRMED_MODEL_IDS`).
    return isinstance(returned, str) and returned in CONFIRMED_MODEL_IDS.get(requested, frozenset())


def _limits(usage: Usage, prepared: PreparedRequest) -> str | None:
    """A known bill that exceeded the declared token limits: it settles exactly, then progress stops. The dollar hold
    alone would not catch it (an output of 129 for max 128 is far below a 2048-token reservation)."""
    if usage.input_total > prepared.max_input:
        return "input_limit_exceeded"
    if usage.output > prepared.max_output:
        return "output_limit_exceeded"
    return None


def openai_evidence(response: Mapping[str, Any], prepared: PreparedRequest, cache_mode: str) -> Evidence:
    rid = _request_id(response.get("id"))
    model = _safe_model(response.get("model"))
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return Evidence(None, UNKNOWN, rid, model)
    details, out_details = _object(usage.get("input_tokens_details")), _object(usage.get("output_tokens_details"))
    raw_split = details.get("cache_write_tokens_details")
    split = _object(raw_split)
    counts = {"input_tokens": _count(usage.get("input_tokens")), "cache_read": _count(details.get("cached_tokens")),
              "cache_creation": _count(details.get("cache_write_tokens")),
              "output": _count(usage.get("output_tokens")), "reasoning": _count(out_details.get("reasoning_tokens")),
              "total": _count(usage.get("total_tokens"))}
    if any(value is None for value in counts.values()):
        return _unpriced(rid, model, "usage_malformed", counts)
    if counts["total"] != (counts["input_tokens"] or 0) + (counts["output"] or 0):
        # Responses usage is inclusive: total = input + output. A contradiction is never resolved by guessing.
        return _unpriced(rid, model, "usage_inconsistent", counts)
    writes = counts["cache_creation"] or 0
    reads = counts["cache_read"] or 0
    input_total = counts["input_tokens"] or 0
    thirty, twelve = 0, 0
    if writes or raw_split is not None:
        counts["cache_creation_30m"] = _count(split.get("ttl_30m_tokens"))
        counts["cache_creation_12h"] = _count(split.get("ttl_12h_tokens"))
        if (short := counts["cache_creation_30m"]) is None or (long := counts["cache_creation_12h"]) is None:
            return _unpriced(rid, model, "cache_ttl_unknown", counts)
        if short + long != writes:
            return _unpriced(rid, model, "cache_split_mismatch", counts)
        thirty, twelve = short, long
    if reads + writes > input_total:
        return _unpriced(rid, model, "usage_inconsistent", counts)
    if response.get("service_tier") != EXPECTED_SERVICE_TIER["openai"]:
        return _unpriced(rid, model, "service_tier_unpriced", counts)
    if not _model_confirmed(prepared.model, response.get("model")):
        return _unpriced(rid, model, "model_unconfirmed", counts)
    try:
        priced = Usage(input_total, cache_read=reads,
                       cache_writes={ttl: n for ttl, n in (("30m", thirty), ("12h", twelve)) if n},
                       output=counts["output"] or 0,
                       reasoning=counts["reasoning"] or 0)
    except InvalidUsage:
        return _unpriced(rid, model, "usage_malformed", counts)
    block: str | None
    if cache_mode == "none" and (reads or writes):
        block = "cache_write_under_none" if writes else "cache_read_under_none"
    elif twelve and cache_mode != "12h":
        block = "cache_ttl_unrequested"
    else:
        block = _limits(priced, prepared)
    return Evidence(priced, _reported(priced), rid, model, block)


def anthropic_evidence(message: Mapping[str, Any], prepared: PreparedRequest, *,
                       usage_inconsistent: bool = False) -> Evidence:
    return _messages_evidence(message, prepared, usage_inconsistent=usage_inconsistent)


def bedrock_evidence(message: Mapping[str, Any], prepared: PreparedRequest) -> Evidence:
    """InvokeModel identity is the fixed endpoint; the request ID is supplied from the AWS response header.

    Cache fields may be omitted (zero); when present, every checksum and split must agree. No tier pin is inferred.
    """
    return _messages_evidence(message, prepared, bedrock=True)


def _messages_evidence(message: Mapping[str, Any], prepared: PreparedRequest, *,
                       usage_inconsistent: bool = False, bedrock: bool = False) -> Evidence:
    """`usage_inconsistent`: a streamed cumulative counter decreased or was malformed (`adapters`); the usage is then
    unknown and blocked, never resolved by picking one of the observed values."""
    rid = _request_id(message.get("_bedrock_request_id") if bedrock else message.get("id"))
    model = _safe_model(message.get("model", "anthropic.claude-haiku-5-5" if bedrock else None))
    usage = message.get("usage")
    if usage_inconsistent:
        return _unpriced(rid, model, "usage_inconsistent", {})
    if not isinstance(usage, dict):
        return Evidence(None, UNKNOWN, rid, model)
    if bedrock:
        usage = dict(usage)
        usage.setdefault("cache_read_input_tokens", 0)
        usage.setdefault("cache_creation_input_tokens", 0)
    split = _object(usage["cache_creation"]) if isinstance(usage.get("cache_creation"), dict) else None
    out_details = _object(usage.get("output_tokens_details"))
    counts: dict[str, int | None] = {
        "input_tokens": _count(usage.get("input_tokens")), "cache_read": _count(usage.get("cache_read_input_tokens")),
        "cache_creation": _count(usage.get("cache_creation_input_tokens")),
        "output": _count(usage.get("output_tokens")),
        "cache_creation_5m": None if split is None else _count(split.get("ephemeral_5m_input_tokens")),
        "cache_creation_1h": None if split is None else _count(split.get("ephemeral_1h_input_tokens")),
        "reasoning": _count(out_details.get("thinking_tokens"))}
    base = ("input_tokens", "cache_read", "cache_creation", "output")
    if any(counts[name] is None for name in base) or ("thinking_tokens" in out_details and counts["reasoning"] is None):
        return _unpriced(rid, model, "usage_incomplete", counts)  # reasoning may be unreported, never malformed
    creation = counts["cache_creation"] or 0
    five, hour = counts["cache_creation_5m"], counts["cache_creation_1h"]
    if creation or split is not None or usage.get("cache_creation") is not None:
        if five is None or hour is None:
            return _unpriced(rid, model, "cache_ttl_unknown", counts)
        if five + hour != creation:
            return _unpriced(rid, model, "cache_split_mismatch", counts)
    if ((not bedrock and usage.get("service_tier") != EXPECTED_SERVICE_TIER["anthropic"])
            or (bedrock and "service_tier" in usage)):
        return _unpriced(rid, model, "service_tier_unpriced", counts)
    if usage.get("speed") not in (None, "standard"):
        return _unpriced(rid, model, "speed_unpriced", counts)
    if usage.get("inference_geo") not in ({None, "us-east-1", "us-east-2", "us-west-2"} if bedrock
                                         else ALLOWED_INFERENCE_GEO):
        return _unpriced(rid, model, "inference_geo_unpriced", counts)
    if ((not bedrock and not _model_confirmed(prepared.model, message.get("model")))
            or (bedrock and model not in {"us.anthropic.claude-haiku-5-5", "anthropic.claude-haiku-5-5",
                                          "claude-haiku-5-5"})):
        return _unpriced(rid, model, "model_unconfirmed", counts)
    writes = {ttl: n for ttl, n in (("5m", five or 0), ("1h", hour or 0)) if n}
    total = (counts["input_tokens"] or 0) + (counts["cache_read"] or 0) + creation
    if bedrock and "total_tokens" in usage:
        counts["total"] = _count(usage["total_tokens"])
        if counts["total"] != total + (counts["output"] or 0):
            return _unpriced(rid, model, "usage_inconsistent", counts)
    try:
        priced = Usage(total, cache_read=counts["cache_read"] or 0, cache_writes=writes,
                       output=counts["output"] or 0, reasoning=counts["reasoning"])
    except InvalidUsage:
        return _unpriced(rid, model, "usage_malformed", counts)
    # Only cache `none` is implemented for Anthropic, so any creation is a mismatch.
    block = "cache_write_under_none" if creation else _limits(priced, prepared)
    if any(isinstance(b, dict) and b.get("type") in ("thinking", "redacted_thinking")
           for b in _items(message.get("content")) or []):
        block = block or "thinking_returned"  # a malformed content shape never stops the bill being priced
    return Evidence(priced, _reported(priced), rid, model, block)


# -- results ------------------------------------------------------------------------------------------------------

def _result(prepared: PreparedRequest, evidence: Evidence, outcome: Outcome, *,
            argument_issue: ToolArgumentIssue | None = None, **fields: Any) -> ModelResult:
    stop = fields.pop("stop_reason", None)
    if stop is not None and stop not in STOP_REASONS:
        stop = None
        fields.setdefault("reason_code", "stop_reason_unrecognised")
    if argument_issue is not None:
        fields["argument_issue"] = argument_issue
    return ModelResult(outcome=outcome, provider=prepared.provider, requested_model=prepared.model,
                       returned_model=evidence.returned_model, provider_request_id=evidence.provider_request_id,
                       usage=evidence.reported, stop_reason=stop, **fields)


def _structured(prepared: PreparedRequest, text: str) -> tuple[str | None, str | None]:
    """The canonical JSON of a valid structured answer (exact decimals), or the reason it is invalid."""
    if prepared.output is None:
        return None, "no_output_schema"
    try:
        value = strict_loads(text)
        canonical = output_bytes(value).decode()
    except CanonicalError:
        return None, "output_not_json"
    except UnicodeError:
        return None, "output_not_unicode"
    if len(canonical.encode()) > MAX_JSON:
        return None, "structured_too_large"
    errors = validation_errors(prepared.output, value)
    if errors:
        # Closed keywords only; retain neither paths nor model-supplied values.
        # Callers need to distinguish missing/wrong fields from length failures
        # after this adapter discards the invalid payload.
        keywords = {error.split("@", 1)[0] for error in errors}
        for keyword, code in (("required", "output_schema_required"), ("type", "output_schema_type"),
                              ("maxLength", "output_schema_max_length")):
            if keyword in keywords:
                return None, code
        return None, "output_schema"
    return canonical, None


def _tool_calls(prepared: PreparedRequest, calls: list[tuple[str, str, str]]) -> tuple[tuple[ToolCall, ...],
                                                                                        str | None]:
    if len(calls) > MAX_TOOL_CALLS:
        return (), "too_many_tool_calls"
    seen: set[str] = set()
    out = []
    for call_id, name, arguments in calls:
        schema: CheckedSchema | None = prepared.tools.get(name)
        if schema is None:
            return (), "unknown_tool"
        if call_id in seen:
            return (), "duplicate_tool_call"
        seen.add(call_id)
        if len(arguments.encode()) > MAX_ARGUMENTS:
            return (), "tool_arguments_too_large"
        try:
            value = strict_loads(arguments)
            canonical = output_bytes(value).decode()
        except (CanonicalError, UnicodeError):
            return (), "tool_arguments_not_json"
        if len(canonical.encode()) > MAX_ARGUMENTS:
            return (), "tool_arguments_too_large"
        if not isinstance(value, dict) or validation_errors(schema, value):
            return (), "tool_arguments_schema"
        try:
            out.append(ToolCall(call_id=call_id, name=name, arguments_json=canonical))
        except ValueError:
            return (), "tool_call_invalid"
    return tuple(out), None


def _finish(prepared: PreparedRequest, evidence: Evidence, text: str, calls: list[tuple[str, str, str]],
            stop_reason: str | None) -> ModelResult:
    if not _unicode(text):
        return _result(prepared, evidence, "invalid_output", reason_code="text_not_unicode", stop_reason=stop_reason)
    if len(text.encode()) > MAX_TEXT:
        return _result(prepared, evidence, "invalid_output", reason_code="text_too_large", stop_reason=stop_reason)
    if calls:
        tool_calls, problem = _tool_calls(prepared, calls)
        if problem is not None:
            issue = None
            if prepared.detailed_tool_errors and len(calls) == 1:
                _, name, arguments = calls[0]
                if problem == "tool_arguments_schema":
                    issue = refused_arguments(name, arguments)
                elif problem == "tool_arguments_not_json":
                    issue = argument_issue(name)
                elif problem == "tool_arguments_too_large":
                    issue = argument_issue(name, constraint="too_long")
            return _result(prepared, evidence, "invalid_output", reason_code=problem, stop_reason=stop_reason,
                           argument_issue=issue)
        return _result(prepared, evidence, "completed", text=text or None, tool_calls=tool_calls,
                       stop_reason=stop_reason)
    if prepared.output is not None:
        structured, problem = _structured(prepared, text)
        if problem is not None:
            return _result(prepared, evidence, "invalid_output", reason_code=problem, stop_reason=stop_reason)
        return _result(prepared, evidence, "structured", structured_json=structured, stop_reason=stop_reason)
    return _result(prepared, evidence, "completed", text=text, stop_reason=stop_reason)


def openai_result(response: Mapping[str, Any], prepared: PreparedRequest, evidence: Evidence) -> ModelResult:
    status = response.get("status")
    if status == "failed":
        return _result(prepared, evidence, "failed", reason_code="provider_failed")
    if status == "incomplete":
        details = response.get("incomplete_details") or {}
        reason = details.get("reason") if isinstance(details, dict) else None
        return _result(prepared, evidence, "truncated", stop_reason=reason if isinstance(reason, str) else None)
    if status != "completed":
        return _result(prepared, evidence, "failed", reason_code="unexpected_status")
    texts: list[str] = []
    calls: list[tuple[str, str, str]] = []
    output = _items(response.get("output", []))
    if output is None:
        return _result(prepared, evidence, "failed", reason_code="response_malformed")
    for item in output:
        if not isinstance(item, dict):
            return _result(prepared, evidence, "failed", reason_code="response_malformed")
        if item.get("type") == "message":
            parts = _items(item.get("content", []))
            if parts is None:
                return _result(prepared, evidence, "failed", reason_code="response_malformed")
            for part in parts:
                if isinstance(part, dict) and part.get("type") == "refusal":
                    return _result(prepared, evidence, "refused", stop_reason="refusal")
                if isinstance(part, dict) and part.get("type") == "output_text" and isinstance(part.get("text"), str):
                    texts.append(part["text"])
        elif item.get("type") == "function_call":
            call_id, name, arguments = item.get("call_id"), item.get("name"), item.get("arguments")
            if not (isinstance(call_id, str) and isinstance(name, str) and isinstance(arguments, str)):
                issue = (argument_issue(name) if prepared.detailed_tool_errors and isinstance(name, str)
                         and name in prepared.tools and not isinstance(arguments, str) else None)
                return _result(prepared, evidence, "invalid_output", reason_code="tool_call_malformed",
                               argument_issue=issue)
            calls.append((call_id, name, arguments))
        elif item.get("type") == "reasoning":
            continue  # reasoning summaries are never carried into results or logs
        else:
            return _result(prepared, evidence, "invalid_output", reason_code="unexpected_output_item")
    return _finish(prepared, evidence, "".join(texts), calls, "completed")


def anthropic_result(message: Mapping[str, Any], prepared: PreparedRequest, evidence: Evidence) -> ModelResult:
    stop = message.get("stop_reason")
    stop_reason = stop if isinstance(stop, str) else None
    content = _items(message.get("content", []))
    if content is None or not all(isinstance(block, dict) for block in content):
        # A provider envelope anomaly, not a model format error: no payload and no repair.
        return _result(prepared, evidence, "failed", reason_code="response_malformed", stop_reason=stop_reason)
    if any(b.get("type") in ("thinking", "redacted_thinking") for b in content):
        return _result(prepared, evidence, "contract_gap", reason_code="thinking_returned", stop_reason=stop_reason)
    if stop_reason == "refusal":
        return _result(prepared, evidence, "refused", stop_reason=stop_reason)
    if stop_reason in ("max_tokens", "model_context_window_exceeded"):
        return _result(prepared, evidence, "truncated", stop_reason=stop_reason)
    if stop_reason not in ("end_turn", "tool_use", "stop_sequence"):
        return _result(prepared, evidence, "failed", reason_code="unexpected_stop", stop_reason=stop_reason)
    texts: list[str] = []
    calls: list[tuple[str, str, str]] = []
    for block in content:
        if not isinstance(block, dict):
            return _result(prepared, evidence, "invalid_output", reason_code="output_malformed")
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            texts.append(block["text"])
        elif block.get("type") == "tool_use":
            call_id, name, arguments = block.get("id"), block.get("name"), block.get("input")
            if not isinstance(call_id, str) or not isinstance(name, str) or not isinstance(arguments, dict):
                issue = (argument_issue(name) if prepared.detailed_tool_errors and isinstance(name, str)
                         and name in prepared.tools and not isinstance(arguments, dict) else None)
                return _result(prepared, evidence, "invalid_output", reason_code="tool_call_malformed",
                               argument_issue=issue)
            try:  # `arguments` came from the exact raw-JSON parse, so its numbers are exact decimals
                arguments_json = output_bytes(arguments).decode()
            except (CanonicalError, UnicodeError):
                return _result(prepared, evidence, "invalid_output", reason_code="tool_arguments_not_json")
            calls.append((call_id, name, arguments_json))
        else:
            return _result(prepared, evidence, "invalid_output", reason_code="unexpected_content_block")
    return _finish(prepared, evidence, "".join(texts), calls, stop_reason)
