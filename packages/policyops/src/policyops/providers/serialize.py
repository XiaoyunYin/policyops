"""The exact provider requests (T11): `ModelRequest` + server-owned actor configuration → one prepared request.

`prepare` performs every check that can be done locally, before anything is reserved:
- the registry (model, effort, cache mode);
- the implemented provider contract (cache, thinking, tier);
- tool and output schema registration (`schema.check_schema`);
- tool-name and history consistency;
- the output limit against the actor's maximum.

It returns a `PreparedRequest` whose canonical body **bytes** are the source of truth:
- `request_sha256` hashes an envelope of the contract version, method, host, path, version headers and body. No
  key or authorization header is part of it, or of anything persisted.
- The count projection is derived from the same body, for the provider's count endpoint.
- The SDK receives a fresh decode of those bytes, and the transport checks that what goes out re-encodes to
  exactly them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from policyops.budget.config import ChatActor, Configuration
from policyops.budget.registry import bedrock_model_refusal
from policyops.providers.bounds import REQUEST_BOUNDS, preflight
from policyops.providers.canonical import (
    CanonicalError,
    canonical_bytes,
    canonical_size,
    fresh,
    sha256_hex,
    strict_loads,
)
from policyops.providers.contract import CONTRACT_VERSION, ENDPOINTS, ContractGap, Provider, require_cache_mode
from policyops.providers.schema import CheckedSchema, SchemaGap, check_schema
from policyops_contracts.model import Message, ModelRequest, TextPart, ToolResultPart, ToolUsePart


OPENAI_COUNT_KEYS = ("model", "input", "instructions", "tools", "tool_choice", "text", "reasoning",
                     "parallel_tool_calls", "truncation")
ANTHROPIC_COUNT_KEYS = ("model", "system", "messages", "tools", "tool_choice", "output_config", "thinking")


@dataclass(frozen=True)
class PreparedRequest:
    provider: Provider
    actor: str
    model: str
    method: str
    host: str
    path: str
    count_path: str
    version_headers: Mapping[str, str]
    body: bytes
    count_body: bytes
    request_sha256: str
    tools: Mapping[str, CheckedSchema]
    output: CheckedSchema | None
    output_name: str | None
    stream: bool
    max_input: int  # the actor's admitted maximum prompt
    max_output: int  # this request's max_output_tokens
    detailed_tool_errors: bool = False

    def params(self) -> dict[str, Any]:
        """A fresh, independent decode of the body for the SDK call (never the source of truth)."""
        value: dict[str, Any] = fresh(self.body)
        return value

    def count_params(self) -> dict[str, Any]:
        value: dict[str, Any] = fresh(self.count_body)
        return value


def _arguments(text: str) -> Any:
    try:
        value = strict_loads(text)
        canonical_bytes(value)
    except CanonicalError as error:
        raise ContractGap("tool-call arguments in the history are not strict canonical JSON") from error
    if not isinstance(value, dict):
        raise ContractGap("tool-call arguments are a JSON object")
    return value


def _check_history(request: ModelRequest) -> None:
    open_calls: set[str] = set()
    names = {tool.name for tool in request.tools}
    for message in request.messages:
        for part in message.parts:
            if isinstance(part, ToolUsePart):
                if part.name not in names:
                    raise ContractGap(f"the history calls an undeclared tool {part.name!r}")
                if part.call_id in open_calls:
                    raise ContractGap("a tool call ID is reused")
                _arguments(part.arguments_json)
                open_calls.add(part.call_id)
            elif isinstance(part, ToolResultPart):
                if part.call_id not in open_calls:
                    raise ContractGap("a tool result names no earlier tool call")
                open_calls.discard(part.call_id)


def _schemas(request: ModelRequest) -> tuple[dict[str, CheckedSchema], CheckedSchema | None]:
    try:
        tools = {tool.name: check_schema(tool.parameters_schema_json) for tool in request.tools}
        output = None if request.output is None else check_schema(request.output.answer_schema_json)
    except SchemaGap as error:
        raise ContractGap(f"schema outside the supported subset: {error}") from error
    return tools, output


# -- OpenAI Responses ---------------------------------------------------------------------------------------------

def _openai_input(message: Message) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    texts: list[dict[str, Any]] = []

    def flush() -> None:
        if texts:
            items.append({"type": "message", "role": message.role, "content": list(texts)})
            texts.clear()

    for part in message.parts:
        if isinstance(part, TextPart):
            texts.append({"type": "input_text" if message.role == "user" else "output_text", "text": part.text})
        elif isinstance(part, ToolUsePart):
            flush()
            items.append({"type": "function_call", "call_id": part.call_id, "name": part.name,
                          "arguments": canonical_bytes(_arguments(part.arguments_json)).decode()})
        else:
            flush()
            items.append({"type": "function_call_output", "call_id": part.call_id, "output": part.content})
    flush()
    return items


def _openai_body(request: ModelRequest, actor: ChatActor, tools: Mapping[str, CheckedSchema],
                 output: CheckedSchema | None) -> dict[str, Any]:
    cache = {"mode": "explicit"} if actor.cache_mode == "none" else {"mode": "implicit", "ttl": actor.cache_mode}
    body: dict[str, Any] = {
        "model": actor.model, "instructions": request.instructions,
        "input": [item for message in request.messages for item in _openai_input(message)],
        "reasoning": {"effort": actor.effort}, "max_output_tokens": request.max_output_tokens,
        "prompt_cache_options": cache, "service_tier": "default", "store": False, "parallel_tool_calls": False,
        "truncation": "disabled", "stream": request.stream, "tool_choice": request.tool_choice,
    }
    if request.tools:
        body["tools"] = [{"type": "function", "name": tool.name, "description": tool.description,
                          "parameters": fresh(tools[tool.name].wire), "strict": True} for tool in request.tools]
    if output is not None and request.output is not None:
        body["text"] = {"format": {"type": "json_schema", "name": request.output.name, "schema": fresh(output.wire),
                                   "strict": True}}
    return body


# -- Anthropic Messages -------------------------------------------------------------------------------------------

def _anthropic_message(message: Message) -> dict[str, Any]:
    content: list[dict[str, Any]] = []
    for part in message.parts:
        if isinstance(part, TextPart):
            content.append({"type": "text", "text": part.text})
        elif isinstance(part, ToolUsePart):
            content.append({"type": "tool_use", "id": part.call_id, "name": part.name,
                            "input": _arguments(part.arguments_json)})
        else:
            content.append({"type": "tool_result", "tool_use_id": part.call_id,
                            "content": [{"type": "text", "text": part.content}], "is_error": part.is_error})
    return {"role": message.role, "content": content}


ANTHROPIC_TOOL_CHOICE: Mapping[str, Mapping[str, object]] = MappingProxyType({
    "auto": {"type": "auto", "disable_parallel_tool_use": True},
    "none": {"type": "none"},
    "required": {"type": "any", "disable_parallel_tool_use": True},
})


def _anthropic_body(request: ModelRequest, actor: ChatActor, tools: Mapping[str, CheckedSchema],
                    output: CheckedSchema | None) -> dict[str, Any]:
    output_config: dict[str, Any] = {"effort": actor.effort}
    if output is not None:
        output_config["format"] = {"type": "json_schema", "schema": fresh(output.wire)}
    body: dict[str, Any] = {
        "model": actor.model, "system": request.instructions,
        "messages": [_anthropic_message(message) for message in request.messages],
        "max_tokens": request.max_output_tokens, "thinking": {"type": "disabled"}, "output_config": output_config,
        # No `speed` field: it is optional, and some models refuse any `speed` value without a beta header (T11
        # diagnostic: the frozen Haiku request's 400 named `speed`). Omitting it keeps the standard default.
        "service_tier": "standard_only", "stream": request.stream,
    }
    if request.tools:
        body["tools"] = [{"name": tool.name, "description": tool.description,
                          "input_schema": fresh(tools[tool.name].wire), "strict": True} for tool in request.tools]
        body["tool_choice"] = dict(ANTHROPIC_TOOL_CHOICE[request.tool_choice])
    return body


# -- preparation --------------------------------------------------------------------------------------------------

def prepare(request: ModelRequest, configuration: Configuration, actor_name: str, *,
            detailed_tool_errors: bool = False) -> PreparedRequest:
    if not isinstance(request, ModelRequest):
        raise TypeError("request must be a ModelRequest")
    preflight(request)
    actor = configuration.actors.get(actor_name)  # type: ignore[call-overload]
    if not isinstance(actor, ChatActor):
        raise ContractGap(f"{actor_name!r} is not a configured chat actor")
    configuration.registry.chat(actor.model, effort=actor.effort, cache_mode=actor.cache_mode)
    provider: Provider = configuration.registry.snapshot.price(actor.model).provider
    require_cache_mode(provider, actor.cache_mode)
    if provider == "anthropic" and actor.effort in ("xhigh", "max"):
        raise ContractGap("thinking cannot be disabled at effort xhigh or max")
    if request.max_output_tokens > actor.max_output:
        raise ContractGap(f"max_output_tokens exceeds the {actor_name} maximum of {actor.max_output}")
    _check_history(request)
    tools, output = _schemas(request)
    endpoint = ENDPOINTS[provider]
    body = (_openai_body if provider == "openai" else _anthropic_body)(request, actor, tools, output)
    if provider == "bedrock":
        if actor.model != "bedrock:us.anthropic.claude-haiku-5-5":
            raise ContractGap(bedrock_model_refusal(actor.model))
        if actor.max_input > 100_000:
            raise ContractGap("bedrock.long_context_unsupported")
        if request.stream or any(not isinstance(part, TextPart) for m in request.messages for part in m.parts):
            raise ContractGap("bedrock.text_only_nonstreaming")
        # One text block per message bounds framing overhead independently of the number of DTO parts.
        body["messages"] = [{"role": m.role, "content": [{"type": "text", "text": "".join(
            part.text for part in m.parts if isinstance(part, TextPart))}]} for m in request.messages]
        for key in ("model", "service_tier", "stream"):
            body.pop(key)
        body["anthropic_version"] = "bedrock-2023-05-31"
    keys = OPENAI_COUNT_KEYS if provider == "openai" else ANTHROPIC_COUNT_KEYS
    count_body = {key: body[key] for key in keys if key in body}
    try:
        canonical_size(body, limit=REQUEST_BOUNDS["body_bytes"])
        canonical_size(count_body, limit=REQUEST_BOUNDS["body_bytes"])
    except CanonicalError as error:
        raise ContractGap("provider body bound exceeded") from error
    body_bytes = canonical_bytes(body)
    count_bytes = canonical_bytes(count_body)
    envelope = canonical_bytes({"contract": CONTRACT_VERSION, "bounds": dict(REQUEST_BOUNDS),
                                "provider": provider, "method": "POST",
                                "host": endpoint.host, "path": endpoint.create_path, "query": {},
                                "version_headers": dict(endpoint.version_headers), "body": body})
    return PreparedRequest(provider, actor_name, actor.model, "POST", endpoint.host, endpoint.create_path,
                           endpoint.count_path, endpoint.version_headers, body_bytes, count_bytes,
                           sha256_hex(envelope), MappingProxyType(tools), output,
                           None if request.output is None else request.output.name, request.stream,
                           actor.max_input, request.max_output_tokens, detailed_tool_errors)
