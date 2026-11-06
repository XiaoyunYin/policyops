"""Upstream-visible messages ↔ conversation DTOs (T29): pure, bounded, verbatim or refused.

Inbound, toward the agent runtime, only what upstream's own `LLMAgent` would see:
- `opening_from_history`: the orchestrator's initial agent history must be exactly one assistant opener with text
  and no tool call. Anything else (an empty or longer history, a tool call, audio) is `unsupported_initial_history`.
- `user_message`: an upstream `UserMessage` routed to the agent (no tool call, no audio, text content).
- `tool_result`: the upstream `ToolMessage` answering the pending call, from the agent's own request, with exactly
  that ID. Its visible content, error flag and identity are kept, including an environment rejection
  (`execution_status="rejected"` with `error=True`), which the model must see. `execution_status` is replay
  metadata and authorizes nothing here; a rejection without the error flag is malformed. `MultiToolMessage` is
  refused: the agent never emits more than one call.

Outbound, toward the upstream orchestrator:
- `assistant_text`: the agent's customer-facing message as an upstream `AssistantMessage`.
- `assistant_tool_call`: the agent's single accepted call, its arguments mapped back through the catalog's omission
  plan (`tools.to_upstream_arguments`) and its call ID kept.

Audio is unsupported: a message carrying voice data by upstream's own `is_voice_message` (`is_audio=True` or any
`audio_content`) is refused, never reduced to its text. Text is never stripped, normalized, padded or truncated.
Each length bound and UTF-8 representability is checked before any DTO is built, and every refusal is a fixed typed
code that never echoes content; no raw-input exception is chained onto it. Only new objects are returned: nothing of
the source message is kept. Upstream classes are imported lazily, and only once its import side effects are
disabled.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from pydantic import ValidationError

from policyops_contracts.conversation import (
    KNOWLEDGE_TOOL,
    MAX_TOOL_CONTENT,
    AgentMessage,
    AgentToolCall,
    ToolResult,
    UserMessage,
)
from policyops_evals.harness.tools import ArgumentsRefused, CatalogMapping, to_upstream_arguments


MAX_USER_TEXT = 8000
MAX_AGENT_TEXT = 4000

MessageCode = Literal[
    "unsupported_initial_history", "wrong_message_type", "tool_call_in_user_message", "audio_unsupported",
    "multi_tool_message", "wrong_requestor", "wrong_call_id", "malformed_tool_message", "empty_content",
    "oversize_content", "unrepresentable_text", "unknown_tool", "invalid_arguments", "upstream_not_prepared",
]


class MessageRefused(ValueError):
    """A message cannot cross the boundary faithfully. The message is the fixed code only."""

    def __init__(self, code: MessageCode) -> None:
        self.code: MessageCode = code
        super().__init__(code)


def _upstream() -> Any:
    """`tau2.data_model.message`, imported only once upstream's import-time side effects are disabled."""
    if os.environ.get("PYTHON_DOTENV_DISABLED") != "1" or \
            os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP", "").lower() != "true":
        raise MessageRefused("upstream_not_prepared")
    from tau2.data_model import message

    return message


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        raise MessageRefused("empty_content" if value is None else "wrong_message_type")
    if not value:
        raise MessageRefused("empty_content")
    if len(value) > limit:
        raise MessageRefused("oversize_content")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:  # an unpaired surrogate cannot cross a UTF-8 boundary
        raise MessageRefused("unrepresentable_text") from None
    return value


def opening_from_history(message_history: object) -> AgentMessage:
    upstream = _upstream()
    if not isinstance(message_history, list | tuple) or len(message_history) != 1:
        raise MessageRefused("unsupported_initial_history")
    (opener,) = message_history
    if type(opener) is not upstream.AssistantMessage or opener.role != "assistant":
        raise MessageRefused("unsupported_initial_history")
    if opener.is_tool_call() or upstream.is_voice_message(opener):
        raise MessageRefused("unsupported_initial_history")
    text = _text(opener.content, MAX_AGENT_TEXT)
    try:
        return AgentMessage(text=text)
    except ValidationError:
        raise MessageRefused("unrepresentable_text") from None


def user_message(source: object) -> UserMessage:
    upstream = _upstream()
    if type(source) is not upstream.UserMessage:
        raise MessageRefused("wrong_message_type")
    message: Any = source  # an exact upstream UserMessage (upstream ships no type information)
    if message.role != "user":
        raise MessageRefused("wrong_message_type")
    if message.is_tool_call():
        raise MessageRefused("tool_call_in_user_message")
    if upstream.is_voice_message(message):
        raise MessageRefused("audio_unsupported")
    text = _text(message.content, MAX_USER_TEXT)
    try:
        return UserMessage(text=text)
    except ValidationError:
        raise MessageRefused("unrepresentable_text") from None


def tool_result(source: object, pending_call_id: str) -> ToolResult:
    upstream = _upstream()
    if type(source) is upstream.MultiToolMessage:
        raise MessageRefused("multi_tool_message")
    if type(source) is not upstream.ToolMessage:
        raise MessageRefused("wrong_message_type")
    message: Any = source  # an exact upstream ToolMessage (upstream ships no type information)
    if message.role != "tool":
        raise MessageRefused("wrong_message_type")
    if message.requestor != "assistant":
        raise MessageRefused("wrong_requestor")
    if not isinstance(message.id, str) or message.id != pending_call_id:
        raise MessageRefused("wrong_call_id")
    if not isinstance(message.error, bool):
        raise MessageRefused("malformed_tool_message")
    if message.execution_status not in ("executed", "rejected") or (
            message.execution_status == "rejected" and not message.error):
        raise MessageRefused("malformed_tool_message")
    content = _text(message.content, MAX_TOOL_CONTENT)
    try:
        return ToolResult(call_id=pending_call_id, content=content, is_error=message.error)
    except ValidationError:
        raise MessageRefused("unrepresentable_text") from None


def assistant_text(message: AgentMessage) -> Any:
    upstream = _upstream()
    if type(message) is not AgentMessage:
        raise MessageRefused("wrong_message_type")
    return upstream.AssistantMessage(role="assistant", content=message.text)


def assistant_tool_call(call: AgentToolCall, catalog: CatalogMapping) -> Any:
    upstream = _upstream()
    if type(call) is not AgentToolCall:
        raise MessageRefused("wrong_message_type")
    if call.name == KNOWLEDGE_TOOL or call.name not in catalog.tools:
        raise MessageRefused("unknown_tool")  # the knowledge tool is served by PolicyOps, never by upstream
    try:
        arguments = to_upstream_arguments(catalog, call.name, call.arguments_json)
    except ArgumentsRefused:
        raise MessageRefused("invalid_arguments") from None
    return upstream.AssistantMessage(role="assistant", content=None, tool_calls=[
        upstream.ToolCall(id=call.call_id, name=call.name, arguments=arguments, requestor="assistant")])
