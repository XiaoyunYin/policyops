"""Pure shared single-action parsing, report mapping and chronological transcript mechanics."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import json
import re

from pydantic import TypeAdapter, ValidationError

from policyops.domain.protocol import step_violation
from policyops.providers.calls import CallReport
from policyops.providers.tools import StepRefused, to_agent_step
from policyops_contracts.agent import AgentStep, MessageStep, ToolCallStep
from policyops_contracts.conversation import (
    KNOWLEDGE_TOOL,
    AgentMessage,
    AgentToolCall,
    Entry,
    NoticeCode,
    RuntimeNotice,
    TerminalReason,
    ToolResult,
    UserMessage,
)
from policyops_contracts.model import (
    Message,
    ModelResult,
    Part,
    TextPart,
    ToolResultPart,
    ToolUsePart,
)
from policyops_contracts.retail import (
    TransferToHumanAgents,
)
from policyops_contracts.retrieval import QueryText


OPENING_MARKER = "[conversation start]"
NOTICE_TEXT: dict[NoticeCode, str] = {
    code: f"[runtime notice] Your previous reply was not a valid single action ({code}). Reply with exactly one "
          "tool call or one message."
    for code in ("several_tool_calls", "text_with_tool_call", "empty_reply", "unknown_tool", "invalid_arguments",
                 "invalid_output", "protocol_violation")
}
_INVALID_OUTPUT: dict[str, NoticeCode] = {
    "unknown_tool": "unknown_tool", "too_many_tool_calls": "several_tool_calls",
    "duplicate_tool_call": "several_tool_calls", "tool_arguments_schema": "invalid_arguments",
    "tool_arguments_not_json": "invalid_arguments", "tool_arguments_too_large": "invalid_arguments",
    "tool_call_malformed": "invalid_arguments", "tool_call_invalid": "invalid_arguments",
}
_STEP_REFUSED: dict[str, NoticeCode] = {
    "several_tool_calls": "several_tool_calls", "text_with_tool_call": "text_with_tool_call",
    "arguments_not_json": "invalid_arguments", "arguments_not_an_object": "invalid_arguments",
    "arguments_invalid": "invalid_arguments", "empty_message": "empty_reply",
}
_COUNT_REASON = re.compile(r"^count[._]")
_SLUG = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_QUERY: TypeAdapter[str] = TypeAdapter(QueryText)
class TranscriptInvariant(RuntimeError):
    """The transcript cannot be serialized faithfully (a defect): it is refused, never re-sorted."""


def provider_messages(transcript: Sequence[Entry], *, opening: bool = False) -> tuple[Message, ...]:
    """Chronological provider history. Raises `TranscriptInvariant` instead of reordering anything. In opening mode
    the transcript starts with the visible opener, presented behind the synthetic marker; otherwise an agent entry
    cannot come first."""
    if type(opening) is not bool:
        raise TypeError("opening is a bool")
    messages: list[Message] = []
    user: list[Part] = []
    open_call: str | None = None  # an assistant tool call whose result must be the very next entry

    def flush() -> None:
        if user:
            messages.append(Message(role="user", parts=tuple(user)))
            user.clear()

    try:
        entries = transcript
        if opening:
            first = entries[0] if entries else None
            if not isinstance(first, AgentMessage):
                raise TranscriptInvariant("an opening-mode transcript starts with the visible opener")
            messages.append(Message(role="user", parts=(TextPart(text=OPENING_MARKER),)))
            messages.append(Message(role="assistant", parts=(TextPart(text=first.text),)))
            entries = entries[1:]
        for entry in entries:
            if len(user) == 64:
                flush()
            if open_call is not None:
                if not (isinstance(entry, ToolResult) and entry.call_id == open_call):
                    raise TranscriptInvariant("a tool call is not directly followed by its result")
                user.append(ToolResultPart(call_id=entry.call_id, content=entry.content, is_error=entry.is_error))
                open_call = None
            elif isinstance(entry, ToolResult):
                raise TranscriptInvariant("a tool result does not directly follow its call")
            elif isinstance(entry, UserMessage):
                user.append(TextPart(text=entry.text))
            elif isinstance(entry, RuntimeNotice):
                user.append(TextPart(text=NOTICE_TEXT[entry.code]))
            elif isinstance(entry, AgentMessage | AgentToolCall):
                if not user:
                    raise TranscriptInvariant("an agent action follows a user-side entry")
                flush()
                if isinstance(entry, AgentMessage):
                    messages.append(Message(role="assistant", parts=(TextPart(text=entry.text),)))
                else:
                    messages.append(Message(role="assistant", parts=(ToolUsePart(
                        call_id=entry.call_id, name=entry.name, arguments_json=entry.arguments_json),)))
                    open_call = entry.call_id
            else:
                raise TranscriptInvariant("an unknown transcript entry")
        if open_call is not None:
            raise TranscriptInvariant("the last tool call has no result")
        if not user:
            raise TranscriptInvariant("a request ends with a user-side entry")
        flush()
    except ValidationError as error:
        raise TranscriptInvariant("the transcript does not fit the provider message bounds") from error
    return tuple(messages)


def entry_bytes(entry: Entry) -> int:
    if isinstance(entry, UserMessage | AgentMessage):
        text = entry.text
    elif isinstance(entry, AgentToolCall):
        text = entry.name + entry.arguments_json
    elif isinstance(entry, ToolResult):
        text = entry.content
    else:
        text = NOTICE_TEXT[entry.code]
    return len(text.encode("utf-8"))


@dataclass(frozen=True)
class Notice:
    code: NoticeCode


@dataclass(frozen=True)
class Say:
    message: AgentMessage
    step: AgentStep | None


@dataclass(frozen=True)
class Use:
    call: AgentToolCall
    step: AgentStep | None
    query: str | None  # set for the knowledge tool


def _slug(value: str | None) -> str | None:
    return value if value is not None and _SLUG.match(value) else None


def report_terminal(report: CallReport) -> tuple[TerminalReason, str | None] | None:
    """A T11 report → its terminal reason, or None when the result is a model reply to parse. Exhaustive."""
    reason = _slug(report.reason)
    if report.status == "budget":
        return "budget", reason
    if report.status == "deadline":
        return "deadline", reason
    if report.status == "contract_gap":
        return "contract_gap", reason
    if report.status == "failed":
        if reason is not None and (reason == "count_not_admitted" or _COUNT_REASON.match(reason)):
            return "count_not_admitted", reason
        return "provider_failed", reason
    if report.status != "result" or not isinstance(report.result, ModelResult):
        return "provider_failed", "report_invalid"
    outcome = report.result.outcome
    if outcome == "refused":
        return "model_refused", _slug(report.result.reason_code)
    if outcome == "truncated":
        return "model_truncated", _slug(report.result.stop_reason)
    if outcome == "failed":
        return "provider_failed", _slug(report.result.reason_code)
    if outcome == "contract_gap":
        return "contract_gap", _slug(report.result.reason_code)
    return None


def parse(result: ModelResult, *, names: dict[str, bool], retail: bool,
          previous: AgentStep | None) -> Notice | Say | Use:
    if result.outcome == "invalid_output":
        return Notice(_INVALID_OUTPUT.get(result.reason_code or "", "invalid_output"))
    if result.outcome != "completed":  # a structured answer was never requested
        return Notice("invalid_output")
    calls, text = result.tool_calls, result.text
    if len(calls) > 1:
        return Notice("several_tool_calls")
    if calls and text:
        return Notice("text_with_tool_call")
    if not calls and not text:
        return Notice("empty_reply")
    if calls:
        (call,) = calls
        if call.name not in names:
            return Notice("unknown_tool")
        accepted = AgentToolCall(call_id=call.call_id, name=call.name, arguments_json=call.arguments_json)
        if call.name == KNOWLEDGE_TOOL:
            try:
                arguments = json.loads(call.arguments_json)
                if not isinstance(arguments, dict) or set(arguments) != {"query"}:
                    return Notice("invalid_arguments")
                query = _QUERY.validate_python(arguments["query"])
            except (ValueError, ValidationError):
                return Notice("invalid_arguments")
            if retail and after_transfer(previous):
                return Notice("protocol_violation")
            return Use(accepted, None, query)
        if not retail:
            return Use(accepted, None, None)
        try:
            step = to_agent_step(result)
        except StepRefused as refused:
            return Notice(_STEP_REFUSED.get(refused.code, "invalid_output"))
        if step_violation(previous, step) is not None:
            return Notice("protocol_violation")
        return Use(accepted, step, None)
    try:
        said = AgentMessage(text=text or "")
    except ValidationError:
        return Notice("invalid_output")
    if not retail:
        return Say(said, None)
    step = MessageStep(text=said.text)
    if step_violation(previous, step) is not None:
        return Notice("protocol_violation")
    return Say(said, step)


def after_transfer(previous: AgentStep | None) -> bool:
    return isinstance(previous, ToolCallStep) and isinstance(previous.call, TransferToHumanAgents)
