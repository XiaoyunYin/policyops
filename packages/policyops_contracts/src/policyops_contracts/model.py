"""Provider-neutral model request and result DTOs (T11). Pydantic only, so the evaluator can share them later.

They carry semantics, not wire formats: the app's provider serializers turn a `ModelRequest`, together with the
server-owned actor configuration, into one exact provider request. Every nested JSON value (a tool or output
schema, tool-call arguments, structured output) travels as JSON **text**, so a DTO is deeply immutable. A result is
never authorization or truth: a tool call is a proposal for the deterministic services, and a structured result
still needs domain validation.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.tool_diagnostics import ToolArgumentIssue


Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")]
CallId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=200_000)]
JsonText = Annotated[str, StringConstraints(min_length=1, max_length=65_536)]
Count = Annotated[int, Field(ge=0, lt=2**31)]


class TextPart(WireModel):
    kind: Literal["text"] = "text"
    text: LongText


class ToolUsePart(WireModel):
    """An earlier assistant tool call, replayed in the history."""

    kind: Literal["tool_use"] = "tool_use"
    call_id: CallId
    name: Name
    arguments_json: JsonText


class ToolResultPart(WireModel):
    kind: Literal["tool_result"] = "tool_result"
    call_id: CallId
    content: LongText
    is_error: bool = False


Part = Annotated[TextPart | ToolUsePart | ToolResultPart, Field(discriminator="kind")]


class Message(WireModel):
    role: Literal["user", "assistant"]
    parts: Annotated[tuple[Part, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def _parts_fit_role(self) -> Message:
        kinds = {part.kind for part in self.parts}
        if self.role == "user" and "tool_use" in kinds:
            raise ValueError("only an assistant message has tool calls")
        if self.role == "assistant" and "tool_result" in kinds:
            raise ValueError("only a user message has tool results")
        return self


class ToolSpec(WireModel):
    """A tool the model may propose. `parameters_schema_json` is the full domain JSON Schema of its arguments."""

    name: Name
    description: Annotated[str, StringConstraints(min_length=1, max_length=1024)]
    parameters_schema_json: JsonText


class OutputSpec(WireModel):
    """A structured final answer. `answer_schema_json` is the full domain JSON Schema of the answer object."""

    name: Name
    answer_schema_json: JsonText


class ModelRequest(WireModel):
    instructions: LongText
    messages: Annotated[tuple[Message, ...], Field(min_length=1, max_length=256)]
    tools: Annotated[tuple[ToolSpec, ...], Field(max_length=32)] = ()
    tool_choice: Literal["auto", "none", "required"] = "auto"
    output: OutputSpec | None = None
    max_output_tokens: Annotated[int, Field(ge=1, le=128_000)]
    stream: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> ModelRequest:
        names = [tool.name for tool in self.tools]
        if len(set(names)) != len(names):
            raise ValueError("tool names are unique")
        if self.tool_choice == "required" and not self.tools:
            raise ValueError("a required tool choice needs tools")
        if self.messages[0].role != "user":
            raise ValueError("the conversation starts with a user message")
        return self


class ReportedUsage(WireModel):
    """Provider-neutral usage. `known` means every billed count was reported and is consistent: cache parts within the
    whole prompt, reasoning within the output, each cache lifetime once. `reasoning` is informational and may be
    None (unreported) even when known. `unknown` carries no counts and is never read as zero."""

    state: Literal["known", "unknown"]
    input_total: Count | None = None
    cache_read: Count | None = None
    cache_writes: tuple[tuple[Literal["30m", "12h", "5m", "1h"], Count], ...] = ()
    output: Count | None = None
    reasoning: Count | None = None

    @model_validator(mode="after")
    def _complete_when_known(self) -> ReportedUsage:
        counts = (self.input_total, self.cache_read, self.output, self.reasoning)
        if self.state == "unknown":
            if any(count is not None for count in counts) or self.cache_writes:
                raise ValueError("unknown usage carries no counts")
            return self
        if self.input_total is None or self.cache_read is None or self.output is None:
            raise ValueError("known usage reports every billed count")
        lifetimes = [ttl for ttl, _ in self.cache_writes]
        if len(set(lifetimes)) != len(lifetimes):
            raise ValueError("each cache lifetime appears once")
        if self.cache_read + sum(n for _, n in self.cache_writes) > self.input_total:
            raise ValueError("cache reads and writes are parts of the prompt")
        if self.reasoning is not None and self.reasoning > self.output:
            raise ValueError("reasoning is part of the output")
        return self


class ToolCall(WireModel):
    call_id: CallId
    name: Name
    arguments_json: JsonText


Outcome = Literal["completed", "structured", "refused", "truncated", "invalid_output", "contract_gap", "failed"]


class ModelResult(WireModel):
    outcome: Outcome
    provider: Literal["openai", "anthropic", "bedrock"]
    requested_model: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    returned_model: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None
    provider_request_id: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None
    text: Annotated[str, StringConstraints(max_length=262_144)] | None = None
    structured_json: JsonText | None = None
    tool_calls: Annotated[tuple[ToolCall, ...], Field(max_length=16)] = ()
    stop_reason: Annotated[str, StringConstraints(max_length=64)] | None = None
    reason_code: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")] | None = None
    usage: ReportedUsage
    argument_issue: ToolArgumentIssue | None = Field(default=None, exclude_if=lambda value: value is None)
