"""The retail domain bridge (T11): tool specs from the T05 retail DTOs, and results → one checked `AgentStep`.

A tool's argument schema is the retail DTO's own pydantic JSON schema, minus its `tool` discriminator. It is the full
domain schema, ID patterns, list bounds and enums included. The provider receives only its documented wire projection
(`schema.check_schema`).

A result becomes an `AgentStep` only through `to_agent_step`, and only as one of these:
- exactly one tool call and no text: the arguments are validated by the full retail DTO, including its cross-field
  rules such as pairing `item_ids` with `new_item_ids`;
- text and no tool calls.

Anything else is refused with a reason code: several calls, text mixed with a call, an unknown tool, an invalid
argument, or any outcome other than `completed`. An `AgentStep` is still only a proposal: authorization, consent and
approval stay with the deterministic services.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import TypeAdapter, ValidationError

from policyops.providers.canonical import CanonicalError, output_bytes, strict_loads
from policyops_contracts.agent import AgentStep, MessageStep, ToolCallStep
from policyops_contracts.model import ModelResult, ToolSpec
from policyops_contracts.retail import ToolCall as RetailToolCall


_STEP: TypeAdapter[ToolCallStep | MessageStep] = TypeAdapter(AgentStep)
_CALL: TypeAdapter[Any] = TypeAdapter(RetailToolCall)


class StepRefused(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def retail_tool_spec(model: Any, description: str) -> ToolSpec:
    """A ToolSpec from one retail tool DTO class (for example `ReturnDeliveredOrderItems`)."""
    schema = model.model_json_schema()
    name = schema["properties"]["tool"]["const"]
    del schema["properties"]["tool"]
    schema["required"] = [field for field in schema.get("required", []) if field != "tool"]
    return ToolSpec(name=name, description=description, parameters_schema_json=json.dumps(schema, sort_keys=True))


def to_agent_step(result: ModelResult) -> ToolCallStep | MessageStep:
    if result.outcome != "completed":
        raise StepRefused(f"outcome_{result.outcome}")
    if result.tool_calls:
        if len(result.tool_calls) != 1:
            raise StepRefused("several_tool_calls")
        if result.text:
            raise StepRefused("text_with_tool_call")
        (call,) = result.tool_calls
        try:
            arguments = strict_loads(call.arguments_json)
        except CanonicalError as error:
            raise StepRefused("arguments_not_json") from error
        if not isinstance(arguments, dict) or "tool" in arguments:
            raise StepRefused("arguments_not_an_object")
        try:
            # JSON mode: the strict retail DTO sees exactly what a JSON client would send.
            validated = _CALL.validate_json(output_bytes({"tool": call.name, **arguments}))
        except (ValidationError, CanonicalError) as error:
            raise StepRefused("arguments_invalid") from error
        return ToolCallStep(call=validated)
    if not result.text:
        raise StepRefused("empty_message")
    try:
        return MessageStep(text=result.text)
    except ValidationError as error:
        raise StepRefused("message_invalid") from error


def validate_step(step: object) -> ToolCallStep | MessageStep:
    return _STEP.validate_python(step)
