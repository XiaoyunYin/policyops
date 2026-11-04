"""Model-facing retail agent steps: exactly one tool call or exactly one message.

The pinned policy allows at most one tool call at a time and never a tool call
together with a customer message, so a step is one or the other by
construction. Sequence rules (authentication first, transfer followed by the
exact handoff text) are checked by policyops.domain.
"""

from typing import Annotated, Literal

from pydantic import Field

from policyops_contracts.base import WireModel
from policyops_contracts.retail import ToolCall
from policyops_contracts.scalars import MessageText


class ToolCallStep(WireModel):
    kind: Literal["tool_call"] = "tool_call"
    call: ToolCall


class MessageStep(WireModel):
    kind: Literal["message"] = "message"
    text: MessageText


AgentStep = Annotated[ToolCallStep | MessageStep, Field(discriminator="kind")]
