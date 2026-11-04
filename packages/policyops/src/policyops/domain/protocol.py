"""Retail agent step-sequence rules.

`AgentStep` already makes each step exactly one tool call or one message. This
module adds the sequence rule for handoff: a transfer_to_human_agents call must
be followed, as the very next step, by the exact handoff message, after which
the conversation ends; the handoff text is not allowed anywhere else.
Deterministic work behind a single tool call may run concurrently; the
model-facing protocol stays serialized.
"""

from collections.abc import Sequence

from policyops_contracts.agent import AgentStep, MessageStep, ToolCallStep
from policyops_contracts.retail import HANDOFF_MESSAGE, TransferToHumanAgents


def _is_transfer(step: AgentStep | None) -> bool:
    return isinstance(step, ToolCallStep) and isinstance(step.call, TransferToHumanAgents)


def _is_handoff(step: AgentStep | None) -> bool:
    return isinstance(step, MessageStep) and step.text == HANDOFF_MESSAGE


def step_violation(previous: AgentStep | None, step: AgentStep) -> str | None:
    if _is_handoff(previous):
        return "the conversation ended with the handoff message"
    if _is_transfer(previous) and not _is_handoff(step):
        return "a transfer must be followed by the exact handoff message"
    if _is_handoff(step) and not _is_transfer(previous):
        return "the handoff message may only follow a transfer"
    return None


def sequence_violation(steps: Sequence[AgentStep]) -> tuple[int, str] | None:
    previous: AgentStep | None = None
    for index, step in enumerate(steps):
        problem = step_violation(previous, step)
        if problem is not None:
            return index, problem
        previous = step
    return None
