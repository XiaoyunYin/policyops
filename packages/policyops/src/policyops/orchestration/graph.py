"""Sequential, bounded investigation. Checkpointed actions carry no execution authority."""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import time
from typing import Any, Literal, Protocol, TypedDict
from uuid import uuid5

from langchain_core.runnables import RunnableLambda
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import field_validator
from sqlalchemy.exc import DBAPIError

from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.mechanics import Notice, Say, Use, after_transfer, entry_bytes, parse, report_terminal
from policyops.orchestration.minimal import AGENT_NAMESPACE, AGENT_OPERATION
from policyops.orchestration.ports import KnowledgePort, ModelPort
from policyops.orchestration.state import (
    AwaitingApproval,
    InvestigationAction,
    InvestigationCompleted,
    InvestigationFailed,
    InvestigationState,
    state_from_json,
)
from policyops.persistence.database import PersistenceError
from policyops.persistence.runs import Fenced
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.runtime.spec import investigation_message_id
from policyops_contracts.base import WireModel
from policyops_contracts.conversation import (
    AgentLimits,
    Entry,
    PendingToolOutcome,
    PolicyContext,
    RuntimeNotice,
    ToolResult,
)
from policyops_contracts.grounding import GroundedAnswer
from policyops_contracts.model import ModelResult
from policyops_contracts.proposal import EvidenceRef
from policyops_contracts.retail import TOOL_KINDS, ToolKind, ToolName


GRAPH_NODES = ("investigate", "retrieve", "read", "propose", "finalize")
GRAPH_ENTRY = "investigate"
GRAPH_TARGETS = (*GRAPH_NODES, END)
ABSTENTION = "I cannot answer from the available verified policy evidence."


class Actions(Protocol):
    async def read(self, state: InvestigationState, *, deadline: float) -> ToolResult: ...
    async def propose(self, state: InvestigationState, *, deadline: float) -> AwaitingApproval | ToolResult: ...
    def evidence(self, index: int) -> tuple[EvidenceRef, ...]: ...
    def finalize(self, state: InvestigationState, *, deadline: float
                 ) -> tuple[Literal["answered", "abstained"], str]: ...


class GraphEnvelope(WireModel):
    state: InvestigationState

    @field_validator("state", mode="before")
    @classmethod
    def checked(cls, value: Any) -> InvestigationState:
        return state_from_json(value)


class GraphInput(TypedDict):
    state: dict[str, Any]


def update(state: InvestigationState, **fields: Any) -> InvestigationState:
    return state_from_json(state.model_dump(mode="json") | {
        k: v.model_dump(mode="json") if isinstance(v, WireModel) else v for k, v in fields.items()})


def failed(state: InvestigationState, kind: InvestigationFailed) -> InvestigationState:
    return update(state, terminal=kind)


def completed(state: InvestigationState, kind: Literal["answered", "abstained", "handoff"],
              text: str) -> InvestigationState:
    return update(state, final_text=text, terminal=InvestigationCompleted(
        kind=kind, message_id=investigation_message_id(state.workspace_id, state.run_id)))


@dataclass
class InvestigationGraph:
    model: ModelPort
    knowledge: KnowledgePort
    actions: Actions
    policy: PolicyContext
    limits: AgentLimits
    deadline: float
    fence: Callable[[], None]

    def fits(self, state: InvestigationState, entries: tuple[Entry, ...]) -> bool:
        transcript = (*state.transcript, *entries)
        return (len(transcript) <= self.limits.transcript_messages
                and sum(entry_bytes(e) for e in transcript) <= self.limits.transcript_bytes)

    async def node(self, name: str, data: GraphEnvelope) -> dict[str, Any]:
        self.fence()
        state = data.state
        if state.terminal is not None:
            return {"state": state.model_dump(mode="json")}
        if time.monotonic() >= self.deadline:
            state = failed(state, InvestigationFailed(kind="deadline"))
        elif state.step_count >= state.max_steps:
            state = failed(state, InvestigationFailed(kind="loop_ceiling"))
        else:
            state = update(state, step_count=state.step_count + 1, current_node=name)
            try:
                if name == "investigate":
                    state = await self.investigate(state)
                elif name == "finalize":
                    kind, text = self.actions.finalize(state, deadline=self.deadline)
                    state = completed(state, kind, text)
                else:
                    state = await self.dispatch(name, state)
            except (Fenced, DBAPIError, PersistenceError, AccountingUnconfirmed):
                raise
            except asyncio.CancelledError:
                # Executor-owned cancellation must propagate so lease loss cannot become a success.
                raise
            except Exception:
                state = failed(state, InvestigationFailed(kind="provider_error" if name == "investigate"
                                                          else "tool_error"))
        self.fence()
        if time.monotonic() >= self.deadline:
            state = failed(state, InvestigationFailed(kind="deadline"))
        return {"state": state.model_dump(mode="json")}

    async def investigate(self, state: InvestigationState) -> InvestigationState:
        if state.model_calls >= self.limits.model_calls or not self.fits(state, ()):
            return failed(state, InvestigationFailed(kind="loop_ceiling"))
        key = uuid5(AGENT_NAMESPACE, f"{state.run_id}:{state.model_calls}")
        try:
            report = await self.model.complete(prompt.request(self.policy, self.limits, state.transcript),
                                               key=key, operation=AGENT_OPERATION, deadline=self.deadline)
        except asyncio.CancelledError:
            # A provider-originated cancellation is typed; external task cancellation is owned by the executor.
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                raise
            return failed(state, InvestigationFailed(kind="provider_cancelled"))
        state = update(state, model_calls=state.model_calls + 1,
                       cleanup_unconfirmed=state.cleanup_unconfirmed or any(
                           r.cleanup_confirmed is False for r in report.attempts))
        if time.monotonic() >= self.deadline:
            return failed(state, InvestigationFailed(kind="deadline"))
        if (report.reason or "").startswith("replayed_"):
            return failed(state, InvestigationFailed(kind="provider_result_unavailable"))
        ending = report_terminal(report)
        if ending is not None:
            kind: Literal["budget_exceeded", "deadline", "provider_error"] = (
                "budget_exceeded" if ending[0] == "budget" else "deadline" if ending[0] == "deadline"
                else "provider_error")
            return failed(state, InvestigationFailed(kind=kind))
        if not isinstance(report.result, ModelResult):
            return failed(state, InvestigationFailed(kind="provider_error"))
        result = report.result
        names = {t.name: t.read_only for t in prompt.catalog().all_tools()}
        action: Notice | Say | Use
        # Control tools use the same one-call gate, then their own schema (never retail to_agent_step).
        if (result.outcome == "completed" and len(result.tool_calls) == 1 and not result.text
                and result.tool_calls[0].name == prompt.FINISH):
            if after_transfer(state.previous_step):
                action = Notice("protocol_violation")
            else:
                try:
                    answer = GroundedAnswer.model_validate_json(result.tool_calls[0].arguments_json)
                except ValueError:
                    action = Notice("invalid_arguments")
                else:
                    return update(state, invalid_count=0,
                                  next_action=InvestigationAction(kind="finalize", answer=answer))
        else:
            action = parse(result, names=names, retail=True, previous=state.previous_step)
        if isinstance(action, Notice):
            notice = RuntimeNotice(code=action.code)
            if not self.fits(state, (notice,)):
                return failed(state, InvestigationFailed(kind="loop_ceiling"))
            state = update(state, invalid_count=state.invalid_count + 1,
                           transcript=[e.model_dump(mode="json") for e in (*state.transcript, notice)],
                           next_action=None)
            return (failed(state, InvestigationFailed(kind="provider_error"))
                    if state.invalid_count >= self.limits.consecutive_invalid else state)
        if isinstance(action, Say):
            if after_transfer(state.previous_step):
                return completed(state, "handoff", action.message.text)
            return update(state, invalid_count=0, next_action=InvestigationAction(kind="finalize"))
        if (state.tool_steps >= self.limits.steps_per_turn or not self.fits(state, (action.call,))
                or len(state.transcript) + 2 > self.limits.transcript_messages):
            return failed(state, InvestigationFailed(kind="loop_ceiling"))
        if action.query is not None:
            if state.retrieval_index >= min(self.limits.knowledge_steps, 16):
                return failed(state, InvestigationFailed(kind="loop_ceiling"))
            target: Literal["retrieve", "read", "propose"] = "retrieve"
        else:
            target = "propose" if TOOL_KINDS[ToolName(action.call.name)] == ToolKind.WRITE else "read"
        return update(state, invalid_count=0, tool_steps=state.tool_steps + 1,
                      next_action=InvestigationAction(kind=target, call=action.call, step=action.step,
                                                     query=action.query),
                      transcript=[e.model_dump(mode="json") for e in (*state.transcript, action.call)],
                      pending_tool=PendingToolOutcome(call_id=action.call.call_id, name=action.call.name,
                                                      read_only=names[action.call.name]))

    async def dispatch(self, name: str, state: InvestigationState) -> InvestigationState:
        action = state.next_action
        if action is None or action.call is None:
            return failed(state, InvestigationFailed(kind="tool_error"))
        if name == "retrieve":
            if action.query is None:
                return failed(state, InvestigationFailed(kind="tool_error"))
            found = await self.knowledge.search(action.query, conversation_id=state.run_id,
                                                 index=state.retrieval_index, deadline=self.deadline)
            result = ToolResult(call_id=action.call.call_id, content=found.content, is_error=found.is_error)
            if not found.is_error:
                refs = self.actions.evidence(state.retrieval_index)
                by_id = {r.evidence_id: r for r in (*state.recorded_evidence, *refs)}
                state = update(state, retrieved_steps=[*state.retrieved_steps, state.retrieval_index],
                               recorded_evidence=[r.model_dump(mode="json") for r in by_id.values()])
            state = update(state, retrieval_index=state.retrieval_index + 1)
        else:
            produced = (await self.actions.propose(state, deadline=self.deadline) if name == "propose"
                        else await self.actions.read(state, deadline=self.deadline))
            if isinstance(produced, AwaitingApproval):
                return update(state, pending_tool=None, terminal=produced)
            result = ToolResult.model_validate_json(produced.model_dump_json())
        if result.call_id != action.call.call_id or not self.fits(state, (result,)):
            return failed(state, InvestigationFailed(kind="tool_error"))
        return update(state, next_action=None, pending_tool=None, previous_step=action.step or state.previous_step,
                      transcript=[e.model_dump(mode="json") for e in (*state.transcript, result)])

    def compile(self, saver: BaseCheckpointSaver[int] | None = None) -> CompiledStateGraph[Any, Any, Any, Any]:
        graph = StateGraph(GraphEnvelope, input_schema=GraphInput)
        for name in GRAPH_NODES:
            async def invoke(data: GraphEnvelope, node: str = name) -> dict[str, Any]:
                return await self.node(node, data)
            graph.add_node(name, RunnableLambda(invoke))
            graph.add_conditional_edges(name, route, list(GRAPH_TARGETS))
        graph.add_edge(START, GRAPH_ENTRY)
        return graph.compile(checkpointer=saver)


def route(data: GraphEnvelope) -> str:
    if data.state.terminal is not None:
        return END
    action = data.state.next_action
    return action.kind if action is not None else "investigate"
