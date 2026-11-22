"""Sequential, bounded investigation. Checkpointed actions carry no execution authority."""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import json
import time
from typing import Any, Literal, Protocol, TypedDict
from uuid import uuid5

from langchain_core.runnables import RunnableLambda
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import ValidationError, field_validator
from pydantic_core import to_jsonable_python
from sqlalchemy.exc import DBAPIError

from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.context import fit
from policyops.orchestration.mechanics import Notice, Say, Use, after_transfer, parse, report_terminal
from policyops.orchestration.minimal import AGENT_NAMESPACE, AGENT_OPERATION
from policyops.orchestration.ports import KnowledgePort, ModelPort
from policyops.orchestration.profile import InvestigationProfile
from policyops.orchestration.state import (
    AwaitingApproval,
    InvestigationAction,
    InvestigationCompleted,
    InvestigationFailed,
    InvestigationState,
    InvestigationStopped,
    state_from_json,
)
from policyops.orchestration.stops import InvestigationStop, stop_reason
from policyops.persistence.database import PersistenceError
from policyops.persistence.runs import Fenced
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.tool_diagnostics import argument_issue
from policyops.runtime.spec import Stopped, investigation_message_id, unconfirmed_stop
from policyops.telemetry import annotate, count, observed
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
from policyops_contracts.stops import StopDetails, StopReason


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
    return state_from_json(state.model_dump(mode="json") | to_jsonable_python(fields))


def failed(state: InvestigationState, kind: InvestigationFailed) -> InvestigationState:
    return update(state, terminal=kind)


def completed(state: InvestigationState, kind: Literal["answered", "abstained", "handoff"],
              text: str) -> InvestigationState:
    return update(state, final_text=text, terminal=InvestigationCompleted(
        kind=kind, message_id=investigation_message_id(state.workspace_id, state.run_id)))


def stopped(state: InvestigationState, reason: StopReason, *, usage_unconfirmed: bool = False) -> InvestigationState:
    return update(state, terminal=InvestigationStopped(details=StopDetails(
        reason=reason, usage_unconfirmed=usage_unconfirmed or reason == StopReason.USAGE_UNCONFIRMED,
        cleanup_unconfirmed=state.cleanup_unconfirmed)))


@dataclass
class InvestigationGraph:
    model: ModelPort
    knowledge: KnowledgePort
    actions: Actions
    policy: PolicyContext
    limits: AgentLimits
    deadline: float
    fence: Callable[[], None]
    resource_stop: Callable[[], StopReason | None] = lambda: None
    accounting: Stopped | None = None
    profile: InvestigationProfile = InvestigationProfile.BASELINE

    def fitted(self, state: InvestigationState, entries: tuple[Entry, ...] = ()) -> InvestigationState:
        return fit(state, self.policy, self.limits, append=entries, profile=self.profile)

    @observed("graph.node")
    async def node(self, name: str, data: GraphEnvelope) -> dict[str, Any]:
        annotate(node=name, run_id=data.state.run_id)
        self.fence()
        state = self.fitted(data.state)
        if state.terminal is not None:
            return {"state": state.model_dump(mode="json")}
        if time.monotonic() >= self.deadline and state.terminal is None:
            state = stopped(state, StopReason.ACTIVE_TIME)
        elif state.step_count >= state.max_steps:
            state = failed(state, InvestigationFailed(kind="loop_ceiling"))
        else:
            state = update(state, step_count=state.step_count + 1, current_node=name)
            try:
                reason = self.resource_stop() if name != "finalize" else None
                if reason is not None:
                    state = stopped(state, reason)
                elif name == "investigate":
                    state = await self.investigate(state)
                elif name == "finalize":
                    kind, text = self.actions.finalize(state, deadline=self.deadline)
                    state = completed(state, kind, text)
                else:
                    state = await self.dispatch(name, state)
            except InvestigationStop as error:
                state = update(state, terminal=InvestigationStopped(details=error.details))
            except AccountingUnconfirmed as error:
                self.accounting = unconfirmed_stop(error.report)
                state = update(state, terminal=InvestigationStopped(details=self.accounting.details))
            except (Fenced, DBAPIError, PersistenceError):
                raise
            except asyncio.CancelledError:
                # Executor-owned cancellation must propagate so lease loss cannot become a success.
                raise
            except Exception as error:
                annotate(exception_type=type(error).__name__, error_code="boundary_error")
                count("errors", error_code="boundary_error")
                state = failed(state, InvestigationFailed(kind="provider_error" if name == "investigate"
                                                          else "tool_error"))
        self.fence()
        if time.monotonic() >= self.deadline and state.terminal is None:
            state = stopped(state, StopReason.ACTIVE_TIME)
        if isinstance(state.terminal, InvestigationFailed):
            annotate(outcome="failed")
        elif isinstance(state.terminal, InvestigationStopped):
            annotate(outcome="refused")
        return {"state": self.fitted(state).model_dump(mode="json")}

    async def investigate(self, state: InvestigationState) -> InvestigationState:
        if state.model_calls >= self.limits.model_calls:
            return stopped(state, StopReason.CALL_CAP)
        state = self.fitted(state)
        if state.terminal is not None:
            return state
        key = uuid5(AGENT_NAMESPACE, f"{state.run_id}:{state.model_calls}")
        try:
            report = await self.model.complete(prompt.request(self.policy, self.limits, state.transcript,
                facts_text=json.dumps([f.model_dump(mode="json") for f in state.critical_facts], ensure_ascii=False,
                                      separators=(",", ":")), profile=self.profile),
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
            return stopped(state, StopReason.ACTIVE_TIME,
                           usage_unconfirmed=any(r.fate == "unresolved" for r in report.attempts))
        if report.reason in {"replayed_unresolved", "replayed_dispatching"}:
            return stopped(state, StopReason.USAGE_UNCONFIRMED, usage_unconfirmed=True)
        if (report.reason or "").startswith("replayed_"):
            return failed(state, InvestigationFailed(kind="provider_result_unavailable"))
        ending = report_terminal(report)
        if ending is not None and (ending[0] in {"budget", "deadline", "contract_gap"}
                or report.reason in {"blocked_by_overrun", "blocked_by_contract", "count_cap",
                                     "count_rejected", "count_not_admitted"}):
            reason = (StopReason.ACTIVE_TIME if ending[0] == "deadline" else
                      StopReason.CONTRACT_BLOCK if ending[0] == "contract_gap" else stop_reason(report.reason))
            return stopped(state, reason, usage_unconfirmed=any(r.fate == "unresolved" for r in report.attempts))
        if any(record.fate == "unresolved" for record in report.attempts):
            return stopped(state, StopReason.USAGE_UNCONFIRMED, usage_unconfirmed=True)
        if ending is not None:
            return failed(state, InvestigationFailed(kind="provider_error"))
        if not isinstance(report.result, ModelResult):
            return failed(state, InvestigationFailed(kind="provider_error"))
        result = report.result
        names = {t.name: t.read_only for t in prompt.catalog(self.profile).all_tools()}
        detailed = self.profile is InvestigationProfile.TOOL_CONTRACT_V1
        action: Notice | Say | Use
        # Control tools use the same one-call gate, then their own schema (never retail to_agent_step).
        if (result.outcome == "completed" and len(result.tool_calls) == 1 and not result.text
                and result.tool_calls[0].name == prompt.FINISH):
            if after_transfer(state.previous_step):
                action = Notice("protocol_violation")
            else:
                try:
                    answer = GroundedAnswer.model_validate_json(result.tool_calls[0].arguments_json)
                except ValidationError as error:
                    action = Notice("invalid_arguments", argument_issue(prompt.FINISH, error) if detailed else None)
                else:
                    return update(state, invalid_count=0,
                                  next_action=InvestigationAction(kind="finalize", answer=answer))
        else:
            action = parse(result, names=names, retail=True, previous=state.previous_step,
                           detailed_tool_errors=detailed)
        if isinstance(action, Notice):
            notice = (RuntimeNotice(code=action.code) if action.argument_issue is None else
                      RuntimeNotice(code=action.code, argument_issue=action.argument_issue))
            state = update(state, invalid_count=state.invalid_count + 1,
                           next_action=None)
            state = self.fitted(state, (notice,))
            if state.terminal is not None:
                return state
            return (stopped(state, StopReason.INVALID_CAP)
                    if state.invalid_count >= self.limits.consecutive_invalid else state)
        if isinstance(action, Say):
            if after_transfer(state.previous_step):
                return completed(state, "handoff", action.message.text)
            return update(state, invalid_count=0, next_action=InvestigationAction(kind="finalize"))
        if state.tool_steps >= self.limits.steps_per_turn:
            return stopped(state, StopReason.TOOL_CAP)
        if state.model_calls >= self.limits.model_calls:
            return stopped(state, StopReason.CALL_CAP)
        if action.query is not None:
            if state.retrieval_index >= min(self.limits.knowledge_steps, 16):
                return stopped(state, StopReason.RETRIEVAL_CAP)
            target: Literal["retrieve", "read", "propose"] = "retrieve"
        else:
            target = "propose" if TOOL_KINDS[ToolName(action.call.name)] == ToolKind.WRITE else "read"
        state = update(state, invalid_count=0, tool_steps=state.tool_steps + 1,
                      next_action=InvestigationAction(kind=target, call=action.call, step=action.step,
                                                     query=action.query),
                      pending_tool=PendingToolOutcome(call_id=action.call.call_id, name=action.call.name,
                                                      read_only=names[action.call.name]))
        return self.fitted(state, (action.call,))

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
                               evidence_call_ids=([*state.evidence_call_ids, action.call.call_id]
                                                  if refs else state.evidence_call_ids),
                               recorded_evidence=[r.model_dump(mode="json") for r in by_id.values()])
            state = update(state, retrieval_index=state.retrieval_index + 1)
        else:
            produced = (await self.actions.propose(state, deadline=self.deadline) if name == "propose"
                        else await self.actions.read(state, deadline=self.deadline))
            if isinstance(produced, AwaitingApproval):
                facts = state.critical_facts
                if produced.fact is not None:
                    kept = tuple(f for f in facts if (f.proposal_id, f.proposal_version) != (
                        produced.fact.proposal_id, produced.fact.proposal_version))
                    if len(kept) >= 64:
                        return stopped(state, StopReason.CONTEXT_LIMIT)
                    facts = (*kept, produced.fact)
                return update(state, pending_tool=None, terminal=produced, critical_facts=facts)
            result = ToolResult.model_validate_json(produced.model_dump_json())
        if result.call_id != action.call.call_id:
            return failed(state, InvestigationFailed(kind="tool_error"))
        state = self.fitted(state, (result,))
        if state.terminal is not None:
            return state
        return update(state, next_action=None, pending_tool=None, previous_step=action.step or state.previous_step)

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
