"""Offline composed graph edges, action admission, bounded recovery and strict finalization."""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
import json
from pathlib import Path
import time
from typing import Any, Literal, cast
from uuid import uuid4

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
)
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.errors import GraphRecursionError, NodeCancelledError
import pytest
from sqlalchemy.exc import DBAPIError

from policyops.budget.config import DEFAULT_ACTORS, ChatActor, Configuration
from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.adapters import InvestigationAdapters
from policyops.orchestration.graph import ABSTENTION, InvestigationGraph, failed, update
from policyops.orchestration.minimal import prompt_sha256
from policyops.orchestration.state import (
    AwaitingApproval,
    CheckpointStateVersionError,
    InvestigationAction,
    InvestigationFailed,
    InvestigationState,
    InvestigationStopped,
    state_from_json,
)
from policyops.persistence import checkpoint_json as codec
from policyops.providers.calls import CallReport
from policyops.providers.serialize import prepare
from policyops.runtime import investigation as runtime
from policyops.runtime.spec import Outcome, Retry, StepContext
from policyops_contracts.conversation import AgentLimits, ToolResult, UserMessage
from policyops_contracts.grounding import CitedQuote, ReconcileOutcome, RecordOutcome
from policyops_contracts.model import ModelRequest, ToolCall
from policyops_contracts.proposal import EvidenceRef
from policyops_contracts.stops import StopReason
from policyops_testing.agent_fakes import FakeKnowledge, ScriptedModel, calls, fictional_policy, report, result, says
from tests.unit.test_grounding import CORPUS, RUN, WS, Reader, answer, quote, synthetic, validator


class RecordingSaver(BaseCheckpointSaver[int]):
    """All graph outputs pass the production closed codec, while persistence is explicitly in-memory."""

    def __init__(self) -> None:
        super().__init__(serde=codec.CheckpointJsonSerializer())
        self.memory = InMemorySaver(serde=self.serde)

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        return await self.memory.aget_tuple(config)

    async def aput(self, config: RunnableConfig, checkpoint: Checkpoint, metadata: CheckpointMetadata,
                   new_versions: ChannelVersions) -> RunnableConfig:
        codec.encode_checkpoint(checkpoint)
        codec.metadata(metadata)
        return await self.memory.aput(config, checkpoint, metadata, new_versions)

    async def aput_writes(self, config: RunnableConfig, writes: Sequence[tuple[str, Any]], task_id: str,
                          task_path: str = "") -> None:
        checked = [(channel, codec.channel_value(channel, value, pending=True)) for channel, value in writes]
        await self.memory.aput_writes(config, checked, task_id, task_path)


def initial(**fields: Any) -> InvestigationState:
    return update(InvestigationState(state_version=2, workspace_id=WS, case_id=uuid4(), run_id=RUN,
                                     graph_sha256="1" * 64, prompt_sha256="2" * 64, config_sha256="3" * 64,
                                     transcript=(UserMessage(text="Help with a refund."),)), **fields)


@dataclass
class Actions:
    nodes: list[str] = field(default_factory=list)
    error: Literal["raise", "wrong_id", "known"] | None = None

    async def read(self, state: InvestigationState, *, deadline: float) -> ToolResult:
        self.nodes.append("read")
        if self.error == "raise":
            raise RuntimeError("must never enter transcript/checkpoint")
        assert state.next_action is not None and state.next_action.call is not None
        return ToolResult(call_id="wrong" if self.error == "wrong_id" else state.next_action.call.call_id,
                          content="safe error" if self.error else "read result", is_error=self.error == "known")

    async def propose(self, state: InvestigationState, *, deadline: float) -> AwaitingApproval | ToolResult:
        self.nodes.append("propose")
        return AwaitingApproval(proposal_id=uuid4(), proposal_version=1)

    def evidence(self, index: int) -> tuple[EvidenceRef, ...]:
        return ()

    def finalize(self, state: InvestigationState, *, deadline: float
                 ) -> tuple[Literal["answered", "abstained"], str]:
        self.nodes.append("finalize")
        return "abstained", ABSTENTION


def graph(model: ScriptedModel, actions: Actions | None = None, *, limits: AgentLimits | None = None,
          saver: BaseCheckpointSaver[int] | None = None) -> tuple[InvestigationGraph, Actions]:
    actions = actions or Actions()
    return InvestigationGraph(model, FakeKnowledge(), actions, fictional_policy(),
                               limits or AgentLimits(knowledge_steps=16), time.monotonic() + 60, lambda: None), actions


def run(model: ScriptedModel, state: InvestigationState | None = None, actions: Actions | None = None,
        **options: Any) -> tuple[InvestigationState, Actions]:
    build, actions = graph(model, actions, **options)
    final = asyncio.run(build.compile(RecordingSaver()).ainvoke(
        {"state": (state or initial()).model_dump(mode="json")},
        {"configurable": {"thread_id": "test"}, "recursion_limit": 66}, durability="sync"))
    return state_from_json(final["state"]), actions


ABSTAIN = {"v": "policyops.grounded-answer/v1", "outcome": "abstain", "assertions": [],
           "abstention": {"reason": "insufficient_evidence", "detail": None}}


@pytest.mark.parametrize("name,args,node", [
    ("search_policy", {"query": "refunds"}, "retrieve"),
    ("calculate", {"expression": "1+1"}, "read"),
    ("cancel_pending_order", {"order_id": "#W1234567", "reason": "no longer needed"}, "propose"),
])
def test_edges(name: str, args: dict[str, Any], node: str) -> None:
    model = ScriptedModel([calls(name, args), calls(prompt.FINISH, ABSTAIN)])
    final, actions = run(model)
    assert final.terminal is not None
    assert final.terminal.kind == ("awaiting_approval" if node == "propose" else "abstained")
    assert len(model.keys) == (1 if node == "propose" else 2)
    if node != "retrieve":
        assert actions.nodes[0] == node
    else:
        assert final.retrieved_steps == (0,) and final.retrieval_index == 1
    assert final.pending_tool is None


@pytest.mark.parametrize("bad", [
    report(result(calls=(ToolCall(call_id="1", name="calculate", arguments_json='{"expression":"1"}'),
                         ToolCall(call_id="2", name="calculate", arguments_json='{"expression":"2"}')))),
    report(result(text="hello", calls=(ToolCall(call_id="1", name=prompt.FINISH,
                                               arguments_json=json.dumps(ABSTAIN)),))),
    calls("unknown", {}), calls(prompt.FINISH, {}), report(result()),
])
def test_invalid_replies_dispatch_nothing_then_recover(bad: CallReport) -> None:
    model = ScriptedModel([bad, calls(prompt.FINISH, ABSTAIN)])
    final, actions = run(model)
    assert final.terminal is not None and final.terminal.kind == "abstained"
    assert actions.nodes == ["finalize"] and final.model_calls == 2
    assert final.transcript[-1].kind == "notice"


def test_invalid_ceiling_and_plain_prose_abstains() -> None:
    final, actions = run(ScriptedModel([calls("unknown", {}), calls("unknown", {})]))
    assert isinstance(final.terminal, InvestigationStopped) and final.terminal.details.reason == StopReason.INVALID_CAP
    assert final.model_calls == final.invalid_count == 2 and not actions.nodes
    final, _ = run(ScriptedModel([says("Uncited policy assertion must not be delivered.")]))
    assert final.final_text == ABSTENTION


def test_transfer_requires_exact_handoff_and_is_not_a_proposal() -> None:
    from policyops_contracts.retail import HANDOFF_MESSAGE
    final, actions = run(ScriptedModel([calls("transfer_to_human_agents", {"summary": "Needs help."}),
                                       says(HANDOFF_MESSAGE)]))
    assert final.terminal is not None and final.terminal.kind == "handoff"
    assert actions.nodes == ["read"] and final.final_text == HANDOFF_MESSAGE


@pytest.mark.parametrize("error,kind", [("raise", "tool_error"), ("wrong_id", "tool_error"), ("known", "abstained")])
def test_tool_errors_keep_unknown_until_matched(error: Any, kind: str) -> None:
    final, _ = run(ScriptedModel([calls("calculate", {"expression": "1"}), calls(prompt.FINISH, ABSTAIN)]),
                   actions=Actions(error=error))
    assert final.terminal is not None and final.terminal.kind == kind
    assert (final.pending_tool is not None) == (kind == "tool_error")
    assert "must never enter" not in final.model_dump_json()


def test_persisted_ceiling_refuses_new_work_after_resume() -> None:
    model = ScriptedModel([])
    final, actions = run(model, initial(step_count=32))
    assert final.terminal is not None and final.terminal.kind == "loop_ceiling"
    assert not model.requests and not actions.nodes


def test_saved_model_cap_and_duplicate_evidence_identities_are_refused() -> None:
    model = ScriptedModel([])
    final, _ = run(model, initial(model_calls=16))
    assert final.terminal is not None and final.terminal.kind == "stopped" and not model.keys
    for changes in ({"retrieved_steps": [0, 0]}, {"retrieved_steps": [-1]},
                    {"input_message_ids": [str(RUN), str(RUN)]}):
        with pytest.raises(ValueError):
            initial(**changes)


def test_recursion_guard_terminal_update_roundtrips_closed_codec() -> None:
    async def execute() -> None:
        model = ScriptedModel([calls("calculate", {"expression": "1"})])
        build, _ = graph(model)
        saver = RecordingSaver()
        compiled = build.compile(saver)
        config: RunnableConfig = {"configurable": {"thread_id": "recursion"}, "recursion_limit": 1}
        with pytest.raises(GraphRecursionError):
            await compiled.ainvoke({"state": initial().model_dump(mode="json")}, config, durability="sync")
        saved = await saver.aget_tuple(config)
        assert saved is not None
        state = state_from_json(saved.checkpoint["channel_values"]["state"])
        terminal = failed(state, InvestigationFailed(kind="loop_ceiling"))
        await compiled.aupdate_state(config, {"state": terminal.model_dump(mode="json")}, as_node="finalize")
        resumed = await compiled.ainvoke(None, config, durability="sync")
        assert resumed["state"]["terminal"]["kind"] == "loop_ceiling" and len(model.keys) == 1
    asyncio.run(execute())


@pytest.mark.parametrize("report_value,kind", [(CallReport(None, "failed", "replayed_settled"),
                                                "provider_result_unavailable"),
                                               (CallReport(None, "budget", "usd_cap"), "stopped"),
                                               (CallReport(None, "deadline", "deadline"), "stopped")])
def test_typed_provider_failures(report_value: CallReport, kind: str) -> None:
    model = ScriptedModel([report_value])
    final, _ = run(model)
    assert final.terminal is not None and final.terminal.kind == kind and len(model.keys) == 1


def test_provider_cancellation_and_external_cancellation_cleanup() -> None:
    async def provider_cancel(request: ModelRequest) -> CallReport:
        raise asyncio.CancelledError
    final, _ = run(ScriptedModel([provider_cancel]))
    assert final.terminal is not None and final.terminal.kind == "provider_cancelled"

    async def external() -> None:
        entered, cleaned = asyncio.Event(), asyncio.Event()
        async def waiting(request: ModelRequest) -> CallReport:
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()
            raise AssertionError("unreachable")
        build, _ = graph(ScriptedModel([waiting]))
        task = asyncio.create_task(build.compile(RecordingSaver()).ainvoke(
            {"state": initial().model_dump(mode="json")}, {"configurable": {"thread_id": "cancel"}},
            durability="sync"))
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleaned.is_set()
    asyncio.run(external())


@pytest.mark.parametrize("node", ["read", "propose"])
def test_executor_retries_node_cancellation_from_compiled_graph(node: str, monkeypatch: pytest.MonkeyPatch) -> None:
    class Cancelled(Actions):
        async def read(self, state: InvestigationState, *, deadline: float) -> ToolResult:
            raise asyncio.CancelledError

        async def propose(self, state: InvestigationState, *, deadline: float) -> AwaitingApproval | ToolResult:
            raise asyncio.CancelledError

    selected = (calls("calculate", {"expression": "1"}) if node == "read" else
                calls("cancel_pending_order", {"order_id": "#W1234567", "reason": "no longer needed"}))
    build, _ = graph(ScriptedModel([selected]), Cancelled())
    wrapped: list[NodeCancelledError] = []

    async def execute(self: runtime.InvestigationExecutor, context: StepContext) -> Outcome:
        try:
            await build.compile(RecordingSaver()).ainvoke(
                {"state": initial().model_dump(mode="json")}, {"configurable": {"thread_id": node}},
                durability="sync")
        except NodeCancelledError as error:
            wrapped.append(error)
            raise
        raise AssertionError("node cancellation did not propagate")

    monkeypatch.setattr(runtime.InvestigationExecutor, "_execute", execute)
    executor = object.__new__(runtime.InvestigationExecutor)
    assert executor.execute(cast(StepContext, None)) == Retry("investigation_node_cancelled")
    assert len(wrapped) == 1


@pytest.mark.parametrize("boundary", ["node", "checkpoint"])
def test_simulated_crash_signal_propagates_through_compiled_graph(boundary: str) -> None:
    class SimulatedCrash(BaseException):
        pass

    class CrashActions(Actions):
        async def propose(self, state: InvestigationState, *, deadline: float) -> AwaitingApproval | ToolResult:
            raise SimulatedCrash

    class CrashSaver(RecordingSaver):
        async def aput(self, config: RunnableConfig, checkpoint: Checkpoint, metadata: CheckpointMetadata,
                       new_versions: ChannelVersions) -> RunnableConfig:
            saved = await super().aput(config, checkpoint, metadata, new_versions)
            state = checkpoint["channel_values"].get("state")
            if state is not None and state["step_count"] == 1:
                raise SimulatedCrash
            return saved

    build, _ = graph(ScriptedModel([
        calls("cancel_pending_order", {"order_id": "#W1234567", "reason": "no longer needed"})]), CrashActions())
    with pytest.raises(SimulatedCrash):
        asyncio.run(build.compile(CrashSaver() if boundary == "checkpoint" else RecordingSaver()).ainvoke(
            {"state": initial().model_dump(mode="json")}, {"configurable": {"thread_id": boundary}},
            durability="sync"))


def test_graph_digest_is_source_independent_and_tracks_state_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    original = runtime.graph_digest()

    def no_source_reads(self: Path) -> bytes:
        raise AssertionError("graph identity must not read source bytes")

    monkeypatch.setattr(Path, "read_bytes", no_source_reads)
    assert runtime.graph_digest() == original

    class ChangedState(InvestigationState):
        new_state_field: bool = False

    with monkeypatch.context() as changed:
        changed.setattr(runtime, "InvestigationState", ChangedState)
        assert runtime.graph_digest() != original
    assert runtime.graph_digest() == original
    monkeypatch.setattr(runtime, "GRAPH_VERSION", "policyops.investigation-graph/v999")
    assert runtime.graph_digest() != original


def test_old_version_never_dispatches() -> None:
    state = initial().model_dump(mode="json") | {"state_version": 0}
    build, _ = graph(ScriptedModel([]))
    with pytest.raises((CheckpointStateVersionError, ValueError)):
        asyncio.run(build.compile().ainvoke({"state": state}))


def test_transient_database_failure_survives_checkpoint_error_recording() -> None:
    class Unavailable(Actions):
        async def read(self, state: InvestigationState, *, deadline: float) -> ToolResult:
            raise DBAPIError("synthetic statement", {}, RuntimeError("sensitive diagnostic must not persist"))
    model = ScriptedModel([calls("calculate", {"expression": "1"})])
    with pytest.raises(DBAPIError):
        run(model, actions=Unavailable())


@pytest.mark.parametrize("configuration", [Configuration(), Configuration(actors={
    **DEFAULT_ACTORS, "agent": ChatActor("agent", "claude-haiku-5-5", "low")})])
def test_graph_prompt_prepares_and_differs_from_baseline(configuration: Configuration) -> None:
    prepare(prompt.request(fictional_policy(), AgentLimits(knowledge_steps=16), (UserMessage(text="q"),)),
            configuration, "agent")
    assert prompt.digest() != prompt_sha256(knowledge_tool=True)


def test_real_gateway_tool_port_keeps_customer_and_call_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.gateway.steps import StepResult
    from policyops_contracts.agent import AgentStep, ToolCallStep
    from policyops_contracts.conversation import AgentToolCall
    from policyops_contracts.retail import GetUserDetails
    from policyops_testing.gateway_cases import Setup, W, gateway_for
    gateway, retail, _ = gateway_for(Setup())
    adapter = object.__new__(InvestigationAdapters)
    adapter.gateway = gateway
    observed: list[AgentStep] = []
    original = gateway.step

    def step(value: AgentStep, *, previous: AgentStep | None, sequence: int) -> StepResult:
        observed.append(value)
        return original(value, previous=previous, sequence=sequence)

    monkeypatch.setattr(gateway, "step", step)

    async def execute() -> None:
        def selected(call_id: str, user_id: str) -> InvestigationState:
            return initial(step_count=2, next_action=InvestigationAction(
                kind="read", call=AgentToolCall(call_id=call_id, name="get_user_details",
                                               arguments_json=json.dumps({"user_id": user_id})),
                step=ToolCallStep(call=GetUserDetails(user_id=user_id))))

        state = selected("good", W.user_id)
        reply = await adapter.read(state, deadline=time.monotonic() + 10)
        assert reply.call_id == "good" and not reply.is_error and len(retail.calls) == 1
        assert state.next_action is not None and observed[-1] is state.next_action.step
        state = selected("foreign", W.other_user)
        refused = await adapter.read(state, deadline=time.monotonic() + 10)
        assert refused.call_id == "foreign" and refused.is_error and len(retail.calls) == 1
        assert state.next_action is not None and observed[-1] is state.next_action.step
    asyncio.run(execute())


def test_context_claim_property_is_read_only() -> None:
    from policyops.persistence.runs import ClaimToken
    from policyops.runtime.worker import Context
    token = ClaimToken(uuid4(), uuid4(), uuid4(), uuid4(), uuid4(), 1, 1)
    context = Context(cast(Any, None), token, uuid4(), cast(Any, None))
    assert context.claim_token is token
    with pytest.raises(AttributeError):
        context.claim_token = token  # type: ignore[misc]


@pytest.mark.parametrize("bad", ["missing", "mixed", "uncited", "stale", "unobserved", "valid", "ambiguous"])
def test_strict_finalize_uses_actual_validator_and_fixed_abstention(bad: str) -> None:
    reader = Reader()
    reader.add(0, synthetic(0, ["Refunds take ten days."]))
    if bad == "stale":
        reader.current = uuid4()
    citations: tuple[CitedQuote, ...] = (quote(0, "E1", "Refunds"),)
    if bad == "missing":
        citations = (quote(1, "E1", "Refunds"),)
    elif bad == "mixed":
        citations += (quote(0, "E1", "fabricated quote"),)
    elif bad == "uncited":
        citations = ()
    value = answer((False, citations))  # forcing policy_dependent=True must close T14's label escape
    recorded: list[object] = []

    class Recorder:
        def record(self, bundle: Any, **kwargs: Any) -> RecordOutcome:
            recorded.append(bundle)
            return RecordOutcome(status="record_ambiguous" if bad in {"ambiguous", "unobserved"} else "recorded",
                                 committed="unknown" if bad in {"ambiguous", "unobserved"} else "observed",
                                 claims=1, distinct=1, inserted=0 if bad in {"ambiguous", "unobserved"} else 1)

        def reconcile(self, bundle: Any, **kwargs: Any) -> ReconcileOutcome:
            assert bundle is recorded[0]
            return ReconcileOutcome(status="recorded" if bad == "ambiguous" else "not_observed_yet",
                                    generation_current=True)

    adapter = object.__new__(InvestigationAdapters)
    adapter.validator = validator(reader)
    adapter.recorder = cast(Any, Recorder())
    adapter.gateway = cast(Any, type("Gateway", (), {"scope": type("Scope", (), {"run": type("Run", (), {
        "run_id": RUN, "workspace_id": WS})()})()})())
    adapter.retrieval_scope = cast(Any, type("Scope", (), {"corpus_key": CORPUS})())
    adapter.references = {}
    state = initial(retrieved_steps=[0], next_action=InvestigationAction(kind="finalize", answer=value))
    kind, text = adapter.finalize(state, deadline=100)
    if bad in {"valid", "ambiguous"}:
        assert kind == "answered" and text.startswith("A claim. [") and len(recorded) == 1
    else:
        assert (kind, text) == ("abstained", ABSTENTION)
        assert not recorded or bad == "unobserved"
