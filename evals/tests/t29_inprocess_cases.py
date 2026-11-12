"""Real registered factory/T20/wire suspension, visible inputs and owned cleanup."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import gc
import json
from pathlib import Path
import threading
import time
from typing import Any, cast
from uuid import uuid4
import weakref

import pytest

from policyops.orchestration.ports import agent_model_port
from policyops_contracts.conversation import ToolResult, UserMessage
from policyops_evals.harness.adapter import (
    FACTORY_NAME,
    OpenSession,
    ToolRequest,
    ToolReturnRequest,
    TrialBudget,
    TrialSlot,
    TurnEnded,
    UserTurnRequest,
    register,
    trial,
)
from policyops_evals.harness.inprocess import BridgeRefused, InProcessAgentBridge, OwnedLoop
from policyops_evals.harness.tools import map_upstream_tools

from .t29_support import CANARY, Routes, books, tool


def fixture() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(
        (Path(__file__).parents[1] / "fixtures/t29-fictional-v1.json").read_text(encoding="utf-8")))


def environment() -> Any:
    from tau2.domains.retail.data_model import RetailDB
    from tau2.domains.retail.environment import get_environment
    data = fixture()
    return get_environment(db=RetailDB.model_validate(data["db"]), policy=data["policy"])


def opened(outputs: list[Any]) -> tuple[InProcessAgentBridge, OpenSession, Routes]:
    from policyops_contracts.conversation import AgentMessage, PolicyContext
    from policyops_contracts.digest import text_sha256
    ledger, binding, _ = books()
    routes = Routes(outputs)
    bridge = InProcessAgentBridge(ledger.configuration, agent_model_port(ledger, binding, routes.providers))
    env = environment()
    request = OpenSession(uuid4(), PolicyContext(domain="retail", source="harness_domain_policy",
        text=env.get_policy(), sha256=text_sha256(env.get_policy())),
        map_upstream_tools(env.get_tools()).catalog, AgentMessage(text="Visible greeting."))
    return bridge, request, routes


def test_registered_factory_drops_poison_and_releases_it_with_real_bridge() -> None:
    from tau2.data_model.message import AssistantMessage
    from tau2.data_model.message import UserMessage as UpUser
    from tau2.runner.build import build_agent

    class Poison:
        def __getattribute__(self, name: str) -> Any:
            raise AssertionError("hidden accessed")

        def __repr__(self) -> str:
            raise AssertionError("hidden rendered")

        def __reduce__(self) -> Any:
            raise AssertionError("hidden serialized")

    ledger, binding, _ = books()
    routes = Routes(["Visible answer."])
    bridge = InProcessAgentBridge(ledger.configuration, agent_model_port(ledger, binding, routes.providers))
    register()
    poison = Poison()
    ref = weakref.ref(poison)
    env = environment()
    env_ref = weakref.ref(env)
    with trial(TrialSlot(uuid4(), "retail", bridge, TrialBudget(time.monotonic() + 10, time.monotonic, 0, 2))):
        agent = build_agent(FACTORY_NAME, env, task=poison, llm="ignored")
    del poison, env
    gc.collect()
    assert ref() is None and env_ref() is None
    try:
        state = agent.get_init_state([AssistantMessage(role="assistant", content="Visible opener.")])
        reply, _ = agent.generate_next_message(UpUser(role="user", content="Hello."), state)
        assert reply.content == "Visible answer."
        assert CANARY not in json.dumps(routes.seen)
        assert CANARY not in bridge._agent.snapshot().model_dump_json()  # type: ignore[union-attr]
    finally:
        agent.stop()
    assert not bridge.runtime.thread.is_alive()


def test_real_tool_suspension_result_and_followup_preserve_call_and_wire_sequences() -> None:
    bridge, request, routes = opened([tool("get_user_details", {"user_id": "fictional_user_001"}),
                                      "The user exists.", "Followup."])
    try:
        config = bridge.open(request, seconds=10)
        event = bridge.user_turn(UserTurnRequest(request.session_id, 1, 0, UserMessage(text="Check user.")), seconds=9)
        assert isinstance(event, ToolRequest) and event.call.call_id == "call_t29"
        assert len([r for r in routes.seen if r["kind"] == "create"]) == 1
        assert bridge._turn is not None and not bridge._turn.done()  # suspended, no environment retained
        with pytest.raises(BridgeRefused, match="call_mismatch"):
            bridge.tool_return(ToolReturnRequest(request.session_id, 2, ToolResult(call_id="wrong", content="x")),
                               seconds=9)
        event = bridge.tool_return(ToolReturnRequest(request.session_id, 2,
            ToolResult(call_id="call_t29", content="{\"user_id\":\"fictional_user_001\"}")), seconds=9)
        assert isinstance(event, TurnEnded) and event.outcome.message is not None
        assert event.outcome.message.text == "The user exists."
        assert event.outcome.config_sha256 == config.config_sha256 and event.seq == 2
        with pytest.raises(BridgeRefused, match="sequence_mismatch"):
            bridge.tool_return(ToolReturnRequest(request.session_id, 2,
                ToolResult(call_id="call_t29", content="duplicate")), seconds=9)
        event = bridge.user_turn(UserTurnRequest(request.session_id, 3, 1, UserMessage(text="Again.")), seconds=9)
        assert isinstance(event, TurnEnded) and event.outcome.turn == 1
        assert bridge._events.empty()
    finally:
        bridge.close(request.session_id, seconds=2)
    assert not bridge.runtime.thread.is_alive()
    with pytest.raises(BridgeRefused):
        bridge.user_turn(UserTurnRequest(request.session_id, 4, 2, UserMessage(text="Late.")), seconds=1)


def test_foreign_and_out_of_order_requests_do_no_provider_work() -> None:
    bridge, request, routes = opened([])
    try:
        bridge.open(request, seconds=10)
        for invalid in (UserTurnRequest(uuid4(), 1, 0, UserMessage(text="x")),
                        UserTurnRequest(request.session_id, 2, 0, UserMessage(text="x")),
                        UserTurnRequest(request.session_id, 1, 1, UserMessage(text="x"))):
            with pytest.raises(BridgeRefused):
                bridge.user_turn(invalid, seconds=1)
        bridge.close(uuid4(), seconds=1)
        assert not bridge._closed and not routes.seen
    finally:
        bridge.close(request.session_id, seconds=2)


def test_setup_failure_releases_owned_loop_and_preserves_original_error() -> None:
    bridge, request, _ = opened([])
    request = replace(request, catalog=request.catalog.model_copy(update={"knowledge_tool": True}))
    with pytest.raises(ValueError, match="knowledge"):
        bridge.open(request, seconds=10)
    assert not bridge.runtime.thread.is_alive()
    bridge.close(request.session_id, seconds=1)


def test_cancel_at_tool_suspension_leaves_unknown_and_releases_loop() -> None:
    bridge, request, _ = opened([tool("get_user_details", {"user_id": "fictional_user_001"})])
    bridge.open(request, seconds=10)
    event = bridge.user_turn(UserTurnRequest(request.session_id, 1, 0, UserMessage(text="Check.")), seconds=9)
    assert isinstance(event, ToolRequest)
    bridge.close(request.session_id, seconds=2)
    snapshot = bridge._agent.snapshot()  # type: ignore[union-attr]
    assert snapshot.terminal == "cancelled" and snapshot.pending_tool is not None
    assert not bridge.runtime.thread.is_alive() and bridge._pending is None


def test_loop_start_failure_closes_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[asyncio.AbstractEventLoop] = []
    original = asyncio.new_event_loop

    def new() -> asyncio.AbstractEventLoop:
        loop = original()
        created.append(loop)
        return loop

    def fail(self: threading.Thread) -> None:
        raise RuntimeError("scripted_start_failure")

    monkeypatch.setattr(asyncio, "new_event_loop", new)
    monkeypatch.setattr(threading.Thread, "start", fail)
    with pytest.raises(RuntimeError, match="scripted_start_failure"):
        OwnedLoop()
    assert len(created) == 1 and created[0].is_closed()


def test_thread_construction_failure_releases_acquired_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(asyncio, "new_event_loop", lambda: loop)

    def fail(**kwargs: Any) -> Any:
        raise RuntimeError("thread_construction_failure")

    monkeypatch.setattr(threading, "Thread", fail)
    with pytest.raises(RuntimeError, match="thread_construction_failure"):
        OwnedLoop()
    assert loop.is_closed()


@pytest.mark.parametrize("end_by", ["close", "deadline"])
def test_inflight_provider_cancellation_wakes_waiter_and_keeps_usage_hold(end_by: str) -> None:
    started, cancelled = threading.Event(), threading.Event()

    async def hang(request: Any) -> Any:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    ledger, binding, store = books()
    bridge, request, _ = opened([])
    routes = Routes([hang])
    bridge.configuration = ledger.configuration
    bridge.model = agent_model_port(ledger, binding, routes.providers)
    bridge.open(request, seconds=10)
    errors: list[Exception] = []

    def wait() -> None:
        try:
            bridge.user_turn(UserTurnRequest(request.session_id, 1, 0, UserMessage(text="Hello")),
                             seconds=0.5 if end_by == "deadline" else 9)
        except Exception as error:
            errors.append(error)

    caller = threading.Thread(target=wait)
    caller.start()
    try:
        assert started.wait(3)
        if end_by == "deadline":
            caller.join(2)
        bridge.close(request.session_id, seconds=2)
        caller.join(2)
        assert not caller.is_alive() and len(errors) == 1 and isinstance(errors[0], BridgeRefused)
        assert cancelled.is_set() and not bridge.runtime.thread.is_alive()
        assert len(store.attempts) == 1
        attempt = next(iter(store.attempts.values()))
        assert attempt.state == "unresolved" and attempt.actual_usd is None
        assert all(scope.held_usd > 0 for scope in store.scopes.values())
        assert [entry["kind"] for entry in routes.seen] == ["count", "create"]
    finally:
        bridge.close(request.session_id, seconds=2)
        caller.join(2)
