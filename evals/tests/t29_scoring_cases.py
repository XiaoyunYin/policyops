"""Fictional end-to-end upstream environment/orchestrator/evaluator, all SDK calls scripted."""

from __future__ import annotations

from contextlib import contextmanager
import json
import time
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import httpx2
import pytest

from policyops.orchestration.ports import agent_model_port
from policyops_contracts.model import ToolResultPart, ToolUsePart
from policyops_evals.harness.actors import ActorBindings, ActorCeilings, ActorRefused, actor_request
from policyops_evals.harness.adapter import FACTORY_NAME, TrialBudget, TrialSlot, register, trial
from policyops_evals.harness.inprocess import InProcessAgentBridge, OwnedLoop
from policyops_evals.studies.scoring import JudgeRefused, score, validate_judgement

from .t29_inprocess_cases import environment, fixture
from .t29_support import CANARY, Routes, books, judgement, tool


@contextmanager
def bound(outputs: list[Any], *, calls: int = 20) -> Any:
    ledger, binding, store = books(calls=calls)
    routes = Routes(outputs)
    loop = OwnedLoop()
    actors = ActorBindings(ledger, binding, routes.providers, loop=loop, deadline=time.monotonic() + 20,
                           ceilings=ActorCeilings(12, 1), upstream_seed=7)
    try:
        with actors.install():
            yield actors, routes, store
    finally:
        loop.close(seconds=2)


def simulate(actors: ActorBindings, *, change: bool = True, assertions: bool = True) -> tuple[Any, Any, Any]:
    from tau2.data_model.tasks import Task
    from tau2.orchestrator.orchestrator import Orchestrator
    from tau2.runner.build import build_agent
    from tau2.user.user_simulator import UserSimulator

    data = fixture()
    task = Task.model_validate(data["task"])
    if not assertions:
        task.evaluation_criteria.nl_assertions = []
    env = environment()
    bridge = InProcessAgentBridge(actors.ledger.configuration,
        agent_model_port(actors.ledger, actors.binding, actors.providers), loop=actors.loop)
    register()
    try:
        with trial(TrialSlot(uuid4(), "retail", bridge, TrialBudget(actors.deadline, time.monotonic, 0, 2))):
            agent = build_agent(FACTORY_NAME, env, task=task, llm="ignored")
        user = UserSimulator(llm=actors.config("simulator").model, instructions=str(task.user_scenario),
                             llm_args={"reasoning_effort": actors.config("simulator").effort},
                             global_guidelines_override=data["simulator_guidelines"])
        orchestrator = Orchestrator(domain="retail", agent=agent, user=user, environment=env, task=task,
                                    max_steps=12, seed=7, timeout=15)
        simulation = orchestrator.run()
        # Evaluator must start from the original DB, not the mutated environment.
        from tau2.domains.retail.data_model import RetailDB
        result = score(simulation, task, actors=actors,
                       env_kwargs={"db": RetailDB.model_validate(data["db"]), "policy": data["policy"]})
        return result, bridge, simulation
    finally:
        if bridge._connection is not None:
            bridge.close(bridge._connection.session_id, seconds=2)


@pytest.mark.parametrize(("change", "met", "expected"), [(True, True, 1), (False, True, 0), (True, False, 0)])
def test_fictional_scored_trajectory(change: bool, met: bool, expected: int,
                                     monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    from policyops_contracts import wire
    encoded: list[bytes] = []
    original = wire.encode_payload

    def encode(frame: Any) -> bytes:
        payload = original(frame)
        encoded.append(payload)
        return payload

    monkeypatch.setattr(wire, "encode_payload", encode)
    data = fixture()
    outputs = [data["visible_request"]]
    if change:
        action = data["task"]["evaluation_criteria"]["actions"][0]
        outputs.append(tool(action["name"], action["arguments"]))
    outputs += ["Your address has been changed.", "###STOP###", judgement(met=met)]
    with bound(outputs) as (actors, routes, store):
        result, bridge, simulation = simulate(actors, change=change)
        assert result.error is None and result.composite.reward == expected
        assert result.environment.db_check.db_match is change
        assert result.composite.nl_assertions[0].met is met
        creates = [r["body"] for r in routes.seen if r["kind"] == "create"]
        assert all(body["model"] == "gpt-6-luna" for body in creates)
        agent_bodies = [body for body in creates if "Fictional shop" in body["instructions"]]
        assert agent_bodies and all(CANARY not in json.dumps(body) for body in agent_bodies)
        assert any(CANARY in json.dumps(body) for body in creates)  # simulator is allowed hidden instructions
        assert CANARY not in bridge._agent.snapshot().model_dump_json()
        assert encoded and all(CANARY.encode() not in payload for payload in encoded)
        assert CANARY not in caplog.text
        assert all(a.state == "settled" for a in store.attempts.values())
        assert {a.intent.actor for a in store.attempts.values()} == {"agent", "simulator", "judge"}
        assert routes.closed == len(routes.seen)
        assert simulation.termination_reason.value == "user_stop"


@pytest.mark.parametrize("bad", ["{}", '{"results":[]}', '{"results":null}', "not json",
    judgement("Other assertion"), judgement().replace("true", '"true"'),
    '{"results":[],"results":[]}', json.dumps({"results": json.loads(judgement())["results"] * 2})])
def test_judge_coverage_failures_preserve_db_and_billed_usage(bad: str) -> None:
    data = fixture()
    action = data["task"]["evaluation_criteria"]["actions"][0]
    with bound([data["visible_request"], tool(action["name"], action["arguments"]),
                "Your address has been changed.", "###STOP###", bad]) as (actors, _, store):
        result, _, _ = simulate(actors)
        assert result.environment.db_check.db_match and result.composite is None
        assert result.error == "scoring_unavailable"
        judges = [a for a in store.attempts.values() if a.intent.actor == "judge"]
        assert len(judges) == 1 and judges[0].actual_usd is not None and judges[0].state == "settled"


def test_no_assertions_needs_no_judge() -> None:
    data = fixture()
    with bound([data["visible_request"], "No change.", "###STOP###"]) as (actors, routes, store):
        result, _, _ = simulate(actors, change=False, assertions=False)
        assert result.composite is not None and result.composite.nl_assertions == []
        assert all(a.intent.actor != "judge" for a in store.attempts.values())
        assert not routes.outputs


def test_judge_validator_rejects_oversize_and_wrong_types() -> None:
    for text in ("x" * 65_537, "[" * 1000, judgement().replace("true", "1"),
                 judgement().replace("Fictional scripted judgement.", "")):
        with pytest.raises(JudgeRefused):
            validate_judgement(text, ("The agent confirmed the address change.",))


def test_bindings_are_exclusive_restore_on_failure_and_suppress_content() -> None:
    from loguru import logger
    from tau2.evaluator import evaluator_nl_assertions as nl
    from tau2.user import user_simulator as user
    from tau2.utils import llm_utils
    original = (nl.generate, user.generate, llm_utils.generate, nl.DEFAULT_LLM_NL_ASSERTIONS)
    lines: list[str] = []
    sink = logger.add(lines.append, format="{message}")
    try:
        with pytest.raises(RuntimeError, match="scripted"), bound([]) as (actors, _, _):
            logger.bind(secret=CANARY).error(CANARY)
            with pytest.raises(ActorRefused, match="already_bound"), actors.install():
                pass
            for generate in (llm_utils.generate, llm_utils._generate_once, llm_utils.completion):
                with pytest.raises(ActorRefused, match="unbound_generation"):
                    generate()
            raise RuntimeError("scripted")
        assert not lines
        assert (nl.generate, user.generate, llm_utils.generate, nl.DEFAULT_LLM_NL_ASSERTIONS) == original
        logger.info("restored")
        assert len(lines) == 1 and "restored" in lines[0]
    finally:
        logger.remove(sink)


def test_shared_budget_exhaustion_stops_simulator_agent_and_judge() -> None:
    from tau2.data_model.message import SystemMessage, UserMessage
    from tau2.user import user_simulator

    from policyops_contracts.conversation import UserMessage as VisibleUser
    from policyops_evals.harness.adapter import TurnEnded, UserTurnRequest

    from .t29_inprocess_cases import opened

    with bound(["Visible user."], calls=1) as (actors, routes, store):
        args = dict(model="gpt-6-luna", messages=[SystemMessage(role="system", content="Hidden simulator."),
            UserMessage(role="user", content="Hello")], reasoning_effort="low", seed=7,
            call_name="user_simulator_response")
        assert user_simulator.generate(**args).content == "Visible user."
        with pytest.raises(ActorRefused, match="budget"):
            user_simulator.generate(**args)
        bridge, request, _ = opened([])
        bridge.model = agent_model_port(actors.ledger, actors.binding, actors.providers)
        bridge.configuration = actors.ledger.configuration
        try:
            bridge.open(request, seconds=10)
            event = bridge.user_turn(UserTurnRequest(request.session_id, 1, 0, VisibleUser(text="Hello")), seconds=9)
            assert isinstance(event, TurnEnded) and event.outcome.terminal == "budget"
            with actors.judging(lambda text: None), pytest.raises(ActorRefused, match="budget"):
                actors._generate("judge", model="gpt-6-luna", messages=args["messages"],
                                 reasoning_effort="low", call_name="nl_assertions_eval")
        finally:
            bridge.close(request.session_id, seconds=2)
        assert len(store.attempts) == 1 and len(routes.seen) == 2


def test_actor_conversion_preserves_roles_and_tool_ids_and_refuses_audio() -> None:
    from tau2.data_model.message import AssistantMessage, SystemMessage, ToolCall, ToolMessage, UserMessage
    history = [SystemMessage(role="system", content="Instructions"), UserMessage(role="user", content="Hi"),
        AssistantMessage(role="assistant", tool_calls=[ToolCall(id="c1", name="read", arguments={"id": "x"})]),
        ToolMessage(role="tool", id="c1", content="result", error=True)]
    request, _ = actor_request(history, None, max_output=256)
    call, result = request.messages[1].parts[0], request.messages[2].parts[0]
    assert isinstance(call, ToolUsePart) and isinstance(result, ToolResultPart)
    assert call.call_id == result.call_id == "c1" and result.is_error
    history[1] = UserMessage(role="user", content="text", is_audio=True)
    with pytest.raises(ActorRefused, match="audio"):
        actor_request(history, None, max_output=256)


def test_unavailable_judge_retains_environment_and_unknown_billing_hold() -> None:
    data = fixture()
    action = data["task"]["evaluation_criteria"]["actions"][0]
    with bound([data["visible_request"], tool(action["name"], action["arguments"]),
                "Your address has been changed.", "###STOP###",
                httpx2.ReadError("scripted-unavailable")]) as (actors, _, store):
        result, _, _ = simulate(actors)
        assert result.environment.db_check.db_match and result.composite is None
        judges = [a for a in store.attempts.values() if a.intent.actor == "judge"]
        assert len(judges) == 1 and judges[0].state == "unresolved" and judges[0].actual_usd is None
        assert all(scope.held_usd > 0 for scope in store.scopes.values())


def test_oversized_transcript_refused_before_judge_or_upstream_rendering() -> None:
    task = SimpleNamespace(evaluation_criteria=SimpleNamespace(nl_assertions=[]))
    for messages in ([SimpleNamespace(content="x" * 200_001)],
                     [SimpleNamespace(content="x" * 100_000)] * 2,
                     [SimpleNamespace(content="x")] * 257):
        with pytest.raises(JudgeRefused, match="transcript_bounds"):
            score(SimpleNamespace(messages=messages), task, actors=cast(Any, None))


def test_actor_setup_failure_restores_every_patched_symbol(monkeypatch: pytest.MonkeyPatch) -> None:
    from tau2.evaluator import evaluator_nl_assertions as nl
    from tau2.user import user_simulator as user
    from tau2.utils import llm_utils
    ledger, binding, _ = books()
    loop = OwnedLoop()
    actors = ActorBindings(ledger, binding, lambda: Routes([]).providers(), loop=loop,
                           deadline=time.monotonic() + 10, ceilings=ActorCeilings(1, 1))
    saved = nl.generate, user.generate, llm_utils.generate, nl.DEFAULT_LLM_NL_ASSERTIONS_ARGS

    def fail(actor: Any) -> Any:
        raise RuntimeError("setup_failure")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(actors, "config", fail)
            with pytest.raises(RuntimeError, match="setup_failure"), actors.install():
                pass
        assert (nl.generate, user.generate, llm_utils.generate, nl.DEFAULT_LLM_NL_ASSERTIONS_ARGS) == saved
        with actors.install():
            pass  # exclusivity lock was released too
    finally:
        loop.close(seconds=2)


@pytest.mark.parametrize("extra", [{"model": "unknown"}, {"temperature": 0}, {"seed": 8},
                                   {"reasoning_effort": "high"}])
def test_unapproved_actor_arguments_refuse_before_count_or_inference(extra: dict[str, Any]) -> None:
    from tau2.data_model.message import SystemMessage, UserMessage
    from tau2.user import user_simulator
    with bound([]) as (_, routes, _):
        args = dict(model="gpt-6-luna", messages=[SystemMessage(role="system", content="Simulator."),
            UserMessage(role="user", content="Hi")], reasoning_effort="low", seed=7,
            call_name="user_simulator_response") | extra
        with pytest.raises(ActorRefused, match="actor_arguments"):
            user_simulator.generate(**args)
        assert not routes.seen
