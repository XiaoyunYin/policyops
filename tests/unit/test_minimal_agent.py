"""T20 minimal agent baseline, offline: owned conversation state, fixed runtime notices with chronological history
(prepared by the real T11 serializers for both providers), exact call/result binding, unknown tool outcomes,
limits, cancellation and configuration identity. Scripted ports only: no provider, network, key or ledger."""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Awaitable, Callable
import inspect
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

import pytest

from policyops.budget.config import DEFAULT_ACTORS, ChatActor, Configuration
from policyops.budget.ledger import Ledger, RunBinding
from policyops.orchestration import minimal, ports
from policyops.orchestration.minimal import (
    AGENT_NAMESPACE,
    AGENT_OPERATION,
    NOTICE_TEXT,
    POLICY_HEADING,
    AgentConfigurationError,
    ConversationBusy,
    ConversationClosed,
    DeadlineInvalid,
    MinimalAgent,
    TranscriptInvariant,
    agent_config,
    build_request,
    prompt_text,
    provider_messages,
    retail_catalog,
)
from policyops.orchestration.ports import agent_model_port
from policyops.providers.calls import CallReport, Providers
from policyops.providers.serialize import prepare
from policyops_contracts.conversation import (
    AgentLimits,
    AgentMessage,
    AgentToolCall,
    Entry,
    KnowledgeResult,
    PolicyContext,
    RuntimeNotice,
    ToolCatalog,
    ToolDescriptor,
    ToolResult,
    UserMessage,
)
from policyops_contracts.model import TextPart, ToolCall, ToolResultPart, ToolUsePart
from policyops_contracts.retail import HANDOFF_MESSAGE
from policyops_testing.agent_fakes import (
    FakeKnowledge,
    FakeTools,
    ScriptedModel,
    calls,
    fictional_policy,
    report,
    result,
    says,
)


LUNA = Configuration()
HAIKU = Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "claude-haiku-5-5", "low")})
ACCOUNT_SCHEMA = json.dumps({"type": "object", "additionalProperties": False, "required": ["account_id"],
                             "properties": {"account_id": {"type": "string"}}}, sort_keys=True)
ACCOUNT = ToolDescriptor(name="get_account", description="Read an account (fictional).",
                         parameters_schema_json=ACCOUNT_SCHEMA, read_only=True)
CLOSE = ToolDescriptor(name="close_account", description="Close an account (fictional).",
                       parameters_schema_json=ACCOUNT_SCHEMA, read_only=False)
BANKING = ToolCatalog(mode="descriptor", tools=(ACCOUNT, CLOSE), knowledge_tool=True)
ORDER = {"order_id": "#W0000001"}


def later(seconds: float = 30.0) -> float:
    return time.monotonic() + seconds


class Built:
    def __init__(self, script: list[Any], *, catalog: ToolCatalog | None = None, limits: AgentLimits | None = None,
                 configuration: Configuration = LUNA, tools: FakeTools | None = None,
                 knowledge: FakeKnowledge | None = None, policy: PolicyContext | None = None,
                 conversation_id: UUID | None = None) -> None:
        self.catalog = catalog or retail_catalog()
        self.policy = policy or fictional_policy("banking_knowledge" if self.catalog.mode == "descriptor"
                                                 else "retail")
        if limits is None and self.catalog.knowledge_tool:
            limits = AgentLimits(knowledge_steps=10)
        self.model = ScriptedModel(script)
        self.tools = tools or FakeTools()
        self.knowledge = knowledge or (FakeKnowledge() if self.catalog.knowledge_tool else None)
        self.conversation_id = conversation_id or uuid4()
        self.config = agent_config(self.policy, self.catalog, configuration, limits)
        self.agent = MinimalAgent(self.config, self.policy, self.catalog, conversation_id=self.conversation_id,
                                  model=self.model, tools=self.tools, knowledge=self.knowledge,
                                  configuration=configuration, env="test")

    def turn(self, text: str = "Hello, please check order #W0000001.", seconds: float = 30.0) -> Any:
        return asyncio.run(self.agent.turn(UserMessage(text=text), deadline=later(seconds)))

    def kinds(self) -> list[str]:
        return [entry.kind for entry in self.agent.snapshot().transcript]


def roles(messages: Any) -> list[tuple[str, list[str]]]:
    return [(m.role, [p.kind for p in m.parts]) for m in messages]


# -- construction -------------------------------------------------------------------------------------------------

C512 = Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "gpt-6-luna", "low", max_output=512)})


def _refusals() -> list[tuple[str, Callable[[dict[str, Any]], None], str]]:
    def change_config(**update: Any) -> Callable[[dict[str, Any]], None]:
        return lambda k: k.update(config=k["config"].model_copy(update=update))

    def bypass(k: dict[str, Any]) -> None:  # constructed without validation: re-validated and refused
        limits = AgentLimits.model_construct(**{**dict(AgentLimits()), "model_calls": 0})
        k["config"] = type(k["config"]).model_construct(**{**dict(k["config"]), "limits": limits})

    def output_cap(k: dict[str, Any]) -> None:
        k.update(configuration=C512, config=agent_config(k["policy"], k["catalog"], C512))

    return [
        ("policy digest", change_config(policy_sha256="1" * 64), "bind this policy"),
        ("catalog digest", change_config(catalog_sha256="1" * 64), "bind this tool catalog"),
        ("prompt digest", change_config(prompt_sha256="1" * 64), "bind this prompt"),
        ("actor digest", lambda k: k.update(configuration=HAIKU), "bind this agent actor"),
        ("domain", change_config(domain="banking_knowledge"), "bind this policy"),
        ("knowledge port without the tool", lambda k: k.update(knowledge=FakeKnowledge()), "go together"),
        ("knowledge steps without the tool", change_config(limits=AgentLimits(knowledge_steps=1)), "knowledge_steps"),
        ("output cap over the actor maximum", output_cap, "maximum"),
        ("fictional policy outside tests", lambda k: k.update(env=None), "fictional"),
        ("arbitrary model port", lambda k: k.update(model=object()), "model port"),
        ("conversation id", lambda k: k.update(conversation_id="not-a-uuid"), "UUID"),
        ("unvalidated configuration", bypass, "invalid"),
    ]


@pytest.mark.parametrize(("case", "change", "match"), _refusals(), ids=[case for case, _, _ in _refusals()])
def test_every_construction_refusal_happens_before_any_port_call(
        case: str, change: Callable[[dict[str, Any]], None], match: str) -> None:
    built = Built([])
    kwargs: dict[str, Any] = {"config": built.config, "policy": built.policy, "catalog": built.catalog,
                              "conversation_id": uuid4(), "model": built.model, "tools": built.tools,
                              "knowledge": None, "configuration": LUNA, "env": "test"}
    change(kwargs)
    with pytest.raises(AgentConfigurationError, match=match):
        MinimalAgent(**kwargs)
    assert built.model.requests == [] and built.tools.calls == []


def test_retail_mode_uses_exactly_the_typed_tools_and_knowledge_needs_its_port_and_steps() -> None:
    tools = retail_catalog().tools
    edited = ToolCatalog(mode="retail", tools=tools[:-1])
    policy = fictional_policy()
    with pytest.raises(AgentConfigurationError, match="typed retail tools"):
        MinimalAgent(agent_config(policy, edited, LUNA), policy, edited, conversation_id=uuid4(),
                     model=ScriptedModel([]), tools=FakeTools(), knowledge=None, configuration=LUNA, env="test")
    banking = fictional_policy("banking_knowledge")
    for limits, knowledge in ((AgentLimits(), FakeKnowledge()), (AgentLimits(knowledge_steps=10), None)):
        with pytest.raises(AgentConfigurationError):
            MinimalAgent(agent_config(banking, BANKING, LUNA, limits), banking, BANKING, conversation_id=uuid4(),
                         model=ScriptedModel([]), tools=FakeTools(), knowledge=knowledge, configuration=LUNA,
                         env="test")
    assert Built([], catalog=BANKING).config.limits.knowledge_steps == 10  # banking enables it explicitly
    assert Built([]).config.limits.knowledge_steps == 0                     # the retail default has none


def test_a_descriptor_schema_outside_the_provider_subset_is_refused_at_construction() -> None:
    loose = ToolDescriptor(name="loose", description="No additionalProperties (fictional).",
                           parameters_schema_json='{"type":"object","properties":{"a":{"type":"string"}}}',
                           read_only=True)
    with pytest.raises(AgentConfigurationError, match="prepared"):
        Built([], catalog=ToolCatalog(mode="descriptor", tools=(loose,)))


class _ProductionTools:
    async def execute(self, call: AgentToolCall, *, deadline: float) -> ToolResult:
        raise AssertionError("never called at construction")


def test_the_production_model_port_is_explicit_and_test_ports_need_the_test_environment() -> None:
    ledger = Ledger(cast(Any, None), LUNA)
    factory: Callable[[], Providers] = lambda: Providers(credentials={}, transport=lambda p: cast(Any, None))  # noqa: E731
    port = agent_model_port(ledger, RunBinding(uuid4()), factory)
    assert ports.is_agent_model_port(port) and not ports.is_agent_model_port(ScriptedModel([]))
    with pytest.raises(TypeError):
        agent_model_port(cast(Any, None), RunBinding(uuid4()), factory)
    with pytest.raises(TypeError):
        agent_model_port(ledger, cast(Any, uuid4()), factory)
    policy = PolicyContext(domain="retail", source="harness_domain_policy", text="Fictional.",
                           sha256=fictional_policy(text="Fictional.").sha256)
    config = agent_config(policy, retail_catalog(), LUNA)
    # The explicit adapter needs no test environment and sends nothing at construction (no store, no factory call).
    MinimalAgent(config, policy, retail_catalog(), conversation_id=uuid4(), model=port, tools=_ProductionTools(),
                 knowledge=None, configuration=LUNA, env=None)
    for model, tools in ((ScriptedModel([]), cast(Any, object())), (port, FakeTools())):
        with pytest.raises(AgentConfigurationError, match="test"):
            MinimalAgent(config, policy, retail_catalog(), conversation_id=uuid4(), model=model, tools=tools,
                         knowledge=None, configuration=LUNA, env=None)


def test_public_signatures_take_no_open_keywords_or_any() -> None:
    targets: list[Callable[..., Any]] = [MinimalAgent.__init__, MinimalAgent.turn, ports.ModelPort.complete,
                                         ports.ToolPort.execute, ports.KnowledgePort.search, ports.agent_model_port]
    for target in targets:
        signature = inspect.signature(target)
        assert all(p.kind is not p.VAR_KEYWORD and p.kind is not p.VAR_POSITIONAL
                   for p in signature.parameters.values()), target
        assert "Any" not in str(signature), target
    for module in (minimal, ports):
        source = ast.parse(Path(cast(str, module.__file__)).read_text(encoding="utf-8"))
        assert not any(isinstance(node, ast.arg) and node.annotation is not None
                       and "Any" in ast.unparse(node.annotation) for node in ast.walk(source)), module


# -- conversations --------------------------------------------------------------------------------------------

def test_a_tool_call_result_and_message_form_one_chronological_turn_with_fresh_keys() -> None:
    built = Built([calls("get_order_details", ORDER), says("Your order is pending.")])
    outcome = built.turn()
    assert outcome.message == AgentMessage(text="Your order is pending.") and outcome.terminal is None
    assert [e.kind for e in outcome.appended] == ["user", "tool_call", "tool_result", "agent"]
    assert (outcome.model_calls, outcome.counts_claimed, outcome.inferences_dispatched) == (2, 2, 2)
    assert built.tools.calls == [AgentToolCall(call_id="call_1", name="get_order_details",
                                               arguments_json='{"order_id":"#W0000001"}')]
    assert built.model.keys == [uuid5(AGENT_NAMESPACE, f"{built.conversation_id}:{i}") for i in (0, 1)]
    assert built.model.operations == [AGENT_OPERATION] * 2
    assert roles(built.model.requests[1].messages) == [("user", ["text"]), ("assistant", ["tool_use"]),
                                                       ("user", ["tool_result"])]
    built.model.script.append(says("Anything else?"))
    second = built.turn("Thanks.")
    assert second.turn == 1 and built.model.keys[-1] == uuid5(AGENT_NAMESPACE, f"{built.conversation_id}:2")
    assert built.agent.snapshot().turns == 2 and built.agent.snapshot().model_calls == 3


def test_transfer_then_the_exact_handoff_message_ends_the_conversation() -> None:
    built = Built([calls("transfer_to_human_agents", {"summary": "Out of scope request."}), says(HANDOFF_MESSAGE)])
    outcome = built.turn()
    assert (outcome.terminal, outcome.message) == ("handoff", None)
    assert outcome.appended[-1] == AgentMessage(text=HANDOFF_MESSAGE)
    with pytest.raises(ConversationClosed):
        built.turn("Hello?")
    assert built.model.requests[-1:] and len(built.model.requests) == 2


def test_retail_protocol_violations_become_notices_and_the_model_may_recover() -> None:
    built = Built([says(HANDOFF_MESSAGE), says("How can I help?")])
    assert built.turn().message == AgentMessage(text="How can I help?")
    assert built.kinds() == ["user", "notice", "agent"]
    after = Built([calls("transfer_to_human_agents", {"summary": "Out of scope."}), says("One moment."),
                   says(HANDOFF_MESSAGE)], limits=AgentLimits(consecutive_invalid=2))
    assert after.turn().terminal == "handoff"
    assert after.kinds() == ["user", "tool_call", "tool_result", "notice", "agent"]


INVALID = [
    ("several calls", result(calls=(ToolCall(call_id="a", name="calculate", arguments_json='{"expression":"1+1"}'),
                                    ToolCall(call_id="b", name="calculate", arguments_json='{"expression":"2"}'))),
     "several_tool_calls"),
    ("text with a call", result(text="Checking.", calls=(ToolCall(call_id="a", name="get_order_details",
                                                                  arguments_json='{"order_id":"#W0000001"}'),)),
     "text_with_tool_call"),
    ("no action", result(text=None), "empty_reply"),
    ("unknown tool (T11)", result("invalid_output", reason_code="unknown_tool"), "unknown_tool"),
    ("schema (T11)", result("invalid_output", reason_code="tool_arguments_schema"), "invalid_arguments"),
    ("other invalid output", result("invalid_output", reason_code="text_too_large"), "invalid_output"),
    ("retail DTO arguments", result(calls=(ToolCall(call_id="a", name="get_order_details",
                                                    arguments_json='{"order_id":"W1"}'),)), "invalid_arguments"),
    ("structured answer", result("structured"), "invalid_output"),
    ("message over the bound", result(text="x" * 4001), "invalid_output"),
]


@pytest.mark.parametrize(("case", "value", "code"), INVALID, ids=[case for case, _, _ in INVALID])
def test_an_invalid_reply_leaves_only_a_fixed_notice_then_recovery_prepares_for_both_providers(
        case: str, value: Any, code: str) -> None:
    for configuration in (LUNA, HAIKU):
        built = Built([report(value), says("Done.")], configuration=configuration)
        outcome = built.turn()
        assert outcome.message == AgentMessage(text="Done.") and outcome.invalid_steps == 1
        notice = outcome.appended[1]
        assert notice == RuntimeNotice(code=code)  # type: ignore[arg-type]
        dumped = built.agent.snapshot().model_dump_json()
        assert "Checking." not in dumped and '"a"' not in dumped and "W1" not in dumped  # nothing reflected
        (question, notice_part) = built.model.requests[1].messages[0].parts
        assert isinstance(question, TextPart) and isinstance(notice_part, TextPart)
        assert notice_part.text == NOTICE_TEXT[code]  # type: ignore[index]
        prepare(built.model.requests[1], configuration, "agent")


def test_consecutive_invalid_replies_are_terminal_and_keep_question_then_notices_in_order() -> None:
    built = Built([says(""), report(result(text=None)), report(result("invalid_output", reason_code="unknown_tool"))],
                  limits=AgentLimits(consecutive_invalid=3))
    outcome = built.turn("Where is my order?")
    assert (outcome.terminal, outcome.detail, outcome.invalid_steps) == ("invalid_steps", "unknown_tool", 3)
    (message,) = built.model.requests[2].messages
    assert [p.text for p in message.parts if isinstance(p, TextPart)] == [
        "Where is my order?", NOTICE_TEXT["empty_reply"], NOTICE_TEXT["empty_reply"]]
    with pytest.raises(ConversationClosed):
        built.turn()


def test_a_tool_result_stays_first_after_its_call_and_notices_follow_it_for_both_providers() -> None:
    for configuration in (LUNA, HAIKU):
        built = Built([calls("get_order_details", ORDER), says(""), says("It is pending."), says("Bye.")],
                      configuration=configuration)
        built.turn()
        request = built.model.requests[2]
        assert roles(request.messages) == [("user", ["text"]), ("assistant", ["tool_use"]),
                                           ("user", ["tool_result", "text"])]
        prepare(request, configuration, "agent")
        built.turn("Thanks, that is all.")
        final = built.model.requests[3]
        assert roles(final.messages)[-2:] == [("assistant", ["text"]), ("user", ["text"])]
        prepare(final, configuration, "agent")


BAD_HISTORIES: list[tuple[str, list[Entry]]] = [
    ("result not first", [UserMessage(text="q"), AgentToolCall(call_id="c", name="x", arguments_json="{}"),
                          RuntimeNotice(code="empty_reply"), ToolResult(call_id="c", content="r")]),
    ("result after text", [UserMessage(text="q"), AgentMessage(text="a"), ToolResult(call_id="c", content="r")]),
    ("duplicate result", [UserMessage(text="q"), AgentToolCall(call_id="c", name="x", arguments_json="{}"),
                          ToolResult(call_id="c", content="r"), ToolResult(call_id="c", content="r")]),
    ("result of another call", [UserMessage(text="q"), AgentToolCall(call_id="c", name="x", arguments_json="{}"),
                                ToolResult(call_id="d", content="r")]),
    ("call without result", [UserMessage(text="q"), AgentToolCall(call_id="c", name="x", arguments_json="{}")]),
    ("starts with the agent", [AgentMessage(text="a"), UserMessage(text="q")]),
    ("ends with the agent", [UserMessage(text="q"), AgentMessage(text="a")]),
    ("two agent actions in a row", [UserMessage(text="q"), AgentMessage(text="a"), AgentMessage(text="b"),
                                    UserMessage(text="q")]),
]


@pytest.mark.parametrize(("case", "history"), BAD_HISTORIES, ids=[case for case, _ in BAD_HISTORIES])
def test_an_inconsistent_history_is_refused_never_reordered(case: str, history: list[Entry]) -> None:
    with pytest.raises(TranscriptInvariant):
        provider_messages(history)


def test_a_consistent_history_maps_one_to_one_in_append_order() -> None:
    history: list[Entry] = [UserMessage(text="q"), RuntimeNotice(code="empty_reply"),
                            AgentToolCall(call_id="c", name="x", arguments_json="{}"),
                            ToolResult(call_id="c", content="r", is_error=True), RuntimeNotice(code="unknown_tool"),
                            AgentMessage(text="a"), UserMessage(text="q2")]
    messages = provider_messages(history)
    assert roles(messages) == [("user", ["text", "text"]), ("assistant", ["tool_use"]),
                               ("user", ["tool_result", "text"]), ("assistant", ["text"]), ("user", ["text"])]
    assert messages[2].parts[0] == ToolResultPart(call_id="c", content="r", is_error=True)
    assert messages[1].parts[0] == ToolUsePart(call_id="c", name="x", arguments_json="{}")


# -- provider outcomes --------------------------------------------------------------------------------------------

OUTCOMES = [
    (CallReport(None, "budget", "run_calls"), "budget", "run_calls"),
    (CallReport(None, "deadline", "deadline"), "deadline", "deadline"),
    (CallReport(None, "contract_gap", "no server credential for openai"), "contract_gap", None),
    (CallReport(None, "failed", "count.http_429"), "count_not_admitted", "count.http_429"),
    (CallReport(None, "failed", "count_not_admitted"), "count_not_admitted", "count_not_admitted"),
    (CallReport(None, "failed", "replayed_settled"), "provider_failed", "replayed_settled"),
    (CallReport(None, "failed", "ledger_conflict"), "provider_failed", "ledger_conflict"),
    (CallReport(None, "failed", "timeout"), "provider_failed", "timeout"),
    (report(result("refused", stop_reason="refusal")), "model_refused", None),
    (report(result("truncated", stop_reason="max_output_tokens")), "model_truncated", "max_output_tokens"),
    (report(result("failed", reason_code="provider_failed")), "provider_failed", "provider_failed"),
    (report(result("contract_gap", reason_code="usage_incomplete")), "contract_gap", "usage_incomplete"),
    (CallReport(None, "result", None), "provider_failed", "report_invalid"),
]


@pytest.mark.parametrize(("value", "terminal", "detail"), OUTCOMES, ids=[o[1] + ":" + str(o[2]) for o in OUTCOMES])
def test_every_report_status_and_outcome_maps_to_its_terminal(value: CallReport, terminal: str,
                                                              detail: str | None) -> None:
    built = Built([value])
    outcome = built.turn()
    assert (outcome.terminal, outcome.detail, outcome.message) == (terminal, detail, None)
    assert built.kinds() == ["user"]  # refusal and truncation are never a message
    with pytest.raises(ConversationClosed):  # no re-key after a terminal (a replayed key stays replayed)
        built.turn()


# -- limits ---------------------------------------------------------------------------------------------------

def test_call_and_step_limits_are_terminal_and_an_excess_call_is_neither_kept_nor_executed() -> None:
    built = Built([calls("get_order_details", ORDER)], limits=AgentLimits(model_calls=1))
    assert built.turn().terminal == "model_calls_exhausted"
    steps = Built([calls("get_order_details", ORDER), calls("calculate", {"expression": "1+1"}, "call_2")],
                  limits=AgentLimits(steps_per_turn=1))
    outcome = steps.turn()
    assert outcome.terminal == "steps_per_turn_exhausted" and outcome.pending_tool is None
    assert [c.call_id for c in steps.tools.calls] == ["call_1"]
    assert steps.kinds() == ["user", "tool_call", "tool_result"]


def test_an_over_limit_message_is_terminal_without_truncation() -> None:
    built = Built([says("Hi.")], limits=AgentLimits(transcript_bytes=1024))
    assert built.turn("short").message is not None
    before = built.agent.snapshot().transcript
    outcome = built.turn("x" * 1100)
    assert outcome.terminal == "transcript_limit" and outcome.appended == ()
    assert built.agent.snapshot().transcript == before
    count = Built([says("a"), says("b")], limits=AgentLimits(transcript_messages=3))
    count.turn()
    assert count.turn().terminal == "transcript_limit"


def test_the_knowledge_tool_is_bound_to_the_pending_call_and_bounded() -> None:
    built = Built([calls("search_policy", {"query": "refund rules"}, "k1"),
                   calls("search_policy", {"query": "more"}, "k2")],
                  catalog=BANKING, limits=AgentLimits(knowledge_steps=1))
    outcome = built.turn()
    assert outcome.terminal == "knowledge_steps_exhausted"
    assert built.knowledge is not None
    assert built.knowledge.queries == [("refund rules", built.conversation_id, 0)]
    result_entry = built.agent.snapshot().transcript[2]
    assert result_entry == ToolResult(call_id="k1", content=built.knowledge.content)
    assert built.tools.calls == []  # knowledge never goes to the tool port


def test_invalid_knowledge_arguments_and_a_disabled_knowledge_tool_are_notices() -> None:
    built = Built([calls("search_policy", {"query": "   "}), says("ok")], catalog=BANKING)
    built.turn()
    assert built.agent.snapshot().transcript[1] == RuntimeNotice(code="invalid_arguments")
    retail = Built([calls("search_policy", {"query": "refunds"}), says("ok")])
    retail.turn()
    assert retail.agent.snapshot().transcript[1] == RuntimeNotice(code="unknown_tool")


# -- unknown tool outcomes --------------------------------------------------------------------------------------

async def _raise(call: AgentToolCall) -> object:
    raise RuntimeError("secret upstream detail 12345")


async def _wrong_id(call: AgentToolCall) -> object:
    return ToolResult(call_id="other", content="x")


async def _not_a_result(call: AgentToolCall) -> object:
    return {"call_id": call.call_id, "content": "x"}


async def _huge(call: AgentToolCall) -> object:
    return ToolResult(call_id=call.call_id, content="x" * 32_000)


@pytest.mark.parametrize(("handler", "terminal", "detail"), [
    (_raise, "tool_port_failed", "port.runtimeerror"), (_wrong_id, "tool_result_invalid", None),
    (_not_a_result, "tool_result_invalid", None), (_huge, "tool_result_invalid", "transcript_limit"),
], ids=["port error", "wrong call id", "not a result", "over the transcript bound"])
def test_a_begun_dispatch_without_a_validated_result_leaves_the_outcome_unknown(
        handler: Callable[[AgentToolCall], Awaitable[object]], terminal: str, detail: str | None) -> None:
    built = Built([calls("cancel_pending_order", {"order_id": "#W0000001", "reason": "no longer needed"})],
                  tools=FakeTools(handler=handler), limits=AgentLimits(transcript_bytes=16_000))
    outcome = built.turn()
    assert (outcome.terminal, outcome.detail) == (terminal, detail)
    pending = outcome.pending_tool
    assert pending is not None and (pending.call_id, pending.name, pending.read_only, pending.outcome) == (
        "call_1", "cancel_pending_order", False, "unknown")
    assert built.agent.snapshot().pending_tool == pending
    assert built.kinds() == ["user", "tool_call"]
    assert "secret upstream detail" not in built.agent.snapshot().model_dump_json() + outcome.model_dump_json()


def test_a_knowledge_port_cannot_bind_or_fake_a_call_id() -> None:
    async def tool_result(query: str) -> object:
        return ToolResult(call_id="k1", content="x")

    built = Built([calls("search_policy", {"query": "refunds"}, "k1")], catalog=BANKING,
                  knowledge=FakeKnowledge(handler=tool_result))
    outcome = built.turn()
    assert outcome.terminal == "tool_result_invalid" and outcome.pending_tool is not None
    assert outcome.pending_tool.read_only is True


# -- ownership, cancellation and deadlines ----------------------------------------------------------------------

def test_cancellation_closes_the_instance_and_keeps_an_unknown_tool_outcome_only_after_dispatch() -> None:
    async def scenario(during_tool: bool) -> tuple[MinimalAgent, FakeTools, list[asyncio.Task[Any]]]:
        started = asyncio.Event()

        async def stall(*_: object) -> CallReport:
            started.set()
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

        async def stall_tool(call: AgentToolCall) -> object:
            return await stall()

        script: list[Any] = [calls("get_order_details", ORDER)] if during_tool else [stall]
        tools = FakeTools(handler=stall_tool)
        built = Built(script, tools=tools)
        task = asyncio.create_task(built.agent.turn(UserMessage(text="Hi"), deadline=later()))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(ConversationClosed):
            await built.agent.turn(UserMessage(text="again"), deadline=later())
        return built.agent, tools, [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    agent, tools, left = asyncio.run(scenario(during_tool=False))
    snapshot = agent.snapshot()
    assert (snapshot.terminal, snapshot.pending_tool, snapshot.model_calls, left) == ("cancelled", None, 1, [])
    agent, tools, left = asyncio.run(scenario(during_tool=True))
    snapshot = agent.snapshot()
    assert snapshot.terminal == "cancelled" and left == [] and tools.cleaned == ["call_1"]
    assert snapshot.pending_tool is not None and snapshot.pending_tool.call_id == "call_1"


def test_an_unexpected_port_error_closes_the_instance_and_propagates_unchanged() -> None:
    async def broken(request: Any) -> CallReport:
        raise KeyError("boom")

    built = Built([broken])
    with pytest.raises(KeyError, match="boom"):
        built.turn()
    assert built.agent.snapshot().terminal == "internal_error"
    with pytest.raises(ConversationClosed):
        built.turn()


def test_a_concurrent_turn_or_an_invalid_deadline_is_refused_without_any_state_change() -> None:
    async def scenario() -> None:
        release = asyncio.Event()

        async def wait(request: Any) -> CallReport:
            await release.wait()
            return says("Done.")

        built = Built([wait])
        first = asyncio.create_task(built.agent.turn(UserMessage(text="one"), deadline=later()))
        await asyncio.sleep(0)
        with pytest.raises(ConversationBusy):
            await built.agent.turn(UserMessage(text="two"), deadline=later())
        release.set()
        assert (await first).message == AgentMessage(text="Done.")
        before = built.agent.snapshot()
        for deadline in (float("nan"), float("inf"), time.monotonic() - 1, True):
            with pytest.raises(DeadlineInvalid):
                await built.agent.turn(UserMessage(text="three"), deadline=cast(float, deadline))
        assert built.agent.snapshot() == before

    asyncio.run(scenario())


def test_sequential_turns_may_use_new_loops_but_a_turn_from_another_thread_is_refused_while_busy() -> None:
    built = Built([says("a"), says("b")])
    assert built.turn().message is not None and built.turn().message is not None  # two asyncio.run loops
    started, release = threading.Event(), threading.Event()

    async def wait(request: Any) -> CallReport:
        started.set()
        await asyncio.to_thread(release.wait, 10)
        return says("c")

    busy = Built([wait])
    worker = threading.Thread(target=busy.turn)
    worker.start()
    try:
        assert started.wait(10)
        with pytest.raises(ConversationBusy):
            busy.turn("from another thread")
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive() and busy.agent.snapshot().turns == 1
    assert len(busy.model.requests) == 1  # the refused turn reached no port


def test_the_turn_deadline_reaches_every_port() -> None:
    built = Built([calls("get_order_details", ORDER), says("ok")])
    deadline = later()
    asyncio.run(built.agent.turn(UserMessage(text="hi"), deadline=deadline))
    assert built.model.deadlines == [deadline, deadline]


# -- identity -------------------------------------------------------------------------------------------------

def test_equal_configuration_and_state_give_byte_identical_requests_across_conversations() -> None:
    script = [calls("get_order_details", ORDER), says("Pending.")]
    first, second = Built(list(script)), Built(list(script))
    first.turn()
    second.turn()
    assert first.conversation_id != second.conversation_id and first.model.keys != second.model.keys
    for a, b in zip(first.model.requests, second.model.requests, strict=True):
        assert prepare(a, LUNA, "agent").body == prepare(b, LUNA, "agent").body
    request = first.model.requests[0]
    assert request.instructions == prompt_text(knowledge_tool=False) + POLICY_HEADING + first.policy.text
    assert str(first.conversation_id) not in request.model_dump_json()
    assert first.agent.config_sha256 == second.agent.config_sha256 == first.config.digest()
    assert build_request(first.policy, first.catalog, first.config.limits,
                         first.agent.snapshot().transcript[:1]) == request


def test_the_knowledge_prompt_and_tool_change_the_configuration_identity() -> None:
    retail, knowledge = retail_catalog(), retail_catalog(knowledge_tool=True)
    policy = fictional_policy()
    plain = agent_config(policy, retail, LUNA)
    searching = agent_config(policy, knowledge, LUNA, AgentLimits(knowledge_steps=10))
    assert plain.prompt_sha256 != searching.prompt_sha256 and plain.catalog_sha256 != searching.catalog_sha256
    request = build_request(policy, knowledge, searching.limits, (UserMessage(text="q"),))
    assert [tool.name for tool in request.tools][-1] == "search_policy" and len(request.tools) == 17
    assert KnowledgeResult(content="x").is_error is False


# -- review regressions: late replies and the production adapter's actor binding (draft-composition-findings-1) ----

class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now


def _clocked(monkeypatch: pytest.MonkeyPatch, now: float) -> _Clock:
    clock = _Clock(now)
    monkeypatch.setattr(minimal, "time", SimpleNamespace(monotonic=clock.monotonic))
    return clock


@pytest.mark.parametrize("late", [False, True], ids=["fast", "late"])
def test_a_model_reply_returned_after_the_deadline_is_never_a_timely_message(monkeypatch: pytest.MonkeyPatch,
                                                                             late: bool) -> None:
    clock = _clocked(monkeypatch, 10.0)

    async def reply(request: Any) -> CallReport:
        clock.now = 12.0 if late else 10.5
        return says("Your order is pending.")

    built = Built([reply])
    outcome = asyncio.run(built.agent.turn(UserMessage(text="hi"), deadline=11.0))
    if not late:
        assert outcome.message == AgentMessage(text="Your order is pending.") and outcome.terminal is None
        return
    assert (outcome.message, outcome.terminal, outcome.detail) == (None, "deadline", "late_model_result")
    assert (outcome.model_calls, outcome.counts_claimed, outcome.inferences_dispatched) == (1, 1, 1)  # work kept
    assert built.kinds() == ["user"] and built.model.script == []  # nothing accepted, no further model call


def test_a_late_tool_result_is_kept_truthfully_and_no_model_work_follows(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _clocked(monkeypatch, 10.0)

    async def slow(call: AgentToolCall) -> object:
        clock.now = 12.0
        return ToolResult(call_id=call.call_id, content='{"status":"pending"}')

    built = Built([calls("get_order_details", ORDER), says("unused")], tools=FakeTools(handler=slow))
    outcome = asyncio.run(built.agent.turn(UserMessage(text="hi"), deadline=11.0))
    assert (outcome.terminal, outcome.pending_tool) == ("deadline", None)  # the observation is known, not unknown
    assert built.kinds() == ["user", "tool_call", "tool_result"]
    assert len(built.model.requests) == 1


def _factory(counter: list[int]) -> Callable[[], Providers]:
    def factory() -> Providers:
        counter.append(1)
        raise AssertionError("no provider factory call")
    return factory


def test_the_production_adapter_must_bind_the_declared_agent_actor_without_a_factory_call() -> None:
    policy = PolicyContext(domain="retail", source="harness_domain_policy", text="Fictional.",
                           sha256=fictional_policy(text="Fictional.").sha256)
    config = agent_config(policy, retail_catalog(), LUNA)
    counter: list[int] = []
    matched = agent_model_port(Ledger(cast(Any, None), LUNA), RunBinding(uuid4()), _factory(counter))
    assert ports.bound_actor_sha256(matched) == config.actor_config_sha256
    MinimalAgent(config, policy, retail_catalog(), conversation_id=uuid4(), model=matched, tools=_ProductionTools(),
                 knowledge=None, configuration=LUNA)
    other = agent_model_port(Ledger(cast(Any, None), HAIKU), RunBinding(uuid4()), _factory(counter))
    with pytest.raises(AgentConfigurationError, match="ledger does not bind"):
        MinimalAgent(config, policy, retail_catalog(), conversation_id=uuid4(), model=other,
                     tools=_ProductionTools(), knowledge=None, configuration=LUNA)
    assert counter == [] and ports.bound_actor_sha256(ScriptedModel([])) is None


def test_a_ledger_configuration_changed_after_binding_sends_and_reserves_nothing() -> None:
    policy = PolicyContext(domain="retail", source="harness_domain_policy", text="Fictional.",
                           sha256=fictional_policy(text="Fictional.").sha256)
    counter: list[int] = []
    ledger = Ledger(cast(Any, None), LUNA)  # no store: any reservation would fail loudly
    port = agent_model_port(ledger, RunBinding(uuid4()), _factory(counter))
    agent = MinimalAgent(agent_config(policy, retail_catalog(), LUNA), policy, retail_catalog(),
                         conversation_id=uuid4(), model=port, tools=_ProductionTools(), knowledge=None,
                         configuration=LUNA)
    ledger.configuration = HAIKU
    outcome = asyncio.run(agent.turn(UserMessage(text="hi"), deadline=later()))
    assert (outcome.terminal, outcome.detail) == ("contract_gap", "actor_configuration_changed")
    assert (outcome.counts_claimed, outcome.inferences_dispatched, counter) == (0, 0, [])
