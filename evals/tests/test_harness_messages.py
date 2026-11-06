"""T29 visible-message compatibility: verbatim conversions and fixed, content-free refusals between pinned upstream
messages and the conversation DTOs. Fictional messages only.

Upstream message classes are exercised in a fresh isolated interpreter (upstream import side effects disabled, an
empty TAU2_DATA_DIR, the network guard installed), so this module never fixes upstream's data directory for later
evaluator tests. The import guard and the error-chain checks run in-process.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback
from typing import Any
from uuid import uuid4

import pytest

from policyops_evals.harness import messages, tools
from policyops_evals.harness.messages import MessageRefused
from policyops_evals.harness.tools import ArgumentsRefused, CatalogRefused, SchemaRefused


REPO = Path(__file__).resolve().parents[2]

# The child is a fresh isolated interpreter whose venv `.pth` entries point at whichever checkout the venv was built
# from. CHILD_PRELUDE routes first-party imports to the checkout that holds THESE tests (the roots in argv[1]), drops
# every other sys.path entry that provides a first-party package, refuses preloaded first-party modules, and reports
# each exercised module's file and SHA-256 so the parent can prove the bytes it tested.
CHILD_PRELUDE = r"""
import hashlib, json, os, sys
ROOTS = [os.path.realpath(root) for root in json.loads(sys.argv[1])]
FIRST_PARTY = ("policyops_evals", "policyops_contracts", "policyops_testing", "policyops")
assert not [m for m in sys.modules if m.split(".")[0] in FIRST_PARTY], "a first-party module was preloaded"
def _provides(entry):
    return any(os.path.isdir(os.path.join(entry, name)) for name in FIRST_PARTY)
sys.path[:] = ROOTS + [p for p in sys.path if os.path.realpath(p or ".") not in ROOTS and not _provides(p or ".")]
def binding(names):
    report = {}
    for name in names:
        path = os.path.realpath(sys.modules[name].__file__)
        with open(path, "rb") as handle:
            report[name] = {"file": path, "sha256": hashlib.sha256(handle.read()).hexdigest()}
    return report
"""
ROOTS = [REPO / "evals" / "src", REPO / "packages" / "policyops_contracts" / "src", REPO / "tests" / "support"]


def child_argv(script: str) -> list[str]:
    return [sys.executable, "-I", "-B", "-X", "utf8", "-c", CHILD_PRELUDE + script, json.dumps([str(r) for r in ROOTS])]


def assert_bound_to_this_checkout(report: dict[str, Any], expected: set[str]) -> None:
    """Every exercised first-party module came from this checkout, with exactly the bytes beside these tests."""
    assert set(report) == expected
    for name, entry in report.items():
        path = Path(entry["file"])
        assert any(path.is_relative_to(root.resolve()) for root in ROOTS), (name, entry["file"])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], name

SCENARIOS = r"""
import warnings
from policyops_testing import network
network.install()
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from tau2.data_model.message import AssistantMessage, MultiToolMessage, ToolCall, ToolMessage, UserMessage
    from tau2.orchestrator.orchestrator import DEFAULT_FIRST_AGENT_MESSAGE
from policyops_contracts.conversation import AgentMessage, AgentToolCall
from policyops_evals.harness import messages as M, tools as T

out = {}
def case(name, thunk):
    try:
        value = thunk()
        out[name] = {"ok": True, "value": value.model_dump(mode="json") if hasattr(value, "model_dump") else value}
    except M.MessageRefused as refused:
        out[name] = {"ok": False, "code": refused.code}

TEXT = "Hello\n\tI'd like to return order #W0000001 — café ☃\r\n  "
call = ToolCall(id="call_1", name="get_order_details", arguments={"order_id": "#W0000001"})
def tm(**changes):
    body = dict(id="call_1", role="tool", content='{"status": "pending"}', requestor="assistant")
    body.update(changes)
    return ToolMessage(**body)

case("opener_default", lambda: M.opening_from_history([DEFAULT_FIRST_AGENT_MESSAGE.model_copy(deep=True)]))
case("opener_custom", lambda: M.opening_from_history([AssistantMessage(role="assistant", content="Welcome back.")]))
case("opener_empty_history", lambda: M.opening_from_history([]))
case("opener_two", lambda: M.opening_from_history([AssistantMessage(role="assistant", content="a"),
                                                   UserMessage(role="user", content="b")]))
case("opener_tool_call", lambda: M.opening_from_history([AssistantMessage(role="assistant", tool_calls=[call])]))
case("opener_audio_flag", lambda: M.opening_from_history([AssistantMessage(role="assistant", content="a",
                                                                           is_audio=True)]))
case("opener_audio_content", lambda: M.opening_from_history([AssistantMessage(role="assistant", content="a",
                                                                              audio_content="YQ==")]))
case("opener_user", lambda: M.opening_from_history([UserMessage(role="user", content="a")]))
case("user_verbatim", lambda: M.user_message(UserMessage(role="user", content=TEXT)))
case("user_none", lambda: M.user_message(UserMessage(role="user", content=None, tool_calls=None)))
case("user_empty", lambda: M.user_message(UserMessage(role="user", content="")))
case("user_oversize", lambda: M.user_message(UserMessage(role="user", content="x" * 8001)))
case("user_max", lambda: M.user_message(UserMessage(role="user", content="x" * 8000)))
case("user_control", lambda: M.user_message(UserMessage(role="user", content="bell\x07")))
case("user_surrogate", lambda: M.user_message(UserMessage(role="user", content="bad \ud800")))
case("user_tool_call", lambda: M.user_message(UserMessage(role="user", content=None,
                                                          tool_calls=[ToolCall(id="u1", name="x", arguments={},
                                                                               requestor="user")])))
case("user_audio_flag", lambda: M.user_message(UserMessage(role="user", content="Hello", is_audio=True)))
case("user_audio_content", lambda: M.user_message(UserMessage(role="user", content="Hello", is_audio=False,
                                                              audio_content="YQ==")))
case("user_wrong_type", lambda: M.user_message(AssistantMessage(role="assistant", content="Hello")))
case("tool_ok", lambda: M.tool_result(tm(), "call_1"))
case("tool_error", lambda: M.tool_result(tm(content="Error: order not found", error=True), "call_1"))
case("tool_rejected", lambda: M.tool_result(tm(content="Rejected by environment", error=True,
                                               execution_status="rejected"), "call_1"))
# Upstream's own validator refuses this combination; a constructed-without-validation object models a malformed peer.
case("tool_rejected_without_error", lambda: M.tool_result(ToolMessage.model_construct(
    id="call_1", role="tool", content="x", requestor="assistant", error=False, execution_status="rejected"), "call_1"))
case("tool_wrong_id", lambda: M.tool_result(tm(id="call_2"), "call_1"))
case("tool_user_requestor", lambda: M.tool_result(tm(requestor="user"), "call_1"))
case("tool_multi", lambda: M.tool_result(MultiToolMessage(role="tool", tool_messages=[tm(), tm(id="call_2")]),
                                         "call_1"))
case("tool_none", lambda: M.tool_result(tm(content=None), "call_1"))
case("tool_oversize", lambda: M.tool_result(tm(content="x" * 32001), "call_1"))
case("tool_not_a_tool_message", lambda: M.tool_result(UserMessage(role="user", content="x"), "call_1"))

params = {"type": "object", "required": ["agent_tool_name"], "properties": {
    "agent_tool_name": {"type": "string"}, "arguments": {"type": "string", "default": "{}"}}}
catalog = T.map_catalog([("call_discoverable_agent_tool", "Call (fictional).", params, "write")], knowledge_tool=True)
def outbound_text():
    m = M.assistant_text(AgentMessage(text=TEXT.replace("\r", "")))
    m.validate()
    return {"type": type(m).__name__, "role": m.role, "content": m.content, "tool_calls": m.tool_calls,
            "cost": m.cost, "usage": m.usage, "raw_data": m.raw_data}
def outbound_call(arguments):
    m = M.assistant_tool_call(AgentToolCall(call_id="call_9", name="call_discoverable_agent_tool",
                                            arguments_json=arguments), catalog)
    m.validate()
    (c,) = m.tool_calls
    return {"type": type(m).__name__, "content": m.content, "id": c.id, "name": c.name, "arguments": c.arguments,
            "requestor": c.requestor, "is_tool_call": m.is_tool_call()}
case("out_text", outbound_text)
case("out_call_omitted", lambda: outbound_call('{"agent_tool_name":"unlock_x","arguments":null}'))
case("out_call_kept", lambda: outbound_call('{"agent_tool_name":"unlock_x","arguments":"{\\"k\\":2}"}'))
case("out_call_bad_shape", lambda: outbound_call('{"agent_tool_name":"unlock_x"}'))
case("out_knowledge", lambda: M.assistant_tool_call(AgentToolCall(call_id="k1", name="search_policy",
                                                                  arguments_json='{"query":"refunds"}'), catalog))
case("out_unknown", lambda: M.assistant_tool_call(AgentToolCall(call_id="k1", name="other", arguments_json="{}"),
                                                  catalog))
print(json.dumps({"cases": out, "binding": binding(
    ["policyops_evals", "policyops_evals.harness", "policyops_evals.harness.tools", "policyops_evals.harness.messages",
     "policyops_contracts", "policyops_contracts.conversation", "policyops_testing.network"])}))
"""


@pytest.fixture(scope="module")
def results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    empty = tmp_path_factory.mktemp("empty-tau2-data")
    env = {**os.environ, "TAU2_DATA_DIR": str(empty)}
    done = subprocess.run(child_argv(SCENARIOS), env=env, cwd=empty, capture_output=True, text=True,
                          encoding="utf-8", timeout=300, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    loaded: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    # Retained evidence (written before the binding assertion): the child's exact module sources and hashes.
    record = {"id": "messages", "source_root": str(REPO), "modules": loaded["binding"]}
    (empty / "child-binding-messages.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    assert_bound_to_this_checkout(loaded["binding"], {
        "policyops_evals", "policyops_evals.harness", "policyops_evals.harness.tools",
        "policyops_evals.harness.messages", "policyops_contracts", "policyops_contracts.conversation",
        "policyops_testing.network"})
    cases: dict[str, Any] = loaded["cases"]
    return cases


def refusal(results: dict[str, Any], name: str) -> str:
    entry = results[name]
    assert entry["ok"] is False, (name, entry)
    code: str = entry["code"]
    return code


TEXT = "Hello\n\tI'd like to return order #W0000001 — café ☃\r\n  "


def test_the_initial_history_must_be_exactly_one_text_opener(results: dict[str, Any]) -> None:
    assert results["opener_default"] == {"ok": True,
                                         "value": {"kind": "agent", "text": "Hi! How can I help you today?"}}
    assert results["opener_custom"]["value"]["text"] == "Welcome back."
    for name in ("opener_empty_history", "opener_two", "opener_tool_call", "opener_audio_flag", "opener_audio_content",
                 "opener_user"):
        assert refusal(results, name) == "unsupported_initial_history", name


def test_user_text_is_carried_verbatim_or_refused_with_a_fixed_code(results: dict[str, Any]) -> None:
    assert results["user_verbatim"] == {"ok": True, "value": {"kind": "user", "text": TEXT}}  # no strip or normalize
    assert results["user_max"]["ok"] is True
    expected = {"user_none": "empty_content", "user_empty": "empty_content", "user_oversize": "oversize_content",
                "user_control": "unrepresentable_text", "user_surrogate": "unrepresentable_text",
                "user_tool_call": "tool_call_in_user_message", "user_audio_flag": "audio_unsupported",
                "user_audio_content": "audio_unsupported", "user_wrong_type": "wrong_message_type"}
    assert {name: refusal(results, name) for name in expected} == expected


def test_tool_results_keep_identity_content_and_error_including_environment_rejections(
        results: dict[str, Any]) -> None:
    assert results["tool_ok"]["value"] == {"kind": "tool_result", "call_id": "call_1",
                                           "content": '{"status": "pending"}', "is_error": False}
    assert results["tool_error"]["value"] == {"kind": "tool_result", "call_id": "call_1",
                                              "content": "Error: order not found", "is_error": True}
    assert results["tool_rejected"]["value"] == {"kind": "tool_result", "call_id": "call_1",
                                                 "content": "Rejected by environment", "is_error": True}
    expected = {"tool_rejected_without_error": "malformed_tool_message", "tool_wrong_id": "wrong_call_id",
                "tool_user_requestor": "wrong_requestor", "tool_multi": "multi_tool_message",
                "tool_none": "empty_content", "tool_oversize": "oversize_content",
                "tool_not_a_tool_message": "wrong_message_type"}
    assert {name: refusal(results, name) for name in expected} == expected


def test_outbound_messages_are_valid_upstream_single_actions_with_the_call_identity(results: dict[str, Any]) -> None:
    assert results["out_text"]["value"] == {"type": "AssistantMessage", "role": "assistant",
                                            "content": TEXT.replace("\r", ""), "tool_calls": None, "cost": None,
                                            "usage": None, "raw_data": None}
    assert results["out_call_omitted"]["value"] == {
        "type": "AssistantMessage", "content": None, "id": "call_9", "name": "call_discoverable_agent_tool",
        "arguments": {"agent_tool_name": "unlock_x"}, "requestor": "assistant", "is_tool_call": True}
    assert results["out_call_kept"]["value"]["arguments"] == {"agent_tool_name": "unlock_x", "arguments": '{"k":2}'}
    assert refusal(results, "out_call_bad_shape") == "invalid_arguments"
    assert refusal(results, "out_knowledge") == "unknown_tool"  # served by PolicyOps, never by upstream
    assert refusal(results, "out_unknown") == "unknown_tool"


def test_upstream_is_never_imported_before_its_side_effects_are_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "0")
    with pytest.raises(MessageRefused, match="upstream_not_prepared"):
        messages.user_message(object())


def test_refusals_never_carry_the_input_in_their_formatted_exception_chain() -> None:
    """Review regression (draft-finding-error-chain-1): a runtime-generated canary must not reach any formatted
    traceback, through the message, a cause or a context."""
    canary = f"canary-{uuid4().hex}"
    params = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}
    mapping = tools.map_catalog([("act", "Act (fictional).", params, "write")])
    raised: list[BaseException] = []
    for thunk in (
            lambda: tools.map_tool(f"bad name {canary}", "Act.", params, "write"),
            lambda: tools.map_tool("act", f"bad \x00 {canary}", params, "write"),
            lambda: tools.map_catalog([(f"bad name {canary}", "Act.", params, "write")]),
            lambda: tools.strictify('{"type": "object", "properties": {' + json.dumps(canary)),
            lambda: tools.to_upstream_arguments(mapping, "act", '{"a": ' + json.dumps(canary)),
            lambda: tools.to_upstream_arguments(mapping, "act", json.dumps({"a": canary, "b": canary})),
            lambda: messages._text(f"{canary}\ud800", 100),
    ):
        with pytest.raises((SchemaRefused, CatalogRefused, ArgumentsRefused, MessageRefused)) as caught:
            thunk()
        raised.append(caught.value)
    for error in raised:
        assert canary not in "".join(traceback.format_exception(error)), type(error).__name__
        assert (error.__cause__ is None and error.__suppress_context__) or error.__context__ is None
