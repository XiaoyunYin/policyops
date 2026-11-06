"""T29 registered upstream factory and `HalfDuplexAgent` adapter over a typed fake bridge (offline).

`harness.adapter` imports upstream on load, so this parent process never imports it. Every behavioural check runs in
one fresh isolated child: upstream import side effects disabled, an empty TAU2_DATA_DIR, the network guard installed,
upstream tool calls trapped, and first-party imports routed to (and byte-bound against) this checkout. The child
drives the real pinned `build_agent`, `Environment`, `Registry` and message classes with fictional data only. The
parent checks the adapter's source with the AST.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest


REPO = Path(__file__).resolve().parents[2]
ADAPTER = REPO / "evals" / "src" / "policyops_evals" / "harness" / "adapter.py"

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
BOUND = {"policyops_evals", "policyops_evals.harness", "policyops_evals.harness.tools",
         "policyops_evals.harness.messages", "policyops_evals.harness.adapter", "policyops_contracts",
         "policyops_contracts.conversation", "policyops_testing.network"}


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
import dataclasses, gc, threading, traceback, warnings, weakref
from uuid import UUID, uuid4
from policyops_testing import network
network.install()
DATA = os.path.realpath(os.environ["TAU2_DATA_DIR"])
DATA_OPENS = []
def audit(event, args):
    if event == "open" and isinstance(args[0], (str, bytes)):
        path = os.path.realpath(os.fsdecode(args[0]))
        if path.startswith(DATA):
            DATA_OPENS.append(path)
sys.addaudithook(audit)
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from tau2.environment.tool import Tool
    from tau2.environment.environment import Environment
    from tau2.domains.retail.tools import RetailTools
    from tau2.domains.banking_knowledge.retrieval_toolkits import KnowledgeToolsPlain
    from tau2.data_model.message import AssistantMessage, MultiToolMessage, ToolMessage, UserMessage
    from tau2.orchestrator.orchestrator import DEFAULT_FIRST_AGENT_MESSAGE
    from tau2.runner.build import build_agent
    from tau2.registry import Registry
TOOL_CALLS = []
Tool.__call__ = lambda self, *a, **k: TOOL_CALLS.append(self.name)
Tool._call = lambda self, *a, **k: TOOL_CALLS.append(self.name)
from policyops_contracts.conversation import (AgentMessage, AgentToolCall, PendingToolOutcome, ToolResult,
                                              TurnOutcome, UserMessage as UM)
from policyops_evals.harness import adapter as A

CFG = "a" * 64
FICT = "# Example policy (fictional)\n\nHelp the customer. policy-canary-" + uuid4().hex
cases = {}


class Clock:
    def __init__(self, now=0.0):
        self.now, self.broken = now, None
    def __call__(self):
        if self.broken == "raise":
            raise RuntimeError("clock canary")
        return float("nan") if self.broken == "nan" else self.now


def describe(value):
    if dataclasses.is_dataclass(value):
        return {f.name: describe(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, UUID):
        return str(value)
    return value


class Fake:
    def __init__(self, script, close_error=None):
        self.script, self.records, self.closed, self.close_error, self.turn = list(script), [], [], close_error, None
    def _next(self, kind, request, seconds):
        self.records.append({"kind": kind, "seconds": seconds, "request": describe(request)})
        if kind == "user_turn":
            self.turn = request.turn
        return self.script.pop(0)(request, self)
    def open(self, request, *, seconds):
        return self._next("open", request, seconds)
    def user_turn(self, request, *, seconds):
        return self._next("user_turn", request, seconds)
    def tool_return(self, request, *, seconds):
        return self._next("tool_return", request, seconds)
    def close(self, session_id, *, seconds):
        self.closed.append([str(session_id), seconds])
        if self.close_error is not None:
            raise self.close_error


def opened(cfg=CFG):
    return lambda req, fake: A.SessionOpened(req.session_id, cfg)
def tool(call_id, name, args):
    call = AgentToolCall(call_id=call_id, name=name, arguments_json=json.dumps(args, separators=(",", ":")))
    return lambda req, fake: A.ToolRequest(req.session_id, req.seq, call)
def outcome(fake, session, *, message=None, terminal=None, appended=(), detail=None, pending=None, turn=None, cfg=CFG):
    return TurnOutcome(conversation_id=session, turn=fake.turn if turn is None else turn, config_sha256=cfg,
                       message=None if message is None else AgentMessage(text=message), terminal=terminal,
                       detail=detail, appended=appended, model_calls=1, invalid_steps=0, counts_claimed=1,
                       inferences_dispatched=1, cleanup_unconfirmed=False, pending_tool=pending)
def says(text, **kw):
    return lambda req, fake: A.TurnEnded(req.session_id, req.seq, outcome(fake, req.session_id, message=text, **kw))
def ends(terminal, **kw):
    return lambda req, fake: A.TurnEnded(req.session_id, req.seq,
                                         outcome(fake, req.session_id, terminal=terminal, **kw))


def turns(fake):
    return sum(r["kind"] == "user_turn" for r in fake.records)


def opener():
    return [DEFAULT_FIRST_AGENT_MESSAGE.model_copy(deep=True)]
def user(text="Hi, where is order #W0000001?"):
    return UserMessage(role="user", content=text)
def tm(call_id, content='{"status":"pending"}', **kw):
    return ToolMessage(id=call_id, role="tool", content=content, requestor="assistant", **kw)


def make(script, *, domain="retail", kit=None, clock=None, end=100.0, margin=1.0, grace=2.0, close_error=None):
    fake = Fake(script, close_error)
    clock = clock or Clock()
    slot = A.TrialSlot(uuid4(), domain, fake, A.TrialBudget(end, clock, margin, grace))
    kit = kit if kit is not None else (RetailTools(None) if domain == "retail" else KnowledgeToolsPlain(None))
    env = Environment(domain_name=domain, policy=FICT, tools=kit)
    with A.trial(slot):
        agent = build_agent(A.FACTORY_NAME, env)
    return agent, fake, clock, slot


def outcome_of(thunk):
    try:
        value = thunk()
        return {"ok": True, "value": value}
    except A.AdapterRefused as refused:
        return {"ok": False, "code": refused.code, "chain": refused.__cause__ is None and
                (refused.__suppress_context__ or refused.__context__ is None)}
    except A.AgentTerminated as ended:
        return {"ok": False, "terminal": ended.reason, "detail": ended.detail,
                "pending": None if ended.pending_tool is None else ended.pending_tool.model_dump(mode="json")}
    except BaseException as other:
        return {"ok": False, "other": type(other).__name__}


def case(name, thunk):
    cases[name] = outcome_of(thunk)


def call_view(message):
    (c,) = message.tool_calls
    message.validate()
    return {"type": type(message).__name__, "content": message.content, "id": c.id, "name": c.name,
            "arguments": c.arguments, "requestor": c.requestor}


A.register()
A.register()  # idempotent for this very factory

# -- poison, canaries and retention through real build_agent ---------------------------------------------------
TRIPS = []
class Poison:
    __slots__ = ("__weakref__",)
    def __getattribute__(self, name):
        if name == "__class__":
            return object.__getattribute__(self, name)
        TRIPS.append("attr:" + name)
        raise RuntimeError("poison")
def _trip(name):
    def method(self, *args, **kwargs):
        TRIPS.append(name)
        raise RuntimeError("poison")
    return method
for _name in ("__repr__", "__str__", "__format__", "__bool__", "__len__", "__iter__", "__eq__", "__hash__",
              "__reduce_ex__", "__reduce__", "__getstate__", "__copy__", "__deepcopy__", "__contains__",
              "__getitem__"):
    setattr(Poison, _name, _trip(_name))


def poison_case():
    llm_canary, args_canary = "canary-llm-" + uuid4().hex, "canary-args-" + uuid4().hex
    poison = Poison()
    kit = RetailTools(None)
    env = Environment(domain_name="retail", policy=FICT, tools=kit)
    fake = Fake([opened(), says("Hello.")])
    slot = A.TrialSlot(uuid4(), "retail", fake, A.TrialBudget(100.0, Clock(), 1.0, 2.0))
    with A.trial(slot):
        agent = build_agent(A.FACTORY_NAME, env, llm=llm_canary, llm_args={"canary": args_canary}, task=poison)
    trips_after_build = list(TRIPS)
    refs = {"poison": weakref.ref(poison), "env": weakref.ref(env), "toolkit": weakref.ref(kit)}
    del poison, env, kit
    gc.collect()
    alive = {name: ref() is not None for name, ref in refs.items()}
    state = agent.get_init_state(opener())
    reply, _ = agent.generate_next_message(user(), state)
    # A direct factory call with an unknown future keyword (also poison) under a fresh slot.
    poison2, kit2 = Poison(), RetailTools(None)
    slot2 = A.TrialSlot(uuid4(), "retail", Fake([]), A.TrialBudget(100.0, Clock(), 1.0, 2.0))
    with A.trial(slot2):
        A.create_policyops_agent(tools=list(kit2.get_tools().values()), domain_policy=FICT, task=poison2,
                                 future_keyword=Poison())
    records = json.dumps(fake.records)
    exposed = records + repr(vars(agent)) + json.dumps(agent.diagnostics)
    return {"trips_after_build": trips_after_build, "trips": list(TRIPS), "alive": alive,
            "agent_type": type(agent).__name__, "base_tools": agent.tools, "reply": reply.content,
            "canaries_exposed": [c for c in (llm_canary, args_canary) if c in exposed],
            "policy_canary_in_open": fake.records[0]["request"]["policy"]["text"] == FICT,
            "opening": fake.records[0]["request"]["opening"],
            "catalog_names": [t["name"] for t in fake.records[0]["request"]["catalog"]["tools"]]}
case("poison", poison_case)


# -- a full multi-step turn, repeated IDs in later calls, null omission ----------------------------------------
def happy():
    agent, fake, clock, _ = make([opened(), tool("c1", "get_order_details", {"order_id": "#W0000001"}),
                                  tool("c2", "get_user_details", {"user_id": "james_johnson_9321"}), says("Done."),
                                  tool("c1", "get_order_details", {"order_id": "#W0000002"}), says("Again.")])
    s0 = agent.get_init_state(opener())
    m1, s1 = agent.generate_next_message(user(), s0)
    m2, s2 = agent.generate_next_message(tm("c1", error=True, content="Error: not found"), s1)
    m3, s3 = agent.generate_next_message(tm("c2"), s2)
    m4, s4 = agent.generate_next_message(user("And order 2?"), s3)
    m5, s5 = agent.generate_next_message(tm("c1"), s4)
    m3.validate(); m5.validate()
    agent.stop(None, s5)
    agent.stop(None, s5)
    return {"calls": [call_view(m1), call_view(m2), call_view(m4)], "texts": [m3.content, m5.content],
            "text_types": [type(m3).__name__, m3.tool_calls], "steps": [s.step for s in (s0, s1, s2, s3, s4, s5)],
            "distinct_states": len({id(s) for s in (s0, s1, s2, s3, s4, s5)}),
            "requests": [(r["kind"], r["request"].get("seq"), r["request"].get("turn")) for r in fake.records],
            "tool_results": [r["request"]["result"] for r in fake.records if r["kind"] == "tool_return"],
            "user_texts": [r["request"]["message"]["text"] for r in fake.records if r["kind"] == "user_turn"],
            "closed": len(fake.closed), "close_seconds": fake.closed[0][1],
            "session_closed_is_own": fake.closed[0][0] == fake.records[0]["request"]["session_id"]}
case("happy", happy)


def banking_null():
    agent, fake, _, _ = make([opened(), tool("k1", "call_discoverable_agent_tool",
                                             {"agent_tool_name": "unlock_x", "arguments": None})],
                             domain="banking_knowledge")
    s0 = agent.get_init_state(opener())
    m1, _ = agent.generate_next_message(user(), s0)
    return {"call": call_view(m1), "domain": fake.records[0]["request"]["policy"]["domain"],
            "source": fake.records[0]["request"]["policy"]["source"]}
case("banking_null", banking_null)


# -- stale or mismatched envelopes and outcomes ---------------------------------------------------------------
def stale(script, turns=1):
    agent, fake, _, _ = make([opened(), *script])
    state = agent.get_init_state(opener())
    result = None
    for index in range(turns):
        result = outcome_of(lambda: agent.generate_next_message(user(f"turn {index}"), state))
        if result["ok"]:
            state = result["value"][1]
            result = {"ok": True}
    after = outcome_of(lambda: agent.generate_next_message(user("again"), state))
    return {"result": result, "after": after, "closed": len(fake.closed)}
case("stale_seq", lambda: stale([lambda req, fake: A.ToolRequest(req.session_id, req.seq - 1,
                                                                 AgentToolCall(call_id="c", name="calculate",
                                                                               arguments_json='{"expression":"1"}'))]))
case("stale_session", lambda: stale([lambda req, fake: A.TurnEnded(uuid4(), req.seq,
                                                                   outcome(fake, req.session_id, message="x"))]))
case("stale_turn", lambda: stale([says("first"), lambda req, fake: A.TurnEnded(
    req.session_id, req.seq, outcome(fake, req.session_id, message="replayed", turn=0))], turns=2))
case("stale_config", lambda: stale([says("x", cfg="b" * 64)]))
case("stale_conversation", lambda: stale([lambda req, fake: A.TurnEnded(
    req.session_id, req.seq, outcome(fake, uuid4(), message="x"))]))


# -- legitimate terminal outcomes and knowledge entries -------------------------------------------------------
def terminal(script):
    agent, fake, _, _ = make([opened(), *script])
    state = agent.get_init_state(opener())
    return {"result": outcome_of(lambda: agent.generate_next_message(user(), state)), "closed": len(fake.closed)}
KNOWLEDGE = (UM(text="Hi"), AgentToolCall(call_id="k1", name="search_policy", arguments_json='{"query":"refunds"}'),
             ToolResult(call_id="k1", content="[1] Refunds (fictional)."))
case("terminal_pre_append", lambda: terminal([ends("transcript_limit", appended=())]))
case("terminal_knowledge", lambda: terminal([ends("knowledge_steps_exhausted", appended=KNOWLEDGE)]))
AFTER_KNOWLEDGE = (*KNOWLEDGE, AgentMessage(text="Per [1], yes."))
case("message_after_knowledge", lambda: terminal([says("Per [1], yes.", appended=AFTER_KNOWLEDGE)]))
PENDING = PendingToolOutcome(call_id="c9", name="cancel_pending_order", read_only=False)
case("terminal_pending", lambda: terminal([ends("tool_port_failed", detail="port.runtimeerror", pending=PENDING)]))


# -- invalid port returns --------------------------------------------------------------------------------------
case("port_dict", lambda: terminal([lambda req, fake: {"session_id": str(req.session_id), "seq": req.seq}]))
BAD_CALL = AgentToolCall.model_construct(kind="tool_call", call_id="bad id!", name="get_order_details",
                                         arguments_json="{}")
case("port_bad_call", lambda: terminal([lambda req, fake: A.ToolRequest(req.session_id, req.seq, BAD_CALL)]))
def bad_outcome(req, fake):
    return A.TurnEnded(req.session_id, req.seq, TurnOutcome.model_construct(
        conversation_id=req.session_id, turn=0, config_sha256=CFG, appended=()))
case("port_bad_outcome", lambda: terminal([bad_outcome]))
case("port_seq_type", lambda: terminal([lambda req, fake: A.TurnEnded(req.session_id, float(req.seq),
                                                                      outcome(fake, req.session_id, message="x"))]))
case("port_unknown_tool", lambda: terminal([tool("c1", "delete_everything", {})]))
case("port_knowledge_call", lambda: terminal([tool("k1", "search_policy", {"query": "refunds"})]))
CANARY = "port-canary-" + uuid4().hex
def raising(error):
    def respond(req, fake):
        raise error
    return respond
def port_raises():
    agent, fake, _, _ = make([opened(), raising(ValueError(CANARY))])
    state = agent.get_init_state(opener())
    try:
        agent.generate_next_message(user(), state)
    except A.AdapterRefused as refused:
        return {"code": refused.code, "leak": CANARY in "".join(traceback.format_exception(refused)),
                "closed": len(fake.closed), "diag": agent.diagnostics}
case("port_raises", port_raises)
def port_interrupt():
    agent, fake, _, _ = make([opened(), raising(KeyboardInterrupt())])
    state = agent.get_init_state(opener())
    try:
        agent.generate_next_message(user(), state)
    except KeyboardInterrupt:
        return {"interrupt_preserved": True, "closed": len(fake.closed)}
case("port_interrupt", port_interrupt)


# -- session acquisition --------------------------------------------------------------------------------------
def init_case(open_response, *, close_error=None):
    agent, fake, clock, _ = make([open_response], close_error=close_error)
    result = outcome_of(lambda: agent.get_init_state(opener()))
    own = fake.records[0]["request"]["session_id"] if fake.records else None
    return {"result": result, "closed": fake.closed, "own": own, "diag": agent.diagnostics,
            "closed_only_own": all(c[0] == own for c in fake.closed)}
def late_open(req, fake):
    CLOCKS[-1].now = 500.0
    return A.SessionOpened(req.session_id, CFG)
CLOCKS = []
def late_case():
    clock = Clock()
    CLOCKS.append(clock)
    agent, fake, _, _ = make([late_open], clock=clock)
    result = outcome_of(lambda: agent.get_init_state(opener()))
    return {"result": result, "closed": fake.closed, "own": fake.records[0]["request"]["session_id"]}
case("open_late", late_case)
FOREIGN = uuid4()
case("open_foreign", lambda: init_case(lambda req, fake: A.SessionOpened(FOREIGN, CFG)))
case("open_bad_digest", lambda: init_case(lambda req, fake: A.SessionOpened(req.session_id, "XYZ")))
case("open_dict", lambda: init_case(lambda req, fake: {"session_id": str(req.session_id)}))
case("open_raises", lambda: init_case(raising(RuntimeError("open canary"))))
case("open_raises_close_fails", lambda: init_case(raising(RuntimeError("open")), close_error=OSError("close")))
case("open_history_empty", lambda: outcome_of(lambda: make([opened()])[0].get_init_state([])))


# -- budget and clock -------------------------------------------------------------------------------------------
def bad_clock(mode):
    clock = Clock()
    agent, fake, _, _ = make([opened(), says("never")], clock=clock)
    state = agent.get_init_state(opener())
    clock.broken = mode
    result = outcome_of(lambda: agent.generate_next_message(user(), state))
    return {"result": result, "closed": fake.closed, "user_turn_calls": turns(fake)}
case("clock_nan", lambda: bad_clock("nan"))
case("clock_raises", lambda: bad_clock("raise"))
def budget(**changes):
    values = {"end": 100.0, "clock": Clock(), "margin": 1.0, "grace": 2.0} | changes
    return outcome_of(lambda: A.TrialBudget(**values))
cases["budget"] = {name: budget(**change) for name, change in {
    "end_nan": {"end": float("nan")}, "end_inf": {"end": float("inf")}, "margin_negative": {"margin": -1.0},
    "margin_nan": {"margin": float("nan")}, "grace_zero": {"grace": 0.0}, "grace_inf": {"grace": float("inf")},
    "grace_large": {"grace": 31.0}, "clock_not_callable": {"clock": 3}, "end_bool": {"end": True}}.items()}
def exhausted():
    clock = Clock()
    agent, fake, _, _ = make([opened(), says("never")], clock=clock)
    state = agent.get_init_state(opener())
    clock.now = 99.5
    result = outcome_of(lambda: agent.generate_next_message(user(), state))
    later = outcome_of(lambda: agent.generate_next_message(user(), state))
    fresh = outcome_of(lambda: agent.get_init_state(opener()))
    return {"result": result, "later": later, "fresh_init": fresh, "closed": len(fake.closed),
            "user_turn_calls": sum(r["kind"] == "user_turn" for r in fake.records)}
case("exhausted", exhausted)
def capped():
    agent, fake, _, _ = make([opened(), says("ok")], end=5000.0)
    agent.generate_next_message(user(), agent.get_init_state(opener()))
    return [r["seconds"] for r in fake.records]
case("capped_seconds", capped)


# -- owner thread, re-entry, deferred stop ---------------------------------------------------------------------
def wrong_thread():
    agent, fake, _, _ = make([opened(), says("ok")])
    state = agent.get_init_state(opener())
    seen = {}
    def other():
        seen.update(outcome_of(lambda: agent.generate_next_message(user(), state)))
    worker = threading.Thread(target=other)
    worker.start(); worker.join(10)
    then = outcome_of(lambda: agent.generate_next_message(user(), state))
    return {"other_thread": seen, "owner_after": then["ok"], "user_turn_calls": turns(fake)}
case("wrong_thread", wrong_thread)
def reentrant():
    holder = {}
    def respond(req, fake):
        holder["inner"] = outcome_of(lambda: holder["agent"].generate_next_message(user("inner"), holder["state"]))
        return says("outer ok")(req, fake)
    agent, fake, _, _ = make([opened(), respond])
    holder["agent"], holder["state"] = agent, agent.get_init_state(opener())
    outer = outcome_of(lambda: agent.generate_next_message(user(), holder["state"]))
    return {"inner": holder["inner"], "outer_ok": outer["ok"], "user_turn_calls": turns(fake)}
case("reentrant", reentrant)
def deferred_stop():
    holder = {}
    def respond(req, fake):
        holder["agent"].stop()
        return says("would succeed")(req, fake)
    agent, fake, _, _ = make([opened(), respond])
    holder["agent"] = agent
    state = agent.get_init_state(opener())
    result = outcome_of(lambda: agent.generate_next_message(user(), state))
    return {"result": result, "closed": len(fake.closed)}
case("deferred_stop", deferred_stop)


# -- slot claim and registration -------------------------------------------------------------------------------
def slots():
    kit = RetailTools(None)
    env = Environment(domain_name="retail", policy=FICT, tools=kit)
    outside = outcome_of(lambda: build_agent(A.FACTORY_NAME, env))
    slot = A.TrialSlot(uuid4(), "retail", Fake([]), A.TrialBudget(100.0, Clock(), 1.0, 2.0))
    with A.trial(slot):
        first = outcome_of(lambda: build_agent(A.FACTORY_NAME, env))
        second = outcome_of(lambda: build_agent(A.FACTORY_NAME, env))
    reenter = outcome_of(lambda: A.trial(slot).__enter__())
    contended = A.TrialSlot(uuid4(), "retail", Fake([]), A.TrialBudget(100.0, Clock(), 1.0, 2.0))
    barrier, results = threading.Barrier(2), []
    def contend():
        def run():
            with A.trial(contended):
                barrier.wait(5)
                return build_agent(A.FACTORY_NAME, env)
        results.append(outcome_of(run))
    threads = [threading.Thread(target=contend) for _ in range(2)]
    [t.start() for t in threads]; [t.join(10) for t in threads]
    return {"outside": outside, "first": first["ok"], "second": second, "reenter": reenter,
            "context_after": A._CURRENT.get() is None, "contended": sorted(r["ok"] for r in results),
            "contended_codes": sorted(r.get("code", "") for r in results)}
case("slots", slots)
def registration():
    reg = Registry()
    reg.register_agent_factory(lambda tools, domain_policy, **kw: None, A.FACTORY_NAME)
    conflict = outcome_of(lambda: A.register(reg))
    fresh = Registry()
    A.register(fresh); A.register(fresh)
    return {"conflict": conflict, "fresh_is_ours": fresh.get_agent_factory(A.FACTORY_NAME) is A.create_policyops_agent}
case("registration", registration)


# -- protocol, state and fixed errors ---------------------------------------------------------------------------
def protocol():
    out = {}
    agent, fake, _, _ = make([opened()])
    state = agent.get_init_state(opener())
    multi = MultiToolMessage(role="tool", tool_messages=[tm("a"), tm("b")])
    out["multi_tool"] = outcome_of(lambda: agent.generate_next_message(multi, state))
    agent, fake, _, _ = make([opened()])
    state = agent.get_init_state(opener())
    out["tool_without_pending"] = outcome_of(lambda: agent.generate_next_message(tm("c1"), state))
    agent, fake, _, _ = make([opened(), tool("c1", "calculate", {"expression": "1+1"})])
    state = agent.get_init_state(opener())
    _, state = agent.generate_next_message(user(), state)
    out["user_while_pending"] = outcome_of(lambda: agent.generate_next_message(user(), state))
    agent, fake, _, _ = make([opened(), tool("c1", "calculate", {"expression": "1+1"})])
    state = agent.get_init_state(opener())
    _, state = agent.generate_next_message(user(), state)
    out["wrong_tool_id"] = outcome_of(lambda: agent.generate_next_message(tm("c2"), state))
    out["wrong_tool_id_diag"] = agent.diagnostics
    agent, fake, _, _ = make([opened()])
    state = agent.get_init_state(opener())
    out["state_copy"] = outcome_of(lambda: agent.generate_next_message(user(), dataclasses.replace(state)))
    agent, fake, _, _ = make([opened()])
    out["not_initialized"] = outcome_of(lambda: agent.generate_next_message(user(), None))
    agent, fake, _, _ = make([opened()])
    agent.get_init_state(opener())
    out["init_twice"] = outcome_of(lambda: agent.get_init_state(opener()))
    agent, fake, _, _ = make([opened()])
    state = agent.get_init_state(opener())
    secret = "user-canary-" + uuid4().hex
    try:
        agent.generate_next_message(user(secret + "\x07"), state)
    except A.AdapterRefused as refused:
        shown = "".join(traceback.format_exception(refused)) + json.dumps(agent.diagnostics)
        out["user_refused"] = {"code": refused.code, "leak": secret in shown}
    agent, fake, _, _ = make([opened()])
    agent.set_seed(300); agent.set_seed(True)
    out["seed"] = {"seed": agent.seed, "diag": agent.diagnostics, "is_stop": agent.is_stop(None)}
    original = A.MAX_EVENTS
    A.MAX_EVENTS = 1
    try:
        agent, fake, _, _ = make([opened(), says("one"), says("two")])
        state = agent.get_init_state(opener())
        _, state = agent.generate_next_message(user(), state)
        out["event_limit"] = outcome_of(lambda: agent.generate_next_message(user(), state))
    finally:
        A.MAX_EVENTS = original
    return out
case("protocol", protocol)

# -- review regressions (draft-findings-boundaries-1) ------------------------------------------------------------
def spoofed(error, where):
    script = [raising(error)] if where == "open" else [opened(), raising(error)]
    agent, fake, _, _ = make(script)
    try:
        if where == "open":
            agent.get_init_state(opener())
        else:
            agent.generate_next_message(user(), agent.get_init_state(opener()))
    except A.AdapterRefused as refused:
        return {"code": refused.code, "leak": SPOOF in "".join(traceback.format_exception(refused)) + str(refused),
                "closed": len(fake.closed), "diag": agent.diagnostics}
    except BaseException as other:
        return {"other": type(other).__name__, "leak": SPOOF in str(other)}
SPOOF = "spoof-canary-" + uuid4().hex
case("spoof_open_refused", lambda: spoofed(A.AdapterRefused(SPOOF), "open"))
case("spoof_open_terminated", lambda: spoofed(A.AgentTerminated("deadline", SPOOF), "open"))
case("spoof_turn_refused", lambda: spoofed(A.AdapterRefused(SPOOF), "turn"))
case("spoof_turn_terminated", lambda: spoofed(A.AgentTerminated("budget", SPOOF), "turn"))


class SetupAbort(BaseException):
    pass
class CloseAbort(BaseException):
    pass
def primary_preserved():
    agent, fake, _, _ = make([raising(SetupAbort())], close_error=CloseAbort())
    try:
        agent.get_init_state(opener())
    except BaseException as error:
        caught = type(error).__name__
    return {"caught": caught, "closed": len(fake.closed), "diag": agent.diagnostics}
case("cleanup_base_primary", primary_preserved)
def stop_never_raises():
    agent, fake, _, _ = make([opened()], close_error=CloseAbort())
    agent.get_init_state(opener())
    raised = []
    for _ in range(2):
        try:
            agent.stop()
        except BaseException as error:
            raised.append(type(error).__name__)
    return {"raised": raised, "closed": len(fake.closed), "diag": agent.diagnostics}
case("cleanup_base_stop", stop_never_raises)


def policy_bound():
    calls = []
    original = A.text_sha256
    A.text_sha256 = lambda text: calls.append(len(text)) or original(text)
    try:
        kit = RetailTools(None)
        tools = list(kit.get_tools().values())
        out = {}
        for name, text in (("oversize", "x" * 64_001), ("empty", ""), ("not_str", b"policy")):
            slot = A.TrialSlot(uuid4(), "retail", Fake([]), A.TrialBudget(100.0, Clock(), 1.0, 2.0))
            with A.trial(slot):
                out[name] = outcome_of(lambda: A.create_policyops_agent(tools=tools, domain_policy=text))
        out["hash_calls_before_valid"] = list(calls)
        unicode_policy = "Pol\u00edtica \u2603 \u2014 " + "y" * 100
        slot = A.TrialSlot(uuid4(), "retail", Fake([opened()]), A.TrialBudget(100.0, Clock(), 1.0, 2.0))
        with A.trial(slot):
            agent = A.create_policyops_agent(tools=tools, domain_policy=unicode_policy)
        agent.get_init_state(opener())
        out["unicode_policy_ok"] = slot.bridge.records[0]["request"]["policy"]["text"] == unicode_policy
        out["hash_calls"] = list(calls)
        return out
    finally:
        A.text_sha256 = original
case("policy_bound", policy_bound)


ITERATIONS = []
class History(list):
    def __iter__(self):
        ITERATIONS.append("iter")
        return super().__iter__()
class Recorder:
    def __iter__(self):
        ITERATIONS.append("iter")
        return iter(opener())
    def __len__(self):
        ITERATIONS.append("len")
        return 1
def history_shape():
    out = {}
    for name, history in (("list_subclass_two", History(opener() * 2)), ("list_subclass_one", History(opener())),
                          ("custom_iterable", Recorder()), ("generator", (m for m in opener())),
                          ("two_items", opener() * 2)):
        agent, fake, _, _ = make([opened()])
        out[name] = {"result": outcome_of(lambda: agent.get_init_state(history)), "opens": len(fake.records)}
    out["iterations"] = list(ITERATIONS)
    agent, fake, _, _ = make([opened()])
    out["tuple_one"] = outcome_of(lambda: agent.get_init_state(tuple(opener())))["ok"]
    agent, fake, _, _ = make([opened()])
    out["list_one"] = outcome_of(lambda: agent.get_init_state(opener()))["ok"]
    return out
case("history_shape", history_shape)

print(json.dumps({"cases": cases, "tool_calls": TOOL_CALLS, "data_opens": DATA_OPENS, "binding": binding(
    ["policyops_evals", "policyops_evals.harness", "policyops_evals.harness.tools", "policyops_evals.harness.messages",
     "policyops_evals.harness.adapter", "policyops_contracts", "policyops_contracts.conversation",
     "policyops_testing.network"])}, default=str))
"""


@pytest.fixture(scope="module")
def child(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    empty = tmp_path_factory.mktemp("empty-tau2-data")
    env = {**os.environ, "TAU2_DATA_DIR": str(empty)}
    done = subprocess.run(child_argv(SCENARIOS), env=env, cwd=empty, capture_output=True, text=True,
                          encoding="utf-8", timeout=300, check=False)
    assert done.returncode == 0, done.stderr[-3000:]
    loaded: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    # Retained evidence (written before the binding assertion): the child's exact module sources and hashes.
    record = {"id": "adapter", "source_root": str(REPO), "modules": loaded["binding"]}
    (empty / "child-binding-adapter.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    assert_bound_to_this_checkout(loaded["binding"], BOUND)
    assert loaded["tool_calls"] == [] and loaded["data_opens"] == []
    cases: dict[str, Any] = loaded["cases"]
    return cases


def refused(entry: dict[str, Any]) -> str:
    assert entry["ok"] is False and "code" in entry, entry
    assert entry["chain"] is True, entry  # no raw-data exception chain
    code: str = entry["code"]
    return code


# -- source checks (parent; no upstream import) --------------------------------------------------------------------

def test_the_factory_drops_hidden_keywords_first_and_never_touches_them() -> None:
    tree = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    (factory,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "create_policyops_agent"]
    assert factory.args.kwarg is not None and factory.args.kwarg.arg == "_ignored"
    first = factory.body[0]
    assert isinstance(first, ast.Delete) and [t.id for t in first.targets if isinstance(t, ast.Name)] == ["_ignored"]
    uses = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "_ignored"]
    assert len(uses) == 1 and uses[0] is first.targets[0]  # the `del` is the only code that names it


def test_the_adapter_imports_no_application_and_the_package_init_imports_nothing() -> None:
    tree = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names] + \
              [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m == "policyops" or m.startswith("policyops.")]
    init = ast.parse((ADAPTER.parent / "__init__.py").read_text(encoding="utf-8"))
    assert [type(n).__name__ for n in init.body] == ["Expr"]  # docstring only


# -- behaviour (isolated child) ------------------------------------------------------------------------------------

def test_poison_and_canaries_through_real_build_agent_leave_no_trip_or_reference(child: dict[str, Any]) -> None:
    value = child["poison"]["value"]
    assert value["trips_after_build"] == [] and value["trips"] == []  # build_agent + factory + a future keyword
    assert value["alive"] == {"poison": False, "env": False, "toolkit": False}  # nothing retained by the agent
    assert value["agent_type"] == "PolicyOpsAgent" and value["base_tools"] == [] and value["reply"] == "Hello."
    assert value["canaries_exposed"] == [] and value["policy_canary_in_open"] is True
    assert value["opening"] == {"kind": "agent", "text": "Hi! How can I help you today?"}
    assert len(value["catalog_names"]) == 16 and "get_order_details" in value["catalog_names"]


def test_a_user_turn_with_several_tool_steps_maps_exact_upstream_identities(child: dict[str, Any]) -> None:
    value = child["happy"]["value"]
    assert value["calls"] == [
        {"type": "AssistantMessage", "content": None, "id": "c1", "name": "get_order_details",
         "arguments": {"order_id": "#W0000001"}, "requestor": "assistant"},
        {"type": "AssistantMessage", "content": None, "id": "c2", "name": "get_user_details",
         "arguments": {"user_id": "james_johnson_9321"}, "requestor": "assistant"},
        {"type": "AssistantMessage", "content": None, "id": "c1", "name": "get_order_details",  # a later, legal reuse
         "arguments": {"order_id": "#W0000002"}, "requestor": "assistant"}]
    assert value["texts"] == ["Done.", "Again."] and value["text_types"] == ["AssistantMessage", None]
    assert value["steps"] == [0, 1, 2, 3, 4, 5] and value["distinct_states"] == 6
    assert value["requests"] == [["open", None, None], ["user_turn", 1, 0], ["tool_return", 2, None],
                                 ["tool_return", 3, None], ["user_turn", 4, 1], ["tool_return", 5, None]]
    assert value["tool_results"][0] == {"kind": "tool_result", "call_id": "c1", "content": "Error: not found",
                                        "is_error": True}
    assert value["user_texts"] == ["Hi, where is order #W0000001?", "And order 2?"]
    assert value["closed"] == 1 and value["close_seconds"] == 2.0 and value["session_closed_is_own"] is True


def test_null_means_omit_reaches_upstream_and_the_domain_comes_from_the_slot(child: dict[str, Any]) -> None:
    value = child["banking_null"]["value"]
    assert value["call"]["arguments"] == {"agent_tool_name": "unlock_x"}
    assert (value["domain"], value["source"]) == ("banking_knowledge", "harness_domain_policy")


def test_stale_or_mismatched_envelopes_refuse_before_any_upstream_action(child: dict[str, Any]) -> None:
    expected = {"stale_seq": "stale_event", "stale_session": "session_mismatch", "stale_turn": "stale_event",
                "stale_config": "stale_event", "stale_conversation": "stale_event"}
    for name, code in expected.items():
        value = child[name]["value"]
        assert refused(value["result"]) == code, name
        assert refused(value["after"]) == "agent_closed" and value["closed"] == 1, name


def test_legitimate_terminal_outcomes_surface_unchanged_and_knowledge_entries_are_accepted(
        child: dict[str, Any]) -> None:
    assert child["terminal_pre_append"]["value"]["result"] == {"ok": False, "terminal": "transcript_limit",
                                                               "detail": None, "pending": None}
    assert child["terminal_knowledge"]["value"]["result"]["terminal"] == "knowledge_steps_exhausted"
    assert child["message_after_knowledge"]["value"]["result"]["ok"] is True
    pending = child["terminal_pending"]["value"]
    assert pending["result"] == {"ok": False, "terminal": "tool_port_failed", "detail": "port.runtimeerror",
                                 "pending": {"call_id": "c9", "name": "cancel_pending_order", "read_only": False,
                                             "outcome": "unknown"}}
    assert all(child[n]["value"]["closed"] == 1 for n in ("terminal_pre_append", "terminal_knowledge",
                                                         "terminal_pending"))


def test_invalid_port_returns_are_refused_with_fixed_codes(child: dict[str, Any]) -> None:
    for name in ("port_dict", "port_bad_call", "port_bad_outcome"):
        assert refused(child[name]["value"]["result"]) == "bridge_protocol", name
    assert refused(child["port_seq_type"]["value"]["result"]) == "stale_event"
    assert refused(child["port_unknown_tool"]["value"]["result"]) == "message_refused"
    assert refused(child["port_knowledge_call"]["value"]["result"]) == "message_refused"
    raised = child["port_raises"]["value"]
    assert (raised["code"], raised["leak"], raised["closed"]) == ("bridge_failed", False, 1)
    assert raised["diag"] == [["bridge_failed", "valueerror"]]
    assert child["port_interrupt"]["value"] == {"interrupt_preserved": True, "closed": 1}


def test_session_acquisition_always_releases_its_own_id_and_never_a_foreign_one(child: dict[str, Any]) -> None:
    late = child["open_late"]["value"]
    assert late["result"] == {"ok": False, "terminal": "deadline", "detail": "late_bridge_result", "pending": None}
    assert late["closed"] == [[late["own"], 2.0]]
    expected = {"open_foreign": "session_mismatch", "open_bad_digest": "bridge_protocol",
                "open_dict": "bridge_protocol", "open_raises": "bridge_failed",
                "open_raises_close_fails": "bridge_failed"}
    for name, code in expected.items():
        value = child[name]["value"]
        assert refused(value["result"]) == code, name
        assert value["closed"] == [[value["own"], 2.0]] and value["closed_only_own"], name
    assert ["foreign_session_returned", None] in child["open_foreign"]["value"]["diag"]
    assert ["close_failed", "oserror"] in child["open_raises_close_fails"]["value"]["diag"]  # primary error kept
    assert refused(child["open_history_empty"]["value"]) == "unsupported_initial_history"


def test_budget_and_clock_faults_close_the_agent_with_the_finite_grace(child: dict[str, Any]) -> None:
    for name in ("clock_nan", "clock_raises"):
        value = child[name]["value"]
        assert refused(value["result"]) == "clock_invalid", name
        assert len(value["closed"]) == 1 and value["closed"][0][1] == 2.0, name  # cleanup never reads the clock
        assert value["user_turn_calls"] == 0, name
    assert {name: entry["code"] for name, entry in child["budget"].items()} == dict.fromkeys(child["budget"],
                                                                                              "budget_invalid")
    exhausted = child["exhausted"]["value"]
    assert exhausted["result"] == {"ok": False, "terminal": "deadline", "detail": "trial_budget_exhausted",
                                   "pending": None}
    assert refused(exhausted["later"]) == "agent_closed" and refused(exhausted["fresh_init"]) == "agent_closed"
    assert (exhausted["closed"], exhausted["user_turn_calls"]) == (1, 0)
    assert child["capped_seconds"]["value"] == [900.0, 900.0]


def test_owner_thread_reentry_and_deferred_stop_do_no_extra_bridge_work(child: dict[str, Any]) -> None:
    wrong = child["wrong_thread"]["value"]
    assert refused(wrong["other_thread"]) == "wrong_thread"
    assert wrong["owner_after"] is True and wrong["user_turn_calls"] == 1
    reentrant = child["reentrant"]["value"]
    assert refused(reentrant["inner"]) == "reentrant_call"
    assert reentrant["outer_ok"] is True and reentrant["user_turn_calls"] == 1
    deferred = child["deferred_stop"]["value"]
    assert refused(deferred["result"]) == "agent_closed" and deferred["closed"] == 1  # no success after the stop


def test_the_slot_claim_is_single_use_permanent_and_registration_fails_closed(child: dict[str, Any]) -> None:
    slots = child["slots"]["value"]
    assert refused(slots["outside"]) == "slot_unavailable" and slots["first"] is True
    assert refused(slots["second"]) == "slot_unavailable" and refused(slots["reenter"]) == "slot_unavailable"
    assert slots["context_after"] is True
    assert slots["contended"] == [False, True] and slots["contended_codes"] == ["", "slot_unavailable"]
    registration = child["registration"]["value"]
    assert refused(registration["conflict"]) == "registration_conflict" and registration["fresh_is_ours"] is True


def test_protocol_and_state_misuse_are_refused_without_leaking_content(child: dict[str, Any]) -> None:
    protocol = child["protocol"]["value"]
    expected = {"multi_tool": "multi_tool_message", "tool_without_pending": "protocol_out_of_order",
                "user_while_pending": "protocol_out_of_order", "wrong_tool_id": "message_refused",
                "state_copy": "state_mismatch", "not_initialized": "not_initialized",
                "init_twice": "already_initialized", "event_limit": "event_limit"}
    assert {name: refused(protocol[name]) for name in expected} == expected
    assert ["message_refused", "wrong_call_id"] in protocol["wrong_tool_id_diag"]
    assert protocol["user_refused"] == {"code": "message_refused", "leak": False}
    assert protocol["seed"] == {"seed": 300, "diag": [["seed_invalid", None]], "is_stop": False}


def test_a_port_cannot_spoof_a_trusted_adapter_error_or_leak_through_it(child: dict[str, Any]) -> None:
    """Review regression (draft-findings-boundaries-1, 1)."""
    for name in ("spoof_open_refused", "spoof_open_terminated", "spoof_turn_refused", "spoof_turn_terminated"):
        value = child[name]["value"]
        assert (value["code"], value["leak"], value["closed"]) == ("bridge_failed", False, 1), name
        assert value["diag"][0][0] == "bridge_failed", name


def test_cleanup_failures_never_replace_the_primary_error_or_escape_stop(child: dict[str, Any]) -> None:
    """Review regression (draft-findings-boundaries-1, 2)."""
    primary = child["cleanup_base_primary"]["value"]
    assert primary["caught"] == "SetupAbort" and primary["closed"] == 1
    assert ["close_failed", "closeabort"] in primary["diag"]
    stop = child["cleanup_base_stop"]["value"]
    assert stop["raised"] == [] and stop["closed"] == 1 and stop["diag"] == [["close_failed", "closeabort"]]


def test_the_policy_is_bounded_before_any_hash_and_unicode_policies_pass(child: dict[str, Any]) -> None:
    """Review regression (draft-findings-boundaries-1, 3)."""
    value = child["policy_bound"]["value"]
    for name in ("oversize", "empty", "not_str"):
        assert refused(value[name]) == "policy_invalid", name
    assert value["hash_calls_before_valid"] == []
    assert value["unicode_policy_ok"] is True and len(value["hash_calls"]) == 1


def test_the_initial_history_shape_is_refused_before_any_copy_or_iteration(child: dict[str, Any]) -> None:
    """Review regression (draft-findings-boundaries-1, 4)."""
    value = child["history_shape"]["value"]
    for name in ("list_subclass_two", "list_subclass_one", "custom_iterable", "generator", "two_items"):
        assert refused(value[name]["result"]) == "unsupported_initial_history", name
        assert value[name]["opens"] == 0, name
    assert value["iterations"] == []
    assert value["tuple_one"] is True and value["list_one"] is True
