"""Scripted ports for the minimal agent (T20); test only (application environment).

They never call a provider or execute a real action. `ScriptedModel` returns scripted T11 `CallReport`s and records
every request, key and operation it received. `FakeTools` returns in-memory results over the fictional
`domain.examples.World` fixtures, or runs a scripted handler. `FakeKnowledge` returns content only. Each records the
cleanup of every call it began (including a cancelled one), and each declares `test_only`, which the agent refuses
outside the test environment.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import json
from typing import Any, ClassVar, Literal
from uuid import UUID, uuid4

from policyops.domain.examples import World
from policyops.providers.calls import AttemptRecord, CallReport
from policyops_contracts.conversation import AgentToolCall, KnowledgeResult, PolicyContext, ToolResult
from policyops_contracts.digest import text_sha256
from policyops_contracts.model import ModelRequest, ModelResult, Outcome, ReportedUsage, ToolCall


USAGE = ReportedUsage(state="known", input_total=900, cache_read=0, output=40)
FICTIONAL_POLICY_TEXT = ("# Example retail policy (fictional)\n\nAuthenticate the customer by email before any "
                         "account action. Transfer to a human agent when a request is out of scope.")


def fictional_policy(domain: Literal["retail", "banking_knowledge"] = "retail",
                     text: str = FICTIONAL_POLICY_TEXT) -> PolicyContext:
    return PolicyContext(domain=domain, source="fictional", text=text, sha256=text_sha256(text))


def granted(fate: Literal["settled", "unresolved"] = "settled", *, cleanup: bool = True) -> AttemptRecord:
    """One attempt record with both grants (what a sent T11 attempt reports)."""
    return AttemptRecord(uuid4(), "agent.step.r0.a0", "0" * 64, fate=fate, cleanup_confirmed=cleanup,
                         count_granted=True, dispatch_granted=True)


def result(outcome: Outcome = "completed", *, text: str | None = None, calls: tuple[ToolCall, ...] = (),
           reason_code: str | None = None, stop_reason: str | None = None) -> ModelResult:
    return ModelResult(outcome=outcome, provider="openai", requested_model="gpt-6-luna", text=text,
                       tool_calls=calls, reason_code=reason_code, stop_reason=stop_reason, usage=USAGE)


def report(value: ModelResult, *attempts: AttemptRecord) -> CallReport:
    return CallReport(value, "result", value.reason_code, list(attempts or (granted(),)))


def says(text: str) -> CallReport:
    return report(result(text=text))


def calls(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> CallReport:
    return report(result(calls=(ToolCall(call_id=call_id, name=name,
                                          arguments_json=json.dumps(arguments, sort_keys=True,
                                                                    separators=(",", ":"))),)))


Scripted = CallReport | Callable[[ModelRequest], Awaitable[CallReport]]


@dataclass
class ScriptedModel:
    script: list[Scripted]
    requests: list[ModelRequest] = field(default_factory=list)
    keys: list[UUID] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    deadlines: list[float] = field(default_factory=list)
    test_only: ClassVar[bool] = True

    async def complete(self, request: ModelRequest, *, key: UUID, operation: str, deadline: float) -> CallReport:
        self.requests.append(request)
        self.keys.append(key)
        self.operations.append(operation)
        self.deadlines.append(deadline)
        if not self.script:
            raise AssertionError("an unscripted model call")
        step = self.script.pop(0)
        return step if isinstance(step, CallReport) else await step(request)


def world_reads(world: World | None = None) -> dict[str, str]:
    """Canonical JSON read results over the fictional fixtures (not upstream semantics)."""
    world = world or World()
    return {
        "find_user_id_by_email": json.dumps(world.user_id),
        "get_user_details": world.customer().model_dump_json(),
        "get_order_details": world.order().model_dump_json(),
        "calculate": "42",
        "transfer_to_human_agents": "Transfer successful",
    }


@dataclass
class FakeTools:
    results: dict[str, str] = field(default_factory=world_reads)
    handler: Callable[[AgentToolCall], Awaitable[object]] | None = None
    calls: list[AgentToolCall] = field(default_factory=list)
    cleaned: list[str] = field(default_factory=list)
    test_only: ClassVar[bool] = True

    async def execute(self, call: AgentToolCall, *, deadline: float) -> ToolResult:
        self.calls.append(call)
        try:
            if self.handler is not None:
                return await self.handler(call)  # type: ignore[return-value]  # a handler may return anything
            return ToolResult(call_id=call.call_id, content=self.results[call.name])
        finally:
            self.cleaned.append(call.call_id)


@dataclass
class FakeKnowledge:
    content: str = "[1] Refunds go to the original payment method. (fictional evidence)"
    handler: Callable[[str], Awaitable[object]] | None = None
    queries: list[tuple[str, UUID, int]] = field(default_factory=list)
    cleaned: list[int] = field(default_factory=list)
    test_only: ClassVar[bool] = True

    async def search(self, query: str, *, conversation_id: UUID, index: int, deadline: float) -> KnowledgeResult:
        self.queries.append((query, conversation_id, index))
        try:
            if self.handler is not None:
                return await self.handler(query)  # type: ignore[return-value]
            return KnowledgeResult(content=self.content)
        finally:
            self.cleaned.append(index)
