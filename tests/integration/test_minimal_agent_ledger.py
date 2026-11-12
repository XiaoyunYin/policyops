"""T20 composed: the minimal agent with the explicit agent adapter, the real T11 `call`, the real T10/T11 ledger on
PostgreSQL (actual app runtime role), the real SDK clients and a scripted `httpx2` transport. It checks that the
agent's grant counts match the ledger, and that cancellation billing follows the phase that was interrupted: a stalled
dispatched create keeps its unresolved hold, while a cancelled tool after a settled model call keeps the known bill and
invents no hold. No external provider HTTP, key or provider account; a mock transport proves the boundary only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import json
import time
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import httpx2
from pydantic import SecretStr
import pytest

from policyops.budget.config import Configuration
from policyops.budget.ledger import Ledger, RunBinding
from policyops.orchestration import minimal
from policyops.orchestration.minimal import ConversationClosed, MinimalAgent, agent_config, retail_catalog
from policyops.orchestration.ports import agent_model_port
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import NewCase, NewRun, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers.calls import Providers
from policyops_contracts.conversation import AgentToolCall, UserMessage
from policyops_contracts.digest import text_sha256
from policyops_testing.agent_fakes import FakeTools, fictional_policy
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.claims import component_ledger as build_app_ledger


pytestmark = pytest.mark.postgres
KEY = SecretStr("synthetic-test-credential-0000")
Handler = Callable[[httpx2.Request], httpx2.Response | Awaitable[httpx2.Response]]
USAGE = {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
         "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8}, "total_tokens": 940}


class Body(httpx2.AsyncByteStream):
    def __init__(self, data: bytes) -> None:
        self.data = data

    async def __aiter__(self) -> Any:
        yield self.data


class Routes(httpx2.AsyncBaseTransport):
    """Scripted answers per path; records every request that reached it."""

    def __init__(self, counts: list[Handler], creates: list[Handler]) -> None:
        self.queues = {"count": list(counts), "create": list(creates)}
        self.seen: list[str] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        kind = "count" if request.url.path.endswith(("input_tokens", "count_tokens")) else "create"
        self.seen.append(kind)
        assert self.queues[kind], f"an unscripted {kind} request reached the transport"
        answer = self.queues[kind].pop(0)(request)
        return await answer if asyncio.iscoroutine(answer) else answer  # type: ignore[return-value]


def reply(data: Any) -> Handler:
    body = json.dumps(data).encode()
    return lambda request: httpx2.Response(200, headers={"content-type": "application/json"}, stream=Body(body),
                                           request=request)


def tokens(n: int) -> Handler:
    return reply({"object": "response.input_tokens", "input_tokens": n})


def luna(*output: dict[str, Any]) -> dict[str, Any]:
    return {"id": f"resp_{uuid4().hex[:8]}", "object": "response", "model": "gpt-6-luna", "status": "completed",
            "service_tier": "default", "usage": USAGE, "output": list(output)}


def message(text: str) -> Handler:
    return reply(luna({"type": "message", "role": "assistant",
                       "content": [{"type": "output_text", "text": text, "annotations": []}]}))


def function_call(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> Handler:
    return reply(luna({"type": "function_call", "call_id": call_id, "name": name,
                       "arguments": json.dumps(arguments)}))


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("minimal_agent")


def setup(db: AppDatabase) -> tuple[Ledger, RunBinding, UUID]:
    ws, case, run, now = uuid4(), uuid4(), uuid4(), datetime.now(UTC)
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=ws, slug=f"ws-{ws.hex[:12]}", name="Minimal agent test",
                                              created_at=now))
    with workspace_transaction(db.engine(APP_RUNTIME), ws) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=ws, scenario="retail", customer_user_id=None,
                                                created_by=None, created_at=now))
        repo.create_run(conn, NewRun(id=run, workspace_id=ws, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=now + timedelta(hours=1),
                                     created_at=now))
    books = build_app_ledger(env="test", engine=db.engine(APP_RUNTIME, pool_size=6), workspace_id=ws,
                             configuration=Configuration())
    return books, RunBinding(run), run


def attempts(db: AppDatabase, run: UUID) -> list[tuple[Any, ...]]:
    with db.superuser() as conn:
        rows: list[tuple[Any, ...]] = conn.execute(
            "SELECT a.state, a.count_state, a.contract_block, a.actual_usd FROM app.usage_attempts a "
            "JOIN app.budget_scopes s ON s.id = a.scope_id WHERE s.run_id = %s ORDER BY a.created_at",
            (run,)).fetchall()
    return rows


def run_scope(db: AppDatabase, run: UUID) -> tuple[Any, ...]:
    with db.superuser() as conn:
        return tuple(conn.execute("SELECT spent_usd, held_usd, calls_consumed, calls_held, counts_used "
                                  "FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone())


def agent(books: Ledger, binding: RunBinding, routes: Routes, tools: FakeTools) -> MinimalAgent:
    policy, catalog = fictional_policy(), retail_catalog()
    port = agent_model_port(books, binding, lambda: Providers(credentials={"openai": KEY, "anthropic": KEY},
                                                              transport=lambda provider: routes))
    return MinimalAgent(agent_config(policy, catalog, books.configuration), policy, catalog,
                        conversation_id=uuid4(), model=port, tools=tools, knowledge=None,
                        configuration=books.configuration, env="test")


def leftover_tasks() -> list[asyncio.Task[Any]]:
    return [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]


def test_a_settled_conversation_reports_exactly_the_ledger_grants(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    routes = Routes([tokens(1200), tokens(1300)],
                    [function_call("get_order_details", {"order_id": "#W0000001"}), message("It is pending.")])
    tools = FakeTools()
    bot = agent(books, binding, routes, tools)
    outcome = asyncio.run(bot.turn(UserMessage(text="Where is order #W0000001?"), deadline=time.monotonic() + 30))
    assert outcome.message is not None and outcome.message.text == "It is pending."
    assert [e.kind for e in outcome.appended] == ["user", "tool_call", "tool_result", "agent"]
    assert routes.seen == ["count", "create", "count", "create"]
    assert [c.call_id for c in tools.calls] == ["call_1"]
    rows = attempts(db, run)
    assert [row[:3] for row in rows] == [("settled", "admitted", None)] * 2 and all(row[3] > 0 for row in rows)
    spent, held, consumed, calls_held, counts = run_scope(db, run)
    assert (held, consumed, calls_held, counts) == (0, 2, 0, 2) and spent == sum(row[3] for row in rows)
    assert (outcome.model_calls, outcome.counts_claimed, outcome.inferences_dispatched) == (2, counts, consumed)
    assert outcome.cleanup_unconfirmed is False


def test_cancelling_a_stalled_dispatched_create_keeps_its_unresolved_hold(db: AppDatabase) -> None:
    books, binding, run = setup(db)

    async def scenario() -> tuple[MinimalAgent, list[asyncio.Task[Any]]]:
        sent = asyncio.Event()

        async def hang(request: httpx2.Request) -> httpx2.Response:
            sent.set()
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

        bot = agent(books, binding, Routes([tokens(1200)], [hang]), FakeTools())
        task = asyncio.create_task(bot.turn(UserMessage(text="Hello"), deadline=time.monotonic() + 30))
        await sent.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(ConversationClosed):
            await bot.turn(UserMessage(text="again"), deadline=time.monotonic() + 30)
        return bot, leftover_tasks()

    bot, left = asyncio.run(scenario())
    assert attempts(db, run) == [("unresolved", "admitted", None, None)]
    assert run_scope(db, run)[1:4] == (Decimal("0.002624"), 1, 0)  # the hold, and the call slot it consumed
    snapshot = bot.snapshot()
    assert (snapshot.terminal, snapshot.pending_tool, snapshot.model_calls, left) == ("cancelled", None, 1, [])


def test_cancelling_a_tool_after_a_settled_model_call_keeps_the_known_bill_and_invents_no_hold(
        db: AppDatabase) -> None:
    books, binding, run = setup(db)

    async def scenario() -> tuple[MinimalAgent, FakeTools, list[asyncio.Task[Any]]]:
        started = asyncio.Event()

        async def stall(call: AgentToolCall) -> object:
            started.set()
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

        tools = FakeTools(handler=stall)
        bot = agent(books, binding, Routes([tokens(1200)], [function_call(
            "cancel_pending_order", {"order_id": "#W0000001", "reason": "no longer needed"})]), tools)
        task = asyncio.create_task(bot.turn(UserMessage(text="Cancel it"), deadline=time.monotonic() + 30))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return bot, tools, leftover_tasks()

    bot, tools, left = asyncio.run(scenario())
    ((state, count_state, block, actual),) = attempts(db, run)
    assert (state, count_state, block) == ("settled", "admitted", None) and actual > 0
    spent, held, consumed, calls_held, counts = run_scope(db, run)
    assert (spent, held, consumed, calls_held, counts) == (actual, 0, 1, 0, 1)
    snapshot = bot.snapshot()
    assert snapshot.terminal == "cancelled" and left == [] and tools.cleaned == ["call_1"]
    pending = snapshot.pending_tool
    assert pending is not None and (pending.call_id, pending.name, pending.read_only, pending.outcome) == (
        "call_1", "cancel_pending_order", False, "unknown")


def test_a_reply_settled_after_the_deadline_is_billed_but_never_accepted(db: AppDatabase,
                                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    """The agent's clock is skewed past the turn deadline while T11 receives and settles the reply on the real
    clock: the actual adapter/ledger boundary records the known bill, and the agent refuses the late action."""
    books, binding, run = setup(db)
    skew = SimpleNamespace(offset=0.0)
    monkeypatch.setattr(minimal, "time", SimpleNamespace(monotonic=lambda: time.monotonic() + skew.offset))

    def late(request: httpx2.Request) -> httpx2.Response:
        skew.offset = 3600.0
        answer = message("Done, your order is cancelled.")(request)
        assert isinstance(answer, httpx2.Response)
        return answer

    routes = Routes([tokens(1200)], [late])
    bot = agent(books, binding, routes, FakeTools())
    outcome = asyncio.run(bot.turn(UserMessage(text="Cancel it"), deadline=time.monotonic() + 30))
    assert (outcome.message, outcome.terminal, outcome.detail) == (None, "deadline", "late_model_result")
    assert (outcome.counts_claimed, outcome.inferences_dispatched) == (1, 1)
    ((state, _, _, actual),) = attempts(db, run)
    assert state == "settled" and actual > 0 and run_scope(db, run)[1:4] == (0, 1, 0)
    assert [e.kind for e in bot.snapshot().transcript] == ["user"] and routes.seen == ["count", "create"]
