"""T14 grant observability composed: `providers.calls.call` with the real T10/T11 app ledger on PostgreSQL (actual app
runtime), the real OpenAI SDK and a scripted `httpx2` transport. `count_granted` / `dispatch_granted` record exactly
the ledger grants this invocation obtained, next to the ledger's own attempt state and the transport's observed
requests (grants are not proof of transmission; the transport counts are separate evidence). No external HTTP."""

from __future__ import annotations

import asyncio
from pathlib import Path
import time
from typing import Any
from uuid import UUID, uuid4

import httpx2
import pytest

from policyops.budget.config import Configuration
from policyops.budget.ledger import Ledger, RunBinding
from policyops.persistence.runs import Fenced
from policyops.providers.calls import CallLimits, CallReport, call
from policyops_contracts.model import Message, ModelRequest, OutputSpec, TextPart
from policyops_testing.app_database import AppDatabase
from policyops_testing.claims import component_ledger as build_app_ledger
from policyops_testing.retrieval_fixtures import Handler, Scripted, World, count_reply, luna_reply, openai_json, slow


pytestmark = pytest.mark.postgres
ANSWER = '{"type":"object","properties":{"decision":{"type":"string","enum":["a","b"]}},"required":["decision"],' \
         '"additionalProperties":false}'
REQUEST = ModelRequest(instructions="Decide.", max_output_tokens=256,
                       messages=(Message(role="user", parts=(TextPart(text="Choose."),)),),
                       output=OutputSpec(name="answer", answer_schema_json=ANSWER))


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    return World(shared_db, tmp_path)


def ledger(world: World) -> Ledger:
    return build_app_ledger(env="test", engine=world.engine, workspace_id=world.ws, configuration=Configuration())


def go(books: Ledger, transport: Scripted, run: UUID, key: UUID, *, seconds: float = 30.0) -> CallReport:
    return asyncio.run(call(books, transport.providers()(), RunBinding(run), key, "rerank", REQUEST, "reranker",
                            deadline=time.monotonic() + seconds,
                            limits=CallLimits(retries_per_request=0, repairs=0, backoff_seconds=0.0)))


def attempt_rows(world: World, run: UUID) -> list[tuple[Any, ...]]:
    with world.db.superuser() as conn:
        return [tuple(r) for r in conn.execute(
            "SELECT a.operation_id, a.state, a.count_state FROM app.usage_attempts a JOIN app.budget_scopes s "
            "ON s.workspace_id = a.workspace_id AND s.id = a.scope_id WHERE s.run_id = %s ORDER BY a.created_at",
            (run,)).fetchall()]


def flags(report: CallReport) -> tuple[bool, bool]:
    (record,) = report.attempts
    return record.count_granted, record.dispatch_granted


def test_a_settled_call_and_a_replaying_duplicate(world: World) -> None:
    run, key, books = world.run(), uuid4(), ledger(world)
    owner = Scripted(counts=[count_reply(1200)], creates=[luna_reply('{"decision": "a"}')])
    first = go(books, owner, run, key)
    assert first.status == "result" and flags(first) == (True, True) and first.attempts[0].fate == "settled"
    duplicate = Scripted()
    again = go(books, duplicate, run, key)
    assert again.attempts[0].fate == "replayed" and flags(again) == (False, False) and duplicate.seen == []
    assert attempt_rows(world, run) == [("rerank.r0.a0", "settled", "admitted")]
    assert owner.seen == ["count", "create"]


@pytest.mark.parametrize(("counts", "count_state"), [
    ([openai_json({"error": {"message": "synthetic"}}, status=500)], "failed"),
    ([count_reply(20_000)], "rejected"),
])
def test_a_failed_or_unadmitted_count_keeps_only_the_count_grant(world: World, counts: list[Handler],
                                                                 count_state: str) -> None:
    run = world.run()
    transport = Scripted(counts=counts)
    report = go(ledger(world), transport, run, uuid4())
    assert flags(report) == (True, False) and report.attempts[0].fate == "released"
    assert attempt_rows(world, run) == [("rerank.r0.a0", "released", count_state)] and transport.seen == ["count"]


def test_a_run_ended_during_the_count_refuses_dispatch_after_the_count_grant(world: World) -> None:
    run = world.run()

    def end_then_count(request: httpx2.Request) -> httpx2.Response:
        world.end(run)  # synchronous test setup between the count grant and the dispatch decision
        answer = count_reply(1200)(request)
        assert isinstance(answer, httpx2.Response)
        return answer

    transport = Scripted(counts=[end_then_count])
    with pytest.raises(Fenced, match="run_terminal"):
        go(ledger(world), transport, run, uuid4())
    assert transport.seen == ["count"]
    assert attempt_rows(world, run) == [("rerank.r0.a0", "released", "admitted")]


def test_a_count_cap_refusal_has_no_grant(world: World) -> None:
    run, books = world.run(), ledger(world)
    go(books, Scripted(counts=[count_reply(1200)], creates=[luna_reply('{"decision": "a"}')]), run, uuid4())
    with world.db.superuser() as conn:  # exhaust the run scope's count units (test setup)
        conn.execute("UPDATE app.budget_scopes SET counts_used = cap_counts WHERE run_id = %s", (run,))
    transport = Scripted()
    report = go(books, transport, run, uuid4())
    assert (report.status, report.reason) == ("budget", "count_cap") and flags(report) == (False, False)
    assert transport.seen == []


def test_the_deadline_during_the_count_and_after_the_dispatch(world: World) -> None:
    run, books = world.run(), ledger(world)
    during_count = go(books, Scripted(counts=[slow(count_reply(1200), 30.0)]), run, uuid4(), seconds=1.0)
    assert during_count.status == "deadline" and flags(during_count) == (True, False)
    assert during_count.attempts[0].fate == "released"
    after_dispatch = go(books, Scripted(counts=[count_reply(1200)], creates=[slow(luna_reply("{}"), 30.0)]), run,
                        uuid4(), seconds=1.5)
    assert after_dispatch.status == "deadline" and flags(after_dispatch) == (True, True)
    assert after_dispatch.attempts[0].fate == "unresolved"
    assert sorted(r[1:] for r in attempt_rows(world, run)) == [("released", "failed"),  # an interrupted count
                                                              ("unresolved", "admitted")]
