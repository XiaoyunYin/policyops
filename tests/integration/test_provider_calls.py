"""T11 composed: `providers.calls.call` with the real T10/T11 ledger on PostgreSQL (actual app and eval runtime
roles), the real SDK clients and a scripted `httpx2` transport. It checks what is reserved, counted, sent, settled,
held, released or blocked for each provider behaviour. No external provider HTTP and no key or provider account:
loopback PostgreSQL and the Docker harness are used, and a mock transport proves the boundary, not any account's
capability or counting accuracy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import json
import time
from typing import Any
from uuid import UUID, uuid4, uuid5

import httpx2
from pydantic import SecretStr
import pytest

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.budget.ledger import EvalBinding, Ledger, LedgerConflict, RunBinding
from policyops.persistence import repositories as repo
from policyops.persistence.budget import build_app_ledger, build_eval_ledger
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import NewCase, NewRun, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, EVAL_RUNTIME
from policyops.providers.calls import CallLimits, CallReport, Providers, call, call_sync
from policyops.providers.canonical import canonical_bytes, sha256_hex
from policyops.providers.contract import CONTRACT_VERSION, ENDPOINTS
from policyops.providers.serialize import prepare
from policyops_contracts.digest import text_sha256
from policyops_contracts.model import Message, ModelRequest, ModelResult, OutputSpec, TextPart
from policyops_testing.app_database import AppDatabase, NewDatabase


pytestmark = pytest.mark.postgres
KEY = SecretStr("synthetic-test-credential-0000")
SHA = "a" * 64
ANSWER = json.dumps({"type": "object", "properties": {"decision": {"type": "string", "enum": ["approve", "deny"]}},
                     "required": ["decision"], "additionalProperties": False})
Handler = Callable[[httpx2.Request], httpx2.Response | Awaitable[httpx2.Response]]


class Chunks(httpx2.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, delay: float = 0.0, forever: bytes | None = None) -> None:
        self.chunks, self.delay, self.forever, self.closed = chunks, delay, forever, False

    async def __aiter__(self) -> Any:
        for chunk in self.chunks:
            yield chunk
        while self.forever is not None:
            await asyncio.sleep(self.delay)
            yield self.forever

    async def aclose(self) -> None:
        self.closed = True


class Routes(httpx2.AsyncBaseTransport):
    """Scripted answers per path; records every request that reached it."""

    def __init__(self, counts: list[Handler] | None = None, creates: list[Handler] | None = None) -> None:
        self.queues = {"count": list(counts or []), "create": list(creates or [])}
        self.seen: list[str] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        kind = "count" if request.url.path.endswith(("input_tokens", "count_tokens")) else "create"
        self.seen.append(kind)
        assert self.queues[kind], f"an unscripted {kind} request reached the transport"
        answer = self.queues[kind].pop(0)(request)
        return await answer if asyncio.iscoroutine(answer) else answer  # type: ignore[return-value]


def reply(data: Any, status: int = 200, **headers: str) -> Handler:
    body = json.dumps(data).encode()
    return lambda request: httpx2.Response(status, headers={"content-type": "application/json", **headers},
                                           stream=Chunks([body]), request=request)


def tokens(n: int) -> Handler:
    return reply({"object": "response.input_tokens", "input_tokens": n})


def luna(text: str, **changes: Any) -> Handler:
    usage = {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8}, "total_tokens": 940}
    return reply({"id": f"resp_{uuid4().hex[:8]}", "object": "response", "model": "gpt-6-luna",
                  "status": "completed", "service_tier": "default", "usage": usage,
                  "output": [{"type": "message", "role": "assistant",
                              "content": [{"type": "output_text", "text": text, "annotations": []}]}]} | changes)


def providers(routes: Routes) -> Providers:
    return Providers(credentials={"openai": KEY, "anthropic": KEY}, transport=lambda provider: routes)


def request(**changes: Any) -> ModelRequest:
    body: dict[str, Any] = {"instructions": "Decide the return.", "max_output_tokens": 256,
                            "messages": (Message(role="user", parts=(TextPart(text="Return #W0000001."),)),),
                            "output": OutputSpec(name="answer", answer_schema_json=ANSWER)} | changes
    return ModelRequest(**body)


def workspace(db: AppDatabase) -> UUID:
    ws = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=ws, slug=f"ws-{ws.hex[:12]}", name="Provider calls test",
                                              created_at=datetime.now(UTC)))
    return ws


def new_run(db: AppDatabase, ws: UUID) -> UUID:
    case, run, now = uuid4(), uuid4(), datetime.now(UTC)
    with workspace_transaction(db.engine(APP_RUNTIME), ws) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=ws, scenario="retail", customer_user_id=None,
                                                created_by=None, created_at=now))
        repo.create_run(conn, NewRun(id=run, workspace_id=ws, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=now + timedelta(hours=1),
                                     created_at=now))
    return run


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("provider_calls")


def setup(db: AppDatabase, configuration: Configuration | None = None) -> tuple[Ledger, RunBinding, UUID]:
    ws = workspace(db)
    run = new_run(db, ws)
    books = build_app_ledger(env="test", engine=db.engine(APP_RUNTIME, pool_size=6), workspace_id=ws,
                             configuration=configuration or Configuration())
    return books, RunBinding(run), run


def result_of(report: CallReport) -> ModelResult:
    assert report.result is not None, report
    return report.result


def attempts(db: AppDatabase, run: UUID) -> list[tuple[Any, ...]]:
    with db.superuser() as conn:
        rows: list[tuple[Any, ...]] = conn.execute(
                            "SELECT a.operation_id, a.state, a.count_state, a.contract_block, a.actual_usd "
                            "FROM app.usage_attempts a JOIN app.budget_scopes s ON s.id = a.scope_id "
                            "WHERE s.run_id = %s ORDER BY a.created_at, a.operation_id", (run,)).fetchall()
    return rows


def run_scope(db: AppDatabase, run: UUID) -> tuple[Any, ...]:
    with db.superuser() as conn:
        return tuple(conn.execute("SELECT spent_usd, held_usd, calls_consumed, calls_held, counts_used, "
                                  "contract_block FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone())


def go(books: Ledger, binding: Any, routes: Routes, *, req: ModelRequest | None = None, actor: Any = "agent",
       key: UUID | None = None, seconds: float = 30.0, limits: CallLimits | None = None) -> CallReport:
    return asyncio.run(call(books, providers(routes), binding, key or uuid4(), "decide", req or request(), actor,
                            deadline=time.monotonic() + seconds, limits=limits or CallLimits(backoff_seconds=0.0)))


# -- outcomes -----------------------------------------------------------------------------------------------------

def test_a_valid_answer_counts_once_sends_once_and_settles_the_exact_bill(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    routes = Routes([tokens(1200)], [luna('{"decision": "approve"}')])
    report = go(books, binding, routes)
    assert report.status == "result" and result_of(report).outcome == "structured"
    assert result_of(report).structured_json == '{"decision":"approve"}'
    assert routes.seen == ["count", "create"]
    assert attempts(db, run) == [("decide.r0.a0", "settled", "admitted", None, Decimal("0.00011"))]
    assert run_scope(db, run) == (Decimal("0.00011"), 0, 1, 0, 1, None)
    with db.superuser() as conn:
        assert conn.execute("SELECT count(*) FROM app.usage_events WHERE run_id = %s", (run,)).fetchone() == (1,)


def test_a_known_cache_violation_settles_blocks_and_hands_on_no_payload(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    usage = {"input_tokens": 1000, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 200},
             "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 1040}
    routes = Routes([tokens(1200)], [luna('{"decision": "approve"}', usage=usage)])
    report = go(books, binding, routes)
    assert report.status == "contract_gap" and result_of(report).outcome == "contract_gap"
    gap = result_of(report)
    assert gap.structured_json is None and gap.text is None and not gap.tool_calls
    (row,) = attempts(db, run)
    assert row[1:4] == ("settled", "admitted", "cache_write_under_none") and row[4] > 0  # the true bill
    assert run_scope(db, run)[5] == "cache_write_under_none"
    blocked = go(books, binding, Routes())  # no further reservation, count or request
    assert (blocked.status, blocked.reason) == ("budget", "blocked_by_contract")


def test_unpriceable_evidence_keeps_the_hold_and_blocks_every_eval_parent(db: AppDatabase) -> None:
    books, store = build_eval_ledger(env="test", engine=db.engine(EVAL_RUNTIME, pool_size=6),
                                     configuration=Configuration())
    caps = Caps()
    study = store.ensure_study("calls-block", SHA, cap_usd=Decimal(5), cap_calls=100)
    invocation = store.ensure_invocation(study, uuid4(), caps)
    scenario = store.ensure_scenario(study, "task-1", 0, SHA, caps)
    routes = Routes([tokens(1200)], [luna('{"decision": "approve"}', service_tier="priority")])
    report = go(books, EvalBinding(study, invocation, scenario), routes)
    assert report.status == "contract_gap" and result_of(report).structured_json is None
    with db.superuser() as conn:
        assert conn.execute("SELECT state, contract_block, actual_usd FROM evaluation.usage_attempts").fetchall() == [
            ("unresolved", "service_tier_unpriced", None)]  # no invented bill
        scopes = conn.execute("SELECT kind, held_usd > 0, contract_block FROM evaluation.budget_scopes "
                              "WHERE id = ANY(%s) ORDER BY kind", ([study, invocation, scenario],)).fetchall()
    assert scopes == [("invocation", True, "service_tier_unpriced"), ("scenario", True, "service_tier_unpriced"),
                      ("study", True, "service_tier_unpriced")]


def test_missing_usage_keeps_the_hold_without_a_block(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    report = go(books, binding, Routes([tokens(1200)], [luna('{"decision": "deny"}', usage=None)]))
    assert result_of(report).outcome == "structured"  # the answer is usable; its bill is unknown
    assert attempts(db, run) == [("decide.r0.a0", "unresolved", "admitted", None, None)]
    assert run_scope(db, run)[1] == Decimal("0.002624")  # the conservative hold stays


def test_a_token_limit_breach_below_the_dollar_hold_settles_and_stops(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    usage = {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "output_tokens": 129, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 1029}
    report = go(books, binding, Routes([tokens(1200)], [luna('{"decision": "deny"}', usage=usage)]),
                req=request(max_output_tokens=128))
    assert (report.status, report.reason) == ("contract_gap", "output_limit_exceeded")
    (row,) = attempts(db, run)
    assert row[1] == "settled" and row[3] == "output_limit_exceeded" and row[4] < Decimal("0.002624")


def test_usage_beyond_the_admitted_count_is_a_count_underestimate(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    usage = {"input_tokens": 2000, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "output_tokens": 10, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 2010}
    report = go(books, binding, Routes([tokens(1000)], [luna('{"decision": "deny"}', usage=usage)]))
    assert (report.status, report.reason) == ("contract_gap", "count_underestimate")  # 2000 > 1000 + 256
    assert attempts(db, run)[0][1:4] == ("settled", "admitted", "count_underestimate")


# -- counting ------------------------------------------------------------------------------------------------------

def test_a_failed_or_rejected_count_releases_and_never_sends(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    failed = go(books, binding, Routes([reply({"error": {}}, 500)]))
    rejected = go(books, binding, Routes([tokens(15_900)]))
    assert (failed.reason, rejected.reason) == ("count.http_500", "count_rejected")
    rows = attempts(db, run)
    assert [(r[1], r[2]) for r in rows] == [("released", "failed"), ("released", "rejected")]
    assert run_scope(db, run)[1:5] == (0, 0, 0, 2)  # no inference; both count units stay consumed


def test_a_duplicate_caller_never_counts_sends_or_releases_another_callers_attempt(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    gate = asyncio.Event
    started: dict[str, Any] = {}

    async def slow_count(request: httpx2.Request) -> httpx2.Response:
        started["counting"].set()
        await started["proceed"].wait()
        answer = tokens(1200)(request)
        assert isinstance(answer, httpx2.Response)
        return answer

    routes = Routes([slow_count], [luna('{"decision": "approve"}')])
    key = uuid4()

    async def both() -> tuple[CallReport, CallReport]:
        started["counting"], started["proceed"] = gate(), gate()
        deadline = time.monotonic() + 30
        first = asyncio.create_task(call(books, providers(routes), binding, key, "decide", request(), "agent",
                                         deadline=deadline))
        await started["counting"].wait()
        duplicate = await call(books, providers(routes), binding, key, "decide", request(), "agent",
                               deadline=deadline)
        started["proceed"].set()
        return await first, duplicate

    original, duplicate = asyncio.run(both())
    assert (duplicate.status, duplicate.reason) == ("failed", "replayed_reserved")
    assert duplicate.attempts[0].fate == "replayed"
    assert original.status == "result" and routes.seen == ["count", "create"]  # one count, one inference
    assert attempts(db, run) == [("decide.r0.a0", "settled", "admitted", None, Decimal("0.00011"))]


# -- retries, repair and deadlines ---------------------------------------------------------------------------------

def test_a_rate_limit_is_retried_as_a_new_accounted_attempt(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    routes = Routes([tokens(1200), tokens(1200)],
                    [reply({"error": {"type": "rate_limit_error"}}, 429, **{"retry-after": "0"}),
                     luna('{"decision": "approve"}')])
    report = go(books, binding, routes)
    assert report.status == "result" and routes.seen == ["count", "create", "count", "create"]
    rows = attempts(db, run)
    assert [(r[0], r[1]) for r in rows] == [("decide.r0.a0", "unresolved"), ("decide.r0.a1", "settled")]
    assert run_scope(db, run)[2] == 2  # both physical requests consumed a call


def test_an_invalid_answer_gets_exactly_one_repair(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    routes = Routes([tokens(1200), tokens(1300)], [luna('{"decision": "maybe"}'), luna('{"decision": "deny"}')])
    report = go(books, binding, routes)
    assert result_of(report).outcome == "structured" and result_of(report).structured_json == '{"decision":"deny"}'
    assert [r[0] for r in attempts(db, run)] == ["decide.r0.a0", "decide.r1.a0"]
    twice = go(books, binding, Routes([tokens(1200), tokens(1300)],
                                      [luna('{"decision": "maybe"}'), luna('{"decision": "maybe"}')]))
    assert result_of(twice).outcome == "invalid_output"  # no second repair


def trickle(stream: Chunks) -> Handler:
    return lambda request: httpx2.Response(200, headers={"content-type": "text/event-stream"}, stream=stream,
                                           request=request)


def test_the_attempt_cap_cuts_a_trickling_stream_while_the_caller_has_time_left(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    streams = [Chunks([b"event: response.created\ndata: "], delay=0.01, forever=b"x") for _ in range(2)]
    routes = Routes([tokens(1200), tokens(1200)], [trickle(stream) for stream in streams])
    started = time.monotonic()
    report = go(books, binding, routes, req=request(stream=True), seconds=60.0,
                limits=CallLimits(backoff_seconds=0.0, attempt_seconds=0.5))
    elapsed = time.monotonic() - started
    assert (report.status, report.reason) == ("failed", "timeout") and elapsed < 20
    assert all(stream.closed for stream in streams)
    assert [r[1] for r in attempts(db, run)] == ["unresolved", "unresolved"]  # possibly billed: never released


def test_the_caller_deadline_during_a_count_releases_the_unsent_attempt(db: AppDatabase) -> None:
    books, binding, run = setup(db)

    async def never(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    report = go(books, binding, Routes([never]), seconds=0.5)
    assert report.status == "deadline"
    assert attempts(db, run) == [("decide.r0.a0", "released", "failed", None, None)]


def test_cancellation_right_after_the_grant_keeps_the_liability(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    sent = asyncio.Event

    async def scenario() -> None:
        flags = {"sent": sent()}

        async def hang(request: httpx2.Request) -> httpx2.Response:
            flags["sent"].set()
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

        task = asyncio.create_task(call(books, providers(Routes([tokens(1200)], [hang])), binding, uuid4(), "decide",
                                        request(), "agent", deadline=time.monotonic() + 30))
        await flags["sent"].wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert attempts(db, run) == [("decide.r0.a0", "unresolved", "admitted", None, None)]
    assert run_scope(db, run)[1:3] == (Decimal("0.002624"), 1)


# -- refused before anything is reserved ---------------------------------------------------------------------------

def test_contract_gaps_and_missing_credentials_reserve_nothing(db: AppDatabase) -> None:
    long_cache = Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "gpt-6-luna", "low", "12h")})
    books, binding, run = setup(db, long_cache)
    assert go(books, binding, Routes()).status == "contract_gap"
    books, binding, run = setup(db)
    no_key = Providers(credentials={}, transport=lambda provider: Routes())
    report = asyncio.run(call(books, no_key, binding, uuid4(), "decide", request(), "agent",
                              deadline=time.monotonic() + 5))
    assert report.status == "contract_gap" and "credential" in (report.reason or "")
    assert attempts(db, run) == []
    with pytest.raises(ValueError, match="finite"):
        asyncio.run(call(books, providers(Routes()), binding, uuid4(), "d", request(), "agent",
                         deadline=float("inf")))
    with pytest.raises(ValueError, match="integer"):
        CallLimits(retries_per_request=True)

    async def inside_a_loop() -> None:
        with pytest.raises(RuntimeError, match="event loop"):
            call_sync(books, providers(Routes()), binding, uuid4(), "d", request(), "agent",
                      deadline=time.monotonic() + 5)

    asyncio.run(inside_a_loop())


# -- C2: evidence survives unrepresentable results, exceptions after a grant, cleanup reporting -----------------

def test_a_known_bill_settles_even_when_its_result_cannot_be_represented(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    report = go(books, binding, Routes([tokens(1200)], [luna("bad \ud800 text")]), req=request(output=None),
                limits=CallLimits(repairs=0, backoff_seconds=0.0))  # isolate the settlement, without a repair
    assert result_of(report).outcome == "invalid_output" and result_of(report).text is None
    (row,) = attempts(db, run)
    assert row[1] == "settled" and row[4] == Decimal("0.00011")  # the exact bill is kept


def test_an_unrepresentable_model_id_keeps_the_hold_and_blocks_every_eval_parent(db: AppDatabase) -> None:
    books, store = build_eval_ledger(env="test", engine=db.engine(EVAL_RUNTIME, pool_size=6),
                                     configuration=Configuration())
    caps = Caps()
    study = store.ensure_study("calls-model", SHA, cap_usd=Decimal(5), cap_calls=100)
    invocation = store.ensure_invocation(study, uuid4(), caps)
    scenario = store.ensure_scenario(study, "task-1", 0, SHA, caps)
    report = go(books, EvalBinding(study, invocation, scenario),
                Routes([tokens(1200)], [luna('{"decision": "approve"}', model="m" * 300)]))
    assert (report.status, report.reason) == ("contract_gap", "model_unconfirmed")
    with db.superuser() as conn:
        assert conn.execute("SELECT state, contract_block, actual_usd FROM evaluation.usage_attempts").fetchall() == [
            ("unresolved", "model_unconfirmed", None)]
        blocks = conn.execute("SELECT count(*) FROM evaluation.budget_scopes WHERE id = ANY(%s) AND "
                              "contract_block = 'model_unconfirmed'", ([study, invocation, scenario],)).fetchone()
    assert blocks == (3,)


def test_an_unexpected_exception_after_the_grant_keeps_the_liability(db: AppDatabase,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    import policyops.providers.calls as calls_module

    books, binding, run = setup(db)

    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(calls_module, "invoke", broken)
    with pytest.raises(RuntimeError, match="unexpected"):
        go(books, binding, Routes([tokens(1200)]))
    assert attempts(db, run) == [("decide.r0.a0", "unresolved", "admitted", None, None)]


class HangingClose(Chunks):
    async def aclose(self) -> None:
        await asyncio.sleep(3600)


def test_unconfirmed_cleanup_is_reported_without_touching_the_bill(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    body = json.dumps({"id": "resp_x", "object": "response", "model": "gpt-6-luna", "status": "completed",
                       "service_tier": "default", "output": [{"type": "message", "role": "assistant", "content": [
                           {"type": "output_text", "text": '{"decision": "deny"}', "annotations": []}]}],
                       "usage": {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0,
                                                                               "cache_write_tokens": 0},
                                 "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 0},
                                 "total_tokens": 940}}).encode()

    def hanging(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "application/json"}, stream=HangingClose([body]),
                               request=request)

    report = go(books, binding, Routes([tokens(1200)], [hanging]))
    assert result_of(report).outcome == "structured"
    assert report.cleanup_unconfirmed == (report.attempts[0].attempt_id,)
    assert attempts(db, run)[0][1] == "settled"  # the known bill still settles



# -- C2: the reviewer's C1 accounting cases (c1-provider-accounting-1) as regressions ----------------------------

def test_an_overlong_incomplete_reason_still_settles_the_known_bill(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    report = go(books, binding, Routes([tokens(1200)], [luna("", status="incomplete",
                                                             incomplete_details={"reason": "r" * 300})]))
    assert result_of(report).outcome == "truncated" and result_of(report).stop_reason is None
    (row,) = attempts(db, run)
    assert row[1] == "settled" and row[4] == Decimal("0.00011")  # never left dispatching
    assert run_scope(db, run)[1] == 0


def test_an_unconfirmed_model_or_inconsistent_total_blocks_the_next_reservation(db: AppDatabase) -> None:
    usage = {"input_tokens": 100, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "output_tokens": 10, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 99_999}
    for changes, code in (({"model": "m" * 300}, "model_unconfirmed"), ({"usage": usage}, "usage_inconsistent")):
        books, binding, run = setup(db)
        report = go(books, binding, Routes([tokens(1200)], [luna('{"decision": "approve"}', **changes)]))
        assert (report.status, report.reason) == ("contract_gap", code)
        assert attempts(db, run) == [("decide.r0.a0", "unresolved", "admitted", code, None)]
        followup = go(books, binding, Routes())
        assert (followup.status, followup.reason) == ("budget", "blocked_by_contract")


def test_an_unconfirmed_count_close_is_reported_and_the_bill_still_settles(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    body = json.dumps({"object": "response.input_tokens", "input_tokens": 1200}).encode()

    def hanging_count(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "application/json"}, stream=HangingClose([body]),
                               request=request)

    report = go(books, binding, Routes([hanging_count], [luna('{"decision": "deny"}')]))
    assert result_of(report).outcome == "structured"
    assert report.cleanup_unconfirmed == (report.attempts[0].attempt_id,)
    assert attempts(db, run)[0][1] == "settled"



# -- C3: malformed containers, cumulative stream counters, interrupted cleanup -----------------------------------

def haiku_message(**changes: Any) -> dict[str, Any]:
    return {"id": f"msg_{uuid4().hex[:8]}", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [{"type": "text", "text": '{"decision": "deny"}'}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 700, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
                      "output_tokens": 30, "service_tier": "standard"}} | changes


HAIKU_USD = Decimal("0.000085")  # (700 x 0.10 + 30 x 0.50) / 1e6


def test_malformed_containers_settle_their_known_bill_without_payload(db: AppDatabase) -> None:
    for actor, answer, usd in (("agent", luna("x", output=1), Decimal("0.00011")),
                               ("judge", reply(haiku_message(content=1)), HAIKU_USD)):
        books, binding, run = setup(db)
        report = go(books, binding, Routes([tokens(1200)], [answer]), actor=actor)
        assert (report.status, report.reason) == ("result", "response_malformed")
        assert result_of(report).outcome == "failed" and result_of(report).structured_json is None
        assert attempts(db, run) == [("decide.r0.a0", "settled", "admitted", None, usd)]


def test_a_malformed_container_with_an_unconfirmed_model_holds_and_blocks(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    report = go(books, binding, Routes([tokens(1200)], [luna("x", output=1, model="other-model")]))
    assert (report.status, report.reason) == ("contract_gap", "model_unconfirmed")
    assert attempts(db, run) == [("decide.r0.a0", "unresolved", "admitted", "model_unconfirmed", None)]
    assert go(books, binding, Routes()).reason == "blocked_by_contract"


def stream_of(*outputs: int) -> Handler:
    start = haiku_message(content=[], stop_reason=None) | {
        "usage": {"input_tokens": 700, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
                  "output_tokens": 1, "service_tier": "standard"}}
    events = [("message_start", {"type": "message_start", "message": start}),
              ("content_block_start", {"type": "content_block_start", "index": 0,
                                       "content_block": {"type": "text", "text": ""}}),
              ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                       "delta": {"type": "text_delta", "text": '{"decision": "deny"}'}}),
              ("content_block_stop", {"type": "content_block_stop", "index": 0})]
    events += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                                  "usage": {"output_tokens": n}}) for n in outputs]
    events.append(("message_stop", {"type": "message_stop"}))
    text = "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()
    return lambda request: httpx2.Response(200, headers={"content-type": "text/event-stream"},
                                           stream=Chunks([text]), request=request)


def test_decreasing_cumulative_stream_usage_holds_and_blocks(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    good = go(books, binding, Routes([tokens(1200)], [stream_of(30, 80, 120)]), actor="judge",
              req=request(stream=True))
    assert result_of(good).outcome == "structured"
    bad = go(books, binding, Routes([tokens(1200)], [stream_of(120, 30)]), actor="judge", req=request(stream=True))
    assert (bad.status, bad.reason) == ("contract_gap", "usage_inconsistent")
    rows = attempts(db, run)
    assert rows[0][1] == "settled" and rows[0][4] == Decimal("0.00013")  # (700 x 0.10 + 120 x 0.50) / 1e6
    assert rows[1][1:5] == ("unresolved", "admitted", "usage_inconsistent", None)
    assert go(books, binding, Routes(), actor="judge").reason == "blocked_by_contract"


class HungClose(Chunks):
    async def aclose(self) -> None:
        await asyncio.sleep(3600)


def stalled(request: httpx2.Request) -> httpx2.Response:
    stream = HungClose([b"event: response.created\ndata: "], delay=0.01, forever=b"x")
    return httpx2.Response(200, headers={"content-type": "text/event-stream"}, stream=stream, request=request)


def stalled_count(request: httpx2.Request) -> httpx2.Response:
    stream = HungClose([b'{"input_tokens": '], delay=0.01, forever=b" ")
    return httpx2.Response(200, headers={"content-type": "application/json"}, stream=stream, request=request)


def test_interrupted_counts_and_requests_never_claim_their_cleanup(db: AppDatabase) -> None:
    limits = CallLimits(retries_per_request=0, repairs=0, backoff_seconds=0.0, attempt_seconds=0.3)
    books, binding, run = setup(db)
    counted = go(books, binding, Routes([stalled_count]), limits=limits, seconds=30.0)
    assert counted.reason == "count.attempt_timeout"
    assert counted.cleanup_unconfirmed == (counted.attempts[0].attempt_id,)
    sent = go(books, binding, Routes([tokens(1200)], [stalled]), req=request(stream=True), limits=limits,
              seconds=30.0)
    assert (sent.status, sent.reason) == ("failed", "timeout")
    assert sent.cleanup_unconfirmed == (sent.attempts[0].attempt_id,)
    assert [row[1] for row in attempts(db, run)] == ["released", "unresolved"]  # holds as before



def test_a_malformed_then_valid_cache_split_holds_and_blocks(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    handler = stream_of(30)
    response = handler(httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))
    assert isinstance(response, httpx2.Response) and isinstance(response.stream, Chunks)
    text = b"".join(response.stream.chunks)
    bad = text.replace(b'"cache_creation_input_tokens": 0,', b'"cache_creation_input_tokens": 0, "cache_creation": '
                                                              b'{"ephemeral_5m_input_tokens": "bad", '
                                                              b'"ephemeral_1h_input_tokens": 0},', 1)
    assert bad != text
    bad = bad.replace(b'"usage": {"output_tokens": 30}', b'"usage": {"output_tokens": 30, "cache_creation": '
                                                         b'{"ephemeral_5m_input_tokens": 0, '
                                                         b'"ephemeral_1h_input_tokens": 0}}', 1)

    def malformed(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, stream=Chunks([bad]),
                               request=request)

    report = go(books, binding, Routes([tokens(1200)], [malformed]), actor="judge", req=request(stream=True))
    assert (report.status, report.reason) == ("contract_gap", "usage_inconsistent")
    assert attempts(db, run) == [("decide.r0.a0", "unresolved", "admitted", "usage_inconsistent", None)]
    assert go(books, binding, Routes(), actor="judge").reason == "blocked_by_contract"


# -- the Haiku request omits the optional `speed` field (T11 compatibility repair) -----------------------------------

class Capture:
    """Records the exact JSON body of every count and create request the real SDK put on the wire."""

    def __init__(self, routes: Routes) -> None:
        self.routes = routes
        self.bodies: list[tuple[str, Any]] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        kind = "count" if request.url.path.endswith(("input_tokens", "count_tokens")) else "create"
        self.bodies.append((kind, json.loads(await request.aread())))
        return await self.routes.handle_async_request(request)


def haiku_go(books: Ledger, binding: Any, transport: Any, key: UUID) -> CallReport:
    providers_ = Providers(credentials={"openai": KEY, "anthropic": KEY}, transport=lambda provider: transport)
    return asyncio.run(call(books, providers_, binding, key, "decide", request(), "judge",
                            deadline=time.monotonic() + 30, limits=CallLimits(backoff_seconds=0.0)))


def test_the_sdk_sends_no_speed_for_haiku_and_the_bill_settles_exactly(db: AppDatabase) -> None:
    books, binding, run = setup(db)
    wire = Capture(Routes([reply({"input_tokens": 700})], [reply(haiku_message())]))
    report = haiku_go(books, binding, wire, uuid4())
    assert report.status == "result" and result_of(report).returned_model == "claude-haiku-5-5"
    (count_kind, count_body), (create_kind, create_body) = wire.bodies
    assert (count_kind, create_kind) == ("count", "create")
    assert "speed" not in count_body and "speed" not in create_body  # the SDK injects no default either
    assert create_body["service_tier"] == "standard_only" and create_body["thinking"] == {"type": "disabled"}
    assert create_body["output_config"]["effort"] == "low"
    assert attempts(db, run) == [("decide.r0.a0", "settled", "admitted", None, HAIKU_USD)]


@pytest.mark.parametrize("speed", ["fast", "turbo"])
def test_a_returned_non_standard_speed_still_holds_and_blocks(db: AppDatabase, speed: str) -> None:
    books, binding, run = setup(db)
    message = haiku_message()
    message["usage"] = {**message["usage"], "speed": speed}
    report = haiku_go(books, binding, Routes([reply({"input_tokens": 700})], [reply(message)]), uuid4())
    assert report.reason == "speed_unpriced"
    assert attempts(db, run) == [("decide.r0.a0", "unresolved", "admitted", "speed_unpriced", None)]
    assert go(books, binding, Routes(), actor="judge").reason == "blocked_by_contract"


def test_an_attempt_reserved_under_the_old_request_identity_is_never_reused_or_rekeyed(db: AppDatabase) -> None:
    books, binding, _run = setup(db)
    current = prepare(request(), books.configuration, "judge")
    old = (current.request_sha256, json.loads(current.body))
    endpoint = ENDPOINTS["anthropic"]
    old_sha = sha256_hex(canonical_bytes({"contract": CONTRACT_VERSION, "provider": "anthropic", "method": "POST",
                                          "host": endpoint.host, "path": endpoint.create_path, "query": {},
                                          "version_headers": dict(endpoint.version_headers),
                                          "body": old[1] | {"speed": "standard"}}))
    assert old_sha != current.request_sha256
    key = uuid4()
    books.reserve(binding, uuid5(key, "decide.r0.a0"), "judge", "decide.r0.a0", old_sha)  # as the old source did
    routes = Routes()
    with pytest.raises(LedgerConflict):
        haiku_go(books, binding, routes, key)  # the same stable attempt ID, a different body: refused
    assert routes.seen == []  # nothing was counted or sent
    with db.superuser() as conn:
        assert conn.execute("SELECT request_sha256, state FROM app.usage_attempts WHERE id = %s",
                            (uuid5(key, "decide.r0.a0"),)).fetchone() == (old_sha, "reserved")
    fresh_key = uuid4()  # a new logical request gets a new identity and proceeds normally
    report = haiku_go(books, binding, Routes([reply({"input_tokens": 700})], [reply(haiku_message())]), fresh_key)
    assert report.status == "result"
