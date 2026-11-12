"""T14 rerank stage composed: real PostgreSQL as the actual app runtime, the real T12/T13 retrieval stack, the real
T10/T11 ledger and OpenAI SDK, and a scripted `httpx2` transport (embeddings + Responses count/create). Every case
checks the transport's observed requests, the ledger's attempts and the step trace. No external HTTP and no key.

Ranking quality, latency and the provider's counting accuracy are not measured here (T15)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import httpx2
import pytest

from policyops.budget.config import DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.database import DatabaseUnavailable
from policyops.persistence.embeddings import EmbeddingStore
from policyops.persistence.runs import Fenced
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.embedding_calls import BindingMismatch
from policyops.retrieval.rerank import RERANK_OPERATION, _ModelReranker
from policyops.retrieval.search import Retriever
from policyops_contracts.retrieval import (
    InvocationWork,
    RerankAttempt,
    RerankConfig,
    RetrievalConfig,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    RetrievalScope,
)
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import (
    TOKENIZER,
    Embeddings,
    Handler,
    Scripted,
    ScriptedRerankPort,
    World,
    axis,
    count_reply,
    documents,
    embed_input,
    luna_reply,
    openai_json,
    owned_task,
    ranking_reply,
    slow,
)


pytestmark = pytest.mark.postgres
KEY = "test-banking"
DOCS = [("a", "Refunds", "Refunds go back to the original payment method within ten days."),
        ("b", "Exchanges", "Exchanges keep the same product type and size, and refunds are not exchanges."),
        ("c", "Gift cards", "Store credit and refunds are added to an existing gift card."),
        ("d", "Shipping", "Orders ship within five business days; refunds ship no goods.")]
VECTORS = {embed_input(t, c): v for (_, t, c), v in zip(DOCS, (axis(0), axis(1), axis(0, -1.0), axis(2)), strict=True)}
QUERY = "refunds"


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    world = World(shared_db, tmp_path)
    world.publish(documents(DOCS), key=KEY, embeddings=Embeddings(VECTORS))
    return world


DEFAULT_RERANK = RerankConfig()


def step(run: UUID, *, number: int = 1, mode: str = "hybrid", rerank: RerankConfig | None = DEFAULT_RERANK,
         corpus_key: str = KEY, allowlist: tuple[str, ...] = (), text_value: str = QUERY,
         **config: Any) -> RetrievalQuery:
    return RetrievalQuery(text=text_value, run_id=run, step=number,
                          scope=RetrievalScope(corpus_key=corpus_key, document_allowlist=allowlist),
                          config=RetrievalConfig(mode=mode, rerank=rerank, **config))  # type: ignore[arg-type]


def go(retriever: Retriever, query: RetrievalQuery, *, seconds: float = 60.0) -> RetrievalResult | RetrievalRefused:
    return asyncio.run(retriever.retrieve(query, deadline=time.monotonic() + seconds))


def ok(result: RetrievalResult | RetrievalRefused) -> RetrievalResult:
    assert isinstance(result, RetrievalResult), result
    return result


def refused(result: RetrievalResult | RetrievalRefused, code: str) -> RetrievalRefused:
    assert isinstance(result, RetrievalRefused) and result.code == code, result
    return result


def baseline(world: World, query: RetrievalQuery) -> RetrievalResult:
    """The same request without reranking, on a fresh run: the baseline delivery of the same snapshot."""
    plain = query.model_copy(update={"run_id": world.run(), "config": query.config.model_copy(update={"rerank": None})})
    return ok(go(world.retriever(Embeddings()), plain))


def rerank_attempts(world: World, run: UUID) -> list[tuple[Any, ...]]:
    with world.db.superuser() as conn:
        return [tuple(r) for r in conn.execute(
            "SELECT a.state, a.count_state FROM app.usage_attempts a JOIN app.budget_scopes s "
            "ON s.workspace_id = a.workspace_id AND s.id = a.scope_id WHERE s.run_id = %s AND a.operation_id = %s",
            (run, f"{RERANK_OPERATION}.r0.a0")).fetchall()]


def stored_rerank(world: World, trace_id: UUID) -> dict[str, Any] | None:
    with world.db.superuser() as conn:
        row = conn.execute("SELECT candidates FROM app.retrieval_traces WHERE id = %s", (trace_id,)).fetchone()
    assert row is not None
    value: dict[str, Any] | None = row[0].get("rerank")
    return value


def work(e: int, counts: int, inferences: int, cleanup: bool = False) -> InvocationWork:
    return InvocationWork(embedding_requests=e, rerank_counts_claimed=counts, rerank_inferences_dispatched=inferences,
                          cleanup_unconfirmed=cleanup)


def chunk_ids(result: RetrievalResult) -> list[UUID]:
    return [e.chunk_id for e in result.evidence]


# -- the production adapter --------------------------------------------------------------------------------------

def test_an_applied_ranking_reorders_delivery_and_replays_with_zero_work(world: World) -> None:
    run = world.run()
    query = step(run)
    plain = baseline(world, query)
    window = [f.document_id for f in plain.fused]
    assert len(window) >= 3
    labels = [f"D{i:02d}" for i in range(len(window), 0, -1)]  # exactly the reverse
    transport = Scripted(counts=[count_reply(900)], creates=[ranking_reply(*labels)])
    result = ok(go(world.retriever(transport, rerank=True), query))
    assert result.rerank is not None and result.rerank.status == "applied" and result.rerank.applied
    assert list(result.rerank.order) == window[::-1]
    # The baseline step settled and cached this query's vector in the same workspace: reused, by design.
    assert result.invocation == work(0, 1, 1) and result.provider_requests == 0
    assert transport.seen == ["count", "create"]
    first_doc = result.evidence[0].document_id
    assert first_doc == window[-1] and result.fused == plain.fused  # the trace keeps the baseline fusion
    texts = {e.chunk_id: e.text for e in plain.evidence}
    assert all(texts.get(e.chunk_id, e.text) == e.text for e in result.evidence)  # full chunk texts, never cut
    sent = next(b["body"] for b in transport.bodies if b["kind"] == "create")
    serialized = json.dumps(sent)
    assert "D01" in serialized and not any(str(d) in serialized for d in window)  # labels only, never IDs
    assert sent["max_output_tokens"] == 512 and sent["model"] == "gpt-6-luna"
    assert rerank_attempts(world, run) == [("settled", "admitted")]
    trace = stored_rerank(world, result.trace_id)
    assert trace is not None and trace["status"] == "applied" and trace["window"] == len(window)
    assert QUERY not in json.dumps(trace)
    audit = Scripted()
    again = ok(go(world.retriever(audit, rerank=True), query))
    assert again.replayed and again.invocation == work(0, 0, 0) and audit.seen == [] and audit.factory_calls == 0
    assert (again.payload_sha256, again.evidence_text, again.rerank) == (result.payload_sha256, result.evidence_text,
                                                                         result.rerank)


def responses(status: str = "completed", output: list[Any] | None = None, **changes: Any) -> Handler:
    usage = {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 940}
    return openai_json({"id": f"resp_{uuid4().hex[:8]}", "object": "response", "model": "gpt-6-luna",
                        "status": status, "service_tier": "default", "usage": usage, "output": output or []} | changes)


@pytest.mark.parametrize(("create", "status", "attempt"), [
    (ranking_reply("D99"), "invalid_output", "settled"),  # out-of-window label: the local full schema rejects it
    (luna_reply("not json"), "invalid_output", "settled"),
    (luna_reply(json.dumps({"ranking": ["D01", "D01"]})), "invalid_output", "settled"),
    (responses(output=[{"type": "message", "role": "assistant", "content": [{"type": "refusal", "refusal": "no"}]}]),
     "refused", "settled"),
    (responses("incomplete", incomplete_details={"reason": "max_output_tokens"}), "truncated", "settled"),
    (responses("failed"), "failed", "settled"),
    (ranking_reply("D01", service_tier="priority"), "contract_block", "unresolved"),
    (openai_json({"error": {"message": "synthetic"}}, status=500), "failed", "unresolved"),
])
def test_model_invalid_or_failed_output_falls_back_to_the_flagged_baseline(world: World, create: Handler,
                                                                            status: str, attempt: str) -> None:
    run = world.run()
    query = step(run, mode="lexical")
    plain = baseline(world, query)
    transport = Scripted(counts=[count_reply(900)], creates=[create])
    result = ok(go(world.retriever(transport, rerank=True), query))
    assert result.rerank is not None and (result.rerank.status, result.rerank.applied) == (status, False)
    assert chunk_ids(result) == chunk_ids(plain) and result.evidence_text == plain.evidence_text
    assert result.invocation == work(0, 1, 1, result.invocation.cleanup_unconfirmed)  # type: ignore[union-attr]
    assert rerank_attempts(world, run) == [(attempt, "admitted")]
    assert transport.seen == ["count", "create"]  # no hidden retry, repair or model fallback


def test_the_refuse_policy_turns_a_fallback_into_rerank_unavailable(world: World) -> None:
    run = world.run()
    query = step(run, mode="lexical", rerank=RerankConfig(policy="refuse"))
    transport = Scripted(counts=[count_reply(900)], creates=[luna_reply("not json")])
    result = refused(go(world.retriever(transport, rerank=True), query), "rerank_unavailable")
    assert result.invocation == work(0, 1, 1) and result.detail == "invalid_output"
    assert world.count("app.retrieval_traces") == 0 and world.count("app.retrieval_steps") == 1
    retry = Scripted()  # the same step can only replay the attempt: never a new key or request
    again = refused(go(world.retriever(retry, rerank=True), query), "rerank_unavailable")
    assert again.detail == "prior_attempt" and again.invocation == work(0, 0, 0) and retry.seen == []


@pytest.mark.parametrize("counts", [[openai_json({"error": {"message": "x"}}, status=500)], [count_reply(20_000)]])
def test_a_failed_or_unadmitted_count_falls_back_without_a_request(world: World, counts: list[Handler]) -> None:
    run = world.run()
    transport = Scripted(counts=counts)
    result = ok(go(world.retriever(transport, rerank=True), step(run, mode="lexical")))
    assert result.rerank is not None and result.rerank.status == "count_failed"
    assert result.invocation == work(0, 1, 0) and transport.seen == ["count"]
    assert rerank_attempts(world, run)[0][0] == "released"


def test_a_budget_refusal_reserves_and_sends_nothing(world: World) -> None:
    run = world.run()
    tight = Configuration(caps=replace(Caps(), run_usd=Decimal("0.002")))  # below the $0.002624 reranker hold
    transport = Scripted()
    result = ok(go(world.retriever(transport, rerank=True, configuration=tight), step(run, mode="lexical")))
    assert result.rerank is not None and result.rerank.status == "budget" and result.invocation == work(0, 0, 0)
    assert transport.seen == [] and rerank_attempts(world, run) == []


def test_the_sub_deadline_falls_back_while_the_global_deadline_is_alive(world: World) -> None:
    run = world.run()
    transport = Scripted(counts=[count_reply(900)], creates=[slow(ranking_reply("D01"), 30.0)])
    began = time.monotonic()
    result = ok(go(world.retriever(transport, rerank=True), step(run, mode="lexical", rerank=RerankConfig(seconds=1))))
    assert time.monotonic() - began < 20
    assert result.rerank is not None and result.rerank.status == "timeout"
    assert result.invocation == work(0, 1, 1, True)  # granted and possibly sent: the hold stays
    assert rerank_attempts(world, run) == [("unresolved", "admitted")]


def test_the_global_deadline_during_the_call_refuses_and_a_retry_never_resends(world: World) -> None:
    run = world.run()
    query = step(run)
    shift = [0.0]

    def answer_late(request: httpx2.Request) -> httpx2.Response:
        shift[0] = 10_000.0  # the Retriever's clock passes the global deadline while the request is answered
        reply = ranking_reply("D01")(request)
        assert isinstance(reply, httpx2.Response)
        return reply

    transport = Scripted(counts=[count_reply(900)], creates=[answer_late])
    late = world.retriever(transport, rerank=True, clock=lambda: time.monotonic() + shift[0])
    result = refused(go(late, query), "deadline_passed")
    assert result.invocation == work(1, 1, 1) and world.count("app.retrieval_traces") == 0
    assert rerank_attempts(world, run) == [("settled", "admitted")]  # the bill stays
    retry = Scripted()
    again = ok(go(world.retriever(retry, rerank=True), query))
    assert again.rerank is not None and again.rerank.status == "prior_attempt"  # no new key, no new attempt
    assert again.invocation == work(0, 0, 0) and retry.seen == []


def test_cancellation_propagates_and_keeps_the_hold(world: World) -> None:
    run = world.run()
    started = asyncio.Event()
    transport = Scripted(counts=[count_reply(900)], creates=[slow(ranking_reply("D01"), 30.0, started)])
    retriever = world.retriever(transport, rerank=True)

    async def scenario() -> None:
        async with owned_task(retriever.retrieve(step(run, mode="lexical"), deadline=time.monotonic() + 60)) as task:
            await asyncio.wait_for(started.wait(), 20)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(scenario())
    assert world.count("app.retrieval_traces") == 0 and rerank_attempts(world, run) == [("unresolved", "admitted")]


def test_a_run_ended_during_the_rerank_count_refuses(world: World) -> None:
    run = world.run()

    def end_then_count(request: httpx2.Request) -> httpx2.Response:
        world.end(run)
        reply = count_reply(900)(request)
        assert isinstance(reply, httpx2.Response)
        return reply

    transport = Scripted(counts=[end_then_count])
    with pytest.raises(Fenced, match="run_terminal"):
        go(world.retriever(transport, rerank=True), step(run, mode="lexical"))
    assert transport.seen == ["count"] and world.count("app.retrieval_traces") == 0
    assert rerank_attempts(world, run) == [("released", "admitted")]


# -- gating and bounds ---------------------------------------------------------------------------------------------

def reranker_output(maximum: int) -> Configuration:
    base = DEFAULT_ACTORS["reranker"]
    assert isinstance(base, ChatActor)
    return Configuration(actors={**DEFAULT_ACTORS, "reranker": ChatActor("reranker", base.model, base.effort,
                                                                       max_output=maximum)})


def test_gating_refuses_before_any_intent_and_an_existing_trace_still_replays(world: World, shared_db: AppDatabase,
                                                                             tmp_path: Path) -> None:
    run = world.run()
    transport = Scripted()
    attempts_before = world.count("app.usage_attempts")  # ingestion's own embedding attempt(s)
    gated = refused(go(world.retriever(transport), step(run)), "config_invalid")
    assert gated.detail == "rerank_not_configured" and gated.invocation == work(0, 0, 0)
    bound = refused(go(world.retriever(transport, rerank=True, configuration=reranker_output(600)),
                       step(run, rerank=RerankConfig(max_output_tokens=1024))), "config_invalid")
    assert bound.detail == "rerank_output_bound"
    retail = World(shared_db, tmp_path / "retail")
    retail.publish({"policy": b"# Retail\n\n## Rule\n\nReturns within 30 days."}, key="test-retail", domain="retail",
                   render="identity")
    full = refused(go(retail.retriever(transport, rerank=True), step(retail.run(), mode="full_policy",
                                                                     corpus_key="test-retail")), "config_invalid")
    assert full.detail == "rerank_full_policy"
    assert transport.seen == [] and transport.factory_calls == 0
    assert world.count("app.retrieval_steps") == 0 and world.count("app.usage_attempts") == attempts_before
    recorded = ok(go(world.retriever(Scripted(counts=[count_reply(900)], creates=[ranking_reply("D01")]),
                                     rerank=True), step(run, mode="lexical")))
    audit = Scripted()
    replay = ok(go(world.retriever(audit), step(run, mode="lexical")))  # no adapter needed for an audit replay
    assert replay.replayed and replay.payload_sha256 == recorded.payload_sha256 and audit.seen == []
    conflict = refused(go(world.retriever(Scripted(), rerank=True),
                          step(run, mode="lexical", rerank=RerankConfig(documents=2))), "step_conflict")
    assert conflict.invocation == work(0, 0, 0)


def test_too_few_candidates_or_too_little_time_make_no_call(world: World) -> None:
    port = ScriptedRerankPort()
    one = ok(go(world.retriever(Embeddings(), rerank_port=port),
                step(world.run(), mode="lexical", allowlist=("tau2:banking_knowledge/a",))))
    assert one.rerank is not None and one.rerank.status == "skipped_few_candidates"
    short = ok(go(world.retriever(Embeddings(), rerank_port=port), step(world.run(), mode="lexical"), seconds=2.9))
    assert short.rerank is not None and short.rerank.status == "skipped_deadline" and port.calls == []
    assert short.invocation == work(0, 0, 0)


# -- layer B against a test-only port ------------------------------------------------------------------------------

@pytest.mark.parametrize(("port", "detail"), [
    (ScriptedRerankPort(forge_identity=True), "the rerank outcome is bound to another request"),
    (ScriptedRerankPort(forge_window=True), "the rerank outcome is bound to another request"),
    (ScriptedRerankPort(labels=("D09",)), "an applied ranking outside the window"),
    (ScriptedRerankPort(labels=("D01", "D01")), "an applied ranking outside the window"),
    (ScriptedRerankPort(labels=()), "an applied ranking outside the window"),
    (ScriptedRerankPort(counts_claimed=2), "the rerank outcome reports impossible work"),
    (ScriptedRerankPort(status="integrity", reason="local_gap"), "local_gap"),
    (ScriptedRerankPort(status="invalid_output", attempts=(RerankAttempt(attempt_id=uuid4(), fate="settled"),) * 2),
     "the rerank outcome is not recordable"),
])
def test_a_broken_port_is_an_integrity_refusal_never_a_fallback(world: World, port: ScriptedRerankPort,
                                                                detail: str) -> None:
    run = world.run()
    result = refused(go(world.retriever(Embeddings(), rerank_port=port), step(run, mode="lexical")),
                     "rerank_integrity")
    assert result.detail == detail and world.count("app.retrieval_traces") == 0


@pytest.mark.parametrize("status", ["invalid_ranking", "invalid_output", "refused", "truncated", "failed",
                                    "contract_block", "prior_attempt", "count_failed", "budget", "timeout_candidate"])
def test_every_fallback_class_status_follows_the_policy(world: World, status: str) -> None:
    port = ScriptedRerankPort(status=status, counts_claimed=1)  # type: ignore[arg-type]
    flagged = ok(go(world.retriever(Embeddings(), rerank_port=port), step(world.run(), mode="lexical")))
    expected = "timeout" if status == "timeout_candidate" else status
    assert flagged.rerank is not None and (flagged.rerank.status, flagged.rerank.applied) == (expected, False)
    assert flagged.invocation == work(0, 1, 0)
    strict = refused(go(world.retriever(Embeddings(), rerank_port=port),
                        step(world.run(), mode="lexical", rerank=RerankConfig(policy="refuse"))), "rerank_unavailable")
    assert strict.detail == expected and strict.invocation == work(0, 1, 0)


def test_the_global_deadline_is_checked_before_the_port_identity(world: World) -> None:
    shift = [0.0]

    class LatePort(ScriptedRerankPort):
        async def rerank(self, request: Any, *, deadline: float) -> Any:
            shift[0] = 10_000.0
            return await super().rerank(request, deadline=deadline)

    port = LatePort(forge_identity=True, counts_claimed=1, inferences_dispatched=1)
    retriever = world.retriever(Embeddings(), rerank_port=port, clock=lambda: time.monotonic() + shift[0])
    result = refused(go(retriever, step(world.run(), mode="lexical")), "deadline_passed")
    assert result.invocation == work(0, 1, 1)


def test_a_run_inactive_port_outcome_refuses(world: World) -> None:
    result = refused(go(world.retriever(Embeddings(), rerank_port=ScriptedRerankPort(status="run_not_active")),
                        step(world.run(), mode="lexical")), "run_not_active")
    assert result.invocation == work(0, 0, 0)


# -- binding -------------------------------------------------------------------------------------------------------

def test_the_production_adapter_is_bound_to_the_retrievers_own_ledger_and_providers(world: World) -> None:
    transport = Scripted()
    retriever = world.retriever(transport, rerank=True)
    port = retriever._rerank_port
    assert isinstance(port, _ModelReranker) and port.ledger is retriever.ledger
    assert port.providers is retriever.providers and not port.test_only


def test_a_foreign_ledger_is_refused_before_any_read_or_reservation(world: World, shared_db: AppDatabase,
                                                                   tmp_path: Path) -> None:
    other = World(shared_db, tmp_path / "other")
    transport = Scripted()
    attempts_before = world.count("app.usage_attempts")
    with pytest.raises(BindingMismatch):
        Retriever(world.engine, world.ws, embeddings=EmbeddingStore(world.engine, world.ws, env="test"),
                  ledger=build_app_ledger(env="test", engine=other.engine, workspace_id=other.ws,
                                          configuration=Configuration()),
                  providers=transport.providers(), tokenizer=TOKENIZER, rerank=True)
    assert transport.seen == [] and transport.factory_calls == 0
    assert world.count("app.usage_attempts") == attempts_before


# -- concurrency (design 2 §6.2, design 3 §B4) ---------------------------------------------------------------------

def test_two_callers_on_one_step_report_their_own_work_and_the_trace_winner_is_authoritative(world: World) -> None:
    run = world.run()
    query = step(run)
    started = asyncio.Event()
    owner = Scripted(counts=[count_reply(900)], creates=[slow(ranking_reply("D02", "D01"), 2.0, started)])
    late_writer = Scripted()  # it must not count or send: the owner holds the step's rerank attempt
    owner_side, writer_side = world.retriever(owner, rerank=True), world.retriever(late_writer, rerank=True)
    results: dict[str, RetrievalResult | RetrievalRefused] = {}

    async def scenario() -> None:
        async with owned_task(owner_side.retrieve(query, deadline=time.monotonic() + 60)) as task:
            await asyncio.wait_for(started.wait(), 20)  # the owner's ranking request is in flight
            results["writer"] = await writer_side.retrieve(query, deadline=time.monotonic() + 60)
            results["owner"] = await asyncio.wait_for(task, 30)

    asyncio.run(scenario())
    writer, paid = ok(results["writer"]), ok(results["owner"])
    assert not writer.replayed and writer.rerank is not None and writer.rerank.status == "prior_attempt"
    assert writer.invocation == work(0, 0, 0) and late_writer.seen == []
    assert paid.replayed and paid.rerank == writer.rerank  # the stored winner, never the losing ranking
    assert paid.invocation == work(1, 1, 1)  # the losing writer still reports its own paid work
    audit_transport = Scripted()
    audit = ok(go(world.retriever(audit_transport, rerank=True), query))
    assert audit.invocation == work(0, 0, 0) and audit_transport.seen == []
    assert paid.payload_sha256 == writer.payload_sha256 == audit.payload_sha256
    assert paid.evidence_text == writer.evidence_text == audit.evidence_text
    assert (owner.kinds("embedding"), owner.kinds("count"), owner.kinds("create")) == (1, 1, 1)
    assert rerank_attempts(world, run) == [("settled", "admitted")]
    with world.db.superuser() as conn:
        held, calls_held = conn.execute("SELECT held_usd, calls_held FROM app.budget_scopes WHERE run_id = %s",
                                        (run,)).fetchone()
    assert held == 0 and calls_held == 0



# -- review regressions (draft-findings-1): a ranking returned after the local sub-deadline is never used ----------

class BlockingPort(ScriptedRerankPort):
    """A port whose return is delayed by synchronous work (the event loop cannot interrupt it)."""

    async def rerank(self, request: Any, *, deadline: float) -> Any:
        outcome = await super().rerank(request, deadline=deadline)
        time.sleep(1.2)
        return outcome


@pytest.mark.parametrize("make", [lambda: ScriptedRerankPort(delay=1.2, counts_claimed=1, inferences_dispatched=1),
                                  lambda: BlockingPort(counts_claimed=1, inferences_dispatched=1)])
def test_a_late_applied_ranking_obeys_the_timeout_policy(world: World, make: Any) -> None:
    fast = ok(go(world.retriever(Embeddings(), rerank_port=ScriptedRerankPort()), step(world.run(), mode="lexical")))
    assert fast.rerank is not None and fast.rerank.status == "applied"  # the fast positive
    plain = baseline(world, step(world.run(), mode="lexical"))
    late = ok(go(world.retriever(Embeddings(), rerank_port=make()),
                 step(world.run(), mode="lexical", rerank=RerankConfig(seconds=1))))
    assert late.rerank is not None and (late.rerank.status, late.rerank.reason) == ("timeout", "late_result")
    assert chunk_ids(late) == chunk_ids(plain) and late.invocation == work(0, 1, 1)  # baseline, known work kept
    strict = refused(go(world.retriever(Embeddings(), rerank_port=make()),
                        step(world.run(), mode="lexical", rerank=RerankConfig(seconds=1, policy="refuse"))),
                     "rerank_unavailable")
    assert strict.detail == "timeout" and strict.invocation == work(0, 1, 1)


class ScopeLockHolder:
    """Holds a run's budget-scope row FOR UPDATE on its own thread, started on demand. The thread handle is registered
    from acquisition, BEFORE startup is invoked, so a startup that fails after the thread began is still owned.
    Cleanup gives every handle one bounded join; only Python's own "not started" refusal confirms that no thread ran.
    A thread still alive after its join is reported (stop not confirmed), and no cleanup problem replaces the primary
    failure."""

    def __init__(self, hold: Callable[[threading.Event], None], *,
                 thread_factory: Callable[..., threading.Thread] = threading.Thread,
                 join_seconds: float = 10.0) -> None:
        self.hold, self.factory, self.join_seconds = hold, thread_factory, join_seconds
        self.locked = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = self.factory(target=self.hold, args=(self.locked,), daemon=True)
        self.thread.start()

    def close(self, primary: BaseException | None) -> None:
        thread = self.thread
        if thread is None:
            return
        try:
            thread.join(self.join_seconds)
        except RuntimeError:  # "cannot join thread before it is started": confirmed never started
            return
        if thread.is_alive():
            message = "the scope-lock holder did not stop within its bounded join; stop not confirmed"
            if primary is None:
                raise TimeoutError(message)
            primary.add_note(message)


@contextmanager
def scope_lock_holder(hold: Callable[[threading.Event], None], **kwargs: Any) -> Iterator[ScopeLockHolder]:
    holder = ScopeLockHolder(hold, **kwargs)
    try:
        yield holder
    except BaseException as primary:
        try:
            holder.close(primary)
        except BaseException as cleanup:
            primary.add_note(f"holder cleanup also failed: {type(cleanup).__name__}")
        raise
    holder.close(None)


class StartupFailure(Exception):
    pass


def test_the_lock_holder_owns_its_thread_through_every_startup_failure() -> None:
    # A failure before anything was acquired: no handle, no join, the failure unchanged.
    with (pytest.raises(RuntimeError, match="before the provider call") as early,
          scope_lock_holder(lambda locked: None)):
        raise RuntimeError("before the provider call")
    assert not getattr(early.value, "__notes__", [])

    class FailsBeforeStarting(threading.Thread):
        def start(self) -> None:
            raise StartupFailure("before the thread started")

    with (pytest.raises(StartupFailure, match="before the thread started") as before,
          scope_lock_holder(lambda locked: None, thread_factory=FailsBeforeStarting) as unstarted):
        unstarted.start()
    assert unstarted.thread is not None and unstarted.thread.ident is None  # registered, confirmed never started
    assert not getattr(before.value, "__notes__", [])

    class FailsAfterStarting(threading.Thread):
        def start(self) -> None:
            super().start()
            raise StartupFailure("after the thread started")

    ran = threading.Event()

    def short(locked: threading.Event) -> None:
        ran.set()
        time.sleep(0.3)

    with (pytest.raises(StartupFailure, match="after the thread started") as after,
          scope_lock_holder(short, thread_factory=FailsAfterStarting) as started):
        started.start()
    assert ran.is_set() and started.thread is not None and not started.thread.is_alive()  # owned and joined
    assert not getattr(after.value, "__notes__", [])

    release = threading.Event()

    def until_released(locked: threading.Event) -> None:
        release.wait(30)

    try:
        with (pytest.raises(StartupFailure) as stuck,
              scope_lock_holder(until_released, thread_factory=FailsAfterStarting,
                                join_seconds=0.2) as slow_holder):
            slow_holder.start()
        assert any("stop not confirmed" in note for note in stuck.value.__notes__)  # reported, never assumed
    finally:
        release.set()
        if slow_holder.thread is not None:
            slow_holder.thread.join(10)
    assert slow_holder.thread is not None and not slow_holder.thread.is_alive()

    with scope_lock_holder(lambda locked: locked.set()) as quick:
        quick.start()
        assert quick.locked.wait(10)
    assert quick.thread is not None and not quick.thread.is_alive()


def test_late_ledger_bookkeeping_after_a_valid_answer_stops_with_unconfirmed_usage(world: World) -> None:
    """Composed: the real SDK answers within the local cap, then the real ledger settlement waits on the run's budget
    scope row past the SQL lock cap. The valid ranking is not used; available usage and the hold are retained."""
    run = world.run()
    release = threading.Event()

    def lock_the_scope(locked: threading.Event) -> None:
        with world.db.superuser() as conn, conn.transaction():
            conn.execute("SELECT 1 FROM app.budget_scopes WHERE run_id = %s FOR UPDATE", (run,))
            locked.set()
            assert release.wait(10)

    with scope_lock_holder(lock_the_scope) as holder:
        def answer_then_lock(request: httpx2.Request) -> httpx2.Response:
            holder.start()
            assert holder.locked.wait(10)
            reply = ranking_reply("D02", "D01")(request)
            assert isinstance(reply, httpx2.Response)
            return reply

        transport = Scripted(counts=[count_reply(900)], creates=[answer_then_lock])
        try:
            with pytest.raises(AccountingUnconfirmed) as stopped:
                go(world.retriever(transport, rerank=True), step(run, mode="lexical",
                                                                rerank=RerankConfig(seconds=1)))
        finally:
            release.set()
    assert holder.thread is not None and not holder.thread.is_alive()
    assert isinstance(stopped.value.__cause__, DatabaseUnavailable)
    assert (stopped.value.__cause__.phase, stopped.value.__cause__.sqlstate) == ("body", "55P03")
    report = stopped.value.report
    assert report.attempts[0].evidence is not None and report.attempts[0].dispatch_granted
    assert transport.seen == ["count", "create"] and world.count("app.retrieval_traces") == 0
    assert rerank_attempts(world, run) == [("dispatching", "admitted")]
    with world.db.superuser() as conn:
        assert conn.execute("SELECT held_usd > 0 FROM app.budget_scopes WHERE run_id = %s", (run,)).fetchone() == (
            True,)
