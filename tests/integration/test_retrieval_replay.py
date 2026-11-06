"""T13 step identity and replay on real PostgreSQL as the actual app runtime: byte-identical replay with zero calls,
replay after an activation (historical, still byte-identical), same-step conflicts with and without a trace (the
failed-trace / changed-request defect), a terminal run's audit replay versus a refused new step, and refusals for
tampered or unsupported stored traces."""

from __future__ import annotations

import asyncio
from pathlib import Path
import time
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import text

from policyops.persistence.database import workspace_transaction
from policyops.persistence.retrieval import RetrievalStore, StepRefused
from policyops.retrieval.search import trace_id_for
from policyops_contracts.retrieval import (
    RetrievalConfig,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    RetrievalScope,
)
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import Embeddings, World, documents


pytestmark = pytest.mark.postgres
KEY = "test-banking"
V1 = [("a", "Refunds", "Refunds take ten days."), ("b", "Exchanges", "Exchanges keep the type.")]
V2 = [("a", "Refunds", "Refunds take twenty days."), ("b", "Exchanges", "Exchanges keep the type.")]


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    world = World(shared_db, tmp_path)
    world.publish(documents(V1), key=KEY)
    return world


def step(run_id: UUID, text_value: str = "refunds", *, mode: str = "hybrid", number: int = 1,
         corpus_key: str = KEY, **config: Any) -> RetrievalQuery:
    return RetrievalQuery(text=text_value, run_id=run_id, step=number, scope=RetrievalScope(corpus_key=corpus_key),
                          config=RetrievalConfig(mode=mode, **config))  # type: ignore[arg-type]


def go(world: World, embeddings: Embeddings, query: RetrievalQuery) -> RetrievalResult | RetrievalRefused:
    return asyncio.run(world.retriever(embeddings).retrieve(query, deadline=time.monotonic() + 60))


def test_same_step_replay_is_byte_identical_with_zero_calls(world: World) -> None:
    run_id = world.run()
    first = go(world, Embeddings(), step(run_id))
    assert isinstance(first, RetrievalResult) and first.provider_requests == 1 and not first.replayed
    embeddings = Embeddings()
    again = go(world, embeddings, step(run_id))
    assert isinstance(again, RetrievalResult) and again.replayed and again.generation_current
    assert again.model_dump(exclude={"replayed", "provider_requests"}) == first.model_dump(
        exclude={"replayed", "provider_requests"})
    assert embeddings.requests == [] and embeddings.factory_calls == 0


def test_replay_after_an_activation_is_historical_and_byte_identical(world: World) -> None:
    run_id = world.run()
    first = go(world, Embeddings(), step(run_id, mode="lexical"))
    world.publish(documents(V2), key=KEY)
    again = go(world, Embeddings(), step(run_id, mode="lexical"))
    assert isinstance(first, RetrievalResult) and isinstance(again, RetrievalResult)
    assert again.replayed and not again.generation_current and again.generation_id == first.generation_id
    assert again.evidence_text == first.evidence_text and "ten days" in again.evidence_text


@pytest.mark.parametrize("change", [{"text_value": "exchanges"}, {"corpus_key": "other-corpus"}, {"max_chunks": 5}])
def test_a_changed_request_on_a_completed_step_conflicts(world: World, change: dict[str, Any]) -> None:
    run_id = world.run()
    assert isinstance(go(world, Embeddings(), step(run_id)), RetrievalResult)
    embeddings = Embeddings()
    result = go(world, embeddings, step(run_id, **change))
    assert isinstance(result, RetrievalRefused) and result.code == "step_conflict", result
    assert embeddings.requests == [] and world.count("app.retrieval_steps") == 1


def test_a_failed_trace_keeps_the_request_frozen_and_the_retry_needs_no_call(
        world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    run_id = world.run()

    def fail(self: RetrievalStore, **kwargs: Any) -> bool:
        raise StepRefused("trace_unavailable", "injected")

    monkeypatch.setattr(RetrievalStore, "insert_trace", fail)
    paid = Embeddings()
    failed = go(world, paid, step(run_id))
    assert isinstance(failed, RetrievalRefused) and failed.code == "trace_unavailable"
    assert len(paid.requests) == 1  # the embedding was paid and settled; the bill stays in the ledger
    monkeypatch.undo()
    for change in ({"corpus_key": "other-corpus"}, {"max_chunks": 5}, {"text_value": "exchanges"}):
        probe = Embeddings()
        conflict = go(world, probe, step(run_id, **change))
        assert isinstance(conflict, RetrievalRefused) and conflict.code == "step_conflict", (change, conflict)
        assert probe.requests == []
    retry = Embeddings()
    result = go(world, retry, step(run_id))
    assert isinstance(result, RetrievalResult) and result.dense_status == "ok" and not result.replayed
    assert retry.requests == [] and world.count("app.retrieval_traces") == 1


def run_ledger(world: World, run_id: UUID) -> tuple[tuple[Any, ...], dict[str, int]]:
    """The run's shared budget scope (calls consumed and held, held and spent USD) and its attempts by state."""
    with workspace_transaction(world.engine, world.ws) as conn:
        scope = conn.execute(text("SELECT calls_consumed, calls_held, held_usd, spent_usd FROM app.budget_scopes "
                                  "WHERE run_id = :r"), {"r": run_id}).one()
        attempts = conn.execute(text(
            "SELECT a.state, count(*) FROM app.usage_attempts a JOIN app.budget_scopes s "
            "ON s.workspace_id = a.workspace_id AND s.id = a.scope_id WHERE s.run_id = :r GROUP BY a.state"),
            {"r": run_id}).all()
    return tuple(scope), {state: count for state, count in attempts}


def test_a_trace_conflict_keeps_this_invocations_known_request_count(
        world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """Injected, reachable store interleaving (not a threaded race): an equal same-step trace is committed just
    before this caller's own insert, which then loses. The caller really made one embedding request, so its result
    reports one even though it returns the stored winner; a later pure audit of the same step reports zero."""
    run_id = world.run()
    original = RetrievalStore.insert_trace
    inserts: list[bool] = []

    def lose_the_race(self: RetrievalStore, **kwargs: Any) -> bool:
        inserts.append(original(self, **kwargs))  # an equal competing writer commits first
        inserts.append(original(self, **kwargs))  # then the caller's own insert finds the trace (DO NOTHING)
        return inserts[-1]

    monkeypatch.setattr(RetrievalStore, "insert_trace", lose_the_race)
    paid = Embeddings()
    result = go(world, paid, step(run_id))
    monkeypatch.undo()
    assert inserts == [True, False]
    assert isinstance(result, RetrievalResult) and result.replayed and result.dense_status == "ok"
    assert result.provider_requests == 1 and len(paid.requests) == 1  # the one real SDK request is reported
    assert world.count("app.retrieval_traces") == 1 and world.count("app.retrieval_steps") == 1
    scope, attempts = run_ledger(world, run_id)
    assert scope[0] == 1 and scope[1] == 0 and scope[2] == 0 and scope[3] > 0  # one call consumed, none held, billed
    assert attempts == {"settled": 1}
    probe = Embeddings()
    audit = go(world, probe, step(run_id))
    assert isinstance(audit, RetrievalResult) and audit.replayed and audit.provider_requests == 0
    assert probe.requests == [] and probe.factory_calls == 0  # an ordinary later audit makes and reports nothing
    assert audit.model_dump(exclude={"provider_requests"}) == result.model_dump(exclude={"provider_requests"})
    assert world.count("app.retrieval_traces") == 1 and run_ledger(world, run_id) == (scope, attempts)


def test_a_terminal_runs_trace_replays_for_audit_but_a_new_step_refuses(world: World) -> None:
    run_id = world.run()
    first = go(world, Embeddings(), step(run_id, mode="lexical"))
    world.end(run_id, "succeeded")
    replay = go(world, Embeddings(), step(run_id, mode="lexical"))
    assert isinstance(first, RetrievalResult) and isinstance(replay, RetrievalResult) and replay.replayed
    new = go(world, Embeddings(), step(run_id, mode="lexical", number=2))
    assert isinstance(new, RetrievalRefused) and new.code == "run_not_active"


def test_a_tampered_stored_trace_refuses_replay(world: World) -> None:
    run_id = world.run()
    first = go(world, Embeddings(), step(run_id, mode="lexical"))
    assert isinstance(first, RetrievalResult)
    with world.db.superuser() as conn:  # corrupt the stored record (fixture only)
        conn.execute("UPDATE app.retrieval_traces SET candidates = jsonb_set(candidates, '{evidence_tokens}', "
                     "to_jsonb((candidates->>'evidence_tokens')::int + 1)) WHERE id = %s", (first.trace_id,))
    result = go(world, Embeddings(), step(run_id, mode="lexical"))
    assert isinstance(result, RetrievalRefused) and result.code == "replay_integrity"


def test_a_trace_without_an_intent_or_with_an_unsupported_payload_is_not_replayed(world: World) -> None:
    run_id = world.run()
    generation = RetrievalStore(world.engine, world.ws).pointer(KEY)
    trace_id = trace_id_for(world.ws, run_id, 1)
    with workspace_transaction(world.engine, world.ws) as conn:  # a legacy-shaped trace at the step's ID
        conn.execute(text("INSERT INTO app.retrieval_traces (id, workspace_id, run_id, generation_id, query_sha256, "
                          "authorized_scope, candidates, final_chunk_ids, created_at) VALUES (:id, "
                          "app.current_workspace(), :run, :g, :q, '{}'::jsonb, '{\"legacy\": true}'::jsonb, "
                          "'{}', now())"),
                     {"id": trace_id, "run": run_id, "g": generation, "q": "f" * 64})
    result = go(world, Embeddings(), step(run_id, mode="lexical"))
    assert isinstance(result, RetrievalRefused) and result.code == "replay_unsupported"


class Skew:
    """The retriever's clock: real monotonic time plus a skew that a store call sets once it returns (time that
    passed during a synchronous call, which the deadline never interrupts). The provider path keeps real time."""

    def __init__(self) -> None:
        self.extra = 0.0

    def __call__(self) -> float:
        return time.monotonic() + self.extra


def late(monkeypatch: pytest.MonkeyPatch, method: str, clock: Skew, extra: float) -> None:
    original = getattr(RetrievalStore, method)

    def call(self: RetrievalStore, *args: Any, **kwargs: Any) -> Any:
        value = original(self, *args, **kwargs)
        clock.extra = extra
        return value

    monkeypatch.setattr(RetrievalStore, method, call)


def timed(world: World, embeddings: Embeddings, query: RetrievalQuery,
          clock: Skew) -> RetrievalResult | RetrievalRefused:
    return asyncio.run(world.retriever(embeddings, clock=clock).retrieve(query, deadline=time.monotonic() + 60))


# (store call that returns after the deadline, trace kept, intent kept, provider requests before the expiry)
FRESH = [("find_trace", 0, 0, 0), ("create_intent", 0, 1, 0), ("snapshot", 0, 1, 1), ("insert_trace", 1, 1, 1),
         ("pointer", 1, 1, 1)]


@pytest.mark.parametrize(("method", "traces", "intents", "requests"), FRESH)
def test_a_deadline_passed_during_a_fresh_step_store_call_is_never_a_result(
        world: World, monkeypatch: pytest.MonkeyPatch, method: str, traces: int, intents: int, requests: int) -> None:
    run_id = world.run()
    clock, paid = Skew(), Embeddings()
    late(monkeypatch, method, clock, 120.0)
    expired = timed(world, paid, step(run_id), clock)
    assert isinstance(expired, RetrievalRefused) and expired.code == "deadline_passed", (method, expired)
    assert len(paid.requests) == requests  # no work started after the expiry was observed
    assert (world.count("app.retrieval_traces"), world.count("app.retrieval_steps")) == (traces, intents)
    monkeypatch.undo()
    retry = Embeddings()
    result = go(world, retry, step(run_id))  # timely, same step: the committed records are reused, never reissued
    assert isinstance(result, RetrievalResult) and result.dense_status == "ok", (method, result)
    assert result.replayed == bool(traces) and len(retry.requests) == (1 if requests == 0 else 0)
    assert (world.count("app.retrieval_traces"), world.count("app.retrieval_steps")) == (1, 1)


@pytest.mark.parametrize("method", ["find_trace", "spans", "pointer"])
def test_a_deadline_passed_during_a_replay_read_is_never_a_result(
        world: World, monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    run_id = world.run()
    first = go(world, Embeddings(), step(run_id))
    assert isinstance(first, RetrievalResult)
    clock, probe = Skew(), Embeddings()
    late(monkeypatch, method, clock, 120.0)
    expired = timed(world, probe, step(run_id), clock)
    assert isinstance(expired, RetrievalRefused) and expired.code == "deadline_passed", (method, expired)
    monkeypatch.undo()
    again = go(world, probe, step(run_id))
    assert isinstance(again, RetrievalResult) and again.replayed and again.evidence_text == first.evidence_text
    assert probe.requests == [] and world.count("app.retrieval_traces") == 1


@pytest.mark.parametrize("method", ["find_trace", "create_intent", "snapshot", "insert_trace", "pointer", "spans"])
def test_store_calls_that_return_before_the_deadline_still_succeed(
        world: World, monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    run_id = world.run()
    clock = Skew()
    late(monkeypatch, method, clock, 30.0)  # time passed, the deadline (60 s) did not
    fresh = timed(world, Embeddings(), step(run_id), clock)
    replayed = timed(world, Embeddings(), step(run_id), clock)
    assert isinstance(fresh, RetrievalResult) and not fresh.replayed, (method, fresh)
    assert isinstance(replayed, RetrievalResult) and replayed.replayed and replayed.evidence_text == fresh.evidence_text
