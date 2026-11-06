"""T13 concurrency on real PostgreSQL as the actual app runtime: a generation activation inside a step's snapshot
(the REPEATABLE READ step stays on one generation; a READ COMMITTED control shows the hazard it prevents), concurrent
identical steps (one physical request, the same stored result), a bounded in-progress wait that refuses without a
fallback trace, and an activation between the snapshot and the trace (an honest historical flag)."""

from __future__ import annotations

import asyncio
from pathlib import Path
import threading
import time
from typing import Any

import pytest
from sqlalchemy import text

from policyops.persistence import retrieval as store_module
from policyops.persistence.database import SCOPE_SETTING
from policyops.persistence.retrieval import LEXICAL_SQL, RetrievalStore
from policyops.retrieval.search import RetrieverLimits
from policyops_contracts.retrieval import (
    RetrievalConfig,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    RetrievalScope,
)
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import (
    Embeddings,
    World,
    documents,
    owned_task,
    run_threads,
    until_started,
)


pytestmark = pytest.mark.postgres
KEY = "test-banking"
V1 = [("a", "Refunds", "Refunds take ten days."), ("b", "Exchanges", "Exchanges keep the type.")]
V2 = [("a", "Refunds", "Refunds take twenty days."), ("b", "Exchanges", "Exchanges keep the type.")]


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    world = World(shared_db, tmp_path)
    world.publish(documents(V1), key=KEY)
    return world


def query(world: World, text_value: str = "refunds", mode: str = "lexical", **kwargs: Any) -> RetrievalQuery:
    return RetrievalQuery(text=text_value, run_id=kwargs.pop("run_id", None) or world.run(), step=kwargs.pop("step", 1),
                          scope=RetrievalScope(corpus_key=KEY), config=RetrievalConfig(mode=mode))  # type: ignore[arg-type]


def test_an_activation_inside_the_snapshot_cannot_change_the_steps_generation(
        world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    old = RetrievalStore(world.engine, world.ws).pointer(KEY)
    activated, done = threading.Event(), threading.Event()
    original = store_module._one
    isolation: list[str] = []

    def paused(connection: Any, sql: str, params: Any) -> Any:
        row = original(connection, sql, params)
        if "c.active_generation_id WHERE c.corpus_key" in sql and not activated.is_set():
            isolation.append(connection.execute(text("SHOW transaction_isolation")).scalar_one())
            isolation.append(connection.execute(text("SHOW transaction_read_only")).scalar_one())
            def publish() -> None:
                world.publish(documents(V2), key=KEY)
                done.set()

            activated.set()  # set first: the publisher's own reads must not pause again
            run_threads(world.db, [publish], timeout=60)  # bounded timeout; worker errors are re-raised
        return row

    monkeypatch.setattr(store_module, "_one", paused)
    result = asyncio.run(world.retriever(Embeddings()).retrieve(query(world), deadline=time.monotonic() + 120))
    assert done.is_set() and isinstance(result, RetrievalResult), result
    assert isolation == ["repeatable read", "on"]
    assert result.generation_id == old and result.lexical  # the old generation, still visible in the snapshot
    assert "ten days" in result.evidence_text and not result.generation_current  # observed after the trace
    assert RetrievalStore(world.engine, world.ws).pointer(KEY) != old


def test_read_committed_would_lose_the_old_generations_chunks_mid_step(world: World) -> None:
    """The control: the hazard the REPEATABLE READ snapshot prevents (store SQL, READ COMMITTED on purpose)."""
    old = RetrievalStore(world.engine, world.ws).pointer(KEY)
    with world.engine.connect() as conn:
        conn.execute(text("SELECT set_config(:n, :v, true)"), {"n": SCOPE_SETTING, "v": str(world.ws)})
        params = {"g": old, "docs": None, "n": 20, "per": 2, "q": "refunds"}
        assert conn.execute(text(LEXICAL_SQL), params).all()  # visible before the activation
        world.publish(documents(V2), key=KEY)
        assert conn.execute(text(LEXICAL_SQL), params).all() == []  # the retired generation vanished mid-step
        conn.rollback()


def test_concurrent_identical_steps_make_one_request_and_return_the_same_result(world: World) -> None:
    run_id = world.run()
    embeddings = Embeddings()
    embeddings.delay = 0.5
    retriever = world.retriever(embeddings, limits=RetrieverLimits(wait_seconds=10, poll_seconds=0.05))
    step = query(world, "refunds", mode="hybrid", run_id=run_id, step=2)

    async def both() -> list[RetrievalResult | RetrievalRefused]:
        return list(await asyncio.gather(retriever.retrieve(step, deadline=time.monotonic() + 60),
                                         retriever.retrieve(step, deadline=time.monotonic() + 60)))

    first, second = asyncio.run(both())
    assert isinstance(first, RetrievalResult) and isinstance(second, RetrievalResult), (first, second)
    assert len(embeddings.requests) == 1
    assert (first.payload_sha256, first.evidence_text, first.trace_id) == (second.payload_sha256,
                                                                           second.evidence_text, second.trace_id)
    assert sorted([first.replayed, second.replayed]) == [False, True]
    assert world.count("app.retrieval_traces") == 1 and world.count("app.retrieval_steps") == 1


def test_a_lease_held_past_the_bounded_wait_refuses_without_a_fallback_trace(world: World) -> None:
    run_id = world.run()
    slow = Embeddings()
    slow.delay = 2.0
    owner = world.retriever(slow)
    waiter = world.retriever(Embeddings(), limits=RetrieverLimits(wait_seconds=0.3, poll_seconds=0.05))
    step = query(world, "refunds", mode="hybrid", run_id=run_id, step=3)

    async def race() -> tuple[Any, Any]:
        async with owned_task(owner.retrieve(step, deadline=time.monotonic() + 60)) as first:
            await until_started(slow, first, timeout=10)  # provider dispatch or an early owner outcome, bounded
            second = await waiter.retrieve(step, deadline=time.monotonic() + 60)
            return await asyncio.wait_for(first, 30), second

    first, second = asyncio.run(race())
    assert isinstance(second, RetrievalRefused) and second.code == "step_in_progress"
    assert isinstance(first, RetrievalResult) and first.dense_status == "ok" and len(slow.requests) == 1
    assert world.count("app.retrieval_traces") == 1  # only the owner's trace; no fallback trace


def test_an_activation_after_the_snapshot_is_reported_as_historical(world: World,
                                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    original = RetrievalStore.insert_trace

    def activate_first(self: RetrievalStore, **kwargs: Any) -> bool:
        # The T12 publisher runs its own event loop, so it activates from another thread (owned and bounded).
        run_threads(world.db, [lambda: world.publish(documents(V2), key=KEY)], timeout=60)
        return original(self, **kwargs)

    monkeypatch.setattr(RetrievalStore, "insert_trace", activate_first)
    result = asyncio.run(world.retriever(Embeddings()).retrieve(query(world), deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalResult) and not result.generation_current and not result.replayed
    monkeypatch.undo()
    current = asyncio.run(world.retriever(Embeddings()).retrieve(query(world, step=5), deadline=time.monotonic() + 60))
    assert isinstance(current, RetrievalResult) and current.generation_current


def test_the_bounded_orchestration_helpers_terminate_and_surface_early_outcomes(shared_db: AppDatabase) -> None:
    """Injected controls for the test harness itself (no retrieval runs): an owner that refuses or fails before any
    provider request is surfaced at once, owned tasks are always stopped, and worker errors are re-raised."""

    async def refuse_early() -> str:
        return "refused before dispatch"

    async def fail_early() -> str:
        raise ValueError("failed before dispatch")

    async def check() -> None:
        for owner, expected in ((refuse_early, AssertionError), (fail_early, ValueError)):
            started = time.monotonic()
            with pytest.raises(expected):
                async with owned_task(owner()) as task:
                    await until_started(Embeddings(), task, timeout=5)
            assert time.monotonic() - started < 2
        sleeper = asyncio.Event()
        with pytest.raises(RuntimeError, match="primary"):
            async with owned_task(sleeper.wait()) as task:
                raise RuntimeError("primary")
        assert task.cancelled()

    asyncio.run(check())

    def broken() -> None:
        raise KeyError("worker failure")

    with pytest.raises(KeyError, match="worker failure"):
        run_threads(shared_db, [broken, lambda: None], timeout=5)
    assert threading.active_count() >= 1
