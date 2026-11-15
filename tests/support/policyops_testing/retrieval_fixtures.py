"""Retrieval test support (T13): a scripted embeddings transport with exact chosen vectors, synthetic workspaces,
cases and runs, corpus publication through the real T12 ingestion, a `Retriever` builder and test-only query-plan
capture (never reachable by a model or a production code path).

T14 adds a scripted OpenAI Responses route (count and create) behind the same transport (`Scripted`), and a
`ScriptedRerankPort` that declares `test_only` (the Retriever refuses it outside `env="test"`).

Synthetic text, vectors and credentials only; no external HTTP.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Coroutine, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import threading
import time
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

import httpx2
from pydantic import SecretStr
from sqlalchemy import Engine, text

from policyops.budget.config import Configuration
from policyops.persistence import repositories as repo
from policyops.persistence import runs
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.embeddings import EmbeddingStore
from policyops.persistence.records import NewCase, NewRun, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers import tokenizer as tk
from policyops.providers.calls import Providers
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops.retrieval.rerank import RerankInput, RerankOutcome, RerankPort, StageStatus
from policyops.retrieval.search import Retriever, RetrieverLimits
from policyops_contracts.digest import text_sha256
from policyops_contracts.retrieval import RerankAttempt
from policyops_testing.app_database import AppDatabase
from policyops_testing.claims import component_ledger as build_app_ledger
from policyops_testing.corpus_fixtures import FixtureCorpus, banking, write


TOKENIZER = tk.load()
DIMENSIONS = 1536
CAPS = PaidCaps("text-embedding-3-small", DIMENSIONS, Decimal("0.01"), 64, 1_000_000, 3600)


def axis(index: int, value: float = 1.0, *, base: float = 0.0) -> list[float]:
    """A vector along one axis (exact cosine distances: 0 same, 1 orthogonal, 2 opposite)."""
    vector = [base] * DIMENSIONS
    vector[index] = value
    return vector


def hashed(text_value: str) -> list[float]:
    seed = int(hashlib.sha256(text_value.encode()).hexdigest()[:8], 16)
    return [((i * 7 + seed) % 13 - 6 + 0.5) / 100.0 for i in range(DIMENSIONS)]


class Embeddings(httpx2.AsyncBaseTransport):
    """The scripted OpenAI embeddings endpoint: `vectors[text]` or a deterministic hashed vector; optionally a read
    error after the request was sent (`fail`), or a request that never answers (`hang`), or a delay. Counts
    physical requests and their inputs."""

    def __init__(self, vectors: Mapping[str, list[float]] | None = None) -> None:
        self.vectors: dict[str, list[float]] = dict(vectors or {})
        self.requests: list[list[str]] = []
        self.fail = False
        self.hang = False
        self.delay = 0.0
        self.factory_calls = 0

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        inputs = json.loads(await request.aread())["input"]
        self.requests.append(inputs)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.hang:
            await asyncio.Event().wait()
        if self.fail:
            raise httpx2.ReadError("scripted read error after the request was sent", request=request)
        tokens = sum(TOKENIZER.counts(inputs))
        body = {"object": "list", "model": "text-embedding-3-small",
                "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
                "data": [{"object": "embedding", "index": i, "embedding": self.vectors.get(t) or hashed(t)}
                         for i, t in enumerate(inputs)]}
        return httpx2.Response(200, headers={"content-type": "application/json"},
                               content=json.dumps(body).encode(), request=request)

    def providers(self) -> Callable[[], Providers]:
        """A providers factory; `factory_calls` counts credential reads (the factory is the credential boundary)."""
        def build() -> Providers:
            self.factory_calls += 1
            return Providers(credentials={"openai": SecretStr("synthetic-test-credential-0000")},
                             transport=lambda name: self)
        return build


Handler = Callable[[httpx2.Request], httpx2.Response | Coroutine[Any, Any, httpx2.Response]]


def openai_json(data: Any, status: int = 200) -> Handler:
    body = json.dumps(data).encode()
    return lambda request: httpx2.Response(status, headers={"content-type": "application/json"}, content=body,
                                           request=request)


def count_reply(tokens: int) -> Handler:
    return openai_json({"object": "response.input_tokens", "input_tokens": tokens})


def luna_reply(text_value: str, *, usage: Any = "default", **changes: Any) -> Handler:
    """A synthetic Luna Responses answer with known usage (or `usage=None` for missing usage)."""
    known = {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8}, "total_tokens": 940}
    return openai_json({"id": f"resp_{uuid4().hex[:8]}", "object": "response", "model": "gpt-6-luna",
                        "status": "completed", "service_tier": "default",
                        "usage": known if usage == "default" else usage,
                        "output": [{"type": "message", "role": "assistant",
                                    "content": [{"type": "output_text", "text": text_value, "annotations": []}]}]}
                       | changes)


def ranking_reply(*labels: str, **changes: Any) -> Handler:
    return luna_reply(json.dumps({"ranking": list(labels)}), **changes)


def slow(handler: Handler, seconds: float, started: asyncio.Event | None = None) -> Handler:
    async def run(request: httpx2.Request) -> httpx2.Response:
        if started is not None:
            started.set()
        await asyncio.sleep(seconds)
        answer = handler(request)
        return await answer if asyncio.iscoroutine(answer) else answer
    return run


class Scripted(Embeddings):
    """The scripted embeddings endpoint plus scripted OpenAI Responses `count` and `create` answers (consumed in
    order; an unscripted request fails the test). `seen` records every request kind that reached the transport."""

    def __init__(self, vectors: Mapping[str, list[float]] | None = None, *, counts: Sequence[Handler] = (),
                 creates: Sequence[Handler] = ()) -> None:
        super().__init__(vectors)
        self.counts, self.creates = list(counts), list(creates)
        self.seen: list[str] = []
        self.bodies: list[dict[str, Any]] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path.endswith("/embeddings"):
            self.seen.append("embedding")
            return await super().handle_async_request(request)
        kind = "count" if path.endswith("input_tokens") else "create"
        self.seen.append(kind)
        self.bodies.append({"kind": kind, "body": json.loads(await request.aread())})
        queue = self.counts if kind == "count" else self.creates
        if not queue:
            raise AssertionError(f"an unscripted {kind} request reached the transport")
        answer = queue.pop(0)(request)
        return await answer if asyncio.iscoroutine(answer) else answer

    def kinds(self, kind: str) -> int:
        return self.seen.count(kind)


@dataclass
class ScriptedRerankPort:
    """A test-only rerank port: echoes the request identity and window unless told to forge them, and returns the
    scripted status, labels and work. `calls` records every input it received."""

    status: StageStatus = "applied"
    labels: tuple[str, ...] | None = None  # default: the window reversed
    counts_claimed: int = 0
    inferences_dispatched: int = 0
    cleanup_unconfirmed: bool = False
    reason: str | None = None
    attempts: tuple[RerankAttempt, ...] = ()
    forge_identity: bool = False
    forge_window: bool = False
    delay: float = 0.0
    calls: list[RerankInput] = field(default_factory=list)
    test_only: bool = True

    async def rerank(self, request: RerankInput, *, deadline: float) -> RerankOutcome:
        self.calls.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        labels = tuple(reversed(request.labels)) if self.labels is None else self.labels
        window = request.window_document_ids[::-1] if self.forge_window else request.window_document_ids
        return RerankOutcome(self.status, self.reason, "0" * 64 if self.forge_identity else request.request_identity,
                             window, labels if self.status == "applied" else (), self.attempts, self.counts_claimed,
                             self.inferences_dispatched, self.cleanup_unconfirmed)


@dataclass
class World:
    """One synthetic workspace with helpers for runs, corpora and retrievers."""

    db: AppDatabase
    root: Path
    ws: UUID = field(default_factory=uuid4)
    published: int = 0

    def __post_init__(self) -> None:
        with transaction(self.db.engine(AUTH_RUNTIME)) as conn:
            repo.create_workspace(conn, Workspace(id=self.ws, slug=f"ws-{self.ws.hex[:12]}", name="Retrieval",
                                                  created_at=datetime.now(UTC)))
        self.engine: Engine = self.db.engine(APP_RUNTIME, pool_size=8)

    def run(self) -> UUID:
        """A new active run on its own new case (one active workbench run per case)."""
        case, run = uuid4(), uuid4()
        now = datetime.now(UTC)
        with workspace_transaction(self.engine, self.ws) as conn:
            created = repo.create_case(conn, NewCase(id=case, workspace_id=self.ws, scenario="retail",
                                                     customer_user_id=None, created_by=None, created_at=now))
            repo.create_run(conn, NewRun(id=run, workspace_id=self.ws, case_id=case, case_version=created.version,
                                         mode="workbench", graph_sha256=text_sha256("g"),
                                         prompt_sha256=text_sha256("p"),
                                         config_sha256=text_sha256("c"), deadline_at=now + timedelta(hours=1),
                                         created_at=now))
        return run

    def end(self, run_id: UUID, state: str = "cancelled") -> None:
        with workspace_transaction(self.engine, self.ws) as conn:
            run = runs.get_run(conn, run_id, lock=True)
            assert run is not None
            runs.set_state(conn, run, state, datetime.now(UTC))  # type: ignore[arg-type]

    def publish(self, documents: Mapping[str, bytes], *, key: str = "test-banking", domain: str = "banking_knowledge",
                render: str = "tau2-banking/v1", embeddings: Embeddings | None = None) -> UUID:
        self.published += 1
        root = self.root / f"acq-{self.published}"
        raw, digest = write(root, [FixtureCorpus(key, domain, render, documents)])
        provider = embeddings or Embeddings()
        outcome = ingest(Request(self.ws, key, raw, digest, root, "execute", CAPS), engine=self.engine,
                         tokenizer=TOKENIZER, providers=provider.providers(), env="test")
        if outcome.outcome != "activated":
            raise AssertionError(outcome.to_json())
        return UUID(outcome.details["generation_id"])

    def retriever(self, embeddings: Embeddings, *, configuration: Configuration | None = None,
                  limits: RetrieverLimits | None = None, clock: Callable[[], float] = time.monotonic,
                  rerank: bool = False, rerank_port: RerankPort | None = None,
                  lexical_mode: Literal["all_terms", "any_terms"] = "all_terms") -> Retriever:
        configuration = configuration or Configuration()
        return Retriever(self.engine, self.ws, embeddings=EmbeddingStore(self.engine, self.ws, env="test"),
                         ledger=build_app_ledger(env="test", engine=self.engine, workspace_id=self.ws,
                                                 configuration=configuration),
                         providers=embeddings.providers(), tokenizer=TOKENIZER, limits=limits, clock=clock,
                         rerank=rerank, rerank_port=rerank_port, env="test" if rerank_port is not None else None,
                         lexical_mode=lexical_mode)

    def count(self, table: str) -> int:
        with self.db.superuser() as conn:
            # `table` is a fixed test constant.
            return int(conn.execute(f"SELECT count(*) FROM {table} WHERE workspace_id = %s",  # noqa: S608
                                    (self.ws,)).fetchone()[0])


def documents(entries: Sequence[tuple[str, str, str]]) -> dict[str, bytes]:
    """`(key, title, content)` banking-style documents."""
    return {key: banking(key, title, content) for key, title, content in entries}


def embed_input(title: str, content: str) -> str:
    """The T12 embedding input of a single-section banking document (`## title` becomes the heading path)."""
    return f"{title}\n\n{content}"


def explain(engine: Engine, workspace_id: UUID, sql: str, params: Mapping[str, Any]) -> list[Any]:
    """Test-only plan capture: `EXPLAIN (FORMAT JSON)` of one fixed retrieval statement as the actual runtime role."""
    with workspace_transaction(engine, workspace_id) as conn:
        row = conn.execute(text("EXPLAIN (FORMAT JSON) " + sql), dict(params)).scalar_one()
    return row if isinstance(row, list) else json.loads(row)


# -- bounded test orchestration ------------------------------------------------------------------------------------

async def until_started(transport: Embeddings, owner: asyncio.Task[Any], *, timeout: float = 10.0) -> None:
    """Wait, bounded, until `transport` received a request or `owner` finished. An owner that finished first (a
    refusal or an error before dispatch) is surfaced at once instead of being waited for."""
    deadline = time.monotonic() + timeout
    while not transport.requests:
        if owner.done():
            raise AssertionError(f"the owner finished before any provider request: {owner.result()!r}")
        if time.monotonic() >= deadline:
            raise TimeoutError("no provider request within the bounded wait")
        await asyncio.sleep(0.02)


@asynccontextmanager
async def owned_task(coroutine: Coroutine[Any, Any, Any], *, cleanup_seconds: float = 30.0
                     ) -> AsyncIterator[asyncio.Task[Any]]:
    """A task owned from creation: on every exit path it is cancelled if still running and awaited, bounded. A
    cleanup failure is attached to the primary failure (never replacing it)."""
    task = asyncio.create_task(coroutine)
    try:
        yield task
    except BaseException as primary:
        try:
            await _stop(task, cleanup_seconds)
        except BaseException as cleanup:
            primary.add_note(f"task cleanup also failed: {type(cleanup).__name__}")
        raise
    await _stop(task, cleanup_seconds)


async def _stop(task: asyncio.Task[Any], seconds: float) -> None:
    if not task.done():
        task.cancel()
    done, _ = await asyncio.wait({task}, timeout=seconds)
    if not done:
        raise TimeoutError("an owned task did not stop within its bounded cleanup")
    if not task.cancelled():
        task.exception()  # retrieve it, so nothing is reported as never retrieved


class Actor(Protocol):
    """What `run_threads` needs from a thread (scripted actors replace `threading.Thread` in its own controls)."""

    def start(self) -> None: ...

    def join(self, timeout: float | None = None) -> None: ...

    def is_alive(self) -> bool: ...


def cancel_app_statements(db: AppDatabase) -> None:
    """Cancel the app-runtime statements of this test database only (never another database, never this backend)."""
    with db.superuser() as conn:
        conn.execute("SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE datname = current_database() "
                     "AND usename = %s AND pid <> pg_backend_pid()", (APP_RUNTIME,))


def run_threads(db: AppDatabase, targets: Sequence[Callable[[], object]], *, timeout: float = 60.0,
                join_seconds: float = 10.0, thread_factory: Callable[..., Actor] = threading.Thread,
                cancel: Callable[[AppDatabase], None] = cancel_app_statements) -> None:
    """Start, then join every thread within one global deadline; re-raise the first worker error.

    Every thread that started gets a bounded join attempt, even when a later start, the cancellation or a join
    fails. A thread still alive at the deadline, or after a start or join failure, has this test database's
    app-runtime statements cancelled and is joined once more, bounded. The primary failure (a start/join error, else
    the deadline overrun, else the first worker error) is raised with every secondary failure as a type-only note.
    The guarantee is bounded attempts plus a report, not a confirmed stop: a thread that cannot be confirmed stopped is
    reported as such. `daemon=True` only keeps such a thread from blocking interpreter exit; it neither stops it nor
    releases what it holds."""
    errors: list[BaseException] = []

    def wrap(target: Callable[[], object]) -> Callable[[], None]:
        def run() -> None:
            try:
                target()
            except BaseException as error:
                errors.append(error)
        return run

    started: list[Actor] = []
    primary: BaseException | None = None
    notes: list[str] = []
    deadline = time.monotonic() + timeout
    try:
        for target in targets:
            thread = thread_factory(target=wrap(target), daemon=True)
            thread.start()
            started.append(thread)
        for thread in started:
            thread.join(max(0.0, deadline - time.monotonic()))
    except BaseException as error:
        primary = error
    alive = [t for t in started if t.is_alive()]
    if alive:
        try:
            cancel(db)
        except Exception as error:
            notes.append(f"statement cancellation failed: {type(error).__name__}")
        for thread in alive:
            try:
                thread.join(join_seconds)
            except Exception as error:
                notes.append(f"cleanup join failed: {type(error).__name__}")
    still = [t for t in started if t.is_alive()]
    if primary is None and still:
        primary = TimeoutError(f"{len(still)} test thread(s) did not stop after cancellation; stop not confirmed")
    elif primary is None and alive:
        primary = TimeoutError(f"{len(alive)} test thread(s) exceeded the deadline and were cancelled")
    elif primary is None and errors:
        primary = errors[0]
    elif still:
        notes.append(f"{len(still)} test thread(s) still alive after cancellation; stop not confirmed")
    if primary is None:
        return
    if errors and primary is not errors[0]:
        notes.append("worker error(s): " + ", ".join(type(e).__name__ for e in errors))
    for note in notes:
        primary.add_note(note)
    raise primary
