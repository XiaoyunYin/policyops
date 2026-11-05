"""T12 embedding foundation composed on real PostgreSQL as the actual app runtime LOGIN role: the persisted job and
frozen plan, local counting, the real ledger (reserve, count, single dispatch grant, settle or hold), exact evidence
and the vector cache, leases and races, crashes before and after publication, interrupted cleanup, deadlines, the
budget preflight, binding checks, tenancy and grants. The provider is the real SDK over a scripted `httpx2`
transport that counts physical requests: no external HTTP, key or account.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
import json
import threading
import time
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import httpx2
from pydantic import SecretStr
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

from policyops.budget.config import Caps, Configuration
from policyops.budget.ledger import Ledger, OperationBinding
from policyops.persistence import repositories as repo
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.embeddings import EmbeddingStore, EvidenceConflict, JobConflict, OperationScope
from policyops.persistence.records import Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers import embedding_calls as calls
from policyops.providers import tokenizer as tk
from policyops.providers.calls import Providers
from policyops.providers.embedding_calls import EmbedLimits, JobReport, PreparedJob, prepare_job, run_job
from policyops_contracts.embedding import EmbeddingJob
from policyops_testing.app_database import AppDatabase, NewDatabase


pytestmark = pytest.mark.postgres
KEY = SecretStr("synthetic-test-credential-0000")
TOKENIZER = tk.load()
FAST = EmbedLimits(lease_seconds=60.0, wait_seconds=0.5, poll_seconds=0.05, attempt_seconds=30.0)
SHORT = EmbedLimits(lease_seconds=60.0, wait_seconds=0.5, poll_seconds=0.05, attempt_seconds=0.5)
WORST = Configuration().reservation("embedding").worst_usd
TEXTS = ["Refunds go to the original payment method.", "Exchanges keep the same product type.",
         "Refunds go to the original payment method.", "Cancelled orders cannot be modified.", "A fourth line."]
LONG = [f"{i} " + "policy " * 3000 for i in range(4)]  # about 3000 tokens each: two fit in one 8192-token request
Handler = Callable[[httpx2.Request, dict[str, Any]], Awaitable[httpx2.Response]]


def vector(seed: int) -> list[float]:
    return [((i * 7 + seed) % 13 - 6 + 0.5) / 100.0 for i in range(1536)]


def body_for(inputs: list[str]) -> dict[str, Any]:
    tokens = sum(TOKENIZER.counts(inputs))
    return {"object": "list", "model": "text-embedding-3-small",
            "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
            "data": [{"object": "embedding", "index": i, "embedding": vector(len(text))}
                     for i, text in enumerate(inputs)]}


class Stream(httpx2.AsyncByteStream):
    def __init__(self, data: bytes, close: Callable[[], Awaitable[None]] | None = None) -> None:
        self.data, self.close = data, close

    async def __aiter__(self) -> Any:
        yield self.data

    async def aclose(self) -> None:
        if self.close is not None:
            await self.close()


def reply(data: Any, *, close: Callable[[], Awaitable[None]] | None = None,
          request_id: str | None = None) -> httpx2.Response:
    headers = {"content-type": "application/json"} | ({"x-request-id": request_id} if request_id else {})
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    return httpx2.Response(200, headers=headers, stream=Stream(raw, close))


async def valid(request: httpx2.Request, body: dict[str, Any]) -> httpx2.Response:
    return reply(body_for(body["input"]))


async def hang(request: httpx2.Request, body: dict[str, Any]) -> httpx2.Response:
    await asyncio.Event().wait()
    raise AssertionError("unreachable")


async def hang_close() -> None:
    await asyncio.Event().wait()


class Provider(httpx2.AsyncBaseTransport):
    """The scripted embeddings endpoint: counts physical requests. Shared by attempts, so never really closed."""

    def __init__(self, handler: Handler = valid, close: Callable[[], Awaitable[None]] | None = None) -> None:
        self.handler, self.close = handler, close
        self.requests: list[list[str]] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(await request.aread())
        self.requests.append(body["input"])
        response = await self.handler(request, body)
        response.request = request
        return response

    async def aclose(self) -> None:
        if self.close is not None:
            await self.close()


def providers(provider: Provider, credential: SecretStr | None = KEY) -> Providers:
    return Providers(credentials={} if credential is None else {"openai": credential},
                     transport=lambda name: provider)


def new_workspace(db: AppDatabase, ws: UUID | None = None) -> UUID:
    ws = ws or uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=ws, slug=f"ws-{ws.hex[:12]}", name="Embedding test",
                                              created_at=datetime.now(UTC)))
    return ws


class Env:
    def __init__(self, db: AppDatabase, configuration: Configuration | None = None, *, ws: UUID | None = None,
                 engine: Engine | None = None) -> None:
        self.db = db
        self.ws = ws or new_workspace(db)
        self.engine = engine or db.engine(APP_RUNTIME, pool_size=8)
        self.configuration = configuration or Configuration()
        self.ledger = self.new_ledger()
        self.store = EmbeddingStore(self.engine, self.ws, env="test")

    def new_ledger(self) -> Ledger:
        return build_app_ledger(env="test", engine=self.engine, workspace_id=self.ws,
                                configuration=self.configuration)

    def job(self, texts: list[str], subject: str = "subject-1") -> PreparedJob:
        return prepare_job(EmbeddingJob(purpose="ingest", subject_key=subject, inputs=tuple(texts)),
                           self.configuration, TOKENIZER, deadline=time.monotonic() + 60)

    def run(self, prepared: PreparedJob, provider: Provider, *, limits: EmbedLimits = FAST,
            credential: SecretStr | None = KEY, seconds: float = 60.0, ledger: Ledger | None = None) -> JobReport:
        return asyncio.run(run_job(ledger or self.ledger, self.store, providers(provider, credential), prepared,
                                   deadline=time.monotonic() + seconds, limits=limits))

    def sql(self, query: str, *params: Any) -> list[tuple[Any, ...]]:
        with self.db.superuser() as conn:
            cursor = conn.execute(query, params)
            return [tuple(row) for row in cursor.fetchall()] if cursor.description else []

    def job_id(self, subject: str = "subject-1") -> UUID:
        rows = self.sql("SELECT id FROM app.embedding_jobs WHERE workspace_id = %s AND subject_key = %s",
                        self.ws, subject)
        job: UUID = rows[0][0]
        return job

    def attempts(self, job: UUID | None) -> list[tuple[Any, ...]]:
        return self.sql("SELECT a.state, a.count_state, a.count_source, a.counted_input_tokens, a.contract_block, "
                        "a.actual_usd FROM app.usage_attempts a JOIN app.budget_scopes s ON s.id = a.scope_id "
                        "WHERE s.operation_key = %s ORDER BY a.operation_id", str(job))

    def scope(self, job: UUID | None) -> tuple[Any, ...]:
        (row,) = self.sql("SELECT spent_usd, held_usd, calls_consumed, calls_held, counts_used, contract_block "
                          "FROM app.budget_scopes WHERE operation_key = %s", str(job))
        return row

    def batches(self, job: UUID | None) -> list[tuple[Any, ...]]:
        return self.sql("SELECT ordinal, state, positions FROM app.embedding_batches WHERE job_id = %s "
                        "ORDER BY ordinal", job)

    def evidence(self, job: UUID | None) -> list[tuple[Any, ...]]:
        return self.sql("SELECT ordinal, outcome, prompt_tokens, total_tokens FROM app.embedding_attempt_evidence "
                        "WHERE job_id = %s ORDER BY ordinal", job)

    def cache_rows(self) -> int:
        count: int = self.sql("SELECT count(*) FROM app.embedding_cache WHERE workspace_id = %s", self.ws)[0][0]
        return count

    def expire_leases(self, job: UUID) -> None:
        self.sql("UPDATE app.embedding_batches SET lease_until = now() - interval '1 second' "
                 "WHERE job_id = %s AND lease_owner IS NOT NULL", job)


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("embeddings")


def usd(tokens: int) -> Decimal:
    return Decimal(tokens) * Decimal("0.02") / 1_000_000


# -- the normal path -------------------------------------------------------------------------------------------------

def test_a_job_counts_locally_sends_once_publishes_and_settles_the_exact_bill(db: AppDatabase) -> None:
    env, provider = Env(db), Provider()
    report = env.run(env.job(TEXTS), provider)
    assert report.status == "complete" and report.physical_requests == 1
    unique = list(dict.fromkeys(TEXTS))
    assert provider.requests == [unique]  # distinct inputs once, in first-occurrence order
    tokens = sum(TOKENIZER.counts(unique))
    assert env.attempts(report.job_id) == [("settled", "admitted", "local.tiktoken-cl100k", tokens, None,
                                            usd(tokens))]
    assert env.scope(report.job_id) == (usd(tokens), 0, 1, 0, 1, None)
    assert env.evidence(report.job_id) == [(0, "published", tokens, tokens)]
    assert env.cache_rows() == 4
    assert [v.position for v in report.vectors] == [0, 1, 2, 3, 4]
    assert report.vectors[0].vector == report.vectors[2].vector  # the duplicate input reuses its one vector
    assert env.sql("SELECT state FROM app.embedding_jobs WHERE id = %s", report.job_id) == [("complete",)]
    assert env.sql("SELECT count(*) FROM app.usage_events WHERE attempt_id IS NOT NULL") == [(1,)]


def test_a_rerun_and_the_same_inputs_elsewhere_make_no_call(db: AppDatabase) -> None:
    env, provider = Env(db), Provider()
    first = env.run(env.job(TEXTS), provider)
    again = env.run(env.job(TEXTS), provider)
    other = env.run(env.job(list(reversed(TEXTS)), subject="subject-2"), provider)
    assert len(provider.requests) == 1 and again.job_id == first.job_id
    assert again.status == other.status == "complete" and other.physical_requests == 0
    assert env.batches(other.job_id) == []  # all cached at planning: no batch, no reservation
    assert {v.input_sha256: v.vector for v in other.vectors} == {v.input_sha256: v.vector for v in first.vectors}


def test_an_empty_job_makes_no_call_and_a_changed_identity_conflicts(db: AppDatabase) -> None:
    env, provider = Env(db), Provider()
    empty = env.run(env.job([], subject="empty"), provider)
    assert (empty.status, empty.physical_requests, provider.requests) == ("complete", 0, [])
    env.run(env.job(TEXTS), provider)
    with pytest.raises(JobConflict):
        env.run(env.job([*TEXTS, "one more"]), provider)
    assert len(provider.requests) == 1


def test_packing_respects_the_input_and_token_limits_and_the_plan_is_frozen(db: AppDatabase) -> None:
    env, provider = Env(db), Provider()
    many = [f"line {i}" for i in range(70)]
    report = env.run(env.job(LONG[:3] + many), provider)
    assert report.status == "complete"
    assert [len(batch) for batch in provider.requests] == [2, 64, 7]  # tokens, then the 64-input limit
    assert all(sum(TOKENIZER.counts(batch)) <= 8192 for batch in provider.requests)
    assert [row[0] for row in env.batches(report.job_id)] == [0, 1, 2]


def test_inputs_above_the_aggregate_byte_limit_are_split_into_legal_requests(db: AppDatabase) -> None:
    env, provider = Env(db), Provider()
    texts = [(" " * 1000 + "a") * 32 + "b" * 735 + str(i) for i in range(9)]  # 32,768 bytes each, few tokens
    report = env.run(env.job(texts), provider)
    assert report.status == "complete" and [len(batch) for batch in provider.requests] == [8, 1]
    assert all(sum(len(t.encode("utf-8")) for t in batch) <= 262_144 for batch in provider.requests)
    assert [a[0] for a in env.attempts(report.job_id)] == ["settled", "settled"] and len(report.vectors) == 9


# -- the accounting table on the real ledger -----------------------------------------------------------------------

def answering(change: str) -> Handler:
    async def handler(request: httpx2.Request, body: dict[str, Any]) -> httpx2.Response:
        data = body_for(body["input"])
        tokens = data["usage"]["prompt_tokens"]
        if change == "contradiction":
            data["usage"] = {"prompt_tokens": tokens, "total_tokens": tokens + 1}
        elif change == "count":
            data["usage"] = {"prompt_tokens": tokens + 3, "total_tokens": tokens + 3}
        elif change == "model":
            data["model"] = "text-embedding-3-large"
        elif change == "vectors":
            data["data"][0]["embedding"] = data["data"][0]["embedding"][:10]
        elif change == "unparseable":
            return reply(b"{not json")
        return reply(data)
    return handler


@pytest.mark.parametrize(("change", "attempt", "block", "batch", "outcome"), [
    ("contradiction", "unresolved", "embedding_usage_contradiction", "blocked", "usage_contradiction"),
    ("model", "unresolved", "embedding_model_mismatch", "blocked", "model_mismatch"),
    ("count", "settled", "embedding_count_mismatch", "blocked", "count_mismatch"),
    ("vectors", "settled", None, "vectors_invalid", "vectors_invalid"),
    ("unparseable", "unresolved", None, "unresolved", None),
])
def test_the_accounting_table(db: AppDatabase, change: str, attempt: str, block: str | None, batch: str,
                              outcome: str | None) -> None:
    env = Env(db)
    report = env.run(env.job(TEXTS[:2]), Provider(answering(change)))
    (row,) = env.attempts(report.job_id)
    assert (row[0], row[4]) == (attempt, block)
    spent, held, *_, scope_block = env.scope(report.job_id)
    assert scope_block == block
    if attempt == "settled":
        assert spent > 0 and held == 0  # the known bill, even when blocked or the vectors are unusable
    else:
        assert spent == 0 and held == WORST  # unpriceable or unknown: the hold stays, nothing invented
    assert env.batches(report.job_id)[0][1] == batch
    assert [e[1] for e in env.evidence(report.job_id)] == ([] if outcome is None else [outcome])
    assert env.cache_rows() == 0 and report.status != "complete"


# -- plan, cache and resume ------------------------------------------------------------------------------------------

def test_cache_growth_after_planning_satisfies_an_unreserved_batch_without_rebatching(db: AppDatabase) -> None:
    env = Env(db)
    prepared = env.job(LONG)
    job, batches = env.store.plan_job(prepared.identity, prepared.inputs, calls.pack(prepared, env.configuration),
                                      window_seconds=180)
    assert [b.plan.positions for b in batches] == [(0, 1), (2, 3)]
    env.run(env.job(LONG[2:], subject="elsewhere"), Provider())  # another job publishes batch 1's inputs
    provider = Provider()
    report = env.run(prepared, provider)
    assert report.status == "complete" and provider.requests == [LONG[:2]]
    assert env.batches(job.id) == [(0, "published", [0, 1]), (1, "satisfied_by_cache", [2, 3])]
    assert len(env.attempts(job.id)) == 1  # the satisfied batch never reserved


class Crash(BaseException):
    pass


def crash(*args: Any, **kwargs: Any) -> None:
    raise Crash


def test_a_crash_after_publication_settles_from_its_own_evidence_on_resume(db: AppDatabase,
                                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    env, provider = Env(db), Provider()
    prepared = env.job(TEXTS[:2])
    monkeypatch.setattr(calls, "_account", crash)
    with pytest.raises(Crash):
        env.run(prepared, provider)
    monkeypatch.undo()
    job = env.job_id()
    assert [a[0] for a in env.attempts(job)] == ["dispatching"] and env.evidence(job)[0][1] == "published"
    env.expire_leases(job)
    report = env.run(prepared, provider)
    assert report.status == "complete" and len(provider.requests) == 1  # settled from evidence, never resent
    assert report.batches[0].fate == "reconciled"
    assert [a[0] for a in env.attempts(job)] == ["settled"] and env.scope(job)[1] == 0


def test_a_crash_before_publication_is_orphaned_never_resent_and_an_unrelated_cache_hit_settles_nothing(
        db: AppDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
    env, provider = Env(db), Provider()
    prepared = env.job(TEXTS[:2])
    monkeypatch.setattr(calls._Run, "_publish", crash)
    with pytest.raises(Crash):
        env.run(prepared, provider)
    monkeypatch.undo()
    job = env.job_id()
    env.run(env.job(TEXTS[:2], subject="unrelated"), Provider())  # the same inputs are now cached elsewhere
    env.expire_leases(job)
    report = env.run(prepared, provider)
    assert len(provider.requests) == 1 and report.batches[0].fate == "orphaned"
    assert [a[0] for a in env.attempts(job)] == ["dispatching"]  # possibly billed: kept, never marked or released
    assert env.scope(job)[1] == WORST and env.evidence(job) == [] and report.status == "incomplete"


def test_evidence_is_first_write_wins_and_must_match_batch_attempt_and_job(db: AppDatabase) -> None:
    env = Env(db)
    report = env.run(env.job(TEXTS[:2]), Provider())
    evidence = env.store.evidence(env.sql("SELECT attempt_id FROM app.embedding_attempt_evidence")[0][0])
    assert evidence is not None and evidence.outcome == "published"
    vectors = [report.vectors[0].vector, report.vectors[1].vector]
    assert env.store.publish(evidence, vectors) is False  # an identical replay
    for changed in (replace(evidence, prompt_tokens=evidence.prompt_tokens + 1,
                            total_tokens=evidence.total_tokens + 1),
                    replace(evidence, request_sha256="0" * 64),
                    replace(evidence, input_digests=(evidence.input_digests[1], evidence.input_digests[0])),
                    replace(evidence, ordinal=1)):
        with pytest.raises(EvidenceConflict):
            env.store.publish(changed, vectors)
    assert env.cache_rows() == 2


# -- ownership races (the ledger is the only sender grant) -----------------------------------------------------------

def pause(method: Callable[..., Any], reached: threading.Event, go: threading.Event, *, after: bool) -> Any:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not after:
            reached.set()
            assert go.wait(30)
        result = method(*args, **kwargs)
        if after:
            reached.set()
            assert go.wait(30)
        return result
    return wrapper


def in_thread(target: Callable[[], JobReport]) -> tuple[threading.Thread, list[JobReport]]:
    out: list[JobReport] = []
    thread = threading.Thread(target=lambda: out.append(target()), daemon=True)
    thread.start()
    return thread, out


def test_a_stale_creator_never_releases_the_new_owners_reservation(db: AppDatabase) -> None:
    env, provider = Env(db), Provider()
    prepared = env.job(TEXTS[:2])
    stale = env.new_ledger()
    reached, go = threading.Event(), threading.Event()
    stale.claim_count = pause(stale.claim_count, reached, go, after=False)  # type: ignore[method-assign]
    thread, out = in_thread(lambda: env.run(prepared, provider, ledger=stale))
    assert reached.wait(30)  # A created the reservation and is about to claim its count
    job = env.job_id()
    env.expire_leases(job)
    current = env.run(prepared, provider)  # B takes over, counts, dispatches and settles
    go.set()
    thread.join(30)
    (late,) = out
    assert current.status == "complete" and late.status == "blocked" and late.batches[-1].fate == "refused"
    assert len(provider.requests) == 1 and [a[0] for a in env.attempts(job)] == ["settled"]
    assert env.scope(job)[1:4] == (0, 1, 0)  # nothing held, one call consumed, B's reservation never released


@pytest.mark.parametrize("stage", ["after_the_dispatch_grant", "while_the_provider_responds"])
def test_lease_expiry_around_the_grant_keeps_one_request_and_the_late_bill(db: AppDatabase, stage: str) -> None:
    env = Env(db)
    reached, go = threading.Event(), threading.Event()

    async def slow(request: httpx2.Request, body: dict[str, Any]) -> httpx2.Response:
        if stage == "while_the_provider_responds":
            reached.set()
            assert await asyncio.to_thread(go.wait, 30)
        return reply(body_for(body["input"]))

    provider = Provider(slow)
    prepared = env.job(TEXTS[:2])
    first = env.new_ledger()
    if stage == "after_the_dispatch_grant":
        first.begin_dispatch = pause(first.begin_dispatch, reached, go, after=True)  # type: ignore[method-assign]
    thread, out = in_thread(lambda: env.run(prepared, provider, ledger=first))
    assert reached.wait(30)
    job = env.job_id()
    env.expire_leases(job)
    takeover = env.run(prepared, provider)
    assert takeover.batches[0].fate == "orphaned" and takeover.physical_requests == 0
    go.set()
    thread.join(30)
    (original,) = out
    assert original.batches[0].reason is not None and "lease_lost" in original.batches[0].reason
    assert len(provider.requests) == 1
    assert [a[0] for a in env.attempts(job)] == ["settled"] and env.evidence(job)[0][1] == "published"
    final = env.run(prepared, provider)  # the next owner reconciles the batch from the evidence
    assert final.status == "complete" and final.batches[0].fate == "reconciled" and len(provider.requests) == 1


def test_a_live_foreign_lease_is_waited_for_a_bounded_time(db: AppDatabase) -> None:
    env, provider = Env(db), Provider()
    prepared = env.job(TEXTS[:2])
    job, _ = env.store.plan_job(prepared.identity, prepared.inputs, calls.pack(prepared, env.configuration),
                                window_seconds=180)
    env.sql("UPDATE app.embedding_batches SET lease_owner = %s, lease_until = now() + interval '1 hour' "
            "WHERE job_id = %s", uuid4(), job.id)
    started = time.monotonic()
    report = env.run(prepared, provider)
    assert report.status == "in_progress_elsewhere" and time.monotonic() - started < 10
    assert provider.requests == [] and env.attempts(job.id) == []


# -- publication failure, interrupted cleanup, deadlines ------------------------------------------------------------

def test_a_failed_publication_keeps_the_bill_and_orphans_the_batch(db: AppDatabase,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    env, provider = Env(db), Provider()
    tries: list[int] = []

    def fail(*args: Any, **kwargs: Any) -> bool:
        tries.append(1)
        raise OperationalError("INSERT", {}, Exception("database unavailable"))

    monkeypatch.setattr(env.store, "publish", fail)
    report = env.run(env.job(TEXTS[:2]), provider)
    assert len(tries) == 3 and len(provider.requests) == 1  # database retries only, never a second request
    assert (report.batches[0].state, report.batches[0].reason) == ("orphaned", "publication_failed")
    assert [a[0] for a in env.attempts(report.job_id)] == ["settled"] and env.scope(report.job_id)[1] == 0


@pytest.mark.parametrize("stage", ["response_stream_close", "transport_close"])
def test_a_cancellation_during_cleanup_after_the_body_still_settles_the_bill(db: AppDatabase, stage: str) -> None:
    env = Env(db)
    closing: list[asyncio.Event] = []

    async def stall_close() -> None:
        closing[0].set()
        await asyncio.Event().wait()

    async def respond(request: httpx2.Request, body: dict[str, Any]) -> httpx2.Response:
        return reply(body_for(body["input"]), close=stall_close if stage == "response_stream_close" else None,
                     request_id="req_cancelled1")

    provider = Provider(respond, close=stall_close if stage == "transport_close" else None)
    prepared = env.job(TEXTS[:2])

    async def scenario() -> None:
        closing.append(asyncio.Event())
        task = asyncio.create_task(run_job(env.ledger, env.store, providers(provider), prepared,
                                           deadline=time.monotonic() + 60, limits=FAST))
        await closing[0].wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task  # the cancellation itself is preserved

    asyncio.run(scenario())
    job = env.job_id()
    assert len(provider.requests) == 1
    assert [a[0] for a in env.attempts(job)] == ["settled"] and env.scope(job)[1] == 0  # the known bill kept
    assert env.evidence(job)[0][1] == "published" and env.cache_rows() == 2
    assert env.batches(job)[0][1] == "published"


def test_a_timeout_during_cleanup_after_the_body_settles_and_reports_unconfirmed_cleanup(db: AppDatabase) -> None:
    env = Env(db)

    async def respond(request: httpx2.Request, body: dict[str, Any]) -> httpx2.Response:
        return reply(body_for(body["input"]), close=hang_close)

    report = env.run(env.job(TEXTS[:2]), Provider(respond), limits=SHORT)
    (batch,) = report.batches
    assert (batch.state, batch.reason, batch.cleanup_confirmed) == ("published", "timeout_after_body", False)
    assert [a[0] for a in env.attempts(report.job_id)] == ["settled"]


def test_a_hung_provider_keeps_the_hold_at_the_attempt_cap(db: AppDatabase) -> None:
    env = Env(db)
    started = time.monotonic()
    report = env.run(env.job(TEXTS[:2]), Provider(hang), limits=SHORT)
    assert time.monotonic() - started < 15
    assert (report.batches[0].state, report.batches[0].reason) == ("unresolved", "timeout")
    assert [a[0] for a in env.attempts(report.job_id)] == ["unresolved"] and env.scope(report.job_id)[1] == WORST


def test_the_server_window_bounds_a_huge_caller_deadline_and_a_restart_cannot_extend_it(db: AppDatabase) -> None:
    configuration = Configuration(caps=Caps(active_seconds=1))
    env = Env(db, configuration)
    prepared = env.job(LONG)  # two batches
    started = time.monotonic()
    report = env.run(prepared, Provider(hang), seconds=10_000.0)
    assert time.monotonic() - started < 15 and report.status == "deadline"
    job = env.job_id()
    assert env.sql("SELECT deadline_at - created_at FROM app.embedding_jobs WHERE id = %s", job)[0][0].seconds == 1
    restarted = Env(db, configuration, ws=env.ws, engine=env.engine)
    provider = Provider()
    resumed = restarted.run(prepared, provider, seconds=10_000.0)
    assert resumed.status == "deadline" and provider.requests == []  # no new reservation after the window
    assert len(env.attempts(job)) == 1 and env.batches(job)[1][1] == "planned"


# -- before anything is reserved -------------------------------------------------------------------------------------

@pytest.mark.parametrize("caps", [Caps(operation_usd=WORST + WORST / 2), Caps(operation_calls=1)])
def test_a_plan_above_the_caps_reserves_nothing(db: AppDatabase, caps: Caps) -> None:
    env, provider = Env(db, Configuration(caps=caps)), Provider()
    report = env.run(env.job(LONG), provider)  # two batches
    assert (report.status, report.reason) == ("budget", "plan_exceeds_caps")
    assert provider.requests == [] and env.attempts(report.job_id) == []


def test_outstanding_holds_count_against_the_preflight() -> None:
    def store(held: str) -> Any:
        scope = OperationScope(Decimal("0.001"), 64, 64, Decimal(0), Decimal(held), 0, 0, 0, None)
        return SimpleNamespace(unreserved=set, operation_scope=lambda kind, key: scope)

    batch = SimpleNamespace(state="planned", plan=SimpleNamespace(attempt_id=uuid4()))
    ledger = SimpleNamespace(configuration=Configuration())
    binding = OperationBinding("embedding", "k")
    calls.preflight(ledger, store("0"), binding, [batch])  # type: ignore[arg-type, list-item]
    with pytest.raises(calls._Stop, match="plan_exceeds_caps"):
        calls.preflight(ledger, store("0.0009"), binding, [batch])  # type: ignore[arg-type, list-item]


def test_a_missing_credential_or_ambient_setting_reserves_nothing(db: AppDatabase,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    env, provider = Env(db), Provider()
    report = env.run(env.job(TEXTS[:2]), provider, credential=None)
    assert (report.status, report.reason) == ("blocked", "no_credential") and env.attempts(report.job_id) == []
    monkeypatch.setenv("OPENAI_ORG_ID", "org-test")
    report = env.run(env.job(TEXTS[:2]), provider)
    assert (report.status, report.reason) == ("blocked", "ambient_sdk_settings")
    assert env.attempts(report.job_id) == [] and provider.requests == []


def test_a_ledger_and_store_from_different_workspaces_or_databases_are_refused_before_any_write(
        db: AppDatabase, new_app_database: NewDatabase) -> None:
    env, other, provider = Env(db), Env(db), Provider()
    with pytest.raises(calls.BindingMismatch, match="workspaces"):
        asyncio.run(run_job(other.ledger, env.store, providers(provider), env.job(TEXTS[:2]),
                            deadline=time.monotonic() + 60))
    second = new_app_database("embeddings_second")
    elsewhere = Env(second, ws=new_workspace(second, env.ws))  # the same workspace UUID in another database
    with pytest.raises(calls.BindingMismatch, match="engines"):
        asyncio.run(run_job(elsewhere.ledger, env.store, providers(provider), env.job(TEXTS[:2]),
                            deadline=time.monotonic() + 60))
    assert provider.requests == [] and env.sql("SELECT count(*) FROM app.embedding_jobs") == [(0,)]


# -- tenancy and grants (actual runtime role) ------------------------------------------------------------------------

TABLES = ("embedding_jobs", "embedding_job_inputs", "embedding_batches", "embedding_attempt_evidence",
          "embedding_cache")


def test_another_workspace_sees_nothing_and_pays_for_its_own_vectors(db: AppDatabase) -> None:
    alpha, beta, provider = Env(db), Env(db), Provider()
    first = alpha.run(alpha.job(TEXTS[:2]), provider)
    digests = [v.input_sha256 for v in first.vectors]
    config = alpha.job(TEXTS[:2]).request_config_sha256
    assert beta.store.cached(config, digests) == {}  # alpha's vectors are invisible to beta
    report = beta.run(beta.job(TEXTS[:2]), provider)
    assert report.physical_requests == 1 and len(provider.requests) == 2  # no cross-workspace reuse
    for env in (alpha, beta):
        with workspace_transaction(env.engine, env.ws) as conn:
            for table in TABLES:
                rows = conn.execute(text(f"SELECT DISTINCT workspace_id FROM app.{table}")).scalars().all()  # noqa: S608
                assert rows == [env.ws], table


@pytest.mark.parametrize(("statement", "allowed"), [
    ("UPDATE app.embedding_batches SET state = 'orphaned'", True),
    ("UPDATE app.embedding_batches SET lease_owner = NULL, lease_until = NULL, fence = fence + 1", True),
    ("UPDATE app.embedding_jobs SET state = 'incomplete', version = version + 1", True),
    ("UPDATE app.embedding_batches SET positions = '{0}'", False),
    ("UPDATE app.embedding_batches SET request_sha256 = repeat('0', 64)", False),
    ("UPDATE app.embedding_jobs SET input_set_sha256 = repeat('0', 64)", False),
    ("UPDATE app.embedding_jobs SET deadline_at = deadline_at + interval '1 hour'", False),
    ("UPDATE app.embedding_job_inputs SET text = 'x'", False),
    ("UPDATE app.embedding_attempt_evidence SET prompt_tokens = 0", False),
    ("UPDATE app.embedding_cache SET attempt_id = attempt_id", False),
    ("DELETE FROM app.embedding_cache", False),
    ("DELETE FROM app.embedding_attempt_evidence", False),
    ("DELETE FROM app.embedding_batches", False),
    ("DELETE FROM app.embedding_job_inputs", False),
    ("DELETE FROM app.embedding_jobs", False),
])
def test_runtime_grants_allow_only_advancement_columns(db: AppDatabase, statement: str, allowed: bool) -> None:
    env = Env(db)
    env.run(env.job(TEXTS[:2]), Provider())
    if allowed:
        with workspace_transaction(env.engine, env.ws) as conn:
            assert conn.execute(text(statement)).rowcount >= 1
    else:
        with pytest.raises(ProgrammingError, match="permission denied"), \
                workspace_transaction(env.engine, env.ws) as conn:
            conn.execute(text(statement))


def test_a_foreign_workspace_row_is_refused_by_row_level_security(db: AppDatabase) -> None:
    alpha, beta = Env(db), Env(db)
    alpha.run(alpha.job(TEXTS[:2]), Provider())
    with pytest.raises(ProgrammingError, match="row-level security"), \
            workspace_transaction(beta.engine, beta.ws) as conn:
        conn.execute(text("INSERT INTO app.embedding_jobs (id, workspace_id, purpose, subject_key, "
                          "input_set_sha256, input_count, request_config_sha256, tokenizer_sha256, state, "
                          "created_at, deadline_at, updated_at) VALUES (:id, :alpha, 'ingest', 'x', repeat('a', 64), "
                          "0, repeat('a', 64), repeat('a', 64), 'running', now(), now() + interval '1 minute', "
                          "now())"), {"id": uuid4(), "alpha": alpha.ws})
