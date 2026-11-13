"""T14 grant observability in `providers.calls` (offline): `AttemptRecord.count_granted` / `dispatch_granted` are set
exactly when this call obtained `CountGranted` / `DispatchGranted`, before the count or request is awaited, and are
never cleared by later fates, deadlines or cancellation. A duck-typed scripted ledger and a scripted SDK transport;
no database and no external HTTP. The flags are grant facts, not proof that bytes left the process."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass, fields
import json
import time
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import httpx2
from pydantic import SecretStr
import pytest

from policyops.budget.config import ChatActor, Configuration
from policyops.budget.ledger import (
    BudgetExhausted,
    CountGranted,
    CountRefused,
    DispatchGranted,
    DispatchRefused,
    Reserved,
    RunBinding,
)
from policyops.providers import calls
from policyops.providers.calls import AttemptRecord, CallLimits, CallReport, Providers
from policyops.retrieval.rerank import attempt_work
from policyops_contracts.model import Message, ModelRequest, OutputSpec, TextPart
from policyops_contracts.provider_failures import closed_failure_code
from policyops_testing.retrieval_fixtures import Scripted, count_reply, luna_reply, openai_json, slow


ANSWER = json.dumps({"type": "object", "properties": {"decision": {"type": "string", "enum": ["a", "b"]}},
                     "required": ["decision"], "additionalProperties": False})
KEY = SecretStr("synthetic-test-credential-0000")
REQUEST = ModelRequest(instructions="Decide.", max_output_tokens=256,
                       messages=(Message(role="user", parts=(TextPart(text="Choose."),)),),
                       output=OutputSpec(name="answer", answer_schema_json=ANSWER))


def attempt(state: str = "reserved", count_state: str = "none", tokens: int | None = None) -> SimpleNamespace:
    return SimpleNamespace(state=state, count_state=count_state, counted_input_tokens=tokens)


class Books:
    """A scripted ledger with the `Ledger` surface `call` uses; records every call."""

    def __init__(self, *, reserve: str = "created", claim: str = "grant", count_state: str = "admitted",
                 dispatch: str = "grant") -> None:
        self.configuration = Configuration()
        self.reserve_mode, self.claim_mode, self.count_state, self.dispatch_mode = reserve, claim, count_state, dispatch
        self.log: list[str] = []

    def reserve(self, binding: Any, attempt_id: UUID, actor: str, operation: str, sha: str) -> Reserved:
        self.log.append("reserve")
        if self.reserve_mode == "budget":
            raise BudgetExhausted("run", "run_calls")
        return Reserved(attempt(), self.reserve_mode == "created")  # type: ignore[arg-type]

    def claim_count(self, attempt_id: UUID, sha: str) -> CountGranted | CountRefused:
        self.log.append("claim_count")
        if self.claim_mode == "grant":
            return CountGranted(attempt())  # type: ignore[arg-type]
        return CountRefused(attempt(), self.claim_mode)  # type: ignore[arg-type]

    def record_count(self, attempt_id: UUID, *, tokens: int | None, source: str) -> Any:
        self.log.append(f"record_count:{source}")
        return attempt(count_state=self.count_state if tokens is not None else "failed", tokens=tokens)

    def begin_dispatch(self, attempt_id: UUID, sha: str) -> DispatchGranted | DispatchRefused:
        self.log.append("begin_dispatch")
        if self.dispatch_mode == "grant":
            return DispatchGranted(attempt("dispatching"))  # type: ignore[arg-type]
        if self.dispatch_mode == "replayed":
            return DispatchRefused(attempt("dispatching"), "dispatching")  # type: ignore[arg-type]
        return DispatchRefused(attempt("reserved"), self.dispatch_mode)  # type: ignore[arg-type]

    def release(self, attempt_id: UUID) -> None:
        self.log.append("release")

    def mark_unresolved(self, attempt_id: UUID, **_: Any) -> None:
        self.log.append("mark_unresolved")

    def settle(self, attempt_id: UUID, settlement: Any) -> None:
        self.log.append("settle")


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[AttemptRecord]]:
    """Every AttemptRecord `call` creates (reachable even when the call is cancelled)."""
    created: list[AttemptRecord] = []

    @dataclass
    class Recording(AttemptRecord):
        def __post_init__(self) -> None:
            created.append(self)

    monkeypatch.setattr(calls, "AttemptRecord", Recording)
    yield created


def run(books: Books, transport: Scripted, *, seconds: float = 30.0, attempt_seconds: float = 30.0) -> CallReport:
    providers = Providers(credentials={"openai": KEY},
                          transport=lambda provider: transport)
    return asyncio.run(calls.call(books, providers, RunBinding(uuid4()), uuid4(), "rerank", REQUEST,  # type: ignore[arg-type]
                                  "reranker", deadline=time.monotonic() + seconds,
                                  limits=CallLimits(retries_per_request=0, repairs=0, backoff_seconds=0.0,
                                                    attempt_seconds=attempt_seconds)))


@pytest.mark.parametrize("phase", ["count", "inference"])
@pytest.mark.parametrize("code", ["http_429", "http_529", "timeout", "connection", "malformed"])
@pytest.mark.parametrize("model", ["gpt-6-luna", "claude-haiku-5-5"])
def test_failure_codes_survive_calls_without_sensitive_values(phase: str, code: str, model: str) -> None:
    canary = "PRIVATE_BODY_HEADER_KEY_CANARY"

    def fail(request: httpx2.Request) -> httpx2.Response:
        if code == "timeout":
            raise httpx2.ReadTimeout(canary, request=request)
        if code == "connection":
            raise httpx2.ConnectError(canary, request=request)
        if code == "malformed":
            return httpx2.Response(200, content=canary.encode(), request=request)
        return httpx2.Response(int(code[5:]), json={"error": {"message": canary}},
                               headers={"x-private": canary}, request=request)

    class FailureScript(Scripted):
        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            is_count = request.url.path.endswith(("input_tokens", "count_tokens"))
            self.seen.append("count" if is_count else "create")
            if is_count and phase == "inference":
                return httpx2.Response(200, json={"input_tokens": 900}, request=request)
            return fail(request)

    transport = FailureScript()
    books = Books()
    books.configuration = Configuration(actors={**books.configuration.actors,
                                                "reranker": ChatActor("reranker", model, "low")})
    provider = "openai" if model == "gpt-6-luna" else "anthropic"
    providers = Providers({provider: KEY}, lambda _: transport)
    report = asyncio.run(calls.call(books, providers, RunBinding(uuid4()), uuid4(), "test",  # type: ignore[arg-type]
        REQUEST, "reranker", deadline=time.monotonic() + 30,
        limits=CallLimits(retries_per_request=0, repairs=0)))
    assert report.failure_code == report.attempts[0].failure_code == code
    assert report.attempts[0].fate == ("released" if phase == "count" else "unresolved")
    assert ("mark_unresolved" in books.log) == (phase == "inference")
    assert canary not in repr(report) and canary not in repr(books.log)
    assert closed_failure_code(canary) is None
    assert closed_failure_code("http_529 " + canary) is None
    assert len(transport.seen) == (1 if phase == "count" else 2)  # no implicit retries


def flags(record: AttemptRecord) -> tuple[bool, bool]:
    return record.count_granted, record.dispatch_granted


def test_the_flags_are_trailing_defaulted_fields_and_positional_construction_still_works() -> None:
    names = [f.name for f in fields(AttemptRecord)]
    assert names[-3:] == ["count_granted", "dispatch_granted", "evidence"]
    record = AttemptRecord(uuid4(), "rerank.r0.a0", "a" * 64)
    assert (record.fate, record.reason, record.cleanup_confirmed, *flags(record)) == (None, None, None, False, False)


def test_a_settled_call_obtained_both_grants(records: list[AttemptRecord]) -> None:
    transport = Scripted(counts=[count_reply(1200)], creates=[luna_reply('{"decision": "a"}')])
    report = run(Books(), transport)
    (record,) = records
    assert report.attempts == [record] and record.fate == "settled" and flags(record) == (True, True)
    assert transport.seen == ["count", "create"]


@pytest.mark.parametrize(("books", "fate"), [
    (Books(reserve="replayed"), "replayed"),          # another owner: nothing changed, nothing sent
    (Books(reserve="budget"), "not_reserved"),
    (Books(claim="count_cap"), "released"),           # the count claim itself was refused
    (Books(claim="run_not_active"), "released"),
])
def test_no_grant_before_a_count_claim(records: list[AttemptRecord], books: Books, fate: str) -> None:
    transport = Scripted()
    run(books, transport)
    (record,) = records
    assert record.fate == fate and flags(record) == (False, False) and transport.seen == []


@pytest.mark.parametrize(("books", "counts", "fate", "dispatch_asked"), [
    (Books(), [openai_json({"error": {"message": "x"}}, status=500)], "released", False),  # the count failed
    (Books(count_state="rejected"), [count_reply(20_000)], "released", False),          # counted, not admitted
    (Books(dispatch="run_not_active"), [count_reply(1200)], "released", True),           # dispatch refused
    (Books(dispatch="replayed"), [count_reply(1200)], "replayed", True),                # no longer reserved
])
def test_a_count_grant_without_a_dispatch_grant(records: list[AttemptRecord], books: Books, counts: list[Any],
                                                fate: str, dispatch_asked: bool) -> None:
    transport = Scripted(counts=counts)
    run(books, transport)
    (record,) = records
    assert record.fate == fate and flags(record) == (True, False) and transport.seen == ["count"]
    assert ("begin_dispatch" in books.log) is dispatch_asked


def test_the_deadline_during_the_count_keeps_the_count_grant(records: list[AttemptRecord]) -> None:
    books = Books()
    transport = Scripted(counts=[slow(count_reply(1200), 30.0)])
    report = run(books, transport, seconds=0.5)
    (record,) = records
    assert report.status == "deadline" and record.fate == "released" and record.cleanup_confirmed is False
    assert flags(record) == (True, False) and "record_count:interrupted" in books.log


def test_an_expired_attempt_cap_after_dispatch_keeps_both_grants(records: list[AttemptRecord]) -> None:
    books = Books()
    transport = Scripted(counts=[count_reply(1200)], creates=[slow(luna_reply("{}"), 30.0)])
    run(books, transport, attempt_seconds=0.5)
    (record,) = records
    assert record.fate == "unresolved" and flags(record) == (True, True) and "mark_unresolved" in books.log


def test_the_deadline_after_dispatch_keeps_both_grants(records: list[AttemptRecord]) -> None:
    books = Books()
    transport = Scripted(counts=[count_reply(1200)], creates=[slow(luna_reply("{}"), 30.0)])
    report = run(books, transport, seconds=1.0)
    (record,) = records
    assert report.status == "deadline" and record.fate == "unresolved" and flags(record) == (True, True)


@pytest.mark.parametrize("phase", ["count", "create"])
def test_cancellation_keeps_the_grants_already_obtained(records: list[AttemptRecord], phase: str) -> None:
    started = asyncio.Event()
    if phase == "count":
        transport = Scripted(counts=[slow(count_reply(1200), 30.0, started)])
    else:
        transport = Scripted(counts=[count_reply(1200)], creates=[slow(luna_reply("{}"), 30.0, started)])
    books = Books()
    providers = Providers(credentials={"openai": KEY},
                          transport=lambda provider: transport)

    async def scenario() -> None:
        task = asyncio.create_task(calls.call(books, providers, RunBinding(uuid4()), uuid4(), "rerank",  # type: ignore[arg-type]
                                              REQUEST, "reranker", deadline=time.monotonic() + 30,
                                              limits=CallLimits(retries_per_request=0, repairs=0)))
        try:
            await asyncio.wait_for(started.wait(), 10)
        finally:
            task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 10)

    asyncio.run(scenario())
    (record,) = records
    assert flags(record) == ((True, False) if phase == "count" else (True, True))
    assert record.fate == ("released" if phase == "count" else "unresolved") and record.cleanup_confirmed is False


def test_invocation_work_is_derived_from_the_exact_flags_only() -> None:
    granted = AttemptRecord(uuid4(), "a", "a" * 64, fate="replayed", count_granted=True)  # fate alone is ambiguous
    sent = AttemptRecord(uuid4(), "b", "b" * 64, fate="unresolved", cleanup_confirmed=False, count_granted=True,
                         dispatch_granted=True)
    replay = AttemptRecord(uuid4(), "c", "c" * 64, fate="replayed")
    assert attempt_work([replay]) == attempt_work([]) and attempt_work([replay]).counts_claimed == 0
    assert (attempt_work([granted]).counts_claimed, attempt_work([granted]).inferences_dispatched) == (1, 0)
    work = attempt_work([sent])
    assert (work.counts_claimed, work.inferences_dispatched, work.cleanup_unconfirmed) == (1, 1, True)
