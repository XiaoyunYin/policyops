"""Run runtime building blocks without a database (T09): the runtime catalog and specs, test-only wiring guards,
the event-version rule, stored-event decoding, stream settings and positions, backoff, and the stream loop's
lifetime bound under a permanent backlog."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
import json
import time
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

from pydantic import ValidationError
import pytest
from starlette.requests import Request

from policyops.api import runs as runs_api
from policyops.api.runs import StreamSettings, build_runs_runtime, start_position
from policyops.auth.service import AuthError, ExpectedContext
from policyops.persistence import runs as store
from policyops.runtime.clock import DatabaseLeaseClock, FixedLeaseClock, UnsafeTestHook, require_test_environment
from policyops.runtime.outbox import build_dispatcher
from policyops.runtime.spec import Retry, RuntimeCatalog, RuntimeSpec
from policyops.runtime.worker import backoff, build_worker
from policyops.services.runs import EventSnapshot
from policyops_contracts.clock import FixedClock
from policyops_contracts.events import EscalationRequested, EventEnvelope
from policyops_contracts.scalars import RunScope
from policyops_testing.scripted import ScriptedExecutor, scripted_spec


NOW = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
NOBODY = cast(Any, None)  # engines the guards must refuse before ever touching


def spec(spec_id: str = "test.scripted-v1", **changes: Any) -> RuntimeSpec:
    built = scripted_spec(ScriptedExecutor(), spec_id=spec_id)
    return RuntimeSpec(**{**built.__dict__, **changes})


# -- catalog and specs -------------------------------------------------------------------------------------------

def test_the_catalog_binds_all_three_digests_and_is_read_only() -> None:
    one = spec()
    catalog = RuntimeCatalog.of([one], default=one.spec_id)
    assert catalog.start_spec is one and catalog.test_only
    assert catalog.for_run(one.graph_sha256, one.prompt_sha256, one.config_sha256) is one
    assert catalog.for_run("f" * 64, one.prompt_sha256, one.config_sha256) is None
    assert catalog.for_run(one.graph_sha256, "f" * 64, one.config_sha256) is None
    with pytest.raises(TypeError):
        catalog.specs[("a" * 64, "b" * 64, "c" * 64)] = one  # type: ignore[index]
    with pytest.raises(ValueError, match="distinct"):
        RuntimeCatalog.of([one, RuntimeSpec(**{**one.__dict__, "spec_id": "test.other"})])  # same binding twice
    with pytest.raises(ValueError, match="distinct"):
        RuntimeCatalog.of([one, spec(graph_sha256="e" * 64)])  # the same spec ID twice
    with pytest.raises(ValueError, match="default"):
        RuntimeCatalog.of([one], default="test.missing")
    assert RuntimeCatalog().start_spec is None and not RuntimeCatalog().test_only


@pytest.mark.parametrize("changes", [
    {"spec_id": "Not A Slug"}, {"graph_sha256": "x" * 64}, {"config_sha256": "A" * 64}, {"max_attempts": 0},
    {"max_attempts": 101}, {"lease": timedelta(milliseconds=500)}, {"lease": timedelta(minutes=11)},
    {"lease": timedelta(minutes=5), "run_timeout": timedelta(minutes=5)}, {"run_timeout": timedelta(hours=25)},
])
def test_runtime_specs_are_validated(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        spec(**changes)


@pytest.mark.parametrize("reason", ["", "Has Spaces", "x" * 65, "1starts-with-digit", "line\nbreak"])
def test_retry_reasons_are_slugs(reason: str) -> None:
    with pytest.raises(ValueError):
        Retry(reason)


def test_backoff_doubles_and_is_capped() -> None:
    assert [backoff(n).total_seconds() for n in (1, 2, 3, 4)] == [2, 4, 8, 16]
    assert backoff(100) == timedelta(minutes=5) and backoff(0) == timedelta(seconds=2)


# -- test-only wiring --------------------------------------------------------------------------------------------

def test_test_only_parts_are_refused_outside_the_test_environment() -> None:
    fixed = FixedLeaseClock(FixedClock(NOW))
    scripted = RuntimeCatalog.of([spec()], default="test.scripted-v1")
    require_test_environment(fixed, "test")
    require_test_environment(DatabaseLeaseClock(), "deployment")
    for env in ("local", "deployment"):
        with pytest.raises(UnsafeTestHook):
            require_test_environment(fixed, env)
        with pytest.raises(UnsafeTestHook):
            build_runs_runtime(env=env, app_engine=NOBODY, ledger_clock=FixedClock(NOW), clock=fixed)
        with pytest.raises(UnsafeTestHook):
            build_runs_runtime(env=env, app_engine=NOBODY, ledger_clock=FixedClock(NOW), catalog=scripted)
        with pytest.raises(UnsafeTestHook):  # refused before the engines are touched
            build_worker(env=env, app_engine=NOBODY, discovery_engine=NOBODY, clock=fixed)
        with pytest.raises(UnsafeTestHook):
            build_worker(env=env, app_engine=NOBODY, discovery_engine=NOBODY, catalog=scripted)
        with pytest.raises(UnsafeTestHook):
            build_dispatcher(env=env, app_engine=NOBODY, discovery_engine=NOBODY, clock=fixed)
    production = build_runs_runtime(env="deployment", app_engine=NOBODY, ledger_clock=FixedClock(NOW))
    assert isinstance(production.service.clock, DatabaseLeaseClock) and production.service.catalog.start_spec is None


# -- the event version rule (D2) ---------------------------------------------------------------------------------

def envelope(**changes: Any) -> dict[str, Any]:
    scope = RunScope(workspace_id=uuid4(), case_id=uuid4(), run_id=uuid4())
    base = {"event_id": str(uuid4()), "scope": scope.model_dump(mode="json"), "sequence": 1,
            "occurred_at": NOW.isoformat(), "payload": {"type": "escalation.requested", "rule_id": "x"}}
    return {**base, **changes}


@pytest.mark.parametrize("version", [True, 1.0, "1", 2, None])
def test_event_version_must_be_the_integer_1(version: Any) -> None:
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate_json(json.dumps(envelope(event_version=version)))
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate(envelope(event_version=version))


def test_event_version_1_and_its_default_are_unchanged() -> None:
    assert EventEnvelope.model_validate_json(json.dumps(envelope(event_version=1))).event_version == 1
    assert EventEnvelope.model_validate_json(json.dumps(envelope())).event_version == 1


# -- stored-event decoding ---------------------------------------------------------------------------------------

def run_record() -> store.Run:
    return store.Run(id=uuid4(), workspace_id=uuid4(), case_id=uuid4(), case_version=1, mode="workbench",
                     graph_sha256="a" * 64, prompt_sha256="b" * 64, config_sha256="c" * 64, state="running",
                     initiated_by=None, generation=1, event_highwater=3, event_retention_floor=0, deadline_at=NOW,
                     active_remaining_us=0, active_started_at=NOW, created_at=NOW, updated_at=NOW, version=2)


def row(*, schema: str = "policyops.run-event/v1", event_type: str = "escalation.requested",
        payload: Any = None) -> Any:
    return SimpleNamespace(id=uuid4(), sequence=2, event_type=event_type, schema_version=schema,
                           payload=json.dumps(payload if payload is not None else
                                              {"type": "escalation.requested", "rule_id": "x"}), occurred_at=NOW)


@pytest.mark.parametrize("stored", [
    row(schema="policyops.run-event/v2"),                                    # unknown schema version
    row(event_type="run.state_changed"),                                     # type disagrees with the payload
    row(event_type="run.state_changed", payload={"current": "running"}),     # an old untyped payload
    row(payload={"type": "escalation.requested"}),                           # an invalid typed payload
])
def test_undecodable_stored_events_are_marked_unsupported(stored: Any) -> None:
    decoded = store._decode(run_record(), stored)
    assert isinstance(decoded, store.UnsupportedEvent)
    assert (decoded.sequence, decoded.event_type, decoded.schema_version) == (
        2, stored.event_type, stored.schema_version)


def test_a_valid_stored_event_decodes_as_its_envelope() -> None:
    run = run_record()
    decoded = store._decode(run, row())
    assert isinstance(decoded, EventEnvelope) and decoded.scope == run.scope
    assert decoded.payload == EscalationRequested(rule_id="x")


# -- stream settings, positions and the loop ---------------------------------------------------------------------

def expected(run: store.Run) -> ExpectedContext:
    return ExpectedContext(principal_id=uuid4(), workspace_id=run.workspace_id)


def collect(stream: AsyncIterator[bytes]) -> list[bytes]:
    async def drain() -> list[bytes]:
        return [chunk async for chunk in stream]

    return asyncio.run(drain())


@pytest.mark.parametrize("settings", [
    {"poll_interval": 0.001}, {"poll_interval": 11}, {"poll_interval": 1, "heartbeat_interval": 0.5},
    {"heartbeat_interval": 61}, {"max_lifetime": 0.5}, {"max_lifetime": 3601}, {"batch": 0}, {"batch": 501},
])
def test_stream_settings_are_bounded(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        StreamSettings(**settings)


def request(*headers: tuple[str, str]) -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "query_string": b"",
                    "headers": [(k.lower().encode(), v.encode()) for k, v in headers]})


def test_the_start_position_prefers_the_reconnect_header() -> None:
    assert start_position(request(), None) == 0
    assert start_position(request(), "7") == 7
    assert start_position(request(("Last-Event-ID", "3")), "7") == 3
    assert start_position(request(("Last-Event-ID", "3")), "not-validated-when-the-header-wins") == 3
    for headers, after in (((), "-1"), ((), "x"), ((), "1" * 20), ((("Last-Event-ID", "0x1"),), None),
                           ((("Last-Event-ID", "1"), ("Last-Event-ID", "1")), None), ((), "")):
        with pytest.raises(AuthError) as refused:
            start_position(request(*headers), after)
        assert refused.value.rule_id == "api.invalid_event_position"


def test_the_stream_lifetime_holds_under_a_permanent_backlog() -> None:
    """Every poll returns a full batch (more is always waiting): the stream must still end at its lifetime with
    an id-free `reconnect` control frame instead of running forever."""
    settings = StreamSettings(poll_interval=0.01, heartbeat_interval=0.01, max_lifetime=1.0, batch=3)
    run = run_record()
    authorized = SimpleNamespace(workspace_id=run.workspace_id)
    service = SimpleNamespace(resolve=lambda cookie: object(),
                              authorize=lambda session, action, *, expected: authorized)

    def snapshot(_authorized: Any, _run_id: Any, *, after: int, limit: int) -> EventSnapshot:
        events = [EventEnvelope(event_id=uuid4(), scope=run.scope, sequence=after + i + 1, occurred_at=NOW,
                                payload=EscalationRequested(rule_id="x")) for i in range(limit)]
        return EventSnapshot(events=list(events), highwater=after + limit + 10, floor=0, terminal=False)

    runtime = SimpleNamespace(stream=settings, service=SimpleNamespace(snapshot=snapshot))
    started = time.monotonic()
    chunks = collect(runs_api._stream(cast(Any, SimpleNamespace(service=service)), cast(Any, runtime),
                                      expected(run), run.id, "cookie", 0))
    assert time.monotonic() - started < 3
    assert chunks[-1] == b"event: reconnect\ndata: {}\n\n"
    ids = [int(chunk.split(b"\n", 1)[0][4:]) for chunk in chunks if chunk.startswith(b"id: ")]
    assert ids == list(range(1, len(ids) + 1)) and len(ids) >= 3


# -- F1: the raw constructor enforces the same invariants as `.of` ------------------------------------------------

def test_the_raw_constructor_snapshots_and_freezes_the_callers_mapping() -> None:
    from policyops.runtime.spec import binding
    from policyops.runtime.worker import checked_parts

    production = RuntimeSpec(**{**spec().__dict__, "test_only": False})
    scripted = spec()
    caller = {binding(production): production}
    catalog = RuntimeCatalog(caller, default=production.spec_id)
    lease_clock, checked = checked_parts("deployment", None, catalog)  # a production-looking catalog passes
    caller[binding(production)] = scripted  # the caller later swaps in a test-only spec under the same binding
    caller[("d" * 64, "e" * 64, "f" * 64)] = scripted
    assert checked.for_run(*binding(production)) is production and not checked.test_only
    assert len(checked.specs) == 1 and isinstance(lease_clock, DatabaseLeaseClock)
    with pytest.raises(TypeError):
        checked.specs[binding(production)] = scripted  # type: ignore[index]


def test_the_raw_constructor_refuses_inconsistent_catalogs() -> None:
    from policyops.runtime.spec import binding

    one = spec()
    other = spec(spec_id="test.other")  # another definition: other digests
    with pytest.raises(ValueError, match="own"):
        RuntimeCatalog({binding(other): one})  # a spec under another spec's binding
    with pytest.raises(ValueError, match="own"):
        RuntimeCatalog({("a" * 64, "b" * 64, "c" * 64): one})
    with pytest.raises(ValueError, match="own"):
        RuntimeCatalog({binding(one): cast(Any, "not a spec")})
    same_id = RuntimeSpec(**{**other.__dict__, "spec_id": one.spec_id})
    with pytest.raises(ValueError, match="distinct"):
        RuntimeCatalog({binding(one): one, binding(same_id): same_id})
    with pytest.raises(ValueError, match="default"):
        RuntimeCatalog({binding(one): one}, default="test.missing")
    with pytest.raises(ValueError, match="default"):
        RuntimeCatalog(default=one.spec_id)
    assert RuntimeCatalog({binding(one): one}, default=one.spec_id).start_spec is one


# -- F4: lifetime per event and across delivery -------------------------------------------------------------------

def test_the_lifetime_is_checked_before_every_event_of_a_batch() -> None:
    settings = StreamSettings(poll_interval=0.01, heartbeat_interval=0.01, max_lifetime=1.0, batch=3)
    run = run_record()
    authorized = SimpleNamespace(workspace_id=run.workspace_id)
    service = SimpleNamespace(resolve=lambda cookie: object(),
                              authorize=lambda session, action, *, expected: authorized)

    def snapshot(_authorized: Any, _run_id: Any, *, after: int, limit: int) -> EventSnapshot:
        events = [EventEnvelope(event_id=uuid4(), scope=run.scope, sequence=after + i + 1, occurred_at=NOW,
                                payload=EscalationRequested(rule_id="x")) for i in range(limit)]
        return EventSnapshot(events=list(events), highwater=after + limit, floor=0, terminal=False)

    runtime = SimpleNamespace(stream=settings, service=SimpleNamespace(snapshot=snapshot))
    frames = runs_api._stream(cast(Any, SimpleNamespace(service=service)), cast(Any, runtime), expected(run),
                              run.id, "cookie", 0)

    async def consume() -> list[bytes]:
        first = await frames.__anext__()
        await asyncio.sleep(1.1)  # a slow consumer: the lifetime passes in the middle of the batch
        rest = [chunk async for chunk in frames]
        return [first, *rest]

    received = asyncio.run(consume())
    assert received[0].startswith(b"id: 1\n")
    assert received[1:] == [b"event: reconnect\ndata: {}\n\n"]  # not durable event 2, and then the end


def test_an_idle_poll_longer_than_the_lifetime_still_ends_on_time() -> None:
    settings = StreamSettings(poll_interval=10, heartbeat_interval=10, max_lifetime=1.0, delivery_grace=0.1)
    run = run_record()
    authorized = SimpleNamespace(workspace_id=run.workspace_id)
    service = SimpleNamespace(resolve=lambda cookie: object(),
                              authorize=lambda session, action, *, expected: authorized)

    def snapshot(_authorized: Any, _run_id: Any, *, after: int, limit: int) -> EventSnapshot:
        return EventSnapshot(events=[], highwater=after, floor=0, terminal=False)

    runtime = SimpleNamespace(stream=settings, service=SimpleNamespace(snapshot=snapshot))
    started = time.monotonic()
    chunks = collect(runs_api._stream(cast(Any, SimpleNamespace(service=service)), cast(Any, runtime),
                                      expected(run), run.id, "cookie", 0))
    assert 0.9 <= time.monotonic() - started < 2 and chunks == [b"event: reconnect\ndata: {}\n\n"]


def test_the_connection_deadline_cuts_off_a_stalled_send_through_inner_middleware() -> None:
    """The composed shape: StreamDeadline outermost, a BaseHTTPMiddleware inside it (like the error boundary), then
    an endless event stream. The client stops reading (its first body send never returns); the request must
    still end at the connection deadline."""
    from fastapi import FastAPI

    app = FastAPI()
    app.state.runs = SimpleNamespace(stream=StreamSettings(max_lifetime=1.0, delivery_grace=0.5))

    @app.middleware("http")
    async def inner(request: Any, call_next: Any) -> Any:
        return await call_next(request)

    def endless() -> Any:
        while True:
            yield b": heartbeat\n\n"
            time.sleep(0.01)

    @app.get("/api/v1/runs/{run_id}/events")
    def events(run_id: str) -> Any:
        return runs_api.EventStreamResponse(endless())

    app.add_middleware(runs_api.StreamDeadline)
    stalled = asyncio.Event()

    async def receive() -> dict[str, Any]:
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: Any) -> None:
        if message["type"] == "http.response.body":
            stalled.set()
            await asyncio.sleep(3600)  # the client never reads

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": "GET", "scheme": "http", "path": "/api/v1/runs/x/events", "raw_path": b"/api/v1/runs/x/events",
             "query_string": b"", "root_path": "", "headers": [], "client": ("127.0.0.1", 1),
             "server": ("127.0.0.1", 80)}

    async def drive() -> float:
        started = time.monotonic()
        await asyncio.wait_for(app(scope, receive, send), timeout=10)
        return time.monotonic() - started

    elapsed = asyncio.run(drive())
    assert stalled.is_set() and 1.4 <= elapsed < 4


def test_stream_settings_bound_the_delivery_grace() -> None:
    for grace in (0.05, 31):
        with pytest.raises(ValueError):
            StreamSettings(delivery_grace=grace)
    assert StreamSettings(max_lifetime=10, delivery_grace=2).connection_deadline == 12
