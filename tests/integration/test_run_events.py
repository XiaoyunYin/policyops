"""Run event streaming (T09): server-sent events over a real loopback HTTP server (uvicorn in a thread) and real
PostgreSQL, as the actual runtime roles. The worker runs in-process with the scripted test executor and the
controlled clock; the stream's poll, heartbeat and lifetime bounds are short server settings for the test.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
import json
import threading
import time
from typing import Any, cast
from uuid import UUID, uuid4

import httpx
import pytest

from policyops.api.runs import StreamSettings
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.runtime.spec import RuntimeCatalog
from policyops_contracts.events import EventEnvelope
from policyops_testing import case_api, live_server, openapi_check
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.case_api import CaseApi
from policyops_testing.scripted import ScriptedExecutor, scripted_spec


pytestmark = pytest.mark.postgres
EVENTS = "/api/v1/runs/{run_id}/events"
STREAM = StreamSettings(poll_interval=0.05, heartbeat_interval=0.2, max_lifetime=2.0, batch=2)


@dataclass
class Frame:
    id: str | None = None
    event: str | None = None
    data: str | None = None
    comment: str | None = None
    raw: list[str] = field(default_factory=list)


def frames(lines: Iterator[str]) -> Iterator[Frame]:
    current = Frame()
    for line in lines:
        if line == "":
            if current.raw:
                yield current
            current = Frame()
            continue
        current.raw.append(line)
        name, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if name == "":
            current.comment = value
        elif name in ("id", "event", "data"):
            setattr(current, name, value)
    if current.raw:
        yield current


@pytest.fixture
def fresh(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("events")


@dataclass
class Setup:
    api: CaseApi
    catalog: RuntimeCatalog
    executor: ScriptedExecutor
    workspace: UUID
    browser: Any
    url: str

    def client(self, browser: Any | None = None) -> httpx.Client:
        jar = {name: value for name, value in (browser or self.browser).cookies.items()}  # httpx2 jar -> plain
        return httpx.Client(base_url=self.url, cookies=jar, timeout=15)

    def started_run(self) -> str:
        case = self.api.create(self.browser).json()["case_id"]
        response = self.api.start_run(self.browser, case, '"1"')
        assert response.status_code == 202
        return str(response.json()["run_id"])


@pytest.fixture
def setup(fresh: AppDatabase) -> Iterator[Setup]:
    executor = ScriptedExecutor(events=3)
    built = scripted_spec(executor)
    catalog = RuntimeCatalog.of([built], default=built.spec_id)
    api = case_api.build(fresh, catalog=catalog, stream=STREAM)
    workspace = api.workspace("events")
    browser = api.member(f"subject-{uuid4().hex[:10]}", workspace, "analyst")
    with live_server.serve(api.app) as url:
        yield Setup(api, catalog, executor, workspace, browser, url)


def stream(setup: Setup, run_id: str, *, client: httpx.Client | None = None,
           **request: Any) -> tuple[httpx.Response, list[Frame]]:
    with client or setup.client() as own, own.stream("GET", f"/api/v1/runs/{run_id}/events", **request) as response:
        collected = list(frames(response.iter_lines())) if response.status_code == 200 else []
        if response.status_code != 200:
            response.read()
    openapi_check.check_response(response, "GET", EVENTS)
    return response, collected


def ids(collected: list[Frame]) -> list[int]:
    return [int(f.id) for f in collected if f.id is not None]


def test_the_stream_replays_ordered_events_and_ends_after_the_terminal_one(setup: Setup) -> None:
    run = setup.started_run()
    assert setup.api.worker(setup.catalog).run_once() == 1
    response, collected = stream(setup, run)
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store" and response.headers["x-accel-buffering"] == "no"
    assert ids(collected) == [1, 2, 3, 4, 5, 6]
    events = [EventEnvelope.model_validate_json(f.data or "") for f in collected if f.id]
    assert [e.sequence for e in events] == [1, 2, 3, 4, 5, 6]
    assert [f.event for f in collected if f.id] == [e.payload.type for e in events]
    final = events[-1].payload
    assert final.type == "run.state_changed" and getattr(final, "current", None) == "succeeded"
    assert {e.scope.run_id for e in events} == {UUID(run)}


def test_positions_precedence_and_refusals_before_headers(setup: Setup) -> None:
    run = setup.started_run()
    setup.api.worker(setup.catalog).run_once()
    assert ids(stream(setup, run, headers={"Last-Event-ID": "3"})[1]) == [4, 5, 6]
    assert ids(stream(setup, run, params={"after": "4"})[1]) == [5, 6]
    # A reconnect resends the original URL: the header wins, and only the selected position is validated.
    assert ids(stream(setup, run, params={"after": "4"}, headers={"Last-Event-ID": "2"})[1]) == [3, 4, 5, 6]
    assert ids(stream(setup, run, params={"after": "x" * 40}, headers={"Last-Event-ID": "5"})[1]) == [6]
    assert ids(stream(setup, run, params={"after": "6"})[1]) == []
    requests: list[dict[str, Any]] = [
        {"params": {"after": "-1"}}, {"params": {"after": "1.0"}}, {"params": {"after": "+2"}},
                    {"params": {"after": "9" * 20}}, {"headers": {"Last-Event-ID": "abc"}},
                    {"headers": [("Last-Event-ID", "1"), ("Last-Event-ID", "2")]}]
    for request in requests:
        response, _ = stream(setup, run, **request)
        assert response.status_code == 422 and response.json()["rule_id"] == "api.invalid_event_position", request
    ahead, _ = stream(setup, run, params={"after": "7"})
    assert ahead.status_code == 422 and ahead.json()["rule_id"] == "api.event_position_ahead"
    stranger = setup.api.member(f"s-{uuid4().hex[:8]}", setup.api.workspace("other"), "analyst")
    foreign, _ = stream(setup, run, client=setup.client(stranger))
    assert foreign.status_code == 404 and foreign.json()["rule_id"] == "api.run_not_found"
    unknown, _ = stream(setup, str(uuid4()))
    assert unknown.status_code == 404


def test_a_retention_gap_requires_resynchronization(setup: Setup) -> None:
    run = setup.started_run()
    setup.api.worker(setup.catalog).run_once()
    with setup.api.db.superuser() as conn:  # a future purge, simulated: rows up to 2 retired, the floor moved
        conn.execute("DELETE FROM app.run_events WHERE run_id = %s AND sequence <= 2", (UUID(run),))
        conn.execute("UPDATE app.runs SET event_retention_floor = 2 WHERE id = %s", (UUID(run),))
    gap_requests: list[dict[str, Any]] = [{"params": {"after": "1"}}, {}, {"headers": {"Last-Event-ID": "0"}}]
    for request in gap_requests:
        response, _ = stream(setup, run, **request)
        assert response.status_code == 409 and response.json()["rule_id"] == "api.event_gap_resync_required"
    assert ids(stream(setup, run, params={"after": "2"})[1]) == [3, 4, 5, 6]  # the floor itself is valid
    # The high-water mark, not MAX(sequence), allocates: a new event never reuses a retired sequence.
    assert setup.api.scalar("SELECT event_highwater FROM app.runs WHERE id = %s", UUID(run)) == 6


def test_heartbeats_and_the_lifetime_limit_carry_no_event_id(setup: Setup) -> None:
    run = setup.started_run()  # queued, never processed: nothing more arrives
    started = time.monotonic()
    _, collected = stream(setup, run)
    elapsed = time.monotonic() - started
    assert ids(collected) == [1]
    assert any(f.comment == "heartbeat" for f in collected)
    assert collected[-1].event == "reconnect" and collected[-1].id is None
    assert all(f.id is None for f in collected if f.event in ("reconnect", "resync") or f.comment)
    assert STREAM.max_lifetime <= elapsed < STREAM.max_lifetime + 5


def read_in_background(setup: Setup, run_id: str, client: httpx.Client) -> tuple[threading.Thread, list[Frame],
                                                                                   threading.Event]:
    collected: list[Frame] = []
    first = threading.Event()

    def reader() -> None:
        with client, client.stream("GET", f"/api/v1/runs/{run_id}/events") as response:
            for frame_ in frames(response.iter_lines()):
                collected.append(frame_)
                if frame_.id is not None:
                    first.set()

    thread = threading.Thread(target=reader)
    thread.start()
    return thread, collected, first


def test_a_membership_revoked_midstream_ends_the_stream_without_more_events(setup: Setup) -> None:
    who = f"subject-{uuid4().hex[:10]}"
    viewer = setup.api.member(who, setup.workspace, "auditor")
    run = setup.started_run()
    thread, collected, first = read_in_background(setup, run, setup.client(viewer))
    assert first.wait(10)
    membership = setup.api.rows("SELECT id FROM identity.memberships WHERE principal_id = %s",
                                setup.api.principal(who))[0][0]
    with workspace_transaction(setup.api.runtime.app_engine, setup.workspace) as conn:
        assert repo.revoke_membership(conn, membership, setup.api.clock.now())
    setup.api.worker(setup.catalog).run_once()  # new events now exist
    thread.join(10)
    assert not thread.is_alive()
    assert ids(collected) == [1]  # nothing after the revocation, and no resync/reconnect frame either
    assert not any(f.event for f in collected if f.id is None)


def test_a_logout_midstream_ends_the_stream(setup: Setup) -> None:
    viewer = setup.api.member(f"subject-{uuid4().hex[:10]}", setup.workspace, "auditor")
    run = setup.started_run()
    thread, collected, first = read_in_background(setup, run, setup.client(viewer))
    assert first.wait(10)
    csrf = viewer.cookies.get(case_api.CSRF_COOKIE) or ""
    logout = viewer.post("/api/v1/auth/logout", headers={"Origin": case_api.ORIGIN, "X-CSRF-Token": csrf})
    assert logout.status_code == 204
    setup.api.worker(setup.catalog).run_once()
    thread.join(10)
    assert not thread.is_alive() and ids(collected) == [1]


def test_an_undecodable_stored_event_keeps_its_place(setup: Setup) -> None:
    """A row in the shape the T06 repository test stores (`{"current": "running"}`, no type or previous state) is
    sent as `event: unsupported` with only its identifiers; nothing is invented, and later events still follow."""
    run = setup.started_run()
    with workspace_transaction(setup.api.runtime.app_engine, setup.workspace) as conn:
        repo.append_run_event(conn, event_id=uuid4(), workspace_id=setup.workspace, run_id=UUID(run),
                              event_type="run.state_changed", schema_version="policyops.run-event/v1",
                              payload_json='{"current": "running"}', occurred_at=setup.api.clock.now())
        repo.append_run_event(conn, event_id=uuid4(), workspace_id=setup.workspace, run_id=UUID(run),
                              event_type="run.state_changed", schema_version="policyops.run-event/v9",
                              payload_json='{"type": "run.state_changed", "previous": null, "current": "queued"}',
                              occurred_at=setup.api.clock.now())
    setup.api.worker(setup.catalog).run_once()
    _, collected = stream(setup, run)
    by_id = {int(f.id): f for f in collected if f.id}
    assert sorted(by_id) == list(range(1, 9))  # queued, the two stored rows, running, 3 steps, succeeded
    for sequence, schema in ((2, "policyops.run-event/v1"), (3, "policyops.run-event/v9")):
        assert by_id[sequence].event == "unsupported"
        data = json.loads(by_id[sequence].data or "")
        assert set(data) == {"event_id", "sequence", "event_type", "schema_version"}
        assert (data["sequence"], data["event_type"], data["schema_version"]) == (
            sequence, "run.state_changed", schema)
    assert by_id[8].event == "run.state_changed"


@pytest.mark.parametrize(("poll", "stall"), [(0.05, True), (10.0, True), (10.0, False)])
def test_the_served_app_cuts_off_a_stalled_event_stream(fresh: AppDatabase, poll: float, stall: bool) -> None:
    """The actual composed app (all middleware, real PostgreSQL), with any allowed poll interval, even one longer
    than the lifetime: the response ends by max_lifetime + delivery_grace whether the client keeps reading or
    stops reading after the first frame (a stalled send), and no database connection stays checked out."""
    import asyncio

    executor = ScriptedExecutor(events=3)
    built = scripted_spec(executor)
    stream = StreamSettings(poll_interval=poll, heartbeat_interval=max(poll, 0.2), max_lifetime=1.0, batch=3,
                            delivery_grace=0.1)
    api = case_api.build(fresh, catalog=RuntimeCatalog.of([built], default=built.spec_id), stream=stream)
    workspace = api.workspace("stall")
    browser = api.member(f"subject-{uuid4().hex[:10]}", workspace, "analyst")
    case = api.create(browser).json()["case_id"]
    run = api.start_run(browser, case, '"1"').json()["run_id"]
    cookie = "; ".join(f"{name}={value}" for name, value in browser.cookies.items())
    sent: list[dict[str, Any]] = []
    received: list[int] = []

    async def receive() -> dict[str, Any]:
        if not received:  # the (empty) GET body, as a real server delivers it; then nothing more arrives
            received.append(1)
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if stall and message["type"] == "http.response.body":
            await asyncio.sleep(3600)  # stalled: the client never reads

    path = f"/api/v1/runs/{run}/events"
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": "GET", "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": [(b"host", b"127.0.0.1:8000"), (b"cookie", cookie.encode())],
             "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8000)}

    async def drive() -> float:
        started = time.monotonic()
        await asyncio.wait_for(api.app(scope, receive, send), timeout=15)
        return time.monotonic() - started

    elapsed = asyncio.run(drive())
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 200
    assert 0.9 <= elapsed < 1.1 + 0.5  # the deadline plus scheduling slack, whatever the poll interval
    time.sleep(0.5)  # the generator's thread finishes its current poll step
    assert cast(Any, api.runtime.app_engine.pool).checkedout() == 0  # a QueuePool


@pytest.mark.parametrize("slow", ["preflight snapshot", "initial session check"])
def test_pre_header_work_is_cut_off_at_the_connection_deadline(fresh: AppDatabase, slow: str) -> None:
    """A slow database query before the response headers (the preflight snapshot, or the initial session/membership
    check) must not hold the request past max_lifetime + delivery_grace: the request ends without headers, and the
    abandoned query finishes later and returns its pool connection."""
    import asyncio

    from sqlalchemy import text

    from policyops.persistence import runs as store

    executor = ScriptedExecutor()
    built = scripted_spec(executor)
    stream = StreamSettings(poll_interval=0.05, heartbeat_interval=0.2, max_lifetime=1.0, delivery_grace=0.1)
    api = case_api.build(fresh, catalog=RuntimeCatalog.of([built], default=built.spec_id), stream=stream)
    workspace = api.workspace("preheader")
    browser = api.member(f"subject-{uuid4().hex[:10]}", workspace, "analyst")
    run = api.start_run(browser, api.create(browser).json()["case_id"], '"1"').json()["run_id"]
    cookie = "; ".join(f"{name}={value}" for name, value in browser.cookies.items())
    slow_done = threading.Event()

    def sleep_in(connection: Any) -> None:
        connection.execute(text("SET LOCAL statement_timeout = '4s'"))
        connection.execute(text("SELECT pg_sleep(2.5)"))
        slow_done.set()

    if slow == "preflight snapshot":
        real_events = store.events_after
        first = [True]

        def slow_events(connection: Any, run_: Any, after: int, limit: int) -> Any:
            if first[0]:
                first[0] = False
                sleep_in(connection)
            return real_events(connection, run_, after, limit)

        patched: Any = pytest.MonkeyPatch()
        patched.setattr(store, "events_after", slow_events)
        engine = api.runtime.app_engine
    else:
        from policyops.persistence.database import transaction

        service = api.runtime.service
        real_resolve = service.resolve

        def slow_resolve(cookie_: Any) -> Any:
            with transaction(service.auth_engine) as connection:
                sleep_in(connection)
            return real_resolve(cookie_)

        patched = pytest.MonkeyPatch()
        patched.setattr(service, "resolve", slow_resolve)
        engine = service.auth_engine
    sent: list[dict[str, Any]] = []
    received: list[int] = []

    async def receive() -> dict[str, Any]:
        if not received:
            received.append(1)
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    path = f"/api/v1/runs/{run}/events"
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": "GET", "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": [(b"host", b"127.0.0.1:8000"), (b"cookie", cookie.encode())],
             "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8000)}

    async def drive() -> float:
        started = time.monotonic()
        await asyncio.wait_for(api.app(scope, receive, send), timeout=15)
        return time.monotonic() - started

    try:
        elapsed = asyncio.run(drive())
        assert elapsed < 1.1 + 0.5, elapsed  # the connection deadline, not the 2.5 s query
        assert not slow_done.is_set()  # the response ended while the query was still running
        assert not any(m["type"] == "http.response.start" for m in sent)  # cut off before any headers
        assert slow_done.wait(10)  # the abandoned query finishes ...
        deadline = time.monotonic() + 10
        while cast(Any, engine.pool).checkedout() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert cast(Any, engine.pool).checkedout() == 0  # ... and its connection is back in the pool
    finally:
        patched.undo()
    assert api.run(browser, run).status_code == 200  # the API is still usable


def test_the_events_route_keeps_its_refusal_order(setup: Setup) -> None:
    """Authorization still precedes path/query validation on the events route (now an async dependency)."""
    with httpx.Client(base_url=setup.url, timeout=15) as anonymous:
        response = anonymous.get("/api/v1/runs/not-a-uuid/events", params={"after": "x"})
    openapi_check.check_response(response, "GET", EVENTS)
    assert response.status_code == 401 and response.json()["rule_id"] == "auth.session"
    with setup.client() as member:
        response = member.get("/api/v1/runs/not-a-uuid/events")
    openapi_check.check_response(response, "GET", EVENTS)
    assert response.status_code == 422 and response.json()["rule_id"] == "api.invalid_input"
