"""Run routes (T09), under /api/v1.

* `POST /cases/{id}/runs`: start a workbench run (`Idempotency-Key`, strong case `If-Match`). The response is 202
  Accepted with the queued run, its `ETag` and `Location`. It is 503 `runtime.unconfigured` while no run runtime
  is installed, and 409 `api.run_active` while the case already has an active run.
* `GET /runs/{id}`: the run, with its version as a strong `ETag`.
* `POST /runs/{id}/cancel`: request cancellation (`Idempotency-Key`; no version precondition, as it acts on the
  current state). A terminal run is returned unchanged.
* `GET /runs/{id}/events`: server-sent events from the durable, ordered run events.

The event stream:
- **Frames.** Each event is `id: <sequence>`, `event: <payload type>`, `data: <EventEnvelope JSON>`. A stored event
  this version cannot decode (an unknown schema version, or a payload that is not a valid typed event of its
  stored type, such as rows from before typed events) is sent in its place as `event: unsupported` with only its
  ID, sequence, stored type and schema version: its position is kept and its content is never guessed. Control
  frames carry no `id`, so they never move the client's last event ID: the `: heartbeat` comment, `event: resync`
  (the client's position is no longer retained) and `event: reconnect` (the maximum stream lifetime was reached).
- **Start position.** `Last-Event-ID`, which a reconnecting client sends, takes precedence over `?after=`, the
  initial position, and only the selected value is validated (an `after` left over in a reconnect URL is ignored
  when a valid header is present). The value is digits only (0 means from the start, which is also the default).
- **Refused before any headers are sent.** A malformed position is 422 `api.invalid_event_position`. A position
  beyond the run's high-water mark is 422 `api.event_position_ahead`. A position below its retention floor (the
  last retired sequence) is 409 `api.event_gap_resync_required`.
- **Cancellation.** The initial authorization (an async dependency) and preflight snapshot, like every later poll,
  run in worker threads that a cancellation (the delivery deadline, a disconnect) abandons rather than awaits, so
  `StreamDeadline` can end the request even before headers are sent. An abandoned query still finishes and ends its
  own transaction.
- **Each poll.** The session and the current membership (VIEW_CASE in the same workspace) are checked again, then
  the run's bounds, state and a bounded batch of events are read in one short transaction, which closes before
  anything is yielded. A revoked session or membership, or a run that is no longer visible, ends the stream with
  no further data.
- **End.** The stream ends after a terminal run's last event has been sent, which is only possible once that event
  is committed, or at the lifetime limit, which is checked before every event, with `reconnect`. Independently,
  `StreamDeadline` cuts the whole response off at `max_lifetime + delivery_grace`, a send stalled by a slow
  client included.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from functools import partial
import json
import re
import time
from typing import Annotated, Literal
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import Engine
from starlette.types import ASGIApp, Receive, Scope, Send

from policyops.api import docs
from policyops.api.auth import NO_STORE, AuthRuntime, Model, Runtime, require_action
from policyops.api.cases import WRITE_HEADERS, expected_version, idempotency_key, view, written
from policyops.auth.service import AuthError, Authorized
from policyops.domain.roles import Action
from policyops.persistence.runs import UnsupportedEvent
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, UnsafeTestHook, require_test_environment
from policyops.runtime.spec import UNCONFIGURED, RuntimeCatalog
from policyops.services.runs import RunService, RunView, etag
from policyops_contracts.clock import Clock
from policyops_contracts.errors import ErrorCode


POSITION = re.compile(r"[0-9]{1,19}")


@dataclass(frozen=True)
class StreamSettings:
    """Server-side bounds of one event stream (never chosen by the client)."""

    poll_interval: float = 1.0
    heartbeat_interval: float = 15.0
    max_lifetime: float = 300.0
    batch: int = 100
    # Extra time for the final frames to be delivered; `StreamDeadline` ends the whole response (including a send
    # stalled by a slow client) at max_lifetime + delivery_grace.
    delivery_grace: float = 2.0

    def __post_init__(self) -> None:
        if not 0.01 <= self.poll_interval <= 10 or not self.poll_interval <= self.heartbeat_interval <= 60:
            raise ValueError("poll interval 0.01-10 s and heartbeat interval from the poll interval up to 60 s")
        if not 1 <= self.max_lifetime <= 3600 or not 1 <= self.batch <= 500:
            raise ValueError("lifetime 1-3600 s and batch 1-500")
        if not 0.1 <= self.delivery_grace <= 30:
            raise ValueError("delivery grace 0.1-30 s")

    @property
    def connection_deadline(self) -> float:
        return self.max_lifetime + self.delivery_grace


@dataclass(frozen=True)
class RunsRuntime:
    service: RunService
    stream: StreamSettings


def build_runs_runtime(*, env: str, app_engine: Engine, ledger_clock: Clock, clock: LeaseClock | None = None,
                       catalog: RuntimeCatalog = UNCONFIGURED, stream: StreamSettings | None = None) -> RunsRuntime:
    """Wire the run API. Production uses the database clock and, until T21 installs a runtime, an empty catalog;
    test-only clocks and executors are refused outside `env == "test"`."""
    lease_clock = clock or DatabaseLeaseClock()
    require_test_environment(lease_clock, env)
    if catalog.test_only and env != "test":
        raise UnsafeTestHook("a test-only runtime catalog is only allowed when POLICYOPS_ENV=test")
    service = RunService(app_engine=app_engine, clock=lease_clock, catalog=catalog, ledger_clock=ledger_clock)
    return RunsRuntime(service=service, stream=stream or StreamSettings())


EVENTS_PATH = re.compile(r"/api/v1/runs/[^/]+/events")


class StreamDeadline:
    """Pure ASGI middleware, installed outermost: an event-stream request (the whole request, from the initial
    authorization and preflight snapshot before any headers, through every inner middleware, to the last frame) is
    cancelled at the stream's connection deadline, `max_lifetime + delivery_grace`. That also ends a send stalled by
    a client that stops reading. The async producer is cancelled at whatever it awaits; a database query already
    running in its worker thread is abandoned, finishes on its own and ends the short transaction it owns (no
    transaction spans an await or a yield). The response is cut off with no further frame, so no event ID is
    invented or advanced; the client reconnects from its last received ID. Cutting off before the headers is
    observed at the ASGI level (no response start is sent); what the HTTP client then sees depends on the server
    and has not been verified here."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        runs = getattr(getattr(scope.get("app"), "state", None), "runs", None) if scope["type"] == "http" else None
        if runs is None or not EVENTS_PATH.fullmatch(scope["path"]):
            await self.app(scope, receive, send)
            return
        with anyio.move_on_after(runs.stream.connection_deadline):
            await self.app(scope, receive, send)


def runs_runtime(request: Request) -> RunsRuntime:
    value: RunsRuntime = request.app.state.runs
    return value


Runs = Annotated[RunsRuntime, Depends(runs_runtime)]


async def stream_viewer(request: Request, auth: Runtime) -> Authorized:
    """The event stream's authorization (VIEW_CASE, the same rules as `require_action`). It is an async dependency
    whose session/membership queries run in a worker thread that a cancellation abandons. A synchronous dependency
    would run in a thread the request must wait for, so the delivery deadline could not end the request before
    the response headers. It still runs before path/query validation errors are raised (401/403 first)."""
    cookie = request.cookies.get(auth.settings.session_cookie)
    return await anyio.to_thread.run_sync(
        lambda: auth.service.authorize(auth.service.resolve(cookie), Action.VIEW_CASE), abandon_on_cancel=True)


class StartRunIn(Model):
    mode: Literal["workbench"]


class EventStreamResponse(StreamingResponse):
    media_type = "text/event-stream"


def invalid_position() -> AuthError:
    return AuthError(422, ErrorCode.INVALID_INPUT, "The event position is not valid.", "api.invalid_event_position")


def start_position(request: Request, after: str | None) -> int:
    values = request.headers.getlist("last-event-id")
    if len(values) > 1:
        raise invalid_position()
    raw = values[0] if values else after if after is not None else "0"
    if not POSITION.fullmatch(raw):
        raise invalid_position()
    return int(raw)


def frame(sequence: int, event: str, data: str) -> bytes:
    return f"id: {sequence}\nevent: {event}\ndata: {data}\n\n".encode()


def control(event: str) -> bytes:
    return f"event: {event}\ndata: {{}}\n\n".encode()


LOCATION = {"Location": {"description": "URL of the run.", "schema": {"type": "string"}}}
LAST_EVENT_ID = {"name": "Last-Event-ID", "in": "header", "required": False,
                 "description": "Reconnect position (the last received event id); takes precedence over `after`.",
                 "schema": {"type": "string", "pattern": "^[0-9]{1,19}$"}}
STREAM_DESCRIPTION = ("Server-sent events: `id: <sequence>`, `event: <payload type>`, `data: <EventEnvelope JSON>` "
                      "per event (`event: unsupported` with only identifiers for a stored event this version cannot "
                      "decode); control frames (`: heartbeat`, `event: resync`, `event: reconnect`) have no id.")


def build_router() -> APIRouter:
    router = APIRouter()

    @router.post("/cases/{case_id}/runs", status_code=202, response_model=RunView,
                 **docs.operation(csrf=True, headers=[docs.IDEMPOTENCY_KEY, docs.IF_MATCH],
                                  errors=(401, 403, 404, 409, 422, 428, 503),
                                  success={202: {"description": "Queued (or the replayed original).",
                                                 "headers": {**WRITE_HEADERS, **LOCATION}}}))
    def start_run(case_id: UUID, request: Request, body: StartRunIn,
                  authorized: Annotated[Authorized, Depends(require_action(Action.START_RUN))],
                  runs: Runs) -> Response:
        del body  # the only browser mode; validated so the intent is explicit
        key, version = idempotency_key(request), expected_version(request)
        result = runs.service.start(authorized, key=key, case_id=case_id, expected_version=version)
        return written(result, location=f"/api/v1/runs/{result.run_id}")

    @router.get("/runs/{run_id}", response_model=RunView,
                **docs.operation(session=True, errors=(401, 403, 404, 422),
                                 success={200: {"description": "The run.", "headers": {"ETag": docs.ETAG_HEADER}}}))
    def get_run(run_id: UUID, authorized: Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))],
                runs: Runs) -> Response:
        run = runs.service.get_run(authorized, run_id)
        return view(run, headers={"ETag": etag(run.version)})

    @router.post("/runs/{run_id}/cancel", response_model=RunView,
                 **docs.operation(csrf=True, headers=[docs.IDEMPOTENCY_KEY], errors=(401, 403, 404, 409, 422),
                                  success={200: {"description": "The run after the request (or the replayed "
                                                 "original); a terminal run is unchanged.",
                                                 "headers": WRITE_HEADERS}}))
    def cancel_run(run_id: UUID, request: Request,
                   authorized: Annotated[Authorized, Depends(require_action(Action.CANCEL_RUN))],
                   runs: Runs) -> Response:
        return written(runs.service.cancel(authorized, key=idempotency_key(request), run_id=run_id))

    @router.get("/runs/{run_id}/events", response_class=EventStreamResponse,
                **docs.operation(session=True, headers=[LAST_EVENT_ID], errors=(401, 403, 404, 409, 422),
                                 streaming=True,
                                 success={200: {"description": STREAM_DESCRIPTION,
                                                "content": {"text/event-stream": {"schema": {"type": "string"}}}}}))
    async def run_events(run_id: UUID, request: Request, authorized: Annotated[Authorized, Depends(stream_viewer)],
                         auth: Runtime, runs: Runs, after: Annotated[str | None, Query(
                             description="Initial position (digits; 0 = from the start). Ignored when Last-Event-ID "
                                         "is sent; only the selected position is validated.")] = None) -> Response:
        position = start_position(request, after)
        # Abandoned, not awaited, on cancellation (the delivery deadline): the snapshot ends its own transaction.
        snapshot = await anyio.to_thread.run_sync(
            partial(runs.service.snapshot, authorized, run_id, after=0, limit=1), abandon_on_cancel=True)
        if snapshot is None:
            raise AuthError(404, ErrorCode.NOT_FOUND, "No such run.", "api.run_not_found")
        if position > snapshot.highwater:
            raise AuthError(422, ErrorCode.INVALID_INPUT, "The event position is ahead of this run.",
                            "api.event_position_ahead")
        if position < snapshot.floor:
            raise AuthError(409, ErrorCode.CONFLICT, "Events before this position are no longer retained; reload "
                            "the run and resynchronize.", "api.event_gap_resync_required")
        cookie = request.cookies.get(auth.settings.session_cookie)
        stream = _stream(auth, runs, authorized.workspace_id, run_id, cookie, position)
        return EventStreamResponse(stream, headers={**NO_STORE, "X-Accel-Buffering": "no"})

    return router


async def _stream(auth: AuthRuntime, runs: RunsRuntime, workspace_id: UUID, run_id: UUID, cookie: str | None,
                  position: int) -> AsyncIterator[bytes]:
    """The event stream as an async generator, so cancellation (the delivery deadline, a disconnect) is honoured at
    every wait. The synchronous session/membership check and database poll run in worker threads that a
    cancellation abandons instead of awaiting: such a poll still ends its own short transaction and returns its
    connection. The idle wait is a cancellable sleep, never longer than the remaining lifetime."""
    settings = runs.stream
    service = auth.service
    started = last_beat = time.monotonic()
    last = position

    def remaining() -> float:
        return settings.max_lifetime - (time.monotonic() - started)

    while True:
        try:  # the current session and membership, on every poll
            authorized = await anyio.to_thread.run_sync(
                lambda: service.authorize(service.resolve(cookie), Action.VIEW_CASE), abandon_on_cancel=True)
        except AuthError:
            return
        if authorized.workspace_id != workspace_id:
            return
        snapshot = await anyio.to_thread.run_sync(
            partial(runs.service.snapshot, authorized, run_id, after=last, limit=settings.batch),
            abandon_on_cancel=True)
        if snapshot is None:
            return
        if last < snapshot.floor:
            yield control("resync")
            return
        for event in snapshot.events:
            if remaining() <= 0:  # checked before every durable event
                yield control("reconnect")
                return
            if isinstance(event, UnsupportedEvent):  # kept in order with its id; content not reinterpreted
                yield frame(event.sequence, "unsupported", json.dumps({
                    "event_id": str(event.event_id), "sequence": event.sequence, "event_type": event.event_type,
                    "schema_version": event.schema_version}, separators=(",", ":")))
            else:
                yield frame(event.sequence, event.payload.type, event.model_dump_json())
            last = event.sequence
        if snapshot.terminal and last >= snapshot.highwater:
            return
        if remaining() <= 0:  # enforced even while every batch is full (a backlog)
            yield control("reconnect")
            return
        if len(snapshot.events) == settings.batch:
            continue  # more is waiting: no sleep
        now = time.monotonic()
        if now - last_beat >= settings.heartbeat_interval:
            yield b": heartbeat\n\n"
            last_beat = now
        await anyio.sleep(max(0.0, min(settings.poll_interval, remaining())))
