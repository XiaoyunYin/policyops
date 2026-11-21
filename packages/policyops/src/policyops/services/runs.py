"""Run operations behind the HTTP API (T09): start, read, cancel and the event snapshots SSE streams.

- **Start** (`run.start`) takes the shared idempotent write path and then, under the case row lock, checks the
  current role (START_RUN) and the strong case version, and allows at most one active workbench run per case. It
  creates, atomically: the run bound to the case version and the frozen server runtime spec (its real digests and
  the initiating principal), its first event and outbox intent, its execute job and an audit row.
  - Without an installed runtime spec it is refused with 503 `runtime.unconfigured` before anything is written.
  - An idempotent replay of an earlier success still replays.
- **Cancel** (`run.cancel`) is a desired-state action without a version precondition. Under the run, then job,
  locks it moves an active run to `cancelled` and increments its generation, so any in-flight claim is fenced out.
  It finishes the job and appends the event, outbox intent and audit row together. Cancelling a terminal run is a
  no-op (no event or audit). Nothing remote exists to undo in this task; T19 adds reconciliation.

Run, job and event times come from the lease clock (the database in production); the ledger keeps the service clock.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine

from policyops.auth.service import AuthError, Authorized
from policyops.domain.roles import Action
from policyops.persistence import idempotency as idem
from policyops.persistence import repositories as repo
from policyops.persistence import runs as store
from policyops.persistence.database import workspace_transaction
from policyops.runtime.clock import LeaseClock
from policyops.runtime.spec import RuntimeCatalog
from policyops.services.writes import WriteResult, audit, idempotent_write, not_found, recheck
from policyops_contracts.base import WireModel
from policyops_contracts.clock import Clock
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import RunStateChanged
from policyops_contracts.scalars import PositiveVersion, Sha256Hex, UtcDatetime


class RunView(WireModel):
    run_id: UUID
    case_id: UUID
    case_version: PositiveVersion
    mode: Literal["workbench", "evaluation"]
    state: store.RunState
    initiated_by: UUID | None
    graph_sha256: Sha256Hex
    prompt_sha256: Sha256Hex
    config_sha256: Sha256Hex
    event_highwater: int
    created_at: UtcDatetime
    updated_at: UtcDatetime
    deadline_at: UtcDatetime | None
    version: PositiveVersion


def run_view(run: store.Run) -> RunView:
    return RunView(run_id=run.id, case_id=run.case_id, case_version=run.case_version, mode=run.mode,
                   state=run.state, initiated_by=run.initiated_by, graph_sha256=run.graph_sha256,
                   prompt_sha256=run.prompt_sha256, config_sha256=run.config_sha256,
                   event_highwater=run.event_highwater, created_at=run.created_at, updated_at=run.updated_at,
                   deadline_at=run.deadline_at, version=run.version)


def etag(version: int) -> str:
    return f'"{version}"'


@dataclass(frozen=True)
class EventSnapshot:
    """One poll: events after a position, read in the same transaction as the run's state and bounds."""

    events: list[store.StoredEvent]
    highwater: int
    floor: int
    terminal: bool


@dataclass
class RunService:
    app_engine: Engine
    clock: LeaseClock
    catalog: RuntimeCatalog
    ledger_clock: Clock  # the service clock, for ledger rows
    run_id_factory: Callable[[], UUID] = uuid4  # server composition only, never a request field

    def _ledger_now(self, _connection: Connection) -> datetime:
        return self.ledger_clock.now()

    # -- reads ------------------------------------------------------------------------------------------------

    def get_run(self, authorized: Authorized, run_id: UUID) -> RunView:
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            run = store.get_run(connection, run_id)
        if run is None:
            raise not_found("run")
        return run_view(run)

    def snapshot(self, authorized: Authorized, run_id: UUID, *, after: int, limit: int) -> EventSnapshot | None:
        """None when the run is not visible, or the principal no longer holds VIEW_CASE in this workspace."""
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            try:
                recheck(connection, authorized, Action.VIEW_CASE)
            except AuthError:
                return None
            run = store.get_run(connection, run_id)
            if run is None:
                return None
            events = store.events_after(connection, run, after, limit) if after >= run.event_retention_floor \
                else []
            return EventSnapshot(events=events, highwater=run.event_highwater, floor=run.event_retention_floor,
                                 terminal=run.terminal)

    # -- writes -----------------------------------------------------------------------------------------------

    def start(self, authorized: Authorized, *, key: str, case_id: UUID, expected_version: int) -> WriteResult:
        def mutate(connection: Connection) -> WriteResult:
            spec = self.catalog.start_spec
            if spec is None:
                raise AuthError(503, ErrorCode.UNAVAILABLE, "No run runtime is configured on this server.",
                                "runtime.unconfigured")
            case = repo.lock_case(connection, case_id)
            if case is None:
                raise not_found()
            recheck(connection, authorized, Action.START_RUN)  # after waiting for the case lock
            if case.version != expected_version:
                raise AuthError(409, ErrorCode.STALE_VERSION, "The case changed; reload it and retry.",
                                "api.stale_version")
            if store.active_workbench_run(connection, case_id) is not None:
                raise run_active()
            now = self.clock.now(connection)
            try:
                run = store.create_run(
                    connection, run_id=self.run_id_factory(), workspace_id=authorized.workspace_id, case_id=case_id,
                    case_version=case.version, graph_sha256=spec.graph_sha256, prompt_sha256=spec.prompt_sha256,
                    config_sha256=spec.config_sha256, initiated_by=authorized.session.principal_id,
                    deadline_at=now + spec.run_timeout, now=now)
            except store.ActiveRunExists:
                raise run_active() from None
            store.append_event(connection, run, RunStateChanged(previous=None, current="queued"), now)
            store.create_execute_job(connection, run, max_attempts=spec.max_attempts, now=now)
            audit(connection, authorized, action="run.started", target_type="run", target_id=run.id, before=None,
                  after=text_sha256(spec.config_sha256), occurred_at=now)
            created = store.get_run(connection, run.id)
            if created is None:
                raise RuntimeError("the run vanished inside its own transaction")
            return WriteResult(202, run_view(created).model_dump(mode="json"), etag(created.version), case_id, None,
                               replayed=False, run_id=created.id)

        return idempotent_write(
            self.app_engine, authorized, key=key, intent=idem.StartRunIntent(
                case_id=case_id, expected_version=expected_version, mode="workbench"),
            action=Action.START_RUN, visible=lambda c: repo.get_case(c, case_id) is not None, missing="case",
            mutate=mutate, now=self._ledger_now)

    def cancel(self, authorized: Authorized, *, key: str, run_id: UUID) -> WriteResult:
        def mutate(connection: Connection) -> WriteResult:
            run = store.get_run(connection, run_id, lock=True)  # run, then job
            if run is None:
                raise not_found("run")
            recheck(connection, authorized, Action.CANCEL_RUN)  # after waiting for the run lock
            if run.terminal:  # desired state already reached (or another terminal state): no-op
                return WriteResult(200, run_view(run).model_dump(mode="json"), etag(run.version), run.case_id,
                                   None, replayed=False, run_id=run.id)
            job = store.execute_job_of(connection, run.id, lock=True)
            now = self.clock.now(connection)
            cancelled = store.set_state(connection, run, "cancelled", now, bump_generation=True)
            store.append_event(connection, cancelled, RunStateChanged(previous=run.state, current="cancelled"), now)
            if job is not None and job.state in ("queued", "leased"):
                store.end_job(connection, job, state="done", now=now, error_code="run_cancelled")
            audit(connection, authorized, action="run.cancelled", target_type="run", target_id=run.id,
                  before=text_sha256(run.state), after=text_sha256("cancelled"), occurred_at=now)
            final = store.get_run(connection, run.id)
            if final is None:
                raise RuntimeError("the run vanished inside its own transaction")
            return WriteResult(200, run_view(final).model_dump(mode="json"), etag(final.version), run.case_id, None,
                               replayed=False, run_id=run.id)

        return idempotent_write(
            self.app_engine, authorized, key=key, intent=idem.CancelRunIntent(run_id=run_id),
            action=Action.CANCEL_RUN, visible=lambda c: store.get_run(c, run_id) is not None, missing="run",
            mutate=mutate, now=self._ledger_now)


def run_active() -> AuthError:
    return AuthError(409, ErrorCode.CONFLICT, "This case already has an active run.", "api.run_active")
