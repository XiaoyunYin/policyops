"""Runs, leased jobs, durable run events and the outbox (T09; schema from revision 0005).

All functions except `discover_*` run as the app runtime inside `workspace_transaction`, so RLS confines them to
one workspace. `discover_*` run as `policyops_worker_discovery`, which can read only job/outbox scheduling
metadata (IDs, workspace, state and times).

Lock order, everywhere: case → run → job → outbox rows. Claims use `SKIP LOCKED` on the run, then the job; every
worker mutation locks the run, then the job, and checks the claim's fence (`check_fence`); a heartbeat locks
only the job. No caller holds a transaction across an executor call, a sleep or an SSE yield.

Times come from the lease clock (`policyops.runtime.clock`), read in the same transaction **after** the locks a
decision depends on (`check_fence` and `heartbeat` take the clock for that reason), never before a wait.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from typing import Any, Literal
from uuid import UUID, uuid4

from psycopg import errors as pg_errors
from sqlalchemy import Connection, text
from sqlalchemy.exc import DBAPIError

from policyops.persistence import repositories as repo
from policyops.persistence.database import PersistenceError
from policyops.persistence.records import NewJob
from policyops.runtime.clock import LeaseClock
from policyops_contracts.base import WireModel
from policyops_contracts.events import EventEnvelope, EventPayload
from policyops_contracts.scalars import RunScope, UtcDatetime


RunState = Literal["queued", "running", "waiting_input", "waiting_approval", "reconciling", "succeeded", "failed",
                   "cancelled", "budget_exceeded"]
ACTIVE_STATES: frozenset[str] = frozenset({"queued", "running", "waiting_input", "waiting_approval", "reconciling"})
TERMINAL_STATES: frozenset[str] = frozenset({"succeeded", "failed", "cancelled", "budget_exceeded"})
EXECUTE_KIND = "run.execute"
EVENT_TOPIC = "run.event"
NOTIFY_CHANNEL = "policyops_run_events"
MAX_EVENT_PAGE = 500

RUN_COLUMNS = ("id, workspace_id, case_id, case_version, mode, graph_sha256, prompt_sha256, config_sha256, state, "
               "initiated_by, generation, event_highwater, event_retention_floor, deadline_at, created_at, "
               "updated_at, version")
JOB_COLUMNS = ("id, workspace_id, run_id, kind, state, claim_id, lease_owner, lease_expires_at, attempts, "
               "max_attempts, available_at, deadline_at, last_error_code, version")
# Fixed column lists only (no input): S608 does not apply.
INSERT_RUN = ("INSERT INTO app.runs (id, workspace_id, case_id, case_version, mode, graph_sha256, prompt_sha256, "  # noqa: S608
              "config_sha256, state, initiated_by, deadline_at, created_at, updated_at) VALUES (:id, :w, :c, :cv, "
              "'workbench', :g, :p, :cfg, 'queued', :by, :deadline, :now, :now) RETURNING " + RUN_COLUMNS)
UPDATE_STATE = ("UPDATE app.runs SET state = :state, updated_at = greatest(updated_at, :now), "  # noqa: S608
                "version = version + 1, "
                "generation = generation + :bump WHERE id = :id RETURNING " + RUN_COLUMNS)


class ActiveRunExists(PersistenceError):
    """The case already has an active workbench run."""


class Fenced(PersistenceError):
    """The claim is no longer current (reclaimed, expired, cancelled, past its deadline or finished)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Run(WireModel):
    id: UUID
    workspace_id: UUID
    case_id: UUID
    case_version: int
    mode: Literal["workbench", "evaluation"]
    graph_sha256: str
    prompt_sha256: str
    config_sha256: str
    state: RunState
    initiated_by: UUID | None
    generation: int
    event_highwater: int
    event_retention_floor: int
    deadline_at: UtcDatetime
    created_at: UtcDatetime
    updated_at: UtcDatetime
    version: int

    @property
    def scope(self) -> RunScope:
        return RunScope(workspace_id=self.workspace_id, case_id=self.case_id, run_id=self.id)

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES


class Job(WireModel):
    id: UUID
    workspace_id: UUID
    run_id: UUID
    kind: str
    state: Literal["queued", "leased", "done", "dead"]
    claim_id: UUID | None
    lease_owner: UUID | None
    lease_expires_at: UtcDatetime | None
    attempts: int
    max_attempts: int
    available_at: UtcDatetime
    deadline_at: UtcDatetime
    last_error_code: str | None
    version: int


@dataclass(frozen=True)
class ClaimToken:
    """What a worker holds for one claim; every later mutation is checked against it."""

    workspace_id: UUID
    run_id: UUID
    job_id: UUID
    claim_id: UUID
    owner: UUID
    generation: int
    attempt: int


def _run(row: Any) -> Run:
    return Run.model_validate(dict(row), strict=False)


def _job(row: Any) -> Job:
    return Job.model_validate(dict(row), strict=False)


# -- reads and locks --------------------------------------------------------------------------------------------

def get_run(connection: Connection, run_id: UUID, *, lock: bool = False, skip_locked: bool = False) -> Run | None:
    suffix = " FOR UPDATE SKIP LOCKED" if skip_locked else " FOR UPDATE" if lock else ""
    row = connection.execute(text(f"SELECT {RUN_COLUMNS} FROM app.runs WHERE id = :id{suffix}"),  # noqa: S608
                             {"id": run_id}).mappings().first()
    return _run(row) if row else None


def get_job(connection: Connection, job_id: UUID, *, lock: bool = False, skip_locked: bool = False) -> Job | None:
    suffix = " FOR UPDATE SKIP LOCKED" if skip_locked else " FOR UPDATE" if lock else ""
    row = connection.execute(text(f"SELECT {JOB_COLUMNS} FROM app.jobs WHERE id = :id{suffix}"),  # noqa: S608
                             {"id": job_id}).mappings().first()
    return _job(row) if row else None


def execute_job_of(connection: Connection, run_id: UUID, *, lock: bool = False) -> Job | None:
    suffix = " FOR UPDATE" if lock else ""
    row = connection.execute(text(f"SELECT {JOB_COLUMNS} FROM app.jobs WHERE run_id = :r AND kind = :k"  # noqa: S608
                                  f"{suffix}"), {"r": run_id, "k": EXECUTE_KIND}).mappings().first()
    return _job(row) if row else None


def active_workbench_run(connection: Connection, case_id: UUID) -> UUID | None:
    row = connection.execute(text("SELECT id FROM app.runs WHERE case_id = :c AND mode = 'workbench' "
                                  "AND state = ANY(:active)"), {"c": case_id, "active": sorted(ACTIVE_STATES)}).first()
    return row[0] if row else None


# -- creation ---------------------------------------------------------------------------------------------------

def create_run(connection: Connection, *, run_id: UUID, workspace_id: UUID, case_id: UUID, case_version: int,
               graph_sha256: str, prompt_sha256: str, config_sha256: str, initiated_by: UUID,
               deadline_at: datetime, now: datetime) -> Run:
    """Insert a queued workbench run (the caller holds the case lock). One active workbench run per case."""
    try:
        with connection.begin_nested():
            row = connection.execute(text(INSERT_RUN), {
                "id": run_id, "w": workspace_id, "c": case_id, "cv": case_version, "g": graph_sha256,
                "p": prompt_sha256, "cfg": config_sha256, "by": initiated_by, "deadline": deadline_at,
                "now": now}).mappings().one()
    except DBAPIError as exc:
        if isinstance(exc.orig, pg_errors.UniqueViolation) and "runs_one_active_workbench" in str(exc.orig):
            raise ActiveRunExists(f"case {case_id} already has an active workbench run") from exc
        raise
    return _run(row)


def create_execute_job(connection: Connection, run: Run, *, max_attempts: int, now: datetime) -> UUID:
    job_id, _created = repo.enqueue_job(connection, NewJob(
        id=uuid4(), workspace_id=run.workspace_id, run_id=run.id, dedupe_key=f"run:{run.id}:execute",
        kind=EXECUTE_KIND, run_generation=run.generation, max_attempts=max_attempts, available_at=now,
        deadline_at=run.deadline_at, created_at=now))
    return job_id


# -- events and outbox ------------------------------------------------------------------------------------------

def append_event(connection: Connection, run: Run, payload: EventPayload, now: datetime) -> EventEnvelope:
    """Append a typed event (sequence from the durable high-water mark, under the run lock) and, in the same
    transaction, its outbox publication intent."""
    event_id = uuid4()
    sequence = repo.append_run_event(
        connection, event_id=event_id, workspace_id=run.workspace_id, run_id=run.id, event_type=payload.type,
        schema_version="policyops.run-event/v1", payload_json=payload.model_dump_json(), occurred_at=now)
    envelope = EventEnvelope(event_id=event_id, scope=run.scope, sequence=sequence, occurred_at=now,
                             payload=payload)
    connection.execute(text(
        "INSERT INTO app.outbox_events (id, workspace_id, run_id, dedupe_key, topic, payload, created_at) VALUES "
        "(:id, :w, :r, :key, :topic, CAST(:payload AS jsonb), :now)"),
        {"id": uuid4(), "w": run.workspace_id, "r": run.id, "key": f"run-event:{event_id}", "topic": EVENT_TOPIC,
         "payload": json.dumps({"run_id": str(run.id), "sequence": sequence, "event_id": str(event_id)}),
         "now": now})
    return envelope


SUPPORTED_EVENT_SCHEMA = "policyops.run-event/v1"


@dataclass(frozen=True)
class UnsupportedEvent:
    """A stored event this version cannot decode: an unknown schema version, a type that disagrees with its
    payload, or a payload that is not a current typed event (for example rows written before typed events). Its
    position and identity are kept; its content is never relabelled, completed or guessed."""

    event_id: UUID
    sequence: int
    event_type: str
    schema_version: str


StoredEvent = EventEnvelope | UnsupportedEvent


def events_after(connection: Connection, run: Run, after: int, limit: int) -> list[StoredEvent]:
    """Stored events after a position, in sequence order. Each is decoded only if its schema version is supported
    and its payload is a valid typed event of the stored type; otherwise it is returned as `UnsupportedEvent`."""
    if not 1 <= limit <= MAX_EVENT_PAGE or after < 0:
        raise ValueError("limit out of range")
    rows = connection.execute(text(
        "SELECT id, sequence, event_type, schema_version, payload::text AS payload, occurred_at FROM app.run_events "
        "WHERE run_id = :r AND sequence > :after ORDER BY sequence LIMIT :limit"),
        {"r": run.id, "after": after, "limit": limit}).all()
    return [_decode(run, row) for row in rows]


def _decode(run: Run, row: Any) -> StoredEvent:
    unsupported = UnsupportedEvent(event_id=row.id, sequence=row.sequence, event_type=row.event_type,
                                   schema_version=row.schema_version)
    if row.schema_version != SUPPORTED_EVENT_SCHEMA:
        return unsupported
    try:
        envelope = EventEnvelope.model_validate_json(json.dumps({
            "schema_version": row.schema_version, "event_id": str(row.id), "scope": run.scope.model_dump(mode="json"),
            "sequence": row.sequence, "occurred_at": row.occurred_at.isoformat(), "payload": json.loads(row.payload)}))
    except ValueError:  # pydantic's ValidationError is a ValueError
        return unsupported
    return envelope if envelope.payload.type == row.event_type else unsupported


def set_state(connection: Connection, run: Run, state: RunState, now: datetime, *,
              bump_generation: bool = False) -> Run:
    """Change a locked run's state (and optionally fence out every current claim)."""
    row = connection.execute(text(UPDATE_STATE), {"state": state, "now": now, "bump": 1 if bump_generation else 0,
                                                  "id": run.id}).mappings().one()
    return _run(row)


# -- claims and fencing -----------------------------------------------------------------------------------------

def claim(connection: Connection, run: Run, job: Job, *, owner: UUID, lease: timedelta, now: datetime
          ) -> ClaimToken:
    """Lease a claimable job (the caller locked run, then job, and checked claimability): a new stable claim ID,
    attempts + 1, and a new run generation, which fences out any earlier claim."""
    claim_id = uuid4()
    updated = connection.execute(text(
        "UPDATE app.jobs SET state = 'leased', claim_id = :claim, lease_owner = :owner, lease_expires_at = :until, "
        "attempts = attempts + 1, version = version + 1, updated_at = greatest(updated_at, :now) WHERE id = :id "
        "RETURNING attempts"), {"claim": claim_id, "owner": owner, "until": now + lease, "now": now,
                                "id": job.id}).scalar_one()
    generation = connection.execute(text("UPDATE app.runs SET generation = generation + 1 WHERE id = :id "
                                         "RETURNING generation"), {"id": run.id}).scalar_one()
    return ClaimToken(workspace_id=run.workspace_id, run_id=run.id, job_id=job.id, claim_id=claim_id, owner=owner,
                      generation=int(generation), attempt=int(updated))


def claimable(job: Job, now: datetime) -> bool:
    if job.state == "queued":
        return job.available_at <= now
    return job.state == "leased" and job.lease_expires_at is not None and job.lease_expires_at <= now


def check_fence(connection: Connection, token: ClaimToken, clock: LeaseClock) -> tuple[Run, Job, datetime]:
    """Lock run, then job, read the clock (after any wait for those locks) and verify the claim is still current;
    raises `Fenced` with a typed reason. Returns the time the decision was made at."""
    run = get_run(connection, token.run_id, lock=True)
    job = get_job(connection, token.job_id, lock=True)
    now = clock.now(connection)
    if run is None or job is None:
        raise Fenced("missing")
    if job.state != "leased" or job.claim_id != token.claim_id or job.lease_owner != token.owner:
        raise Fenced("claim_lost")
    if run.generation != token.generation:
        raise Fenced("generation_changed")
    if job.lease_expires_at is None or job.lease_expires_at <= now:
        raise Fenced("lease_expired")
    if job.deadline_at <= now or run.deadline_at <= now:
        raise Fenced("deadline_exceeded")
    if run.terminal:
        raise Fenced("run_terminal")
    return run, job, now


def heartbeat(connection: Connection, token: ClaimToken, *, lease: timedelta, clock: LeaseClock) -> bool:
    """Extend the lease of a current, unexpired claim (job row lock only; the clock is read after it). The claim ID
    never changes, so the fence a worker holds stays valid; an expired lease cannot be revived."""
    if get_job(connection, token.job_id, lock=True) is None:
        return False
    now = clock.now(connection)
    row = connection.execute(text(
        "UPDATE app.jobs j SET lease_expires_at = least(:until, j.deadline_at), version = j.version + 1, "
        "updated_at = greatest(j.updated_at, :now) WHERE j.id = :id AND j.state = 'leased' AND j.claim_id = :claim "
        "AND j.lease_owner = :owner AND j.lease_expires_at > :now AND j.deadline_at > :now "
        "AND (SELECT r.generation FROM app.runs r WHERE r.id = j.run_id) = :generation RETURNING j.id"),
        {"until": now + lease, "now": now, "id": token.job_id, "claim": token.claim_id, "owner": token.owner,
         "generation": token.generation}).first()
    return row is not None


def end_job(connection: Connection, job: Job, *, state: Literal["queued", "done", "dead"], now: datetime,
            error_code: str | None = None, available_at: datetime | None = None) -> None:
    """Release (back to queued, with backoff), finish or dead-letter a locked job, clearing its lease."""
    connection.execute(text(
        "UPDATE app.jobs SET state = :state, claim_id = NULL, lease_owner = NULL, lease_expires_at = NULL, "
        "last_error_code = :code, available_at = coalesce(:available, available_at), version = version + 1, "
        "updated_at = greatest(updated_at, :now) WHERE id = :id"),
        {"state": state, "code": error_code, "available": available_at, "now": now, "id": job.id})


# -- discovery (worker discovery role) and dispatch ---------------------------------------------------------------

def discover_jobs(connection: Connection, now: datetime, limit: int) -> list[tuple[UUID, UUID]]:
    """(job, workspace) pairs that look claimable: due queued jobs, then expired leases. Only scheduling metadata
    is readable; the claim re-reads and re-checks everything under the app role."""
    rows = connection.execute(text(
        "SELECT id, workspace_id FROM app.jobs WHERE (state = 'queued' AND available_at <= :now) "
        "OR (state = 'leased' AND lease_expires_at <= :now) ORDER BY coalesce(lease_expires_at, available_at), id "
        "LIMIT :limit"), {"now": now, "limit": limit}).all()
    return [(row[0], row[1]) for row in rows]


def discover_outbox(connection: Connection, limit: int) -> list[UUID]:
    """Workspaces with undelivered run-event intents, oldest first. Only the topic this dispatcher publishes is
    considered, so rows of other topics (left undelivered for their own consumers) cannot starve it."""
    rows = connection.execute(text(
        "SELECT workspace_id FROM app.outbox_events WHERE delivered_at IS NULL AND topic = :topic "
        "GROUP BY workspace_id ORDER BY min(created_at) LIMIT :limit"), {"topic": EVENT_TOPIC, "limit": limit}).all()
    return [row[0] for row in rows]


def publish_outbox(connection: Connection, *, limit: int, clock: LeaseClock) -> int:
    """Publish up to `limit` undelivered run-event intents of the scoped workspace: one generic, empty `pg_notify`
    wake-up and `delivered_at` in this one transaction. The notification is sent exactly when the rows are marked
    (at commit); `delivered_at` means "publication committed", not that any client received it."""
    ids = connection.execute(text(
        "SELECT id FROM app.outbox_events WHERE delivered_at IS NULL AND topic = :topic ORDER BY created_at, id "
        "LIMIT :limit FOR UPDATE SKIP LOCKED"), {"topic": EVENT_TOPIC, "limit": limit}).scalars().all()
    if not ids:
        return 0
    now = clock.now(connection)
    # No run, tenant or sequence in the payload: every session of this database can LISTEN, so the wake-up says
    # only "something changed"; identical notifications in one transaction coalesce into one.
    connection.execute(text("SELECT pg_notify(:channel, '')"), {"channel": NOTIFY_CHANNEL})
    connection.execute(text("UPDATE app.outbox_events SET delivered_at = greatest(created_at, :now) "
                            "WHERE id = ANY(:ids)"), {"now": now, "ids": list(ids)})
    return len(ids)
