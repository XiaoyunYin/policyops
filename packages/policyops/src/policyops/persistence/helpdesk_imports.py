"""Import checkpoints and typed, redacted outcomes under the app runtime role."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import Connection, text

from policyops.domain.helpdesk_rules import ProjectionReason, RejectReason
from policyops.persistence.database import StaleVersion


OutcomeKind = Literal["accepted", "updated", "duplicate", "skipped_stale", "quarantined", "rejected"]
OutcomeReason = ProjectionReason | RejectReason | Literal["case_created", "snapshot_advanced", "same_snapshot",
                                                         "older_snapshot"]


@dataclass(frozen=True)
class ImportKey:
    workspace_id: UUID
    connection_id: str
    format_version: int
    file_sha256: str


@dataclass(frozen=True)
class Checkpoint:
    id: UUID
    destination_sha256: str
    mapping_sha256: str
    exported_at: datetime
    records_total: int
    next_record: int
    state: Literal["running", "completed"]
    version: int


@dataclass(frozen=True)
class Outcome:
    record_no: int
    ticket_id: int | None
    disposition: OutcomeKind
    reason: OutcomeReason


def try_lock_connection(connection: Connection, key: ImportKey) -> bool:
    lock = f"helpdesk-import:{key.workspace_id}:{key.connection_id}"
    return connection.execute(text("SELECT pg_try_advisory_lock(hashtextextended(:key, 0))"),
                              {"key": lock}).scalar_one() is True


def checkpoint(connection: Connection, key: ImportKey) -> Checkpoint | None:
    row = connection.execute(text("""
        SELECT id, destination_sha256, mapping_sha256, exported_at, records_total, next_record, state, version
        FROM app.helpdesk_imports
        WHERE workspace_id = :workspace_id AND connection_id = :connection_id
          AND format_version = :format_version AND file_sha256 = :file_sha256
    """), vars(key)).mappings().one_or_none()
    return None if row is None else Checkpoint(**row)


def create_run(connection: Connection, key: ImportKey, *, destination: str, mapping: str,
               exported_at: datetime, total: int) -> Checkpoint:
    state: Literal["running", "completed"] = "running" if total else "completed"
    run = Checkpoint(uuid4(), destination, mapping, exported_at, total, 0, state, 1)
    connection.execute(text("""
        INSERT INTO app.helpdesk_imports (id, workspace_id, connection_id, format_version, file_sha256,
            destination_sha256, mapping_sha256, exported_at, records_total, state)
        VALUES (:id, :workspace_id, :connection_id, :format_version, :file_sha256,
            :destination_sha256, :mapping_sha256, :exported_at, :records_total, :state)
    """), vars(key) | vars(run))
    return run


def save_outcome(connection: Connection, workspace: UUID, run_id: UUID, outcome: Outcome, sha256: str) -> None:
    connection.execute(text("""
        INSERT INTO app.helpdesk_import_records
            (workspace_id, import_id, record_no, ticket_id, record_sha256, disposition, reason)
        VALUES (:workspace, :run, :record_no, :ticket_id, :sha, :disposition, :reason)
    """), {"workspace": workspace, "run": run_id, "sha": sha256} | vars(outcome))


def advance(connection: Connection, workspace: UUID, run: Checkpoint, outcomes: list[Outcome]) -> Checkpoint:
    counts = Counter(outcome.disposition for outcome in outcomes)
    row = connection.execute(text("""
        UPDATE app.helpdesk_imports
        SET next_record = :next, accepted = accepted + :accepted, updated = updated + :updated,
            duplicate = duplicate + :duplicate, skipped_stale = skipped_stale + :skipped_stale,
            quarantined = quarantined + :quarantined, rejected = rejected + :rejected, version = version + 1,
            state = CASE WHEN :next = records_total THEN 'completed' ELSE 'running' END
        WHERE workspace_id = :workspace AND id = :id AND version = :version
          AND next_record = :observed AND state = 'running'
        RETURNING id, destination_sha256, mapping_sha256, exported_at, records_total, next_record, state, version
    """), {"next": run.next_record + len(outcomes), "workspace": workspace, "id": run.id, "version": run.version,
           "observed": run.next_record, "accepted": counts["accepted"], "updated": counts["updated"],
           "duplicate": counts["duplicate"], "skipped_stale": counts["skipped_stale"],
           "quarantined": counts["quarantined"], "rejected": counts["rejected"]}).mappings().one_or_none()
    if row is None:
        raise StaleVersion("help desk import checkpoint changed")
    return Checkpoint(**row)


def report(connection: Connection, workspace: UUID, run: Checkpoint) -> tuple[Outcome, ...]:
    rows = connection.execute(text("""
        SELECT record_no, ticket_id, disposition, reason
        FROM app.helpdesk_import_records
        WHERE workspace_id = :workspace AND import_id = :run AND record_no <= :committed
        ORDER BY record_no
    """), {"workspace": workspace, "run": run.id, "committed": run.next_record}).mappings()
    return tuple(Outcome(**row) for row in rows)
