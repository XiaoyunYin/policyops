"""Local historical ticket import with atomic batches and a durable outcome ledger."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from time import monotonic, sleep
from uuid import uuid4

from sqlalchemy import Connection, Engine

from policyops.domain.helpdesk_rules import destination_digest, digest
from policyops.persistence import helpdesk_imports as store
from policyops.persistence import repositories as repo
from policyops.persistence.database import (
    DatabaseUnavailable,
    ImmutableRecord,
    TransactionOutcomeUnknown,
    connect_runtime,
    connection_transaction,
    workspace_transaction,
)
from policyops.persistence.helpdesk_imports import Checkpoint, ImportKey, Outcome
from policyops.persistence.records import AuditEvent
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.services.helpdesk_export import FORMAT_VERSION, ImportRefused, Record, VerifiedExport
from policyops.services.helpdesk_projection import project_snapshot
from policyops.settings import HelpdeskConnection


@dataclass(frozen=True)
class Report:
    file_sha256: str
    records_total: int
    next_record: int
    state: str
    counts: dict[str, int]
    outcomes: tuple[Outcome, ...]


@dataclass(frozen=True)
class TicketImport:
    engine: Engine
    config: HelpdeskConnection

    def __post_init__(self) -> None:
        if self.config.writeback_enabled:
            raise ImportRefused("writeback_enabled")

    def _key(self, sha256: str) -> ImportKey:
        return ImportKey(self.config.workspace_id, self.config.connection_id, FORMAT_VERSION, sha256)

    def _check_export_time(self, connection: Connection, exported_at: datetime) -> datetime:
        if exported_at.utcoffset() != timedelta(0):
            raise ImportRefused("invalid_exported_at")
        now = DatabaseLeaseClock().now(connection)
        if exported_at > now + timedelta(minutes=5):
            raise ImportRefused("exported_at_in_future")
        return now

    def plan(self, source: VerifiedExport, exported_at: datetime) -> dict[str, int | str]:
        with workspace_transaction(self.engine, self.config.workspace_id) as connection:
            self._check_export_time(connection, exported_at)
        counts: Counter[str] = Counter(record.reason or "valid"
                                       for batch in source.batches(exported_at) for record in batch)
        return {"file_sha256": source.sha256, "size_bytes": source.size, "records_total": source.records_total,
                "valid": counts.pop("valid", 0), **counts}

    def run(self, source: VerifiedExport, exported_at: datetime) -> Report:
        key = self._key(source.sha256)
        deadline = monotonic() + 30
        failures = 0
        while True:
            try:
                with connect_runtime(self.engine) as connection:
                    try:
                        with connection_transaction(connection, key.workspace_id):
                            locked = store.try_lock_connection(connection, key)
                        if locked:
                            return self._run_locked(connection, key, source, exported_at)
                    finally:
                        # The session lock survives COMMIT and ROLLBACK. Close the physical
                        # session so it can never escape into the pool or be reused after a disconnect.
                        connection.invalidate()
            except (TransactionOutcomeUnknown, DatabaseUnavailable):
                failures += 1
                if failures > 3:
                    raise
                # Acquire a new session and reread the durable cursor before replaying a batch.
                deadline = monotonic() + 30
            else:
                if monotonic() >= deadline:
                    raise ImportRefused("connection_busy")
            sleep(0.1)

    def _run_locked(self, connection: Connection, key: ImportKey, source: VerifiedExport,
                    exported_at: datetime) -> Report:
        destination = destination_digest(self.config.api_origin, self.config.integration_user_id)
        mapping = digest(json.dumps(sorted(self.config.allowed_group_ids), separators=(",", ":")).encode())
        with connection_transaction(connection, key.workspace_id):
            self._check_export_time(connection, exported_at)
            run = store.checkpoint(connection, key)
            if run is not None:
                pinned = (run.destination_sha256, run.mapping_sha256, run.exported_at, run.records_total)
                if pinned != (destination, mapping, exported_at, source.records_total):
                    raise ImportRefused("run_parameters_changed")
                if run.state == "completed":
                    return self._report(connection, key, run)

        start = run.next_record if run is not None else 0
        # An empty export still receives a completed run and its one audit.
        batches = source.batches(exported_at, start=start) if source.records_total else ((),)
        for batch in batches:
            with connection_transaction(connection, key.workspace_id):
                if run is None:
                    now = DatabaseLeaseClock().now(connection)
                    run = store.create_run(connection, key, destination=destination, mapping=mapping,
                                           exported_at=exported_at, total=source.records_total)
                    repo.append_audit(connection, AuditEvent(id=uuid4(), workspace_id=key.workspace_id,
                        actor_kind="system", actor_principal_id=None, action="helpdesk.import",
                        target_type="helpdesk_import", target_id=run.id, correlation_id=run.id, occurred_at=now))
                outcomes = []
                for record in batch:
                    with connection.begin_nested():
                        outcome = self._project(connection, record)
                        store.save_outcome(connection, key.workspace_id, run.id, outcome, record.sha256)
                        outcomes.append(outcome)
                if outcomes:
                    run = store.advance(connection, key.workspace_id, run, outcomes)
        if run is None or run.state != "completed":
            raise ImportRefused("invalid_checkpoint")
        with connection_transaction(connection, key.workspace_id):
            return self._report(connection, key, run)

    def _project(self, connection: Connection, record: Record) -> Outcome:
        number, identity = record.number, record.ticket_id
        if record.ticket is None:
            return Outcome(number, identity, "rejected", record.reason or "invalid_ticket")
        projection = project_snapshot(connection, self.config, record.ticket, record.articles,
                                      authorized_at=lambda: DatabaseLeaseClock().now(connection),
                                      reconcile_history=True)
        if projection is None:
            raise ImmutableRecord("import projection requires the database clock")
        decision = projection.decision
        if decision.reason is not None:
            return Outcome(number, identity, "quarantined", decision.reason)
        if decision.state == "stale":
            return Outcome(number, identity, "skipped_stale", "older_snapshot")
        if decision.state == "duplicate":
            return Outcome(number, identity, "duplicate", "same_snapshot")
        if projection.created_case_id is not None:
            return Outcome(number, identity, "accepted", "case_created")
        return Outcome(number, identity, "updated", "snapshot_advanced")

    def report(self, file_sha256: str) -> Report:
        key = self._key(file_sha256)
        with workspace_transaction(self.engine, key.workspace_id) as connection:
            run = store.checkpoint(connection, key)
            if run is None:
                raise ImportRefused("run_not_found")
            return self._report(connection, key, run)

    def _report(self, connection: Connection, key: ImportKey, run: Checkpoint) -> Report:
        outcomes = store.report(connection, key.workspace_id, run)
        counts = dict.fromkeys(("accepted", "updated", "duplicate", "skipped_stale", "quarantined", "rejected"), 0)
        counts.update(Counter(row.disposition for row in outcomes))
        return Report(key.file_sha256, run.records_total, run.next_record, run.state, counts, outcomes)
