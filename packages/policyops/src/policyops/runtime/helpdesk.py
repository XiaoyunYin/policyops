"""Short workspace transactions around each leased help desk worker step."""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
import logging
from uuid import UUID, uuid4

import httpx
from sqlalchemy import Connection, Engine
from sqlalchemy.engine import RowMapping

from policyops.adapters.zammad_client import REJECTIONS, RemoteError, ZammadClient
from policyops.domain.helpdesk_rules import destination_digest, digest, note_body
from policyops.persistence import helpdesk as store
from policyops.persistence.database import (
    DatabaseUnavailable,
    SqlProfile,
    TransactionOutcomeUnknown,
    transaction,
    verify_runtime_role,
    workspace_transaction,
)
from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, UnsafeTestHook, require_test_environment
from policyops.services.helpdesk_inbound import apply_snapshot
from policyops.services.helpdesk_writeback import QUIESCENCE, Note, Result, backoff, deliver, expired
from policyops.settings import HelpdeskConnection, HelpdeskSettings


log = logging.getLogger("policyops.helpdesk")


def _destination(config: HelpdeskConnection) -> str:
    return destination_digest(config.api_origin, config.integration_user_id)


@dataclass
class _Step:
    # The version observed under lock or returned by a committed claim/checkpoint.
    version: int | None = None


class HelpdeskWorker:
    def __init__(self, *, env: str, app: Engine, discovery: Engine, settings: HelpdeskSettings,
                 clock: LeaseClock | None = None, transport: httpx.BaseTransport | None = None) -> None:
        if env not in {"local", "test"} or (env != "test" and transport is not None):
            raise UnsafeTestHook("help desk runtime requires local or test; injected transport requires test")
        self.clock = clock or DatabaseLeaseClock()
        require_test_environment(self.clock, env)
        verify_runtime_role(app, APP_RUNTIME)
        verify_runtime_role(discovery, WORKER_DISCOVERY)
        self.app, self.discovery, self.settings, self.transport = app, discovery, settings, transport
        self.owner = uuid4()

    def run_once(self) -> None:
        for queue in store.Queue:
            try:
                with transaction(self.discovery) as connection:
                    due = store.due(connection, queue, self.clock.now(connection))
            except (DatabaseUnavailable, TransactionOutcomeUnknown) as error:
                log.warning("helpdesk_database_retry", extra={"queue": queue.value,
                                                              "error_type": type(error).__name__})
                continue
            for workspace, identity in due:
                step = _Step()
                try:
                    if queue == store.Queue.EVENTS:
                        self.process_event(workspace, identity, step=step)
                    else:
                        self.process_writeback(workspace, identity, step=step)
                except (DatabaseUnavailable, TransactionOutcomeUnknown) as error:
                    log.warning("helpdesk_database_retry", extra={"queue": queue.value,
                                                                  "error_type": type(error).__name__})
                except Exception as error:
                    log.error("helpdesk_step_failed", extra={"error_type": type(error).__name__})
                    try:
                        self._record_internal_error(queue, workspace, identity, step)
                    except Exception as marking_error:
                        log.error("helpdesk_step_failure_record_failed",
                                  extra={"error_type": type(marking_error).__name__})

    def _record_internal_error(self, queue: store.Queue, workspace: UUID, identity: UUID, step: _Step) -> None:
        if step.version is None:
            return
        with workspace_transaction(self.app, workspace, profile=SqlProfile.LEASE) as connection:
            row = store.lock_row(connection, queue, identity)
            if row is None or row.version != step.version or row.state not in {"pending", "dispatching"}:
                return
            now = self.clock.now(connection)
            if queue == store.Queue.EVENTS:
                store.event_result(connection, identity, "failed", "internal_error", now)
            else:
                result = Result("unconfirmed" if row.state == "dispatching" else "failed", "internal_error")
                self._record(connection, row, result, now)

    def _config(self, workspace: UUID, connection_id: str, destination: str) -> HelpdeskConnection | None:
        config = self.settings.connection(connection_id)
        if config is None or config.workspace_id != workspace or _destination(config) != destination:
            return None
        return config

    def process_event(self, workspace: UUID, identity: UUID, *, step: _Step | None = None) -> bool:
        step = step or _Step()
        queue = store.Queue.EVENTS
        with workspace_transaction(self.app, workspace, profile=SqlProfile.LEASE) as connection:
            row = store.lock_row(connection, queue, identity)
            now = self.clock.now(connection)
            if row is None or not store.claimable(row, now):
                return False
            step.version = row.version
            config = self._config(workspace, row.connection_id, row.destination_sha256)
            if config is None or row.attempts >= store.EVENT_ATTEMPTS:
                store.event_result(connection, identity, "failed",
                                   "connection_changed" if config is None else "attempts_exhausted", now)
                return True
            ticket_id = int(row.ticket_id)
            token = store.claim(connection, queue, row, self.owner, now)
        step.version = token.version
        try:
            with closing(ZammadClient(config, transport=self.transport)) as client:
                ticket = client.ticket(ticket_id)
                articles = client.articles(ticket_id)
                if client.ticket(ticket_id) != ticket:
                    raise RemoteError("snapshot_changed")
        except RemoteError as error:
            with workspace_transaction(self.app, workspace, profile=SqlProfile.LEASE) as connection:
                row = store.lock_row(connection, queue, identity)
                now = self.clock.now(connection)
                if row is not None and store.held(row, token, now):
                    if error.code == "incomplete_scan":
                        state = "incomplete_scan"
                    elif error.code in REJECTIONS.values() or row.attempts >= store.EVENT_ATTEMPTS:
                        state = "failed"
                    else:
                        state = "pending"
                    next_at = now + backoff(row.attempts) if state == "pending" else now
                    store.event_result(connection, identity, state, error.code, next_at)
            return True
        with workspace_transaction(self.app, workspace) as connection:
            row = store.lock_row(connection, queue, identity)
            if row is not None and store.held(row, token, self.clock.now(connection)):
                apply_snapshot(connection, config, row, ticket, articles, self.clock, token)
        return True

    def _authority(self, connection: Connection, workspace: UUID,
                   row: RowMapping) -> tuple[HelpdeskConnection, Note] | None:
        link = store.case_link(connection, row.case_id)
        if link is None or link.id != row.link_id or link.workspace_id != workspace:
            return None
        config = self._config(workspace, link.connection_id, link.destination_sha256)
        if config is None or not config.writeback_enabled or link.group_id not in config.allowed_group_ids:
            return None
        customer = store.requester(connection, workspace, link.connection_id, link.requester_id)
        if customer != link.customer_user_id:
            return None
        try:
            body = note_body(row.id, row.template_version)
        except ValueError:
            return None
        if digest(body.encode()) != row.body_sha256:
            return None
        return config, Note(row.id, link.ticket_id, link.requester_id, config.integration_user_id,
                            config.allowed_group_ids, body, row.body_sha256)

    def process_writeback(self, workspace: UUID, identity: UUID, *, step: _Step | None = None) -> bool:
        step = step or _Step()
        queue = store.Queue.WRITEBACKS
        with workspace_transaction(self.app, workspace, profile=SqlProfile.LEASE) as connection:
            row = store.lock_row(connection, queue, identity)
            now = self.clock.now(connection)
            if row is None or not store.claimable(row, now):
                return False
            step.version = row.version
            possibly_sent = row.state == "dispatching"
            result = expired(possibly_sent=possibly_sent, now=now, deadline=row.deadline_at,
                             limit_reached=(row.reconciles >= store.RECONCILES if possibly_sent
                                            else row.attempts >= store.WRITE_ATTEMPTS))
            if result is not None:
                self._record(connection, row, result, now)
                return True
            authority = self._authority(connection, workspace, row)
            if authority is None:
                self._record(connection, row,
                             Result("unconfirmed" if possibly_sent else "failed", "authority_changed"), now)
                return True
            config, note = authority
            reconcile_count = int(row.reconciles)
            token = store.claim(connection, queue, row, self.owner, now)
        step.version = token.version

        def checkpoint() -> bool:
            nonlocal token
            with workspace_transaction(self.app, workspace, profile=SqlProfile.LEASE) as connection:
                current = store.lock_row(connection, queue, identity)
                now = self.clock.now(connection)
                if current is None or not store.held(current, token, now):
                    return False
                if self._authority(connection, workspace, current) != authority:
                    self._record(connection, current, Result("failed", "authority_changed"), now)
                    return False
                now = self.clock.now(connection)
                if not store.held(current, token, now):
                    return False
                if now >= current.deadline_at:
                    self._record(connection, current, Result("failed", "deadline_elapsed"), now)
                    return False
                token = store.checkpoint(connection, current, now, QUIESCENCE)
            step.version = token.version
            return True

        with closing(ZammadClient(config, transport=self.transport)) as client:
            result = deliver(client, note, possibly_sent=possibly_sent, reconciles=reconcile_count,
                             checkpoint=checkpoint)
        if result is not None:
            with workspace_transaction(self.app, workspace, profile=SqlProfile.LEASE) as connection:
                row = store.lock_row(connection, queue, identity)
                now = self.clock.now(connection)
                if row is None or not store.held(row, token, now):
                    return True
                self._record(connection, row, result, now)
            log.info("helpdesk_writeback_result", extra={"operation_id": identity, "state": result.state,
                                                         "reason": result.reason})
        return True

    @staticmethod
    def _record(connection: Connection, row: RowMapping, result: Result, now: datetime) -> None:
        if result.state == "pending":
            next_at = min(row.deadline_at, now + backoff(row.attempts))
        elif result.state == "dispatching":
            next_at = now + QUIESCENCE
        else:
            next_at = now
        store.writeback_result(connection, row.id, result.state, result.reason, next_at,
                               matches=result.matches, reconciles=int(result.reconcile))
