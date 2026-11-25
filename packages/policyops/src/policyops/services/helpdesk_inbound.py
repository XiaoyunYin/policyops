"""Verify inbound wake-ups and apply an authoritative, bounded snapshot atomically."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re
from typing import Literal
from uuid import uuid4

from sqlalchemy import Connection, Engine
from sqlalchemy.engine import RowMapping

from policyops.domain.helpdesk_rules import destination_digest, signature_valid
from policyops.persistence import helpdesk as store
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.persistence.records import AuditEvent
from policyops.runtime.clock import LeaseClock
from policyops.services.helpdesk_projection import disposition as disposition
from policyops.services.helpdesk_projection import project_snapshot
from policyops.settings import HelpdeskConnection, HelpdeskSettings
from policyops_contracts.helpdesk import Article, Ticket, TicketWakeup


IntakeStatus = Literal[202, 400, 401, 404]


@dataclass(frozen=True)
class Inbound:
    settings: HelpdeskSettings
    engine: Engine
    clock: LeaseClock

    def receive(self, connection_id: str, body: bytes, signatures: list[bytes],
                deliveries: list[bytes]) -> IntakeStatus:
        config = self.settings.connection(connection_id)
        if config is None:
            return 404
        if not signature_valid(config.signing_secret.get_secret_value(), body, signatures):
            return 401
        try:
            # Reject duplicate fields and numeric datetimes before storing the minimal raw body.
            fields = json.loads(body, object_pairs_hook=tuple)
            if not isinstance(fields, tuple) or len(fields) != 2 or not isinstance(dict(fields).get("updated_at"), str):
                return 400
            wakeup = TicketWakeup.model_validate_json(body)
        except (ValueError, RecursionError):
            return 400
        delivery = (deliveries[0].decode("ascii") if len(deliveries) == 1
                    and re.fullmatch(rb"[!-~]{1,128}", deliveries[0]) else None)
        with workspace_transaction(self.engine, config.workspace_id) as connection:
            now = self.clock.now(connection)
            if not now - timedelta(seconds=config.max_event_age_seconds) <= wakeup.updated_at <= now + timedelta(
                    minutes=5):
                return 400
            store.enqueue_event(connection, workspace=config.workspace_id, connection_id=connection_id,
                destination=destination_digest(config.api_origin, config.integration_user_id),
                wakeup=wakeup, delivery_id=delivery, body=body, now=now)
        return 202


def apply_snapshot(connection: Connection, config: HelpdeskConnection, event: RowMapping, ticket: Ticket,
                   articles: tuple[Article, ...], clock: LeaseClock, token: store.Claim) -> None:
    """The caller holds the inbox lock. Recheck the lease after the ticket and case locks."""

    def authorized_at() -> datetime | None:
        now = clock.now(connection)
        return now if store.held(event, token, now) else None

    projected = project_snapshot(connection, config, ticket, articles, authorized_at=authorized_at)
    if projected is None:
        return
    decision, now = projected.decision, projected.now
    event_id = token.id
    if decision.state == "rejected_mapping":
        repo.append_audit(connection, AuditEvent(id=uuid4(), workspace_id=config.workspace_id, actor_kind="system",
            actor_principal_id=None, action="helpdesk.rejected_mapping", target_type="helpdesk_event",
            target_id=event_id, reason=decision.reason, correlation_id=event_id, occurred_at=now))
    if projected.created_case_id is not None:
        repo.append_audit(connection, AuditEvent(id=uuid4(), workspace_id=config.workspace_id, actor_kind="system",
            actor_principal_id=None, action="helpdesk.case_created", target_type="case",
            target_id=projected.created_case_id, correlation_id=event_id, occurred_at=now))
    store.event_result(connection, event_id, decision.state, decision.reason, now)
