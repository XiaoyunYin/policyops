"""Verify inbound wake-ups and apply an authoritative, bounded snapshot atomically."""

from dataclasses import dataclass
from datetime import timedelta
import json
import re
from typing import Literal
from uuid import uuid4

from sqlalchemy import Connection, Engine
from sqlalchemy.engine import RowMapping

from policyops.domain.helpdesk_rules import (
    article_message_id,
    destination_digest,
    imported_text,
    signature_valid,
    ticket_mark,
)
from policyops.persistence import helpdesk as store
from policyops.persistence import repositories as repo
from policyops.persistence.database import ImmutableRecord, workspace_transaction
from policyops.persistence.records import AuditEvent, NewCase
from policyops.runtime.clock import LeaseClock
from policyops.settings import HelpdeskConnection, HelpdeskSettings
from policyops_contracts.helpdesk import Article, Ticket, TicketWakeup
from policyops_contracts.scalars import CaseScope


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


@dataclass(frozen=True)
class Disposition:
    state: Literal["applied", "stale", "rejected_mapping"]
    reason: str | None = None


def disposition(config: HelpdeskConnection, ticket: Ticket, articles: tuple[Article, ...], link: store.Link | None,
                customer: str | None) -> Disposition:
    if ticket.group_id not in config.allowed_group_ids:
        return Disposition("rejected_mapping", "disallowed_group")
    destination = destination_digest(config.api_origin, config.integration_user_id)
    if link is not None and link.destination_sha256 != destination:
        return Disposition("rejected_mapping", "destination_changed")
    if link is not None and ticket.customer_id != link.requester_id:
        return Disposition("rejected_mapping", "requester_changed")
    if customer is None or (link is not None and customer != link.customer_user_id):
        return Disposition("rejected_mapping", "unmapped_requester")
    if link is not None and ticket_mark(ticket, articles) <= (link.ticket_updated_at, link.max_article_id):
        return Disposition("stale")
    return Disposition("applied")


def apply_snapshot(connection: Connection, config: HelpdeskConnection, event: RowMapping, ticket: Ticket,
                   articles: tuple[Article, ...], clock: LeaseClock, token: store.Claim) -> None:
    """The caller holds the inbox lock. Lock the ticket key and link next, then the case."""
    workspace = config.workspace_id
    link = store.lock_ticket(connection, workspace, config.connection_id, ticket.id)
    customer = store.requester(connection, workspace, config.connection_id, ticket.customer_id)
    decision = disposition(config, ticket, articles, link, customer)
    case = None if link is None or decision.state != "applied" else repo.lock_case(connection, link.case_id)
    now = clock.now(connection)
    if not store.held(event, token, now):
        return
    event_id = token.id
    if decision.state == "rejected_mapping":
        repo.append_audit(connection, AuditEvent(id=uuid4(), workspace_id=workspace, actor_kind="system",
            actor_principal_id=None, action="helpdesk.rejected_mapping", target_type="helpdesk_event",
            target_id=event_id, reason=decision.reason, correlation_id=event_id, occurred_at=now))
    if decision.state != "applied":
        store.event_result(connection, event_id, decision.state, decision.reason, now)
        return
    if customer is None or (link is not None and (case is None or case.customer_user_id != customer)):
        raise ImmutableRecord("help desk case binding changed")

    case_id = uuid4() if link is None else link.case_id
    scope = CaseScope(workspace_id=workspace, case_id=case_id)
    _, article_id = ticket_mark(ticket, articles)
    if link is None:
        repo.create_case(connection, NewCase(id=case_id, workspace_id=workspace, scenario="retail",
            customer_user_id=customer, created_by=None, created_at=now))
        store.create_link(connection, workspace=workspace, connection_id=config.connection_id,
            destination=destination_digest(config.api_origin, config.integration_user_id),
            case_id=case_id, customer=customer, ticket=ticket, max_article_id=article_id, now=now)
        repo.append_audit(connection, AuditEvent(id=uuid4(), workspace_id=workspace, actor_kind="system",
            actor_principal_id=None, action="helpdesk.case_created", target_type="case", target_id=case_id,
            correlation_id=event_id, occurred_at=now))
    else:
        store.advance_link(connection, link, ticket, article_id)

    appended = False
    for article in sorted(articles, key=lambda item: item.id):
        body = imported_text(article, config.integration_user_id)
        identity = article_message_id(workspace, config.connection_id, ticket.id, article.id)
        if body is not None and repo.message_by_id(connection, scope, identity) is None:
            repo.append_message(connection, message_id=identity, scope=scope, source="helpdesk_ticket",
                                entered_by=None, text_value=body, created_at=now)
            appended = True
    if appended:
        repo.bump_case_version(connection, case_id, now)
    store.event_result(connection, event_id, "applied", None, now)
