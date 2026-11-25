"""Project a bounded ticket snapshot under the shared ticket and case locks."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import Connection

from policyops.domain.helpdesk_rules import (
    ProjectionReason,
    article_message_id,
    destination_digest,
    imported_text,
    ticket_mark,
)
from policyops.persistence import helpdesk as store
from policyops.persistence import repositories as repo
from policyops.persistence.database import ImmutableRecord
from policyops.persistence.records import NewCase
from policyops.settings import HelpdeskConnection
from policyops_contracts.digest import text_sha256
from policyops_contracts.helpdesk import Article, Ticket
from policyops_contracts.scalars import CaseScope


@dataclass(frozen=True)
class Disposition:
    state: Literal["applied", "stale", "rejected_mapping", "duplicate", "quarantined"]
    reason: ProjectionReason | None = None


@dataclass(frozen=True)
class Projection:
    decision: Disposition
    now: datetime
    created_case_id: UUID | None = None


def disposition(config: HelpdeskConnection, ticket: Ticket, articles: tuple[Article, ...], link: store.Link | None,
                customer: str | None, *, reconcile_history: bool = False) -> Disposition:
    if ticket.group_id not in config.allowed_group_ids:
        return Disposition("rejected_mapping", "disallowed_group")
    destination = destination_digest(config.api_origin, config.integration_user_id)
    if link is not None and link.destination_sha256 != destination:
        return Disposition("rejected_mapping", "destination_changed")
    if link is not None and ticket.customer_id != link.requester_id:
        return Disposition("rejected_mapping", "requester_changed")
    if customer is None or (link is not None and customer != link.customer_user_id):
        return Disposition("rejected_mapping", "unmapped_requester")
    if link is not None:
        incoming, current = ticket_mark(ticket, articles), (link.ticket_updated_at, link.max_article_id)
        if incoming < current or (incoming == current and not reconcile_history):
            return Disposition("stale")
    return Disposition("applied")


def project_snapshot(connection: Connection, config: HelpdeskConnection, ticket: Ticket, articles: tuple[Article, ...],
                     *, authorized_at: Callable[[], datetime | None], reconcile_history: bool = False
                     ) -> Projection | None:
    workspace = config.workspace_id
    link = store.lock_ticket(connection, workspace, config.connection_id, ticket.id)
    customer = store.requester(connection, workspace, config.connection_id, ticket.customer_id)
    decision = disposition(config, ticket, articles, link, customer, reconcile_history=reconcile_history)
    case = None if link is None or decision.state != "applied" else repo.lock_case(connection, link.case_id)
    now = authorized_at()
    if now is None:
        return None
    if decision.state != "applied":
        return Projection(decision, now)
    if customer is None or (link is not None and (case is None or case.customer_user_id != customer)):
        raise ImmutableRecord("help desk case binding changed")

    case_id = uuid4() if link is None else link.case_id
    scope = CaseScope(workspace_id=workspace, case_id=case_id)
    mark = ticket_mark(ticket, articles)
    projected: dict[UUID, str] = {}
    for article in sorted(articles, key=lambda item: item.id):
        body = imported_text(article, config.integration_user_id)
        if body is not None:
            projected[article_message_id(workspace, config.connection_id, ticket.id, article.id)] = body

    existing: dict[UUID, str] = {}
    if link is not None and reconcile_history:
        existing = store.projected_article_digests(connection, scope, limit=len(projected) + 1)
        incoming = {identity: text_sha256(body) for identity, body in projected.items()}
        if mark == (link.ticket_updated_at, link.max_article_id):
            if (ticket.group_id, ticket.state_id) == (link.group_id, link.state_id) and existing == incoming:
                return Projection(Disposition("duplicate"), now)
            return Projection(Disposition("quarantined", "snapshot_conflict"), now)
        if any(incoming.get(identity) != sha for identity, sha in existing.items()):
            return Projection(Disposition("quarantined", "incompatible_history"), now)

    if link is None:
        repo.create_case(connection, NewCase(id=case_id, workspace_id=workspace, scenario="retail",
            customer_user_id=customer, created_by=None, created_at=now))
        store.create_link(connection, workspace=workspace, connection_id=config.connection_id,
            destination=destination_digest(config.api_origin, config.integration_user_id),
            case_id=case_id, customer=customer, ticket=ticket, max_article_id=mark[1], now=now)
    else:
        store.advance_link(connection, link, ticket, mark[1])

    appended = False
    for identity, body in projected.items():
        if identity in existing or (link is not None and not reconcile_history
                                    and repo.message_by_id(connection, scope, identity) is not None):
            continue
        repo.append_message(connection, message_id=identity, scope=scope, source="helpdesk_ticket",
                            entered_by=None, text_value=body, created_at=now)
        appended = True
    if appended:
        repo.bump_case_version(connection, case_id, now)
    return Projection(decision, now, case_id if link is None else None)
