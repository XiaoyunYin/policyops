"""Workspace-scoped connector storage. Discovery can see scheduling columns only."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4, uuid5

from sqlalchemy import Connection, DateTime, Uuid, bindparam, text
from sqlalchemy.engine import RowMapping

from policyops.domain.helpdesk_rules import NOTE_VERSION, digest, note_body
from policyops_contracts.helpdesk import Article, Ticket, TicketWakeup
from policyops_contracts.scalars import CaseScope
from policyops_contracts.seeds import CaseCustomerBinding


EVENT_ATTEMPTS = 8
EVENT_REVIVALS = 3
WRITE_ATTEMPTS = 12
RECONCILES = 3
LEASE = timedelta(seconds=25)
DELIVERY_WINDOW = timedelta(minutes=15)


class Queue(StrEnum):
    EVENTS = "helpdesk_events"
    WRITEBACKS = "helpdesk_writebacks"


@dataclass(frozen=True)
class Claim:
    id: UUID
    owner: UUID
    version: int


@dataclass(frozen=True)
class Link:
    id: UUID
    workspace_id: UUID
    connection_id: str
    ticket_id: int
    requester_id: int
    customer_user_id: str
    destination_sha256: str
    case_id: UUID
    group_id: int
    state_id: int
    ticket_updated_at: datetime
    max_article_id: int
    created_at: datetime


def due(connection: Connection, queue: Queue, now: datetime) -> list[tuple[UUID, UUID]]:
    rows = connection.execute(text(f"""
        SELECT workspace_id, id FROM app.{queue}
        WHERE state IN ('pending', 'dispatching') AND next_attempt_at <= :now
          AND (lease_expires_at IS NULL OR lease_expires_at <= :now)
        ORDER BY next_attempt_at, id LIMIT 1
    """), {"now": now})  # noqa: S608
    return [(row.workspace_id, row.id) for row in rows]


def enqueue_event(connection: Connection, *, workspace: UUID, connection_id: str, destination: str,
                  wakeup: TicketWakeup, delivery_id: str | None, body: bytes, now: datetime) -> bool:
    upsert = text("""
        INSERT INTO app.helpdesk_events AS event
          (id, workspace_id, connection_id, destination_sha256, ticket_id, event_updated_at, delivery_id,
           body_sha256, payload, created_at, next_attempt_at)
        VALUES (:id, :workspace, :connection, :destination, :ticket, :updated, :delivery, :sha, :body, :now, :now)
        ON CONFLICT (workspace_id, connection_id, body_sha256) DO UPDATE
        SET state = 'pending', reason = NULL, attempts = 0, next_attempt_at = EXCLUDED.next_attempt_at,
            revivals = event.revivals + 1, version = event.version + 1
        WHERE event.destination_sha256 = EXCLUDED.destination_sha256 AND event.revivals < :revival_limit
          AND (event.state = 'incomplete_scan' OR
               (event.state = 'failed' AND (event.reason IS NULL OR event.reason NOT IN
                   ('unauthorized', 'forbidden', 'not_found', 'unprocessable'))))
        RETURNING id
    """).bindparams(
        bindparam("id", type_=Uuid), bindparam("workspace", type_=Uuid),
        bindparam("updated", type_=DateTime(timezone=True)), bindparam("now", type_=DateTime(timezone=True)),
    )
    new_id = connection.execute(upsert, {
        "id": uuid4(), "workspace": workspace, "connection": connection_id, "destination": destination,
        "ticket": wakeup.ticket_id, "updated": wakeup.updated_at, "delivery": delivery_id,
        "sha": digest(body), "body": body, "now": now, "revival_limit": EVENT_REVIVALS,
    }).scalar_one_or_none()
    return new_id is not None


def lock_row(connection: Connection, queue: Queue, identity: UUID) -> RowMapping | None:
    return connection.execute(text(f"SELECT * FROM app.{queue} WHERE id = :id FOR UPDATE"),  # noqa: S608
                              {"id": identity}).mappings().one_or_none()


def claimable(row: RowMapping, now: datetime) -> bool:
    return (row.state in ("pending", "dispatching") and row.next_attempt_at <= now
            and (row.lease_expires_at is None or row.lease_expires_at <= now))


def claim(connection: Connection, queue: Queue, row: RowMapping, owner: UUID, now: datetime) -> Claim:
    version = connection.execute(text(f"""
        UPDATE app.{queue}
        SET lease_owner = :owner, lease_expires_at = :expiry, version = version + 1,
            attempts = attempts + CASE WHEN state = 'pending' THEN 1 ELSE 0 END
        WHERE id = :id RETURNING version
    """), {"id": row.id, "owner": owner, "expiry": now + LEASE}).scalar_one()  # noqa: S608
    return Claim(row.id, owner, version)


def held(row: RowMapping | None, token: Claim, now: datetime) -> bool:
    return (row is not None and row.version == token.version and row.lease_owner == token.owner
            and row.lease_expires_at is not None and now < row.lease_expires_at)


def event_result(connection: Connection, identity: UUID, state: str, reason: str | None, next_at: datetime) -> None:
    connection.execute(text("""
        UPDATE app.helpdesk_events SET state = :state, reason = :reason, next_attempt_at = :next,
            lease_owner = NULL, lease_expires_at = NULL, version = version + 1 WHERE id = :id
    """), {"id": identity, "state": state, "reason": reason, "next": next_at})


def lock_ticket(connection: Connection, workspace: UUID, connection_id: str, ticket_id: int) -> Link | None:
    # Serialize the first insert, too. Key-share locks acquired by writeback's foreign key remain compatible.
    key = f"helpdesk:{workspace}:{connection_id}:{ticket_id}"
    connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key})
    row = connection.execute(text("""
        SELECT * FROM app.helpdesk_ticket_links
        WHERE workspace_id = :workspace AND connection_id = :connection AND ticket_id = :ticket FOR NO KEY UPDATE
    """), {"workspace": workspace, "connection": connection_id, "ticket": ticket_id}).mappings().one_or_none()
    return None if row is None else Link(**row)


def requester(connection: Connection, workspace: UUID, connection_id: str, requester_id: int) -> str | None:
    value: str | None = connection.execute(text("""
        SELECT customer_user_id FROM app.helpdesk_customer_bindings
        WHERE workspace_id = :workspace AND connection_id = :connection AND requester_id = :requester
    """), {"workspace": workspace, "connection": connection_id, "requester": requester_id}).scalar_one_or_none()
    return value


def seed_binding(connection: Connection, *, workspace: UUID, connection_id: str, requester_id: int,
                 customer: str, seed_id: str, now: datetime) -> None:
    connection.execute(text("""
        INSERT INTO app.helpdesk_customer_bindings
            (workspace_id, connection_id, requester_id, customer_user_id, seed_id, created_at)
        VALUES (:workspace, :connection, :requester, :customer, :seed, :now)
        ON CONFLICT (workspace_id, connection_id, requester_id) DO NOTHING
    """), {"workspace": workspace, "connection": connection_id, "requester": requester_id,
           "customer": customer, "seed": seed_id, "now": now})
    existing = connection.execute(text("""
        SELECT customer_user_id, seed_id FROM app.helpdesk_customer_bindings
        WHERE workspace_id = :workspace AND connection_id = :connection AND requester_id = :requester
    """), {"workspace": workspace, "connection": connection_id, "requester": requester_id}).one()
    if tuple(existing) != (customer, seed_id):
        raise ValueError("help desk requester already has a different binding")


def create_link(connection: Connection, *, workspace: UUID, connection_id: str, destination: str,
                case_id: UUID, customer: str, ticket: Ticket, max_article_id: int, now: datetime) -> None:
    connection.execute(text("""
        INSERT INTO app.helpdesk_ticket_links
            (id, workspace_id, connection_id, destination_sha256, ticket_id, requester_id, customer_user_id,
             case_id, group_id, state_id, ticket_updated_at, max_article_id, created_at)
        VALUES (:id, :workspace, :connection, :destination, :ticket, :requester, :customer,
                :case, :group, :state, :updated, :article, :now)
    """), {"id": uuid4(), "workspace": workspace, "connection": connection_id, "destination": destination,
           "ticket": ticket.id, "requester": ticket.customer_id, "customer": customer, "case": case_id,
           "group": ticket.group_id, "state": ticket.state_id, "updated": ticket.updated_at,
           "article": max_article_id, "now": now})


def advance_link(connection: Connection, link: Link, ticket: Ticket, max_article_id: int) -> None:
    connection.execute(text("""
        UPDATE app.helpdesk_ticket_links SET group_id = :group, state_id = :state,
            ticket_updated_at = :updated, max_article_id = :article WHERE id = :id
    """), {"id": link.id, "group": ticket.group_id, "state": ticket.state_id, "updated": ticket.updated_at,
           "article": max_article_id})


def case_binding(connection: Connection, scope: CaseScope) -> CaseCustomerBinding | None:
    row = connection.execute(text("""
        SELECT b.seed_id, b.customer_user_id, l.created_at
        FROM app.helpdesk_ticket_links l JOIN app.helpdesk_customer_bindings b
          USING (workspace_id, connection_id, requester_id, customer_user_id)
        WHERE l.workspace_id = :workspace AND l.case_id = :case
    """), {"workspace": scope.workspace_id, "case": scope.case_id}).one_or_none()
    if row is None:
        return None
    return CaseCustomerBinding(scope=scope, seed_id=row.seed_id, user_id=row.customer_user_id, bound_at=row.created_at)


def case_link(connection: Connection, case_id: UUID) -> Link | None:
    row = connection.execute(text("SELECT * FROM app.helpdesk_ticket_links WHERE case_id = :case"),
                             {"case": case_id}).mappings().one_or_none()
    return None if row is None else Link(**row)


def projected_article_digests(connection: Connection, scope: CaseScope, *, limit: int) -> dict[UUID, str]:
    rows = connection.execute(text("""
        SELECT id, text_sha256 FROM app.case_messages
        WHERE workspace_id = :workspace AND case_id = :case AND source = 'helpdesk_ticket'
        LIMIT :limit
    """), {"workspace": scope.workspace_id, "case": scope.case_id, "limit": limit})
    return {row.id: row.text_sha256 for row in rows}


def enqueue_writeback(connection: Connection, link: Link, message_id: UUID, now: datetime) -> None:
    operation = uuid5(link.id, str(message_id))
    sha = digest(note_body(operation, NOTE_VERSION).encode())
    connection.execute(text("""
        INSERT INTO app.helpdesk_writebacks
           (id, workspace_id, case_id, link_id, outcome_message_id, template_version, body_sha256,
            created_at, deadline_at, next_attempt_at)
        VALUES (:id, :workspace, :case, :link, :message, :template, :sha, :now, :deadline, :now)
        ON CONFLICT (workspace_id, outcome_message_id) DO NOTHING
    """), {"id": operation, "workspace": link.workspace_id, "case": link.case_id, "link": link.id,
           "message": message_id, "template": NOTE_VERSION, "sha": sha, "now": now, "deadline": now + DELIVERY_WINDOW})


def checkpoint(connection: Connection, row: RowMapping, now: datetime, quiescence: timedelta) -> Claim:
    version = connection.execute(text("""
        UPDATE app.helpdesk_writebacks SET state = 'dispatching', dispatch_started_at = :now,
            next_attempt_at = :next, lease_expires_at = :expiry, version = version + 1
        WHERE id = :id RETURNING version
    """), {"id": row.id, "now": now, "next": now + quiescence, "expiry": now + LEASE}).scalar_one()
    return Claim(row.id, row.lease_owner, version)


def writeback_result(connection: Connection, identity: UUID, state: str, reason: str | None, next_at: datetime,
                     *, matches: tuple[Article, ...] = (), reconciles: int = 0) -> None:
    article = matches[0] if matches else None
    duplicate_ids = [item.id for item in matches] if len(matches) > 1 else None
    connection.execute(text("""
        UPDATE app.helpdesk_writebacks SET state = :state, reason = :reason, next_attempt_at = :next,
            lease_owner = NULL, lease_expires_at = NULL, version = version + 1,
            dispatch_started_at = CASE WHEN :state = 'pending' THEN NULL ELSE dispatch_started_at END,
            article_id = :article, article_created_at = :created, duplicate_article_ids = :duplicates,
            reconciles = reconciles + :reconciles WHERE id = :id
    """), {"id": identity, "state": state, "reason": reason, "next": next_at,
           "article": article.id if article else None, "created": article.created_at if article else None,
           "duplicates": duplicate_ids, "reconciles": reconciles})
