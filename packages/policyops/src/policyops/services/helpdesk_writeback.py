"""Delivery protocol for one fixed, receipt-backed internal note."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from random import SystemRandom
from typing import Literal
from uuid import UUID

from policyops.adapters.zammad_client import REJECTIONS, TIMEOUT_SECONDS, RemoteError, ZammadClient
from policyops.domain.helpdesk_rules import matching_notes
from policyops.persistence.helpdesk import RECONCILES
from policyops_contracts.helpdesk import Article


QUIESCENCE = timedelta(seconds=2 * TIMEOUT_SECONDS + 2)
_random = SystemRandom()


@dataclass(frozen=True)
class Note:
    operation_id: UUID
    ticket_id: int
    requester_id: int
    integration_user_id: int
    allowed_groups: frozenset[int]
    body: str
    body_sha256: str


@dataclass(frozen=True)
class Result:
    state: Literal["pending", "dispatching", "succeeded", "unconfirmed", "failed"]
    reason: str | None = None
    matches: tuple[Article, ...] = ()
    reconcile: bool = False


def expired(*, possibly_sent: bool, now: datetime, deadline: datetime, limit_reached: bool) -> Result | None:
    if now < deadline and not limit_reached:
        return None
    return Result("unconfirmed" if possibly_sent else "failed",
                  "deadline_elapsed" if now >= deadline else "attempts_exhausted")


def backoff(attempt: int) -> timedelta:
    return timedelta(seconds=min(60, 2 ** min(attempt, 6)) * _random.uniform(0.5, 1))


def _success(matches: tuple[Article, ...]) -> Result:
    return Result("succeeded", "duplicate_detected" if len(matches) > 1 else None, matches)


def deliver(client: ZammadClient, note: Note, *, possibly_sent: bool, reconciles: int,
            checkpoint: Callable[[], bool]) -> Result | None:
    def find(articles: tuple[Article, ...]) -> tuple[Article, ...]:
        return matching_notes(articles, ticket_id=note.ticket_id, author=note.integration_user_id,
                              operation_id=note.operation_id, body_sha256=note.body_sha256)

    def unresolved(reason: str) -> Result:
        return Result("unconfirmed" if reconciles + 1 >= RECONCILES else "dispatching", reason, reconcile=True)

    try:
        matches = find(client.articles(note.ticket_id))
        if matches:
            return _success(matches)
        if possibly_sent:
            return unresolved("note_not_found")
        ticket = client.ticket(note.ticket_id)
        if ticket.customer_id != note.requester_id or ticket.group_id not in note.allowed_groups:
            return Result("failed", "remote_mapping_changed")
    except RemoteError as exc:
        if exc.code in REJECTIONS.values():
            return Result("failed", exc.code)
        if possibly_sent:
            return unresolved(exc.code)
        return Result("failed" if exc.code == "incomplete_scan" else "pending", exc.code)

    # A false result is a lost claim or withdrawn authority. A COMMIT exception also stops the call.
    if not checkpoint():
        return None
    try:
        article = client.post_note(note.ticket_id, note.body)
    except RemoteError as exc:
        if exc.code == "pre_send":
            return Result("pending", exc.code)
        if exc.code in REJECTIONS.values():
            return Result("failed", exc.code)
        return Result("dispatching", exc.code)
    matches = find((article,))
    return _success(matches) if matches else Result("dispatching", "unmatched_response")
