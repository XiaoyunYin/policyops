"""Pure decisions over authenticated wake-ups and bounded remote snapshots."""

from datetime import datetime
import hashlib
import hmac
import re
from uuid import UUID, uuid5

from pydantic import TypeAdapter, ValidationError

from policyops_contracts.helpdesk import Article, Ticket
from policyops_contracts.scalars import MessageText


ARTICLE_NAMESPACE = UUID("e2de4574-ded7-5764-817b-ed269571fe6e")
NOTE_VERSION = 1
_text = TypeAdapter(MessageText)


def signature_valid(secret: str, body: bytes, values: list[bytes]) -> bool:
    if len(values) != 1 or re.fullmatch(rb"sha1=[0-9a-fA-F]{40}", values[0]) is None:
        return False
    # Zammad's documented signature is a body-only HMAC with SHA-1.
    return hmac.compare_digest(hmac.digest(secret.encode(), body, "sha1"), bytes.fromhex(values[0][5:].decode()))


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def ticket_mark(ticket: Ticket, articles: tuple[Article, ...]) -> tuple[datetime, int]:
    return ticket.updated_at, max((article.id for article in articles), default=0)


def article_message_id(workspace_id: UUID, connection_id: str, ticket_id: int, article_id: int) -> UUID:
    return uuid5(uuid5(ARTICLE_NAMESPACE, str(workspace_id)), f"{connection_id}:{ticket_id}:{article_id}")


def destination_digest(origin: str, integration_user_id: int) -> str:
    return digest(f"{origin}\n{integration_user_id}".encode())


def imported_text(article: Article, integration_user_id: int) -> str | None:
    if article.internal or article.sender != "Customer" or article.created_by_id == integration_user_id:
        return None
    mime = article.content_type.partition(";")[0].strip().lower()
    if mime == "text/html":
        return "[Help desk article omitted because it contains HTML.]"
    if mime != "text/plain":
        return None
    try:
        return _text.validate_python(article.body.replace("\r\n", "\n"))
    except ValidationError:
        return "[Help desk article omitted because its plain text is empty, too long, or unsupported.]"


def marker(operation_id: UUID) -> str:
    return f"policyops-op:{operation_id}"


def note_body(operation_id: UUID, version: int) -> str:
    if version != NOTE_VERSION:
        raise ValueError("unknown help desk note template")
    return f"PolicyOps confirmed that the approved retail action committed.\n\n{marker(operation_id)}"


def matching_notes(articles: tuple[Article, ...], *, ticket_id: int, author: int, operation_id: UUID,
                   body_sha256: str) -> tuple[Article, ...]:
    return tuple(sorted((item for item in articles if (
        item.ticket_id == ticket_id and item.internal and item.created_by_id == author
        and marker(operation_id) in item.body.splitlines() and digest(item.body.encode()) == body_sha256
    )), key=lambda item: item.id))
