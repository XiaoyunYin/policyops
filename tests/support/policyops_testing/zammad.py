"""Fictional Zammad HTTP fixtures shaped by the sanitized 7.2.3-0019 capture."""

from datetime import UTC, datetime
import hmac
import json
from pathlib import Path
from secrets import token_hex
from typing import Any, Literal
from uuid import UUID, uuid4

import httpx
from pydantic import SecretStr

from policyops.settings import HelpdeskConnection, HelpdeskSettings


NOW = datetime(2026, 11, 24, 10, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "helpdesk"
Fault = Literal["connect", "drop", "lost", "commit_503", "401", "403", "404", "422"]


def settings(workspace: UUID | None = None, *, enabled: bool = True) -> HelpdeskSettings:
    return HelpdeskSettings(connections=(HelpdeskConnection(
        connection_id="fixture", workspace_id=workspace or uuid4(), signing_secret=SecretStr(token_hex(24)),
        api_token=SecretStr(token_hex(24)), api_origin="https://zammad.example.invalid",
        allowed_group_ids=frozenset({7}), integration_user_id=19, writeback_enabled=enabled),))


def webhook(ticket_id: int = 42, updated_at: datetime = NOW) -> bytes:
    if ticket_id == 42 and updated_at == NOW:
        return (FIXTURES / "zammad-webhook.json").read_bytes().rstrip(b"\n")
    timestamp = updated_at.isoformat().replace("+00:00", "Z")
    return json.dumps({"ticket_id": ticket_id, "updated_at": timestamp}, separators=(",", ":")).encode()


def sign(config: HelpdeskConnection, body: bytes) -> bytes:
    return b"sha1=" + hmac.digest(config.signing_secret.get_secret_value().encode(), body, "sha1").hex().encode()


class FakeZammad:
    def __init__(self, config: HelpdeskConnection) -> None:
        self.config = config
        self.ticket: dict[str, Any] = json.loads((FIXTURES / "zammad-ticket.json").read_bytes())
        self.articles: list[dict[str, Any]] = json.loads((FIXTURES / "zammad-articles.json").read_bytes())
        self.fault: Fault | None = None
        self.lookup_outage = False
        self.calls: list[tuple[str, str]] = []
        self.posts: list[dict[str, Any]] = []
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "zammad.example.invalid"
        authorization = "Token token=" + self.config.api_token.get_secret_value()
        if not hmac.compare_digest(request.headers.get("Authorization", ""), authorization):
            raise AssertionError("fake Zammad received incorrect API authentication")
        entry = (request.method, request.url.path)
        self.calls.append(entry)
        if entry == ("GET", "/api/v1/tickets/42"):
            return httpx.Response(200, json=self.ticket)
        if entry == ("GET", "/api/v1/ticket_articles/by_ticket/42"):
            if self.lookup_outage:
                raise httpx.ConnectError("simulated unavailable", request=request)
            return httpx.Response(200, json=self.articles)
        assert entry == ("POST", "/api/v1/ticket_articles")
        payload = json.loads(request.content)
        assert set(payload) == {"ticket_id", "body", "internal", "type", "content_type", "subject"}
        assert payload["ticket_id"] == 42 and payload["internal"] is True
        assert payload["type"] == "note" and payload["content_type"] == "text/plain"
        self.posts.append(payload)
        fault, self.fault = self.fault, None
        if fault == "connect":
            raise httpx.ConnectError("simulated before send", request=request)
        if fault == "drop":
            raise httpx.ReadError("simulated broken response", request=request)
        if fault in {"401", "403", "404", "422"}:
            return httpx.Response(int(fault))
        note = self.add(payload["body"], article_id=max(row["id"] for row in self.articles) + 1,
                        subject=payload["subject"])
        if fault == "lost":
            raise httpx.ReadTimeout("simulated lost response", request=request)
        if fault == "commit_503":
            return httpx.Response(503)
        return httpx.Response(201, json=note)

    def add(self, body: str, *, article_id: int, author: int | None = None,
            internal: bool = True, subject: str = "Fictional ticket article") -> dict[str, Any]:
        article = {
            "id": article_id, "ticket_id": 42, "internal": internal,
            "created_by_id": self.config.integration_user_id if author is None else author,
            "created_at": self.ticket["updated_at"], "sender": "Agent" if author is None else "Customer",
            "content_type": "text/plain", "body": body, "type": "note", "subject": subject,
        }
        self.articles.append(article)
        return article
