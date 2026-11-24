"""Narrow Zammad HTTP client. No redirects, ambient proxy credentials or automatic retries."""

from time import monotonic
from typing import Any, Literal

import httpx
from pydantic import TypeAdapter, ValidationError

from policyops.settings import HelpdeskConnection
from policyops_contracts.helpdesk import Article, Ticket


MAX_RESPONSE_BYTES = 256 * 1024
MAX_ARTICLES = 200
TIMEOUT_SECONDS = 3
RemoteCode = Literal["pre_send", "unavailable", "incomplete_scan", "unauthorized", "forbidden",
                     "not_found", "unprocessable", "snapshot_changed"]
REJECTIONS: dict[int, RemoteCode] = {401: "unauthorized", 403: "forbidden", 404: "not_found", 422: "unprocessable"}
_articles = TypeAdapter(list[Article])


class RemoteError(RuntimeError):
    def __init__(self, code: RemoteCode) -> None:
        super().__init__(code)
        self.code = code


class ZammadClient:
    def __init__(self, config: HelpdeskConnection, *, transport: httpx.BaseTransport | None = None) -> None:
        self._http = httpx.Client(
            base_url=config.api_origin, timeout=TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
            headers={"Authorization": f"Token token={config.api_token.get_secret_value()}",
                     "Accept": "application/json", "Accept-Encoding": "identity"},
            transport=transport,
        )

    def close(self) -> None:
        self._http.close()

    def _request(self, method: str, path: str, *, payload: dict[str, Any] | None = None) -> bytes:
        deadline = monotonic() + TIMEOUT_SECONDS
        received_headers = False
        try:
            with self._http.stream(method, path, json=payload) as response:
                received_headers = True
                rejected = REJECTIONS.get(response.status_code)
                if rejected is not None:
                    raise RemoteError(rejected)
                if not response.is_success:
                    raise RemoteError("unavailable")
                encoding = response.headers.get("Content-Encoding", "identity")
                size = response.headers.get("Content-Length")
                if (encoding.lower() != "identity" or (size is not None and (
                        not size.isascii() or not size.isdecimal() or len(size) > 9
                        or int(size) > MAX_RESPONSE_BYTES))):
                    raise RemoteError("incomplete_scan")
                body = bytearray()
                # MockTransport may return a pre-read response. Real responses are streamed before allocation.
                chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
                for chunk in chunks:
                    if monotonic() >= deadline:
                        raise RemoteError("unavailable")
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise RemoteError("incomplete_scan")
                    body.extend(chunk)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            # A connect failure after receiving headers is not evidence that the request was unsent.
            code: RemoteCode = "unavailable" if received_headers else "pre_send"
            raise RemoteError(code) from None
        except httpx.HTTPError:
            raise RemoteError("unavailable") from None
        return bytes(body)

    def ticket(self, ticket_id: int) -> Ticket:
        body = self._request("GET", f"/api/v1/tickets/{ticket_id}")
        try:
            result = Ticket.model_validate_json(body)
        except ValidationError:
            raise RemoteError("incomplete_scan") from None
        if result.id != ticket_id:
            raise RemoteError("incomplete_scan")
        return result

    def articles(self, ticket_id: int) -> tuple[Article, ...]:
        body = self._request("GET", f"/api/v1/ticket_articles/by_ticket/{ticket_id}")
        try:
            articles = _articles.validate_json(body)
        except ValidationError:
            raise RemoteError("incomplete_scan") from None
        if (len(articles) > MAX_ARTICLES or any(item.ticket_id != ticket_id for item in articles)
                or len({item.id for item in articles}) != len(articles)):
            raise RemoteError("incomplete_scan")
        return tuple(articles)

    def post_note(self, ticket_id: int, body: str) -> Article:
        raw = self._request("POST", "/api/v1/ticket_articles",
                            payload={"ticket_id": ticket_id, "body": body, "internal": True, "type": "note",
                                     "content_type": "text/plain", "subject": "PolicyOps outcome"})
        try:
            return Article.model_validate_json(raw)
        except ValidationError:
            raise RemoteError("incomplete_scan") from None
