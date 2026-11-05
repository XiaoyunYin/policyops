"""Case API building blocks without a database (T08): status transitions, typed idempotency intents, cursors,
the OpenAPI export and the received-body bound at the ASGI level."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
import hashlib
import itertools
import json
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from pydantic import SecretStr, ValidationError
import pytest

from policyops.api import docs
from policyops.api.app import API_PREFIX, create_app
from policyops.api.auth import AuthRuntime
from policyops.api.body_limit import BodyLimit
from policyops.api.openapi import DEFAULT_VALIDATION_SCHEMAS, UndocumentedError, document, export, schema_app
from policyops.auth.service import AuthError
from policyops.domain.case_status import TRANSITIONS, CaseStatus, TransitionRefused, plan_transition
from policyops.persistence import idempotency as idem
from policyops.services.cases import CaseCursor, decode_cursor, encode_cursor
from policyops.settings import AuthSettings
from policyops_contracts.clock import FixedClock
from policyops_testing.openapi_check import DOCUMENT_PATH


# -- status transitions -----------------------------------------------------------------------------------------

ALLOWED = {("open", "in_progress"), ("in_progress", "resolved"), ("resolved", "closed"), ("resolved", "in_progress")}


@pytest.mark.parametrize(("current", "target"), list(itertools.product(CaseStatus, CaseStatus)))
def test_transition_table_is_exactly_the_documented_one(current: CaseStatus, target: CaseStatus) -> None:
    if current == target:
        assert plan_transition(current, target) is False
    elif (current.value, target.value) in ALLOWED:
        assert plan_transition(current, target) is True
    else:
        with pytest.raises(TransitionRefused):
            plan_transition(current, target)
    assert TRANSITIONS[CaseStatus.CLOSED] == frozenset()


# -- typed idempotency intents ----------------------------------------------------------------------------------

CASE = UUID("00000000-0000-4000-8000-000000000001")


def test_intent_digests_are_canonical_and_pinned() -> None:
    """Changing an intent's fields or canonical form must change its schema_version (and these pins)."""
    create = idem.CreateCaseIntent(scenario="retail")
    status = idem.StatusIntent(case_id=CASE, expected_version=3, status="resolved")
    message = idem.MessageIntent(case_id=CASE, expected_version=3, source="staff_note", text="café \U0001F600")
    assert json.dumps(create.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) == (
        '{"operation":"case.create","scenario":"retail","schema_version":"policyops.idempotency-intent/v1"}')
    assert idem.intent_sha256(create) == PINNED["create"] == hashlib.sha256(
        b'{"operation":"case.create","scenario":"retail","schema_version":"policyops.idempotency-intent/v1"}').hexdigest()
    assert idem.intent_sha256(status) == PINNED["status"]
    assert idem.intent_sha256(message) == PINNED["message"]
    assert len({idem.intent_sha256(i) for i in (create, status, message)}) == 3


PINNED = {
    "create": "1ad4acd6d3f232a6015867563fa158d2e97ee22d449c7ee2b044b1032d584a7b",
    "status": "a63170a65fefe4b0c35be363fc68f002331bb82d5fc59a68f6488b9b1ba4c83d",
    "message": "a56c2167a93f65f378b1b8514f5a721b0c47fc62e42e53bd31ade29705bda8b3",
}


def test_intents_cannot_shadow_their_operation_or_version() -> None:
    with pytest.raises(ValidationError):
        idem.CreateCaseIntent(scenario="retail", operation="case.status")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        idem.StatusIntent(case_id=CASE, expected_version=1, status="open", operation="case.message")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        idem.CreateCaseIntent(scenario="retail", schema_version="policyops.idempotency-intent/v2")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        idem.CreateCaseIntent(scenario="retail", path="/api/v1/cases")  # type: ignore[call-arg]
    intent = idem.StatusIntent(case_id=CASE, expected_version=1, status="open")
    with pytest.raises(ValidationError):
        intent.operation = "case.create"  # type: ignore[assignment,misc]


@pytest.mark.parametrize("fields", [
    {"case_id": str(CASE)},          # strict: a UUID, not its text
    {"expected_version": True},      # strict: not a bool
    {"expected_version": 0},
    {"expected_version": "3"},
    {"status": "archived"},
])
def test_intent_fields_are_strictly_typed(fields: dict[str, Any]) -> None:
    base: dict[str, Any] = {"case_id": CASE, "expected_version": 3, "status": "open"}
    with pytest.raises(ValidationError):
        idem.StatusIntent(**{**base, **fields})


def test_message_intent_applies_message_text_rules() -> None:
    for text in ("", "x" * 4001, "bell\x07"):
        with pytest.raises(ValidationError):
            idem.MessageIntent(case_id=CASE, expected_version=1, source="staff_note", text=text)
    with pytest.raises(ValidationError):
        idem.MessageIntent(case_id=CASE, expected_version=1, source="agent", text="x")  # type: ignore[arg-type]


# -- cursors ----------------------------------------------------------------------------------------------------

WORKSPACE = UUID("00000000-0000-4000-8000-0000000000aa")
AT = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)


def _b64(value: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def test_cursor_round_trip_is_bound_to_workspace_and_filter() -> None:
    cursor = encode_cursor(CaseCursor(w=WORKSPACE, s=CaseStatus.OPEN, c=AT, i=CASE))
    assert decode_cursor(cursor, WORKSPACE, CaseStatus.OPEN) == (AT, CASE)
    for workspace, status in ((uuid4(), CaseStatus.OPEN), (WORKSPACE, None), (WORKSPACE, CaseStatus.CLOSED)):
        with pytest.raises(AuthError) as refused:
            decode_cursor(cursor, workspace, status)
        assert (refused.value.status, refused.value.rule_id) == (422, "api.invalid_cursor")


def _tampered() -> Iterator[str]:
    good = json.loads(CaseCursor(w=WORKSPACE, s=None, c=AT, i=CASE).model_dump_json())
    for change in ({"v": True}, {"v": 1}, {"v": 1.0}, {"v": "policyops.case-cursor/v2"}, {"i": 5}, {"i": None},
                   {"i": "not-a-uuid"}, {"i": "ABCDEF00-0000-4000-8000-00000000000A"}, {"w": 7},
                   {"c": "2026-03-01T09:00:00"},
                   {"c": 1772355600}, {"c": "2026-03-01T09:00:00+01:00"}, {"s": "archived"}, {"s": 1},
                   {"extra": 1}):
        yield _b64({**good, **change})
    yield _b64({k: v for k, v in good.items() if k != "i"})
    yield from (_b64([good]), _b64("cursor"), _b64(None), _b64(good) + "=", _b64(good) + "A", "", "a" * 401,
                "!!!!", "éééé", _b64(good).replace("-", "+").replace("_", "/") + "/")


@pytest.mark.parametrize("value", list(_tampered()))
def test_malformed_cursors_are_refused_with_422(value: str) -> None:
    with pytest.raises(AuthError) as refused:
        decode_cursor(value, WORKSPACE, None)
    assert (refused.value.status, refused.value.rule_id) == (422, "api.invalid_cursor")


# -- OpenAPI export ---------------------------------------------------------------------------------------------

SETTINGS = AuthSettings(env="test", public_origin="http://127.0.0.1:8000", oidc_issuer="http://127.0.0.1:5556/dex",
                        oidc_client_id="policyops-test", oidc_client_secret=SecretStr("unit-test-only-secret"),
                        session_absolute_ttl=timedelta(hours=8), session_idle_ttl=timedelta(hours=1))


def test_committed_openapi_document_matches_a_fresh_export() -> None:
    assert DOCUMENT_PATH.read_bytes() == export()


def test_export_uses_the_served_route_composition_without_runtime_values() -> None:
    # Wiring reads only the service's clock (for the default runs runtime); nothing connects or is called.
    service = cast(Any, SimpleNamespace(clock=FixedClock(datetime(2026, 1, 1, tzinfo=UTC))))
    runtime = AuthRuntime(settings=SETTINGS, service=service, app_engine=cast(Any, None))
    served = create_app(runtime)
    assert document(served) == document(schema_app())  # the served app documents exactly the exported routes
    assert all(path.startswith(API_PREFIX) for path in json.loads(export())["paths"])
    text = export().decode()
    for value in ("unit-test-only-secret", "127.0.0.1", "policyops-test", "HTTPValidationError", "/test/"):
        assert value not in text


def test_every_operation_documents_its_enforced_requirements() -> None:
    exported = json.loads(export())
    for path, item in exported["paths"].items():
        for method, operation in item.items():
            statuses = set(operation["responses"])
            assert {"400", "413", "500"} <= statuses, (method, path)
            for status in statuses - {"200", "201", "202", "204", "302", "303"}:
                assert operation["responses"][status]["content"]["application/json"]["schema"] == {
                    "$ref": "#/components/schemas/ErrorEnvelope"}, (method, path, status)
            if operation.get("parameters") or "requestBody" in operation:
                assert "422" in statuses, (method, path)
            names = {p["name"]: p for p in operation.get("parameters", []) if p["in"] == "header"}
            unsafe = method in ("post", "patch")
            public = path in ("/api/v1/auth/login", "/api/v1/auth/callback", "/api/v1/health/live")
            if unsafe:
                assert operation["security"] == [{"session": [], "csrf": []}], path
            elif not public:
                assert operation["security"] == [{"session": []}], path
            if path.startswith("/api/v1/cases") and unsafe:
                assert names["Idempotency-Key"]["required"] is True and "409" in statuses
            if (method, path) in (("patch", "/api/v1/cases/{case_id}"), ("post", "/api/v1/cases/{case_id}/messages")):
                assert names["If-Match"]["required"] is True and "428" in statuses
    assert set(exported["components"]["securitySchemes"]) == {docs.SESSION_SCHEME, docs.CSRF_SCHEME}


def test_export_refuses_fastapi_default_validation_errors() -> None:
    app = FastAPI()

    @app.get("/undocumented/{item}")
    def undocumented(item: int) -> dict[str, int]:
        return {"item": item}

    with pytest.raises(UndocumentedError):
        document(app)
    assert DEFAULT_VALIDATION_SCHEMAS == ("HTTPValidationError", "ValidationError")


# -- received-body bound ------------------------------------------------------------------------------------------

def _drive(limit_app: Any, headers: list[tuple[bytes, bytes]], chunks: list[dict[str, Any]]
           ) -> tuple[list[dict[str, Any]], int]:
    sent: list[dict[str, Any]] = []
    pulled = 0

    async def receive() -> dict[str, Any]:
        nonlocal pulled
        pulled += 1
        if pulled <= len(chunks):
            return chunks[pulled - 1]
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/api/v1/x", "headers": headers}
    asyncio.run(limit_app(scope, receive, send))
    return sent, pulled


class Inner:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.called = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        self.messages.append(await receive())
        self.messages.append(await receive())  # after the body: the server's next message (a disconnect here)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})


def part(body: bytes, more: bool) -> dict[str, Any]:
    return {"type": "http.request", "body": body, "more_body": more}


def test_body_within_the_limit_reaches_the_app_as_one_message() -> None:
    inner = Inner()
    sent, pulled = _drive(BodyLimit(inner, max_bytes=10), [], [part(b"12345", True), part(b"67890", False)])
    assert inner.messages == [part(b"1234567890", False), {"type": "http.disconnect"}]
    assert sent[0]["status"] == 204 and pulled == 3


# Payload markers use letters outside hexadecimal, so they can never occur by chance in the response's generated
# correlation UUID (a digit marker such as b"123" could, and made this test intermittently fail).
OVERFLOW_MARKERS = (b"QZXWVU", b"TSRQP")


@pytest.mark.parametrize("chunks", [
    [part(b"QZXWVUTSRQP", False)],
    [part(b"QZXWVU", True), part(b"TSRQP", True), part(b"never read", False)],
])
def test_overflow_is_refused_without_reading_further_or_calling_the_app(chunks: list[dict[str, Any]]) -> None:
    inner = Inner()
    sent, pulled = _drive(BodyLimit(inner, max_bytes=10), [], chunks)
    assert not inner.called and sent[0]["status"] == 413 and pulled == min(len(chunks), 2)
    body = b"".join(m.get("body", b"") for m in sent)
    # No request bytes echoed in the response: even a 3-byte prefix of either marker (non-hex letters, so never
    # part of the generated correlation UUID) must be absent.
    assert not any(marker[:3] in body for marker in OVERFLOW_MARKERS)


@pytest.mark.parametrize(("headers", "status"), [
    ([(b"content-length", b"11")], 413), ([(b"content-length", b"5"), (b"content-length", b"5")], 400),
    ([(b"content-length", b"five")], 400), ([(b"content-length", b"-1")], 400),
    ([(b"content-length", b"1" * 20)], 400),
])
def test_declared_lengths_are_checked_before_reading(headers: list[tuple[bytes, bytes]], status: int) -> None:
    inner = Inner()
    sent, pulled = _drive(BodyLimit(inner, max_bytes=10), headers, [part(b"x", False)])
    assert not inner.called and pulled == 0 and sent[0]["status"] == status
    body = json.loads(b"".join(m.get("body", b"") for m in sent))
    assert body["rule_id"] == f"api.http_{status}"


def test_a_disconnect_during_the_body_stops_without_calling_the_app() -> None:
    inner = Inner()
    sent, _ = _drive(BodyLimit(inner, max_bytes=10), [], [part(b"123", True), {"type": "http.disconnect"}])
    assert not inner.called and sent == []


def test_the_exact_limit_is_accepted() -> None:
    inner = Inner()
    _drive(BodyLimit(inner, max_bytes=10), [(b"content-length", b"10")], [part(b"1234567890", False)])
    assert inner.messages[0] == part(b"1234567890", False)
