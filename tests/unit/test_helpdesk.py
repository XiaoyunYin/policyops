"""Offline signature, transport, mapping and delivery protocol tests."""

from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
import hmac
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import Any, Never, cast
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import RowMapping

from policyops.adapters.zammad_client import REJECTIONS, RemoteError, ZammadClient
from policyops.domain.helpdesk_rules import destination_digest, digest, imported_text, note_body
from policyops.persistence import helpdesk as store
from policyops.persistence.database import ImmutableRecord
from policyops.persistence.helpdesk import RECONCILES, Link
from policyops.runtime import helpdesk as runtime
from policyops.runtime.clock import FixedLeaseClock
from policyops.services import helpdesk_inbound
from policyops.services.helpdesk_writeback import Note, Result, deliver, expired
from policyops_contracts.clock import FixedClock
from policyops_contracts.helpdesk import TicketWakeup
from policyops_testing.zammad import NOW, FakeZammad, Fault, settings, sign, webhook


def test_seed_wires_the_zammad_7_2_webhook_and_trigger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = Path(__file__).resolve().parents[2] / "infra" / "compose"
    monkeypatch.syspath_prepend(str(directory))
    wire = runpy.run_path(str(directory / "helpdesk_seed.py"))["wire"]
    config = settings().connections[0]
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps({"connections": [config.model_dump(mode="json") | {
        "api_token": config.api_token.get_secret_value(), "signing_secret": config.signing_secret.get_secret_value(),
    }]}), encoding="utf-8")
    requests: list[tuple[str, str, dict[str, Any]]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        signing_secret = body.pop("signature_token", None)
        if request.url.path == "/api/v1/webhooks":
            if not isinstance(signing_secret, str) or not hmac.compare_digest(
                    signing_secret, config.signing_secret.get_secret_value()):
                pytest.fail("webhook signing secret did not match the configured value")
        elif signing_secret is not None:
            pytest.fail("unexpected signing secret in a non-webhook request")
        requests.append((request.method, request.url.path, body))
        return httpx.Response(201, json={"id": len(requests)})

    with httpx.Client(base_url="http://127.0.0.1:8081", transport=httpx.MockTransport(handle)) as zammad:
        assert wire(zammad, settings_file, "fixture", 8080, 8) == {"webhook_id": 1, "trigger_id": 2}

    template = '{"ticket_id":"#{ticket.id}","updated_at":"#{ticket.updated_at.iso8601}"}'
    assert requests == [
        ("POST", "/api/v1/webhooks", {
            "name": "PolicyOps fixture", "active": True, "ssl_verify": True,
            "endpoint": "http://policyops-helpdesk:8080/api/v1/integrations/zammad/fixture/events",
            "customized_payload": True, "custom_payload": template,
        }),
        ("POST", "/api/v1/triggers", {
            "name": "PolicyOps fixture", "active": True, "activator": "action",
            "execution_condition_mode": "always",
            "condition": {"ticket.group_id": {"operator": "is", "value": ["7", "8"]}},
            "perform": {"notification.webhook": {"webhook_id": 1}},
        }),
    ]
    assert json.loads(requests[0][2]["custom_payload"]) == {
        "ticket_id": "#{ticket.id}", "updated_at": "#{ticket.updated_at.iso8601}",
    }


def test_verify_before_opening_a_workspace_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    config, other = settings().connections[0], settings().connections[0]
    app_settings = settings(config.workspace_id).model_copy(update={"connections": (config,)})
    clock = FixedClock(NOW)
    transactions = []
    received: list[bytes] = []

    @contextmanager
    def workspace(_engine: Engine, workspace_id: object) -> Iterator[Connection]:
        transactions.append(workspace_id)
        yield cast(Connection, object())

    def enqueue(_connection: Connection, **fields: Any) -> None:
        received.append(fields["body"])

    monkeypatch.setattr(helpdesk_inbound, "workspace_transaction", workspace)
    monkeypatch.setattr(store, "enqueue_event", enqueue)
    service = helpdesk_inbound.Inbound(app_settings, cast(Engine, object()), FixedLeaseClock(clock))
    raw = webhook()
    signature = sign(config, raw)
    assert service.receive("unknown", raw, [signature], []) == 404
    for headers in ([], [b"sha1=no"], [signature, signature], [signature + b"," + signature], [sign(other, raw)]):
        assert service.receive(config.connection_id, raw, headers, []) == 401
    assert service.receive(config.connection_id, raw + b" ", [signature], []) == 401
    assert service.receive(config.connection_id, b"broken", [sign(config, b"broken")], []) == 400
    duplicate = b'{"ticket_id":"unrelated field content",' + raw[1:]
    assert service.receive(config.connection_id, duplicate, [sign(config, duplicate)], []) == 400
    assert transactions == []
    old = webhook(updated_at=NOW - timedelta(days=1, seconds=1))
    assert service.receive(config.connection_id, old, [sign(config, old)], []) == 400
    assert received == []
    ruby_time = raw.replace(b"2026-11-24T10:00:00Z", b"2026-11-24 10:00:00 UTC")
    assert service.receive(config.connection_id, ruby_time, [sign(config, ruby_time)], []) == 400
    assert received == []
    assert service.receive(config.connection_id, raw, [signature], [b"delivery"]) == 202
    assert transactions == [config.workspace_id] * 2
    assert received == [raw]


def test_inbox_upsert_revives_only_eligible_rows() -> None:
    # Exercise the upsert's state transitions in memory. PostgreSQL role and concurrency
    # behavior is covered by the help desk integration tests.
    engine = create_engine("sqlite://")
    config = settings().connections[0]
    raw = webhook()
    with engine.begin() as connection:
        connection.execute(text("ATTACH DATABASE ':memory:' AS app"))
        connection.execute(text("""
            CREATE TABLE app.helpdesk_events (
                id TEXT PRIMARY KEY, workspace_id TEXT, connection_id TEXT, destination_sha256 TEXT,
                ticket_id INTEGER, event_updated_at TEXT, delivery_id TEXT, body_sha256 TEXT, payload BLOB,
                created_at TEXT, next_attempt_at TEXT, state TEXT DEFAULT 'pending', reason TEXT,
                attempts INTEGER DEFAULT 0, revivals INTEGER DEFAULT 0, version INTEGER DEFAULT 1,
                UNIQUE (workspace_id, connection_id, body_sha256)
            )
        """))

        def enqueue(now: datetime = NOW) -> bool:
            return store.enqueue_event(connection, workspace=config.workspace_id, connection_id=config.connection_id,
                destination=destination_digest(config.api_origin, config.integration_user_id),
                wakeup=TicketWakeup.model_validate_json(raw), delivery_id=None, body=raw, now=now)

        def set_terminal(state: str, reason: str | None) -> None:
            connection.execute(text("UPDATE app.helpdesk_events SET state=:state, reason=:reason, attempts=8"),
                               {"state": state, "reason": reason})

        assert enqueue()
        for state, reason in [("applied", None), ("stale", None), ("rejected_mapping", "disallowed_group"),
                              *(("failed", reason) for reason in REJECTIONS.values())]:
            set_terminal(state, reason)
            assert not enqueue()
        for revival, (state, reason) in enumerate([
            ("failed", "pre_send"), ("incomplete_scan", "incomplete_scan"), ("failed", "internal_error"),
        ], start=1):
            set_terminal(state, reason)
            now = NOW + timedelta(minutes=revival)
            assert enqueue(now)
            assert not enqueue(now)
            row = connection.execute(text("""
                SELECT state, reason, attempts, revivals, version, next_attempt_at
                FROM app.helpdesk_events
            """)).one()
            assert tuple(row) == ("pending", None, 0, revival, revival + 1, now.strftime("%Y-%m-%d %H:%M:%S.%f"))
        set_terminal("failed", "pre_send")
        assert not enqueue()
    engine.dispose()


@pytest.mark.parametrize(("queue", "state", "recording", "expected"), [
    (store.Queue.EVENTS, "pending", "ok", "failed"),
    (store.Queue.WRITEBACKS, "pending", "ok", "failed"),
    (store.Queue.WRITEBACKS, "dispatching", "ok", "unconfirmed"),
    (store.Queue.EVENTS, "pending", "stale", None),
    (store.Queue.WRITEBACKS, "dispatching", "error", None),
])
def test_worker_isolates_step_errors(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
                                     queue: store.Queue, state: str, recording: str, expected: str | None) -> None:
    cfg = settings()
    workspace = cfg.connections[0].workspace_id
    engine = cast(Engine, object())
    broken, next_id = uuid4(), uuid4()
    seen: list[UUID] = []
    results: list[tuple[UUID, str, str | None]] = []
    active: list[Connection] = []

    @contextmanager
    def transaction(*_args: object, **_kwargs: object) -> Iterator[Connection]:
        connection = cast(Connection, object())
        assert active == []
        active.append(connection)
        try:
            yield connection
        finally:
            active.pop()

    def lock_row(connection: Connection, _queue: store.Queue, identity: UUID) -> RowMapping:
        assert active == [connection]
        seen.append(identity)
        is_broken = identity == broken
        version = 2 if is_broken and recording == "stale" and seen.count(broken) > 1 else 1
        return cast(RowMapping, SimpleNamespace(
            state=state if is_broken else "pending", next_attempt_at=NOW, lease_expires_at=None, version=version,
            connection_id="fixture" if is_broken else "other", destination_sha256="unused",
            deadline_at=NOW + timedelta(minutes=5), reconciles=0, attempts=0, id=identity,
        ))

    def poison(*_args: object) -> Never:
        raise ImmutableRecord("sensitive error detail")

    def record(connection: Connection, identity: UUID, state: str, reason: str | None,
               _next_at: datetime, **_kwargs: object) -> None:
        assert active == [connection]
        if identity == broken and recording == "error":
            raise RuntimeError("sensitive recording detail")
        results.append((identity, state, reason))

    monkeypatch.setattr(runtime, "verify_runtime_role", lambda *_: None)
    monkeypatch.setattr(runtime, "transaction", transaction)
    monkeypatch.setattr(runtime, "workspace_transaction", transaction)
    monkeypatch.setattr(store, "due", lambda _conn, current, _now: [(workspace, broken), (workspace, next_id)]
                        if current == queue else [])
    monkeypatch.setattr(store, "lock_row", lock_row)
    monkeypatch.setattr(store, "event_result", record)
    monkeypatch.setattr(store, "writeback_result", record)
    worker = runtime.HelpdeskWorker(env="test", app=engine, discovery=engine,
                                    settings=cfg, clock=FixedLeaseClock(FixedClock(NOW)))
    monkeypatch.setattr(worker, "_config", lambda _tenant, connection_id, _destination:
                        poison() if connection_id == "fixture" else None)
    monkeypatch.setattr(worker, "_authority", lambda _conn, _tenant, row: poison() if row.id == broken else None)
    worker.run_once()
    assert seen == [broken, broken, next_id]
    assert results == [
        *([] if expected is None else [(broken, expected, "internal_error")]),
        (next_id, "failed", "connection_changed" if queue == store.Queue.EVENTS else "authority_changed"),
    ]
    assert [(item.message, vars(item)["error_type"], item.exc_info) for item in caplog.records] == [
        ("helpdesk_step_failed", "ImmutableRecord", None),
        *([("helpdesk_step_failure_record_failed", "RuntimeError", None)] if recording == "error" else []),
    ]


def test_remote_mark_mapping_and_article_provenance() -> None:
    config = settings().connections[0]
    fake = FakeZammad(config)
    with closing(ZammadClient(config, transport=fake.transport)) as client:
        ticket = client.ticket(42)
        articles = client.articles(42)
    destination = destination_digest(config.api_origin, config.integration_user_id)
    link = Link(uuid4(), config.workspace_id, config.connection_id, ticket.id, ticket.customer_id, "demo_user_1",
                destination, uuid4(), ticket.group_id, ticket.state_id, ticket.updated_at, 100, NOW)
    decide = helpdesk_inbound.disposition
    assert decide(config, ticket, articles, link, "demo_user_1").state == "applied"
    advanced = replace(link, ticket_updated_at=NOW + timedelta(seconds=1), max_article_id=102)
    assert decide(config, ticket, articles, advanced, "demo_user_1").state == "stale"
    assert decide(config, ticket, articles, replace(link, max_article_id=101), "demo_user_1").state == "stale"
    assert decide(config, ticket, articles, None, None).reason == "unmapped_requester"
    changed = ticket.model_copy(update={"customer_id": 12})
    assert decide(config, changed, articles, link, "demo_user_2").reason == "requester_changed"
    outside = ticket.model_copy(update={"group_id": 8})
    assert decide(config, outside, articles, link, "demo_user_1").reason == "disallowed_group"
    [article] = articles
    assert imported_text(article, 19) == "yes"
    assert imported_text(article.model_copy(update={"internal": True}), 19) is None
    assert imported_text(article.model_copy(update={"created_by_id": 19}), 19) is None
    html = article.model_copy(update={"content_type": "text/html", "body": "<b>secret text</b>"})
    assert imported_text(html, 19) == "[Help desk article omitted because it contains HTML.]"
    assert imported_text(article.model_copy(update={"body": "你" * 4000}), 19) == "你" * 4000
    oversized = imported_text(article.model_copy(update={"body": "你" * 4001}), 19)
    assert oversized and "omitted" in oversized and "你" not in oversized


@pytest.mark.parametrize("limit", ["bytes", "count", "ticket", "id"])
def test_incomplete_scans_fail_closed(limit: str) -> None:
    config = settings().connections[0]
    fake = FakeZammad(config)
    if limit == "bytes":
        fake.articles[0]["body"] = "x" * (256 * 1024)
    elif limit == "count":
        fake.articles = [fake.articles[0] | {"id": n} for n in range(1, 202)]
    elif limit == "ticket":
        fake.articles[0]["ticket_id"] = 43
    else:
        fake.articles.append(fake.articles[0])
    with closing(ZammadClient(config, transport=fake.transport)) as client, pytest.raises(
            RemoteError, match=r"^incomplete_scan$"):
        client.articles(42)


def note_for(fake: FakeZammad) -> Note:
    operation = uuid4()
    body = note_body(operation, 1)
    return Note(operation, 42, 11, fake.config.integration_user_id, fake.config.allowed_group_ids,
                body, digest(body.encode()))


def send(fake: FakeZammad, note: Note, *, possibly_sent: bool = False, reconciles: int = 0) -> Result:
    def checkpoint() -> bool:
        assert not possibly_sent
        assert fake.calls[-1] == ("GET", "/api/v1/tickets/42")
        return True

    with closing(ZammadClient(fake.config, transport=fake.transport)) as client:
        result = deliver(client, note, possibly_sent=possibly_sent, reconciles=reconciles, checkpoint=checkpoint)
    assert result is not None
    return result


def test_lookup_first_and_duplicates() -> None:
    fake = FakeZammad(settings().connections[0])
    note = note_for(fake)
    fake.add(note.body, article_id=102)
    assert send(fake, note).matches[0].id == 102
    fake.add(note.body, article_id=104)
    result = send(fake, note)
    assert (result.state, result.reason, [item.id for item in result.matches]) == (
        "succeeded", "duplicate_detected", [102, 104])
    assert fake.posts == []


def test_pre_send_outage_recovers_and_ignores_spoofed_note() -> None:
    fake = FakeZammad(settings().connections[0])
    note = note_for(fake)
    fake.add(note.body, article_id=102, author=11, internal=False)
    fake.add(note.body, article_id=103, internal=False)
    fake.add(note.body, article_id=104, author=11)
    fake.add(note.body + "\nextra", article_id=105)
    fake.lookup_outage = True
    assert send(fake, note).state == "pending" and not fake.posts
    fake.lookup_outage = False
    fake.fault = "connect"
    assert send(fake, note).reason == "pre_send"
    assert len(fake.articles) == 5
    result = send(fake, note)
    assert result.state == "succeeded" and len(fake.articles) == 6
    assert [payload["body"] for payload in fake.posts] == [note.body, note.body]


@pytest.mark.parametrize("fault", ["lost", "commit_503"])
def test_possibly_sent_recovers_by_lookup_after_restart(fault: Fault) -> None:
    fake = FakeZammad(settings().connections[0])
    fake.fault = fault
    note = note_for(fake)
    assert send(fake, note).state == "dispatching"
    retry = send(fake, note, possibly_sent=True)
    assert retry.state == "succeeded" and retry.matches[0].id == 102
    assert retry.matches[0].created_at == datetime.fromisoformat(fake.ticket["updated_at"])
    assert len(fake.posts) == 1


def test_possible_send_with_no_match_exhausts_lookups() -> None:
    fake = FakeZammad(settings().connections[0])
    fake.fault = "drop"
    note = note_for(fake)
    assert send(fake, note).state == "dispatching"
    assert [send(fake, note, possibly_sent=True, reconciles=attempt).state for attempt in range(RECONCILES)] == [
        "dispatching", "dispatching", "unconfirmed"]
    assert len(fake.posts) == 1
    assert expired(possibly_sent=True, now=NOW, deadline=NOW, limit_reached=False) == Result(
        "unconfirmed", "deadline_elapsed")
    assert expired(possibly_sent=False, now=NOW, deadline=NOW, limit_reached=False) == Result(
        "failed", "deadline_elapsed")


@pytest.mark.parametrize(("fault", "reason"), [("401", "unauthorized"), ("403", "forbidden"),
                                             ("404", "not_found"), ("422", "unprocessable")])
def test_rejected_post_is_terminal(fault: Fault, reason: str) -> None:
    fake = FakeZammad(settings().connections[0])
    fake.fault = fault
    assert send(fake, note_for(fake)) == Result("failed", reason)
    assert len(fake.posts) == 1 and len(fake.articles) == 1
