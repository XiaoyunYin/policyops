"""The web app's actual API client, over real HTTP, to the environment-configured served API on real PostgreSQL (T25).

`apps/web/src/api/client.ts` is executed by Node through the real Vite dev server (the unmodified `vite.config.ts`,
port chosen by the OS) and its real `/api` proxy, which forwards to the actual `create_served_app()` served by
uvicorn on an owned loopback port, which writes to the owned PostgreSQL under the restricted runtime roles. Covered:
create a case, post a staff note, list messages, an explicit identical-key / If-Match replay (the original response,
one effect), an expected-context mismatch (409, no effect), a stale If-Match (409, no effect) and the 503
`runtime.unconfigured` start (no run created). The wire log and the database rows are asserted. No model is called.

Limits, stated plainly. Node is not a browser: the Cookie and Origin headers and `document.cookie` (the readable CSRF
cookie) are fixture emulation, so this proves nothing about SameSite, CORS preflight or rendering. The session is
minted by trusted fixture provisioning (the same rows a login writes), not by a live OIDC login (the served API's real
Dex login is covered by test_serve.py); the issuer is a loopback address nothing listens on, and the in-process
network guard would fail any request to it. No component of the web UI is involved, only the client module.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack
from datetime import timedelta
import json
import os
from pathlib import Path
import secrets
import socket
import time
from typing import Any
from uuid import UUID, uuid4

import pytest
import uvicorn

from policyops.api import serve
from policyops.auth import tokens
from policyops.persistence import identity
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction
from policyops.persistence.records import Membership, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_contracts.clock import SystemClock
from policyops_testing import network, redaction
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.live_server import serve as live
from policyops_testing.operator_client import ClientReply, OperatorClientHost, checked_report_path, write_report


pytestmark = pytest.mark.postgres
WEB_ROOT = Path(__file__).resolve().parents[2] / "apps" / "web"
ISSUER = "http://127.0.0.1:9"  # a valid loopback issuer that nothing listens on and the harness never contacts
SESSION_COOKIE, CSRF_COOKIE = "policyops_session_local", "policyops_csrf_local"
NAMES = tuple(serve.APPLICATION_NAMES.values())
TEXT = "Customer asked for a refund on order 1042; waiting on warehouse confirmation."


@pytest.fixture(scope="module")
def proof_db(app_cluster: AppCluster) -> Iterator[AppDatabase]:
    database = app_cluster.create_database("operator_http")
    database.upgrade()
    yield database
    database.dispose()


def server_logins(database: AppDatabase) -> list[tuple[str, str]]:
    with database.superuser() as conn:
        rows = conn.execute("SELECT application_name, usename FROM pg_stat_activity WHERE datname = %s "
                            "AND application_name = ANY(%s) ORDER BY 1, 2", (database.name, list(NAMES))).fetchall()
    return [(row[0], row[1]) for row in rows]


def wait_no_logins(database: AppDatabase, timeout: float = 10.0) -> list[tuple[str, str]]:
    deadline = time.monotonic() + timeout
    while (logins := server_logins(database)) and time.monotonic() < deadline:
        time.sleep(0.05)
    return logins


def accepts_connections(port: int) -> bool:
    with network.allow("127.0.0.1", port), socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


class Provisioned:
    """Trusted fixture provisioning: a workspace, an analyst member and the session rows a login would have written.
    The raw cookie and CSRF values stay here (registered for redaction); only their digests reach the database."""

    def __init__(self, database: AppDatabase) -> None:
        now = SystemClock().now()
        self.session, self.csrf = tokens.new_token(), tokens.new_token()
        redaction.register(self.session, self.csrf)
        self.workspace_id = uuid4()
        with transaction(database.engine(AUTH_RUNTIME)) as conn:
            self.principal_id = identity.find_or_create_principal(
                conn, issuer=ISSUER, subject=f"http-proof-{uuid4().hex[:12]}", display_name="HTTP proof analyst",
                now=now)
            repo.create_workspace(conn, Workspace(id=self.workspace_id, slug=f"http-{uuid4().hex[:8]}",
                                                  name="Client HTTP proof", created_at=now))
            repo.add_membership(conn, Membership(id=uuid4(), workspace_id=self.workspace_id,
                                                 principal_id=self.principal_id, role="analyst", created_at=now))
            identity.create_session(conn, session_id=uuid4(), principal_id=self.principal_id,
                                    workspace_id=self.workspace_id, cookie_sha256=tokens.digest(self.session),
                                    csrf_sha256=tokens.digest(self.csrf), now=now, expires_at=now + timedelta(hours=1),
                                    rotated_from=None)

    def forget(self) -> None:
        redaction.forget(self.session, self.csrf)


class Stack:
    """The composed system under test: Node/Vite host -> Vite proxy -> served API (uvicorn) -> PostgreSQL."""

    def __init__(self, database: AppDatabase, monkeypatch: pytest.MonkeyPatch, fail_after_host: bool = False) -> None:
        self.database, self.monkeypatch, self.fail_after_host = database, monkeypatch, fail_after_host
        self.owned = ExitStack()
        self.host: OperatorClientHost | None = None
        self.served: serve.ServedApp | None = None
        self.api_port = 0
        self._listener: socket.socket | None = None
        self.secrets = (self.password(AUTH_RUNTIME), self.password(APP_RUNTIME))
        self.client_secret = secrets.token_urlsafe(24)
        redaction.register(*self.secrets, self.client_secret)

    def password(self, role: str) -> str:
        return self.database.server.passwords[role]

    def listener(self) -> socket.socket:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self._listener

    def server_factory(self, _app: Any) -> Any:
        """Called by `live` after it bound its owned listener: learn that port, start the Node/Vite host aimed at it
        (owned by the outer stack from the moment it exists, even if API startup then fails), learn the real Vite
        origin, configure the served API for exactly that origin, and return the uvicorn server."""
        assert self._listener is not None
        self.api_port = self._listener.getsockname()[1]
        self.host = OperatorClientHost.start(web_root=WEB_ROOT, proxy_port=self.api_port,
                                             secrets=(*self.secrets, self.client_secret))
        self.owned.enter_context(self.host)  # release knows the active error (it is never replaced)
        if self.fail_after_host:
            raise RuntimeError("injected failure after the Node host was started")
        server = self.database.server
        for name in list(os.environ):
            if (name.startswith("POLICYOPS_") and name != "POLICYOPS_TEMP_DIR") or name in serve.REFUSED_LIBPQ_ENV:
                self.monkeypatch.delenv(name)
        values = {"POLICYOPS_ENV": "local", "POLICYOPS_PUBLIC_ORIGIN": self.host.origin,
                  "POLICYOPS_OIDC_ISSUER": ISSUER, "POLICYOPS_OIDC_CLIENT_ID": "policyops-http-proof",
                  "POLICYOPS_OIDC_CLIENT_SECRET":
                      self.client_secret,
                  "POLICYOPS_DB_HOST": "127.0.0.1", "POLICYOPS_DB_PORT": str(server.port),
                  "POLICYOPS_DB_NAME": self.database.name, "POLICYOPS_DB_SSLMODE": "disable",
                  "POLICYOPS_DB_POOL_SIZE": "2", "POLICYOPS_DB_AUTH_PASSWORD":
                      self.password(AUTH_RUNTIME),
                  "POLICYOPS_DB_APP_PASSWORD":
                      self.password(APP_RUNTIME)}
        for name, value in values.items():
            self.monkeypatch.setenv(name, value)
        self.served = serve.create_served_app()
        self.owned.callback(self.served.close)
        return uvicorn.Server(uvicorn.Config(self.served, log_level="warning", access_log=False, lifespan="on",
                                             ws="none"))

    def forget(self) -> None:
        redaction.forget(*self.secrets, self.client_secret)


def test_actual_client_http_roundtrip_on_postgres(proof_db: AppDatabase, monkeypatch: pytest.MonkeyPatch,
                                                  tmp_path: Path) -> None:
    raw_report = os.environ.get("POLICYOPS_HTTP_PROOF_REPORT")  # read first: the stack clears POLICYOPS_* settings
    # Optional, redacted; validated before anything runs or is created: a new file inside POLICYOPS_TEMP_DIR.
    report = (checked_report_path(raw_report, os.environ.get("POLICYOPS_TEMP_DIR"), WEB_ROOT.parents[1])
              if raw_report else None)
    stack = Stack(proof_db, monkeypatch)
    proof = Provisioned(proof_db)
    wire: list[tuple[str, dict[str, Any]]] = []
    try:
        with stack.owned:
            with live(None, listener_factory=stack.listener, server_factory=stack.server_factory) as api_url:
                assert api_url == f"http://127.0.0.1:{stack.api_port}"
                host = stack.host
                assert host is not None and stack.served is not None
                origin = host.origin
                assert origin != api_url  # the client talks to Vite's own origin; only the proxy knows the API port
                assert server_logins(proof_db) == [("policyops-api-app", APP_RUNTIME),
                                                   ("policyops-api-auth", AUTH_RUNTIME)]
                host.configure_session(session=proof.session, csrf=proof.csrf, session_cookie_name=SESSION_COOKIE,
                                       csrf_cookie_name=CSRF_COOKIE)
                wire = scenario(host, proof_db, proof, origin)
            assert wait_no_logins(proof_db) == []  # the API's lifespan released both engines
            assert stack.served is not None and stack.served.close() == []
        assert stack.host is not None and stack.host.issues == []
        assert not accepts_connections(int(origin.rsplit(":", 1)[1]))  # Vite is gone
    finally:
        proof.forget()
        stack.forget()
    if report is not None:
        write_report(report, (json.dumps([{"step": step, **entry} for step, entry in wire], indent=1) + "\n")
                     .encode("utf-8"))


def test_host_start_failure_after_vite_is_released(proof_db: AppDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
    """Control for the ownership scheme: the API factory fails after the Node host was started (so before `live`
    could yield). The primary error propagates and the exact Node/Vite child is released from the outer stack."""
    stack = Stack(proof_db, monkeypatch, fail_after_host=True)
    try:
        with (pytest.raises(RuntimeError, match="injected failure after the Node host was started"), stack.owned,
              live(None, listener_factory=stack.listener, server_factory=stack.server_factory)):
            raise AssertionError("must not be reached")  # pragma: no cover
        assert stack.host is not None and stack.host.origin
        assert stack.host.issues == [] and stack.host._process.poll() == 0 and stack.host.close() == []
        assert not accepts_connections(int(stack.host.origin.rsplit(":", 1)[1]))
        assert stack._listener is not None and stack._listener.fileno() == -1  # live closed its listener
        assert wait_no_logins(proof_db) == []
    finally:
        stack.forget()


def test_requests_really_traverse_the_vite_proxy() -> None:
    """Control: the client's only route to the API is Vite's proxy. Aimed at a loopback port nothing listens on, the
    same actual client call fails at the proxy (a non-envelope 5xx): the roundtrip cannot have bypassed it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    session, csrf = tokens.new_token(), tokens.new_token()
    redaction.register(session, csrf)
    host = OperatorClientHost.start(web_root=WEB_ROOT, proxy_port=closed_port, secrets=(session, csrf))
    try:
        host.configure_session(session=session, csrf=csrf, session_cookie_name=SESSION_COOKIE,
                               csrf_cookie_name=CSRF_COOKIE)
        reply = host.call("getMe")
        assert not reply.ok and reply.error is not None and reply.error["kind"] == "http"
        assert reply.error["code"] is None and reply.error["status"] in (500, 502, 503, 504)
        assert len(reply.wire) == 1 and reply.wire[0]["path"] == "/api/v1/me"
    finally:
        assert host.close() == []
        redaction.forget(session, csrf)


# -- the scenario -------------------------------------------------------------------------------------------------


def counts(database: AppDatabase, workspace_id: UUID) -> dict[str, int]:
    with database.superuser() as conn:
        def n(sql: str) -> int:
            row = conn.execute(sql, (workspace_id,)).fetchone()
            assert row is not None
            return int(row[0])
        return {"cases": n("SELECT count(*) FROM app.cases WHERE workspace_id = %s"),
                "messages": n("SELECT count(*) FROM app.case_messages WHERE workspace_id = %s"),
                "idempotency": n("SELECT count(*) FROM app.request_idempotency WHERE workspace_id = %s"),
                "audit": n("SELECT count(*) FROM app.audit_events WHERE workspace_id = %s"),
                "runs": n("SELECT count(*) FROM app.runs WHERE workspace_id = %s"),
                "run_events": n("SELECT count(*) FROM app.run_events WHERE workspace_id = %s"),
                "outbox": n("SELECT count(*) FROM app.outbox_events WHERE workspace_id = %s")}


def one(reply: ClientReply) -> dict[str, Any]:
    """The single wire exchange of a call (the client sends exactly one request per function)."""
    assert len(reply.wire) == 1 and reply.wire_dropped == 0, reply.wire
    assert reply.wire[0]["response"]["body_complete"] is True
    return reply.wire[0]


def new_key() -> str:
    return f"http-{uuid4().hex}"


def scenario(host: OperatorClientHost, database: AppDatabase, proof: Provisioned,
             origin: str) -> list[tuple[str, dict[str, Any]]]:
    log: list[tuple[str, dict[str, Any]]] = []
    workspace = proof.workspace_id

    def record(step: str, reply: ClientReply) -> ClientReply:
        log.extend((step, entry) for entry in reply.wire)
        return reply

    def expect_headers(entry: dict[str, Any], *, write: bool, key: str | None = None,
                       if_match: int | None = None) -> None:
        request = entry["request"]
        assert request["has_cookie"] is True
        assert request["headers"]["policyops-expected-principal"] == str(proof.principal_id)
        assert request["headers"]["policyops-expected-workspace"] == str(workspace)
        assert request["headers"]["accept"] == "application/json"
        assert request["has_csrf"] is write and (not write or request["csrf_matches_readable_cookie"] is True)
        assert ("origin" in request["headers"]) is write
        if write:
            assert request["headers"]["origin"] == origin  # the real Vite origin, as configured in AuthSettings
            assert request["headers"]["idempotency-key"] == key
            assert request["headers"].get("if-match") == (None if if_match is None else f'"{if_match}"')

    # 1. getMe: the session's principal, workspace and current role as the server reports them.
    me = record("getMe", host.call("getMe"))
    assert me.ok and one(me)["status"] == 200 and one(me)["response"]["headers"]["cache-control"] == "no-store"
    assert me.value["principal_id"] == str(proof.principal_id) and me.value["workspace_id"] == str(workspace)
    assert [w["roles"] for w in me.value["workspaces"]] == [["analyst"]]
    context = {"principal_id": me.value["principal_id"], "workspace_id": me.value["workspace_id"]}
    assert one(me)["request"]["has_csrf"] is False and "origin" not in one(me)["request"]["headers"]
    assert counts(database, workspace) == dict.fromkeys(counts(database, workspace), 0)

    empty = record("listCases", host.call("listCases", context=context))
    assert empty.ok and empty.value["items"] == []
    expect_headers(one(empty), write=False)

    # 2. createCase.
    create_key = new_key()
    created = record("createCase", host.call("createCase", key=create_key, context=context))
    assert created.ok and created.value["replayed"] is False
    case = created.value["value"]
    expect_headers(one(created), write=True, key=create_key)
    assert one(created)["status"] == 201 and one(created)["response"]["headers"]["etag"] == f'"{case["version"]}"'
    assert "idempotent-replayed" not in one(created)["response"]["headers"]
    after_create = counts(database, workspace)
    assert after_create["cases"] == 1 and after_create["idempotency"] == 1 and after_create["audit"] >= 1
    assert after_create["messages"] == 0 and after_create["runs"] == 0
    with database.superuser() as conn:
        row = conn.execute("SELECT version, status FROM app.cases WHERE id = %s AND workspace_id = %s",
                           (UUID(case["case_id"]), workspace)).fetchone()
    assert row is not None and row[0] == case["version"] and row[1] == case["status"]

    # 3. postMessage (staff note) against the case's current version.
    note_key = new_key()
    note = {"source": "staff_note", "text": TEXT}
    posted = record("postMessage", host.call("postMessage", case_id=case["case_id"], message=note, key=note_key,
                                             if_match=case["version"], context=context))
    assert posted.ok and posted.value["replayed"] is False
    expect_headers(one(posted), write=True, key=note_key, if_match=case["version"])
    message, new_case = posted.value["value"]["message"], posted.value["value"]["case"]
    assert message["source"] == "staff_note" and message["text"] == TEXT and message["entered_by"] == str(
        proof.principal_id)
    assert new_case["version"] > case["version"]
    assert one(posted)["status"] == 201 and one(posted)["response"]["headers"]["etag"] == f'"{new_case["version"]}"'
    after_post = counts(database, workspace)
    assert after_post == {**after_create, "messages": 1, "idempotency": 2, "audit": after_post["audit"]}
    assert after_post["audit"] > after_create["audit"]
    with database.superuser() as conn:
        stored = conn.execute("SELECT source, text, entered_by, sequence FROM app.case_messages WHERE case_id = %s "
                              "AND workspace_id = %s", (UUID(case["case_id"]), workspace)).fetchall()
    assert [tuple(r) for r in stored] == [("staff_note", TEXT, proof.principal_id, message["sequence"])]

    # 4. listMessages sees exactly that message.
    listed = record("listMessages", host.call("listMessages", case_id=case["case_id"], after=0, context=context))
    assert listed.ok and [m["message_id"] for m in listed.value["items"]] == [message["message_id"]]
    assert listed.value["items"][0]["text"] == TEXT
    assert listed.value["next_after_sequence"] in (None, message["sequence"])

    # 5. Explicit identical replay: same key, body and If-Match (now stale against the case) -> the original answer.
    replay = record("postMessage.replay", host.call("postMessage", case_id=case["case_id"], message=note, key=note_key,
                                                    if_match=case["version"], context=context))
    assert replay.ok and replay.value["replayed"] is True
    assert replay.value["value"] == posted.value["value"]  # the stored original response, not a new message
    expect_headers(one(replay), write=True, key=note_key, if_match=case["version"])
    assert one(replay)["status"] == 201 and one(replay)["response"]["headers"]["idempotent-replayed"] == "true"
    assert one(replay)["response"]["body_sha256"] == one(posted)["response"]["body_sha256"]
    assert counts(database, workspace) == after_post  # one effect

    # 6. Expected-context mismatch: a request composed for another workspace is refused and changes nothing.
    other = {**context, "workspace_id": str(uuid4())}
    mismatch_key = new_key()
    mismatch = record("postMessage.context_mismatch", host.call(
        "postMessage", case_id=case["case_id"], message={"source": "staff_note", "text": "must never be stored"},
        key=mismatch_key, if_match=new_case["version"], context=other))
    assert not mismatch.ok and mismatch.error is not None
    assert (mismatch.error["status"], mismatch.error["code"], mismatch.error["context_changed"]) == (
        409, "context_changed", True)
    assert one(mismatch)["status"] == 409
    assert one(mismatch)["request"]["headers"]["policyops-expected-workspace"] == other["workspace_id"]
    assert counts(database, workspace) == after_post
    with database.superuser() as conn:
        key_rows = conn.execute("SELECT count(*) FROM app.request_idempotency WHERE idempotency_key = %s",
                                (mismatch_key,)).fetchone()
    assert key_rows is not None and key_rows[0] == 0

    # 7. A stale If-Match with a fresh key is refused 409 api.stale_version and changes nothing.
    stale = record("postMessage.stale", host.call(
        "postMessage", case_id=case["case_id"], message={"source": "staff_note", "text": "stale write"},
        key=new_key(), if_match=case["version"], context=context))
    assert not stale.ok and stale.error is not None and stale.error["stale_version"] is True
    assert (stale.error["status"], stale.error["code"], stale.error["rule_id"]) == (
        409, "stale_version", "api.stale_version")
    assert counts(database, workspace) == after_post

    # 8. Start a run: no runtime is installed, so 503 runtime.unconfigured and no run (or event) is created.
    run_key = new_key()
    started = record("startRun", host.call("startRun", case_id=case["case_id"], key=run_key,
                                           if_match=new_case["version"], context=context))
    assert not started.ok and started.error is not None and started.error["runtime_unconfigured"] is True
    assert (started.error["status"], started.error["code"], started.error["rule_id"]) == (
        503, "unavailable", "runtime.unconfigured")
    expect_headers(one(started), write=True, key=run_key, if_match=new_case["version"])
    assert one(started)["status"] == 503
    final = counts(database, workspace)
    assert (final["runs"], final["run_events"], final["outbox"]) == (0, 0, 0)
    assert final["cases"] == 1 and final["messages"] == 1 and final["idempotency"] == 2
    with database.superuser() as conn:
        version_row = conn.execute("SELECT version FROM app.cases WHERE id = %s AND workspace_id = %s",
                                   (UUID(case["case_id"]), workspace)).fetchone()
    assert version_row is not None and version_row[0] == new_case["version"]  # unchanged by the refused start
    return log
