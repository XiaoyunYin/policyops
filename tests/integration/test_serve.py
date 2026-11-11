"""The environment-configured API server on real PostgreSQL and the owned pinned Dex (fictional users): the actual
`create_served_app` factory and lifespan, served by uvicorn on an ephemeral loopback port and driven over real HTTP
(an httpx client standing in for a browser; no real browser). Covers the distinct actual runtime logins, refusal of
a privileged role and a wrong credential with everything released, partial startup after the OIDC client is opened,
shutdown release, and the supported `python -m policyops.api.serve` entry failing with a sanitized message."""

from __future__ import annotations

from collections.abc import Iterator
import html
import os
import re
import socket
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urljoin
from uuid import UUID, uuid4

import httpx
import pytest
import uvicorn

from policyops.api import serve
from policyops.api.app import build_auth_runtime
from policyops.auth.oidc import OidcClient
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction
from policyops.persistence.records import Membership, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_contracts.clock import SystemClock
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.dex import CLIENT_ID, OwnedDex
from policyops_testing.live_server import serve as live


pytestmark = pytest.mark.postgres
ORIGIN = "http://127.0.0.1:8000"  # the public origin Dex redirects to; requests go to the ephemeral port
REDIRECT = ORIGIN + "/api/v1/auth/callback"
FORM_ACTION = re.compile(r'<form[^>]*method="post"[^>]*action="([^"]+)"', re.IGNORECASE)
CANARY = "canary-9Wd4-wrong-app-password"
NAMES = tuple(serve.APPLICATION_NAMES.values())


@pytest.fixture(scope="module")
def serve_db(app_cluster: AppCluster) -> Iterator[AppDatabase]:
    database = app_cluster.create_database("serve")
    database.upgrade()
    yield database
    database.dispose()


def settings_env(dex: OwnedDex, database: AppDatabase, **changes: str) -> dict[str, str]:
    server = database.server
    return {"POLICYOPS_ENV": "local", "POLICYOPS_PUBLIC_ORIGIN": ORIGIN, "POLICYOPS_OIDC_ISSUER": dex.issuer,
            "POLICYOPS_OIDC_CLIENT_ID": CLIENT_ID,
            "POLICYOPS_OIDC_CLIENT_SECRET":
                dex.client_secret,
            "POLICYOPS_DB_HOST": "127.0.0.1", "POLICYOPS_DB_PORT": str(server.port),
            "POLICYOPS_DB_NAME": database.name, "POLICYOPS_DB_SSLMODE": "disable", "POLICYOPS_DB_POOL_SIZE": "2",
            "POLICYOPS_DB_AUTH_PASSWORD":
                server.passwords[AUTH_RUNTIME],
            "POLICYOPS_DB_APP_PASSWORD":
                server.passwords[APP_RUNTIME],
            **changes}


@pytest.fixture
def configured(dex: OwnedDex, serve_db: AppDatabase, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    for name in list(os.environ):
        if (name.startswith("POLICYOPS_") and name != "POLICYOPS_TEMP_DIR") or name in serve.REFUSED_LIBPQ_ENV:
            monkeypatch.delenv(name)
    values = settings_env(dex, serve_db)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


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


def lifespan_server(app: Any) -> Any:
    return uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False, lifespan="on", ws="none"))


class Lifespan:
    """Drives the ASGI lifespan protocol directly (startup-failure cases, without a server thread)."""

    def __init__(self, app: serve.ServedApp) -> None:
        self.app, self.sent = app, list[dict[str, Any]]()

    def startup_failure(self) -> dict[str, Any]:
        import asyncio

        async def scenario() -> None:
            async def receive() -> dict[str, Any]:
                return {"type": "lifespan.startup"}

            async def send(message: dict[str, Any]) -> None:
                self.sent.append(message)
            await asyncio.wait_for(self.app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive,
                                            send), 60)  # type: ignore[arg-type]

        asyncio.run(scenario())
        assert len(self.sent) == 1 and self.sent[0]["type"] == "lifespan.startup.failed", self.sent
        return self.sent[0]


def issuer_login(dex: OwnedDex, authorization_url: str, user: str) -> str:
    """A browser at the issuer: follow Dex's redirects, submit its password form, stop at our redirect URI."""
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=10) as browser:
        response = browser.get(authorization_url)
        for _ in range(12):
            if response.status_code in (302, 303):
                location = urljoin(str(response.url), response.headers["location"])
                if location.startswith(REDIRECT):
                    return location
                assert location.startswith(dex.issuer), location
                response = browser.get(location)
                continue
            form = FORM_ACTION.search(response.text)
            assert response.status_code == 200 and form and 'name="password"' in response.text
            response = browser.post(urljoin(str(response.url), html.unescape(form.group(1))),
                                    data={"login": f"{user}@example.invalid", "password": dex.passwords[user]})
    raise AssertionError("Dex did not redirect to the callback")


def test_served_api_over_real_http_with_distinct_runtime_logins(configured: dict[str, str], dex: OwnedDex,
                                                                serve_db: AppDatabase,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[OidcClient] = []
    real_init = OidcClient.__post_init__

    def record(client: OidcClient) -> None:
        real_init(client)
        opened.append(client)
    monkeypatch.setattr(OidcClient, "__post_init__", record)  # observation only

    served = serve.create_served_app()
    assert server_logins(serve_db) == [] and opened == []  # the factory opened nothing
    with live(served, server_factory=lifespan_server) as url, \
            httpx.Client(base_url=url, trust_env=False, follow_redirects=False, timeout=15) as browser:
        # The started server's only logins: each engine authenticated as its own restricted runtime role.
        assert server_logins(serve_db) == [("policyops-api-app", APP_RUNTIME), ("policyops-api-auth", AUTH_RUNTIME)]
        assert browser.get("/api/v1/health/live").json() == {"status": "ok"}
        started = browser.get("/api/v1/auth/login", params={"return_to": "/cases"})
        assert started.status_code == 302 and started.headers["location"].startswith(dex.issuer)
        callback = issuer_login(dex, started.headers["location"], "alice")
        done = browser.get(callback.removeprefix(ORIGIN))
        assert done.status_code == 303 and done.headers["location"] == "/cases"
        me = browser.get("/api/v1/me")
        assert me.status_code == 200 and me.headers["cache-control"] == "no-store"
        principal = me.json()["principal_id"]
        assert me.json()["workspaces"] == []

        workspace = Workspace(id=uuid4(), slug=f"serve-{uuid4().hex[:8]}", name="Served workspace",
                              created_at=SystemClock().now())
        with transaction(serve_db.engine(AUTH_RUNTIME)) as conn:  # trusted synthetic provisioning (test setup)
            repo.create_workspace(conn, workspace)
            repo.add_membership(conn, Membership(id=uuid4(), workspace_id=workspace.id, principal_id=UUID(principal),
                                                 role="analyst", created_at=SystemClock().now()))
        csrf = {"X-CSRF-Token": browser.cookies.get("policyops_csrf_local") or ""}
        select = {"workspace_id": str(workspace.id)}
        no_origin = browser.post("/api/v1/auth/workspace", json=select, headers=csrf)
        assert no_origin.status_code == 403
        assert browser.post("/api/v1/auth/workspace", json=select,
                            headers={"Origin": ORIGIN, **csrf}).status_code == 204

        expected = {"PolicyOps-Expected-Principal": principal, "PolicyOps-Expected-Workspace": str(workspace.id)}
        assert browser.get("/api/v1/cases").status_code == 400  # the expected-context headers are required
        listed = browser.get("/api/v1/cases", headers=expected)
        assert listed.status_code == 200 and listed.json()["items"] == []
        write = {"Origin": ORIGIN, "X-CSRF-Token": browser.cookies.get("policyops_csrf_local") or "", **expected}
        created = browser.post("/api/v1/cases", json={"scenario": "retail"},
                               headers={**write, "Idempotency-Key": str(uuid4())})
        assert created.status_code == 201
        case_id, etag = created.json()["case_id"], created.headers["etag"]
        run = browser.post(f"/api/v1/cases/{case_id}/runs", json={"mode": "workbench"},
                           headers={**write, "Idempotency-Key": str(uuid4()), "If-Match": etag})
        assert run.status_code == 503 and run.json()["rule_id"] == "runtime.unconfigured"  # no runtime installed
        other = {**expected, "PolicyOps-Expected-Workspace": str(uuid4())}
        mismatch = browser.get("/api/v1/cases", headers=other)
        assert mismatch.status_code == 409 and mismatch.json()["rule_id"] == "auth.workspace_changed"
        assert len(opened) == 1 and not opened[0]._http.is_closed
    # Lifespan shutdown released both engines (no login left) and the OIDC client.
    assert wait_no_logins(serve_db) == []
    assert all(client._http.is_closed for client in opened) and served.close() == []


def test_privileged_runtime_role_is_refused_and_nothing_stays_open(configured: dict[str, str],
                                                                   serve_db: AppDatabase) -> None:
    with serve_db.superuser() as conn:
        conn.execute(f"ALTER ROLE {APP_RUNTIME} CREATEDB")
    try:
        failed = Lifespan(serve.create_served_app()).startup_failure()
    finally:
        with serve_db.superuser() as conn:
            conn.execute(f"ALTER ROLE {APP_RUNTIME} NOCREATEDB")
    assert failed["message"] == ("API server startup failed at app runtime role check: RuntimeRoleError: "
                                 f"{APP_RUNTIME} has privileges a runtime role must not have")
    assert wait_no_logins(serve_db) == []


def test_partial_startup_after_the_oidc_client_releases_real_resources(configured: dict[str, str],
                                                                      serve_db: AppDatabase,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[OidcClient] = []
    real_build = build_auth_runtime

    def build(*args: Any, **kwargs: Any) -> Any:
        runtime = real_build(*args, **kwargs)
        opened.append(runtime.service.oidc)
        assert server_logins(serve_db) == [("policyops-api-app", APP_RUNTIME), ("policyops-api-auth", AUTH_RUNTIME)]
        return runtime

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("injected after the runtime was wired")
    monkeypatch.setattr(serve, "build_auth_runtime", build)
    monkeypatch.setattr(serve, "create_app", fail)
    failed = Lifespan(serve.create_served_app()).startup_failure()
    assert failed["message"] == "API server startup failed at application: RuntimeError"
    assert len(opened) == 1 and opened[0]._http.is_closed
    assert wait_no_logins(serve_db) == []


@pytest.mark.parametrize(("variable", "expected"), [
    ("POLICYOPS_DB_APP_PASSWORD", "app runtime role check: OperationalError (no SQLSTATE: password authentication "
                                  "refused)"),
    # A closed loopback port: refused (Linux) or, as observed on Windows, a bounded psycopg ConnectionTimeout.
    ("POLICYOPS_DB_PORT", ("auth runtime role check: OperationalError (no SQLSTATE: connection refused)",
                           "auth runtime role check: ConnectionTimeout (no SQLSTATE: connect timeout)")),
])
def test_wrong_credential_or_endpoint_fails_with_a_category_and_releases(
        configured: dict[str, str], serve_db: AppDatabase, monkeypatch: pytest.MonkeyPatch, variable: str,
        expected: str | tuple[str, ...]) -> None:
    monkeypatch.setenv(variable, CANARY if variable.endswith("PASSWORD") else str(_free_port()))
    started = time.monotonic()
    failed = Lifespan(serve.create_served_app()).startup_failure()
    accepted = (expected,) if isinstance(expected, str) else expected
    assert failed["message"] in tuple("API server startup failed at " + text for text in accepted)
    assert time.monotonic() - started < 30  # bounded: a 5 s libpq connect timeout per attempt
    for secret in (CANARY, *serve_db.server.passwords.values()):
        assert secret not in failed["message"]
    assert wait_no_logins(serve_db) == []


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def test_supported_entry_fails_startup_without_rendering_secrets(configured: dict[str, str], dex: OwnedDex,
                                                                 serve_db: AppDatabase) -> None:
    env = {name: value for name, value in os.environ.items()
           if not name.startswith("POLICYOPS_") or name == "POLICYOPS_TEMP_DIR"}
    env.update(settings_env(dex, serve_db, POLICYOPS_DB_APP_PASSWORD=CANARY), PYTHONDONTWRITEBYTECODE="1")
    process = subprocess.Popen([sys.executable, "-B", "-X", "utf8", "-m", "policyops.api.serve", "--port",
                                str(_free_port())], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output, _ = process.communicate(timeout=90)
    finally:
        if process.poll() is None:  # never left running: the owned child is stopped and reaped
            process.kill()
            process.communicate(timeout=30)
    text = output.decode("utf-8", "replace")
    assert process.returncode == 3, text[-3000:]
    assert ("API server startup failed at app runtime role check: OperationalError (no SQLSTATE: password "
            "authentication refused)") in text
    assert "Application startup failed. Exiting." in text
    for secret in (CANARY, dex.client_secret, *serve_db.server.passwords.values()):
        assert secret not in text
    assert "Uvicorn running on" not in text  # nothing was bound
    assert wait_no_logins(serve_db) == []
