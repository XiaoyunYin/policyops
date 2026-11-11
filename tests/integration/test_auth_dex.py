"""The real OIDC flow against the owned pinned Dex (fictional users): login form, authorization code with PKCE
S256, client authentication, RS256 ID token signature/claims, then the PolicyOps session, on real PostgreSQL.
Runs in `local` mode, so no test hook (fake transport) is involved."""

from __future__ import annotations

from collections.abc import Iterator
import html
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit
from uuid import uuid4

from fastapi.testclient import TestClient
import httpx
from pydantic import SecretStr
import pytest
from sqlalchemy import text

from policyops.api.app import build_auth_runtime, create_app
from policyops.api.auth import EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER
from policyops.auth import tokens
from policyops.auth.oidc import OidcError
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction
from policyops.persistence.records import Membership, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.settings import AuthSettings
from policyops_contracts.clock import SystemClock
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.dex import CLIENT_ID, OwnedDex


pytestmark = pytest.mark.postgres
ORIGIN = "http://127.0.0.1:8000"
REDIRECT = ORIGIN + "/api/v1/auth/callback"
FORM_ACTION = re.compile(r'<form[^>]*method="post"[^>]*action="([^"]+)"', re.IGNORECASE)


@pytest.fixture(scope="module")
def dex_db(app_cluster: AppCluster) -> Iterator[AppDatabase]:
    database = app_cluster.create_database("dex")
    database.upgrade()
    yield database
    database.dispose()


@pytest.fixture
def app(dex: OwnedDex, dex_db: AppDatabase) -> Iterator[Any]:
    settings = AuthSettings(env="local", public_origin=ORIGIN, oidc_issuer=dex.issuer, oidc_client_id=CLIENT_ID,
                            oidc_client_secret=SecretStr(dex.client_secret))
    runtime = build_auth_runtime(settings, auth_engine=dex_db.engine(AUTH_RUNTIME),
                                 app_engine=dex_db.engine(APP_RUNTIME), clock=SystemClock())
    yield create_app(runtime), runtime
    runtime.service.oidc.close()


def issuer_login(dex: OwnedDex, authorization_url: str, user: str, password: str) -> tuple[str | None, str]:
    """A browser at the issuer: follow Dex's redirects, submit its password form, stop at our redirect URI.
    Returns (callback URL or None, last Dex page text)."""
    submitted = False
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=10) as browser:
        response = browser.get(authorization_url)
        for _ in range(12):
            if response.status_code in (302, 303):
                location = urljoin(str(response.url), response.headers["location"])
                if location.startswith(REDIRECT):
                    return location, ""
                assert location.startswith(dex.issuer), location  # never leaves the issuer before our callback
                response = browser.get(location)
                continue
            form = FORM_ACTION.search(response.text)
            if response.status_code == 200 and form and 'name="password"' in response.text:
                if submitted:  # the form came back: the login was refused
                    break
                action = urljoin(str(response.url), html.unescape(form.group(1)))
                response = browser.post(action, data={"login": f"{user}@example.invalid", "password": password})
                submitted = True
                continue
            break
        return None, response.text


def login(app: Any, dex: OwnedDex, user: str, password: str | None = None) -> tuple[TestClient, Any]:
    client = TestClient(app, base_url=ORIGIN, follow_redirects=False)
    started = client.get("/api/v1/auth/login", params={"return_to": "/cases"})
    assert started.status_code == 302
    callback, _ = issuer_login(dex, started.headers["location"], user, password or dex.passwords[user])
    assert callback is not None
    return client, client.get(callback.removeprefix(ORIGIN))


def test_real_dex_login_creates_a_session_without_implicit_membership(app: Any, dex: OwnedDex,
                                                                      dex_db: AppDatabase) -> None:
    application, runtime = app
    client, done = login(application, dex, "alice")
    assert done.status_code == 303 and done.headers["location"] == "/cases"
    me = client.get("/api/v1/me").json()
    assert me["workspaces"] == [] and me["workspace_id"] is None
    with transaction(dex_db.engine(AUTH_RUNTIME)) as conn:
        principal = conn.execute(text("SELECT id, issuer, subject FROM identity.principals WHERE id = :id"),
                                 {"id": me["principal_id"]}).one()
    assert principal.issuer == dex.issuer and principal.subject  # identity = issuer + subject
    workspace = Workspace(id=uuid4(), slug="dex-workspace", name="Dex workspace",
                          created_at=SystemClock().now())
    with transaction(dex_db.engine(AUTH_RUNTIME)) as conn:  # trusted synthetic provisioning
        repo.create_workspace(conn, workspace)
        repo.add_membership(conn, Membership(id=uuid4(), workspace_id=workspace.id,
                                             principal_id=principal.id, role="admin", created_at=SystemClock().now()))
    headers = {"Origin": ORIGIN, "X-CSRF-Token": client.cookies.get("policyops_csrf_local") or ""}
    assert client.post("/api/v1/auth/workspace", json={"workspace_id": str(workspace.id)},
                       headers=headers).status_code == 204
    assert client.get("/api/v1/me").json()["roles"] == ["admin"]
    expected = {EXPECTED_PRINCIPAL_HEADER: str(principal.id), EXPECTED_WORKSPACE_HEADER: str(workspace.id)}
    assert client.get("/api/v1/workspace/members").status_code == 400  # the T25a expected-context headers
    assert client.get("/api/v1/workspace/members", headers=expected).status_code == 200
    headers["X-CSRF-Token"] = client.cookies.get("policyops_csrf_local") or ""
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/v1/me").status_code == 401
    assert runtime is not None


def test_distinct_dex_users_are_distinct_principals(app: Any, dex: OwnedDex) -> None:
    application, _ = app
    alice, _ = login(application, dex, "alice")
    bob, _ = login(application, dex, "bob")
    assert alice.get("/api/v1/me").json()["principal_id"] != bob.get("/api/v1/me").json()["principal_id"]
    again, _ = login(application, dex, "alice")
    assert again.get("/api/v1/me").json()["principal_id"] == alice.get("/api/v1/me").json()["principal_id"]


def test_wrong_password_yields_no_code(app: Any, dex: OwnedDex) -> None:
    application, _ = app
    client = TestClient(application, base_url=ORIGIN, follow_redirects=False)
    started = client.get("/api/v1/auth/login")
    callback, page = issuer_login(dex, started.headers["location"], "carol", "wrong-" + dex.passwords["carol"])
    assert callback is None and "password" in page.lower()


def _code_for(app: Any, dex: OwnedDex, user: str) -> tuple[TestClient, str, str]:
    client = TestClient(app, base_url=ORIGIN, follow_redirects=False)
    started = client.get("/api/v1/auth/login")
    callback, _ = issuer_login(dex, started.headers["location"], user, dex.passwords[user])
    assert callback is not None
    query = parse_qs(urlsplit(callback).query)
    return client, query["code"][0], query["state"][0]


def test_dex_enforces_pkce_and_single_use_codes(app: Any, dex: OwnedDex, dex_db: AppDatabase) -> None:
    application, runtime = app
    oidc = runtime.service.oidc
    _, code, _ = _code_for(application, dex, "bob")
    with pytest.raises(OidcError, match="HTTP 400"):  # the verifier does not match the S256 challenge
        oidc.exchange_code(code, tokens.pkce_pair()[0])
    client, code, state = _code_for(application, dex, "bob")
    assert client.get("/api/v1/auth/callback", params={"code": code, "state": state}).status_code == 303
    with dex_db.superuser() as conn:  # the stored verifier of that (consumed) login, to replay the code exactly
        verifier = conn.execute("SELECT code_verifier FROM identity.login_requests WHERE state_sha256 = %s",
                                (tokens.digest(state),)).fetchone()[0]
    with pytest.raises(OidcError, match="HTTP 400"):
        oidc.exchange_code(code, verifier)  # Dex refuses a code that was already redeemed


def test_dex_tokens_are_rs256_and_validated_against_its_jwks(app: Any, dex: OwnedDex) -> None:
    application, runtime = app
    oidc = runtime.service.oidc
    client = TestClient(application, base_url=ORIGIN, follow_redirects=False)
    started = client.get("/api/v1/auth/login")
    callback, _ = issuer_login(dex, started.headers["location"], "carol", dex.passwords["carol"])
    assert callback is not None
    metadata = oidc.metadata()
    assert metadata.issuer == dex.issuer and metadata.jwks_uri.startswith(dex.issuer)
    assert client.get(callback.removeprefix(ORIGIN)).status_code == 303


def test_dex_log_holds_no_secrets_or_codes(app: Any, dex: OwnedDex) -> None:
    application, _ = app
    client, code, state = _code_for(application, dex, "alice")
    client.get("/api/v1/auth/callback", params={"code": code, "state": state})
    log = (dex.root / "log" / "dex.log").read_text(encoding="utf-8", errors="replace")
    assert log  # Dex did log the flow
    for value in (dex.client_secret, *dex.passwords.values(), code, state):
        assert value not in log
    assert not list((dex.root / "secrets").iterdir()) and not (dex.root / "data" / "config.yaml").exists()
