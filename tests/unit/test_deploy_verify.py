"""Exercise the live driver's actual HTTP/cookie/port decisions without external sockets."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime
import json
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any
from unittest.mock import Mock
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
from pydantic import SecretStr
import pytest
from starlette.datastructures import Headers

from policyops.api import auth
from policyops.api.auth import expected_context
from policyops.auth import tokens
from policyops.auth.service import AuthError, AuthService, IssuedSession, SessionContext, unauthenticated
from policyops.domain.roles import Role
from policyops.persistence.identity import WorkspaceChoice
from policyops.settings import AuthSettings


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import deploy_rollback_drill as rollback
from scripts import deploy_verify as driver


HOST = "demo.example.test"
ORIGIN = f"https://{HOST}"
CSRF = "synthetic-csrf"
SESSION = "synthetic-session"
RELEASE = "a" * 40
CASE = "00000000-0000-0000-0000-000000000001"
PROPOSAL = "00000000-0000-0000-0000-000000000002"
HEADERS = {"strict-transport-security": "max-age=31536000", "x-frame-options": "DENY",
           "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
           "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'"}


def cookies() -> list[str]:
    return [f"__Host-policyops_{name}={value}; Path=/; Secure; SameSite={site}" + extra
            for name, value, site, extra in (("login", "synthetic-login", "Lax", "; HttpOnly"),
                                             ("session", SESSION, "Lax", "; HttpOnly"),
                                             ("csrf", CSRF, "Strict", ""))]


def auth_routes(monkeypatch: pytest.MonkeyPatch, mutation: str | None) -> TestClient:
    """Run the real routes, Origin and CSRF checks with in-memory session and membership storage."""
    settings = AuthSettings(env="test", public_origin=ORIGIN, oidc_issuer=ORIGIN + "/dex",
                            oidc_client_id="policyops", oidc_client_secret=SecretStr("synthetic-oidc-secret"))
    service = AuthService(settings, oidc=Mock(), auth_engine=Mock(), clock=Mock())
    workspace = UUID(CASE) if mutation == "wrong_workspace" else driver.DEMO_WORKSPACE
    role = Role.AUDITOR if mutation == "wrong_role" else Role.ANALYST
    choices = [WorkspaceChoice(workspace_id=workspace, slug="demo", name="Demo", roles=(role.value,))]
    if mutation == "two_workspaces":
        choices.append(WorkspaceChoice(workspace_id=UUID(CASE), slug="other", name="Other", roles=("analyst",)))
    sessions = {SESSION: SessionContext(
        session_id=uuid4(), principal_id=UUID(CASE if mutation == "alice" else driver.ALICE),
        workspace_id=workspace if mutation == "already_selected" else None,
        expires_at=datetime(2030, 1, 1, tzinfo=UTC), csrf_sha256=tokens.digest(CSRF),
    )}

    def resolve(cookie: str | None) -> SessionContext:
        session = sessions.get(cookie or "")
        if session is None:
            raise unauthenticated()
        return session

    def select(session: SessionContext, workspace_id: UUID) -> IssuedSession:
        assert workspace_id == workspace
        issued = IssuedSession(uuid4(), "synthetic-rotated-session", "synthetic-rotated-csrf", "/")
        del sessions[SESSION]
        sessions[issued.cookie] = replace(session, session_id=issued.session_id,
                                          workspace_id=None if mutation == "unconfirmed" else workspace_id,
                                          csrf_sha256=tokens.digest(issued.csrf))
        return issued

    monkeypatch.setattr(service, "resolve", resolve)
    monkeypatch.setattr(service, "workspaces", lambda _session: choices)
    monkeypatch.setattr(service, "roles", lambda session: frozenset({role}) if session.workspace_id else frozenset())
    monkeypatch.setattr(service, "select_workspace", select)
    app = FastAPI()
    auth.install(app, auth.AuthRuntime(settings, service, Mock()))
    app.include_router(auth.build_router(), prefix="/api/v1")
    return TestClient(app, base_url=ORIGIN)


@pytest.mark.parametrize("mutation", [None, "tls", "redirect", "banner", "hsts", "health", "cookie", "port", "release",
                                      "alice", "unreadable_proposal", "wrong_case", "wrong_version", "wrong_digest",
                                      "missing_seed", "local", "already_selected", "wrong_workspace", "wrong_role",
                                      "two_workspaces", "missing_csrf", "selection_non_204", "unconfirmed"])
def test_actual_verification_sequence_rejects_live_policy_failures(monkeypatch: pytest.MonkeyPatch,
                                                                  mutation: str | None, tmp_path: Path) -> None:
    fixture = tmp_path / "seed.json"
    if mutation != "missing_seed":
        fixture.write_text(json.dumps({"proposal_id": PROPOSAL, "proposal_version": 2,
                                       "case_id": CASE, "action_digest": "d" * 64}), encoding="utf-8")
    auth_calls: list[tuple[str, str]] = []

    def response(request: httpx.Request) -> httpx.Response:
        if mutation == "tls":
            raise httpx.ConnectError("synthetic TLS failure", request=request)
        path = request.url.path
        headers = dict(HEADERS)
        if mutation == "banner":
            headers["server"] = "unintended-version"
        if mutation == "hsts":
            headers["strict-transport-security"] = "max-age=0"
        if request.url.scheme == "http":
            return httpx.Response(308, headers={"location": ("http://" if mutation == "redirect" else "https://")
                                               + HOST + "/"})
        if path == "/api/v1/health/ready":
            return httpx.Response(503 if mutation == "health" else 200, json={"status": "ok"}, headers=headers)
        if path == "/release":
            return httpx.Response(200, content=("b" * 40 if mutation == "release" else RELEASE).encode())
        if path in ("/api/v1/me", "/api/v1/auth/workspace"):
            auth_calls.append((request.method, path))
            browser.cookies.clear()
            result = browser.request(request.method, str(request.url), headers=request.headers.raw,
                                     content=request.content)
            if path == "/api/v1/auth/workspace" and mutation == "selection_non_204":
                assert result.status_code == 204
                return httpx.Response(200, text="synthetic-selection-body")
            return httpx.Response(result.status_code, headers=result.headers.raw, content=result.content)
        if path == f"/api/v1/proposals/{PROPOSAL}":
            assert auth_calls[-1] == ("GET", "/api/v1/me")
            assert request.method == "GET" and request.url.query == b"version=2"
            try:
                context = expected_context(Headers(raw=[(key.lower(), value) for key, value in request.headers.raw]))
            except AuthError as error:
                return httpx.Response(error.status)
            assert (str(context.principal_id), str(context.workspace_id)) == (driver.ALICE, str(driver.DEMO_WORKSPACE))
            proposal = {"proposal_id": PROPOSAL, "proposal_version": 3 if mutation == "wrong_version" else 2,
                        "scope": {"case_id": PROPOSAL if mutation == "wrong_case" else CASE},
                        "action_digest": ("f" if mutation == "wrong_digest" else "d") * 64}
            return httpx.Response(404 if mutation == "unreadable_proposal" else 200, json={"proposal": proposal})
        if path == "/api/v1/auth/login":
            return httpx.Response(302, headers={**headers, "location": "/dex/login",
                                                "set-cookie": cookies()[0]})
        if path == "/dex/login" and request.method == "GET":
            return httpx.Response(200, text='<form method="post" action="/dex/login">'
                                  '<input name="login"><input name="password"></form>', headers=headers)
        if path == "/dex/login":
            cookie_headers = cookies()[1:]
            if mutation == "missing_csrf":
                cookie_headers = cookie_headers[:1]
            if mutation == "cookie":
                cookie_headers = [value.replace("Secure; ", "") for value in cookie_headers]
            return httpx.Response(200, headers=[*headers.items(), *[("set-cookie", v) for v in cookie_headers]])
        return httpx.Response(200, headers=headers)

    client_type = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client_type(
        **kwargs, transport=httpx.MockTransport(response)))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kw: [(2, 1, 6, "", ("192.0.2.1", 443))])

    def connect(endpoint: tuple[str, int], **_kwargs: Any) -> Any:
        if mutation == "local":
            pytest.fail("local verifier must not probe ports")
        if endpoint[1] in ({80, 443, 5432} if mutation == "port" else {80, 443}):
            return nullcontext()
        raise OSError("closed")

    monkeypatch.setattr(socket, "create_connection", connect)
    with auth_routes(monkeypatch, mutation) as browser:
        result = driver.verify(HOST, local=mutation == "local", expect_release=RELEASE, seed_path=fixture)
    assert result["passed"] is (mutation in (None, "local", "already_selected")), result
    if mutation != "tls":
        me = ("GET", "/api/v1/me")
        select = ("POST", "/api/v1/auth/workspace")
        rejected_before_selection = {"alice", "wrong_workspace", "wrong_role", "two_workspaces", "missing_csrf"}
        expected_calls = [me]
        if mutation not in rejected_before_selection | {"already_selected"}:
            expected_calls.append(select)
            if mutation != "selection_non_204":
                expected_calls.append(me)
        assert auth_calls == expected_calls
        rejected_session = rejected_before_selection | {"selection_non_204", "unconfirmed"}
        assert result["checks"]["login_session"] is (mutation not in rejected_session)
        if mutation in rejected_session:
            assert result["checks"]["seeded_proposal"] is False
    if mutation == "local":
        assert not result["port_scope"] and not result["observed_open_ports"]
    serialized = json.dumps(result)
    assert "synthetic" not in serialized and "set-cookie" not in serialized


@pytest.mark.parametrize("attribute", ["Secure; ", "HttpOnly", "SameSite=Lax", "Path=/"])
def test_missing_cookie_security_property_is_refused(attribute: str) -> None:
    good = cookies()
    response = httpx.Response(200, headers=[("set-cookie", value) for value in good])
    assert all(driver.cookie_checks([response]).values())
    bad = httpx.Response(200, headers=[("set-cookie", good[0].replace(attribute, "")),
                                      *(('set-cookie', value) for value in good[1:])])
    assert not driver.cookie_checks([bad])["__Host-policyops_login"]


@pytest.mark.parametrize("bad", ["https://demo.test", "demo.test/path", "-a.test", "a..test", "a.test:443"])
def test_host_input_is_only_a_hostname(bad: str) -> None:
    with pytest.raises(ValueError):
        driver.hostname(bad)


def test_output_route_rejects_checkout_and_relative_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for raw in ("", "relative", str(driver.ROOT), str(driver.ROOT / "artifacts")):
        monkeypatch.setenv("POLICYOPS_TEMP_DIR", raw)
        with pytest.raises(ValueError):
            driver.report_path("verify")
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    assert tmp_path in driver.report_path("verify").parents


@pytest.mark.parametrize("kind", ["oversized", "compressed", "foreign_redirect", "redirect_loop"])
def test_verification_transport_is_bounded_and_stays_on_origin(kind: str) -> None:
    calls = []

    def response(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if kind == "oversized":
            return httpx.Response(200, content=b"x" * 262145)
        if kind == "compressed":
            return httpx.Response(200, headers={"content-encoding": "br"})
        return httpx.Response(302, headers={"location": "https://foreign.test/" if kind == "foreign_redirect" else "/"})

    with (httpx.Client(transport=httpx.MockTransport(response), follow_redirects=False) as client,
          pytest.raises(ValueError)):
        driver.fetch(client, "GET", "https://" + HOST, follow=True)
    assert len(calls) == (9 if kind == "redirect_loop" else 1)


@pytest.mark.parametrize("failure", [None, "command", "health", "timeout"])
def test_rollback_records_a_b_a_and_stops_on_failure(monkeypatch: pytest.MonkeyPatch, failure: str | None) -> None:
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["timeout"] == 1800 and kwargs["stdout"] == subprocess.DEVNULL
        commands.append(command)
        if failure == "timeout" and len(commands) == 2:
            raise subprocess.TimeoutExpired(command, 1800)
        return subprocess.CompletedProcess(command, 1 if failure == "command" and len(commands) == 2 else 0,
                                           stdout=b"must not retain raw output")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(rollback, "verify", lambda *_a, **_k: {"passed": not (failure == "health"
                                                                                         and len(commands) == 2)})
    known_hosts = Path("directory with spaces") / "known_hosts"
    result = rollback.drill(HOST, "ubuntu@192.0.2.1", Path("identity"), "a" * 40, "b" * 40,
                            known_hosts=known_hosts)
    assert result["passed"] is (failure is None)
    assert len(commands) == (3 if failure is None else 2)
    assert all("StrictHostKeyChecking=yes" in command for command in commands)
    option = f'UserKnownHostsFile="{known_hosts.resolve().as_posix()}"'
    assert all(option in command and "GlobalKnownHostsFile=none" in command for command in commands)
    assert "must not retain" not in json.dumps(result)
    if failure is None:
        assert commands[-1][-1].endswith("--rollback")
        assert [step["commit"] for step in result["steps"]] == ["a" * 40, "b" * 40, "a" * 40]
    if failure == "timeout":
        assert "may_continue" in result["steps"][-1]["outcome"]
