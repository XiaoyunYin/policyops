"""Exercise the live driver's actual HTTP/cookie/port decisions without external sockets."""

from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any

import httpx
import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import deploy_rollback_drill as rollback
from scripts import deploy_verify as driver


HOST = "demo.example.test"
HEADERS = {"strict-transport-security": "max-age=31536000", "x-frame-options": "DENY",
           "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
           "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'"}


def cookies() -> list[str]:
    return [f"__Host-policyops_{name}=synthetic; Path=/; Secure; SameSite={site}" + extra
            for name, site, extra in (("login", "Lax", "; HttpOnly"), ("session", "Lax", "; HttpOnly"),
                                      ("csrf", "Strict", ""))]


@pytest.mark.parametrize("mutation", [None, "tls", "redirect", "banner", "hsts", "health", "cookie", "port"])
def test_actual_verification_sequence_rejects_live_policy_failures(monkeypatch: pytest.MonkeyPatch,
                                                                  mutation: str | None) -> None:
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
        if path == "/api/v1/auth/login":
            return httpx.Response(302, headers={**headers, "location": "/dex/login",
                                                "set-cookie": cookies()[0]})
        if path == "/dex/login" and request.method == "GET":
            return httpx.Response(200, text='<form method="post" action="/dex/login">'
                                  '<input name="login"><input name="password"></form>', headers=headers)
        if path == "/dex/login":
            cookie_headers = cookies()[1:]
            if mutation == "cookie":
                cookie_headers = [value.replace("Secure; ", "") for value in cookie_headers]
            return httpx.Response(200, headers=[*headers.items(), *[("set-cookie", v) for v in cookie_headers]])
        return httpx.Response(200, headers=headers)

    client_type = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client_type(
        **kwargs, transport=httpx.MockTransport(response)))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kw: [(2, 1, 6, "", ("192.0.2.1", 443))])

    def connect(endpoint: tuple[str, int], **_kwargs: Any) -> Any:
        if endpoint[1] in ({80, 443, 5432} if mutation == "port" else {80, 443}):
            return nullcontext()
        raise OSError("closed")

    monkeypatch.setattr(socket, "create_connection", connect)
    result = driver.verify(HOST)
    assert result["passed"] is (mutation is None)
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
    result = rollback.drill(HOST, "ubuntu@192.0.2.1", Path("identity"), "a" * 40, "b" * 40)
    assert result["passed"] is (failure is None)
    assert len(commands) == (3 if failure is None else 2)
    assert all("StrictHostKeyChecking=yes" in command for command in commands)
    assert "must not retain" not in json.dumps(result)
    if failure is None:
        assert commands[-1][-1].endswith("--rollback")
        assert [step["commit"] for step in result["steps"]] == ["a" * 40, "b" * 40, "a" * 40]
    if failure == "timeout":
        assert "may_continue" in result["steps"][-1]["outcome"]
