"""Bounded public API admission, peer/header trust, and deterministic expiry behavior."""

from __future__ import annotations

from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import Any

from fastapi import FastAPI
import pytest
from starlette.testclient import TestClient
from starlette.types import Scope
import uvicorn

from policyops.api import serve
from policyops.api.rate_limit import PublicRateLimit


def scope(peer: str, *forwarded: bytes) -> Scope:
    result: Any = {"type": "http", "client": (peer, 1234),
                   "headers": [(b"x-policyops-client-ip", value) for value in forwarded]}
    return result  # type: ignore[no-any-return]


def test_fixed_windows_exhaustion_and_capacity_do_not_allow_churn() -> None:
    now = [100.0]
    limit = PublicRateLimit(FastAPI(), requests=2, seconds=10, max_clients=2, clock=lambda: now[0])
    assert limit.admit("a") and limit.admit("a") and not limit.admit("a")
    assert limit.admit("b")
    for index in range(5000):
        assert not limit.admit(f"attacker-{index}")
    assert len(limit.windows) == 2 and not limit.admit("a")
    now[0] = 110
    assert limit.admit("new") and limit.admit("a") and len(limit.windows) == 2


@pytest.mark.parametrize("peer,headers,expected", [
    ("127.0.0.1", [b"192.0.2.1"], "192.0.2.1"),
    ("::1", [b"2001:db8::1"], "2001:db8::1"),
    ("192.0.2.2", [b"192.0.2.1"], "192.0.2.2"),
    ("127.0.0.1", [b"192.0.2.1", b"192.0.2.2"], "127.0.0.1"),
    ("127.0.0.1", [b"192.0.2.1, 192.0.2.2"], "127.0.0.1"),
    ("127.0.0.1", [b"bad"], "127.0.0.1"), ("127.0.0.1", [b"\xff"], "127.0.0.1"),
])
def test_only_loopback_single_ip_header_is_trusted(peer: str, headers: list[bytes], expected: str) -> None:
    assert PublicRateLimit.client_ip(scope(peer, *headers)) == expected


def test_asgi_returns_429_before_app_with_retry_and_no_store() -> None:
    app = FastAPI()

    @app.get("/api/v1/health/ready")
    def healthy() -> dict[str, str]:
        return {"status": "ok"}

    # Explicit ASGI client; never opens sockets or relies on real time.
    with TestClient(PublicRateLimit(app, requests=1)) as client:
        assert client.get("/api/v1/health/ready").status_code == 200
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 429 and response.headers["retry-after"] == "60"
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["rule_id"] == "api.public_rate_limit"


def test_different_caddy_client_ips_have_independent_limits() -> None:
    app = FastAPI()
    with TestClient(PublicRateLimit(app, requests=1), client=("127.0.0.1", 1234)) as client:
        first = client.get("/", headers={"X-PolicyOps-Client-IP": "192.0.2.1"})
        assert first.status_code == 404
        assert client.get("/", headers={"X-PolicyOps-Client-IP": "192.0.2.1"}).status_code == 429
        assert client.get("/", headers={"X-PolicyOps-Client-IP": "192.0.2.2"}).status_code == 404


@pytest.mark.parametrize("flag", [None, "0", "1"])
def test_composed_api_enables_limiter_only_for_public_profile(monkeypatch: pytest.MonkeyPatch,
                                                             flag: str | None) -> None:
    runtime = runpy.run_path(str(Path(__file__).resolve().parents[2] / "infra/compose/runtime.py"))
    closed: list[bool] = []
    served = SimpleNamespace(close=lambda: closed.append(True))
    captured: list[Any] = []
    monkeypatch.setattr(serve, "create_served_app", lambda: served)
    monkeypatch.setattr(uvicorn, "run", lambda app, **_kwargs: captured.append(app))
    monkeypatch.setitem(runtime["api"].__globals__, "secret", lambda _name: "synthetic" * 4)
    for name in ("POLICYOPS_DB_AUTH_PASSWORD", "POLICYOPS_DB_APP_PASSWORD", "POLICYOPS_OIDC_CLIENT_SECRET"):
        monkeypatch.setenv(name, "synthetic" * 4)
    monkeypatch.delenv("POLICYOPS_PUBLIC_RATE_LIMIT", raising=False)
    if flag is not None:
        monkeypatch.setenv("POLICYOPS_PUBLIC_RATE_LIMIT", flag)
    runtime["api"]()
    assert closed == [True] and isinstance(captured[0], PublicRateLimit) is (flag == "1")
