"""Offline probes and regression policies for the burstable-host CPU budget."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from copy import deepcopy
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any
from urllib.error import URLError

import pytest
import yaml  # type: ignore[import-untyped]

from policyops_testing.network import allow


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from infra.compose import health


ROOT = Path(__file__).resolve().parents[2]


def enforce_stdlib(source: str) -> None:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] in sys.stdlib_module_names for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module is not None
            assert node.module.split(".")[0] in sys.stdlib_module_names


def test_health_imports_only_stdlib() -> None:
    enforce_stdlib((ROOT / "infra/compose/health.py").read_text(encoding="utf-8"))


@pytest.mark.parametrize("source", ["import httpx", "from policyops import settings",
                                   "from . import runtime", "def probe():\n import sqlalchemy"])
def test_stdlib_policy_negative_controls(source: str) -> None:
    with pytest.raises(AssertionError):
        enforce_stdlib(source)


@pytest.fixture
def server() -> Iterator[tuple[str, list[str]]]:
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            status, body = {
                "/ok": (200, b'{"status":"ok","checks":{"database":true}}'),
                "/bad": (200, b'{"status":"failed"}'),
                "/list": (200, b'["ok"]'), "/null": (200, b'null'),
                "/invalid": (200, b'not-json'), "/missing": (200, b'{}'),
                "/unavailable": (503, b'{"status":"ok"}'),
                "/created": (201, b'{"status":"ok"}'),
                "/redirect": (302, b'{"status":"ok"}'),
            }[self.path]
            self.send_response(status)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    try:
        thread.start()
        with allow("127.0.0.1", httpd.server_port):
            yield f"http://127.0.0.1:{httpd.server_port}", requests
    finally:
        if thread.is_alive():
            httpd.shutdown()
            thread.join(timeout=2)
        httpd.server_close()
        assert not thread.is_alive()


@pytest.mark.parametrize("path,expected", [("ok", True), ("bad", False), ("list", False), ("null", False),
                                          ("invalid", False), ("missing", False), ("unavailable", False),
                                          ("created", False), ("redirect", False)])
def test_http_semantics(server: tuple[str, list[str]], path: str, expected: bool,
                        monkeypatch: pytest.MonkeyPatch) -> None:
    origin, requests = server
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    assert health.http_health(origin + "/" + path) is expected
    assert requests == ["/" + path]  # A redirect must never reach /ok.


@pytest.mark.parametrize("error", [TimeoutError(), URLError("synthetic"), OSError(), ValueError(),
                                  IncompleteRead(b"partial")])
def test_http_failure_and_bounded_timeout(error: Exception, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def open_url(url: str, *, timeout: float) -> None:
        calls.append((url, timeout))
        raise error

    monkeypatch.setattr(health, "build_opener", lambda *_: SimpleNamespace(open=open_url))
    assert health.http_health("http://127.0.0.1:8000/api/v1/health/ready") is False
    assert calls == [("http://127.0.0.1:8000/api/v1/health/ready", 2)]


@pytest.mark.parametrize("age,expected", [(0, True), (24.999, True), (25, False), (26, False), (-1, True)])
def test_heartbeat_freshness_boundary(tmp_path: Path, age: float, expected: bool,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
    heartbeat = tmp_path / "heartbeat"
    heartbeat.touch()
    os.utime(heartbeat, (100, 100))
    monkeypatch.setattr(health, "HEARTBEAT", heartbeat)
    monkeypatch.setattr(time, "time", lambda: 100 + age)
    assert health.worker_health() is expected


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_heartbeat_requires_existing_regular_file(tmp_path: Path, kind: str,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "heartbeat"
    if kind == "directory":
        path.mkdir()
    monkeypatch.setattr(health, "HEARTBEAT", path)
    assert health.worker_health() is False


@pytest.mark.parametrize("command,url", [
    ("health-api", "http://127.0.0.1:8000/api/v1/health/ready"),
    ("health-retail", "http://127.0.0.1:8001/healthz"), ("health-worker", None),
])
@pytest.mark.parametrize("healthy", [True, False])
def test_command_urls_and_exit_codes(command: str, url: str | None, healthy: bool,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str | None] = []

    def http_probe(actual: str) -> bool:
        calls.append(actual)
        return healthy

    def worker_probe() -> bool:
        calls.append(None)
        return healthy

    monkeypatch.setattr(sys, "argv", ["health.py", command])
    monkeypatch.setattr(health, "http_health", http_probe)
    monkeypatch.setattr(health, "worker_health", worker_probe)
    assert health.main() == (0 if healthy else 1)
    assert calls == [url]


def enforce_health_commands(services: dict[str, Any], interval: str) -> None:
    for name in ("api", "retail", "worker"):
        probe = services[name]["healthcheck"]
        assert probe["test"] == ["CMD", "python", "-B", "infra/compose/health.py", f"health-{name}"]
    for name in ("api", "retail", "worker", "postgres", "dex", "caddy"):
        probe = services[name]["healthcheck"]
        assert probe["interval"] == interval and probe["timeout"] == "5s"
        assert probe["retries"] == 12 and probe["start_period"] == "15s"


def test_local_and_public_health_policy() -> None:
    base = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    enforce_health_commands(base["services"], "10s")
    # Only health mappings are merged here; the separate networking test does a real Compose merge.
    source = (ROOT / "infra/compose/public.yaml").read_text(encoding="utf-8")
    public = yaml.safe_load(source.replace("!override", ""))
    for name, service in public["services"].items():
        base["services"][name].get("healthcheck", {}).update(service.get("healthcheck", {}))
    enforce_health_commands(base["services"], "30s")


@pytest.mark.parametrize("name", ["api", "retail", "worker"])
@pytest.mark.parametrize("change", ["runtime", "command", "interval", "timeout", "retries", "grace"])
def test_health_policy_negative_controls(name: str, change: str) -> None:
    services = deepcopy(yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))["services"])
    probe = services[name]["healthcheck"]
    probe["test"] = list(probe["test"])
    if change == "runtime":
        probe["test"][3] = "infra/compose/runtime.py"
    elif change == "command":
        probe["test"][-1] = "health-other"
    else:
        key = "start_period" if change == "grace" else change
        probe[key] = 0 if key == "retries" else "60s"
    with pytest.raises(AssertionError):
        enforce_health_commands(services, "10s")


def enforce_bytecode(source: str, name: str) -> None:
    commands = source.replace("\\\n", " ")
    compile_line = next(line for line in commands.splitlines() if line.startswith("RUN python -m compileall "))
    assert "-q -f --invalidation-mode unchecked-hash /usr/local/lib/python3.12" in compile_line
    if name in {"app", "retail"}:
        assert "/opt/venv /opt/policyops" in compile_line
        if name == "retail":
            assert "/opt/fixture" in compile_line
        assert commands.rindex("\nCOPY ") < commands.index(compile_line) < commands.index("\nUSER ")
        assert "PYTHONDONTWRITEBYTECODE=1" in commands.split(" AS runtime\n", 1)[1]
        assert 'ENTRYPOINT ["python", "-B", "infra/compose/runtime.py"]' in commands
    else:
        assert " scripts" in compile_line
        assert commands.index(compile_line) < commands.index("RUN python -B scripts/check_bundle.py")


@pytest.mark.parametrize("name", ["app", "retail", "web"])
def test_python_image_bytecode_policy(name: str) -> None:
    enforce_bytecode((ROOT / f"infra/docker/{name}.Dockerfile").read_text(encoding="utf-8"), name)


@pytest.mark.parametrize("name", ["app", "retail", "web"])
@pytest.mark.parametrize("old,new", [("RUN python -m compileall", "RUN echo compileall"),
                                    ("unchecked-hash", "timestamp"), ("-q -f", "-q"),
                                    ("/usr/local/lib/python3.12", "/missing")])
def test_bytecode_policy_negative_controls(name: str, old: str, new: str) -> None:
    source = (ROOT / f"infra/docker/{name}.Dockerfile").read_text(encoding="utf-8")
    with pytest.raises((AssertionError, StopIteration)):
        enforce_bytecode(source.replace(old, new), name)


def test_heartbeat_constant_matches_writer() -> None:
    # The writer stays in runtime.py; check its literal without importing the heavy module.
    tree = ast.parse((ROOT / "infra/compose/runtime.py").read_text(encoding="utf-8"))
    value = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "HEARTBEAT" for target in node.targets))
    assert isinstance(value, ast.Call) and isinstance(value.args[0], ast.Constant)
    assert isinstance(value.args[0].value, str)
    assert Path(value.args[0].value) == health.HEARTBEAT
