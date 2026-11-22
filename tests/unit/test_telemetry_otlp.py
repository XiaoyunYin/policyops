"""Real OTLP protobuf on a loopback receiver, plus network and provisioning boundaries."""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import import_module, metadata
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from threading import Event, Thread
import time
from typing import Any
from uuid import uuid4

import httpx
from pydantic import ValidationError
import pytest

from policyops import telemetry as ot
from policyops.api.app import create_app
from policyops.settings import TelemetrySettings
from policyops.telemetry.attributes import ENUMS, METRIC_KEYS
from policyops.telemetry.sdk import DISPATCH_BUCKETS, SCHEMA_URL, Backend
from policyops_testing import network
from tests.unit.test_telemetry import http_work, wait_for


ROOT = Path(__file__).resolve().parents[2]
CANARY = "private-otlp-probe@example.invalid"
METRICS = {
    "policyops_provider_calls_total", "policyops_provider_input_tokens_total", "policyops_provider_output_tokens_total",
    "policyops_provider_cost_usd_USD_total", "policyops_errors_total", "policyops_jobs_total",
    "policyops_reviews_total",
    "policyops_executions_total", "policyops_queue_depth", "policyops_queue_oldest_due_age_seconds",
    "policyops_provider_dispatch_duration_seconds_sum", "policyops_provider_dispatch_duration_seconds_count",
}


@pytest.fixture
def otlp_extra() -> None:
    try:
        assert metadata.version("opentelemetry-exporter-otlp-proto-http") == "1.45.1"
    except metadata.PackageNotFoundError:
        if os.environ.get("POLICYOPS_REQUIRE_OTLP_TESTS") == "1":
            pytest.fail("the unit job must install policyops[otlp]")
        pytest.skip("requires policyops[otlp], installed by both OS unit jobs")


@contextmanager
def receiver(status: int = 200, *, stall: Event | None = None) -> Iterator[
    tuple[int, list[tuple[str, dict[str, str], bytes]], Event]
]:
    calls: list[tuple[str, dict[str, str], bytes]] = []
    entered = Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            data = self.rfile.read(int(self.headers["Content-Length"]))
            calls.append((self.path, {key.lower(): value for key, value in self.headers.items()}, data))
            entered.set()
            if stall is not None:
                stall.wait(8)
            with suppress(OSError):
                self.send_response(status)
                if status == 307:
                    self.send_header("Location", "/unexpected")
                self.end_headers()
                if status >= 300:
                    self.wfile.write(CANARY.encode())

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        port = server.server_port
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        with network.allow("127.0.0.1", port):
            thread.start()
            try:
                yield port, calls, entered
            finally:
                if stall is not None:
                    stall.set()
                server.shutdown()
                thread.join(timeout=2)


def settings(port: int) -> TelemetrySettings:
    base = f"http://127.0.0.1:{port}"
    return TelemetrySettings(enabled=True, exporter="otlp", traces_url=base + "/v1/traces",
                             metrics_url=base + "/v1/metrics")


@contextmanager
def exporter(port: int, *, release: Event | None = None) -> Iterator[Backend]:
    backend = ot.configure(settings(port), role="demo")
    assert backend is not None
    try:
        yield backend
    finally:
        if release is not None:
            release.set()
        backend.close()
        backend.shutdown_thread.join(timeout=2)
        backend.lane.thread.join(timeout=3)
        assert not backend.shutdown_thread.is_alive() and not backend.lane.thread.is_alive()


def decode(signal: str, data: bytes) -> Any:
    module = import_module(f"opentelemetry.proto.collector.{signal}.v1.{signal}_service_pb2")
    cls = getattr(module, f"Export{signal.capitalize()}ServiceRequest")
    return cls.FromString(data)


def attrs(item: Any) -> dict[str, Any]:
    return {entry.key: getattr(entry.value, entry.value.WhichOneof("value")) for entry in item.attributes}


def assert_metadata(resource: Any, scope: Any) -> None:
    assert resource.schema_url == scope.schema_url == SCHEMA_URL
    assert attrs(resource.resource) == {"service.name": "policyops-demo", "service.version": "0.1.0"}
    assert (scope.scope.name, scope.scope.version) == ("policyops", "1.0.0")
    assert not attrs(scope.scope)


def test_real_wire_metadata_and_allowlist(otlp_extra: None, caplog: pytest.LogCaptureFixture,
                                          monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text(f"machine 127.0.0.1 login fixture password {CANARY}", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    uid = uuid4()

    async def http_canaries() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as client:
            reply = await client.get("/api/v1/health/live", params={"secret": CANARY}, headers={
                "authorization": CANARY, "cookie": CANARY, "baggage": CANARY,
                "traceparent": "00-11111111111111111111111111111111-2222222222222222-01",
            })
            assert reply.status_code == 200

    with receiver() as (port, calls, _), exporter(port) as backend:
        with ot.span("investigation", run_id=uid, model=CANARY, error_code=CANARY):
            ot.annotate(provider="openai", model="gpt-6-luna")
            asyncio.run(http_canaries())
            ot.provider_usage(provider="openai", model="gpt-6-luna", outcome="completed",
                              input_tokens=21, output_tokens=3)
            with ot.provider_dispatch("openai", "gpt-6-luna"):
                pass
            ot.count("jobs", kind="run.execute", outcome="completed", run_id=uid)
        assert backend.flush(5)
        spans: dict[str, dict[str, Any]] = {}
        points: dict[str, int] = {}
        for path, headers, body in calls:
            assert headers["content-type"] == "application/x-protobuf"
            assert not ({"authorization", "proxy-authorization", "cookie"} & headers.keys())
            assert CANARY.encode() not in body
            if path == "/v1/traces":
                for resource in decode("trace", body).resource_spans:
                    for scope in resource.scope_spans:
                        assert_metadata(resource, scope)
                        for span in scope.spans:
                            assert not span.events and not span.status.message
                            assert span.trace_id != bytes.fromhex("11" * 16)
                            spans[span.name] = attrs(span)
            elif path == "/v1/metrics":
                assert str(uid).encode() not in body
                for resource in decode("metrics", body).resource_metrics:
                    for scope in resource.scope_metrics:
                        assert_metadata(resource, scope)
                        for metric in scope.metrics:
                            for point in getattr(metric, metric.WhichOneof("data")).data_points:
                                labels = attrs(point)
                                assert labels.keys() <= METRIC_KEYS
                                assert all(value in ENUMS[key] for key, value in labels.items())
                                if metric.HasField("histogram"):
                                    assert list(point.explicit_bounds) == list(DISPATCH_BUCKETS)
                                    points[metric.name] = point.count
                                else:
                                    points[metric.name] = point.as_int
            else:
                pytest.fail("OTLP used an unexpected endpoint")
        assert set(spans) == {"investigation", "http.request"}
        assert spans["investigation"] == {"run_id": str(uid), "model": "gpt-6-luna",
                                         "provider": "openai", "outcome": "completed", "cost_class": "unconfirmed",
                                         "input_tokens": 21, "output_tokens": 3}
        assert spans["http.request"] == {"run_id": str(uid), "http_method": "GET", "outcome": "completed",
                                        "http_route": "/api/v1/health/live", "http_status": 200}
        assert points == {"policyops.jobs": 1, "policyops.provider.calls": 1,
                          "policyops.provider.input_tokens": 21, "policyops.provider.output_tokens": 3,
                          "policyops.provider.dispatch_duration": 1}
    assert CANARY not in caplog.text


@pytest.mark.parametrize("status", [307, 503])
def test_collector_failure_is_lossy_and_body_never_logged(otlp_extra: None, status: int) -> None:
    with receiver(status) as (port, calls, _):
        script = """
import logging
import logging.config
import sys
from policyops import telemetry as ot
from policyops.api.serve import SERVE_LOG_CONFIG
from policyops.settings import TelemetrySettings
logging.config.dictConfig(SERVE_LOG_CONFIG)
base = 'http://127.0.0.1:' + sys.argv[1]
backend = ot.configure(TelemetrySettings(enabled=True, exporter='otlp',
    traces_url=base + '/v1/traces', metrics_url=base + '/v1/metrics'))
with ot.span('worker.job'):
    ot.count('jobs', kind='run.execute', outcome='completed')
assert not backend.flush(6) and backend.lane.failures >= 2
backend.close()
logging.warning('synthetic application record still reaches the formatter')
"""
        result = subprocess.run([sys.executable, "-B", "-c", script, str(port)],
                                capture_output=True, text=True, timeout=20, check=False)
        assert result.returncode == 0, result.stderr
        assert {path for path, _, _ in calls} == {"/v1/traces", "/v1/metrics"}
        assert CANARY not in result.stderr and CANARY not in result.stdout
        assert len(result.stderr.splitlines()) == 1
        assert json.loads(result.stderr)["event"] == "application_log"


def test_connection_refusal_is_bounded(otlp_extra: None) -> None:
    with socket.socket() as refused:
        refused.bind(("127.0.0.1", 0))
        port = refused.getsockname()[1]
        with network.allow("127.0.0.1", port), exporter(port) as backend:
            http_work()
            assert not backend.flush(4)
            assert backend.lane.failures > 0
            http_work()


def test_stalled_collector_drops_batches_without_blocking_work_or_exit(otlp_extra: None) -> None:
    stall = Event()
    with receiver(stall=stall) as (port, _, entered), exporter(port, release=stall) as backend:
        http_work()
        assert backend.processor.force_flush(timeout_millis=1000) and entered.wait(2)
        started = time.monotonic()
        for _ in range(72):
            with ot.span("worker.job"):
                ot.count("jobs", kind="run.execute", outcome="completed")
            assert backend.processor.force_flush(timeout_millis=1000)
        assert not backend.flush(0.05)
        assert backend.lane.queue.qsize() <= 32 and backend.lane.dropped > 0
        http_work()
        assert time.monotonic() - started < 2
        wait_for(lambda: backend.lane.failures > 0, seconds=4)
        started = time.monotonic()
        backend.close()
        assert time.monotonic() - started < 0.25
        # Close while the first network send is active, then prove the child can exit.
        script = """
import sys
import time
from policyops import telemetry as ot
from policyops.settings import TelemetrySettings
base = 'http://127.0.0.1:' + sys.argv[1]
backend = ot.configure(TelemetrySettings(enabled=True, exporter='otlp',
    traces_url=base + '/v1/traces', metrics_url=base + '/v1/metrics'))
with ot.span('worker.job'):
    pass
assert not backend.flush(0.1)
start = time.monotonic()
backend.close()
assert time.monotonic() - start < 0.25
"""
        result = subprocess.run([sys.executable, "-B", "-c", script, str(port)],
                                capture_output=True, text=True, timeout=12, check=False)
        assert result.returncode == 0, result.stderr


def test_disabled_and_memory_leave_otlp_and_protobuf_unimported() -> None:
    script = """
import sys
from policyops import telemetry as ot
from policyops.settings import TelemetrySettings
assert ot.configure(TelemetrySettings()) is None
backend = ot.configure(TelemetrySettings(enabled=True), role='worker')
with ot.span('worker.job'):
    pass
assert backend.flush(2)
assert backend.spans.get_finished_spans()[0].resource.attributes['service.name'] == 'policyops-worker'
assert not any(name.startswith(('opentelemetry.exporter', 'google.protobuf')) for name in sys.modules)
backend.close()
"""
    result = subprocess.run([sys.executable, "-B", "-c", script],
                            capture_output=True, text=True, timeout=12, check=False)
    assert result.returncode == 0, result.stderr


def test_ambient_otel_and_deployment_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_FUTURE_SETTING", "")
    with pytest.raises(ValidationError, match="OTEL_"):
        TelemetrySettings()
    from policyops.api.serve import ServeConfigError, load_config

    with pytest.raises(ServeConfigError, match="OTEL_"):
        load_config()
    monkeypatch.delenv("OTEL_FUTURE_SETTING")
    before = settings(4318)
    monkeypatch.setenv("POLICYOPS_ENV", "deployment")
    with pytest.raises(ValidationError, match="local only"):
        settings(4318)
    with pytest.raises(ValueError, match="local only"):
        ot.configure(before)


@pytest.mark.parametrize("endpoint", [
    None, "https://127.0.0.1:4318/v1/traces", "http://localhost:4318/v1/traces",
    "http://127.0.0.1:0/v1/traces", "http://127.0.0.1:65536/v1/traces",
    "http://user@127.0.0.1:4318/v1/traces", "http://127.0.0.1:4318/v1/metrics",
    "http://127.0.0.1:4318/v1/traces?x=1", "http://192.0.2.1:4318/v1/traces",
])
def test_otlp_requires_explicit_http_signal_urls(endpoint: str | None) -> None:
    with pytest.raises(ValidationError, match="explicit loopback"):
        TelemetrySettings(enabled=True, exporter="otlp", traces_url=endpoint,
                          metrics_url="http://127.0.0.1:4318/v1/metrics")


def test_local_overlay_and_dashboard_match_pinned_contract() -> None:
    infra = ROOT / "infra"
    pin = json.loads((infra / "images.json").read_text(encoding="utf-8"))["images"]["observability"]
    overlay = (infra / "compose/observability.yaml").read_text(encoding="utf-8")
    assert f"image: {pin['image']}@{pin['digest']}" in overlay
    assert re.findall(r'^\s+- "([^"]+)"$', overlay, re.MULTILINE) == [
        "127.0.0.1:${POLICYOPS_OBSERVABILITY_GRAFANA_PORT:-3000}:3000",
        "127.0.0.1:${POLICYOPS_OBSERVABILITY_OTLP_PORT:-4318}:4318",
    ]
    assert "GF_AUTH_ANONYMOUS_ORG_ROLE: Editor" in overlay
    public = (infra / "compose/public.yaml").read_text(encoding="utf-8")
    assert not re.search(r"otlp|observability|4318|telemetry", public, re.I)
    dashboard = json.loads((infra / "observability/dashboard.json").read_text(encoding="utf-8"))
    queries = [query for panel in dashboard["panels"] for query in panel.get("targets", ())]
    assert all(query["datasource"]["uid"] == "prometheus" for query in queries)
    assert {name for query in queries for name in re.findall(r"\bpolicyops_\w+", query["expr"])} == METRICS
