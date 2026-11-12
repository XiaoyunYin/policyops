"""Core telemetry through real application boundaries, offline exporters and synthetic canaries."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Sequence
from contextlib import nullcontext
from decimal import Decimal
import io
import json
import logging
import threading
import time
from typing import Any, cast
from unittest.mock import MagicMock
from uuid import uuid4

import httpx
from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult, MetricsData
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
import pytest

from policyops import telemetry as ot
from policyops.api.app import create_app
from policyops.api.auth import AuthRuntime
from policyops.api.logging import SafeJsonFormatter
from policyops.api.runs import RunsRuntime
from policyops.auth.service import AuthError
from policyops.budget.ledger import Ledger, RunBinding
from policyops.persistence import database as sql
from policyops.persistence import runs as jobs
from policyops.persistence.database import connection_transaction, observe_sql_failure
from policyops.providers.calls import CallLimits, Providers, call
from policyops.runtime import worker as workers
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.spec import Retry, RuntimeCatalog, Succeeded
from policyops.settings import TelemetrySettings
from policyops.telemetry.attributes import ENUMS, METRIC_KEYS, clean
from policyops.telemetry.sdk import Backend, MemoryMetrics, MemorySpans
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.clock import FixedClock
from policyops_contracts.errors import ErrorCode
from policyops_contracts.model import Message, ModelRequest, TextPart
from policyops_testing.agent_fakes import ScriptedModel, says
from policyops_testing.gateway_cases import Setup, W, gateway_for, tool
from policyops_testing.retrieval_fixtures import Scripted, count_reply, luna_reply, openai_json
from policyops_testing.scripted import ScriptedExecutor, scripted_spec
from tests.unit.test_investigation_graph import initial, run
from tests.unit.test_provider_call_grants import KEY, Books


CANARY = "telemetry-private-canary@example.invalid"


def wait_for(check: Any, seconds: float = 2) -> None:
    deadline = time.monotonic() + seconds
    while not check():
        assert time.monotonic() < deadline, "telemetry test did not finish within its bound"
        threading.Event().wait(0.005)


def flush(backend: Backend) -> None:
    assert backend.processor.force_flush(timeout_millis=1000)
    backend.reader.collect(timeout_millis=1000)
    wait_for(lambda: backend.lane.queue.unfinished_tasks == 0)


@pytest.fixture
def backend() -> Iterator[Backend]:
    built = ot.configure(TelemetrySettings(enabled=True))
    assert built is not None
    try:
        yield built
    finally:
        built.close()
        built.shutdown_thread.join(timeout=2)
        built.lane.thread.join(timeout=2)
        assert not built.shutdown_thread.is_alive() and not built.lane.thread.is_alive()


def spans(backend: Backend) -> tuple[ReadableSpan, ...]:
    assert isinstance(backend.spans, MemorySpans)
    return backend.spans.get_finished_spans()


def metric_points(backend: Backend) -> list[tuple[str, dict[str, Any], float]]:
    assert isinstance(backend.metrics, MemoryMetrics)
    return [(metric.name, dict(point.attributes or {}), getattr(point, "value", 0))
            for batch in backend.metrics.items for resource in batch.resource_metrics
            for scope in resource.scope_metrics for metric in scope.metrics for point in metric.data.data_points]


def rendered(backend: Backend) -> str:
    return "\n".join(s.to_json() for s in spans(backend)) + repr(metric_points(backend))


def test_disabled_path_never_constructs_or_calls_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentelemetry import trace

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("disabled telemetry called the SDK/API")
    monkeypatch.setattr(trace, "get_tracer", forbidden)
    monkeypatch.setattr(Backend, "__init__", forbidden)
    assert ot.configure(TelemetrySettings(enabled=False)) is None

    @ot.observed("provider.call")
    def execute() -> int:
        ot.annotate(model=CANARY)
        ot.count("errors", error_code=CANARY)
        return 7
    assert execute() == 7
    with ot.span("worker.job"):
        assert ot.correlation() == {}
    assert not ot.enabled()


def test_typed_allowlist_rejects_values_as_well_as_keys() -> None:
    uid = uuid4()
    assert clean({"run_id": uid, "job_id": str(uid), "model": CANARY, "tool": CANARY, "prompt": CANARY,
                  "input_tokens": True, "attempt": -1, "http_route": "/" + CANARY}) == {"run_id": str(uid)}
    assert clean({"run_id": uid, "model": "gpt-6-luna", "attempt": 2}, metric=True) == {"model": "gpt-6-luna"}


def test_http_canaries_and_untrusted_trace_headers_never_enter_telemetry(backend: Backend) -> None:
    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as client:
            response = await client.get("/api/v1/health/live", params={"code": CANARY},
                headers={"cookie": CANARY, "authorization": CANARY, "baggage": CANARY,
                         "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"})
            assert response.status_code == 200
            await client.post("/" + CANARY, content=CANARY)
    asyncio.run(exercise())
    flush(backend)
    http = [s for s in spans(backend) if s.name == "http.request"]
    assert len(http) == 2
    assert http[0].attributes is not None
    assert http[0].attributes["http_route"] == "/api/v1/health/live"
    assert http[0].context is not None and http[0].context.trace_id != int("1" * 32, 16)
    assert http[1].attributes is not None and "http_route" not in http[1].attributes
    assert CANARY not in rendered(backend)


def test_http_included_routes_keep_prefix_and_template_on_auth_refusal(backend: Backend) -> None:
    auth = MagicMock()
    auth.service.resolve.side_effect = AuthError(401, ErrorCode.UNAUTHENTICATED, "Sign in.", "auth.required")
    app = create_app(cast(AuthRuntime, auth), cast(RunsRuntime, MagicMock()))
    run_id = uuid4()

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for path in (f"/api/v1/runs/{run_id}", f"/api/v1/cases/{CANARY}/runs"):
                assert (await client.get(path)).status_code == 401
            assert (await client.put(f"/api/v1/runs/{CANARY}")).status_code == 405
            assert (await client.get("/api/v1/" + CANARY)).status_code == 404
    asyncio.run(exercise())
    flush(backend)
    http = [s for s in spans(backend) if s.name == "http.request"]
    assert [dict(s.attributes or {}).get("http_route") for s in http] == [
        "/api/v1/runs/{run_id}", "/api/v1/cases/{case_id}/runs", "/api/v1/runs/{run_id}", None,
    ]
    assert str(run_id) not in rendered(backend) and CANARY not in rendered(backend)


def test_real_provider_retry_preserves_parent_trace_and_counts_known_bills(backend: Backend) -> None:
    books = Books()
    scripted = Scripted(counts=[count_reply(1000), count_reply(1000)],
                        creates=[openai_json({"error": {"message": CANARY}}, 503), luna_reply(CANARY)])
    request = ModelRequest(instructions=CANARY, max_output_tokens=256,
                           messages=(Message(role="user", parts=(TextPart(text=CANARY),)),))
    run_id = uuid4()
    report = asyncio.run(call(cast(Ledger, books), Providers(credentials={"openai": KEY}, transport=lambda _: scripted),
        RunBinding(run_id), uuid4(), CANARY, request, "agent",
        deadline=time.monotonic() + 20, limits=CallLimits(repairs=0, backoff_seconds=0)))
    assert report.status == "result" and report.result is not None and report.result.text == CANARY
    assert scripted.seen == ["count", "create", "count", "create"]
    flush(backend)
    attempts = [s for s in spans(backend) if s.name == "provider.call"]
    parent = next(s for s in spans(backend) if s.name == "provider.request")
    assert len(attempts) == 2 and parent.context is not None
    assert all(s.parent is not None and s.parent.span_id == parent.context.span_id for s in attempts)
    assert all(s.context is not None and s.context.trace_id == parent.context.trace_id for s in attempts)
    assert all(s.attributes is not None and s.attributes["run_id"] == str(run_id) for s in attempts)
    points = metric_points(backend)
    assert any(n.endswith("provider.calls") and a["outcome"] == "failed" and v == 1 for n, a, v in points)
    assert any(n.endswith("provider.input_tokens") and v == 900 for n, a, v in points)
    assert any(n.endswith("provider.cost_usd") and v == pytest.approx(0.00011) for n, a, v in points)
    assert CANARY not in rendered(backend)


def test_tool_arguments_and_exceptions_are_not_serialized(backend: Backend) -> None:
    gateway, _, _ = gateway_for(Setup(authenticated=False))
    raw = tool("find_user_id_by_email", email=CANARY)
    from policyops.gateway.steps import parse_result
    parsed = parse_result(raw)
    assert isinstance(parsed, ToolCallStep)
    gateway.step(parsed, previous=None, sequence=1)
    with pytest.raises(RuntimeError, match="telemetry-private"), ot.span("gateway.step"):
        raise RuntimeError(CANARY)
    flush(backend)
    assert CANARY not in rendered(backend)
    last = spans(backend)[-1]
    assert last.attributes is not None and last.attributes["exception_type"] == "RuntimeError"
    assert last.events == () and last.status.description is None


def test_graph_nodes_never_record_state_or_model_text(backend: Backend) -> None:
    run(ScriptedModel([says(CANARY)]), state=initial())
    flush(backend)
    nodes = [s for s in spans(backend) if s.name == "graph.node"]
    assert nodes and all(s.attributes is not None and s.attributes["node"] in ENUMS["node"] for s in nodes)
    assert CANARY not in rendered(backend)


def test_resume_links_are_bounded_and_restart_falls_back_to_uuid_correlation(backend: Backend) -> None:
    run_id, job_id, operation_id = uuid4(), uuid4(), uuid4()
    for attempt in (1, 2):
        with ot.span("worker.job"):
            ot.claim(run_id=run_id, job_id=job_id, attempt=attempt, generation=attempt)
            ot.annotate(operation_id=operation_id)
    backend.claims.clear()  # the same absence as a fresh worker process
    with ot.span("worker.job"):
        ot.claim(run_id=run_id, job_id=job_id, attempt=3, generation=3)
        ot.annotate(operation_id=operation_id)
    flush(backend)
    first, second, restarted = spans(backend)
    assert len(second.links) == 1 and second.links[0].context == first.context
    assert not restarted.links
    assert restarted.attributes is not None and restarted.attributes["operation_id"] == str(operation_id)
    assert restarted.attributes["run_id"] == str(run_id)
    for _ in range(300):
        with ot.span("worker.job"):
            ot.claim(run_id=uuid4(), job_id=uuid4(), attempt=1, generation=1)
    assert len(backend.claims) == 256


def test_worker_retry_keeps_claim_execution_and_finish_under_linked_job_spans(
    backend: Backend, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = ScriptedExecutor(events=0, outcome="retry")
    spec = scripted_spec(executor)
    worker = workers.Worker(app_engine=MagicMock(), discovery_engine=MagicMock(),
                            clock=FixedLeaseClock(FixedClock(W.now)), catalog=RuntimeCatalog.of([spec]))
    run_id, job_id, workspace_id = uuid4(), uuid4(), uuid4()
    delivered: list[Any] = []

    @ot.observed("worker.claim")
    def claimed(*args: Any) -> Any:
        attempt = len(delivered) + 1
        return jobs.ClaimToken(workspace_id, run_id, job_id, uuid4(), worker.owner, attempt, attempt), uuid4(), spec

    @ot.observed("worker.finish")
    def finish(token: jobs.ClaimToken, result: Any) -> None:
        delivered.append(result)

    monkeypatch.setattr(workers, "workspace_transaction", lambda *a, **k: nullcontext())
    monkeypatch.setattr(jobs, "get_job", lambda *a, **k: None)
    monkeypatch.setattr(worker, "claim", claimed)
    monkeypatch.setattr(worker, "finish", finish)
    assert worker.process(job_id, workspace_id)
    executor.outcome = "succeed"
    assert worker.process(job_id, workspace_id)
    assert isinstance(delivered[0], Retry) and isinstance(delivered[1], Succeeded)
    flush(backend)
    attempts = [s for s in spans(backend) if s.name == "worker.job"]
    assert len(attempts) == 2 and attempts[1].links[0].context == attempts[0].context
    for parent in attempts:
        assert parent.context is not None
        children = [s.name for s in spans(backend) if s.parent is not None
                    and s.parent.span_id == parent.context.span_id]
        assert children == ["worker.claim", "worker.execute", "worker.finish"]


def test_metric_cardinality_and_export_memory_are_bounded(backend: Backend) -> None:
    for _ in range(1000):
        ot.count("jobs", kind="run.execute", outcome="completed", run_id=uuid4(), model=CANARY)
        ot.count("errors", error_code=CANARY, job_id=uuid4())
    ot.provider_usage(provider="openai", model="gpt-6-luna", outcome="completed",
                      input_tokens=20, output_tokens=3, usd=Decimal("0.00001"))
    for _ in range(20):
        backend.reader.collect()
    flush(backend)
    points = metric_points(backend)
    assert all(set(a) <= METRIC_KEYS for _, a, _ in points)
    assert len({(n, tuple(sorted(a.items()))) for n, a, _ in points}) == 6
    assert all(v in ENUMS[k] for _, a, _ in points for k, v in a.items())
    assert isinstance(backend.metrics, MemoryMetrics) and len(backend.metrics.items) <= 16


def test_sql_failure_emits_only_phase_state_class_and_type(backend: Backend) -> None:
    class DriverError(RuntimeError):
        sqlstate = "57014"
    observe_sql_failure(DriverError(CANARY), "commit")
    flush(backend)
    failure = spans(backend)[0]
    assert failure.attributes == {"phase": "commit", "sqlstate_class": "57", "exception_type": "DriverError",
                                   "error_code": "sql_failure", "outcome": "error"}
    assert CANARY not in rendered(backend)


def test_json_logs_drop_preformatted_content_and_preserve_typed_ids(backend: Backend) -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJsonFormatter())
    logger = logging.Logger("synthetic")
    logger.addHandler(handler)
    with ot.span("worker.job"):
        uid = uuid4()
        try:
            raise ValueError(CANARY)
        except ValueError:
            logger.error(CANARY, CANARY, exc_info=True, extra={"run_id": uid, "prompt": CANARY,
                                                             "model": CANARY, "job_id": CANARY})
    item = json.loads(stream.getvalue())
    assert item["run_id"] == str(uid) and item["exception_type"] == "ValueError"
    assert len(item["trace_id"]) == 32 and len(item["span_id"]) == 16
    assert CANARY not in stream.getvalue() and "prompt" not in item and "job_id" not in item


class RaisingSpans(SpanExporter):
    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        raise RuntimeError(CANARY)


class RaisingMetrics(MetricExporter):
    def export(self, metrics_data: MetricsData, timeout_millis: float = 10_000, **kwargs: Any) -> MetricExportResult:
        raise RuntimeError(CANARY)

    def force_flush(self, timeout_millis: float = 10_000) -> bool:
        raise RuntimeError(CANARY)

    def shutdown(self, timeout_millis: float = 30_000, **kwargs: Any) -> None:
        raise RuntimeError(CANARY)


@pytest.mark.parametrize("blocked", [False, True])
def test_raising_and_blocking_exporters_cannot_block_application_or_shutdown(
    blocked: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered, release = threading.Event(), threading.Event()

    class Exporter(RaisingSpans):
        def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
            entered.set()
            if blocked:
                release.wait(10)
            return super().export(spans)
    built = ot.configure(TelemetrySettings(enabled=True), span_exporter=Exporter(), metric_exporter=RaisingMetrics())
    assert built is not None
    try:
        with ot.span("worker.job"):
            ot.count("jobs", kind="run.execute", outcome="completed")
        assert built.processor.force_flush(timeout_millis=1000)
        assert entered.wait(2)
        started = time.monotonic()
        # Real request/provider/gateway paths and a spied transaction commit while export is blocked/raising.
        http_work()
        books = Books()
        scripted = Scripted(counts=[count_reply(1000)], creates=[luna_reply(CANARY)])
        request = ModelRequest(instructions=CANARY, max_output_tokens=256,
                               messages=(Message(role="user", parts=(TextPart(text=CANARY),)),))
        ports = Providers(credentials={"openai": KEY}, transport=lambda _: scripted)
        result = asyncio.run(call(cast(Ledger, books), ports,
            RunBinding(uuid4()), uuid4(), "test", request, "agent",
            deadline=time.monotonic() + 10))
        assert result.status == "result" and "settle" in books.log
        gateway, _, _ = gateway_for(Setup())
        from policyops_contracts.agent import MessageStep
        assert gateway.step(MessageStep(text=CANARY), previous=None, sequence=1).observation is None
        monkeypatch.setattr(sql, "initialize_transaction", lambda *a, **k: None)
        connection = MagicMock()
        with connection_transaction(connection):
            pass
        connection.begin.return_value.commit.assert_called_once()
        for _ in range(60):
            with ot.span("execution.dispatch"):
                pass
            assert built.processor.force_flush(timeout_millis=1000)
            built.reader.collect()
        built.close()
        assert time.monotonic() - started < 2
        assert built.lane.queue.qsize() <= 32
        if blocked:
            assert built.lane.dropped > 0
    finally:
        release.set()
        built.close()
        built.shutdown_thread.join(timeout=2)
        built.lane.thread.join(timeout=2)
    assert built.lane.failures > 0
    assert not built.lane.thread.is_alive()


def http_work() -> None:
    """Real liveness request used by the exporter-isolation test (also valid with telemetry off)."""
    async def request() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as client:
            assert (await client.get("/api/v1/health/live")).status_code == 200
    asyncio.run(request())


def test_initialization_failure_releases_acquired_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.telemetry import sdk

    original = set(threading.enumerate())

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("synthetic setup failure")
    monkeypatch.setattr(sdk, "MeterProvider", fail)
    with pytest.raises(RuntimeError, match="synthetic setup failure"):
        ot.configure(TelemetrySettings(enabled=True))
    assert not ot.enabled()
    wait_for(lambda: not (set(threading.enumerate()) - original))
