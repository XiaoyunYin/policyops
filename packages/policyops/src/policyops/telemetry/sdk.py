"""SDK construction, bounded export and bounded local exporters. Imported only on explicit opt-in."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from importlib import import_module
import math
from queue import Empty, Full, Queue
import threading
import time
from typing import Any, cast
from uuid import UUID

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricExporter,
    MetricExportResult,
    MetricsData,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.metrics.view import ExplicitBucketHistogramAggregation, View
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.trace import SpanContext

from policyops.settings import TelemetrySettings
from policyops.telemetry import ServiceRole, detach
from policyops.telemetry.attributes import CANARY_FINALIZED, CANARY_LABELS


SCHEMA_URL = "https://policyops.local/schemas/telemetry/v1"
DISPATCH_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)
DISPATCH_HISTOGRAM = "policyops.provider.dispatch_duration"


def _otlp_exporters(settings: TelemetrySettings) -> tuple[SpanExporter, MetricExporter]:
    """Keep the optional transport and protobuf outside the default import graph."""
    try:
        traces = import_module("opentelemetry.exporter.otlp.proto.http.trace_exporter")
        metrics = import_module("opentelemetry.exporter.otlp.proto.http.metric_exporter")
        requests = import_module("requests")
    except ImportError as error:
        raise RuntimeError("OTLP requires the policyops[otlp] extra") from error

    def local_session() -> Any:
        session = requests.Session()
        session.trust_env = False
        # Requests otherwise prepares a redirect even with allow_redirects=False.
        session.get_redirect_target = lambda response: None
        send = session.send

        def status_only(request: Any, **kwargs: Any) -> Any:
            kwargs.update(allow_redirects=False, stream=True)
            try:
                with send(request, **kwargs) as response:
                    safe = requests.Response()
                    # Requests treats redirects as success. Reject them without reading their headers or body.
                    safe.status_code = 400 if 300 <= response.status_code < 400 else response.status_code
                    safe._content = b""
                    return safe
            except requests.exceptions.RequestException:
                # Protocol errors can quote bytes supplied by the collector.
                raise requests.exceptions.ConnectionError("OTLP request failed") from None
            finally:
                session.cookies.clear()

        session.send = status_only
        return session

    span_session, metric_session = local_session(), local_session()
    try:
        spans = traces.OTLPSpanExporter(endpoint=settings.traces_url, session=span_session, timeout=1.0)
        points = metrics.OTLPMetricExporter(endpoint=settings.metrics_url, session=metric_session, timeout=1.0)
    except BaseException:
        span_session.close()
        metric_session.close()
        raise
    return cast(SpanExporter, spans), cast(MetricExporter, points)


class MemorySpans(SpanExporter):
    """Last 256 spans only. Inspect get_finished_spans() from trusted local/test code."""

    def __init__(self) -> None:
        self.items: deque[ReadableSpan] = deque(maxlen=256)

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.items.extend(spans)
        return SpanExportResult.SUCCESS

    def get_finished_spans(self) -> tuple[ReadableSpan, ...]:
        return tuple(self.items)


class MemoryMetrics(MetricExporter):
    def __init__(self) -> None:
        super().__init__()
        self.items: deque[MetricsData] = deque(maxlen=16)

    def export(self, metrics_data: MetricsData, timeout_millis: float = 10_000, **kwargs: Any) -> MetricExportResult:
        self.items.append(metrics_data)
        return MetricExportResult.SUCCESS

    def force_flush(self, timeout_millis: float = 10_000) -> bool:
        return True

    def shutdown(self, timeout_millis: float = 30_000, **kwargs: Any) -> None:
        pass


class Lane:
    """One daemon, 32 pending batches. Blocking untrusted exporter code cannot be killed in Python.

    It may retain its one active batch until it returns/process exits. Never join it or create replacement
    threads. Drop overflow; shutdown is best effort, and none of this is an audit/billing source.
    """

    def __init__(self) -> None:
        self.queue: Queue[Callable[[], object]] = Queue(maxsize=32)
        self.closed = threading.Event()
        self.failures = 0
        self.dropped = 0
        self.thread = threading.Thread(target=self._run, name="policyops-export", daemon=True)
        self.thread.start()

    def submit(self, work: Callable[[], object]) -> None:
        if self.closed.is_set():
            return
        try:
            self.queue.put_nowait(work)
        except Full:
            self.dropped += 1

    def _run(self) -> None:
        while not self.closed.is_set() or not self.queue.empty():
            try:
                work = self.queue.get(timeout=0.05)
            except Empty:
                continue
            try:
                result = work()
                if result in (SpanExportResult.FAILURE, MetricExportResult.FAILURE):
                    self.failures += 1
            except BaseException:
                self.failures += 1  # no exception messages or SDK logger fallback
            finally:
                self.queue.task_done()


class QueuedSpans(SpanExporter):
    def __init__(self, exporter: SpanExporter, lane: Lane) -> None:
        self.exporter, self.lane = exporter, lane

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        batch = tuple(spans)
        self.lane.submit(lambda: self.exporter.export(batch))
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self.lane.submit(self.exporter.shutdown)


class QueuedMetrics(MetricExporter):
    def __init__(self, exporter: MetricExporter, lane: Lane) -> None:
        super().__init__()
        self.exporter, self.lane = exporter, lane

    def export(self, metrics_data: MetricsData, timeout_millis: float = 10_000, **kwargs: Any) -> MetricExportResult:
        self.lane.submit(lambda: self.exporter.export(metrics_data, timeout_millis=timeout_millis))
        return MetricExportResult.SUCCESS

    def force_flush(self, timeout_millis: float = 10_000) -> bool:
        return True

    def shutdown(self, timeout_millis: float = 30_000, **kwargs: Any) -> None:
        self.lane.submit(lambda: self.exporter.shutdown(timeout_millis=timeout_millis))


class Backend:
    def __init__(self, settings: TelemetrySettings, *, role: ServiceRole = "api",
                 span_exporter: SpanExporter | None = None,
                 metric_exporter: MetricExporter | None = None) -> None:
        if role not in ("api", "worker", "demo", "canary"):
            raise ValueError("invalid telemetry service role")
        if settings.exporter == "otlp":
            if span_exporter is not None or metric_exporter is not None:
                raise ValueError("OTLP requires the built-in exporters")
            self.spans, self.metrics = _otlp_exporters(settings)
        else:
            self.spans = span_exporter if span_exporter is not None else (
                ConsoleSpanExporter() if settings.exporter == "console" else MemorySpans())
            self.metrics = metric_exporter if metric_exporter is not None else (
                ConsoleMetricExporter() if settings.exporter == "console" else MemoryMetrics())
        self.claim_lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self.claims: OrderedDict[UUID, tuple[int, SpanContext]] = OrderedDict()
        self.lane = Lane()
        self.closed = False
        self._releases: list[Callable[[], None]] = []
        try:
            self._install(role)
        except BaseException:
            self.close()
            raise

    def _install(self, role: ServiceRole) -> None:
        resource = Resource({"service.name": f"policyops-{role}", "service.version": "0.1.0"}, schema_url=SCHEMA_URL)
        self.traces = TracerProvider(resource=resource, shutdown_on_exit=False,
                                     sampler=ALWAYS_ON,
                                     span_limits=SpanLimits(max_attributes=32, max_events=0, max_links=1))
        self._releases.append(self.traces.shutdown)
        self.processor = BatchSpanProcessor(QueuedSpans(self.spans, self.lane), max_queue_size=256,
                                            max_export_batch_size=32, schedule_delay_millis=1000)
        self._releases.append(self.processor.shutdown)
        self.traces.add_span_processor(self.processor)
        self._releases.pop()  # the tracer provider now owns the processor
        self.tracer = self.traces.get_tracer("policyops", "1.0.0", schema_url=SCHEMA_URL)
        self.reader = PeriodicExportingMetricReader(QueuedMetrics(self.metrics, self.lane),
                                                    export_interval_millis=5000, export_timeout_millis=1000)
        self._releases.append(self.reader.shutdown)
        self.meters = MeterProvider(
            resource=resource, metric_readers=[self.reader], shutdown_on_exit=False,
            views=[View(instrument_name=DISPATCH_HISTOGRAM,
                        aggregation=ExplicitBucketHistogramAggregation(boundaries=DISPATCH_BUCKETS))],
        )
        self._releases.pop()  # the meter provider now owns the reader
        self._releases.append(lambda: self.meters.shutdown(timeout_millis=1000))
        meter = self.meters.get_meter("policyops", "1.0.0", schema_url=SCHEMA_URL)
        self.instruments = {name: meter.create_counter("policyops." + name, unit=unit) for name, unit in (
            ("provider.calls", "{call}"), ("provider.input_tokens", "{token}"),
            ("provider.output_tokens", "{token}"), ("provider.cost_usd", "USD"), ("errors", "{error}"),
            ("jobs", "{job}"), ("reviews", "{review}"), ("executions", "{execution}"))}
        self.gauges = {"queue.depth": meter.create_gauge("policyops.queue.depth", unit="{job}"),
                       "queue.oldest_due_age": meter.create_gauge("policyops.queue.oldest_due_age", unit="s")}
        if role == "canary":
            self.gauges.update({name: meter.create_gauge("policyops." + name, unit="1") for name in CANARY_LABELS})
            self.gauges[CANARY_FINALIZED] = meter.create_gauge("policyops." + CANARY_FINALIZED, unit="s")
        self.dispatch_duration = meter.create_histogram(DISPATCH_HISTOGRAM, unit="s")

    def measure(self, name: str, value: int | float, attributes: dict[str, str | int]) -> None:
        if type(value) not in (int, float) or not 0 <= value <= 2**53:
            return
        if name in CANARY_LABELS:
            label, values = CANARY_LABELS[name]
            if attributes.keys() != {label} or attributes[label] not in values:
                return
        if name == CANARY_FINALIZED and attributes:
            return
        if name in self.gauges:
            self.gauges[name].set(value, attributes)
        elif name == "provider.dispatch_duration":
            self.dispatch_duration.record(value, attributes)
        elif name in self.instruments:
            self.instruments[name].add(value, attributes)

    def flush(self, seconds: float) -> bool:
        """Try to export finished spans and current metrics within a caller-side deadline.

        True means both SDK pipelines reached the export lane and no lane losses have been observed.
        A busy flush or a timed-out SDK operation never creates additional background work.
        """
        if not math.isfinite(seconds) or not 0 < seconds <= threading.TIMEOUT_MAX:
            raise ValueError("flush needs a finite positive timeout")
        if self.closed or not self._flush_lock.acquire(blocking=False):
            return False
        deadline = time.monotonic() + seconds
        done = threading.Event()
        delivered = threading.Event()

        def collect() -> None:
            try:
                if not self.processor.force_flush(timeout_millis=int(seconds * 1000)):
                    return
                self.reader.collect(timeout_millis=max(0, deadline - time.monotonic()) * 1000)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.closed:
                    return
                barrier = threading.Event()
                self.lane.queue.put(barrier.set, timeout=remaining)
                if (barrier.wait(max(0, deadline - time.monotonic()))
                        and self.lane.failures == self.lane.dropped == 0):
                    delivered.set()
            except Full:
                pass
            except Exception:
                self.lane.failures += 1
            finally:
                self._flush_lock.release()
                done.set()

        try:
            threading.Thread(target=collect, name="policyops-telemetry-flush", daemon=True).start()
        except BaseException:
            self._flush_lock.release()
            raise
        return done.wait(max(0, deadline - time.monotonic())) and delivered.is_set()

    def close(self) -> None:
        """Detach immediately. Never wait on SDK joins/exporter cleanup on an application thread."""
        if self.closed:
            return
        self.closed = True
        detach(self)

        def finish() -> None:
            try:
                while self._releases:
                    release = self._releases.pop()
                    try:
                        release()
                    except BaseException:
                        self.lane.failures += 1
            finally:
                self.lane.closed.set()
        self.shutdown_thread = threading.Thread(target=finish, name="policyops-telemetry-stop", daemon=True)
        self.shutdown_thread.start()
