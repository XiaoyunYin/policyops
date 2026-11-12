"""SDK construction, bounded export and bounded local exporters. Imported only on explicit opt-in."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from queue import Empty, Full, Queue
import threading
from typing import Any
from uuid import UUID

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricExporter,
    MetricExportResult,
    MetricsData,
    PeriodicExportingMetricReader,
)
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
from policyops.telemetry import detach


SCHEMA_URL = "https://policyops.local/schemas/telemetry/v1"


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
    def __init__(self, settings: TelemetrySettings, *, span_exporter: SpanExporter | None = None,
                 metric_exporter: MetricExporter | None = None) -> None:
        self.spans = span_exporter if span_exporter is not None else (
            ConsoleSpanExporter() if settings.exporter == "console" else MemorySpans())
        self.metrics = metric_exporter if metric_exporter is not None else (
            ConsoleMetricExporter() if settings.exporter == "console" else MemoryMetrics())
        self.claim_lock = threading.Lock()
        self.claims: OrderedDict[UUID, tuple[int, SpanContext]] = OrderedDict()
        self.lane = Lane()
        self.closed = False
        self._releases: list[Callable[[], None]] = []
        try:
            self._install()
        except BaseException:
            self.close()
            raise

    def _install(self) -> None:
        resource = Resource({"service.name": "policyops", "service.version": "0.1.0"}, schema_url=SCHEMA_URL)
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
        self.meters = MeterProvider(resource=resource, metric_readers=[self.reader], shutdown_on_exit=False)
        self._releases.pop()  # the meter provider now owns the reader
        self._releases.append(lambda: self.meters.shutdown(timeout_millis=1000))
        meter = self.meters.get_meter("policyops", "1.0.0", schema_url=SCHEMA_URL)
        self.instruments = {name: meter.create_counter("policyops." + name, unit=unit) for name, unit in (
            ("provider.calls", "{call}"), ("provider.input_tokens", "{token}"),
            ("provider.output_tokens", "{token}"), ("provider.cost_usd", "USD"), ("errors", "{error}"),
            ("jobs", "{job}"), ("reviews", "{review}"), ("executions", "{execution}"))}
        self.gauges = {"queue.depth": meter.create_gauge("policyops.queue.depth", unit="{job}"),
                       "queue.oldest_due_age": meter.create_gauge("policyops.queue.oldest_due_age", unit="s")}

    def measure(self, name: str, value: int | float, attributes: dict[str, str | int]) -> None:
        if type(value) not in (int, float) or not 0 <= value <= 2**53:
            return
        if name in self.gauges:
            self.gauges[name].set(value, attributes)
        elif name in self.instruments:
            self.instruments[name].add(value, attributes)

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
