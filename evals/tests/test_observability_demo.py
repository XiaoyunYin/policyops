"""Driver smoke against the same PostgreSQL and simulator path used by the local demo."""

from importlib import import_module
from pathlib import Path
from types import ModuleType

from opentelemetry.sdk.metrics.export import Histogram, Sum
import pytest

from policyops.settings import TelemetrySettings
import policyops.telemetry as ot
from policyops.telemetry.sdk import MemoryMetrics, MemorySpans
from policyops_testing.postgres import OwnedPostgres

from .scenario_support import pinned_tree


@pytest.fixture
def demo_driver(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    return import_module("scripts.observability_demo")


@pytest.mark.parametrize(
    ("value", "expected"), [(None, 4318), ("", 4318), ("1", 1), ("04319", 4319), ("65535", 65535)],
)
def test_demo_host_port(
    demo_driver: ModuleType, monkeypatch: pytest.MonkeyPatch, value: str | None, expected: int,
) -> None:
    variable = "POLICYOPS_OBSERVABILITY_OTLP_PORT"
    if value is None:
        monkeypatch.delenv(variable, raising=False)
    else:
        monkeypatch.setenv(variable, value)
    assert demo_driver.host_port(variable, 4318) == expected


@pytest.mark.parametrize("value", ["0", "-1", "65536", "1_000", "4318.0", "localhost:4318"])
def test_demo_refuses_invalid_host_port(
    demo_driver: ModuleType, monkeypatch: pytest.MonkeyPatch, value: str,
) -> None:
    variable = "POLICYOPS_OBSERVABILITY_GRAFANA_PORT"
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=variable):
        demo_driver.host_port(variable, 3000)


@pytest.mark.postgres
def test_demo_trace_and_usage_ledger(postgres: OwnedPostgres, tmp_path: Path, demo_driver: ModuleType) -> None:
    backend = ot.configure(TelemetrySettings(enabled=True, exporter="memory"), role="demo")
    assert backend is not None
    try:
        result = demo_driver.run_demo(postgres, tmp_path, pinned_tree(), backend)
        assert backend.flush(6)
        assert isinstance(backend.spans, MemorySpans) and isinstance(backend.metrics, MemoryMetrics)
        spans = [span for span in backend.spans.get_finished_spans() if span.context is not None
                 and f"{span.context.trace_id:032x}" == result.trace]
        [root] = [span for span in spans if span.parent is None]
        assert root.name == "investigation"
        assert root.attributes == {"run_id": str(result.run), "outcome": "ok"}
        assert root.context is not None
        direct = [span for span in spans if span.parent == root.context]
        [proposed] = [span for span in spans if span.name == "graph.node"
                      and (span.attributes or {}).get("node") == "propose"]
        [consent] = [span for span in direct if span.name == "review.execute"]
        [approval] = [span for span in direct if span.name == "review.finish"]
        [dispatch] = [span for span in spans if span.name == "execution.dispatch"]
        [batch] = [span for span in direct if span.name == "execution.batch"]
        [step] = [span for span in spans if span.name == "execution.step" and span.parent == batch.context]
        assert dispatch.parent == step.context
        [investigation] = [span for span in spans if span.name == "investigation" and span is not root]
        by_context = {(context.trace_id, context.span_id): span for span in spans
                      if (context := span.context) is not None}
        assert investigation.context is not None
        investigation_key = (investigation.context.trace_id, investigation.context.span_id)
        parent = proposed.parent
        while parent is not None:
            parent_key = (parent.trace_id, parent.span_id)
            if parent_key == investigation_key:
                break
            parent = by_context[parent_key].parent
        assert parent is not None
        assert all((span.attributes or {}).get("proposal_id") == str(result.proposal)
                   for span in (consent, approval, dispatch))
        assert (dispatch.attributes or {}).get("operation_id") == str(result.operation)
        projected = [span for span in spans if span.name == "review.finish" and span not in direct]
        receipt = max(projected, key=lambda span: span.start_time or 0)
        assert any(span.name == "review.job" and span.context == receipt.parent for span in spans)
        stages = (proposed, consent, approval, dispatch, receipt)
        starts = [span.start_time or 0 for span in stages]
        assert starts == sorted(starts) and len(set(starts)) == len(stages)
        assert all((span.attributes or {}).get("run_id") == str(result.run) for span in stages)
        batch_metrics = backend.metrics.items[-1]
        metrics = {metric.name: metric.data for resource in batch_metrics.resource_metrics
                   for scope in resource.scope_metrics for metric in scope.metrics}
        for name, expected in (("input_tokens", result.input_tokens), ("output_tokens", result.output_tokens)):
            total = metrics[f"policyops.provider.{name}"]
            assert isinstance(total, Sum)
            assert sum(p.value for p in total.data_points
                       if (p.attributes or {}).get("model") == "gpt-6-luna") == expected
        dispatch_metric = metrics["policyops.provider.dispatch_duration"]
        assert isinstance(dispatch_metric, Histogram)
        assert any(p.count > 0 and (p.attributes or {}).get("model") == "text-embedding-3-small"
                   for p in dispatch_metric.data_points)
        assert sum(p.count for p in dispatch_metric.data_points
                   if (p.attributes or {}).get("model") == "gpt-6-luna") == result.calls == 4
    finally:
        backend.close()
        backend.shutdown_thread.join(timeout=2)
        backend.lane.thread.join(timeout=2)
