"""Opt-in manual observability. Disabled instrumentation never calls the OTel API or SDK.

Only this facade is used by application code. No arbitrary attributes, automatic exception
events, baggage, global provider, environment Resource detector or inbound propagation.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from decimal import Decimal
from functools import wraps
import inspect
import time
from typing import TYPE_CHECKING, Any, Literal, ParamSpec, Protocol, TypeVar, Unpack
from uuid import UUID

from policyops.telemetry.attributes import Attributes, clean


if TYPE_CHECKING:
    from opentelemetry.trace import SpanContext

    from policyops.settings import TelemetrySettings
    from policyops.telemetry.sdk import Backend

SpanName = Literal["http.request", "worker.job", "worker.claim", "worker.execute", "worker.finish",
                   "review.job", "review.claim", "review.execute", "review.finish", "investigation",
                   "graph.node", "provider.request", "provider.call", "retrieval.step", "gateway.step",
                   "execution.batch", "execution.reserve", "execution.step", "execution.dispatch",
                   "execution.reconcile", "sql.failure"]
MetricName = Literal["provider.calls", "provider.input_tokens", "provider.output_tokens", "provider.cost_usd",
                     "provider.dispatch_duration",
                     "errors", "jobs", "reviews", "executions", "queue.depth", "queue.oldest_due_age",
                     "canary.proposal_window_count", "canary.ambiguous_window_count",
                     "canary.gateway_window_count", "canary.last_finalized_timestamp"]
ServiceRole = Literal["api", "worker", "demo", "canary"]


class Span(Protocol):
    def set_attributes(self, attributes: dict[str, str | int]) -> None: ...
    def get_span_context(self) -> SpanContext: ...
    def add_link(self, context: SpanContext) -> None: ...


@dataclass
class Frame:
    span: Span
    attributes: dict[str, str | int] = field(default_factory=dict)


_frame: ContextVar[Frame | None] = ContextVar("policyops_telemetry", default=None)
_backend: Backend | None = None
P = ParamSpec("P")
R = TypeVar("R")


def enabled() -> bool:
    return _backend is not None


def configure(settings: TelemetrySettings, *, role: ServiceRole = "api", **exporters: Any) -> Backend | None:
    """Process owner calls once and owns close(). Custom exporters are trusted, server-owned code."""
    global _backend
    settings.require_safe_environment()
    if not settings.enabled:
        return None
    if _backend is not None:
        raise RuntimeError("telemetry already configured")
    from policyops.telemetry.sdk import Backend

    backend = Backend(settings, role=role, **exporters)
    _backend = backend
    return backend


def detach(backend: Backend) -> None:
    global _backend
    if _backend is backend:
        _backend = None


def annotate(**attributes: Unpack[Attributes]) -> None:
    frame = _frame.get() if _backend is not None else None
    if frame is not None:
        safe = clean(attributes)
        frame.attributes.update(safe)
        frame.span.set_attributes(safe)


def count(name: MetricName, value: int | float = 1, **attributes: Unpack[Attributes]) -> None:
    backend = _backend
    if backend is not None:
        backend.measure(name, value, clean(attributes, metric=True))


@contextmanager
def provider_dispatch(provider: str, model: str) -> Iterator[None]:
    """Time one adapter send, including its response/cleanup, outside accounting and backoff."""
    if _backend is None:
        yield
        return
    started = time.monotonic()
    try:
        yield
    finally:
        count("provider.dispatch_duration", time.monotonic() - started, provider=provider, model=model)


def correlation() -> dict[str, str]:
    frame = _frame.get() if _backend is not None else None
    if frame is None:
        return {}
    context = frame.span.get_span_context()
    return {"trace_id": f"{context.trace_id:032x}", "span_id": f"{context.span_id:016x}"} if context.is_valid else {}


@contextmanager
def span(name: SpanName, **attributes: Unpack[Attributes]) -> Iterator[None]:
    backend = _backend
    if backend is None:
        yield
        return
    # SDK setup/recording is local only. Exporters never run on this thread.
    with backend.tracer.start_as_current_span(name, attributes=clean(attributes),
                                              record_exception=False, set_status_on_exception=False) as current:
        inherited = _frame.get()
        inherited_ids = {} if inherited is None else {
            key: value for key, value in inherited.attributes.items()
            if key in {"run_id", "job_id", "attempt", "generation", "operation_id", "proposal_id"}}
        frame = Frame(current, inherited_ids | clean(attributes))
        current.set_attributes(frame.attributes)
        token = _frame.set(frame)
        if "outcome" not in frame.attributes:
            annotate(outcome="ok")
        try:
            yield
        except BaseException as error:
            annotate(outcome="cancelled" if isinstance(error, asyncio.CancelledError) else "error",
                     exception_type=type(error).__name__, error_code="boundary_error")
            count("errors", error_code="boundary_error")
            raise
        finally:
            _frame.reset(token)


def observed(name: SpanName) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def asynchronous(*args: P.args, **kwargs: P.kwargs) -> Any:
                if _backend is None:
                    return await function(*args, **kwargs)
                with span(name):
                    return await function(*args, **kwargs)
            return asynchronous  # type: ignore[return-value]

        @wraps(function)
        def synchronous(*args: P.args, **kwargs: P.kwargs) -> R:
            if _backend is None:
                return function(*args, **kwargs)
            with span(name):
                return function(*args, **kwargs)
        return synchronous
    return decorate


def claim(*, run_id: UUID, job_id: UUID, attempt: int, generation: int) -> None:
    """Link the current job span to the last observed attempt, bounded to 256 jobs per process."""
    backend, frame = _backend, _frame.get()
    if backend is None or frame is None:
        return
    annotate(run_id=run_id, job_id=job_id, attempt=attempt, generation=generation)
    with backend.claim_lock:
        previous = backend.claims.get(job_id)
        if previous is not None:
            if previous[0] >= attempt:
                return  # a delayed old worker cannot replace a newer attempt's context
            if previous[0] == attempt - 1:
                frame.span.add_link(previous[1])
        backend.claims[job_id] = (attempt, frame.span.get_span_context())
        backend.claims.move_to_end(job_id)
        while len(backend.claims) > 256:
            backend.claims.popitem(last=False)


def provider_usage(*, provider: str, model: str, outcome: str, input_tokens: int | None = None,
                   output_tokens: int | None = None, usd: Decimal | None = None) -> None:
    if _backend is None:
        return
    annotate(provider=provider, model=model, outcome=outcome,
             cost_class="known" if usd is not None else "unconfirmed")
    count("provider.calls", provider=provider, model=model, outcome=outcome)
    if input_tokens is not None:
        annotate(input_tokens=input_tokens)
        count("provider.input_tokens", input_tokens, provider=provider, model=model, outcome=outcome)
    if output_tokens is not None:
        annotate(output_tokens=output_tokens)
        count("provider.output_tokens", output_tokens, provider=provider, model=model, outcome=outcome)
    if usd is not None and usd.is_finite() and 0 <= usd <= Decimal("1000000"):
        count("provider.cost_usd", float(usd), provider=provider, model=model, outcome=outcome)
