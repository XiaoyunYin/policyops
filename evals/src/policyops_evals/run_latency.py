"""Report machine latency alongside scenario results without changing their locked summaries."""

from dataclasses import dataclass, replace
from math import ceil
from typing import TypedDict

from policyops.orchestration.profile import InvestigationVersion
from policyops.persistence.database import workspace_transaction
from policyops.persistence.runs import get_run
from policyops.runtime.investigation import InvestigationExecutor
from policyops.runtime.live_agent import Timing, timing
from policyops.runtime.spec import RuntimeSpec
from policyops_evals.scenarios.cases import Scenario
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.runtime import Handler, Profile, Slot, Summary


class Sample(TypedDict):
    elapsed_ms: int | None
    failed: bool


class Distribution(TypedDict):
    observed: int
    samples: int
    failures: int
    p50_ms: int | None
    p95_ms: int | None


def distribution(samples: list[Sample]) -> Distribution:
    elapsed = sorted(sample["elapsed_ms"] for sample in samples if sample["elapsed_ms"] is not None)
    return Distribution(observed=len(samples), samples=len(elapsed), failures=sum(s["failed"] for s in samples),
                        p50_ms=elapsed[ceil(0.50 * len(elapsed)) - 1] if elapsed else None,
                        p95_ms=elapsed[ceil(0.95 * len(elapsed)) - 1] if elapsed else None)


@dataclass(frozen=True)
class ScenarioLatency:
    timestamps: Timing
    count: Distribution
    inference: Distribution
    tools_ms: tuple[tuple[str, int], ...]


def scenario_latency(profile: Profile, slot: Slot, tape: Tape, tools: list[tuple[str, int]]) -> ScenarioLatency:
    with workspace_transaction(profile.app, slot.workspace) as connection:
        run = get_run(connection, slot.run)
        if run is None:
            raise ValueError("scenario run missing")
        timestamps = timing(connection, run)
    return ScenarioLatency(
        timestamps=timestamps,
        count=distribution([Sample(elapsed_ms=e.elapsed_ms, failed=not e.complete or e.status != 200)
                            for e in tape.records if e.phase == "count"]),
        inference=distribution([Sample(elapsed_ms=e.elapsed_ms, failed=not e.complete or e.status != 200)
                                for e in tape.records if e.phase == "create"]),
        tools_ms=tuple(tools),
    )


def run_scripted(profile: Profile, case: Scenario, slot: Slot, tape: Tape, handler: Handler, *,
                 selected: InvestigationVersion) -> tuple[Summary, ScenarioLatency]:
    """Run the existing scenario runner with an extra observer for graph tool elapsed time."""
    tools: list[tuple[str, int]] = []

    def observe(node: str, elapsed_ms: int) -> None:
        tools.append((node, elapsed_ms))

    def bind(spec: RuntimeSpec) -> RuntimeSpec:
        executor = spec.executor
        if not isinstance(executor, InvestigationExecutor):
            raise TypeError("scenario latency requires the investigation executor")
        return replace(spec, executor=replace(executor, record_run=lambda _: (executor.providers(), observe)))

    # The locked scenario runner forwards the profile to the app builder, which also accepts v2 at runtime.
    summary = profile.run_scripted(case, slot, tape, handler, profile=selected, bind_spec=bind)  # type: ignore[arg-type]
    return summary, scenario_latency(profile, slot, tape, tools)
