"""Server-owned runtime specifications and the executor port (T09).

A run is started against a frozen `RuntimeSpec`: its graph/prompt/config digests are recorded on the run, and
the worker later finds the executor again by all three persisted digests. The digests must describe real,
installed content: nothing here invents them. Until T21 installs an investigation runtime, the production catalog
is empty, so starting a run is refused (503) before anything is written, and an already queued job whose spec is
unknown fails visibly as unavailable instead of succeeding or retrying forever. Deterministic scripted
executors exist only in the test support package and are marked `test_only`, which runtime wiring refuses outside
the test environment.

Executors run outside any database transaction. They report progress through `StepContext.emit` (each call is
its own fenced transaction) and keep their lease with `StepContext.heartbeat`; they never change the run's state,
which belongs to the worker.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
import re
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid5

from policyops.persistence.runs import ClaimToken
from policyops_contracts.conversation import AgentMessage
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import EventPayload


SHA256 = re.compile(r"[0-9a-f]{64}")
SLUG = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
MESSAGE_NAMESPACE = UUID("f0391011-238c-5143-b655-a6d2fbb6f7e2")


def investigation_message_id(workspace_id: UUID, run_id: UUID) -> UUID:
    return uuid5(MESSAGE_NAMESPACE, f"{workspace_id}:{run_id}:final")


@dataclass(frozen=True)
class Succeeded:
    pass


@dataclass(frozen=True)
class Failed:
    """A permanent, typed failure of the run (no free text)."""

    code: ErrorCode
    rule_id: str


@dataclass(frozen=True)
class Retry:
    """A transient failure: the job is released with backoff until its attempts or deadline run out. `reason` is a
    typed slug (it is stored as the job's last error code), never exception or prompt text."""

    reason: str

    def __post_init__(self) -> None:
        if not SLUG.fullmatch(self.reason):
            raise ValueError("a retry reason must be a slug")


@dataclass(frozen=True)
class AwaitingApproval:
    proposal_id: UUID
    proposal_version: int


@dataclass(frozen=True)
class InvestigationCompleted:
    message_id: UUID
    text: str

    def __post_init__(self) -> None:
        AgentMessage(text=self.text)


@dataclass(frozen=True)
class BudgetExceeded:
    pass


Outcome = Succeeded | Failed | Retry | AwaitingApproval | InvestigationCompleted | BudgetExceeded


class StepContext(Protocol):
    @property
    def workspace_id(self) -> UUID: ...
    @property
    def case_id(self) -> UUID: ...
    @property
    def run_id(self) -> UUID: ...
    @property
    def attempt(self) -> int: ...
    @property
    def claim_token(self) -> ClaimToken: ...

    def emit(self, payload: EventPayload) -> int:
        """Append one event under the claim's fence; returns its sequence (raises `Fenced` when the claim is lost)."""
        ...

    def heartbeat(self) -> bool:
        """Extend the lease; False when the claim is no longer current (stop working)."""
        ...


class Executor(Protocol):
    def execute(self, context: StepContext) -> Outcome: ...


@dataclass(frozen=True)
class RuntimeSpec:
    spec_id: str
    graph_sha256: str
    prompt_sha256: str
    config_sha256: str
    executor: Executor = field(compare=False)
    max_attempts: int = 3
    lease: timedelta = timedelta(seconds=30)
    run_timeout: timedelta = timedelta(minutes=15)
    test_only: bool = False

    def __post_init__(self) -> None:
        if not SLUG.fullmatch(self.spec_id):
            raise ValueError("spec_id must be a slug")
        for digest in (self.graph_sha256, self.prompt_sha256, self.config_sha256):
            if not SHA256.fullmatch(digest):
                raise ValueError("runtime digests must be lowercase SHA-256 hex")
        if not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts must be 1..100")
        if not timedelta(seconds=1) <= self.lease <= timedelta(minutes=10):
            raise ValueError("the lease must be between 1 second and 10 minutes")
        if not self.lease < self.run_timeout <= timedelta(hours=24):
            raise ValueError("the run timeout must exceed the lease and be at most 24 hours")


Binding = tuple[str, str, str]  # (graph_sha256, prompt_sha256, config_sha256)


def binding(spec: RuntimeSpec) -> Binding:
    return spec.graph_sha256, spec.prompt_sha256, spec.config_sha256


@dataclass(frozen=True)
class RuntimeCatalog:
    """Installed specs, each bound to the full (graph, prompt, config) digest triple a run records, and the spec
    new workbench runs start with (None: not configured). A run only ever runs on the spec matching all three of
    its persisted digests. The mapping is read-only, and duplicate spec IDs or bindings are refused."""

    specs: Mapping[Binding, RuntimeSpec] = field(default_factory=dict)
    default: str | None = None

    def __post_init__(self) -> None:
        # Every construction path, the raw constructor included: take a private snapshot (later changes to the
        # caller's mapping cannot reach the catalog), check that each spec is keyed by its own digest binding,
        # that spec IDs are distinct and that the default is present, then freeze the snapshot read-only.
        snapshot = dict(self.specs)
        for key, spec in snapshot.items():
            if not isinstance(spec, RuntimeSpec) or key != binding(spec):
                raise ValueError("each runtime spec must be keyed by its own (graph, prompt, config) digests")
        ids = [spec.spec_id for spec in snapshot.values()]
        if len(set(ids)) != len(ids):
            raise ValueError("runtime specs must have distinct IDs and distinct digest bindings")
        if self.default is not None and self.default not in ids:
            raise ValueError("the default spec is not in the catalog")
        object.__setattr__(self, "specs", MappingProxyType(snapshot))

    @classmethod
    def of(cls, specs: Iterable[RuntimeSpec], *, default: str | None = None) -> RuntimeCatalog:
        listed = list(specs)
        by_binding = {binding(spec): spec for spec in listed}
        if len(by_binding) != len(listed):  # two specs with one binding would collapse in a mapping
            raise ValueError("runtime specs must have distinct IDs and distinct digest bindings")
        return cls(by_binding, default)

    @property
    def start_spec(self) -> RuntimeSpec | None:
        return next((s for s in self.specs.values() if s.spec_id == self.default), None)

    def for_run(self, graph_sha256: str, prompt_sha256: str, config_sha256: str) -> RuntimeSpec | None:
        return self.specs.get((graph_sha256, prompt_sha256, config_sha256))

    @property
    def test_only(self) -> bool:
        return any(spec.test_only for spec in self.specs.values())


UNCONFIGURED = RuntimeCatalog()
