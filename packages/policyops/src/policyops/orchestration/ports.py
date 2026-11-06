"""The minimal agent's injected ports (T20), and its one explicit production model adapter.

- `ModelPort`: one bounded model call. In production only `agent_model_port`, the existing T11 `call` with the fixed
  `agent` actor, zero retries and zero repairs, the caller's explicit ledger, binding and providers factory. There is
  no default and nothing is constructed implicitly: no client, key, count or provider request exists until a turn
  calls it.
- `ToolPort`: executes one accepted tool call and returns a `ToolResult` for exactly that call ID. Validation of a
  call is not authorization: retail writes stay behind the deterministic gateway and approval path, and fake tools
  are test fixtures.
- `KnowledgePort`: read-only and content-only; the runtime binds its result to the pending call. The
  Retriever-backed adapter and its step allocation are T15b.

A test port declares `test_only` and is refused outside the test environment.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from policyops.budget.ledger import (
    Binding,
    EvalBinding,
    Ledger,
    LedgerConflict,
    OperationBinding,
    RunBinding,
    ScopeInactive,
)
from policyops.providers.calls import CallLimits, CallReport, Providers, call
from policyops_contracts.conversation import AgentToolCall, KnowledgeResult, ToolResult
from policyops_contracts.model import ModelRequest


AGENT_LIMITS = CallLimits(retries_per_request=0, repairs=0, backoff_seconds=0.0)


class ModelPort(Protocol):
    async def complete(self, request: ModelRequest, *, key: UUID, operation: str, deadline: float) -> CallReport: ...


class ToolPort(Protocol):
    async def execute(self, call: AgentToolCall, *, deadline: float) -> ToolResult: ...


class KnowledgePort(Protocol):
    async def search(self, query: str, *, conversation_id: UUID, index: int, deadline: float) -> KnowledgeResult: ...


def _actor_sha256(ledger: Ledger) -> str:
    return ledger.configuration.reservation("agent").config_sha256


@dataclass(frozen=True)
class _AgentModelPort:
    """T11 `call` for the `agent` actor only, on the caller's explicit ledger and binding. T11 prepares and bills
    from `ledger.configuration`, so the agent actor's configuration digest is bound here at construction (the agent
    checks it against its `AgentConfig`) and rechecked before every call: a changed ledger configuration sends,
    reserves and constructs nothing."""

    ledger: Ledger
    binding: Binding
    providers: Callable[[], Providers]
    actor_config_sha256: str
    test_only: bool = field(default=False, init=False)

    async def complete(self, request: ModelRequest, *, key: UUID, operation: str, deadline: float) -> CallReport:
        if _actor_sha256(self.ledger) != self.actor_config_sha256:
            return CallReport(None, "contract_gap", "actor_configuration_changed")
        try:
            return await call(self.ledger, self.providers(), self.binding, key, operation, request, "agent",
                              deadline=deadline, limits=AGENT_LIMITS)
        except LedgerConflict:  # this key's attempt exists with another intent: no new key, no new attempt
            return CallReport(None, "failed", "ledger_conflict")
        except ScopeInactive:
            return CallReport(None, "failed", "scope_inactive")


def agent_model_port(ledger: Ledger, binding: Binding, providers: Callable[[], Providers]) -> ModelPort:
    if not isinstance(ledger, Ledger):
        raise TypeError("ledger must be a Ledger")
    if not isinstance(binding, RunBinding | OperationBinding | EvalBinding):
        raise TypeError("binding must be an explicit ledger binding")
    if not callable(providers):
        raise TypeError("providers must be a factory")
    return _AgentModelPort(ledger, binding, providers, _actor_sha256(ledger))  # no provider factory call


def is_agent_model_port(port: object) -> bool:
    return isinstance(port, _AgentModelPort)


def bound_actor_sha256(port: object) -> str | None:
    """The agent actor configuration digest the production adapter's ledger was bound to (None for other ports)."""
    return port.actor_config_sha256 if isinstance(port, _AgentModelPort) else None
