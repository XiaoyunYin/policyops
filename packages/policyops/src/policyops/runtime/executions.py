"""The execution dispatcher (T19): the bounded consumer of the execution ledger.

Open executions (`pending`, `dispatched` with an expired lease, `unknown`) are the durable outbox of the retail
sink: `app.tool_executions` itself, with `next_attempt_at` as the schedule. `ExecutionDispatcher.dispatch_once()`
discovers up to `batch` due rows through `policyops_worker_discovery` (scheduling metadata only), then advances each
by one bounded step as the app runtime (`Executor.step`: claim, at most one lookup and one mutate or fence, record).
Backoff, the dispatch cap and the reconciliation cap are enforced per row; a row past the reconciliation cap stays
`unknown` and unscheduled (explicitly unresolved). No job kind is added (T22 composes the graph). Reconciliation
continues after the run is terminal; an old lease cannot resend without a current claim and authority.

Composition verifies both engines' actual roles and refuses a test clock or test hooks outside `env == "test"`.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine

from policyops.persistence import executions as ledger
from policyops.persistence.database import transaction, verify_runtime_role
from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, require_test_environment
from policyops.services.execution import (
    ExecutionHooks,
    ExecutionLimits,
    Executor,
    RetailFactory,
    ScopeResolver,
    Step,
)


def build_execution_dispatcher(*, env: str, app_engine: Engine, discovery_engine: Engine, scopes: ScopeResolver,
                               retail: RetailFactory, clock: LeaseClock | None = None,
                               hooks: ExecutionHooks | None = None, limits: ExecutionLimits | None = None,
                               batch: int = 10) -> ExecutionDispatcher:
    lease_clock = clock or DatabaseLeaseClock()
    require_test_environment(lease_clock, env)
    if hooks is not None:
        require_test_environment(hooks, env)
    if not 1 <= batch <= 100:
        raise ValueError("batch out of range")
    verify_runtime_role(app_engine, APP_RUNTIME)
    verify_runtime_role(discovery_engine, WORKER_DISCOVERY)
    executor = Executor(app_engine=app_engine, clock=lease_clock, scopes=scopes, retail=retail, limits=limits,
                        hooks=hooks)
    return ExecutionDispatcher(discovery_engine=discovery_engine, executor=executor, clock=lease_clock, batch=batch)


@dataclass
class ExecutionDispatcher:
    discovery_engine: Engine
    executor: Executor
    clock: LeaseClock
    batch: int = 10

    def dispatch_once(self) -> list[Step]:
        """One bounded pass: at most `batch` executions, each advanced by at most one step. The steps are returned,
        not retained: a long-running loop holds no history."""
        with transaction(self.discovery_engine) as connection:
            due = ledger.discover(connection, self.clock.now(connection), self.batch)
        steps = [self.executor.step(workspace_id, execution_id) for workspace_id, execution_id in due]
        return steps
