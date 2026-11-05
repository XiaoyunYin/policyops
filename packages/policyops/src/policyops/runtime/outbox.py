"""Outbox publication (T09): the consumer side of the run-event publication intents.

Design (recorded before building, corrected in review):
- Every committed run event has an outbox row (topic `run.event`, dedupe key `run-event:{event_id}`), written in
  the same transaction.
- `OutboxDispatcher.dispatch_once()` finds workspaces with undelivered rows through the narrow discovery role.
  Then, per workspace and as the app runtime, it locks a batch with SKIP LOCKED, and in one transaction issues one
  generic `pg_notify('policyops_run_events', '')` and sets `delivered_at` on those rows.
- PostgreSQL sends notifications only if that transaction commits. `delivered_at` therefore means "publication
  committed", not "a client received it": a session that is not listening misses the wake-up, and identical
  notifications in one transaction coalesce into one.
- The payload is empty on purpose. Every session of the same database may LISTEN, so the wake-up carries no run,
  tenant or sequence identifier. A woken consumer re-reads only the rows its own authorization and RLS allow, and
  polling durable events remains the correctness path.
- A failed pass leaves the rows for the next pass. Rows do not depend on the producer's job lease, so they stay
  publishable after that lease ends.
- A non-transactional sink (T19's simulator dispatcher) needs a claimed, at-least-once variant; that is not built
  here.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine

from policyops.persistence import runs as store
from policyops.persistence.database import transaction, verify_runtime_role, workspace_transaction
from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, require_test_environment


def build_dispatcher(*, env: str, app_engine: Engine, discovery_engine: Engine,
                     clock: LeaseClock | None = None) -> OutboxDispatcher:
    """The supported way to compose a dispatcher: a test-only clock is refused unless `env == "test"` (checked
    first, without the database), then both engines must authenticate as their restricted roles."""
    lease_clock = clock or DatabaseLeaseClock()
    require_test_environment(lease_clock, env)
    verify_runtime_role(app_engine, APP_RUNTIME)
    verify_runtime_role(discovery_engine, WORKER_DISCOVERY)
    return OutboxDispatcher(app_engine=app_engine, discovery_engine=discovery_engine, clock=lease_clock)


@dataclass
class OutboxDispatcher:
    app_engine: Engine
    discovery_engine: Engine
    clock: LeaseClock
    workspaces: int = 20
    batch: int = 100

    def dispatch_once(self) -> int:
        with transaction(self.discovery_engine) as connection:
            pending = store.discover_outbox(connection, self.workspaces)
        published = 0
        for workspace_id in pending:
            with workspace_transaction(self.app_engine, workspace_id) as connection:
                published += store.publish_outbox(connection, limit=self.batch, clock=self.clock)
        return published
