"""Real run.execute claims for component fixtures that do not compose the worker.

These fixtures lease through the same persistence operations as the worker. They never bypass ledger admission;
tests of missing/foreign/stale claims use build_app_ledger directly instead.
"""

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Engine, text

from policyops.budget.config import Configuration
from policyops.budget.ledger import (
    Binding,
    CountGranted,
    CountRefused,
    DispatchGranted,
    DispatchRefused,
    Ledger,
    Reserved,
    RunBinding,
)
from policyops.persistence import runs
from policyops.persistence.budget import AppLedgerStore, build_app_ledger
from policyops.persistence.database import workspace_transaction
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock


def claim_run(engine: Engine, workspace_id: UUID, run_id: UUID, *, clock: LeaseClock | None = None
              ) -> runs.ClaimToken:
    clock = clock or DatabaseLeaseClock()
    with workspace_transaction(engine, workspace_id) as connection:
        run = runs.get_run(connection, run_id, lock=True)
        if run is None:
            raise runs.Fenced("missing")
        job = runs.execute_job_of(connection, run.id, lock=True)
        if job is not None and job.state == "leased":
            assert job.claim_id is not None and job.lease_owner is not None
            return runs.ClaimToken(workspace_id, run.id, job.id, job.claim_id, job.lease_owner,
                                   run.generation, job.attempts)
        now = clock.now(connection)
        if job is None:
            identity = runs.create_execute_job(connection, run, max_attempts=10, now=now)
            job = runs.get_job(connection, identity, lock=True)
        assert job is not None
        token = runs.claim(connection, run, job, owner=uuid4(), lease=timedelta(hours=1), now=now)
        if run.state == "queued":
            runs.set_state(connection, run, "running", now)
        return token


def claimed_ledger(*, engine: Engine, workspace_id: UUID, run_id: UUID, configuration: Configuration,
                   clock: LeaseClock | None = None) -> Ledger:
    return build_app_ledger(env="test", engine=engine, workspace_id=workspace_id, configuration=configuration,
                            clock=clock, claim_token=claim_run(engine, workspace_id, run_id, clock=clock))


class ComponentLedger(Ledger):
    """Component tests explicitly obtain real claims rather than exercising worker composition.

    Current claim identities are reconstituted for component replays. This is test setup, not a production
    ownership policy; stale-owner/admission tests must use the unwrapped production factory.
    """

    def _claim(self, run_id: UUID | None) -> None:
        assert isinstance(self.store, AppLedgerStore)
        if run_id is not None:
            self.store.claim_token = claim_run(self.store.engine, self.store.workspace_id, run_id,
                                               clock=self.store.clock)

    def _attempt_claim(self, attempt_id: UUID) -> None:
        assert isinstance(self.store, AppLedgerStore)
        with workspace_transaction(self.store.engine, self.store.workspace_id) as connection:
            run_id = connection.execute(text("SELECT s.run_id FROM app.usage_attempts a JOIN app.budget_scopes s "
                "ON s.workspace_id = a.workspace_id AND s.id = a.scope_id WHERE a.id = :id"),
                {"id": attempt_id}).scalar_one_or_none()
        self._claim(run_id)

    def reserve(self, binding: Binding, attempt_id: UUID, actor: Any, operation_id: str,
                request_sha256: str) -> Reserved:
        if isinstance(binding, RunBinding):
            self._claim(binding.run_id)
        return super().reserve(binding, attempt_id, actor, operation_id, request_sha256)

    def claim_count(self, attempt_id: UUID, request_sha256: str) -> CountGranted | CountRefused:
        self._attempt_claim(attempt_id)
        return super().claim_count(attempt_id, request_sha256)

    def begin_dispatch(self, attempt_id: UUID, request_sha256: str) -> DispatchGranted | DispatchRefused:
        self._attempt_claim(attempt_id)
        return super().begin_dispatch(attempt_id, request_sha256)


def component_ledger(**kwargs: Any) -> Ledger:
    ledger = build_app_ledger(**kwargs)
    return ComponentLedger(ledger.store, ledger.configuration, tuple(ledger.snapshots.values()))
