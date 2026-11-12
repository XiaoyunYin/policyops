"""Synthetic authenticated, claimed runs for the T21 persistence contract tests."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from langgraph.checkpoint.base import Checkpoint, CheckpointMetadata

from policyops.domain.examples import World
from policyops.gateway.ports import GatewayScope
from policyops.orchestration.state import InvestigationState
from policyops.persistence import customer_authentications, repositories, runs
from policyops.persistence.checkpoints import InvestigationSaver
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import NewCase, NewRun, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.runtime.clock import FixedLeaseClock
from policyops_contracts.clock import FixedClock
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication
from policyops_testing.app_database import AppDatabase


NOW = datetime(2026, 11, 11, tzinfo=UTC)
DIGESTS = ("1" * 64, "2" * 64, "3" * 64)
META: CheckpointMetadata = {"source": "loop", "step": 0, "parents": {}}


@dataclass
class Claimed:
    db: AppDatabase
    scope: GatewayScope
    token: runs.ClaimToken
    clock: FixedClock

    def saver(self) -> InvestigationSaver:
        return InvestigationSaver(engine=self.db.engine(APP_RUNTIME), scope=self.scope.run, token=self.token,
                                  graph_sha256=DIGESTS[0], prompt_sha256=DIGESTS[1], config_sha256=DIGESTS[2],
                                  clock=FixedLeaseClock(self.clock))

    def state(self) -> dict[str, Any]:
        scope = self.scope.run
        return InvestigationState(state_version=2, workspace_id=scope.workspace_id, case_id=scope.case_id,
                                  run_id=scope.run_id, graph_sha256=DIGESTS[0], prompt_sha256=DIGESTS[1],
                                  config_sha256=DIGESTS[2]).model_dump(mode="json")

    def reclaim(self) -> runs.ClaimToken:
        self.clock.advance(timedelta(minutes=2))
        with workspace_transaction(self.db.engine(APP_RUNTIME), self.scope.run.workspace_id) as conn:
            run = runs.get_run(conn, self.token.run_id, lock=True)
            job = runs.get_job(conn, self.token.job_id, lock=True)
            assert run is not None and job is not None and runs.claimable(job, self.clock.now())
            self.token = runs.claim(conn, run, job, owner=uuid4(), lease=timedelta(minutes=1), now=self.clock.now())
        return self.token


def claimed(db: AppDatabase) -> Claimed:
    workspace, case, run_id = uuid4(), uuid4(), uuid4()
    scope = RunScope(workspace_id=workspace, case_id=case, run_id=run_id)
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repositories.create_workspace(conn, Workspace(id=workspace, slug=f"t21-{workspace.hex[:12]}", name="T21",
                                                      created_at=NOW))
    with workspace_transaction(db.engine(APP_RUNTIME), workspace) as conn:
        record = repositories.create_case(conn, NewCase(id=case, workspace_id=workspace, scenario="retail",
                                                        customer_user_id=World().user_id, created_by=None,
                                                        created_at=NOW))
        repositories.create_run(conn, NewRun(id=run_id, workspace_id=workspace, case_id=case,
                                             case_version=record.version, mode="workbench", graph_sha256=DIGESTS[0],
                                             prompt_sha256=DIGESTS[1], config_sha256=DIGESTS[2],
                                             deadline_at=NOW + timedelta(hours=2), created_at=NOW))
        run = runs.get_run(conn, run_id, lock=True)
        assert run is not None
        job_id = runs.create_execute_job(conn, run, max_attempts=3, now=NOW)
        job = runs.get_job(conn, job_id, lock=True)
        assert job is not None
        token = runs.claim(conn, run, job, owner=uuid4(), lease=timedelta(minutes=1), now=NOW)
        customer_authentications.record(conn, CustomerAuthentication(
            scope=scope, user_id=World().user_id, lookup_tool="find_user_id_by_email", lookup_call_sha256="0" * 64,
            step_sequence=1, authenticated_at=NOW))
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=workspace, case_id=case), seed_id="retail-demo-9999",
                                  user_id=World().user_id, bound_at=NOW)
    return Claimed(db, GatewayScope(run=scope, binding=binding, fixture_sha256=FIXTURE_SHA256), token, FixedClock(NOW))


def checkpoint(value: dict[str, Any], checkpoint_id: str = "0001") -> Checkpoint:
    return {"v": 4, "id": checkpoint_id, "ts": NOW.isoformat(), "channel_values": {"state": value},
            "channel_versions": {"state": 1}, "versions_seen": {}, "updated_channels": ["state"]}
