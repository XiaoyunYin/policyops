"""The leased worker loop (T09).

`Worker.run_once()` discovers candidate jobs through the narrow discovery role, then for each one:

1. **claim** (one short transaction as the app runtime in the job's workspace; run then job locked with SKIP
   LOCKED). Before any new work it re-checks, at the database's time:
   - the run is still runnable and the job claimable (due queued job, or an expired lease);
   - neither deadline has passed and attempts remain;
   - the run's spec is installed;
   - the run's initiator still holds START_RUN in the workspace (an ended browser session does not matter).

   Failures dead-letter the job and fail the run with a typed error event in that same transaction. Otherwise the
   job is leased with a new stable claim ID and run generation, and a queued run moves to `running` (with its
   event).
2. **execute** outside any transaction. The executor emits events and heartbeats through the fenced context.
3. **finish** (one short fenced transaction): success, a typed permanent failure, or a release with bounded
   backoff (dead letter once attempts are exhausted). A lost claim (`Fenced`) is abandoned without writing:
   whoever fenced it out owns the run now.

`run.review` routes to the deterministic review runtime's separate claim/finish path. A missing review composition
leaves its durable intent queued and excludes it from discovery. Discovery selects only composed kinds; directly
submitted unknown kinds are dead-lettered as `unsupported_job_kind` without touching their run. Deploy schema and
supporting workers before enabling new producers. Logs contain no exception text.

Events written by any step carry their outbox intent in the same transaction; `OutboxDispatcher` publishes them
independently of the claim, so a committed intent survives the end of the lease that produced it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import threading
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine

from policyops.domain.roles import Action, Role, is_allowed
from policyops.orchestration.stops import stop_text
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs
from policyops.persistence import runs as store
from policyops.persistence.database import (
    ImmutableRecord,
    SqlProfile,
    transaction,
    verify_runtime_role,
    workspace_transaction,
)
from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, UnsafeTestHook, require_test_environment
from policyops.runtime.review import ReviewRuntime
from policyops.runtime.spec import (
    UNCONFIGURED,
    AwaitingApproval,
    Failed,
    InvestigationCompleted,
    Outcome,
    Retry,
    RuntimeCatalog,
    RuntimeSpec,
    Stopped,
    Succeeded,
    UsageUnconfirmed,
    investigation_message_id,
    stop_message_id,
    unconfirmed_stop,
)
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import ErrorRaised, EventPayload, MessagePosted, RunStateChanged, RunStopped
from policyops_contracts.scalars import CaseScope
from policyops_contracts.stops import StopDetails, StopReason


log = logging.getLogger("policyops.worker")
BACKOFF_BASE = timedelta(seconds=2)
# Graph jobs execute only in these states; run.review owns the separate approval/reconciliation path.
EXECUTABLE_STATES = frozenset({"queued", "running"})
BACKOFF_CAP = timedelta(minutes=5)


def backoff(attempt: int) -> timedelta:
    return min(BACKOFF_CAP, BACKOFF_BASE * (1 << min(20, max(0, attempt - 1))))


@dataclass
class Context:
    """The executor's view of one claim; every write re-checks the fence in its own transaction."""

    worker: Worker
    token: store.ClaimToken
    case_id: UUID
    spec: RuntimeSpec

    @property
    def workspace_id(self) -> UUID:
        return self.token.workspace_id

    @property
    def run_id(self) -> UUID:
        return self.token.run_id

    @property
    def attempt(self) -> int:
        return self.token.attempt

    @property
    def claim_token(self) -> store.ClaimToken:
        return self.token

    def emit(self, payload: EventPayload) -> int:
        if isinstance(payload, RunStateChanged):
            raise ValueError("run state belongs to the worker, not the executor")
        with workspace_transaction(self.worker.app_engine, self.workspace_id) as connection:
            run, _job, now = store.check_fence(connection, self.token, self.worker.clock)
            return store.append_event(connection, run, payload, now).sequence

    def heartbeat(self) -> bool:
        with workspace_transaction(self.worker.app_engine, self.workspace_id, profile=SqlProfile.LEASE) as connection:
            return store.heartbeat(connection, self.token, lease=self.spec.lease, clock=self.worker.clock)


def build_worker(*, env: str, app_engine: Engine, discovery_engine: Engine, clock: LeaseClock | None = None,
                 catalog: RuntimeCatalog | None = None, review: ReviewRuntime | None = None,
                 **options: Any) -> Worker:
    """The supported way to compose a worker. Test-only parts (the fixed lease clock, scripted runtime specs) are
    refused unless `env == "test"`; this check needs no database and comes first. Both engines must then
    authenticate as their restricted roles (the app runtime and the worker discovery role). `Worker` itself is an
    internal component that assumes this validation was done."""
    lease_clock, installed = checked_parts(
        env, clock or (review.executor.clock if review is not None else None), catalog)
    if review is not None:
        require_test_environment(review, env)
        if review.executor.engine is not app_engine or review.executor.clock is not lease_clock:
            raise ValueError("review runtime must share the worker engine and lease clock")
    verify_runtime_role(app_engine, APP_RUNTIME)
    verify_runtime_role(discovery_engine, WORKER_DISCOVERY)
    return Worker(app_engine=app_engine, discovery_engine=discovery_engine, clock=lease_clock, catalog=installed,
                  review=review, **options)


def checked_parts(env: str, clock: LeaseClock | None, catalog: RuntimeCatalog | None
                  ) -> tuple[LeaseClock, RuntimeCatalog]:
    lease_clock = clock or DatabaseLeaseClock()
    installed = catalog or UNCONFIGURED
    require_test_environment(lease_clock, env)
    if installed.test_only and env != "test":
        raise UnsafeTestHook("a test-only runtime catalog is only allowed when POLICYOPS_ENV=test")
    return lease_clock, installed


@dataclass
class Worker:
    app_engine: Engine
    discovery_engine: Engine
    clock: LeaseClock
    catalog: RuntimeCatalog
    owner: UUID = field(default_factory=uuid4)
    batch: int = 10
    on_claimed: Callable[[store.ClaimToken], None] | None = None  # test observation hook (no behavior change)
    review: ReviewRuntime | None = None

    def discover(self) -> list[tuple[UUID, UUID]]:
        kinds = (store.EXECUTE_KIND,) if self.review is None else (store.EXECUTE_KIND, review_jobs.REVIEW_KIND)
        with transaction(self.discovery_engine, profile=SqlProfile.LEASE) as connection:
            return store.discover_jobs(connection, self.clock.now(connection), self.batch, kinds=kinds)

    def run_once(self) -> int:
        """Process the currently due jobs once; returns how many this worker claimed. A failure while handling
        one job is logged as a code with safe IDs (never exception text) and does not stop the others."""
        claimed = 0
        for job_id, workspace_id in self.discover():
            try:
                if self.process(job_id, workspace_id):
                    claimed += 1
            except Exception as exc:  # contained per job; only the type name is logged
                log.warning("worker_job_error job=%s workspace=%s type=%s", job_id, workspace_id,
                            type(exc).__name__)
        return claimed

    def serve(self, stop: threading.Event, *, idle: float = 1.0) -> None:
        while not stop.is_set():
            if self.run_once() == 0:
                stop.wait(idle)

    def process(self, job_id: UUID, workspace_id: UUID) -> bool:
        with workspace_transaction(self.app_engine, workspace_id) as connection:
            observed = store.get_job(connection, job_id)
        if observed is not None and observed.kind == review_jobs.REVIEW_KIND:
            # Missing composition leaves durable intent queued; it cannot consume it as a graph execution.
            return False if self.review is None else self.review.process(job_id, workspace_id, self.owner)
        claimed = self.claim(job_id, workspace_id)
        if claimed is None:
            return False
        token, case_id, spec = claimed
        if self.on_claimed is not None:
            self.on_claimed(token)
        context = Context(self, token, case_id, spec)
        try:
            outcome: Outcome = spec.executor.execute(context)
        except store.Fenced as fenced:
            log.info("claim_lost claim=%s reason=%s", token.claim_id, fenced.reason)
            return True
        except Exception as exc:  # an executor bug is a transient failure
            # Only a fixed code, safe IDs and the exception type: never its message or traceback, which may carry
            # upstream secrets or customer text.
            log.warning("executor_error run=%s claim=%s type=%s", token.run_id, token.claim_id, type(exc).__name__)
            outcome = Retry("executor_error")
        self.finish(token, outcome)
        return True

    # -- claim ----------------------------------------------------------------------------------------------------

    def claim(self, job_id: UUID, workspace_id: UUID) -> tuple[store.ClaimToken, UUID, RuntimeSpec] | None:
        with workspace_transaction(self.app_engine, workspace_id, profile=SqlProfile.LEASE) as connection:
            job_row = store.get_job(connection, job_id)
            if job_row is None:
                return None
            observed = store.get_run(connection, job_row.run_id)
            if observed is None or repo.lock_case(connection, observed.case_id) is None:
                return None
            run = store.get_run(connection, job_row.run_id, skip_locked=True)  # run first, then job
            job = store.get_job(connection, job_id, skip_locked=True) if run is not None else None
            if run is None or job is None:
                return None
            now = self.clock.now(connection)  # after the locks
            if not store.claimable(job, now):
                return None
            if job.kind == review_jobs.REVIEW_KIND:
                return None  # ReviewRuntime owns its distinct claim/finish path.
            if job.kind != store.EXECUTE_KIND:  # the only kind this worker handles; never run another as execution
                store.end_job(connection, job, state="dead", now=now, error_code="unsupported_job_kind")
                return None
            if run.terminal or run.state not in EXECUTABLE_STATES:
                store.end_job(connection, job, state="done" if run.terminal else "dead", now=now,
                              error_code="run_not_runnable")
                return None
            spec = self.catalog.for_run(run.graph_sha256, run.prompt_sha256, run.config_sha256)
            refusal = self._refusal(connection, run, job, spec, now)
            if refusal is not None:
                reason, code, rule_id = refusal
                if reason == "deadline_exceeded":
                    self._stop_run(connection, run, job, now, StopDetails(reason=StopReason.ACTIVE_TIME))
                else:
                    self._fail_run(connection, run, now, code=code, rule_id=rule_id)
                    store.end_job(connection, job, state="dead", now=now, error_code=reason)
                return None
            if spec is None:  # unreachable: `_refusal` dead-letters a missing spec
                return None
            token = store.claim(connection, run, job, owner=self.owner, lease=spec.lease, now=now)
            if run.state == "queued":
                run = store.get_run(connection, run.id, lock=True) or run
                running = store.set_state(connection, run, "running", now)
                store.append_event(connection, running, RunStateChanged(previous="queued", current="running"), now)
            return token, run.case_id, spec

    def _refusal(self, connection: Connection, run: store.Run, job: store.Job, spec: RuntimeSpec | None,
                 now: datetime) -> tuple[str, ErrorCode, str] | None:
        if job.deadline_at <= now or store.remaining_us(run, now) == 0:
            return "deadline_exceeded", ErrorCode.UNAVAILABLE, "runtime.deadline_exceeded"
        if job.attempts >= job.max_attempts:
            return "max_attempts", ErrorCode.UNAVAILABLE, "runtime.max_attempts"
        if spec is None:
            return "executor_unavailable", ErrorCode.UNAVAILABLE, "runtime.executor_unavailable"
        if run.initiated_by is None or not self._may_start(connection, run.initiated_by):
            return "initiator_not_authorized", ErrorCode.FORBIDDEN, "runtime.initiator_not_authorized"
        return None

    @staticmethod
    def _may_start(connection: Connection, principal: UUID) -> bool:
        roles = frozenset(Role(name) for name in repo.scoped_roles(connection, principal))
        return is_allowed(roles, Action.START_RUN)

    @staticmethod
    def _fail_run(connection: Connection, run: store.Run, now: datetime, *, code: ErrorCode, rule_id: str,
                  retryable: bool = False) -> None:
        locked = store.get_run(connection, run.id, lock=True)
        if locked is None or locked.terminal:
            return
        store.append_event(connection, locked, ErrorRaised(code=code, rule_id=rule_id, correlation_id=uuid4(),
                                                           retryable=retryable), now)
        failed = store.set_state(connection, locked, "failed", now, bump_generation=True)
        store.append_event(connection, failed, RunStateChanged(previous=locked.state, current="failed"), now)

    # -- finish ---------------------------------------------------------------------------------------------------

    @staticmethod
    def _stop_run(connection: Connection, run: store.Run, job: store.Job, now: datetime,
                  details: StopDetails) -> None:
        message = repo.append_message(connection, message_id=stop_message_id(run.workspace_id, run.id),
            scope=CaseScope(workspace_id=run.workspace_id, case_id=run.case_id), source="agent", entered_by=None,
            text_value=stop_text(details), created_at=now)
        repo.bump_case_version(connection, run.case_id, now)
        store.append_event(connection, run, MessagePosted(message_id=message.message_id,
            message_sequence=message.sequence, source="agent"), now)
        store.append_event(connection, run, RunStopped(message_id=message.message_id, details=details), now)
        target: store.RunState = "failed" if details.failed else "budget_exceeded"
        done = store.set_state(connection, run, target, now, bump_generation=True)
        store.append_event(connection, done, RunStateChanged(previous=run.state, current=target), now)
        store.end_job(connection, job, state="done", now=now, error_code=details.reason.value)

    def finish(self, token: store.ClaimToken, outcome: Outcome) -> None:
        if isinstance(outcome, UsageUnconfirmed):
            outcome = unconfirmed_stop(outcome.report)
        try:
            with workspace_transaction(self.app_engine, token.workspace_id) as connection:
                # Message/proposal finalization shares the case -> run -> job lock order.
                if isinstance(outcome, InvestigationCompleted | AwaitingApproval | Stopped | Retry):
                    observed = store.get_run(connection, token.run_id)
                    if observed is None or repo.lock_case(connection, observed.case_id) is None:
                        raise store.Fenced("run_missing")
                run, job, now = store.check_fence(connection, token, self.clock)
                if isinstance(outcome, Stopped):
                    self._stop_run(connection, run, job, now, outcome.details)
                    return
                if isinstance(outcome, Succeeded | InvestigationCompleted | AwaitingApproval):
                    target: store.RunState = "succeeded"
                    if isinstance(outcome, InvestigationCompleted):
                        expected = investigation_message_id(run.workspace_id, run.id)
                        if outcome.message_id != expected:
                            raise ImmutableRecord("final message identity changed")
                        message = repo.append_message(connection, message_id=outcome.message_id,
                                                      scope=CaseScope(workspace_id=run.workspace_id,
                                                                      case_id=run.case_id),
                                                      source="agent", entered_by=None, text_value=outcome.text,
                                                      created_at=now)
                        repo.bump_case_version(connection, run.case_id, now)
                        store.append_event(connection, run, MessagePosted(message_id=message.message_id,
                                                                         message_sequence=message.sequence,
                                                                         source="agent"), now)
                    elif isinstance(outcome, AwaitingApproval):
                        proposal = repo.get_proposal(connection, outcome.proposal_id, outcome.proposal_version)
                        row = repo.proposal_row(connection, outcome.proposal_id, outcome.proposal_version)
                        presentation = repo.get_presentation(connection, outcome.proposal_id, outcome.proposal_version)
                        if (proposal is None or row is None or row.status != "presented"
                                or row.creation_step is None or proposal.scope != run.scope or presentation is None):
                            raise ImmutableRecord("prepared proposal binding changed")
                        presented_message = repo.message_by_id(connection, CaseScope(workspace_id=run.workspace_id,
                                                                          case_id=run.case_id), presentation.message_id)
                        if presented_message is None or presented_message.text != proposal.presentation.text:
                            raise ImmutableRecord("prepared presentation changed")
                        target = "waiting_approval"
                    done = store.set_state(connection, run, target, now, bump_generation=True)
                    store.append_event(connection, done, RunStateChanged(previous=run.state, current=target),
                                       now)
                    store.end_job(connection, job, state="done", now=now)
                elif isinstance(outcome, Failed):
                    self._fail_run(connection, run, now, code=outcome.code, rule_id=outcome.rule_id)
                    store.end_job(connection, job, state="done", now=now, error_code="run_failed")
                elif job.attempts >= job.max_attempts:
                    self._fail_run(connection, run, now, code=ErrorCode.UNAVAILABLE, rule_id="runtime.max_attempts")
                    store.end_job(connection, job, state="dead", now=now, error_code="max_attempts")
                elif (now + backoff(job.attempts) >= job.deadline_at
                      or store.remaining_us(run, now) <= int(backoff(job.attempts).total_seconds() * 1_000_000)):
                    self._stop_run(connection, run, job, now, StopDetails(reason=StopReason.ACTIVE_TIME))
                else:
                    store.end_job(connection, job, state="queued", now=now, error_code=outcome.reason,
                                  available_at=now + backoff(job.attempts))
        except store.Fenced as fenced:
            log.info("claim_lost claim=%s reason=%s", token.claim_id, fenced.reason)
