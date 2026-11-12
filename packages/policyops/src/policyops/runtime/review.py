"""Deterministic decision/expiry continuation. No model or graph is invoked here.

Claims and completion use short case -> run -> job transactions. Retail reads for
T19 reservation occur outside them. The execution ledger alone owns dispatch.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import timedelta
import logging
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import Connection, Engine

from policyops.adapters.retail_client import RetailClient
from policyops.domain.roles import Action, Role, is_allowed
from policyops.gateway.ports import GatewayScope, load_scope
from policyops.gateway.precheck import AuthorityRefs, PrecheckRefused
from policyops.persistence import executions as ledger
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs as jobs
from policyops.persistence import runs as store
from policyops.persistence.database import ImmutableRecord, verify_runtime_role, workspace_transaction
from policyops.persistence.roles import APP_RUNTIME
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, UnsafeTestHook, require_test_environment
from policyops.services.execution import Executor, Reserved, RetailFactory, RetailOperations, ScopeResolver
from policyops.services.review_outcomes import RefusalReason, finish_refusal
from policyops_contracts.events import RunStateChanged
from policyops_contracts.scalars import RunScope
from policyops_contracts.seeds import CaseCustomerBinding


log = logging.getLogger("policyops.review")
DEFER = timedelta(seconds=2)


@dataclass(frozen=True)
class ReviewRefusal:
    reason: RefusalReason


@dataclass(frozen=True)
class ReviewRetry:
    pass


@dataclass(frozen=True)
class Superseded:
    pass


Result = Reserved | ReviewRefusal | ReviewRetry | Superseded


@dataclass(frozen=True)
class BoundScopes:
    engine: Engine
    bindings: tuple[CaseCustomerBinding, ...]
    fixture_sha256: str

    def scope(self, run: RunScope) -> GatewayScope:
        matches = [binding for binding in self.bindings if (binding.scope.workspace_id, binding.scope.case_id)
                   == (run.workspace_id, run.case_id)]
        if len(matches) != 1:
            raise ImmutableRecord("review requires one server-owned case binding")
        return load_scope(self.engine, workspace_id=run.workspace_id, run_id=run.run_id,
                          binding=matches[0], fixture_sha256=self.fixture_sha256)


def build_review_runtime(*, env: str, app_engine: Engine, bindings: tuple[CaseCustomerBinding, ...],
                         fixture_sha256: str, retail_origin: str, retail_key: bytes,
                         clock: LeaseClock | None = None, scopes: ScopeResolver | None = None,
                         retail: RetailFactory | None = None) -> ReviewRuntime:
    """Production constructs its own scope resolver/client. Injected ports require explicit env=test."""
    lease_clock = clock or DatabaseLeaseClock()
    require_test_environment(lease_clock, env)
    if (scopes is not None or retail is not None) and env != "test":
        raise UnsafeTestHook("custom review ports require env=test")
    verify_runtime_role(app_engine, APP_RUNTIME)

    @contextmanager
    def clients(scope: GatewayScope) -> Iterator[RetailOperations]:
        with closing(RetailClient(retail_origin, retail_key, tenant_id=scope.run.workspace_id,
                                  case_id=scope.run.case_id, customer_id=scope.customer_user_id,
                                  fixture_sha256=scope.fixture_sha256)) as client:
            yield client

    executor = Executor(app_engine=app_engine, clock=lease_clock,
                        scopes=scopes or BoundScopes(app_engine, bindings, fixture_sha256), retail=retail or clients)
    return ReviewRuntime(executor, test_only=env == "test")


@dataclass
class ReviewRuntime:
    executor: Executor
    test_only: bool = False

    def process(self, job_id: UUID, workspace_id: UUID, owner: UUID) -> bool:
        token = self.claim(job_id, workspace_id, owner)
        if token is None:
            return False
        try:
            result = self.execute(token)
        except store.Fenced:
            return True
        except (ImmutableRecord, ValidationError):
            result = ReviewRefusal(RefusalReason.RECORD_INVALID)
        except Exception as exc:
            log.warning("review_error job=%s type=%s", token.job_id, type(exc).__name__)
            result = ReviewRetry()
        with suppress(store.Fenced):
            self.finish(token, result)
        return True

    def _locked(self, connection: Connection, job_id: UUID) -> tuple[store.Run, store.Job] | None:
        observed = store.get_job(connection, job_id)
        run = None if observed is None else store.get_run(connection, observed.run_id)
        if run is None or repo.lock_case(connection, run.case_id) is None:
            return None
        run = store.get_run(connection, run.id, lock=True)
        job = store.get_job(connection, job_id, lock=True)
        if run is None or job is None or job.kind != jobs.REVIEW_KIND or job.run_id != run.id:
            return None
        return run, job

    @staticmethod
    def _existing(connection: Connection, run: store.Run, binding: jobs.DecisionBinding | jobs.ExpiryBinding
                  ) -> Reserved | None:
        decision = repo.get_decision(connection, binding.proposal_id, binding.proposal_version)
        execution = None if decision is None else ledger.by_approval(connection, decision.approval_id)
        if execution is None:
            return None
        if (execution.run_id, execution.case_id, execution.workspace_id, execution.proposal_id,
                execution.proposal_version) != (run.id, run.case_id, run.workspace_id, binding.proposal_id,
                                                binding.proposal_version):
            raise ImmutableRecord("review execution binding changed")
        return Reserved(execution, False)

    def claim(self, job_id: UUID, workspace_id: UUID, owner: UUID) -> store.ClaimToken | None:
        with workspace_transaction(self.executor.engine, workspace_id) as connection:
            locked = self._locked(connection, job_id)
            if locked is None:
                return None
            run, job = locked
            now = self.executor.clock.now(connection)
            if not store.claimable(job, now):
                return None
            binding = jobs.binding_of(job)
            if isinstance(binding, jobs.OutcomeBinding):
                return None  # Slice B owns projection and its dedicated fence.
            decision = repo.get_decision(connection, binding.proposal_id, binding.proposal_version)
            if isinstance(binding, jobs.ExpiryBinding) and decision is not None:
                store.end_job(connection, job, state="done", now=now, error_code="superseded_by_decision")
                return None
            # The graph may have presented before its last checkpoint/finish commit. Never fence that claim.
            execute_job = store.execute_job_of(connection, run.id)
            if (run.state in ("queued", "running") and now < run.deadline_at
                    and execute_job is not None and execute_job.state in ("queued", "leased")):
                store.end_job(connection, job, state="queued", now=now,
                              available_at=min(now + DEFER, run.deadline_at))
                return None
            existing = self._existing(connection, run, binding)
            if job.deadline_at <= now:
                store.end_job(connection, job, state="dead", now=now, error_code="review_delivery_expired")
                return None
            if job.attempts >= job.max_attempts:
                if existing is not None:
                    store.end_job(connection, job, state="done", now=now, error_code="execution_reserved")
                else:
                    finish_refusal(connection, run, job, RefusalReason.RETRIES_EXHAUSTED, now, dead=True)
                return None
            token = store.claim(connection, run, job, owner=owner, lease=jobs.LEASE, now=now)
            if (existing is None and isinstance(binding, jobs.DecisionBinding) and decision is not None
                    and decision.decision == "approve" and run.state == "waiting_approval"
                    and now < run.deadline_at):
                updated = store.set_state(connection, run, "reconciling", now)
                store.append_event(connection, updated, RunStateChanged(previous=run.state, current="reconciling"), now)
            return token

    def execute(self, token: store.ClaimToken) -> Result:
        with workspace_transaction(self.executor.engine, token.workspace_id) as connection:
            run, job, now = jobs.check_claim(connection, token, self.executor.clock)
            binding = jobs.binding_of(job)
            if isinstance(binding, jobs.OutcomeBinding):
                raise ImmutableRecord("outcome projection unavailable")
            existing = self._existing(connection, run, binding)
            if existing is not None:
                return existing  # recovery precedes every authority/deadline/refusal check
            row = repo.proposal_row(connection, binding.proposal_id, binding.proposal_version, lock=True)
            proposal = repo.get_proposal(connection, binding.proposal_id, binding.proposal_version)
            decision = repo.get_decision(connection, binding.proposal_id, binding.proposal_version)
            if row is None or proposal is None or proposal.scope != run.scope:
                return ReviewRefusal(RefusalReason.RECORD_INVALID)
            if isinstance(binding, jobs.ExpiryBinding) and decision is not None:
                return Superseded()
            if isinstance(binding, jobs.DecisionBinding):
                if decision is None or decision.approval_id != binding.decision_id or decision.scope != run.scope:
                    return ReviewRefusal(RefusalReason.RECORD_INVALID)
                if decision.decision == "reject":
                    return ReviewRefusal(RefusalReason.REVIEW_REJECTED)
            if run.terminal:
                return ReviewRefusal(RefusalReason.RUN_TERMINAL)
            if run.deadline_at <= now:
                return ReviewRefusal(RefusalReason.RUN_DEADLINE)
            if row.status != "presented":
                return ReviewRefusal(RefusalReason.PROPOSAL_STALE)
            if isinstance(binding, jobs.ExpiryBinding):
                if now < min(proposal.expires_at, run.deadline_at):
                    return ReviewRetry()  # forged early wakeup cannot expire authority
                return ReviewRefusal(RefusalReason.PROPOSAL_EXPIRED)
            if decision is None:
                return ReviewRefusal(RefusalReason.RECORD_INVALID)
            if now >= proposal.expires_at:
                return ReviewRefusal(RefusalReason.PROPOSAL_EXPIRED)
            roles = frozenset() if run.initiated_by is None else frozenset(
                Role(name) for name in repo.locked_roles(connection, run.initiated_by))
            if not is_allowed(roles, Action.START_RUN):
                return ReviewRefusal(RefusalReason.INITIATOR_REVOKED)
            if run.state != "reconciling":
                return ReviewRefusal(RefusalReason.PROPOSAL_STALE)
            refs = AuthorityRefs(binding.proposal_id, binding.proposal_version, decision.consent_id,
                                 decision.approval_id)
        scope = self.executor.scopes.scope(run.scope)
        if scope.run != run.scope:
            return ReviewRefusal(RefusalReason.RECORD_INVALID)
        reserved = self.executor.reserve(scope, refs, token=token)
        if isinstance(reserved, PrecheckRefused):
            return ReviewRetry() if reserved.retryable else ReviewRefusal(RefusalReason.PRECHECK_REFUSED)
        return reserved

    def finish(self, token: store.ClaimToken, result: Result) -> None:
        with workspace_transaction(self.executor.engine, token.workspace_id) as connection:
            locked = self._locked(connection, token.job_id)
            if locked is None:
                raise store.Fenced("missing")
            run, job, now = jobs.check_claim(connection, token, self.executor.clock)
            binding = jobs.binding_of(job)
            if isinstance(binding, jobs.OutcomeBinding):
                raise ImmutableRecord("outcome projection unavailable")
            # Never emit no-effect wording if a reservation committed before a crash/cancellation.
            existing = self._existing(connection, run, binding)
            if existing is not None:
                store.end_job(connection, job, state="done", now=now, error_code="execution_reserved")
            elif isinstance(result, Reserved):
                raise ImmutableRecord("reservation result has no durable execution")
            elif isinstance(binding, jobs.ExpiryBinding) and repo.get_decision(
                    connection, binding.proposal_id, binding.proposal_version) is not None:
                store.end_job(connection, job, state="done", now=now, error_code="superseded_by_decision")
            elif isinstance(result, ReviewRefusal):
                if result.reason == RefusalReason.PROPOSAL_EXPIRED and isinstance(binding, jobs.ExpiryBinding):
                    row = repo.proposal_row(connection, binding.proposal_id, binding.proposal_version, lock=True)
                    if row is not None and row.status == "presented":
                        repo.set_proposal_status(connection, run.workspace_id, binding.proposal_id,
                                                 binding.proposal_version, "expired")
                finish_refusal(connection, run, job, result.reason, now)
            elif isinstance(result, Superseded):
                raise ImmutableRecord("superseded expiry has no durable decision")
            else:
                delay = min(timedelta(minutes=5), DEFER * 2 ** min(job.attempts - 1, 10))
                if job.attempts >= job.max_attempts or now + delay >= job.deadline_at:
                    finish_refusal(connection, run, job, RefusalReason.RETRIES_EXHAUSTED, now, dead=True)
                else:
                    store.end_job(connection, job, state="queued", now=now, error_code="review_retry",
                                  available_at=now + delay)
