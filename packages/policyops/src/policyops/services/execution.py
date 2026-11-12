"""Approved execution and reconciliation (T19): one durable, fenced execution per approval.

The model proposes; this service executes only what persisted T18 records authorize, re-checked by the T17
precheck and again in the dispatch checkpoint. No role, approval, consent or snapshot is accepted from a caller:
authority comes from `PgDecisionStore`, `PgMembership`, `PgSessionStore` and `PgEvidencePort` only. The HMAC service
token is transport identity and request binding, never staff approval.

Transactions (none is held across an HTTP request; lock order corpora -> run -> proposal -> memberships ->
execution; the lease clock is read after the locks):
- **reserve**: a clearing precheck, then one transaction inserts the execution with an operation ID chosen once
  and the immutable stored request and fingerprint (`pending`), with its event and audit row.
- **claim**: the execution FOR UPDATE SKIP LOCKED; a new claim and lease.
- **checkpoint**: evidence, run, proposal, the approver's memberships FOR SHARE and the execution are locked; the
  claim, the run (not terminal), the proposal (still presented), the reviewer role, the evidence and the time
  (`now < authorization_not_after - margin`) are rechecked, then `dispatched`, attempts + 1. Only then is the
  request sent. Settling locally (`precheck_refused`, `cancelled_before_dispatch`) is possible only while no
  checkpoint was ever committed (`attempts = 0`).
- **record**: every validated `OperationResult` (from mutate, lookup, fence, or a late original worker) is routed
  the same way, independent of the prior state and without the claim: `committed` -> `succeeded` (receipt),
  `fenced` -> `reconciled`, any other stored outcome -> `failed`. An equal terminal observation is a no-op; a
  contradicting one is an audited integrity alert and never overwrites. `Unknown`, `Refused` and an unsent expired
  token leave the row `unknown`, and only the current claim may write that.

Reconciliation of `unknown` (or `dispatched` with an expired lease): lookup; a found stored outcome is recorded.
Lookup absence is never proof of non-execution. If the authority is still current (time, run, attempt cap) and a
fresh precheck clears, the **same** operation ID and request are sent again; otherwise the operation is fenced. A
fence is no-business-effect recovery (the immutable original fingerprint; sent only under a live claim, its token
capped at that claim's lease end), allowed after expiry or cancellation; it is not renewed approval. Once-per-order
tools cannot clear the precheck while their own execution is unresolved (`LedgerHistory` is then incomplete), so
they are fenced rather than re-sent: an availability trade-off. After the reconciliation cap the row stays
`unknown`, unscheduled and holding its target reservation, with its last diagnostic code: an explicit unresolved
operation, never a guessed failure.

Limits (not hidden): PostgreSQL lock waits and COMMIT are synchronous and not interrupted by any deadline; an HTTP
request already sent cannot be recalled by cancellation; the authority checks happen immediately before the hand-off
and revocation after the request begins is not atomic with it; capping the token at the lease end narrows a stale
worker's window but is not a COMMIT deadline (the simulator's case lock and the same operation ID carry correctness).
The component assumes one coherent retail database and ledger lifetime: a retail reset or restore while operations
are unresolved is not detected (T38).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import re
from typing import Literal, Protocol
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine

from policyops.adapters.retail_client import AuthorizationExpired, Refused, Unknown
from policyops.domain.roles import Action, Role, is_allowed
from policyops.gateway.ports import GatewayScope, PgMembership, PgSessionStore, RetailPort
from policyops.gateway.precheck import AuthorityRefs, Cleared, PrecheckRefused, precheck
from policyops.gateway.stores import PgDecisionStore, PgEvidencePort, evidence_status
from policyops.persistence import executions as ledger
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs
from policyops.persistence import runs as run_store
from policyops.persistence.database import IdempotencyConflict, workspace_transaction
from policyops.persistence.records import AuditEvent, ExecutionRecord
from policyops.runtime.clock import LeaseClock
from policyops.telemetry import annotate, count, observed
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import ExecutionChanged
from policyops_contracts.retail import OrderOperationHistory, ToolName
from policyops_contracts.retail_service import LookupResult, MutationRequest, OperationResult, Receipt
from policyops_contracts.scalars import RunScope


SLUG = re.compile(r"[^a-z0-9_.-]+")


class RetailOperations(RetailPort, Protocol):
    """The write side of `RetailClient` (one attempt per call, no retries)."""

    def fingerprint(self, operation_id: UUID, request: MutationRequest) -> str: ...

    def mutate(self, operation_id: UUID, request: MutationRequest, *,
               authorization_not_after: float | None = None) -> OperationResult | Unknown: ...

    def lookup(self, operation_id: UUID, request: MutationRequest) -> LookupResult | Unknown: ...

    def fence(self, operation_id: UUID, request: MutationRequest, *,
              authorization_not_after: float | None = None) -> OperationResult | Unknown: ...


class ScopeResolver(Protocol):
    """The server-derived gateway scope of a persisted run (`gateway.ports.load_scope` with the trusted binding)."""

    def scope(self, run: RunScope) -> GatewayScope: ...


RetailFactory = Callable[[GatewayScope], AbstractContextManager[RetailOperations]]


class ExecutionHooks:
    """Development fault seams around the one HTTP call (no-ops). A subclass marked `test_only` models crashes;
    runtime composition refuses it outside the test environment."""

    def before_checkpoint(self, execution: ExecutionRecord) -> None:
        """After the precheck cleared, before the dispatch checkpoint transaction."""

    def before_send(self, execution: ExecutionRecord) -> None:
        """After the dispatch checkpoint committed, before the request is sent."""

    def after_response(self, execution: ExecutionRecord, result: object) -> None:
        """After the response (or Unknown) arrived, before it is recorded."""


class ExecutionIntegrityError(RuntimeError):
    """The stored binding disagrees with the client's fingerprint or a re-derived request (never sent)."""


@dataclass(frozen=True)
class ExecutionLimits:
    max_dispatches: int = 3
    max_reconciles: int = 8
    lease: timedelta = timedelta(seconds=75)
    authority_margin: timedelta = timedelta(seconds=5)
    backoff: timedelta = timedelta(seconds=2)
    backoff_cap: timedelta = timedelta(seconds=60)

    def __post_init__(self) -> None:
        if not (1 <= self.max_dispatches <= 10 and 1 <= self.max_reconciles <= 50):
            raise ValueError("attempt caps out of range")
        # One claim covers one bounded HTTP call: the client timeout (<= 10 s here), the 30-second token and margin.
        if self.lease < timedelta(seconds=45) or self.authority_margin < timedelta(0):
            raise ValueError("the lease must outlast the token and the client timeout")


Action_ = Literal["reserved", "dispatched", "recorded", "unchanged", "contradiction", "unknown", "capped", "settled",
                  "skipped", "lost_claim"]


@dataclass(frozen=True)
class Step:
    execution_id: UUID
    action: Action_
    state: str
    code: str | None = None


@dataclass(frozen=True)
class Reserved:
    execution: ExecutionRecord
    created: bool


def _observed_result(result: Step) -> Step:
    annotate(outcome=result.state if result.state in {"succeeded", "reconciled", "failed", "unknown"}
             else result.action)
    return result


def _slug(value: str) -> str:
    cleaned = SLUG.sub("_", value.lower()).strip("_.-")[:64]
    return cleaned if cleaned[:1].isalpha() else f"c_{cleaned}"[:64]


def _receipt_sha256(receipt: Receipt | None) -> str | None:
    return None if receipt is None else hashlib.sha256(receipt.model_dump_json().encode("utf-8")).hexdigest()


def route(result: OperationResult) -> tuple[str, str]:
    """(state, outcome) of a validated stored outcome (R1), whatever the row's prior state and source."""
    if result.outcome == "committed":
        return "succeeded", "committed"
    if result.outcome == "fenced":
        return "reconciled", "fenced"
    return "failed", result.outcome


class LedgerHistory:
    """`HistoryPort` over the execution ledger: complete only when no other execution of the case is unresolved and
    the succeeded receipts form a contiguous retail case-version chain from 1 to the observed `case_version` (the
    simulator's case version, not the app case row's). Any commit the ledger did not record breaks the chain, so
    once-per-order rules escalate. Proven only for a simulator case written exclusively through this ledger."""

    def __init__(self, engine: Engine, run: RunScope, *, exclude: UUID | None = None) -> None:
        self._engine, self._run, self._exclude = engine, run, exclude

    def history(self, order_id: str, *, case_version: int) -> OrderOperationHistory:
        with workspace_transaction(self._engine, self._run.workspace_id) as connection:
            rows = ledger.case_executions(connection, self._run.case_id)
        unresolved = any(row.state in ("dispatched", "unknown") or (row.state == "pending" and row.id != self._exclude)
                         for row in rows)
        receipts = sorted((row.receipt for row in rows if row.receipt is not None),
                          key=lambda receipt: receipt.case_version_before)
        expected, chained = 1, True
        for receipt in receipts:
            chained = chained and receipt.case_version_before == expected
            expected = receipt.case_version_after
        complete = not unresolved and chained and expected == case_version
        tools = sorted({row.tool for row in rows if row.state == "succeeded" and row.target_kind == "order"
                        and row.target_id == order_id})
        return OrderOperationHistory(order_id=order_id, complete=complete,
                                     successful_tools=tuple(ToolName(tool) for tool in tools) if complete else ())


class _Now:
    """The precheck's `Clock`, answered by the lease clock in a short transaction (one time authority)."""

    def __init__(self, engine: Engine, clock: LeaseClock, workspace_id: UUID) -> None:
        self._engine, self._clock, self._workspace = engine, clock, workspace_id

    def now(self) -> datetime:
        with workspace_transaction(self._engine, self._workspace) as connection:
            return self._clock.now(connection)


class Executor:
    def __init__(self, *, app_engine: Engine, clock: LeaseClock, scopes: ScopeResolver, retail: RetailFactory,
                 limits: ExecutionLimits | None = None, hooks: ExecutionHooks | None = None,
                 owner: UUID | None = None) -> None:
        self.engine, self.clock, self.scopes, self.retail = app_engine, clock, scopes, retail
        self.limits, self.hooks, self.owner = limits or ExecutionLimits(), hooks or ExecutionHooks(), owner or uuid4()
        self._decisions, self._membership = PgDecisionStore(app_engine), PgMembership(app_engine)
        self._sessions, self._evidence = PgSessionStore(app_engine), PgEvidencePort(app_engine)

    # -- shared pieces ------------------------------------------------------------------------------------------

    def _precheck(self, scope: GatewayScope, execution: ExecutionRecord | None, refs: AuthorityRefs,
                  client: RetailOperations) -> Cleared | PrecheckRefused:
        history = LedgerHistory(self.engine, scope.run, exclude=None if execution is None else execution.id)
        return precheck(scope, refs, retail=client, sessions=self._sessions, membership=self._membership,
                        clock=_Now(self.engine, self.clock, scope.run.workspace_id), decisions=self._decisions,
                        history=history, evidence=self._evidence)

    def _changed(self, connection: Connection, run: run_store.Run, execution: ExecutionRecord, now: datetime,
                 action: str) -> None:
        """The execution's run event (with its outbox intent) and audit row, in the transition's transaction."""
        run_store.append_event(connection, run, ExecutionChanged(
            execution_id=execution.id, operation_id=execution.operation_id, tool=ToolName(execution.tool),
            state=execution.state, attempt=execution.attempts, outcome=execution.outcome, code=execution.last_code,
            receipt_sha256=_receipt_sha256(execution.receipt)), now)
        repo.append_audit(connection, AuditEvent(
            id=uuid4(), workspace_id=execution.workspace_id, actor_kind="worker", actor_principal_id=None,
            action=action, target_type="tool_execution", target_id=execution.id,
            after_sha256=hashlib.sha256(f"{execution.state}:{execution.outcome}:{execution.version}".encode()
                                        ).hexdigest(), reason=None, correlation_id=execution.operation_id,
            occurred_at=now))
        if execution.terminal or (execution.state == "unknown" and execution.next_attempt_at is None):
            review_jobs.enqueue_outcome(connection, execution)

    @contextmanager
    def _locked(self, execution: ExecutionRecord) -> Iterator[tuple[Connection, run_store.Run, ExecutionRecord,
                                                                     datetime]]:
        with workspace_transaction(self.engine, execution.workspace_id) as connection:
            run = run_store.get_run(connection, execution.run_id, lock=True)
            current = ledger.get(connection, execution.id, lock=True)
            if run is None or current is None:
                raise ledger.LostClaim("the execution or its run is not visible")
            if not ledger.same_binding(current, execution):  # a caller snapshot is never authority
                raise ExecutionIntegrityError("the execution snapshot does not match the stored binding")
            yield connection, run, current, self.clock.now(connection)

    def _backoff(self, execution: ExecutionRecord) -> timedelta:
        exponent = min(execution.attempts + execution.reconcile_attempts, 10)
        delay: timedelta = min(self.limits.backoff_cap, self.limits.backoff * (2 ** exponent))
        return delay

    # -- reservation ----------------------------------------------------------------------------------------

    @observed("execution.reserve")
    def reserve(self, scope: GatewayScope, refs: AuthorityRefs, *,
                token: run_store.ClaimToken | None = None) -> Reserved | PrecheckRefused:
        """Reserve the approval's execution after a clearing precheck. Idempotent per approval: the stored
        operation ID is returned on every repeat that names the same run (hence case and server-derived customer
        binding) and the same proposal, consent and approval; any other combination is an IdempotencyConflict. A
        repeat is not re-prechecked: it neither renews an expired approval nor mints another operation."""
        annotate(run_id=scope.run.run_id, proposal_id=refs.proposal_id, operation="reserve")
        with workspace_transaction(self.engine, scope.run.workspace_id) as connection:
            existing = ledger.by_approval(connection, refs.approval_id)
        if existing is not None:
            annotate(operation_id=existing.operation_id)
            if not ledger.matches_reservation(existing, run=scope.run, approval_id=refs.approval_id,
                                              consent_id=refs.consent_id, proposal_id=refs.proposal_id,
                                              proposal_version=refs.proposal_version):
                raise IdempotencyConflict(f"approval {refs.approval_id} is reserved with other references")
            return Reserved(existing, False)
        with self.retail(scope) as client:
            cleared = self._precheck(scope, None, refs, client)
            if isinstance(cleared, PrecheckRefused):
                annotate(outcome="refused")
                return cleared
            with workspace_transaction(self.engine, scope.run.workspace_id) as connection:
                run = run_store.get_run(connection, scope.run.run_id, lock=True)
                if run is None:
                    raise ledger.LostClaim("the run is not visible")
                # Recheck under the run lock: another worker may have committed during the precheck.
                existing = ledger.by_approval(connection, refs.approval_id)
                if existing is not None:
                    if not ledger.matches_reservation(existing, run=scope.run, approval_id=refs.approval_id,
                            consent_id=refs.consent_id, proposal_id=refs.proposal_id,
                            proposal_version=refs.proposal_version):
                        raise IdempotencyConflict("approval reserved with other references")
                    annotate(operation_id=existing.operation_id)
                    return Reserved(existing, False)
                if token is not None:
                    fenced_run, job, _ = run_store.check_fence(connection, token, self.clock)
                    binding = review_jobs.binding_of(job)
                    if (fenced_run.scope != scope.run or fenced_run.state != "reconciling"
                            or not isinstance(binding, review_jobs.DecisionBinding)
                            or (binding.proposal_id, binding.proposal_version, binding.decision_id) != (
                                refs.proposal_id, refs.proposal_version, refs.approval_id)):
                        raise run_store.Fenced("review_binding_changed")
                    roles = frozenset() if run.initiated_by is None else frozenset(
                        Role(name) for name in repo.locked_roles(connection, run.initiated_by))
                    if not is_allowed(roles, Action.START_RUN):
                        return PrecheckRefused(ErrorCode.FORBIDDEN, "initiator_not_authorized")
                    # Membership locks can wait; the claim must still be live after that wait.
                    run_store.check_fence(connection, token, self.clock, active=True)
                now = self.clock.now(connection)
                if run.terminal or run.active_started_at is None or run_store.remaining_us(run, now) == 0:
                    return PrecheckRefused(ErrorCode.EXPIRED, "run_deadline_exceeded" if not run.terminal
                                           else "run_terminal")
                execution, created = ledger.reserve(
                    connection, run=scope.run, approval_id=refs.approval_id, consent_id=refs.consent_id,
                    proposal_id=refs.proposal_id, proposal_version=refs.proposal_version, request=cleared.request,
                    operation_sha256_of=lambda operation_id: client.fingerprint(operation_id, cleared.request),
                    authorization_not_after=cleared.authorization_not_after, now=now)
                if created:
                    self._changed(connection, run, execution, now, "execution.reserved")
        annotate(operation_id=execution.operation_id)
        return Reserved(execution, created)

    # -- one bounded step -----------------------------------------------------------------------------------

    @observed("execution.step")
    def step(self, workspace_id: UUID, execution_id: UUID) -> Step:
        result = self._step(workspace_id, execution_id)
        outcome = result.state if result.state in {"succeeded", "reconciled", "failed", "unknown"} else result.action
        annotate(outcome=outcome)
        count("executions", outcome=outcome)
        return result

    def _step(self, workspace_id: UUID, execution_id: UUID) -> Step:
        """Claim one due execution and advance it by one bounded step (at most a lookup and one mutate or fence)."""
        with workspace_transaction(self.engine, workspace_id) as connection:
            found = ledger.get(connection, execution_id, skip_locked=True)
            now = self.clock.now(connection)
            if found is None or found.terminal or found.next_attempt_at is None or found.next_attempt_at > now or (
                    found.lease_expires_at is not None and found.lease_expires_at > now):
                return Step(execution_id, "skipped", "busy" if found is None else found.state)
            claimed = ledger.claim(connection, found, owner=self.owner, lease=self.limits.lease, now=now)
        annotate(run_id=claimed.run_id, operation_id=claimed.operation_id, proposal_id=claimed.proposal_id,
                 attempt=claimed.attempts)
        scope = self.scopes.scope(RunScope(workspace_id=claimed.workspace_id, case_id=claimed.case_id,
                                           run_id=claimed.run_id))
        if scope.run != RunScope(workspace_id=claimed.workspace_id, case_id=claimed.case_id, run_id=claimed.run_id):
            raise ExecutionIntegrityError("the resolved scope is not the execution's run")
        with self.retail(scope) as client:
            if client.fingerprint(claimed.operation_id, claimed.request) != claimed.operation_sha256:
                raise ExecutionIntegrityError("the stored fingerprint does not match this client's binding")
            if claimed.state == "pending":
                return self._first(claimed, scope, client)
            return self._reconcile(claimed, scope, client)

    def _refs(self, execution: ExecutionRecord) -> AuthorityRefs:
        return AuthorityRefs(proposal_id=execution.proposal_id, proposal_version=execution.proposal_version,
                             consent_id=execution.consent_id, approval_id=execution.approval_id)

    def _first(self, execution: ExecutionRecord, scope: GatewayScope, client: RetailOperations) -> Step:
        cleared = self._precheck(scope, execution, self._refs(execution), client)
        if isinstance(cleared, PrecheckRefused):
            if cleared.retryable and execution.reconcile_attempts + 1 < self.limits.max_reconciles:
                return self._defer(execution, cleared.detail)  # e.g. facts unreadable: nothing was sent, retry later
            return self._settle(execution, "precheck_refused", "precheck", cleared.detail)
        return self._dispatch(execution, scope, client, cleared)

    def _defer(self, execution: ExecutionRecord, code: str) -> Step:
        with self._locked(execution) as (connection, run, current, now):
            if not ledger.holds_claim(current, execution, now) or current.state != "pending":
                return Step(execution.id, "lost_claim", current.state)
            deferred = ledger.update(connection, current, now, last_code=_slug(code), claim_id=None,
                                     lease_owner=None, lease_expires_at=None,
                                     reconcile_attempts=current.reconcile_attempts + 1,
                                     next_attempt_at=now + self._backoff(current))
            self._changed(connection, run, deferred, now, "execution.deferred")
        return Step(execution.id, "unknown", "pending", deferred.last_code)

    def _settle(self, execution: ExecutionRecord, outcome: str, resolved_by: str, code: str) -> Step:
        """Terminal local refusal: only with the claim and while nothing was ever dispatched."""
        with self._locked(execution) as (connection, run, current, now):
            if not ledger.holds_claim(current, execution, now) or current.attempts != 0:
                return Step(execution.id, "lost_claim", current.state)
            settled = ledger.update(connection, current, now, state="failed", outcome=outcome,
                                    resolved_by=resolved_by, last_code=_slug(code), claim_id=None, lease_owner=None,
                                    lease_expires_at=None, next_attempt_at=None)
            self._changed(connection, run, settled, now, "execution.settled")
        return Step(execution.id, "settled", "failed", settled.last_code)

    def _checkpoint(self, execution: ExecutionRecord, cleared: Cleared) -> ExecutionRecord | Step | str:
        """The dispatch checkpoint. Returns the dispatched row, a Step (settled or lost), or a refusal code when the
        operation was dispatched before (the caller then fences)."""
        proposal = cleared.proposal
        with workspace_transaction(self.engine, execution.workspace_id) as connection:
            evidence = evidence_status(connection, proposal.evidence, run_id=None)  # corpora FOR SHARE first
            run = run_store.get_run(connection, execution.run_id, lock=True)
            row = repo.proposal_row(connection, execution.proposal_id, execution.proposal_version, lock=True)
            approval = None if run is None else repo.decision_by_id(connection, run.scope, execution.approval_id)
            roles = frozenset() if approval is None else frozenset(
                Role(name) for name in repo.locked_roles(connection, approval.principal_id))
            current = ledger.get(connection, execution.id, lock=True)
            now = self.clock.now(connection)  # after every lock
            if run is None or current is None or not ledger.holds_claim(current, execution, now):
                return Step(execution.id, "lost_claim", "unknown" if current is None else current.state)
            refusal: tuple[str, str] | None = None
            if run.terminal:
                refusal = ("cancelled_before_dispatch", "cancel")
            elif run.active_started_at is None or run_store.remaining_us(run, now) == 0:
                refusal = ("precheck_refused", "run_deadline_exceeded")
            elif row is None or row.status != "presented" or row.action_digest != execution.action_digest:
                refusal = ("precheck_refused", "proposal_not_current")
            elif approval is None or Role.REVIEWER not in roles or not is_allowed(roles, Action.DECIDE_PROPOSAL):
                refusal = ("precheck_refused", "approver_not_current_reviewer")
            elif evidence != "current":
                refusal = ("precheck_refused", evidence)
            elif now >= current.authorization_not_after - self.limits.authority_margin:
                refusal = ("precheck_refused", "authorization_expired")
            elif current.attempts >= self.limits.max_dispatches:
                refusal = ("precheck_refused", "dispatch_cap_reached")
            if refusal is not None:
                outcome, code = refusal
                if current.attempts:
                    return code if outcome == "precheck_refused" else "run_cancelled"
                resolved_by = "cancel" if outcome == "cancelled_before_dispatch" else "precheck"
                settled = ledger.update(connection, current, now, state="failed", outcome=outcome,
                                        resolved_by=resolved_by, last_code=_slug(code), claim_id=None,
                                        lease_owner=None, lease_expires_at=None, next_attempt_at=None)
                self._changed(connection, run, settled, now, "execution.settled")
                return Step(execution.id, "settled", "failed", settled.last_code)
            dispatched = ledger.update(connection, current, now, state="dispatched", attempts=current.attempts + 1,
                                       dispatched_at=now, next_attempt_at=current.lease_expires_at, last_code=None)
            self._changed(connection, run, dispatched, now, "execution.dispatched")
        return dispatched  # committed: only now may the request be sent

    @observed("execution.dispatch")
    def _dispatch(self, execution: ExecutionRecord, scope: GatewayScope, client: RetailOperations,
                  cleared: Cleared) -> Step:
        annotate(run_id=execution.run_id, operation_id=execution.operation_id, proposal_id=execution.proposal_id,
                 operation="dispatch", attempt=execution.attempts)
        if client.fingerprint(execution.operation_id, cleared.request) != execution.operation_sha256:
            raise ExecutionIntegrityError("the re-derived request differs from the stored one; nothing was sent")
        self.hooks.before_checkpoint(execution)
        checked = self._checkpoint(execution, cleared)
        if isinstance(checked, Step):
            return _observed_result(checked)
        if isinstance(checked, str):
            return _observed_result(self._fence(execution, client, checked))
        self.hooks.before_send(checked)
        lease_end = checked.lease_expires_at or checked.authorization_not_after
        not_after = min(checked.authorization_not_after - self.limits.authority_margin, lease_end)
        result: OperationResult | Unknown | Refused
        try:
            result = client.mutate(checked.operation_id, checked.request,
                                   authorization_not_after=not_after.timestamp())
        except AuthorizationExpired:
            result = Unknown("authorization_expired_unsent")  # after the checkpoint: reconcile, never "failed"
        except Refused as refused:
            result = refused  # a refusal of this attempt does not prove an earlier attempt had no effect
        self.hooks.after_response(checked, result)
        return _observed_result(self.record(checked, result, "response"))

    @observed("execution.reconcile")
    def _reconcile(self, execution: ExecutionRecord, scope: GatewayScope, client: RetailOperations) -> Step:
        annotate(run_id=execution.run_id, operation_id=execution.operation_id, proposal_id=execution.proposal_id,
                 operation="reconcile", attempt=execution.attempts)
        try:
            found = client.lookup(execution.operation_id, execution.request)
        except Refused as refused:
            found = Unknown(f"lookup_refused_{refused.status}")
        if isinstance(found, LookupResult) and found.result is not None:
            return _observed_result(self.record(execution, found.result, "lookup"))
        now = _Now(self.engine, self.clock, execution.workspace_id).now()
        if execution.attempts < self.limits.max_dispatches and \
                now < execution.authorization_not_after - self.limits.authority_margin:
            cleared = self._precheck(scope, execution, self._refs(execution), client)
            if isinstance(cleared, Cleared):
                return _observed_result(self._dispatch(execution, scope, client, cleared))  # same operation/request
            return _observed_result(self._fence(execution, client, cleared.detail))
        return _observed_result(self._fence(execution, client, "authority_ended"))

    def _fence(self, execution: ExecutionRecord, client: RetailOperations, reason: str) -> Step:
        """Send a fence only under a live claim (re-read now, after any slow lookup), with the service token capped
        at that claim's lease end. A worker whose claim lapsed sends nothing; the next claimant fences."""
        del reason
        with workspace_transaction(self.engine, execution.workspace_id) as connection:
            current = ledger.get(connection, execution.id)
            now = self.clock.now(connection)
        if current is None or current.terminal or current.lease_expires_at is None \
                or not ledger.holds_claim(current, execution, now):
            return Step(execution.id, "lost_claim", "unknown" if current is None else current.state)
        if not ledger.same_binding(current, execution):
            raise ExecutionIntegrityError("the execution snapshot does not match the stored binding")
        result: OperationResult | Unknown | Refused
        try:
            result = client.fence(current.operation_id, current.request,
                                  authorization_not_after=current.lease_expires_at.timestamp())
        except AuthorizationExpired:
            result = Unknown("authorization_expired_unsent")  # nothing was sent: the row stays unresolved
        except Refused as refused:
            result = refused
        return self.record(execution, result, "fence")

    # -- recording ------------------------------------------------------------------------------------------

    def record(self, execution: ExecutionRecord, result: OperationResult | Unknown | Refused,
               resolved_by: Literal["response", "lookup", "fence"]) -> Step:
        if isinstance(result, OperationResult):
            return self._record_stored(execution, result, resolved_by)
        code = _slug(f"refused_{result.status}_{result.code}" if isinstance(result, Refused) else result.reason)
        with self._locked(execution) as (connection, run, current, now):
            if current.terminal:
                return Step(execution.id, "unchanged", current.state, code)
            if not ledger.holds_claim(current, execution, now):
                return Step(execution.id, "lost_claim", current.state, code)  # a stale worker writes nothing
            reconciles = current.reconcile_attempts + (resolved_by != "response")
            capped = reconciles >= self.limits.max_reconciles
            unknown = ledger.update(
                connection, current, now, state="unknown", last_code=code, reconcile_attempts=reconciles,
                claim_id=None, lease_owner=None, lease_expires_at=None,
                next_attempt_at=None if capped else now + self._backoff(current))
            self._changed(connection, run, unknown, now, "execution.unresolved" if capped else "execution.unknown")
        return Step(execution.id, "capped" if capped else "unknown", "unknown", code)

    def _record_stored(self, execution: ExecutionRecord, result: OperationResult,
                       resolved_by: Literal["response", "lookup", "fence"]) -> Step:
        state, outcome = route(result)
        with self._locked(execution) as (connection, run, current, now):
            # The result (and its receipt) must be of the stored row's operation, not only of the caller's snapshot.
            bound = (str(current.operation_id), current.operation_sha256)
            receipt = result.receipt
            if (result.operation_id, result.operation_sha256) != bound or (
                    receipt is not None and (receipt.operation_id, receipt.operation_sha256) != bound):
                raise ExecutionIntegrityError("a stored outcome of another operation")
            if current.terminal:
                if (current.state, current.outcome, current.receipt) == (state, outcome, result.receipt):
                    return Step(execution.id, "unchanged", current.state)
                repo.append_audit(connection, AuditEvent(
                    id=uuid4(), workspace_id=current.workspace_id, actor_kind="worker", actor_principal_id=None,
                    action="execution.contradiction", target_type="tool_execution", target_id=current.id,
                    reason=f"recorded {current.outcome}, observed {outcome} via {resolved_by}",
                    correlation_id=current.operation_id, occurred_at=now))
                return Step(execution.id, "contradiction", current.state, "contradictory_outcome")
            if current.state == "pending":
                raise ExecutionIntegrityError("a stored outcome for an operation that was never dispatched")
            recorded = ledger.update(
                connection, current, now, state=state, outcome=outcome, resolved_by=resolved_by,
                receipt=None if result.receipt is None else result.receipt.model_dump(mode="json"),
                claim_id=None, lease_owner=None, lease_expires_at=None, next_attempt_at=None)
            self._changed(connection, run, recorded, now, "execution.recorded")
        return Step(execution.id, "recorded", state, outcome)
