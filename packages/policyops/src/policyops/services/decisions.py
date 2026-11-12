"""Staff decisions on presented proposals (T18): one short transaction, no remote or human wait inside it.

Order inside the workspace transaction (each later step only after the earlier ones pass):
1. the run row FOR UPDATE (its ID read first from the immutable proposal row), then the proposal row FOR UPDATE;
   an absent or foreign proposal is 404, the same as for another tenant;
2. the principal's active memberships FOR SHARE (conflicts with a revocation's FOR NO KEY UPDATE). The current
   reviewer role is required **before any replay** (403);
3. the stored body re-validated, and the request's `action_digest` equal to the sealed one (409 digest mismatch);
4. an existing decision: an identical request by the same principal (version, digest, decision, reason) is a replay
   that returns the original immutable `ApprovalDecision` (200, the same canonical bytes); anything else is 409;
5. new decisions only: the run not terminal, the row `presented`, the pinned policy, the proposal unexpired, a consent
   current now, then `approval_rules.decide` (reviewer role, separation of duties, expiry = min(proposal, consent,
   now + 15 minutes));
6. the clock read again just before the insert (a decision past its own expiry is refused), then the insert (the
   unique constraint backs the row lock), the `approval.decided` run event and the audit row, then COMMIT.

The clock is read after the blocking locks. Lock waits and COMMIT are synchronous and are not interrupted by any
deadline, so an acknowledged decision can be historically valid yet already expired when the response arrives. An
exception raised by COMMIT itself is `DecisionCommitUnknown` (503, retryable): never success. The retry guidance is to
send the identical request again: it replays the original if the first attempt committed. The run state is not
changed and nothing is executed (T19/T22). Resource versions are not re-read here (that would need the retail service);
the execution precheck re-collects facts and refuses a stale approval.

A rejection also requires a current consent: `approval_decisions.consent_id` is NOT NULL and the accepted
`approval_rules.decide` requires it. A proposal without consent can only expire or be superseded.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import Engine
from sqlalchemy.exc import DBAPIError

from policyops.auth.service import AuthError, Authorized, forbidden
from policyops.domain.approval_rules import Decided, decide
from policyops.domain.roles import Action, Role, is_allowed
from policyops.persistence import repositories as repo
from policyops.persistence import review_jobs
from policyops.persistence import runs as run_store
from policyops.persistence.database import DecisionConflict, ImmutableRecord, workspace_transaction
from policyops.persistence.records import AuditEvent
from policyops.runtime.clock import LeaseClock
from policyops.services.proposal_views import DecisionRequest
from policyops.services.writes import not_found
from policyops_contracts.consent import ApprovalDecision, CustomerConsent
from policyops_contracts.digest import canonical_bytes, sha256_hex
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import ApprovalDecided
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.proposal import ActionProposal


class DecisionCommitUnknown(Exception):
    """COMMIT raised: the decision may or may not be durable. Never reported as decided."""


@dataclass(frozen=True)
class Replay:
    decision: ApprovalDecision


@dataclass(frozen=True)
class NewDecision:
    decision: ApprovalDecision


@dataclass(frozen=True)
class Refusal:
    status: int
    code: ErrorCode
    rule_id: str
    detail: str

    def error(self) -> AuthError:
        return AuthError(self.status, self.code, self.detail, self.rule_id)


@dataclass(frozen=True)
class DecisionResult:
    decision: ApprovalDecision
    replayed: bool


def conflict(code: ErrorCode, rule_id: str, detail: str) -> Refusal:
    return Refusal(409, code, rule_id, detail)


def evaluate(*, principal_id: UUID, roles: frozenset[Role], run_terminal: bool, row_status: str,
             proposal: ActionProposal, existing: ApprovalDecision | None, consent: CustomerConsent | None,
             request: DecisionRequest, approval_id: UUID, now: datetime) -> Replay | NewDecision | Refusal:
    """The decision on already loaded, locked records (pure; steps 2-5 of the module order)."""
    if not roles:
        return Refusal(403, ErrorCode.FORBIDDEN, "auth.membership", "You are not a member of this workspace.")
    if Role.REVIEWER not in roles or not is_allowed(roles, Action.DECIDE_PROPOSAL):
        return Refusal(403, ErrorCode.FORBIDDEN, "auth.role", "Only a current reviewer can decide proposals.")
    if request.action_digest != proposal.action_digest:
        return conflict(ErrorCode.CONFLICT, "api.proposal_digest_mismatch",
                        "The digest does not match this proposal version.")
    if existing is not None:
        if (existing.principal_id, existing.proposal_version, existing.action_digest, existing.decision,
                existing.reason) == (principal_id, request.proposal_version, request.action_digest, request.decision,
                                     request.reason):
            return Replay(existing)
        return conflict(ErrorCode.CONFLICT, "api.proposal_already_decided",
                        "This proposal version already has a decision.")
    if run_terminal:
        return conflict(ErrorCode.CONFLICT, "api.run_terminal", "The run has ended.")
    if row_status == "superseded":
        return conflict(ErrorCode.STALE_VERSION, "api.proposal_superseded", "A newer version replaced this proposal.")
    if row_status == "expired":
        return conflict(ErrorCode.EXPIRED, "api.proposal_expired", "The proposal has expired.")
    if row_status != "presented":
        return conflict(ErrorCode.CONSENT_REQUIRED, "api.proposal_not_presented",
                        "The proposal has not been shown to the customer.")
    if proposal.policy != RETAIL_POLICY:
        return conflict(ErrorCode.STALE_VERSION, "api.policy_changed", "The proposal was made under another policy.")
    if now >= proposal.expires_at:
        return conflict(ErrorCode.EXPIRED, "api.proposal_expired", "The proposal has expired.")
    if consent is None:
        return conflict(ErrorCode.CONSENT_REQUIRED, "api.consent_required",
                        "The customer has not confirmed this proposal.")
    if now >= consent.expires_at:
        return conflict(ErrorCode.EXPIRED, "api.consent_expired", "The customer's confirmation has expired.")
    outcome = decide(approval_id=approval_id, proposal=proposal, consent=consent, principal_id=principal_id,
                     roles=roles, decision=request.decision, reason=request.reason, now=now)
    if isinstance(outcome, Decided):
        return NewDecision(outcome.decision)
    if outcome.code == "separation_of_duties":
        return Refusal(403, ErrorCode.SEPARATION_OF_DUTIES, "api.separation_of_duties",
                       "The operator who entered the customer's confirmation cannot decide it.")
    if outcome.code == "forbidden":
        return Refusal(403, ErrorCode.FORBIDDEN, "auth.role", "Only a current reviewer can decide proposals.")
    return conflict(ErrorCode.CONSENT_REQUIRED, "api.consent_required",
                    "There is no current customer confirmation for this proposal version.")


def decision_digest(decision: ApprovalDecision) -> str:
    return sha256_hex(canonical_bytes(decision))


@dataclass
class DecisionService:
    app_engine: Engine
    clock: LeaseClock

    def decide(self, authorized: Authorized, proposal_id: UUID, request: DecisionRequest) -> DecisionResult:
        principal = authorized.session.principal_id
        body_completed = False
        try:
            with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
                peek = repo.proposal_row(connection, proposal_id, request.proposal_version)
                if peek is None:
                    raise not_found("proposal")
                run = run_store.get_run(connection, peek.run_id, lock=True)  # run before proposal (lock order)
                row = repo.proposal_row(connection, proposal_id, request.proposal_version, lock=True)
                if run is None or row is None or (row.case_id, row.run_id) != (run.case_id, run.id):
                    raise not_found("proposal")
                roles = frozenset(Role(name) for name in repo.locked_roles(connection, principal))
                if not roles:
                    raise forbidden("You are not a member of this workspace.", "auth.membership")
                try:
                    proposal = repo.get_proposal(connection, proposal_id, request.proposal_version)
                except (ImmutableRecord, ValidationError):
                    proposal = None
                if proposal is None or proposal.action_digest != row.action_digest:
                    raise AuthError(500, ErrorCode.INTERNAL, "A stored proposal is not valid.",
                                    "api.proposal_invalid")
                existing = repo.get_decision(connection, proposal_id, request.proposal_version)
                consent = repo.get_consent(connection, proposal_id, request.proposal_version)
                now = self.clock.now(connection)  # after the locks
                outcome = evaluate(principal_id=principal, roles=roles, run_terminal=run.terminal,
                                   row_status=row.status, proposal=proposal, existing=existing, consent=consent,
                                   request=request, approval_id=uuid4(), now=now)
                if isinstance(outcome, Refusal):
                    raise outcome.error()
                if isinstance(outcome, Replay):
                    review_jobs.enqueue_decision(connection, outcome.decision)
                    body_completed = True
                    return DecisionResult(outcome.decision, replayed=True)
                decision = outcome.decision
                checked = self.clock.now(connection)  # again, just before the insert
                if checked >= decision.expires_at:
                    raise conflict(ErrorCode.EXPIRED, "api.proposal_expired", "The proposal has expired.").error()
                try:
                    repo.record_decision(connection, decision)
                except DecisionConflict:  # the row lock serializes deciders; this is the constraint's backstop
                    raise conflict(ErrorCode.CONFLICT, "api.proposal_already_decided",
                                   "This proposal version already has a decision.").error() from None
                run_store.append_event(connection, run, ApprovalDecided(
                    approval_id=decision.approval_id, proposal_id=decision.proposal_id, decision=decision.decision),
                    checked)
                repo.append_audit(connection, AuditEvent(
                    id=uuid4(), workspace_id=authorized.workspace_id, actor_kind="principal",
                    actor_principal_id=principal, action="proposal.decide", target_type="action_proposal",
                    target_id=row.row_id, before_sha256=None, after_sha256=decision_digest(decision),
                    reason=decision.reason, correlation_id=uuid4(), occurred_at=checked))
                review_jobs.enqueue_decision(connection, decision)
                body_completed = True
        except DBAPIError as error:
            if body_completed:  # raised by COMMIT: the outcome is unknown
                raise DecisionCommitUnknown("the decision commit outcome is unknown") from error
            raise
        return DecisionResult(decision, replayed=False)
