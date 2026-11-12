"""Durable proposals: create, supersede, present and customer consent, plus the reviewer reads (T18).

The write operations are **internal**: later workers call them (T21/T22) and tests call them directly. No HTTP route
creates, presents or consents to a proposal, and nothing here accepts a decision, an effect, a role, a consent record
or an approval from a caller. Each is one short workspace transaction with no retail, provider or human wait inside
it; facts are collected by the gateway before `create` is called.

Every write re-checks the persisted context under its locks. The caller's `GatewayScope` (built by the server from the
persisted run and case, `gateway.ports.load_scope`) and `Collected` facts are inputs, not authority: the case row must
still be bound to the scope's customer, the run must belong to the case and not be terminal, and the run's durable
lookup authentication must name the bound customer. Lock order (a subsequence of `repositories`' T18 order):

* `create`: case -> corpora FOR SHARE (evidence only) -> run -> same-intent active proposal rows -> insert;
* `present`: case -> run -> proposal row -> agent message (case already held) -> presentation -> run events;
* `record_customer_reply`: run -> the run's presented proposal row -> consent -> run events. The customer message was
  appended earlier by the case API under the case lock.

`create` picks the proposal ID and version under those locks, reads the clock after them and seals the proposal once
(`domain.retail_rules.propose`). It then requires the exact presentation text to fit one case message
(`proposal_views.presentable`) **before** superseding anything or inserting. A rendering over the bound is refused
(`presentation.message_limit`), never truncated or split. `present` repeats that guard for bodies stored earlier.
A new version supersedes every active version of the same intent in the case, in the same transaction, so at most one
presented version per (case, intent) exists. Statuses only move forward, so a superseded version cannot regain
authority.

Commit is not interruptible by a deadline here; a failure raised by COMMIT leaves the outcome unknown, and these
operations add no automatic retry that could duplicate a message or event.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
import hashlib
from uuid import UUID, uuid4, uuid5

from pydantic import ValidationError
from pydantic_core import PydanticSerializationError
from sqlalchemy import Connection, Engine

from policyops.auth.service import AuthError, Authorized
from policyops.domain.consent_rules import (
    AskAgain,
    Consented,
    ConsentOutcome,
    NotConsent,
    record_reply,
    record_simulator_event,
)
from policyops.domain.retail_rules import Denied, Escalated, intent_digest, propose
from policyops.domain.session import CustomerSession
from policyops.gateway.facts import Collected
from policyops.gateway.ports import GatewayScope
from policyops.gateway.stores import evidence_status
from policyops.persistence import checkpoint_json, customer_authentications
from policyops.persistence import repositories as repo
from policyops.persistence import runs as run_store
from policyops.persistence.customer_authentications import AuthenticationConflict
from policyops.persistence.database import IdempotencyConflict, ImmutableRecord, workspace_transaction
from policyops.persistence.records import AuditEvent
from policyops.persistence.repositories import ProposalRow
from policyops.runtime.clock import LeaseClock
from policyops.services.proposal_views import (
    MAX_PROPOSAL_PAGE,
    ProposalCursor,
    ProposalDetailView,
    ProposalPage,
    case_list_key,
    decode_cursor,
    detail_view,
    encode_cursor,
    invalid,
    presentable,
    review_state,
    summary_view,
)
from policyops.services.writes import not_found
from policyops_contracts.consent import CaseMessage, ProposalPresentationRecord, SimulatorConfirmationEvent
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import ClarificationRequested, ConsentRecorded, MessagePosted, ProposalPresented
from policyops_contracts.proposal import ActionProposal, EvidenceRef
from policyops_contracts.retail import (
    CancelPendingOrder,
    ExchangeDeliveredOrderItems,
    ModifyPendingOrderAddress,
    ModifyPendingOrderItems,
    ModifyPendingOrderPayment,
    ModifyUserAddress,
    ReturnDeliveredOrderItems,
    WriteToolCall,
)
from policyops_contracts.scalars import CaseScope, RunScope


WRITE_CALLS = (CancelPendingOrder, ModifyPendingOrderAddress, ModifyPendingOrderPayment, ModifyPendingOrderItems,
               ReturnDeliveredOrderItems, ExchangeDeliveredOrderItems, ModifyUserAddress)
PROPOSAL_NAMESPACE = UUID("d20b1653-e26e-5c37-85df-d0947e92010c")
MAX_EVIDENCE = 32
MAX_RATIONALE = 1000  # ProposalBody.rationale


@dataclass(frozen=True)
class ProposalRefused:
    """A fixed refusal; nothing was written."""

    code: ErrorCode
    rule_id: str
    detail: str


@dataclass(frozen=True)
class Created:
    proposal: ActionProposal
    superseded: tuple[tuple[UUID, int], ...]


@dataclass(frozen=True)
class Presented:
    record: ProposalPresentationRecord
    message: CaseMessage


@dataclass(frozen=True)
class Prepared:
    """One immutable proposal and its original presentation, including on replay."""

    proposal: ActionProposal
    record: ProposalPresentationRecord
    message: CaseMessage


def _refused(code: ErrorCode, rule_id: str, detail: str) -> ProposalRefused:
    return ProposalRefused(code, rule_id, detail)


def _revalidated_call(call: object) -> WriteToolCall | None:
    """The write call re-validated from its serialized form (a constructed object that skipped validation is
    refused, including one whose fields cannot even be serialized, e.g. a lone surrogate or a foreign object)."""
    if type(call) not in WRITE_CALLS:
        return None
    try:
        return type(call).model_validate_json(call.model_dump_json(warnings=False))  # type: ignore[attr-defined,no-any-return]
    except (ValidationError, PydanticSerializationError):
        return None


def _revalidated_evidence(evidence: Sequence[object]) -> tuple[EvidenceRef, ...] | None:
    """Each reference re-validated, at most MAX_EVIDENCE of them, with distinct citation IDs. A duplicate is refused
    explicitly (never silently resolved to one of the references)."""
    if len(evidence) > MAX_EVIDENCE or any(type(item) is not EvidenceRef for item in evidence):
        return None
    try:
        checked = tuple(EvidenceRef.model_validate_json(item.model_dump_json(warnings=False))  # type: ignore[attr-defined]
                        for item in evidence)
    except (ValidationError, PydanticSerializationError):
        return None
    if len({item.evidence_id for item in checked}) != len(checked):
        return None
    return checked


def checked_rationale(rationale: object) -> str | None:
    """The rationale bound of the proposal contract (1..MAX_RATIONALE characters), plus: a real `str`, encodable as
    UTF-8 (no lone surrogates) and free of control characters other than newline and tab (the `scalars` text rule)."""
    if type(rationale) is not str or not 1 <= len(rationale) <= MAX_RATIONALE:
        return None
    try:
        rationale.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if any((ord(char) < 32 and char not in "\n\t") or 0x7F <= ord(char) < 0xA0 for char in rationale):
        return None
    return rationale


def _audit(connection: Connection, *, workspace_id: UUID, actor_kind: str, action: str, target_id: UUID,
           before: str | None, after: str | None, now: datetime) -> None:
    repo.append_audit(connection, AuditEvent(
        id=uuid4(), workspace_id=workspace_id, actor_kind=actor_kind, actor_principal_id=None,  # type: ignore[arg-type]
        action=action, target_type="action_proposal", target_id=target_id, before_sha256=before,
        after_sha256=after, correlation_id=uuid4(), occurred_at=now))


def _load_body(connection: Connection, row: ProposalRow) -> ActionProposal | None:
    """The stored body, re-validated and checked against its keys; None if it cannot be trusted."""
    try:
        proposal = repo.get_proposal(connection, row.proposal_id, row.proposal_version)
    except (ImmutableRecord, ValidationError):
        return None
    if proposal is None or proposal.action_digest != row.action_digest or (
            proposal.scope.workspace_id, proposal.scope.case_id, proposal.scope.run_id) != (
            row.workspace_id, row.case_id, row.run_id):
        return None
    return proposal


@dataclass
class ProposalService:
    app_engine: Engine
    clock: LeaseClock

    # -- internal writes ----------------------------------------------------------------------------------------

    def create_once(self, scope: GatewayScope, call: WriteToolCall, collected: Collected, *,
                    token: run_store.ClaimToken, step: int, evidence: Sequence[EvidenceRef] = (),
                    rationale: str) -> Prepared | ProposalRefused | Denied | Escalated:
        """Prepare and present atomically under the worker fence; reconcile the SAME run/step after uncertainty.

        Equality binds the request, not mutable facts or a new expiry. An original
        superseded/expired proposal is returned as-is and gains no authority.
        """
        checked_call, checked_evidence = _revalidated_call(call), _revalidated_evidence(evidence)
        rationale_text = checked_rationale(rationale)
        if checked_call is None or checked_evidence is None or rationale_text is None or (
                type(step) is not int or not 0 <= step <= 64):
            return _refused(ErrorCode.INVALID_INPUT, "proposal.input_invalid", "invalid preparation request")
        if (token.workspace_id, token.run_id) != (scope.run.workspace_id, scope.run.run_id):
            raise ValueError("proposal claim does not match scope")
        with workspace_transaction(self.app_engine, scope.run.workspace_id) as connection:
            created = self._create_tx(connection, scope, checked_call, collected, checked_evidence, rationale_text,
                                      creation_step=step, token=token)
            if not isinstance(created, Created):
                return created
            proposal = created.proposal
            record = repo.get_presentation(connection, proposal.proposal_id, proposal.proposal_version)
            if record is not None:
                message = repo.message_by_id(connection, CaseScope(workspace_id=scope.run.workspace_id,
                                                                   case_id=scope.run.case_id), record.message_id)
                if message is None or message.text != proposal.presentation.text:
                    raise ImmutableRecord("proposal replay presentation is invalid")
                return Prepared(proposal, record, message)
            presented = self._present_tx(connection, scope.run, proposal.proposal_id, proposal.proposal_version)
            if not isinstance(presented, Presented):
                # Fail the whole transaction: never commit a half-prepared intent.
                raise ImmutableRecord("proposal preparation could not present atomically")
            return Prepared(proposal, presented.record, presented.message)

    def create(self, scope: GatewayScope, call: WriteToolCall, collected: Collected, *,
               evidence: Sequence[EvidenceRef] = (), rationale: str) -> Created | ProposalRefused | Denied | Escalated:
        # Typed intake, before any transaction work: nothing invalid reaches the locks, a supersede or an insert.
        checked_call = _revalidated_call(call)
        checked_evidence = _revalidated_evidence(evidence)
        rationale_text = checked_rationale(rationale)
        if checked_call is None or checked_evidence is None or rationale_text is None:
            return _refused(ErrorCode.INVALID_INPUT, "proposal.input_invalid",
                            "the proposed call, evidence or rationale is invalid")
        with workspace_transaction(self.app_engine, scope.run.workspace_id) as connection:
            return self._create_tx(connection, scope, checked_call, collected, checked_evidence, rationale_text)

    def _create_tx(self, connection: Connection, scope: GatewayScope, checked_call: WriteToolCall,
                   collected: Collected, checked_evidence: tuple[EvidenceRef, ...], rationale_text: str, *,
                   creation_step: int | None = None, token: run_store.ClaimToken | None = None
                   ) -> Created | ProposalRefused | Denied | Escalated:
        run_scope = scope.run
        case = repo.lock_case(connection, run_scope.case_id)
        if case is None:
            return _refused(ErrorCode.NOT_FOUND, "proposal.case_not_found", "no such case")
        if case.customer_user_id is None or case.customer_user_id != scope.customer_user_id:
            return _refused(ErrorCode.CUSTOMER_MISMATCH, "scope.single_customer",
                            "the case is not bound to this customer")
        replay = (repo.proposal_creation(connection, run_scope.run_id, creation_step)
                  if creation_step is not None else None)
        if replay is None:
            status = evidence_status(connection, checked_evidence, run_id=run_scope.run_id)
            if status != "current":
                return _refused(ErrorCode.STALE_VERSION, f"evidence.{status}", "the cited evidence is not current")
        run = run_store.get_run(connection, run_scope.run_id, lock=True)
        if run is None or run.case_id != run_scope.case_id:
            return _refused(ErrorCode.NOT_FOUND, "proposal.run_not_found", "no such run in this case")
        if run.terminal:
            return _refused(ErrorCode.CONFLICT, "proposal.run_terminal", "the run has ended")
        request_sha256 = None
        if token is not None:
            fenced_run, job, _ = run_store.check_fence(connection, token, self.clock)
            if fenced_run.scope != scope.run or job.run_id != fenced_run.id:
                raise ValueError("proposal job does not match run")
            request_sha256 = hashlib.sha256(checkpoint_json.json_bytes({
                "scope": scope.run.model_dump(mode="json"), "binding": scope.binding.model_dump(mode="json"),
                "fixture_sha256": scope.fixture_sha256, "graph_sha256": run.graph_sha256,
                "prompt_sha256": run.prompt_sha256, "config_sha256": run.config_sha256,
                "action": checked_call.model_dump(mode="json"),
                "evidence": [ref.model_dump(mode="json") for ref in sorted(
                    checked_evidence, key=lambda ref: str(ref.evidence_id))],
                "rationale": rationale_text, "step": creation_step,
            })).hexdigest()
            if replay is not None:
                if replay.creation_request_sha256 != request_sha256:
                    raise IdempotencyConflict("proposal preparation request changed")
                original = _load_body(connection, replay)
                if original is None:
                    raise ImmutableRecord("proposal replay body is invalid")
                if repo.get_presentation(connection, original.proposal_id, original.proposal_version) is None:
                    raise ImmutableRecord("proposal replay has no atomic presentation")
                return Created(original, ())
        try:
            authentication = customer_authentications.load(connection, run_scope)
            session = CustomerSession(binding=scope.binding, run=run_scope, authentication=authentication)
        except (AuthenticationConflict, ValueError):
            return _refused(ErrorCode.CUSTOMER_MISMATCH, "scope.single_customer",
                            "the stored authentication does not match the bound customer")
        if authentication is None:
            return _refused(ErrorCode.CUSTOMER_NOT_AUTHENTICATED, "auth.lookup_required",
                            "the customer is not authenticated in this run")
        intent = intent_digest(run_scope, scope.customer_user_id, checked_call)
        active = repo.active_intent_rows(connection, case.id, intent)
        same_run = [row for row in active if row.run_id == run.id]
        if creation_step is not None:
            proposal_id = uuid5(PROPOSAL_NAMESPACE, f"{run_scope.workspace_id}:{run_scope.run_id}:{creation_step}")
            version = 1
        elif same_run:
            proposal_id = same_run[-1].proposal_id
            version = (repo.latest_proposal_version(connection, proposal_id) or 0) + 1
        else:
            proposal_id, version = uuid4(), 1
        now = self.clock.now(connection)  # after every lock this decision depends on
        try:
            sealed = propose(proposal_id=proposal_id, proposal_version=version, session=session,
                             call=checked_call, facts=collected.facts, evidence=checked_evidence,
                             rationale=rationale_text, now=now)
        except ValidationError:  # any remaining contract refusal: a fixed refusal, no raw data, nothing written
            return _refused(ErrorCode.INVALID_INPUT, "proposal.input_invalid",
                            "the proposal does not satisfy its contract")
        if not isinstance(sealed, ActionProposal):
            return sealed  # denied or escalated: nothing written
        if not presentable(sealed.presentation.text):  # before any supersede or insert
            return _refused(ErrorCode.POLICY_UNSUPPORTED, "presentation.message_limit",
                            "the exact confirmation text does not fit one case message")
        for row in active:
            repo.set_proposal_status(connection, row.workspace_id, row.proposal_id, row.proposal_version,
                                     "superseded")
            _audit(connection, workspace_id=row.workspace_id, actor_kind="worker", action="proposal.supersede",
                   target_id=row.row_id, before=row.action_digest, after=sealed.action_digest, now=now)
        row_id = uuid4()
        if creation_step is None:
            repo.insert_proposal(connection, row_id, sealed)
        else:
            repo.insert_proposal(connection, row_id, sealed, creation_step=creation_step,
                                 creation_request_sha256=request_sha256)
        _audit(connection, workspace_id=run_scope.workspace_id, actor_kind="worker", action="proposal.create",
               target_id=row_id, before=None, after=sealed.action_digest, now=now)
        return Created(sealed, tuple((row.proposal_id, row.proposal_version) for row in active))

    def present(self, run_scope: RunScope, proposal_id: UUID, proposal_version: int) -> Presented | ProposalRefused:
        with workspace_transaction(self.app_engine, run_scope.workspace_id) as connection:
            return self._present_tx(connection, run_scope, proposal_id, proposal_version)

    def _present_tx(self, connection: Connection, run_scope: RunScope, proposal_id: UUID,
                    proposal_version: int) -> Presented | ProposalRefused:
        case = repo.lock_case(connection, run_scope.case_id)
        run = run_store.get_run(connection, run_scope.run_id, lock=True)
        row = repo.proposal_row(connection, proposal_id, proposal_version, lock=True)
        if case is None or run is None or run.case_id != case.id or row is None or (
                row.case_id, row.run_id) != (case.id, run.id):
            return _refused(ErrorCode.NOT_FOUND, "proposal.not_found", "no such proposal in this run")
        if run.terminal:
            return _refused(ErrorCode.CONFLICT, "proposal.run_terminal", "the run has ended")
        if row.status != "created":
            return _refused(ErrorCode.CONFLICT, "proposal.not_presentable", "the proposal is not awaiting display")
        proposal = _load_body(connection, row)
        if proposal is None or proposal.scope != run_scope:
            return _refused(ErrorCode.INTERNAL, "proposal.record_invalid", "the stored proposal is not valid")
        now = self.clock.now(connection)
        if now >= proposal.expires_at:
            return _refused(ErrorCode.EXPIRED, "proposal.expired", "the proposal has expired")
        if not presentable(proposal.presentation.text):  # older or directly seeded bodies
            return _refused(ErrorCode.POLICY_UNSUPPORTED, "presentation.message_limit",
                            "the exact confirmation text does not fit one case message")
        message = repo.append_message(connection, message_id=uuid4(),
                                      scope=CaseScope(workspace_id=case.workspace_id, case_id=case.id),
                                      source="agent", entered_by=None, text_value=proposal.presentation.text,
                                      created_at=now)
        repo.bump_case_version(connection, case.id, now)
        record = ProposalPresentationRecord(
            scope=run_scope, proposal_id=proposal.proposal_id, proposal_version=proposal.proposal_version,
            action_digest=proposal.action_digest, presentation_sha256=proposal.presentation.text_sha256,
            message_id=message.message_id, message_sequence=message.sequence, presented_at=now)
        repo.mark_presented(connection, record)
        run_store.append_event(connection, run, MessagePosted(message_id=message.message_id,
                                                              message_sequence=message.sequence, source="agent"),
                               now)
        run_store.append_event(connection, run, ProposalPresented(
            proposal_id=proposal.proposal_id, proposal_version=proposal.proposal_version,
            action_digest=proposal.action_digest, expires_at=proposal.expires_at), now)
        _audit(connection, workspace_id=run_scope.workspace_id, actor_kind="worker", action="proposal.present",
               target_id=row.row_id, before=None, after=proposal.presentation.text_sha256, now=now)
        return Presented(record, message)

    def record_customer_reply(self, run_scope: RunScope, message_id: UUID, *,
                              simulator_event: SimulatorConfirmationEvent | None = None
                              ) -> ConsentOutcome | ProposalRefused:
        """Classify one persisted customer message against the run's single presented proposal. Only an explicit
        affirmation (or the simulator's constrained confirmation for this exact version) becomes consent."""
        with workspace_transaction(self.app_engine, run_scope.workspace_id) as connection:
            run = run_store.get_run(connection, run_scope.run_id, lock=True)
            if run is None or run.case_id != run_scope.case_id:
                return _refused(ErrorCode.NOT_FOUND, "proposal.run_not_found", "no such run in this case")
            if run.terminal:
                return _refused(ErrorCode.CONFLICT, "proposal.run_terminal", "the run has ended")
            rows = repo.presented_rows_of_run(connection, run.id)
            if len(rows) != 1:
                return NotConsent("there is no single presented proposal in this run")
            row = rows[0]
            proposal = _load_body(connection, row)
            presentation = repo.get_presentation(connection, row.proposal_id, row.proposal_version)
            message = repo.message_by_id(connection, CaseScope(workspace_id=run_scope.workspace_id,
                                                               case_id=run_scope.case_id), message_id)
            if proposal is None or presentation is None or proposal.scope != run_scope:
                return _refused(ErrorCode.INTERNAL, "proposal.record_invalid", "the stored proposal is not valid")
            if message is None:
                return NotConsent("no such message in this case")
            if repo.get_consent(connection, row.proposal_id, row.proposal_version) is not None:
                return NotConsent("this proposal version already has a consent")
            now = self.clock.now(connection)
            if simulator_event is None:
                outcome = record_reply(consent_id=uuid4(), proposal=proposal, presentation=presentation,
                                       message=message, now=now)
            else:
                outcome = record_simulator_event(consent_id=uuid4(), proposal=proposal, presentation=presentation,
                                                 message=message, event=simulator_event, now=now)
            if isinstance(outcome, Consented):
                repo.record_consent(connection, outcome.consent)
                run_store.append_event(connection, run, ConsentRecorded(
                    consent_id=outcome.consent.consent_id, proposal_id=proposal.proposal_id,
                    action_digest=proposal.action_digest), now)
                _audit(connection, workspace_id=run_scope.workspace_id, actor_kind="system", action="consent.record",
                       target_id=row.row_id, before=None, after=outcome.consent.customer_message_sha256, now=now)
            elif isinstance(outcome, AskAgain):
                run_store.append_event(connection, run, ClarificationRequested(
                    proposal_id=proposal.proposal_id, reason=outcome.reason), now)  # type: ignore[arg-type]
        return outcome

    # -- reviewer reads (callers authorize first: `require_action`) ---------------------------------------------

    def _state(self, connection: Connection, row: ProposalRow, now: datetime) -> str:
        presentation = repo.get_presentation(connection, row.proposal_id, row.proposal_version)
        consent = repo.get_consent(connection, row.proposal_id, row.proposal_version)
        decision = repo.get_decision(connection, row.proposal_id, row.proposal_version)
        return review_state(row_status=row.status, presented=presentation is not None, consent=consent,
                            decision=decision, expires_at=row.expires_at, now=now)

    def _page(self, connection: Connection, rows: list[ProposalRow], *, limit: int, workspace_id: UUID,
              list_key: str, now: datetime, states: bool) -> ProposalPage:
        page, more = rows[:limit], len(rows) > limit
        items = []
        for row in page:
            proposal = _load_body(connection, row)
            if proposal is None:
                raise AuthError(500, ErrorCode.INTERNAL, "A stored proposal is not valid.", "api.proposal_invalid")
            state = self._state(connection, row, now) if states else "awaiting_decision"
            items.append(summary_view(row, proposal, state))  # type: ignore[arg-type]
        next_cursor = encode_cursor(ProposalCursor(w=workspace_id, lst=list_key, c=page[-1].created_at,
                                                   i=page[-1].row_id)) if more else None
        return ProposalPage(items=items, next_cursor=next_cursor)

    def inbox(self, authorized: Authorized, *, cursor: str | None, limit: int) -> ProposalPage:
        """Presented versions awaiting a decision, with a consent current now. Reviewer-only (the route requires
        DECIDE_PROPOSAL)."""
        if not 1 <= limit <= MAX_PROPOSAL_PAGE:
            raise invalid(f"limit must be between 1 and {MAX_PROPOSAL_PAGE}.", "api.invalid_limit")
        after = decode_cursor(cursor, authorized.workspace_id, "inbox") if cursor is not None else None
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            now = self.clock.now(connection)
            rows = repo.inbox_page(connection, now=now, after=after, limit=limit + 1)
            return self._page(connection, rows, limit=limit, workspace_id=authorized.workspace_id, list_key="inbox",
                              now=now, states=False)

    def case_proposals(self, authorized: Authorized, case_id: UUID, *, cursor: str | None,
                       limit: int) -> ProposalPage:
        """Every version in the case (the bounded, paginated history; the detail view returns one version)."""
        if not 1 <= limit <= MAX_PROPOSAL_PAGE:
            raise invalid(f"limit must be between 1 and {MAX_PROPOSAL_PAGE}.", "api.invalid_limit")
        key = case_list_key(case_id)
        after = decode_cursor(cursor, authorized.workspace_id, key) if cursor is not None else None
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            if repo.get_case(connection, case_id) is None:
                raise not_found()
            now = self.clock.now(connection)
            rows = repo.case_proposal_page(connection, case_id, after=after, limit=limit + 1)
            return self._page(connection, rows, limit=limit, workspace_id=authorized.workspace_id, list_key=key,
                              now=now, states=True)

    def detail(self, authorized: Authorized, proposal_id: UUID, version: int | None) -> ProposalDetailView:
        """One version (the latest, or `version`), exactly as sealed, with its records and derived state."""
        with workspace_transaction(self.app_engine, authorized.workspace_id) as connection:
            selected = version if version is not None else repo.latest_proposal_version(connection, proposal_id)
            row = repo.proposal_row(connection, proposal_id, selected) if selected is not None else None
            if row is None:
                raise not_found("proposal")
            proposal = _load_body(connection, row)
            if proposal is None:
                raise AuthError(500, ErrorCode.INTERNAL, "A stored proposal is not valid.", "api.proposal_invalid")
            presentation = repo.get_presentation(connection, row.proposal_id, row.proposal_version)
            consent = repo.get_consent(connection, row.proposal_id, row.proposal_version)
            decision = repo.get_decision(connection, row.proposal_id, row.proposal_version)
            consent_message = None if consent is None else repo.message_by_id(
                connection, CaseScope(workspace_id=row.workspace_id, case_id=row.case_id),
                consent.customer_message_id)
            now = self.clock.now(connection)
            return detail_view(row=row, proposal=proposal, presentation=presentation, consent=consent,
                               consent_message=consent_message, decision=decision, now=now)
