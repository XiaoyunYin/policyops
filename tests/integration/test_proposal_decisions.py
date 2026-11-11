"""T18 proposals and decisions on real PostgreSQL, as the actual app/auth runtime roles (RLS active).

Covers the service transactions: create/supersede/present/consent/decide, the single terminal decision under
concurrent reviewers, identical replays, membership revocation ordering, a replay needing the current reviewer role,
ended/superseded/expired/forged/unpresented refusals, a new version racing a decision, a changed policy pin (simulated
by a test-only patch), an expired consent (seeded with a shorter window) leaving the inbox, separation of duties,
tenant isolation, the presentation message bound at create and at present, a tampered stored body, the production
`PgDecisionStore`/`PgEvidencePort` inside the T17 precheck (current approval clears; a superseded version or changed
retail facts do not), and that nothing here executes a business mutation. Evidence: `test_proposal_evidence.py`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import threading
from typing import Any
from uuid import UUID, uuid4

import pytest

from policyops.auth.service import AuthError, Authorized, SessionContext
from policyops.domain.consent_rules import AskAgain, Consented
from policyops.domain.examples import World
from policyops.gateway.facts import Collected, collect
from policyops.gateway.ports import GatewayScope, IncompleteHistory, PgMembership, PgSessionStore, load_scope
from policyops.gateway.precheck import AuthorityRefs, Cleared, PrecheckRefused, precheck
from policyops.gateway.stores import PgDecisionStore, PgEvidencePort
from policyops.persistence import customer_authentications as auth_rows
from policyops.persistence import repositories as repo
from policyops.persistence import runs as run_store
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, NewCase, NewRun, Principal, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.runtime.clock import FixedLeaseClock
from policyops.services.decisions import DecisionResult, DecisionService
from policyops.services.proposal_views import DecisionRequest
from policyops.services.proposals import Created, Presented, ProposalRefused, ProposalService
from policyops_contracts.clock import FixedClock
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.proposal import ActionProposal, EvidenceRef
from policyops_contracts.retail import CancelPendingOrder, ModifyPendingOrderItems
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication
from policyops_testing.app_database import AppDatabase
from policyops_testing.gateway_cases import FakeRetail, state


pytestmark = pytest.mark.postgres
W = World()
START = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
CANCEL = CancelPendingOrder(order_id=W.order_id, reason="no longer needed")


@dataclass
class Tenant:
    db: AppDatabase
    clock: FixedClock
    scope: GatewayScope
    reviewer: UUID
    second_reviewer: UUID
    analyst: UUID
    memberships: dict[UUID, UUID]

    @property
    def run(self) -> RunScope:
        return self.scope.run

    @property
    def engine(self) -> Any:
        return self.db.engine(APP_RUNTIME, pool_size=6)

    def proposals(self) -> ProposalService:
        return ProposalService(app_engine=self.engine, clock=FixedLeaseClock(self.clock))

    def decisions(self) -> DecisionService:
        return DecisionService(app_engine=self.engine, clock=FixedLeaseClock(self.clock))

    def authorized(self, principal: UUID, roles: tuple[str, ...] = ("reviewer",),
                   workspace: UUID | None = None) -> Authorized:
        workspace_id = workspace or self.run.workspace_id
        session = SessionContext(session_id=uuid4(), principal_id=principal, workspace_id=workspace_id,
                                 expires_at=self.clock.now() + timedelta(hours=1), csrf_sha256="0" * 64)
        return Authorized(session=session, workspace_id=workspace_id, roles=frozenset(roles))  # type: ignore[arg-type]

    def value(self, sql: str, *params: Any) -> Any:
        with self.db.superuser() as conn:  # inspection only (bypasses RLS)
            return conn.execute(sql, params).fetchone()[0]

    def count(self, sql: str, *params: Any) -> int:
        return int(self.value(sql, *params))


def principal(db: AppDatabase, label: str) -> UUID:
    principal_id = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_principal(conn, Principal(id=principal_id, issuer="https://issuer.example.invalid",
                                              subject=f"{label}-{principal_id.hex[:8]}", display_name=label.title(),
                                              created_at=START))
    return principal_id


def grant(db: AppDatabase, workspace: UUID, principal_id: UUID, role: str) -> UUID:
    membership = Membership(id=uuid4(), workspace_id=workspace, principal_id=principal_id, role=role,  # type: ignore[arg-type]
                            created_at=START)
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.add_membership(conn, membership)
    return membership.id


def tenant(db: AppDatabase) -> Tenant:
    workspace = uuid4()
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        repo.create_workspace(conn, Workspace(id=workspace, slug=f"t18-{workspace.hex[:12]}", name="T18 test",
                                              created_at=START))
    case, run = uuid4(), uuid4()
    with workspace_transaction(db.engine(APP_RUNTIME), workspace) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=workspace, scenario="retail",
                                                customer_user_id=W.user_id, created_by=None, created_at=START))
        repo.create_run(conn, NewRun(id=run, workspace_id=workspace, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=START + timedelta(hours=2),
                                     created_at=START))
        run_scope = RunScope(workspace_id=workspace, case_id=case, run_id=run)
        auth_rows.record(conn, CustomerAuthentication(
            scope=run_scope, user_id=W.user_id, lookup_tool="find_user_id_by_email",
            lookup_call_sha256=hashlib.sha256(str(run).encode()).hexdigest(), step_sequence=1,
            authenticated_at=START))
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=workspace, case_id=case), seed_id="retail-demo-9999",
                                  user_id=W.user_id, bound_at=START)
    scope = load_scope(db.engine(APP_RUNTIME), workspace_id=workspace, run_id=run, binding=binding,
                       fixture_sha256=FIXTURE_SHA256)
    reviewer, second, analyst = principal(db, "reviewer"), principal(db, "second"), principal(db, "analyst")
    memberships = {reviewer: grant(db, workspace, reviewer, "reviewer"),
                   second: grant(db, workspace, second, "reviewer"),
                   analyst: grant(db, workspace, analyst, "analyst")}
    return Tenant(db, FixedClock(START + timedelta(minutes=1)), scope, reviewer, second, analyst, memberships)


def retail(t: Tenant) -> FakeRetail:
    return FakeRetail(state(), tenant_id=t.run.workspace_id, case_id=t.run.case_id, customer_id=W.user_id)


def facts_for(t: Tenant, call: Any = CANCEL) -> Collected:
    collected = collect(retail(t), t.scope, call, IncompleteHistory())
    assert isinstance(collected, Collected)
    return collected


def created(t: Tenant, call: Any = CANCEL, collected: Collected | None = None) -> ActionProposal:
    result = t.proposals().create(t.scope, call, collected or facts_for(t, call), rationale="Customer asked.")
    assert isinstance(result, Created), result
    return result.proposal


def customer_says(t: Tenant, text_value: str, *, source: str = "simulated_customer",
                  entered_by: UUID | None = None) -> UUID:
    t.clock.advance(timedelta(seconds=1))
    with workspace_transaction(t.engine, t.run.workspace_id) as conn:
        message = repo.append_message(conn, message_id=uuid4(), scope=CaseScope(workspace_id=t.run.workspace_id,
                                                                                 case_id=t.run.case_id),
                                      source=source, entered_by=entered_by, text_value=text_value,  # type: ignore[arg-type]
                                      created_at=t.clock.now())
    return message.message_id


def consented(t: Tenant, *, entered_by: UUID | None = None) -> ActionProposal:
    proposal = created(t)
    t.clock.advance(timedelta(seconds=1))
    assert isinstance(t.proposals().present(t.run, proposal.proposal_id, proposal.proposal_version), Presented)
    source = "operator_entered_customer" if entered_by is not None else "simulated_customer"
    message = customer_says(t, "yes", source=source, entered_by=entered_by)
    t.clock.advance(timedelta(seconds=1))
    assert isinstance(t.proposals().record_customer_reply(t.run, message), Consented)
    return proposal


def ask(proposal: ActionProposal, **overrides: Any) -> DecisionRequest:
    return DecisionRequest.model_validate({"proposal_version": proposal.proposal_version,
                                           "action_digest": proposal.action_digest, "decision": "approve",
                                           "reason": "Order and policy checked.", **overrides})


def refused(call: Callable[[], Any]) -> tuple[int, str]:
    with pytest.raises(AuthError) as error:
        call()
    return error.value.status, error.value.rule_id


COUNTED = {"decisions": "app.approval_decisions", "consents": "app.customer_consents",
           "proposals": "app.action_proposals", "messages": "app.case_messages",
           "executions": "app.tool_executions", "events": "app.run_events", "audit": "app.audit_events"}


def counts(t: Tenant) -> dict[str, int]:
    """Row counts in the tenant's workspace, as superuser (what the services did not write is checked directly)."""
    w = t.run.workspace_id
    return {name: t.count(f"SELECT count(*) FROM {table} WHERE workspace_id = %s", w)  # noqa: S608 - fixed names
            for name, table in COUNTED.items()}


@pytest.fixture
def t(shared_db: AppDatabase) -> Tenant:
    return tenant(shared_db)


# -- the end-to-end path and the T17 precheck -------------------------------------------------------------------

def test_a_consented_presented_proposal_is_decided_once_and_clears_the_precheck(t: Tenant) -> None:
    proposal = consented(t)
    before = counts(t)
    t.clock.advance(timedelta(seconds=1))
    result = t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal))
    assert isinstance(result, DecisionResult) and not result.replayed
    after = counts(t)
    assert after["decisions"] == before["decisions"] + 1
    assert after["events"] == before["events"] + 1 and after["audit"] == before["audit"] + 1
    assert after["executions"] == 0  # nothing is executed in T18
    store = PgDecisionStore(t.engine)
    assert store.proposal(t.run, proposal.proposal_id, 1) == proposal
    consent = store.consent(t.run, result.decision.consent_id)
    assert consent is not None and store.approval(t.run, result.decision.approval_id) == result.decision
    fake = retail(t)
    cleared = precheck(t.scope, AuthorityRefs(proposal.proposal_id, 1, consent.consent_id,
                                              result.decision.approval_id),
                       retail=fake, sessions=PgSessionStore(t.engine), membership=PgMembership(t.engine),
                       clock=t.clock, decisions=store, evidence=PgEvidencePort(t.engine))
    assert isinstance(cleared, Cleared)
    assert all(type(call).__name__.startswith(("Get", "Find")) for call in fake.calls)  # reads only, no mutation
    assert counts(t)["executions"] == 0


def test_a_superseded_or_stale_approval_never_clears(t: Tenant) -> None:
    proposal = consented(t)
    t.clock.advance(timedelta(seconds=1))
    decision = t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal)).decision
    refs = AuthorityRefs(proposal.proposal_id, 1, decision.consent_id, decision.approval_id)

    def check(fake: FakeRetail) -> Cleared | PrecheckRefused:
        return precheck(t.scope, refs, retail=fake, sessions=PgSessionStore(t.engine),
                        membership=PgMembership(t.engine), clock=t.clock, decisions=PgDecisionStore(t.engine))

    changed = retail(t)
    changed.state.order = changed.state.order.model_copy(update={"version": changed.state.order.version + 1})
    stale = check(changed)
    assert isinstance(stale, PrecheckRefused) and stale.code is ErrorCode.STALE_VERSION
    newer = created(t)  # the same intent in the same run: a new version supersedes the approved one
    assert (newer.proposal_id, newer.proposal_version) == (proposal.proposal_id, 2)
    assert PgDecisionStore(t.engine).proposal(t.run, proposal.proposal_id, 1) is None
    gone = check(retail(t))
    assert isinstance(gone, PrecheckRefused) and gone.detail == "proposal_not_found"
    status = t.count("SELECT count(*) FROM app.action_proposals WHERE workspace_id = %s AND proposal_version = 1 "
                     "AND status = 'superseded'", t.run.workspace_id)
    assert status == 1


# -- concurrency and replay ---------------------------------------------------------------------------------------

def race(*calls: Callable[[], Any]) -> list[Any]:
    barrier = threading.Barrier(len(calls))
    results: list[Any] = [None] * len(calls)

    def worker(index: int, call: Callable[[], Any]) -> None:
        barrier.wait()
        try:
            results[index] = call()
        except AuthError as error:
            results[index] = error

    threads = [threading.Thread(target=worker, args=(i, call)) for i, call in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()
    return results


@pytest.mark.parametrize("round_", range(5))
def test_two_simultaneous_reviewers_produce_exactly_one_decision(shared_db: AppDatabase, round_: int) -> None:
    t = tenant(shared_db)
    proposal = consented(t)
    t.clock.advance(timedelta(seconds=1))
    service = t.decisions()
    results = race(lambda: service.decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal)),
                   lambda: service.decide(t.authorized(t.second_reviewer), proposal.proposal_id, ask(proposal)))
    winners = [r for r in results if isinstance(r, DecisionResult)]
    losers = [r for r in results if isinstance(r, AuthError)]
    assert len(winners) == 1 and len(losers) == 1
    assert (losers[0].status, losers[0].rule_id) == (409, "api.proposal_already_decided")
    assert counts(t)["decisions"] == 1
    assert t.count("SELECT count(*) FROM app.audit_events WHERE workspace_id = %s AND action = 'proposal.decide'",
                   t.run.workspace_id) == 1


def test_the_same_reviewer_double_submitting_gets_one_decision_and_identical_replays(t: Tenant) -> None:
    proposal = consented(t)
    t.clock.advance(timedelta(seconds=1))
    service = t.decisions()
    results = race(*(lambda: service.decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal))
                     for _ in range(3)))
    assert all(isinstance(r, DecisionResult) for r in results)
    assert sorted(r.replayed for r in results) == [False, True, True]
    assert len({r.decision.model_dump_json() for r in results}) == 1
    assert counts(t)["decisions"] == 1
    # Later replays return the original even after the run ended (new decisions would be refused).
    with workspace_transaction(t.engine, t.run.workspace_id) as conn:
        run = run_store.get_run(conn, t.run.run_id, lock=True)
        assert run is not None
        run_store.set_state(conn, run, "cancelled", t.clock.now(), bump_generation=True)
    replay = service.decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal))
    assert replay.replayed and replay.decision == results[0].decision


def test_a_revocation_committed_first_refuses_the_decision_even_while_it_waits(t: Tenant) -> None:
    proposal = consented(t)
    t.clock.advance(timedelta(seconds=1))
    revoker = t.db.engine(AUTH_RUNTIME).connect()
    try:
        transaction_ = revoker.begin()
        assert repo.revoke_membership(revoker, t.memberships[t.reviewer], t.clock.now())  # holds the row lock
        outcome: list[Any] = []
        thread = threading.Thread(target=lambda: outcome.append(refused(lambda: t.decisions().decide(
            t.authorized(t.reviewer), proposal.proposal_id, ask(proposal)))))
        thread.start()
        thread.join(timeout=2)
        assert thread.is_alive()  # waiting on FOR SHARE behind the uncommitted revocation
        transaction_.commit()
        thread.join(timeout=30)
        assert outcome == [(403, "auth.membership")]
    finally:
        revoker.close()
    assert counts(t)["decisions"] == 0


# -- refusals -----------------------------------------------------------------------------------------------------

def test_new_decisions_are_refused_with_stable_codes_and_no_writes(t: Tenant) -> None:
    proposal = consented(t)
    service = t.decisions()
    reviewer = t.authorized(t.reviewer)
    before = counts(t)
    assert refused(lambda: service.decide(reviewer, proposal.proposal_id,
                                          ask(proposal, action_digest="0" * 64))) == (409,
                                                                                      "api.proposal_digest_mismatch")
    assert refused(lambda: service.decide(t.authorized(t.analyst, ("analyst",)), proposal.proposal_id,
                                          ask(proposal))) == (403, "auth.role")
    assert refused(lambda: service.decide(reviewer, uuid4(), ask(proposal))) == (404, "api.proposal_not_found")
    assert refused(lambda: service.decide(reviewer, proposal.proposal_id, ask(proposal, proposal_version=2))) == (
        404, "api.proposal_not_found")
    t.clock.advance(timedelta(minutes=16))
    assert refused(lambda: service.decide(reviewer, proposal.proposal_id, ask(proposal))) == (409,
                                                                                            "api.proposal_expired")
    assert counts(t) == before


def test_an_unpresented_or_unconsented_proposal_cannot_be_decided(t: Tenant) -> None:
    proposal = created(t)
    service, reviewer = t.decisions(), t.authorized(t.reviewer)
    assert refused(lambda: service.decide(reviewer, proposal.proposal_id, ask(proposal))) == (
        409, "api.proposal_not_presented")
    t.clock.advance(timedelta(seconds=1))
    t.proposals().present(t.run, proposal.proposal_id, 1)
    for kind in ("approve", "reject"):
        assert refused(lambda kind=kind: service.decide(reviewer, proposal.proposal_id,  # type: ignore[misc]
                                                        ask(proposal, decision=kind))) == (409, "api.consent_required")
    unclear = customer_says(t, "yes but change the address first")
    assert isinstance(t.proposals().record_customer_reply(t.run, unclear), AskAgain)
    assert counts(t)["consents"] == 0


def test_the_operator_who_typed_the_consent_cannot_approve_it(t: Tenant) -> None:
    proposal = consented(t, entered_by=t.reviewer)
    t.clock.advance(timedelta(seconds=1))
    assert refused(lambda: t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal))) == (
        403, "api.separation_of_duties")
    assert not t.decisions().decide(t.authorized(t.second_reviewer), proposal.proposal_id, ask(proposal)).replayed


def test_another_tenant_cannot_see_or_decide(shared_db: AppDatabase, t: Tenant) -> None:
    proposal = consented(t)
    other = tenant(shared_db)
    foreign = other.authorized(other.reviewer)
    assert refused(lambda: other.decisions().decide(foreign, proposal.proposal_id, ask(proposal))) == (
        404, "api.proposal_not_found")
    assert refused(lambda: other.proposals().detail(foreign, proposal.proposal_id, None)) == (
        404, "api.proposal_not_found")
    assert other.proposals().inbox(foreign, cursor=None, limit=100).items == []
    assert refused(lambda: other.proposals().case_proposals(foreign, t.run.case_id, cursor=None, limit=10)) == (
        404, "api.case_not_found")
    mine = t.proposals().inbox(t.authorized(t.reviewer), cursor=None, limit=100)
    assert [item.proposal_id for item in mine.items] == [proposal.proposal_id]


# -- the presentation message bound, stored body integrity, evidence --------------------------------------------

def long_items(t: Tenant) -> tuple[ModifyPendingOrderItems, Collected]:
    lines = (W.item_a,) * 50
    call = ModifyPendingOrderItems(order_id=W.order_id, item_ids=lines, new_item_ids=(W.item_c,) * 50,
                                   payment_method_id=W.card)
    facts = W.facts(order=W.order(items=lines))  # coherent fictional facts with a test-only complete history
    return call, Collected(facts=facts, case_version=5, resource_versions=(), collections=1, reads=3)


def test_an_unpresentable_proposal_is_refused_before_any_supersede_or_insert(t: Tenant) -> None:
    short = ModifyPendingOrderItems(order_id=W.order_id, item_ids=(W.item_a,), new_item_ids=(W.item_c,),
                                    payment_method_id=W.card)
    first = created(t, short, Collected(facts=W.facts(), case_version=5, resource_versions=(), collections=1,
                                        reads=3))
    before = counts(t)
    call, collected = long_items(t)
    result = t.proposals().create(t.scope, call, collected, rationale="Customer asked.")
    assert isinstance(result, ProposalRefused) and result.rule_id == "presentation.message_limit"
    assert counts(t) == before
    status = t.value("SELECT status FROM app.action_proposals WHERE workspace_id = %s AND proposal_id = %s "
                     "AND proposal_version = 1", t.run.workspace_id, first.proposal_id)
    assert status == "created"  # not superseded by the refused create


def test_presenting_an_oversized_stored_body_is_refused_without_a_message(t: Tenant) -> None:
    from policyops.domain.retail_rules import propose
    from policyops.domain.session import CustomerSession

    call, collected = long_items(t)
    with workspace_transaction(t.engine, t.run.workspace_id) as conn:
        session = CustomerSession(binding=t.scope.binding, run=t.run,
                                  authentication=auth_rows.load(conn, t.run))
        sealed = propose(proposal_id=uuid4(), proposal_version=1, session=session, call=call,
                         facts=collected.facts, evidence=(), rationale="Seeded directly.", now=t.clock.now())
        assert isinstance(sealed, ActionProposal)
        repo.insert_proposal(conn, uuid4(), sealed)  # a direct seed, bypassing create's guard
    before = counts(t)
    result = t.proposals().present(t.run, sealed.proposal_id, 1)
    assert isinstance(result, ProposalRefused) and result.rule_id == "presentation.message_limit"
    assert counts(t) == before


def test_unknown_evidence_is_refused_at_create_with_no_writes(t: Tenant) -> None:
    before = counts(t)
    ref = EvidenceRef(evidence_id=uuid4(), document_version_id=uuid4(), content_sha256="a" * 64)
    result = t.proposals().create(t.scope, CANCEL, facts_for(t), evidence=(ref,), rationale="Customer asked.")
    assert isinstance(result, ProposalRefused) and result.rule_id == "evidence.stale_evidence"
    assert counts(t) == before
    assert PgEvidencePort(t.engine).is_current(t.run.workspace_id, ref) is False


def test_a_tampered_stored_body_is_never_authority(new_app_database: Callable[..., AppDatabase]) -> None:
    db = new_app_database("t18_tamper")
    t = tenant(db)
    proposal = consented(t)
    with db.superuser() as conn:  # an owner-level change the runtime trigger would refuse
        conn.execute("ALTER TABLE app.action_proposals DISABLE TRIGGER action_proposals_guard")
        conn.execute("UPDATE app.action_proposals SET body = jsonb_set(body, '{rationale}', '\"tampered\"') "
                     "WHERE workspace_id = %s", (t.run.workspace_id,))
        conn.execute("ALTER TABLE app.action_proposals ENABLE TRIGGER action_proposals_guard")
    assert PgDecisionStore(t.engine).proposal(t.run, proposal.proposal_id, 1) is None
    t.clock.advance(timedelta(seconds=1))
    assert refused(lambda: t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal))) == (
        500, "api.proposal_invalid")
    assert counts(t)["decisions"] == 0


# -- supersede against a decision, current roles at replay, policy and consent changes ---------------------------

def test_a_new_version_racing_a_decision_never_leaves_authority_on_the_old_version(shared_db: AppDatabase) -> None:
    t = tenant(shared_db)
    proposal = consented(t)
    t.clock.advance(timedelta(seconds=1))
    collected = facts_for(t)
    results = race(lambda: t.proposals().create(t.scope, CANCEL, collected, rationale="Customer asked again."),
                   lambda: t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal)))
    newer, decided = results
    assert isinstance(newer, Created) and newer.superseded == ((proposal.proposal_id, 1),)
    if isinstance(decided, AuthError):  # the new version committed first: the old one cannot be decided
        assert (decided.status, decided.rule_id) == (409, "api.proposal_superseded")
        assert counts(t)["decisions"] == 0
    else:  # the decision committed first: it stays on record, but the superseded version is never authority
        assert isinstance(decided, DecisionResult) and counts(t)["decisions"] == 1
        refs = AuthorityRefs(proposal.proposal_id, 1, decided.decision.consent_id, decided.decision.approval_id)
        gone = precheck(t.scope, refs, retail=retail(t), sessions=PgSessionStore(t.engine),
                        membership=PgMembership(t.engine), clock=t.clock, decisions=PgDecisionStore(t.engine))
        assert isinstance(gone, PrecheckRefused) and gone.detail == "proposal_not_found"
    assert PgDecisionStore(t.engine).proposal(t.run, proposal.proposal_id, 1) is None
    assert t.value("SELECT status FROM app.action_proposals WHERE workspace_id = %s AND proposal_version = 1",
                   t.run.workspace_id) == "superseded"
    # The deterministic serialization of the first branch, for its stable code: supersede, then decide.
    s = tenant(shared_db)
    old = consented(s)
    created(s)
    assert refused(lambda: s.decisions().decide(s.authorized(s.reviewer), old.proposal_id, ask(old))) == (
        409, "api.proposal_superseded")
    assert counts(s)["decisions"] == 0 and counts(t)["executions"] == counts(s)["executions"] == 0


def test_a_replay_needs_the_current_reviewer_role(t: Tenant) -> None:
    proposal = consented(t)
    t.clock.advance(timedelta(seconds=1))
    service, session = t.decisions(), t.authorized(t.reviewer)  # the session still claims the reviewer role
    original = service.decide(session, proposal.proposal_id, ask(proposal)).decision
    with transaction(t.db.engine(AUTH_RUNTIME)) as conn:
        assert repo.revoke_membership(conn, t.memberships[t.reviewer], t.clock.now())
    assert refused(lambda: service.decide(session, proposal.proposal_id, ask(proposal))) == (403, "auth.membership")
    grant(t.db, t.run.workspace_id, t.reviewer, "analyst")  # back in the workspace, without the reviewer role
    assert refused(lambda: service.decide(session, proposal.proposal_id, ask(proposal))) == (403, "auth.role")
    assert counts(t)["decisions"] == 1
    assert PgDecisionStore(t.engine).approval(t.run, original.approval_id) == original  # the record is unchanged


def test_a_policy_change_after_sealing_refuses_new_decisions(t: Tenant, monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulated deployment of a newer retail policy (test-only patch of the decision service's pinned policy)."""
    from policyops.services import decisions as decisions_module
    from policyops_contracts.policy import RETAIL_POLICY

    proposal = consented(t)
    assert proposal.policy == RETAIL_POLICY
    t.clock.advance(timedelta(seconds=1))
    monkeypatch.setattr(decisions_module, "RETAIL_POLICY", RETAIL_POLICY.model_copy(update={"sha256": "f" * 64}))
    before = counts(t)
    assert refused(lambda: t.decisions().decide(t.authorized(t.reviewer), proposal.proposal_id, ask(proposal))) == (
        409, "api.policy_changed")
    assert counts(t) == before


def test_an_expired_consent_is_refused_and_leaves_the_inbox(t: Tenant) -> None:
    """A consent with a shorter window than its proposal (seeded directly: through `record_customer_reply` both
    windows end together, and the proposal's expiry is checked first)."""
    from policyops.domain.consent_rules import record_reply
    from policyops_contracts.consent import CustomerConsent

    proposal = created(t)
    t.clock.advance(timedelta(seconds=1))
    assert isinstance(t.proposals().present(t.run, proposal.proposal_id, 1), Presented)
    message_id = customer_says(t, "yes")
    case_scope = CaseScope(workspace_id=t.run.workspace_id, case_id=t.run.case_id)
    with workspace_transaction(t.engine, t.run.workspace_id) as conn:
        presentation = repo.get_presentation(conn, proposal.proposal_id, 1)
        message = repo.message_by_id(conn, case_scope, message_id)
        assert presentation is not None and message is not None
        outcome = record_reply(consent_id=uuid4(), proposal=proposal, presentation=presentation, message=message,
                               now=t.clock.now())
        assert isinstance(outcome, Consented)
        short = CustomerConsent.model_validate({**outcome.consent.model_dump(),
                                                "expires_at": t.clock.now() + timedelta(minutes=2)})
        repo.record_consent(conn, short)
    reviewer = t.authorized(t.reviewer)
    inbox = t.proposals().inbox(reviewer, cursor=None, limit=10)
    assert [item.proposal_id for item in inbox.items] == [proposal.proposal_id]
    t.clock.advance(timedelta(minutes=3))  # the consent has expired; the proposal has not
    assert t.clock.now() < proposal.expires_at
    assert t.proposals().inbox(reviewer, cursor=None, limit=10).items == []
    before = counts(t)
    assert refused(lambda: t.decisions().decide(reviewer, proposal.proposal_id, ask(proposal))) == (
        409, "api.consent_expired")
    assert counts(t) == before
