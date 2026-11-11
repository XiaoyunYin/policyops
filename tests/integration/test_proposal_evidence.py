"""T18 proposal evidence on real PostgreSQL, with real T12 publication and real T14 citations, as the app runtime.

Citations are produced the accepted way (T13 retrieval trace -> T14 validation -> `CitationRecorder`) for a run whose
case is bound to a fictional customer, then cited by `ProposalService.create`. Covers: current evidence creating a
proposal that clears the T17 precheck through `PgEvidencePort`; a later activation retiring it (precheck and new
creation refuse); another run's citation, a wrong whole-version digest or document version; both orderings of a real
publication against creation's corpus SHARE lock; sorted multi-corpus locking; and contradictory states (refused, never
resolved). Every refusal writes nothing. Synthetic text and vectors only; no provider HTTP.

Not claimed: the truth of the cited text, currency after the checking statement, or interruption of a lock wait.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Connection

from policyops.auth.service import Authorized, SessionContext
from policyops.domain.consent_rules import Consented
from policyops.domain.examples import World as RetailWorld
from policyops.gateway.facts import Collected, collect
from policyops.gateway.ports import GatewayScope, IncompleteHistory, PgMembership, PgSessionStore, load_scope
from policyops.gateway.precheck import AuthorityRefs, Cleared, PrecheckRefused, precheck
from policyops.gateway.stores import PgDecisionStore, PgEvidencePort
from policyops.persistence import customer_authentications as auth_rows
from policyops.persistence import repositories as repo
from policyops.persistence.citations import CitationRecorder
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, NewCase, NewRun, Principal
from policyops.persistence.roles import AUTH_RUNTIME
from policyops.retrieval.grounding import EvidenceValidator
from policyops.retrieval.ingest import Request, ingest
from policyops.runtime.clock import FixedLeaseClock
from policyops.services.decisions import DecisionService
from policyops.services.proposal_views import DecisionRequest
from policyops.services.proposals import Created, Presented, ProposalRefused, ProposalService
from policyops_contracts.clock import FixedClock
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.grounding import Assertion, CitedQuote, GroundedAnswer, ValidatedAnswer
from policyops_contracts.proposal import ActionProposal, EvidenceRef
from policyops_contracts.retail import CancelPendingOrder
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.retrieval import RetrievalConfig, RetrievalQuery, RetrievalResult, RetrievalScope
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication
from policyops_testing.app_database import AppDatabase
from policyops_testing.corpus_fixtures import FixtureCorpus, write
from policyops_testing.gateway_cases import FakeRetail, state
from policyops_testing.retrieval_fixtures import CAPS, TOKENIZER, Embeddings, World, documents, run_threads


pytestmark = pytest.mark.postgres
W = RetailWorld()
START = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
KEY_A, KEY_B = "t18-kb-a", "t18-kb-b"  # sorted: A before B
V1 = [("a", "Refunds", "Refunds go back to the original payment method within ten days."),
      ("b", "Cancellation", "Pending orders can be cancelled before they ship.")]
V2 = [(k, t, c.replace("ten days", "twenty days")) for k, t, c in V1]
V1_B = [("c", "Returns", "Delivered items can be returned within ten days.")]  # its own source documents
# A pre-corpus ("legacy") generation has every corpus-ownership column NULL (migration v0010's all-or-none rule).
LEGACY_NULL = ("corpus_key", "source_repository", "source_commit", "source_tree", "source_manifest_sha256",
               "corpus_manifest_sha256", "license_scope", "render", "chunk_config", "tokenizer_sha256",
               "request_config_sha256", "expected_set_sha256", "generation_key_sha256", "document_count",
               "chunk_count")
CANCEL = CancelPendingOrder(order_id=W.order_id, reason="no longer needed")
TABLES = ("app.action_proposals", "app.audit_events", "app.run_events", "app.case_messages", "app.tool_executions")


@dataclass
class Cited:
    """A retrieval workspace with a customer-bound case/run, a reviewer, the controlled clock and the services."""

    world: World
    scope: GatewayScope
    clock: FixedClock
    reviewer: UUID

    @property
    def run(self) -> RunScope:
        return self.scope.run

    def proposals(self) -> ProposalService:
        return ProposalService(app_engine=self.world.engine, clock=FixedLeaseClock(self.clock))

    def counts(self) -> dict[str, int]:
        return {table: self.world.count(table) for table in TABLES}


def publish(world: World, entries: Sequence[tuple[str, str, str]], key: str,
            before_verify: Callable[[Connection, UUID], None] | None = None) -> UUID:
    """The real T12 ingestion and activation (as `World.publish`), optionally with its test hook inside the
    publication transaction (after the corpus row FOR UPDATE and the activation statements, before COMMIT)."""
    world.published += 1
    root = world.root / f"acq-{world.published}"
    raw, digest = write(root, [FixtureCorpus(key, "banking_knowledge", "tau2-banking/v1", documents(entries))])
    outcome = ingest(Request(world.ws, key, raw, digest, root, "execute", CAPS), engine=world.engine,
                     tokenizer=TOKENIZER, providers=Embeddings().providers(), env="test", before_verify=before_verify)
    assert outcome.outcome == "activated", outcome.to_json()
    return UUID(outcome.details["generation_id"])


def bound_run(world: World) -> GatewayScope:
    """A new case bound to the fictional customer, an active run on it and the run's lookup authentication."""
    case, run = uuid4(), uuid4()
    with workspace_transaction(world.engine, world.ws) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=world.ws, scenario="retail",
                                                customer_user_id=W.user_id, created_by=None, created_at=START))
        repo.create_run(conn, NewRun(id=run, workspace_id=world.ws, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=datetime.now(UTC) + timedelta(hours=2),
                                     created_at=START))
        auth_rows.record(conn, CustomerAuthentication(
            scope=RunScope(workspace_id=world.ws, case_id=case, run_id=run), user_id=W.user_id,
            lookup_tool="find_user_id_by_email", lookup_call_sha256=hashlib.sha256(str(run).encode()).hexdigest(),
            step_sequence=1, authenticated_at=START))
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=world.ws, case_id=case), seed_id="retail-demo-9999",
                                  user_id=W.user_id, bound_at=START)
    return load_scope(world.engine, workspace_id=world.ws, run_id=run, binding=binding, fixture_sha256=FIXTURE_SHA256)


def reviewer(world: World) -> UUID:
    principal_id = uuid4()
    with transaction(world.db.engine(AUTH_RUNTIME)) as conn:
        repo.create_principal(conn, Principal(id=principal_id, issuer="https://issuer.example.invalid",
                                              subject=f"reviewer-{principal_id.hex[:8]}", display_name="Reviewer",
                                              created_at=START))
        repo.add_membership(conn, Membership(id=uuid4(), workspace_id=world.ws, principal_id=principal_id,
                                             role="reviewer", created_at=START))
    return principal_id


@pytest.fixture
def cited(shared_db: AppDatabase, tmp_path: Path) -> Cited:
    world = World(shared_db, tmp_path)
    publish(world, V1, KEY_A)
    return Cited(world, bound_run(world), FixedClock(START + timedelta(minutes=1)), reviewer(world))


def cite(cited: Cited, run_id: UUID, fragment: str, *, key: str = KEY_A, step: int = 1) -> EvidenceRef:
    """Retrieve in `run_id`, validate a quote of `fragment` and record it: the real T13/T14 path to one citation."""
    world = cited.world
    query = RetrievalQuery(text=fragment, run_id=run_id, step=step, scope=RetrievalScope(corpus_key=key),
                           config=RetrievalConfig(mode="lexical"))
    result = asyncio.run(world.retriever(Embeddings()).retrieve(query, deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalResult) and result.evidence, result
    evidence = next(e for e in result.evidence if fragment in e.text)
    answer = GroundedAnswer(v="policyops.grounded-answer/v1", outcome="answer", abstention=None, assertions=(
        Assertion(text="A policy claim.", policy_dependent=True, citations=(
            CitedQuote(step=step, evidence_id=evidence.evidence_id, quote=fragment, start=None, end=None),)),))
    validated = EvidenceValidator(world.engine, world.ws, clock=time.monotonic).validate(
        answer, run_id=run_id, authorized_steps=(step,), corpus_key=key, deadline=time.monotonic() + 60)
    assert isinstance(validated, ValidatedAnswer) and validated.bundle is not None, validated
    recorded = CitationRecorder(world.engine, world.ws, clock=time.monotonic).record(
        validated.bundle, run_id=run_id, authorized_steps=(step,), corpus_key=key, deadline=time.monotonic() + 60)
    assert recorded.status == "recorded" and len(recorded.claim_ids) == 1, recorded
    with world.db.superuser() as conn:  # inspection only: the citation's document version and its digest
        version, digest = conn.execute(
            "SELECT c.document_version_id, v.sha256 FROM app.citations c JOIN app.document_versions v "
            "ON v.workspace_id = c.workspace_id AND v.id = c.document_version_id WHERE c.id = %s",
            (recorded.claim_ids[0],)).fetchone()
    return EvidenceRef(evidence_id=recorded.claim_ids[0], document_version_id=version, content_sha256=digest)


def facts(cited: Cited, call: Any = CANCEL) -> Collected:
    collected = collect(FakeRetail(state(), tenant_id=cited.world.ws, case_id=cited.run.case_id,
                                   customer_id=W.user_id), cited.scope, call, IncompleteHistory())
    assert isinstance(collected, Collected)
    return collected


def create(cited: Cited, evidence: Sequence[EvidenceRef], call: Any = CANCEL) -> Any:
    return cited.proposals().create(cited.scope, call, facts(cited, call), evidence=evidence,
                                    rationale="Policy cited.")


def refused_as(result: Any, status: str) -> bool:
    return isinstance(result, ProposalRefused) and (result.code, result.rule_id) == (
        ErrorCode.STALE_VERSION, f"evidence.{status}")


def current(cited: Cited, ref: EvidenceRef) -> bool:
    return PgEvidencePort(cited.world.engine).is_current(cited.world.ws, ref)


def approve(cited: Cited, proposal: ActionProposal) -> AuthorityRefs:
    """Present, record the customer's explicit yes, and have the reviewer approve: the T18 path to authority."""
    service, engine, run = cited.proposals(), cited.world.engine, cited.run
    cited.clock.advance(timedelta(seconds=1))
    assert isinstance(service.present(run, proposal.proposal_id, proposal.proposal_version), Presented)
    cited.clock.advance(timedelta(seconds=1))
    with workspace_transaction(engine, run.workspace_id) as conn:
        reply = repo.append_message(conn, message_id=uuid4(), scope=CaseScope(workspace_id=run.workspace_id,
                                                                               case_id=run.case_id),
                                    source="simulated_customer", entered_by=None, text_value="yes",
                                    created_at=cited.clock.now())
    assert isinstance(service.record_customer_reply(run, reply.message_id), Consented)
    cited.clock.advance(timedelta(seconds=1))
    session = SessionContext(session_id=uuid4(), principal_id=cited.reviewer, workspace_id=run.workspace_id,
                             expires_at=cited.clock.now() + timedelta(hours=1), csrf_sha256="0" * 64)
    authorized = Authorized(session=session, workspace_id=run.workspace_id,
                            roles=frozenset({"reviewer"}))  # type: ignore[arg-type]
    request = DecisionRequest.model_validate({"proposal_version": proposal.proposal_version,
                                              "action_digest": proposal.action_digest, "decision": "approve",
                                              "reason": "Policy and order checked."})
    decision = DecisionService(app_engine=engine, clock=FixedLeaseClock(cited.clock)).decide(
        authorized, proposal.proposal_id, request).decision
    return AuthorityRefs(proposal.proposal_id, proposal.proposal_version, decision.consent_id, decision.approval_id)


def checked(cited: Cited, refs: AuthorityRefs) -> Cleared | PrecheckRefused:
    engine = cited.world.engine
    fake = FakeRetail(state(), tenant_id=cited.world.ws, case_id=cited.run.case_id, customer_id=W.user_id)
    outcome = precheck(cited.scope, refs, retail=fake, sessions=PgSessionStore(engine),
                       membership=PgMembership(engine), clock=cited.clock, decisions=PgDecisionStore(engine),
                       evidence=PgEvidencePort(engine))
    assert all(type(call).__name__.startswith(("Get", "Find")) for call in fake.calls)  # reads only
    return outcome


# -- the positive path and a later activation ------------------------------------------------------------------

def test_current_cited_evidence_is_sealed_and_clears_until_a_new_activation(cited: Cited) -> None:
    refs = [cite(cited, cited.run.run_id, "ten days"), cite(cited, cited.run.run_id, "before they ship", step=2)]
    created = create(cited, refs)
    assert isinstance(created, Created), created
    proposal = created.proposal
    assert set(proposal.evidence) == set(refs) and all(current(cited, ref) for ref in refs)
    authority = approve(cited, proposal)
    assert isinstance(checked(cited, authority), Cleared)

    publish(cited.world, V2, KEY_A)  # the real activation: a new generation, the cited versions retired
    assert not any(current(cited, ref) for ref in refs)
    late = checked(cited, authority)
    assert isinstance(late, PrecheckRefused) and (late.code, late.detail) == (ErrorCode.STALE_VERSION,
                                                                              "evidence_not_current")
    before = cited.counts()
    assert refused_as(create(cited, refs[:1]), "stale_evidence")  # refused before it could supersede version 1
    assert cited.counts() == before and before["app.tool_executions"] == 0
    assert PgDecisionStore(cited.world.engine).proposal(cited.run, proposal.proposal_id, 1) == proposal


def test_another_runs_citation_or_a_wrong_version_binding_is_refused_with_no_writes(cited: Cited) -> None:
    mine = cite(cited, cited.run.run_id, "ten days")
    other_run = bound_run(cited.world).run.run_id  # same workspace and corpus, another case's run
    foreign = cite(cited, other_run, "ten days")
    assert current(cited, foreign)  # current evidence, but not retrieved by this run
    before = cited.counts()
    assert refused_as(create(cited, [foreign]), "stale_evidence")
    assert refused_as(create(cited, [mine.model_copy(update={"content_sha256": "0" * 64})]), "stale_evidence")
    assert refused_as(create(cited, [mine.model_copy(update={"document_version_id": uuid4()})]), "stale_evidence")
    assert refused_as(create(cited, [mine, foreign]), "stale_evidence")
    assert cited.counts() == before
    assert isinstance(create(cited, [mine]), Created)  # the control: the run's own exact binding


# -- publication against creation's corpus SHARE lock ------------------------------------------------------------

def waiting(db: AppDatabase, pattern: str) -> int:
    """Backends of this test database currently waiting on a lock while running a statement like `pattern`."""
    with db.superuser() as conn:
        row = conn.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                           "AND wait_event_type = 'Lock' AND query LIKE %s", (pattern,)).fetchone()
    return int(row[0])


def until(predicate: Callable[[], bool], seconds: float = 20) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_an_activation_holding_the_corpus_lock_first_makes_the_waiting_create_refuse(cited: Cited) -> None:
    ref = cite(cited, cited.run.run_id, "ten days")
    locked, release = threading.Event(), threading.Event()
    outcomes: dict[str, Any] = {}
    before = cited.counts()

    def hold(connection: Connection, generation: UUID) -> None:  # inside the publication transaction
        del connection, generation
        locked.set()
        release.wait(30)

    def activation() -> None:
        outcomes["generation"] = publish(cited.world, V2, KEY_A, before_verify=hold)

    def creator() -> None:
        assert locked.wait(30)
        outcomes["create"] = create(cited, [ref])

    def observer() -> None:
        try:
            assert locked.wait(30)
            outcomes["blocked"] = until(lambda: waiting(cited.world.db, "%app.corpora%FOR SHARE%") > 0)
        finally:
            release.set()

    run_threads(cited.world.db, [activation, creator, observer], timeout=90)
    assert outcomes["blocked"] is True  # creation waited for the publication's row lock
    assert refused_as(outcomes["create"], "stale_evidence")  # and then saw the committed activation
    assert cited.counts() == before and not current(cited, ref)


def test_a_create_holding_the_corpus_share_lock_first_is_current_and_delays_activation(cited: Cited) -> None:
    ref = cite(cited, cited.run.run_id, "ten days")
    held, release = threading.Event(), threading.Event()
    outcomes: dict[str, Any] = {}

    def run_lock() -> None:  # create takes case -> corpora SHARE -> run; holding the run row pauses it after SHARE
        with cited.world.db.superuser() as conn, conn.transaction():
            conn.execute("SELECT 1 FROM app.runs WHERE id = %s FOR UPDATE", (cited.run.run_id,))
            held.set()
            release.wait(30)

    def creator() -> None:
        assert held.wait(30)
        outcomes["create"] = create(cited, [ref])

    def activation() -> None:
        assert held.wait(30)
        assert until(lambda: waiting(cited.world.db, "%app.runs%FOR UPDATE%") > 0)  # create is past its SHARE
        outcomes["generation"] = publish(cited.world, V2, KEY_A)

    def observer() -> None:
        try:
            assert held.wait(30)
            outcomes["blocked"] = until(lambda: waiting(cited.world.db, "%app.corpora%FOR UPDATE%") > 0)
        finally:
            release.set()

    run_threads(cited.world.db, [run_lock, creator, activation, observer], timeout=90)
    assert outcomes["blocked"] is True  # the publication waited behind creation's SHARE lock
    created = outcomes["create"]
    assert isinstance(created, Created) and created.proposal.evidence == (ref,)  # current at its locked check
    assert not current(cited, ref)  # the activation committed afterwards


def test_multiple_corpora_are_locked_in_sorted_key_order(cited: Cited) -> None:
    publish(cited.world, V1_B, KEY_B)
    ref_a = cite(cited, cited.run.run_id, "ten days")
    ref_b = cite(cited, cited.run.run_id, "ten days", key=KEY_B, step=2)

    def probe_nowait(key: str) -> bool:
        """Whether another transaction could take `key` FOR UPDATE right now (released at once)."""
        with cited.world.db.superuser() as conn:
            try:
                with conn.transaction():
                    conn.execute("SELECT 1 FROM app.corpora WHERE workspace_id = %s AND corpus_key = %s "
                                 "FOR UPDATE NOWAIT", (cited.world.ws, key))
            except psycopg.errors.LockNotAvailable:
                return False
        return True

    def ordered(held_key: str, other_key: str, refs: list[EvidenceRef]) -> tuple[bool, Any]:
        held, release = threading.Event(), threading.Event()
        outcomes: dict[str, Any] = {}

        def holder() -> None:
            with cited.world.db.superuser() as conn, conn.transaction():
                conn.execute("SELECT 1 FROM app.corpora WHERE workspace_id = %s AND corpus_key = %s FOR UPDATE",
                             (cited.world.ws, held_key))
                held.set()
                release.wait(30)

        def creator() -> None:
            assert held.wait(30)
            outcomes["create"] = create(cited, refs)

        def observer() -> None:
            try:
                assert held.wait(30)
                assert until(lambda: waiting(cited.world.db, "%app.corpora%FOR SHARE%") > 0)
                outcomes["other_free"] = probe_nowait(other_key)
            finally:
                release.set()

        run_threads(cited.world.db, [holder, creator, observer], timeout=90)
        return outcomes["other_free"], outcomes["create"]

    # B held: creation already holds A (sorted first) while it waits for B, whatever the input order.
    a_free, first = ordered(KEY_B, KEY_A, [ref_b, ref_a])
    assert a_free is False and isinstance(first, Created)
    # A held: creation has not touched B yet.
    b_free, second = ordered(KEY_A, KEY_B, [ref_a, ref_b])
    assert b_free is True and isinstance(second, Created) and second.superseded == (
        (first.proposal.proposal_id, 1),)


# -- contradictory states ----------------------------------------------------------------------------------------

@pytest.mark.parametrize(("state_", "status"), [
    # The runtime role cannot see this contradiction: RLS (`chunks_app_ready`) hides the chunks of a generation that
    # is not ready, so the citation is not found at all and is refused as stale.
    ("active_generation_not_ready", "stale_evidence"),
    ("active_generation_cites_retired_version", "evidence_inconsistent"),
    ("unowned_legacy_generation", "evidence_inconsistent"),
])
def test_contradictory_evidence_states_are_refused_not_resolved(cited: Cited, state_: str, status: str) -> None:
    ref = cite(cited, cited.run.run_id, "ten days")
    with cited.world.db.superuser() as conn:  # test-only corruption, bypassing the guards (owner session)
        generation = conn.execute("SELECT active_generation_id FROM app.corpora WHERE workspace_id = %s "
                                  "AND corpus_key = %s", (cited.world.ws, KEY_A)).fetchone()[0]
        conn.execute("SET session_replication_role = replica")
        if state_ == "active_generation_not_ready":
            conn.execute("UPDATE app.index_generations SET status = 'retired' WHERE id = %s", (generation,))
        elif state_ == "active_generation_cites_retired_version":
            conn.execute("UPDATE app.document_versions SET status = 'retired', effective_to = now() WHERE id = %s",
                         (ref.document_version_id,))
        else:
            assignments = ", ".join(f"{column} = NULL" for column in LEGACY_NULL)
            conn.execute(f"UPDATE app.index_generations SET {assignments} WHERE id = %s",  # noqa: S608 - fixed names
                         (generation,))
        conn.execute("SET session_replication_role = DEFAULT")
    before = cited.counts()
    assert refused_as(create(cited, [ref]), status)
    assert cited.counts() == before and not current(cited, ref)
