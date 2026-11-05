"""Relational invariants on the real server as the app runtime: immutability, digest-bound consent/decisions,
optimistic-version and dedupe races, exact USD amounts and named CHECK constraints."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from functools import partial
import threading
from typing import Any
from uuid import UUID, uuid4

from psycopg import errors
from pydantic import ValidationError
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from policyops.domain.examples import World, build_examples
from policyops.persistence import repositories as repo
from policyops.persistence.database import (
    DecisionConflict,
    IdempotencyConflict,
    ImmutableRecord,
    StaleVersion,
    transaction,
    workspace_transaction,
)
from policyops.persistence.importer import PROPOSAL_ROW, import_synthetic_world
from policyops.persistence.records import NewCase, NewJob, NewRun, UsageEvent
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_contracts.consent import (
    ApprovalDecision,
    CaseMessage,
    CustomerConsent,
    ProposalPresentationRecord,
)
from policyops_contracts.proposal import ActionProposal
from policyops_testing.app_database import AppDatabase, NewDatabase


pytestmark = pytest.mark.postgres
WORLD = World()
NOW = WORLD.now


@pytest.fixture(scope="module")
def world_db(app_cluster: Any) -> Iterator[AppDatabase]:
    database: AppDatabase = app_cluster.create_database("invariants")
    database.upgrade()
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    yield database
    database.dispose()


def scoped[T](db: AppDatabase, fn: Callable[[Any], T], *, pool_size: int = 2) -> T:
    with workspace_transaction(db.engine(APP_RUNTIME, pool_size=pool_size), WORLD.workspace) as conn:
        return fn(conn)


def race[T](db: AppDatabase, workers: int, fn: Callable[[Any, int], T]) -> list[T | Exception]:
    """Run `fn` in `workers` threads, each in its own scoped transaction, released together by a barrier."""
    engine = db.engine(APP_RUNTIME, pool_size=workers)
    barrier = threading.Barrier(workers)

    def one(index: int) -> T | Exception:
        try:
            with workspace_transaction(engine, WORLD.workspace) as conn:
                barrier.wait(timeout=30)
                return fn(conn, index)
        except Exception as exc:  # collected for assertions
            return exc

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, range(workers)))


def new_case(db: AppDatabase) -> UUID:
    case_id = uuid4()
    scoped(db, lambda conn: repo.create_case(conn, NewCase(id=case_id, workspace_id=WORLD.workspace,
                                                           scenario="retail", customer_user_id=None, created_by=None,
                                                           created_at=NOW)))
    return case_id


# -- immutability ---------------------------------------------------------------------------------------------

def test_imported_records_round_trip_as_contracts(world_db: AppDatabase) -> None:
    examples = build_examples()
    reply = CaseMessage.model_validate_json(examples["case-message.operator-entered-yes.json"])
    messages = scoped(world_db, lambda conn: repo.list_messages(conn, WORLD.case_scope, after_sequence=10, limit=5))
    assert messages == [reply]


@pytest.mark.parametrize("statement", [
    "UPDATE app.case_messages SET text = 'changed' WHERE sequence = 11",
    "DELETE FROM app.case_messages WHERE sequence = 11",
    "UPDATE app.customer_consents SET basis = 'simulator_confirmation_event'",
    "UPDATE app.approval_decisions SET decision = 'reject'",
    "UPDATE app.action_proposals SET body = '{}'::jsonb",
    "UPDATE app.action_proposals SET action_digest = repeat('0', 64)",
    "DELETE FROM app.action_proposals",
    "UPDATE app.audit_events SET reason = 'x'",
    "TRUNCATE app.run_events",
])
def test_runtime_cannot_change_immutable_records(world_db: AppDatabase, statement: str) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        scoped(world_db, lambda conn: conn.execute(text(statement)))


def test_proposal_guard_holds_even_for_the_owner_and_superuser(world_db: AppDatabase) -> None:
    with world_db.superuser() as conn, pytest.raises(errors.RaiseException, match="immutable"):
        conn.execute("UPDATE app.action_proposals SET intent_digest = repeat('1', 64)")
    with pytest.raises(ImmutableRecord, match="cannot move from presented to created"):
        scoped(world_db, lambda conn: repo.set_proposal_status(conn, WORLD.workspace, UUID(int=500), 1, "created"))
    with pytest.raises(ProgrammingError, match="presentation time is immutable"):  # raw SQL: the trigger itself
        scoped(world_db, lambda conn: conn.execute(text(
            "UPDATE app.action_proposals SET presented_at = presented_at + interval '1 second' WHERE id = :id"),
            {"id": PROPOSAL_ROW}))


def test_consent_and_decision_are_bound_to_the_proposal_digest(world_db: AppDatabase) -> None:
    examples = build_examples()
    consent = CustomerConsent.model_validate_json(examples["customer-consent.json"])
    decision = ApprovalDecision.model_validate_json(examples["approval-decision.json"])
    with pytest.raises(DecisionConflict):  # a second consent for the same proposal version
        scoped(world_db, lambda conn: repo.record_consent(conn, consent.model_copy(update={"consent_id": uuid4()})))
    with pytest.raises(DecisionConflict):  # a replayed or second decision
        scoped(world_db, lambda conn: repo.record_decision(conn, decision.model_copy(update={"approval_id": uuid4()})))
    forged = decision.model_copy(update={"approval_id": uuid4(), "proposal_version": 2})
    with pytest.raises(DBAPIError) as raised:  # no proposal v2 with that digest exists
        scoped(world_db, lambda conn: repo.record_decision(conn, forged))
    assert isinstance(raised.value.orig, errors.ForeignKeyViolation)


# -- races ----------------------------------------------------------------------------------------------------

def test_optimistic_version_race_has_exactly_one_winner(world_db: AppDatabase) -> None:
    case_id = new_case(world_db)
    results = race(world_db, 4, lambda conn, i: repo.set_case_status(
        conn, case_id, expected_version=1, status="in_progress", now=NOW + timedelta(seconds=i)))
    winners = [r for r in results if not isinstance(r, Exception)]
    assert len(winners) == 1 and winners[0].version == 2
    assert all(isinstance(r, StaleVersion) for r in results if isinstance(r, Exception))
    with pytest.raises(StaleVersion):
        scoped(world_db, lambda conn: repo.set_case_status(conn, case_id, expected_version=1, status="closed",
                                                           now=NOW))


def test_concurrent_message_appends_get_unique_gapless_sequences(world_db: AppDatabase) -> None:
    case_id = new_case(world_db)
    scope = WORLD.case_scope.model_copy(update={"case_id": case_id})
    results = race(world_db, 6, lambda conn, i: repo.append_message(
        conn, message_id=uuid4(), scope=scope, source="simulated_customer", entered_by=None,
        text_value=f"Synthetic message {i}.", created_at=NOW))
    assert not [r for r in results if isinstance(r, Exception)]
    stored = scoped(world_db, lambda conn: repo.list_messages(conn, scope, limit=50))
    assert [m.sequence for m in stored] == [1, 2, 3, 4, 5, 6]


def test_execution_dedupe_race_same_payload_and_conflicting_payload(world_db: AppDatabase) -> None:
    decision = ApprovalDecision.model_validate_json(build_examples()["approval-decision.json"])
    operation = uuid4()
    same = race(world_db, 4, lambda conn, i: repo.begin_execution(
        conn, execution_id=uuid4(), operation_id=operation, decision=decision, argument_digest="a" * 64, now=NOW))
    assert not [r for r in same if isinstance(r, Exception)]
    assert len({r[0].id for r in same}) == 1 and sorted(r[1] for r in same) == [False, False, False, True]  # type: ignore[index]
    other = uuid4()
    mixed = race(world_db, 4, lambda conn, i: repo.begin_execution(
        conn, execution_id=uuid4(), operation_id=other, decision=decision,
        argument_digest="a" * 64 if i == 0 else "b" * 64, now=NOW))
    created = [r for r in mixed if not isinstance(r, Exception) and r[1]]
    assert len(created) == 1
    winner_digest = created[0][0].argument_digest
    for index, result in enumerate(mixed):
        digest = "a" * 64 if index == 0 else "b" * 64
        if digest == winner_digest:
            assert not isinstance(result, Exception)
        else:
            assert isinstance(result, IdempotencyConflict)


def test_concurrent_decisions_have_one_terminal_winner(new_app_database: NewDatabase) -> None:
    database = new_app_database("decision_race")
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    decision = ApprovalDecision.model_validate_json(build_examples()["approval-decision.json"])
    with database.superuser() as conn:  # leave the proposal consented but undecided
        conn.execute("DELETE FROM app.approval_decisions")
    results = race(database, 4, lambda conn, i: repo.record_decision(
        conn, decision.model_copy(update={"approval_id": uuid4(), "decision": "approve" if i % 2 else "reject"})))
    assert sum(1 for r in results if not isinstance(r, Exception)) == 1
    assert all(isinstance(r, DecisionConflict) for r in results if isinstance(r, Exception))


def _job(**changes: Any) -> NewJob:
    base = NewJob(id=uuid4(), workspace_id=WORLD.workspace, run_id=WORLD.run, dedupe_key=f"job-{uuid4()}",
                  kind="investigate", run_generation=1, max_attempts=3, available_at=NOW,
                  deadline_at=NOW + timedelta(minutes=5), created_at=NOW)
    return base.model_copy(update=changes)


def test_job_key_identity_is_the_whole_request_and_survives_worker_changes(world_db: AppDatabase) -> None:
    """C1 finding F2: a reused key with a changed schedule, deadline or retry policy must conflict, while the same
    request still replays after a worker has rescheduled the job (available_at is mutable state)."""
    job = _job()
    assert scoped(world_db, lambda conn: repo.enqueue_job(conn, job)) == (job.id, True)
    replay = job.model_copy(update={"id": uuid4(), "created_at": NOW + timedelta(seconds=9)})  # not identity
    assert scoped(world_db, lambda conn: repo.enqueue_job(conn, replay)) == (job.id, False)
    scoped(world_db, lambda conn: conn.execute(text(  # a worker leases, fails once and reschedules the job
        "UPDATE app.jobs SET state = 'queued', attempts = 1, available_at = available_at + interval '2 minutes', "
        "updated_at = :t, version = version + 1 WHERE id = :id"), {"id": job.id, "t": NOW + timedelta(minutes=1)}))
    assert scoped(world_db, lambda conn: repo.enqueue_job(conn, replay)) == (job.id, False)
    for changes in ({"max_attempts": 4}, {"available_at": NOW + timedelta(minutes=1)},
                    {"deadline_at": NOW + timedelta(minutes=6)}, {"kind": "other"}, {"run_generation": 2}):
        changed = job.model_copy(update={"id": uuid4(), **changes})
        with pytest.raises(IdempotencyConflict):
            scoped(world_db, partial(repo.enqueue_job, job=changed))
    with pytest.raises(ProgrammingError, match="permission denied"):  # the stored identity is immutable
        scoped(world_db, lambda conn: conn.execute(text(
            "UPDATE app.jobs SET request_sha256 = repeat('0', 64) WHERE id = :id"), {"id": job.id}))
    stored = scoped(world_db, lambda conn: conn.execute(text(
        "SELECT request_sha256 FROM app.jobs WHERE id = :id"), {"id": job.id}).scalar_one())
    assert stored == repo.job_request_sha256(job)


def test_concurrent_job_enqueue_has_one_creator(world_db: AppDatabase) -> None:
    same = _job()
    results = race(world_db, 4, lambda conn, i: repo.enqueue_job(conn, same.model_copy(update={"id": uuid4()})))
    assert not [r for r in results if isinstance(r, Exception)]
    assert sorted(r[1] for r in results if not isinstance(r, Exception)) == [False, False, False, True]
    assert len({r[0] for r in results if not isinstance(r, Exception)}) == 1
    differing = _job()
    results = race(world_db, 4, lambda conn, i: repo.enqueue_job(
        conn, differing.model_copy(update={"id": uuid4(), "max_attempts": i + 1})))
    created = [r for r in results if not isinstance(r, Exception)]
    assert len(created) == 1 and created[0][1] is True
    assert sum(isinstance(r, IdempotencyConflict) for r in results) == 3


def test_usage_dedupe(world_db: AppDatabase) -> None:
    usage = _usage(cost=Decimal("0.0000125"))
    assert scoped(world_db, lambda conn: repo.record_usage(conn, usage)) is True
    assert scoped(world_db, lambda conn: repo.record_usage(conn, usage.model_copy(update={"id": uuid4()}))) is False
    with pytest.raises(IdempotencyConflict):
        scoped(world_db, lambda conn: repo.record_usage(conn, usage.model_copy(
            update={"id": uuid4(), "cost_usd": Decimal("0.0000126")})))


# -- exact USD and constraints --------------------------------------------------------------------------------

def _usage(*, cost: Decimal | None, status: str = "known") -> UsageEvent:
    return UsageEvent(id=uuid4(), workspace_id=WORLD.workspace, run_id=WORLD.run, actor="agent", provider="fake",
                      model="fake-small", provider_request_id=f"req-{uuid4()}", uncached_input_tokens=1,
                      cache_read_tokens=0, cache_write_tokens=0, output_tokens=1, reasoning_tokens=0,
                      price_revision="synthetic-1", cost_status=status, cost_usd=cost,  # type: ignore[arg-type]
                      created_at=NOW)


@pytest.mark.parametrize("amount", ["0.000000000000000001", "0.123456789012345678", "999999.999999999999999999",
                                    "0", "1.50"])
def test_usd_amounts_round_trip_exactly(world_db: AppDatabase, amount: str) -> None:
    usage = _usage(cost=Decimal(amount))
    scoped(world_db, lambda conn: repo.record_usage(conn, usage))
    status, stored = scoped(world_db, lambda conn: repo.usage_cost(conn, usage.id))
    assert status == "known" and stored == Decimal(amount) and stored.as_tuple() == Decimal(amount).as_tuple()


@pytest.mark.parametrize("amount", ["0.0000000000000000001", "NaN", "1000000", "-0.01", "Infinity"])
def test_inexact_or_out_of_range_usd_is_rejected_not_rounded(world_db: AppDatabase, amount: str) -> None:
    with pytest.raises(ValidationError):
        _usage(cost=Decimal(amount))
    params = {"id": uuid4(), "w": WORLD.workspace, "r": f"raw-{uuid4()}", "c": amount, "t": NOW}
    with pytest.raises(DBAPIError) as raised:  # bypassing the model: the database check, not a rounding cast
        scoped(world_db, lambda conn: conn.execute(text(
            "INSERT INTO app.usage_events (id, workspace_id, actor, provider, model, provider_request_id, "
            "uncached_input_tokens, cache_read_tokens, cache_write_tokens, output_tokens, reasoning_tokens, "
            "price_revision, cost_status, cost_usd, created_at) VALUES (:id, :w, 'agent', 'fake', 'm', :r, 0, 0, 0, "
            "0, 0, 'p', 'known', CAST(:c AS numeric), :t)"), params))
    assert isinstance(raised.value.orig, errors.CheckViolation)
    assert "usage_events_cost_usd_exact" in str(raised.value.orig)


def test_unknown_cost_is_null_never_zero(world_db: AppDatabase) -> None:
    unknown = _usage(cost=None, status="unknown")
    scoped(world_db, lambda conn: repo.record_usage(conn, unknown))
    assert scoped(world_db, lambda conn: repo.usage_cost(conn, unknown.id)) == ("unknown", None)
    with pytest.raises(ValidationError):
        _usage(cost=Decimal("0"), status="unknown")


CONSTRAINT_CASES = [
    ("case_messages_author_rule", "INSERT INTO app.case_messages (id, workspace_id, case_id, sequence, source, "
     "entered_by, text, text_sha256, created_at) VALUES (gen_random_uuid(), :w, :c, 999, 'staff_note', NULL, 'x', "
     "repeat('a', 64), now())"),
    ("case_messages_source_values", "INSERT INTO app.case_messages (id, workspace_id, case_id, sequence, source, "
     "text, text_sha256, created_at) VALUES (gen_random_uuid(), :w, :c, 998, 'model', 'x', repeat('a', 64), now())"),
    ("case_messages_sequence_unique", "INSERT INTO app.case_messages (id, workspace_id, case_id, sequence, source, "
     "text, text_sha256, created_at) VALUES (gen_random_uuid(), :w, :c, 1, 'seeded', 'x', repeat('a', 64), now())"),
    ("cases_status_values", "UPDATE app.cases SET status = 'deleted' WHERE id = :c"),
    ("cases_version_positive", "UPDATE app.cases SET version = 0 WHERE id = :c"),
    ("runs_state_values", "UPDATE app.runs SET state = 'paused' WHERE id = :r"),
    ("runs_model_calls_bounds", "UPDATE app.runs SET model_calls = -1 WHERE id = :r"),
    # A leased job with a claim (0005) but no lease owner/expiry: only the lease rule is violated.
    ("jobs_lease_state", "INSERT INTO app.jobs (id, workspace_id, run_id, dedupe_key, request_sha256, kind, "
     "run_generation, state, claim_id, max_attempts, available_at, deadline_at, created_at, updated_at) VALUES "
     "(gen_random_uuid(), :w, :r, gen_random_uuid()::text, repeat('a', 64), 'x', 0, 'leased', gen_random_uuid(), 1, "
     "now(), now() + interval '1 hour', now(), now())"),
    ("jobs_claim_state", "INSERT INTO app.jobs (id, workspace_id, run_id, dedupe_key, request_sha256, kind, "
     "run_generation, state, lease_owner, lease_expires_at, max_attempts, available_at, deadline_at, created_at, "
     "updated_at) VALUES (gen_random_uuid(), :w, :r, gen_random_uuid()::text, repeat('a', 64), 'x', 0, 'leased', "
     "gen_random_uuid(), now() + interval '1 minute', 1, now(), now() + interval '1 hour', now(), now())"),
    ("usage_events_reasoning_within_output", "INSERT INTO app.usage_events (id, workspace_id, actor, provider, "
     "model, provider_request_id, uncached_input_tokens, cache_read_tokens, cache_write_tokens, output_tokens, "
     "reasoning_tokens, price_revision, cost_status, cost_usd, created_at) VALUES (gen_random_uuid(), :w, 'agent', "
     "'fake', 'm', gen_random_uuid()::text, 0, 0, 0, 1, 2, 'p', 'unknown', NULL, now())"),
]


@pytest.mark.parametrize(("constraint", "statement"), CONSTRAINT_CASES, ids=[c for c, _ in CONSTRAINT_CASES])
def test_named_constraints_reject_invalid_rows(world_db: AppDatabase, constraint: str, statement: str) -> None:
    with pytest.raises(DBAPIError) as raised:
        scoped(world_db, lambda conn: conn.execute(text(statement), {"w": WORLD.workspace, "c": WORLD.case,
                                                                      "r": WORLD.run}))
    assert isinstance(raised.value.orig, errors.IntegrityError) and constraint in str(raised.value.orig)


def test_active_membership_uniqueness_ignores_revoked_rows(world_db: AppDatabase) -> None:
    insert = text("INSERT INTO identity.memberships (id, workspace_id, principal_id, role, created_at, revoked_at) "
                  "VALUES (:id, :w, :p, 'reviewer', :t, :revoked)")
    with transaction(world_db.engine(AUTH_RUNTIME)) as conn:  # analyst also becomes reviewer once, revoked first
        conn.execute(insert, {"id": uuid4(), "w": WORLD.workspace, "p": WORLD.analyst, "t": NOW, "revoked": NOW})
        conn.execute(insert, {"id": uuid4(), "w": WORLD.workspace, "p": WORLD.analyst, "t": NOW, "revoked": None})
    with pytest.raises(DBAPIError) as raised, transaction(world_db.engine(AUTH_RUNTIME)) as conn:
        conn.execute(insert, {"id": uuid4(), "w": WORLD.workspace, "p": WORLD.analyst, "t": NOW, "revoked": None})
    assert "memberships_active_unique" in str(raised.value.orig)


def test_run_events_get_ordered_sequences(world_db: AppDatabase) -> None:
    sequences = [scoped(world_db, lambda conn: repo.append_run_event(
        conn, event_id=uuid4(), workspace_id=WORLD.workspace, run_id=WORLD.run, event_type="run.state_changed",
        schema_version="policyops.run-event/v1", payload_json='{"current": "running"}', occurred_at=NOW))
        for _ in range(3)]
    assert sequences == [sequences[0], sequences[0] + 1, sequences[0] + 2]
    with pytest.raises(DBAPIError):  # an oversized payload is refused by the size check
        scoped(world_db, lambda conn: repo.append_run_event(
            conn, event_id=uuid4(), workspace_id=WORLD.workspace, run_id=WORLD.run, event_type="run.big",
            schema_version="policyops.run-event/v1", payload_json='{"x": "' + "y" * 200000 + '"}', occurred_at=NOW))


def test_new_run_requires_a_deadline_after_creation() -> None:
    with pytest.raises(ValidationError):
        NewRun(id=uuid4(), workspace_id=WORLD.workspace, case_id=WORLD.case, case_version=1, mode="workbench",
               graph_sha256="0" * 64, prompt_sha256="0" * 64, config_sha256="0" * 64, deadline_at=NOW,
               created_at=NOW)


# -- complete binding records ---------------------------------------------------------------------------------

def _fk(db: AppDatabase, constraint: str, fn: Callable[[Any], Any]) -> None:
    with pytest.raises(DBAPIError) as raised:
        scoped(db, fn)
    assert isinstance(raised.value.orig, errors.ForeignKeyViolation), raised.value.orig
    assert constraint in str(raised.value.orig)


def test_binding_records_round_trip_and_reject_wrong_case_run_or_evidence(new_app_database: NewDatabase) -> None:
    db = new_app_database("bindings")
    import_synthetic_world(auth=db.engine(AUTH_RUNTIME), app=db.engine(APP_RUNTIME))
    examples = build_examples()
    proposal = ActionProposal.model_validate_json(examples["action-proposal.exchange.json"])
    presentation = ProposalPresentationRecord.model_validate_json(examples["proposal-presentation.json"])
    consent = CustomerConsent.model_validate_json(examples["customer-consent.json"])
    decision = ApprovalDecision.model_validate_json(examples["approval-decision.json"])
    pid, pv = proposal.proposal_id, proposal.proposal_version
    stored = scoped(db, lambda conn: (repo.get_proposal(conn, pid, pv), repo.get_presentation(conn, pid, pv),
                                      repo.get_consent(conn, pid, pv), repo.get_decision(conn, pid, pv)))
    assert stored == (proposal, presentation, consent, decision)  # exact contracts, nothing discarded

    # A second case and run in the SAME workspace, with a message carrying the same reply text.
    other_case = new_case(db)
    other_run = uuid4()
    scoped(db, lambda conn: repo.create_run(conn, NewRun(
        id=other_run, workspace_id=WORLD.workspace, case_id=other_case, case_version=1, mode="workbench",
        graph_sha256="0" * 64, prompt_sha256="0" * 64, config_sha256="0" * 64, deadline_at=NOW + timedelta(hours=1),
        created_at=NOW)))
    other_scope = WORLD.case_scope.model_copy(update={"case_id": other_case})
    for number in range(1, 12):
        scoped(db, partial(repo.append_message, message_id=uuid4(), scope=other_scope,
                           source="operator_entered_customer", entered_by=WORLD.analyst,
                           text_value="Yes, please." if number == 11 else f"Other {number}.", created_at=NOW))
    run_in_other_case = proposal.scope.model_copy(update={"run_id": other_run})  # case stays WORLD.case
    other_case_and_run = proposal.scope.model_copy(update={"case_id": other_case, "run_id": other_run})

    # Proposal: its run must belong to its case.
    _fk(db, "action_proposals_run", lambda conn: repo.insert_proposal(
        conn, uuid4(), proposal.model_copy(update={"proposal_id": uuid4(), "scope": run_in_other_case})))

    # Presentation: a fresh proposal row in the right scope, then wrong message case/sequence/digest.
    fresh = proposal.model_copy(update={"proposal_id": uuid4()})
    scoped(db, lambda conn: repo.insert_proposal(conn, uuid4(), fresh))
    shown = presentation.model_copy(update={"proposal_id": fresh.proposal_id})
    with db.superuser() as conn:
        other_message = conn.execute("SELECT id FROM app.case_messages WHERE case_id = %s AND sequence = 10",
                                     (other_case,)).fetchone()[0]
    _fk(db, "proposal_presentations_message", lambda conn: repo.mark_presented(
        conn, shown.model_copy(update={"message_id": other_message})))
    _fk(db, "proposal_presentations_message", lambda conn: repo.mark_presented(
        conn, shown.model_copy(update={"message_sequence": 9})))
    _fk(db, "proposal_presentations_proposal", lambda conn: repo.mark_presented(
        conn, shown.model_copy(update={"presentation_sha256": "e" * 64})))
    _fk(db, "proposal_presentations_proposal", lambda conn: repo.mark_presented(
        conn, shown.model_copy(update={"scope": run_in_other_case})))

    # Consent and decision: remove the imported ones (test superuser), then probe every recorded binding field.
    with db.superuser() as conn:
        conn.execute("DELETE FROM app.approval_decisions")
        conn.execute("DELETE FROM app.customer_consents")
    for constraint, changes in (
            ("customer_consents_presentation", {"scope": run_in_other_case}),
            ("customer_consents_presentation", {"scope": other_case_and_run}),
            ("customer_consents_presentation", {"presented_message_sequence": 9}),
            ("customer_consents_presentation", {"presentation_sha256": "e" * 64}),
            ("customer_consents_message", {"customer_message_sequence": 12}),
            ("customer_consents_message", {"customer_message_sha256": "e" * 64}),
            ("customer_consents_message", {"message_source": "simulated_customer", "entered_by": None}),
            ("customer_consents_message_author", {"entered_by": WORLD.reviewer})):
        forged_consent = consent.model_copy(update={"consent_id": uuid4(), **changes})
        _fk(db, constraint, partial(repo.record_consent, consent=forged_consent))
    scoped(db, lambda conn: repo.record_consent(conn, consent))
    for changes in ({"scope": run_in_other_case}, {"scope": other_case_and_run}):
        forged_decision = decision.model_copy(update={"approval_id": uuid4(), **changes})
        _fk(db, "approval_decisions_consent", partial(repo.record_decision, decision=forged_decision))
    scoped(db, lambda conn: repo.record_decision(conn, decision))
    assert scoped(db, lambda conn: repo.get_decision(conn, pid, pv)) == decision
