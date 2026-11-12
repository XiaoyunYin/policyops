"""Fenced preparation replay: one atomic proposal/presentation/message/audit intent."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from typing import Any
from uuid import uuid4, uuid5

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.domain.examples import World
from policyops.gateway.facts import Collected, collect
from policyops.gateway.ports import IncompleteHistory
from policyops.persistence import repositories as repo
from policyops.persistence.database import IdempotencyConflict, workspace_transaction
from policyops.persistence.roles import APP_RUNTIME
from policyops.persistence.runs import Fenced
from policyops.runtime.clock import FixedLeaseClock
from policyops.services.proposals import PROPOSAL_NAMESPACE, Created, Prepared, ProposalRefused, ProposalService
from policyops_contracts.proposal import EvidenceRef
from policyops_contracts.retail import CancelPendingOrder
from policyops_testing.app_database import AppDatabase
from policyops_testing.checkpoint_cases import Claimed, claimed
from policyops_testing.gateway_cases import FakeRetail, state


pytestmark = pytest.mark.postgres
CALL = CancelPendingOrder(order_id=World().order_id, reason="no longer needed")


def facts(owner: Claimed) -> Collected:
    retail = FakeRetail(state(), tenant_id=owner.scope.run.workspace_id, case_id=owner.scope.run.case_id,
                        customer_id=World().user_id)
    result = collect(retail, owner.scope, CALL, IncompleteHistory())
    assert isinstance(result, Collected)
    return result


def service(owner: Claimed) -> ProposalService:
    return ProposalService(owner.db.engine(APP_RUNTIME), FixedLeaseClock(owner.clock))


def prepare(owner: Claimed, **changes: Any) -> Any:
    args: dict[str, Any] = dict(token=owner.token, step=1, rationale="Customer asked.") | changes
    return service(owner).create_once(owner.scope, CALL, facts(owner), **args)


def counts(owner: Claimed) -> tuple[int, ...]:
    with owner.db.superuser() as conn:
        return tuple(conn.execute(f"SELECT count(*) FROM {table} WHERE workspace_id = %s",  # noqa: S608
                                  (owner.scope.run.workspace_id,)).fetchone()[0] for table in (
                                      "app.action_proposals", "app.proposal_presentations", "app.case_messages",
                                      "app.audit_events", "app.run_events", "app.outbox_events"))


def test_equal_replay_after_lost_ack_returns_original_and_conflict_writes_nothing(shared_db: AppDatabase) -> None:
    owner = claimed(shared_db)
    original = prepare(owner)
    assert isinstance(original, Prepared)
    assert original.proposal.proposal_id == uuid5(PROPOSAL_NAMESPACE,
                                                f"{owner.scope.run.workspace_id}:{owner.scope.run.run_id}:1")
    before = counts(owner)
    assert before == (1, 1, 1, 2, 2, 2)
    assert prepare(owner) == original  # discard first acknowledgement, reconcile same intent
    with pytest.raises(IdempotencyConflict):
        prepare(owner, rationale="Changed request.")
    with pytest.raises(IdempotencyConflict):
        prepare(owner, evidence=(EvidenceRef(evidence_id=uuid4(), document_version_id=uuid4(),
                                             content_sha256="e" * 64),))
    other_call = CALL.model_copy(update={"reason": "ordered by mistake"})
    with pytest.raises(IdempotencyConflict):
        service(owner).create_once(owner.scope, other_call, facts(owner), token=owner.token, step=1,
                                   rationale="Customer asked.")
    with pytest.raises(IdempotencyConflict):
        altered = replace(owner.scope, fixture_sha256="f" * 64)
        service(owner).create_once(altered, CALL, facts(owner), token=owner.token, step=1, rationale="Customer asked.")
    assert counts(owner) == before
    with workspace_transaction(shared_db.engine(APP_RUNTIME), owner.scope.run.workspace_id) as conn:
        row = repo.proposal_creation(conn, owner.scope.run.run_id, 1)
        assert row is not None and row.creation_request_sha256 is not None


def test_replay_never_resurrects_superseded_or_expired_or_changes_expiry(shared_db: AppDatabase) -> None:
    owner = claimed(shared_db)
    first = prepare(owner)
    assert isinstance(first, Prepared)
    legacy = service(owner).create(owner.scope, CALL, facts(owner), rationale="New intent version.")
    assert isinstance(legacy, Created)  # legacy behavior still supersedes
    with workspace_transaction(shared_db.engine(APP_RUNTIME), owner.scope.run.workspace_id) as conn:
        assert repo.proposal_row(conn, first.proposal.proposal_id, 1).status == "superseded"  # type: ignore[union-attr]
    before = counts(owner)
    assert prepare(owner) == first and counts(owner) == before
    # Expiry is not refreshed on replay; extend the worker's lease under a new claim.
    owner.clock.advance(timedelta(minutes=20))
    owner.reclaim()
    assert prepare(owner) == first and counts(owner) == before


def test_competing_same_claim_and_reclaimed_claim_produce_one_intent(shared_db: AppDatabase) -> None:
    owner = claimed(shared_db)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: prepare(owner), range(2)))
    assert isinstance(results[0], Prepared) and results[0] == results[1]
    stale = owner.token
    owner.reclaim()
    assert prepare(owner) == results[0]
    before = counts(owner)
    with pytest.raises(Fenced):
        prepare(owner, token=stale)
    with pytest.raises(Fenced):
        prepare(owner, token=replace(owner.token, claim_id=uuid4()), step=2)
    assert counts(owner) == before
    # Two generations race before any preparation: only the new claim can commit.
    fresh = claimed(shared_db)
    old_token = fresh.token
    fresh.reclaim()

    def race(token: Any) -> Any:
        try:
            return prepare(fresh, token=token)
        except Fenced:
            return "fenced"

    with ThreadPoolExecutor(max_workers=2) as pool:
        raced = list(pool.map(race, (old_token, fresh.token)))
    assert raced[0] == "fenced" and isinstance(raced[1], Prepared)
    assert counts(fresh) == (1, 1, 1, 2, 2, 2)


def test_replay_creation_columns_are_immutable_and_checked(shared_db: AppDatabase) -> None:
    owner = claimed(shared_db)
    assert isinstance(prepare(owner), Prepared)
    for column, value in (("creation_step", 2), ("creation_request_sha256", "b" * 64)):
        with pytest.raises(DBAPIError), workspace_transaction(shared_db.engine(APP_RUNTIME),
                                                             owner.scope.run.workspace_id) as conn:
            conn.execute(text(f"UPDATE app.action_proposals SET {column} = :v"), {"v": value})  # noqa: S608
    with shared_db.superuser() as conn:
        # Separate constraint fault injection from the immutable UPDATE trigger proved above.
        conn.execute("ALTER TABLE app.action_proposals DISABLE TRIGGER action_proposals_guard")
        try:
            for step, seal in ((None, "bad"), (1, None), (65, "a" * 64), (1, "BAD")):
                with pytest.raises(Exception, match="constraint"):
                    conn.execute("UPDATE app.action_proposals SET creation_step = %s, creation_request_sha256 = %s "
                                 "WHERE workspace_id = %s", (step, seal, owner.scope.run.workspace_id))
        finally:
            conn.execute("ALTER TABLE app.action_proposals ENABLE TRIGGER action_proposals_guard")


@pytest.mark.parametrize("step", [-1, 65, True])
def test_invalid_step_writes_nothing(shared_db: AppDatabase, step: Any) -> None:
    owner = claimed(shared_db)
    assert isinstance(prepare(owner, step=step), ProposalRefused)
    assert counts(owner) == (0, 0, 0, 0, 0, 0)
