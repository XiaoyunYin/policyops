"""T14 validation and citation recording composed: real PostgreSQL as the actual app runtime, real T13 step traces,
the unchanged T12 citation guard and read port. Forged and rebound bundles, equal and unequal existing IDs, subset and
superset batches, a fault before COMMIT and a lost COMMIT acknowledgement (explicit test-only fault plan), concurrent
recorders, activation ordering against the corpus share lock, late phase returns under a controlled clock, and
historical reconciliation after an activation. Synthetic text only; no provider HTTP.

Not claimed: entailment or authorization, currency after commit, or interruption of a waiting SQL statement."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
import hashlib
from pathlib import Path
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import pytest

from policyops.persistence import citations as citations_module
from policyops.persistence import retrieval as retrieval_store
from policyops.persistence.citations import CitationRecorder, FaultPlan, RecorderFault, citation_id
from policyops.persistence.corpora import CorpusStore
from policyops.retrieval.grounding import EvidenceValidator
from policyops_contracts.grounding import (
    Assertion,
    CitationBundle,
    CitedQuote,
    GroundedAnswer,
    GroundingRefused,
    ValidatedAnswer,
)
from policyops_contracts.retrieval import RetrievalConfig, RetrievalQuery, RetrievalResult, RetrievalScope
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import Embeddings, World, documents, run_threads


pytestmark = pytest.mark.postgres
KEY = "test-banking"
V1 = [("a", "Refunds", "Refunds go back to the original payment method within ten days."),
      ("b", "Gift cards", "Gift card refunds are instant and final."),
      ("c", "Shipping", "Orders ship within five business days.")]
V2 = [(k, t, c.replace("ten days", "twenty days")) for k, t, c in V1]


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    world = World(shared_db, tmp_path)
    world.publish(documents(V1), key=KEY)
    return world


def retrieve(world: World, run: UUID, step: int, text_value: str = "refunds") -> RetrievalResult:
    query = RetrievalQuery(text=text_value, run_id=run, step=step, scope=RetrievalScope(corpus_key=KEY),
                           config=RetrievalConfig(mode="lexical"))
    result = asyncio.run(world.retriever(Embeddings()).retrieve(query, deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalResult) and result.evidence, result
    return result


def cite(result: RetrievalResult, fragment: str) -> CitedQuote:
    """A quote of `fragment` from the delivered evidence that contains it (offsets omitted: it must be unique)."""
    evidence = next(e for e in result.evidence if fragment in e.text)
    return CitedQuote(step=result.step, evidence_id=evidence.evidence_id, quote=fragment, start=None, end=None)


def answer(*groups: Sequence[CitedQuote]) -> GroundedAnswer:
    return GroundedAnswer(v="policyops.grounded-answer/v1", outcome="answer", abstention=None, assertions=tuple(
        Assertion(text="A policy claim.", policy_dependent=True, citations=tuple(g)) for g in groups))


def validate(world: World, run: UUID, value: GroundedAnswer, *, steps: Sequence[int] = (1, 2),
             clock: Any = time.monotonic, corpus: str = KEY, engine_world: World | None = None
             ) -> ValidatedAnswer | GroundingRefused:
    owner = engine_world or world
    return EvidenceValidator(owner.engine, owner.ws, clock=clock).validate(
        value, run_id=run, authorized_steps=tuple(steps), corpus_key=corpus, deadline=time.monotonic() + 60
        if clock is time.monotonic else 100.0)


def grounded(world: World, run: UUID, *groups: Sequence[CitedQuote]) -> CitationBundle:
    result = validate(world, run, answer(*groups))
    assert isinstance(result, ValidatedAnswer) and result.outcome == "grounded" and result.bundle, result
    return result.bundle


def recorder(world: World, *, clock: Any = time.monotonic, faults: FaultPlan | None = None) -> CitationRecorder:
    return CitationRecorder(world.engine, world.ws, clock=clock, env="test" if faults else None, faults=faults)


def record(world: World, bundle: CitationBundle, run: UUID, *, steps: Sequence[int] = (1, 2),
           **kwargs: Any) -> Any:
    deadline = kwargs.pop("deadline", time.monotonic() + 60)
    return recorder(world, **kwargs).record(bundle, run_id=run, authorized_steps=tuple(steps), corpus_key=KEY,
                                            deadline=deadline)


def reconcile(world: World, bundle: CitationBundle, run: UUID, *, steps: Sequence[int] = (1, 2),
              **kwargs: Any) -> Any:
    deadline = kwargs.pop("deadline", time.monotonic() + 60)
    return recorder(world, **kwargs).reconcile(bundle, run_id=run, authorized_steps=tuple(steps), corpus_key=KEY,
                                               deadline=deadline)


def subset(bundle: CitationBundle, *indexes: int) -> CitationBundle:
    return bundle.model_copy(update={"claims": tuple(bundle.claims[i] for i in indexes)})


def ids(world: World, bundle: CitationBundle) -> list[UUID]:
    return [citation_id(world.ws, c.trace_id, c.chunk_id, c.span_start, c.span_end) for c in bundle.claims]


class Countdown:
    """A controlled clock: 0 until its `expire_at`-th reading, then far past every deadline used here."""

    def __init__(self, expire_at: int) -> None:
        self.expire_at, self.readings = expire_at, 0

    def __call__(self) -> float:
        self.readings += 1
        return 1e9 if self.readings >= self.expire_at else 0.0


# -- validation ----------------------------------------------------------------------------------------------------

def test_validation_scopes_runs_tenants_and_corpora(world: World, shared_db: AppDatabase, tmp_path: Path) -> None:
    run, other_run = world.run(), world.run()
    first = retrieve(world, run, 1)
    retrieve(world, other_run, 2, "gift card")
    value = answer([cite(first, "ten days")])
    assert isinstance(ok := validate(world, run, value), ValidatedAnswer) and ok.outcome == "grounded"
    stranger = World(shared_db, tmp_path / "stranger")  # another tenant cannot address this run's step
    foreign = validate(world, run, value, engine_world=stranger)
    assert isinstance(foreign, ValidatedAnswer) and foreign.citations[0].status == "trace_not_found"
    same_tenant = validate(world, run, answer([CitedQuote(step=2, evidence_id="E1", quote="instant", start=None,
                                                          end=None)]))
    assert isinstance(same_tenant, ValidatedAnswer) and same_tenant.citations[0].status == "trace_not_found"
    wrong = validate(world, run, value, corpus="other-corpus")
    assert isinstance(wrong, ValidatedAnswer) and wrong.citations[0].status == "corpus_mismatch"


@pytest.mark.parametrize("tamper", ["trace", "body"])
def test_a_tampered_trace_or_version_body_is_caught(world: World, tamper: str) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    with world.db.superuser() as conn:
        if tamper == "trace":
            conn.execute("UPDATE app.retrieval_traces SET candidates = jsonb_set(candidates, '{evidence_tokens}', "
                         "'1') WHERE id = %s", (first.trace_id,))
        else:  # test fixture: bypass the immutability guard to corrupt the stored body
            conn.execute("SET session_replication_role = replica")
            conn.execute("UPDATE app.document_versions SET body = body || ' tampered' WHERE id = %s",
                         (first.evidence[0].document_version_id,))
            conn.execute("SET session_replication_role = DEFAULT")
    result = validate(world, run, answer([cite(first, first.evidence[0].text[:12])]))
    assert isinstance(result, ValidatedAnswer) and result.citations[0].status == "trace_integrity"


def test_activation_makes_evidence_stale_and_generations_never_mix(world: World) -> None:
    run = world.run()
    before = retrieve(world, run, 1)
    world.publish(documents(V2), key=KEY)
    stale = validate(world, run, answer([cite(before, "ten days")]))
    assert isinstance(stale, ValidatedAnswer) and stale.outcome == "stale_evidence" and not stale.generation_current
    after = retrieve(world, run, 2)
    mixed = validate(world, run, answer([cite(before, "ten days")], [cite(after, "twenty days")]))
    assert isinstance(mixed, ValidatedAnswer)
    assert [c.status for c in mixed.citations] == ["mixed_generation", "mixed_generation"] and mixed.bundle is None


@pytest.mark.parametrize("expire_at", [2, 3, 4, 5])
def test_late_validation_reads_return_no_result(world: World, expire_at: int) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    clock = Countdown(expire_at)  # 1 entry, 2 step record, 3 spans, 4 pointer, 5 final
    result = validate(world, run, answer([cite(first, "ten days")]), clock=clock)
    assert result == GroundingRefused(code="deadline_passed") and clock.readings == expire_at


# -- recording -----------------------------------------------------------------------------------------------------

def test_a_recorded_bundle_resolves_to_its_quotes_and_replays_as_existing(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days"), cite(first, "instant and final")])
    outcome = record(world, bundle, run)
    assert (outcome.status, outcome.committed, outcome.inserted, outcome.existing) == ("recorded", "observed", 2, 0)
    store = CorpusStore(world.engine, world.ws)
    for claim, identifier in zip(bundle.claims, outcome.claim_ids, strict=True):
        assert store.resolve_citation_text(identifier, run).text == claim.quote
    again = record(world, bundle, run)
    assert (again.status, again.inserted, again.existing, again.existing_ids) == ("recorded", 0, 2,
                                                                                  outcome.distinct_ids)
    assert world.count("app.citations") == 2


def other_chunk(world: World, generation: UUID, delivered: Sequence[UUID]) -> tuple[UUID, UUID]:
    with world.db.superuser() as conn:
        row = conn.execute("SELECT id, document_version_id FROM app.chunks WHERE generation_id = %s AND NOT "
                           "(id = ANY(%s)) LIMIT 1", (generation, list(delivered))).fetchone()
    assert row is not None
    return row[0], row[1]


@pytest.mark.parametrize("forge", ["quote", "quote_digest", "span", "chunk", "trace", "other_run", "undelivered"])
def test_forged_or_rebound_bundles_refuse_and_write_nothing(world: World, forge: str) -> None:
    run, other_run = world.run(), world.run()
    first = retrieve(world, run, 1, "ten days")
    elsewhere = retrieve(world, other_run, 1, "gift card")
    claim = grounded(world, run, [cite(first, "ten days")]).claims[0]
    if forge == "quote":
        changes: dict[str, Any] = {"quote": "ten dayz",
                                   "quote_sha256": hashlib.sha256(b"ten dayz").hexdigest()}
    elif forge == "quote_digest":
        changes = {"quote": "ten dayz"}
    elif forge == "span":
        changes = {"span_start": claim.span_start + 1, "span_end": claim.span_end + 1}
    elif forge == "chunk":
        changes = {"chunk_id": uuid4()}
    elif forge == "trace":
        changes = {"trace_id": elsewhere.trace_id}
    elif forge == "other_run":  # another run's verified claim presented for this run
        changes = grounded(world, other_run, [cite(elsewhere, "instant")]).claims[0].model_dump()
    else:  # a ready chunk of this generation that this step never delivered
        chunk, version = other_chunk(world, first.generation_id, [e.chunk_id for e in first.evidence])
        changes = {"chunk_id": chunk, "document_version_id": version}
    forged = CitationBundle(run_id=run, corpus_key=KEY, claims=(claim.model_copy(update=changes),))
    outcome = record(world, forged, run, steps=(1,))
    expected = {"quote": "quote", "quote_digest": "quote_sha256", "span": "quote", "chunk": "chunk_id",
                "trace": "trace_id", "other_run": "trace_id", "undelivered": "chunk_id"}[forge]
    assert (outcome.status, outcome.code, outcome.failing_claim) == ("refused", f"record_claim_mismatch:{expected}", 0)
    assert world.count("app.citations") == 0
    assert reconcile(world, forged, run, steps=(1,)).status == "citation_integrity"


def test_an_unequal_existing_id_is_a_conflict_for_record_and_reconcile(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days")])
    claim = bundle.claims[0]
    with world.db.superuser() as conn:  # the deterministic ID, another span (fixture row)
        conn.execute("INSERT INTO app.citations (id, workspace_id, trace_id, chunk_id, document_version_id, "
                     "span_start, span_end, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, now())",
                     (ids(world, bundle)[0], world.ws, claim.trace_id, claim.chunk_id, claim.document_version_id,
                      claim.span_start - 1, claim.span_end))
    outcome = record(world, bundle, run)
    assert (outcome.status, outcome.code) == ("refused", "citation_id_conflict")
    assert reconcile(world, bundle, run).status == "citation_id_conflict"
    assert world.count("app.citations") == 1


def test_subsets_supersets_and_a_failure_before_commit(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    both = grounded(world, run, [cite(first, "ten days"), cite(first, "instant and final")])
    only_a = subset(both, 0)
    assert record(world, only_a, run).inserted == 1
    with pytest.raises(RecorderFault):  # after the full recheck, inserts and read-back; COMMIT never sent
        record(world, both, run, faults=FaultPlan(before_commit=True))
    partial = reconcile(world, both, run)
    a_id, b_id = ids(world, both)
    assert (partial.status, partial.matched_ids, partial.missing_ids) == ("incomplete", (a_id,), (b_id,))
    retried = record(world, both, run)
    assert (retried.status, retried.inserted, retried.existing) == ("recorded", 1, 1)
    assert record(world, both, run).existing == 2 and world.count("app.citations") == 2
    forged = both.model_copy(update={"claims": (both.claims[0], both.claims[1].model_copy(update={"quote": "x"}))})
    refused = record(world, forged, run)
    assert refused.code == "record_claim_mismatch:quote_sha256" and refused.failing_claim == 1
    assert set(refused.existing_ids) == {a_id, b_id}  # the forged quote is the claim's mismatch, not a conflict
    assert reconcile(world, forged, run).status == "citation_integrity"


def test_an_ambiguous_commit_is_never_success_and_reconciles(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days")])
    lost = record(world, bundle, run, faults=FaultPlan(after_commit=True))
    assert (lost.status, lost.committed, lost.claim_ids) == ("record_ambiguous", "unknown", tuple(ids(world, bundle)))
    assert reconcile(world, bundle, run).status == "recorded"
    other = grounded(world, run, [cite(first, "instant and final")])
    with pytest.raises(RecorderFault):
        record(world, other, run, faults=FaultPlan(before_commit=True))
    unseen = reconcile(world, other, run)
    assert unseen.status == "not_observed_yet" and not unseen.absence_proven  # never a definitive "not recorded"
    assert record(world, other, run).status == "recorded"


def test_concurrent_recorders_of_the_same_span(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days")])
    outcomes: list[Any] = []
    run_threads(world.db, [lambda: outcomes.append(record(world, bundle, run)) for _ in range(2)], timeout=60)
    assert sorted((o.status, o.inserted, o.existing) for o in outcomes) == [("recorded", 0, 1), ("recorded", 1, 0)]
    assert world.count("app.citations") == 1


def test_duplicate_claims_across_assertions_are_deduplicated(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    a, b = cite(first, "ten days"), cite(first, "instant and final")
    bundle = grounded(world, run, [a, b], [a])
    outcome = record(world, bundle, run)
    assert (outcome.claims, outcome.distinct, outcome.inserted) == (3, 2, 2)
    assert outcome.claim_ids[0] == outcome.claim_ids[2] and list(outcome.distinct_ids) == sorted(set(outcome.claim_ids))


def test_reconciliation_is_historical_after_an_activation_and_new_writes_need_current_evidence(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days"), cite(first, "instant and final")])
    assert record(world, subset(bundle, 0), run).status == "recorded"
    world.publish(documents(V2), key=KEY)  # the cited chunks are now hidden behind the ready-only chunk policy
    history = reconcile(world, subset(bundle, 0), run)
    assert (history.status, history.generation_current) == ("recorded", False)
    late = record(world, bundle, run)
    assert (late.status, late.code, late.existing_ids) == ("refused", "stale_evidence", tuple(ids(world, bundle)[:1]))
    assert world.count("app.citations") == 1


def test_a_held_corpus_row_lock_orders_the_recorder(world: World) -> None:
    """The actual row-lock ordering: a transaction holding the corpus row FOR UPDATE (as T12 publication takes it)
    blocks the recorder's FOR SHARE until it ends. The holder commits UNCHANGED: this is not a concurrent generation
    mutation (a completed activation before recording is the separate sequential stale-evidence case)."""
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days")])
    locked, release = threading.Event(), threading.Event()
    outcomes: list[Any] = []

    def activation() -> None:  # holds the row FOR UPDATE, as T12 publication does, then commits unchanged
        with world.db.superuser() as conn, conn.transaction():
            conn.execute("SELECT 1 FROM app.corpora WHERE workspace_id = %s AND corpus_key = %s FOR UPDATE",
                         (world.ws, KEY))
            locked.set()
            release.wait(30)

    def waiting_recorder() -> None:
        locked.wait(30)
        outcomes.append(record(world, bundle, run))

    def observer() -> None:
        locked.wait(30)
        deadline = time.monotonic() + 20
        try:
            while time.monotonic() < deadline:
                with world.db.superuser() as conn:
                    waiting = conn.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                                           "AND wait_event_type = 'Lock' AND query LIKE %s",
                                           ("%FOR SHARE%",)).fetchone()[0]
                if waiting:
                    outcomes.append("blocked")
                    return
                time.sleep(0.05)
        finally:
            release.set()

    run_threads(world.db, [activation, waiting_recorder, observer], timeout=60)
    assert "blocked" in outcomes and [o.status for o in outcomes if o != "blocked"] == ["recorded"]


@pytest.mark.parametrize(("expire_at", "status", "committed", "rows"), [
    (2, "deadline_passed", "none", 0),      # the share-lock wait: no further read
    (4, "deadline_passed", "none", 0),      # after the step-record read: spans never read, rollback
    (6, "deadline_passed", "none", 0),      # before any write
    (7, "deadline_passed", "none", 0),      # before COMMIT
    (8, "deadline_passed", "observed", 1),  # COMMIT acknowledged late: rows kept
    (9, "deadline_passed", "observed", 1),  # the connection cleanup returned late: never a success
    (10, "recorded", "observed", 1),
])
def test_record_phase_guards_under_a_controlled_clock(world: World, monkeypatch: pytest.MonkeyPatch, expire_at: int,
                                                      status: str, committed: str, rows: int) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days")])
    span_reads: list[int] = []
    original = retrieval_store.read_spans

    def counted(connection: Any, entries: Any) -> Any:
        span_reads.append(1)
        return original(connection, entries)

    monkeypatch.setattr(citations_module, "read_spans", counted)
    # Readings: 1 entry, 2 lock, 3 existing rows, 4 step record, 5 spans, 6 pre-write, 7 pre-commit, 8 commit,
    # 9 close.
    clock = Countdown(expire_at)
    outcome = record(world, bundle, run, clock=clock, deadline=100.0)
    assert (outcome.status, outcome.committed) == (status, committed) and world.count("app.citations") == rows
    assert clock.readings == min(expire_at, 9) and span_reads == ([] if expire_at <= 4 else [1])
    if rows:
        assert outcome.inserted == 1 and outcome.distinct_ids == tuple(ids(world, bundle))


@pytest.mark.parametrize("expire_at", [2, 3, 4, 5])
def test_reconcile_never_returns_after_its_deadline(world: World, expire_at: int) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days")])
    record(world, bundle, run)
    clock = Countdown(expire_at)  # 1 entry, 2 rows, 3 step record, 4 spans, 5 final
    outcome = reconcile(world, bundle, run, clock=clock, deadline=100.0)
    assert outcome.status == "deadline_passed" and clock.readings == expire_at


def test_a_mismatched_context_refuses_before_any_read(world: World) -> None:
    run = world.run()
    first = retrieve(world, run, 1)
    bundle = grounded(world, run, [cite(first, "ten days")])
    for change in ({"run": world.run()}, {"steps": (2,)}):
        outcome = reconcile(world, bundle, change.get("run", run), steps=change.get("steps", (1,)))  # type: ignore[arg-type]
        assert (outcome.status, outcome.code) == ("refused", "record_context_mismatch")

