"""T13's narrow foundation extension on real PostgreSQL as the actual app runtime: run-bound query embedding jobs
(exactly one input, derived binding, the run's shared budget scope, lifecycle checks before any write or cache use)
while default operation-bound ingestion jobs keep their identity and scope exactly. Scripted SDK transport only."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
import time
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from policyops.budget.config import Caps, Configuration
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.database import workspace_transaction
from policyops.persistence.embeddings import EmbeddingStore
from policyops.providers.embedding_calls import (
    QUERY_PURPOSE,
    BindingMismatch,
    EmbedLimits,
    JobReport,
    prepare_job,
    run_job,
)
from policyops_contracts.embedding import EmbeddingJob
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import TOKENIZER, Embeddings, World


pytestmark = pytest.mark.postgres
FAST = EmbedLimits(lease_seconds=60, wait_seconds=0.5, poll_seconds=0.05, attempt_seconds=30)


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    return World(shared_db, tmp_path)


def run(world: World, embeddings: Embeddings, *, purpose: str = QUERY_PURPOSE, subject: str, inputs: tuple[str, ...],
        run_id: UUID | None, configuration: Configuration | None = None) -> JobReport:
    configuration = configuration or Configuration()
    store = EmbeddingStore(world.engine, world.ws, env="test")
    ledger = build_app_ledger(env="test", engine=world.engine, workspace_id=world.ws, configuration=configuration)
    prepared = prepare_job(EmbeddingJob(purpose=purpose, subject_key=subject, inputs=inputs), configuration, TOKENIZER,
                           deadline=time.monotonic() + 30)
    return asyncio.run(run_job(ledger, store, embeddings.providers()(), prepared, deadline=time.monotonic() + 30,
                               limits=FAST, run_id=run_id))


def scopes_of(world: World, job_id: UUID) -> list[tuple[str, str | None, UUID | None]]:
    with workspace_transaction(world.engine, world.ws) as conn:
        rows = conn.execute(text(
            "SELECT s.kind, s.operation_key, s.run_id FROM app.embedding_batches b "
            "JOIN app.usage_attempts a ON a.id = b.attempt_id "
            "JOIN app.budget_scopes s ON s.workspace_id = a.workspace_id AND s.id = a.scope_id "
            "WHERE b.job_id = :job"), {"job": job_id}).all()
    return [tuple(r) for r in rows]


def test_default_operation_bound_jobs_are_unchanged(world: World) -> None:
    embeddings = Embeddings()
    report = run(world, embeddings, purpose="ingestion", subject="ingest.default", inputs=("One rule.", "Two."),
                 run_id=None)
    assert report.status == "complete" and len(embeddings.requests) == 1 and report.job_id is not None
    assert scopes_of(world, report.job_id) == [("operation", str(report.job_id), None)]


def test_a_run_bound_query_job_reserves_only_in_the_shared_run_scope(world: World) -> None:
    run_id = world.run()
    embeddings = Embeddings()
    report = run(world, embeddings, subject=f"query.{run_id}.1", inputs=("Where do refunds go?",), run_id=run_id)
    assert report.status == "complete" and report.physical_requests == 1 and report.job_id is not None
    assert scopes_of(world, report.job_id) == [("run", None, run_id)]


def test_two_steps_racing_for_the_last_run_call_have_one_winner(world: World) -> None:
    run_id = world.run()
    configuration = Configuration(caps=replace(Caps(), run_calls=1))
    embeddings = Embeddings()
    embeddings.delay = 0.3
    store = EmbeddingStore(world.engine, world.ws, env="test")
    ledger = build_app_ledger(env="test", engine=world.engine, workspace_id=world.ws, configuration=configuration)

    async def both() -> list[JobReport]:
        jobs = [prepare_job(EmbeddingJob(purpose=QUERY_PURPOSE, subject_key=f"query.{run_id}.{step}",
                                         inputs=(f"Question {step}?",)), configuration, TOKENIZER,
                            deadline=time.monotonic() + 30) for step in (1, 2)]
        return list(await asyncio.gather(*(run_job(ledger, store, embeddings.providers()(), job,
                                                   deadline=time.monotonic() + 30, limits=FAST, run_id=run_id)
                                           for job in jobs)))

    reports = asyncio.run(both())
    assert sorted(r.status for r in reports) == ["budget", "complete"] and len(embeddings.requests) == 1


@pytest.mark.parametrize("state", ["cancelled", "succeeded", "failed"])
def test_an_inactive_run_is_blocked_before_any_write_even_for_a_cache_hit(world: World, state: str) -> None:
    run_id = world.run()
    cached = run(world, Embeddings(), purpose="ingestion", subject="ingest.cache", inputs=("Cached text.",),
                 run_id=None)
    assert cached.status == "complete"
    world.end(run_id, state)
    jobs_before = world.count("app.embedding_jobs")
    embeddings = Embeddings()
    report = run(world, embeddings, subject=f"query.{run_id}.1", inputs=("Cached text.",), run_id=run_id)
    assert (report.status, report.reason, report.job_id) == ("blocked", "run_not_active", None)
    assert world.count("app.embedding_jobs") == jobs_before and embeddings.requests == []


def test_another_workspaces_run_reads_as_absent(world: World, shared_db: AppDatabase, tmp_path: Path) -> None:
    foreign = World(shared_db, tmp_path / "other").run()
    report = run(world, Embeddings(), subject=f"query.{foreign}.1", inputs=("Text.",), run_id=foreign)
    assert (report.status, report.reason) == ("blocked", "run_not_active")


@pytest.mark.parametrize(("purpose", "subject", "inputs", "run_kind"), [
    (QUERY_PURPOSE, "query.{other}.1", ("Text.",), "own"),  # the subject names another run
    (QUERY_PURPOSE, "query.{own}.1", ("One.", "Two."), "own"),  # not exactly one input
    (QUERY_PURPOSE, "query.{own}.1", ("Text.",), None),  # a query job without a run
    ("ingestion", "ingest.x", ("Text.",), "own"),  # an operation job with a run
])
def test_bindings_the_identity_does_not_admit_are_refused_before_any_write(
        world: World, purpose: str, subject: str, inputs: tuple[str, ...], run_kind: str | None) -> None:
    own = world.run()
    jobs_before = world.count("app.embedding_jobs")
    with pytest.raises(BindingMismatch):
        run(world, Embeddings(), purpose=purpose, subject=subject.format(own=own, other=uuid4()), inputs=inputs,
            run_id=own if run_kind else None)
    assert world.count("app.embedding_jobs") == jobs_before


def test_an_unknown_outcome_keeps_its_hold_and_is_never_reissued(world: World) -> None:
    run_id = world.run()
    embeddings = Embeddings()
    embeddings.fail = True
    first = run(world, embeddings, subject=f"query.{run_id}.1", inputs=("Ambiguous?",), run_id=run_id)
    assert first.status != "complete" and len(embeddings.requests) == 1
    embeddings.fail = False
    again = run(world, embeddings, subject=f"query.{run_id}.1", inputs=("Ambiguous?",), run_id=run_id)
    assert again.status != "complete" and len(embeddings.requests) == 1  # no second request
    with workspace_transaction(world.engine, world.ws) as conn:
        held = conn.execute(text("SELECT held_usd > 0 FROM app.budget_scopes WHERE run_id = :r"),
                            {"r": run_id}).scalar_one()
    assert held


def test_a_cache_hit_makes_no_call(world: World) -> None:
    run_id = world.run()
    assert run(world, Embeddings(), purpose="ingestion", subject="ingest.c", inputs=("Shared text.",),
               run_id=None).status == "complete"
    embeddings = Embeddings()
    report = run(world, embeddings, subject=f"query.{run_id}.1", inputs=("Shared text.",), run_id=run_id)
    assert report.status == "complete" and embeddings.requests == [] and len(report.vectors) == 1
