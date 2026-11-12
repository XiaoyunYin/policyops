"""Revision 0009 (T12 embedding foundation) on real PostgreSQL: a populated 0008 database dumped and restored into a
separate database upgrades with every old row intact and then runs an embedding job; a populated 0009 downgrade is
refused by default and drops only its own tables with the explicit destructive override; an empty one downgrades
and re-upgrades cleanly. Constraints are checked as the actual runtime role."""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json
import time
from uuid import uuid4

import httpx2
from psycopg import errors as pg_errors
from pydantic import SecretStr
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from policyops.budget.config import Configuration
from policyops.budget.ledger import OperationBinding, Settlement
from policyops.budget.pricing import Usage
from policyops.domain.examples import World
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.database import workspace_transaction
from policyops.persistence.embeddings import EmbeddingStore
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.roles import APP_RUNTIME
from policyops.providers import tokenizer as tk
from policyops.providers.calls import Providers
from policyops.providers.embedding_calls import EmbedLimits, prepare_job, run_job
from policyops_contracts.embedding import EmbeddingJob
from policyops_testing.app_database import AppCluster, AppDatabase, NewDatabase
from policyops_testing.migration_fixtures import seed_world


pytestmark = pytest.mark.postgres
APP_SCHEMAS = ("identity", "app", "evaluation", "checkpoints")
NEW_TABLES = ("app.embedding_jobs", "app.embedding_job_inputs", "app.embedding_batches",
              "app.embedding_attempt_evidence", "app.embedding_cache")
FAST = EmbedLimits(lease_seconds=60.0, wait_seconds=0.5, poll_seconds=0.05, attempt_seconds=30.0)
TOKENIZER = tk.load()


class Provider(httpx2.AsyncBaseTransport):
    """A scripted embeddings endpoint answering every request validly; counts physical requests."""

    def __init__(self) -> None:
        self.requests: list[list[str]] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        inputs = json.loads(await request.aread())["input"]
        self.requests.append(inputs)
        tokens = sum(TOKENIZER.counts(inputs))
        body = {"object": "list", "model": "text-embedding-3-small",
                "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
                "data": [{"object": "embedding", "index": i, "embedding": [0.01 * (1 + i)] * 1536}
                         for i in range(len(inputs))]}
        return httpx2.Response(200, headers={"content-type": "application/json"}, content=json.dumps(body).encode(),
                               request=request)


def providers(provider: Provider) -> Providers:
    return Providers(credentials={"openai": SecretStr("synthetic-test-credential-0000")},
                     transport=lambda name: provider)


def counts(database: AppDatabase) -> dict[str, int]:
    with database.superuser() as conn:
        tables = [row[0] for row in conn.execute(
            "SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname = ANY(%s) ORDER BY 1",
            (list(APP_SCHEMAS),)).fetchall()]
        # Table names come from pg_tables of this owned test database, not from input.
        return {table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
                for table in tables}


def populate_0008(database: AppDatabase) -> None:
    """The synthetic world plus one settled operation-scope ledger attempt (0006/0007 rows)."""
    from policyops_testing.migration_fixtures import seed_at_head

    with seed_at_head(database):
        seed_world(database)
        world = World()
        books = build_app_ledger(env="test", engine=database.engine(APP_RUNTIME), workspace_id=world.workspace,
                                 configuration=Configuration())
        attempt = uuid4()
        books.reserve(OperationBinding("legacy", "before-0009"), attempt, "agent", "op.r0.a0", "c" * 64)
        books.claim_count(attempt, "c" * 64)
        books.record_count(attempt, tokens=100, source="openai.count")
        books.begin_dispatch(attempt, "c" * 64)
        books.settle(attempt, Settlement(Usage(input_total=100, output=10), "req_legacy_1"))


def test_a_populated_0008_dump_upgrades_to_0009_intact_and_runs_a_job(app_cluster: AppCluster,
                                                                      new_app_database: NewDatabase) -> None:
    source = new_app_database("emb_0008_src", revision="0008")
    populate_0008(source)
    target = new_app_database("emb_0008_dst", extensions=False, revision=None)
    dump = app_cluster.server.dump_and_restore(source.name, target.name)
    assert dump.is_file() and dump.stat().st_size > 0
    target.report = target.provision_extensions()
    before = counts(target)
    assert before == counts(source) and target.current() == "0008"
    assert before["app.usage_attempts"] == 1 and before["app.case_messages"] > 0
    assert not set(NEW_TABLES) & set(before)
    target.upgrade("0009")  # this revision's own upgrade (0010 has its own migration tests)
    after = counts(target)
    assert target.current() == "0009"
    assert {table: after[table] for table in before} == before  # nothing changed in pre-existing tables
    assert {table: after[table] for table in NEW_TABLES} == dict.fromkeys(NEW_TABLES, 0)
    target.upgrade()
    world = World()
    engine = target.engine(APP_RUNTIME, pool_size=6)
    ledger = build_app_ledger(env="test", engine=engine, workspace_id=world.workspace,
                                  configuration=Configuration())
    store = EmbeddingStore(engine, world.workspace, env="test")
    prepared = prepare_job(EmbeddingJob(purpose="ingest", subject_key="after-upgrade", inputs=("One rule.",)),
                           Configuration(), TOKENIZER, deadline=time.monotonic() + 60)
    provider = Provider()
    report = asyncio.run(run_job(ledger, store, providers(provider), prepared, deadline=time.monotonic() + 60,
                                 limits=FAST))
    assert report.status == "complete" and len(provider.requests) == 1
    with target.superuser() as conn:
        legacy = conn.execute("SELECT state, actual_usd FROM app.usage_attempts WHERE operation_id = 'op.r0.a0'"
                              ).fetchone()
    assert legacy is not None and legacy[0] == "settled" and legacy[1] > Decimal(0)  # the old row still settles


def run_one(database: AppDatabase) -> None:
    from policyops_testing.migration_fixtures import seed_at_head

    with seed_at_head(database):
        world = World()
        engine = database.engine(APP_RUNTIME, pool_size=6)
        ledger = build_app_ledger(env="test", engine=engine, workspace_id=world.workspace,
                                  configuration=Configuration())
        prepared = prepare_job(EmbeddingJob(purpose="ingest", subject_key=f"s-{uuid4().hex[:8]}", inputs=("A rule.",)),
                               Configuration(), TOKENIZER, deadline=time.monotonic() + 60)
        report = asyncio.run(run_job(ledger, EmbeddingStore(engine, world.workspace, env="test"), providers(Provider()),
                                     prepared, deadline=time.monotonic() + 60, limits=FAST))
        assert report.status == "complete"


def test_a_populated_0009_downgrade_is_refused_unless_explicitly_destructive(new_app_database: NewDatabase) -> None:
    database = new_app_database("emb_downgrade", revision="0009")
    seed_world(database)
    run_one(database)
    with pytest.raises(DataLossRefused, match=r"app\.embedding"):
        database.downgrade("0008")
    assert database.current() == "0009"
    with database.superuser() as conn:
        forced = conn.execute("SELECT bool_and(relforcerowsecurity) FROM pg_class c JOIN pg_namespace n "
                              "ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relkind = 'r'").fetchone()
    assert forced == (True,)  # the refusal rolled back the temporary NO FORCE
    kept = counts(database)
    database.downgrade("0008", allow_data_loss=True)  # the explicit destructive override: the vectors are lost
    after = counts(database)
    assert database.current() == "0008" and not set(NEW_TABLES) & set(after)
    assert {table: after[table] for table in after} == {table: kept[table] for table in after}


def test_an_empty_0009_downgrades_and_upgrades_again_cleanly(new_app_database: NewDatabase) -> None:
    database = new_app_database("emb_empty_downgrade", revision="0009")
    database.downgrade("0008")
    assert database.current() == "0008" and not set(NEW_TABLES) & set(counts(database))
    database.upgrade("0009")
    assert database.current() == "0009" and set(NEW_TABLES) <= set(counts(database))


@pytest.mark.parametrize(("statement", "constraint"), [
    ("INSERT INTO app.embedding_job_inputs (workspace_id, job_id, position, input_sha256, text, local_tokens) "
     "SELECT workspace_id, id, 9, repeat('0', 64), 'a text whose digest is not zeros', 3 FROM app.embedding_jobs",
     "embedding_job_inputs_text_digest"),
    ("UPDATE app.embedding_batches SET state = 'gone'", "embedding_batches_state_values"),
    ("UPDATE app.embedding_batches SET lease_owner = gen_random_uuid(), lease_until = NULL",
     "embedding_batches_lease_pair"),
])
def test_named_constraints_hold_for_the_runtime_role(new_app_database: NewDatabase, statement: str,
                                                     constraint: str) -> None:
    database = new_app_database("emb_constraints")
    seed_world(database)
    run_one(database)
    with pytest.raises(IntegrityError, match=constraint), \
            workspace_transaction(database.engine(APP_RUNTIME), World().workspace) as conn:
        conn.execute(text(statement))


def test_evidence_usage_must_be_consistent_unless_recorded_as_a_contradiction(
        new_app_database: NewDatabase) -> None:
    database = new_app_database("emb_evidence_check")
    seed_world(database)
    run_one(database)
    with pytest.raises(pg_errors.CheckViolation, match="embedding_evidence_consistent_usage"), \
            database.superuser() as conn:
        conn.execute("UPDATE app.embedding_attempt_evidence SET total_tokens = prompt_tokens + 1 "
                     "WHERE outcome = 'published'")
