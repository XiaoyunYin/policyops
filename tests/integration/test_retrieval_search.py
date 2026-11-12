"""T13 retrieval on real PostgreSQL as the actual app runtime, over corpora published through the real T12 ingestion
and the real embedding foundation with a scripted transport (exact chosen vectors; no external HTTP): exact cosine
distances and total ties, FTS phrase/ID/hostile input, hybrid RRF, tenancy, allowlists and retired generations, the
retail-only full policy, the evidence budget and trace contents, availability fallback versus refusals, deadlines,
cancellation, invalid vectors, NaN exclusions, query plans, step-job identity and zero-batch jobs.

Synthetic fixtures prove mechanics only, never retrieval quality."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import time
from typing import Any
from uuid import UUID, uuid4

import pytest

from policyops.budget.config import Caps, Configuration
from policyops.persistence.embeddings import EmbeddingStore
from policyops.persistence.retrieval import CANDIDATES_LIMIT, DENSE_SQL, LEXICAL_SQL, SCOPE_LIMIT
from policyops.providers.embedding_calls import QUERY_PURPOSE, EmbedLimits, prepare_job, run_job
from policyops.providers.embeddings import input_sha256
from policyops.retrieval.search import subject_for
from policyops_contracts.embedding import EmbeddingJob
from policyops_contracts.retrieval import (
    RetrievalConfig,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    RetrievalScope,
    TraceCandidates,
)
from policyops_testing.app_database import AppDatabase
from policyops_testing.claims import component_ledger as build_app_ledger
from policyops_testing.retrieval_fixtures import (
    TOKENIZER,
    Embeddings,
    World,
    axis,
    documents,
    embed_input,
    explain,
    owned_task,
    until_started,
)


pytestmark = pytest.mark.postgres
KEY = "test-banking"
DOCS = [("a", "Refunds", "Refunds go back to the original payment method within ten days."),
        ("b", "Exchanges", "Exchanges keep the same product type and size."),
        ("c", "Gift cards", "Store credit is added to an existing gift card."),
        ("d", "Shipping", "Orders ship within five business days.")]
VECTORS = {embed_input(t, c): v for (_, t, c), v in zip(DOCS, (axis(0), axis(1), axis(0, -1.0), axis(2)), strict=True)}
QUERY = "money back to my card"
FAST = EmbedLimits(lease_seconds=60, wait_seconds=0.5, poll_seconds=0.05, attempt_seconds=30)


def uri(key: str) -> str:
    return f"tau2:banking_knowledge/{key}"


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    world = World(shared_db, tmp_path)
    world.publish(documents(DOCS), key=KEY, embeddings=Embeddings(VECTORS))
    return world


def query_for(world: World, text_value: str = QUERY, *, mode: str = "hybrid", run_id: UUID | None = None,
              step: int = 1, corpus_key: str = KEY, allowlist: tuple[str, ...] = (), **config: Any) -> RetrievalQuery:
    return RetrievalQuery(text=text_value, run_id=run_id or world.run(), step=step,
                          scope=RetrievalScope(corpus_key=corpus_key, document_allowlist=allowlist),
                          config=RetrievalConfig(mode=mode, **config))  # type: ignore[arg-type]


def ask(world: World, embeddings: Embeddings, text_value: str = QUERY, *, deadline: float | None = None,
        configuration: Configuration | None = None, **kwargs: Any) -> RetrievalResult | RetrievalRefused:
    query = query_for(world, text_value, **kwargs)
    retriever = world.retriever(embeddings, configuration=configuration)
    return asyncio.run(retriever.retrieve(query, deadline=time.monotonic() + 60 if deadline is None else deadline))


def ok(result: RetrievalResult | RetrievalRefused) -> RetrievalResult:
    assert isinstance(result, RetrievalResult), result
    return result


def refused(result: RetrievalResult | RetrievalRefused, code: str) -> None:
    assert isinstance(result, RetrievalRefused) and result.code == code, result


def uris(world: World, document_ids: list[UUID]) -> list[str]:
    with world.db.superuser() as conn:
        found = dict(conn.execute("SELECT id, source_uri FROM app.documents WHERE id = ANY(%s)",
                                  (document_ids,)).fetchall())
    return [found[d] for d in document_ids]


def test_exact_cosine_distances_and_total_ties(world: World) -> None:
    result = ok(ask(world, Embeddings({QUERY: axis(0)}), mode="dense"))
    assert uris(world, [d.document_id for d in result.dense]) == [uri("a"), uri("b"), uri("d"), uri("c")]
    assert [d.score for d in result.dense] == ["0", "1", "1", "2"]  # b and d tie at 1: ordered by source URI
    assert result.dense_status == "ok" and result.provider_requests == 1 and result.lexical == ()


def test_lexical_phrase_bag_of_words_ids_and_hostile_text(world: World, shared_db: AppDatabase,
                                                         tmp_path: Path) -> None:
    phrase = ok(ask(world, Embeddings(), '"original payment method"', mode="lexical"))
    assert uris(world, [d.document_id for d in phrase.lexical]) == [uri("a")]
    loose = ok(ask(world, Embeddings(), "days", mode="lexical"))
    assert sorted(uris(world, [d.document_id for d in loose.lexical])) == [uri("a"), uri("d")]
    ids = World(shared_db, tmp_path / "ids")
    ids.publish(documents([("o", "Orders", "Order #W2378156 and product 1000000001 were cancelled.")]), key=KEY)
    observed = {token: bool(ok(ask(ids, Embeddings(), token, mode="lexical")).lexical)
                for token in ("W2378156", "#W2378156", "1000000001")}
    (tmp_path / "id-tokenization.json").write_text(json.dumps(observed), encoding="utf-8")  # recorded evidence
    assert observed["1000000001"] and observed["W2378156"]
    for hostile in ("'); DROP TABLE app.chunks; --", "&|!:*", "' \" ( ) <-> ! :* | &"):
        assert isinstance(ask(world, Embeddings(), hostile, mode="lexical"), RetrievalResult)
    empty = ok(ask(world, Embeddings(), "the and of", mode="lexical"))
    assert empty.lexical_status == "empty_query" and empty.lexical == () and empty.evidence == ()


def test_hybrid_fuses_both_branches_with_exact_rrf(world: World) -> None:
    result = ok(ask(world, Embeddings({"exchanges": axis(0)}), "exchanges"))
    order = uris(world, [f.document_id for f in result.fused])
    assert order == [uri("b"), uri("a"), uri("d"), uri("c")]
    assert [f.rrf for f in result.fused] == ["123/3782", "1/61", "1/63", "1/64"]  # b: 1/61 + 1/62
    assert result.fused[0].lexical_rank == 1 and result.fused[0].dense_rank == 2
    assert result.evidence[0].evidence_id == "E1" and result.evidence[0].source_uri == uri("b")


def test_tenancy_allowlists_and_retired_generations(world: World, shared_db: AppDatabase, tmp_path: Path) -> None:
    other = World(shared_db, tmp_path / "other")
    refused(ask(other, Embeddings(), "refunds", mode="lexical"), "corpus_not_found")  # another workspace's corpus
    only = ok(ask(world, Embeddings(), "days", mode="lexical", allowlist=(uri("d"),)))
    assert uris(world, [d.document_id for d in only.lexical]) == [uri("d")]
    refused(ask(world, Embeddings(), "days", mode="lexical", allowlist=("tau2:banking_knowledge/zzz",)),
            "scope_invalid")
    before = ok(ask(world, Embeddings(), "refunds", mode="lexical"))
    edited = [(k, t, "Refunds are no longer accepted." if k == "a" else c) for k, t, c in DOCS]
    new_generation = world.publish(documents(edited), key=KEY, embeddings=Embeddings(VECTORS))
    after = ok(ask(world, Embeddings(), "refunds", mode="lexical"))
    assert after.generation_id == new_generation != before.generation_id
    assert all("ten days" not in e.text for e in after.evidence)  # retired chunks are never candidates


def test_full_policy_is_retail_only_and_all_or_refused(world: World, shared_db: AppDatabase, tmp_path: Path) -> None:
    refused(ask(world, Embeddings(), mode="full_policy"), "full_policy_not_supported")
    retail = World(shared_db, tmp_path / "retail")
    policy = "# Retail\n\n" + "\n\n".join(f"## Rule {i}\n\nRule {i} text." for i in range(12))
    retail.publish({"policy": policy.encode()}, key="test-retail", domain="retail", render="identity")
    result = ok(ask(retail, Embeddings(), mode="full_policy", corpus_key="test-retail"))
    assert len(result.evidence) == 12 and result.lexical_status == "not_used" and result.dense_status == "not_used"
    assert [e.evidence_id for e in result.evidence] == [f"E{i}" for i in range(1, 13)]
    assert result.evidence_tokens <= 4096 and result.provider_requests == 0
    refused(ask(retail, Embeddings(), mode="full_policy", corpus_key="test-retail", full_policy_max_chunks=11),
            "full_policy_too_many_chunks")
    refused(ask(retail, Embeddings(), mode="full_policy", corpus_key="test-retail", max_evidence_tokens=50),
            "full_policy_exceeds_budget")


def test_the_evidence_budget_and_the_trace_record(world: World) -> None:
    run_id = world.run()
    result = ok(ask(world, Embeddings({QUERY: axis(0)}), run_id=run_id))
    assert len(result.evidence) <= 6 and result.evidence_tokens <= 4096
    assert result.evidence_text.startswith("[E1] ") and not result.replayed
    with world.db.superuser() as conn:
        row = conn.execute("SELECT query_sha256, authorized_scope::text, candidates::text, final_chunk_ids, "
                           "pg_column_size(authorized_scope), pg_column_size(candidates) FROM app.retrieval_traces "
                           "WHERE id = %s", (result.trace_id,)).fetchone()
    assert row[0] == input_sha256(QUERY) and QUERY not in row[1] + row[2]  # a digest, never the query text
    candidates = TraceCandidates.model_validate_json(row[2])
    assert candidates.computed_payload_sha256() == candidates.payload_sha256 == result.payload_sha256
    assert list(row[3]) == [e.chunk_id for e in result.evidence]
    assert row[4] <= SCOPE_LIMIT and row[5] <= CANDIDATES_LIMIT
    assert world.count("app.retrieval_steps") == 1


def test_dense_unavailability_falls_back_flagged_or_refuses(world: World) -> None:
    failing = Embeddings()
    failing.fail = True
    fallback = ok(ask(world, failing, "refunds"))
    assert (fallback.dense_status, fallback.dense_unavailable, fallback.provider_requests) == ("unavailable",
                                                                                               "unresolved", 1)
    assert fallback.lexical and fallback.dense == ()
    with world.db.superuser() as conn:
        scope = conn.execute("SELECT authorized_scope->>'embedding_job_id' FROM app.retrieval_traces WHERE id = %s",
                             (fallback.trace_id,)).fetchone()
    assert scope[0] is not None  # the dispatched job stays linked
    refused(ask(world, failing, "refunds again", dense_policy="refuse"), "embedding_unavailable")
    refused(ask(world, failing, "refunds dense", mode="dense"), "embedding_unavailable")
    capped = Configuration(caps=replace(Caps(), run_calls=1))
    run_id = world.run()
    first = ok(ask(world, Embeddings(), "first question", run_id=run_id, step=1, configuration=capped))
    assert first.dense_status == "ok"
    budget = ok(ask(world, Embeddings(), "second question", run_id=run_id, step=2, configuration=capped))
    assert (budget.dense_unavailable, budget.provider_requests) == ("budget", 0)


def test_invalid_run_corpus_or_scope_refuse_before_any_request_or_intent(world: World) -> None:
    embeddings = Embeddings()
    run_id = world.run()
    world.end(run_id)
    refused(ask(world, embeddings, run_id=run_id), "run_not_active")
    refused(ask(world, embeddings, corpus_key="no-such-corpus"), "corpus_not_found")
    refused(ask(world, embeddings, allowlist=("tau2:banking_knowledge/zzz",)), "scope_invalid")
    assert embeddings.requests == [] and embeddings.factory_calls == 0
    assert world.count("app.retrieval_steps") == 0


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), -float("inf"), True, "soon"])
def test_invalid_deadlines_refuse_before_any_work(world: World, deadline: Any) -> None:
    embeddings = Embeddings()
    refused(ask(world, embeddings, deadline=deadline), "deadline_invalid")
    assert world.count("app.retrieval_steps") == 0 and embeddings.factory_calls == 0


def test_a_passed_deadline_refuses_and_cancellation_propagates_without_a_trace(world: World) -> None:
    embeddings = Embeddings()
    refused(ask(world, embeddings, deadline=time.monotonic() - 1), "deadline_passed")
    assert world.count("app.retrieval_steps") == 0
    hanging = Embeddings()
    hanging.hang = True
    query = query_for(world, "will hang")
    retriever = world.retriever(hanging)

    async def cancel_it() -> None:
        async with owned_task(retriever.retrieve(query, deadline=time.monotonic() + 60)) as task:
            await until_started(hanging, task, timeout=10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 30)

    asyncio.run(cancel_it())
    assert world.count("app.retrieval_traces") == 0
    with world.db.superuser() as conn:
        open_transactions = conn.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                                         "AND state LIKE 'idle in transaction%'").fetchone()[0]
    assert open_transactions == 0


def test_an_invalid_cached_query_vector_refuses(world: World) -> None:
    config = RetrievalConfig(mode="hybrid")
    from policyops.providers.embedding_contract import request_config_sha256

    digest = input_sha256("zero vector query")
    with world.db.superuser() as conn:  # a corrupt cache row (triggers and FKs disabled): fixture only
        conn.execute("SET session_replication_role = replica")
        conn.execute("INSERT INTO app.embedding_cache (workspace_id, input_sha256, request_config_sha256, attempt_id, "
                     "vector, created_at) VALUES (%s, %s, %s, %s, %s::vector, now())",
                     (world.ws, digest, request_config_sha256(config.embedding_model, config.embedding_dimensions),
                      uuid4(), "[" + ",".join(["0"] * 1536) + "]"))
        conn.execute("SET session_replication_role = DEFAULT")
    refused(ask(world, Embeddings(), "zero vector query"), "query_vector_invalid")


def test_zero_vector_chunks_are_excluded_and_counted(world: World) -> None:
    with world.db.superuser() as conn:  # a legacy-style zero-vector chunk in the active generation: fixture only
        conn.execute("SET session_replication_role = replica")
        conn.execute("INSERT INTO app.chunks (id, workspace_id, generation_id, document_version_id, heading, "
                     "start_offset, end_offset, text, sha256, embedding, created_at) SELECT gen_random_uuid(), "
                     "k.workspace_id, k.generation_id, k.document_version_id, k.heading, 0, 3, 'abc', k.sha256, "
                     "%s::vector, now() FROM app.chunks k JOIN app.corpora c ON c.active_generation_id = "
                     "k.generation_id WHERE c.workspace_id = %s LIMIT 1",
                     ("[" + ",".join(["0"] * 1536) + "]", world.ws))
        conn.execute("SET session_replication_role = DEFAULT")
    result = ok(ask(world, Embeddings({QUERY: axis(0)}), mode="dense"))
    with world.db.superuser() as conn:
        exclusions = conn.execute("SELECT candidates->'exclusions' FROM app.retrieval_traces WHERE id = %s",
                                  (result.trace_id,)).fetchone()[0]
    assert exclusions["dense_nan_distance"] == 1 and len(result.dense) == 4


def test_query_plans_are_recorded_for_both_branches(world: World, tmp_path: Path) -> None:
    result = ok(ask(world, Embeddings({QUERY: axis(0)})))
    params = {"g": result.generation_id, "docs": None, "n": 20, "per": 2, "q": "refunds",
              "qv": "[" + ",".join(["0.01"] * 1536) + "]"}
    plans = {"lexical": explain(world.engine, world.ws, LEXICAL_SQL, params),
             "dense": explain(world.engine, world.ws, DENSE_SQL, params)}
    (tmp_path / "plans.json").write_text(json.dumps(plans, indent=1), encoding="utf-8")
    for plan in plans.values():
        assert "generation_id" in json.dumps(plan)  # recorded evidence; no planner choice is asserted


def test_an_existing_step_job_with_another_identity_conflicts_without_a_call(world: World) -> None:
    run_id = world.run()
    store = EmbeddingStore(world.engine, world.ws, env="test")
    ledger = build_app_ledger(env="test", engine=world.engine, workspace_id=world.ws, configuration=Configuration())
    other = prepare_job(EmbeddingJob(purpose=QUERY_PURPOSE, subject_key=subject_for(run_id, 4),
                                     inputs=("an older question",)), Configuration(), TOKENIZER,
                        deadline=time.monotonic() + 30)
    first = Embeddings()
    report = asyncio.run(run_job(ledger, store, first.providers()(), other, deadline=time.monotonic() + 30,
                                 limits=FAST, run_id=run_id))
    assert report.status == "complete"
    ok(ask(world, Embeddings(), "the requested question", mode="dense"))  # caches the requested text elsewhere
    embeddings = Embeddings()
    refused(ask(world, embeddings, "the requested question", run_id=run_id, step=4), "step_conflict")
    assert embeddings.requests == [] and embeddings.factory_calls == 0
    assert store.job(report.job_id) is not None  # type: ignore[arg-type]


def test_a_complete_zero_batch_step_job_is_reused_without_a_credential_read(world: World) -> None:
    ok(ask(world, Embeddings(), "already cached question", mode="dense"))  # the text is now cached
    run_id = world.run()
    store = EmbeddingStore(world.engine, world.ws, env="test")
    ledger = build_app_ledger(env="test", engine=world.engine, workspace_id=world.ws, configuration=Configuration())
    prepared = prepare_job(EmbeddingJob(purpose=QUERY_PURPOSE, subject_key=subject_for(run_id, 1),
                                        inputs=("already cached question",)), Configuration(), TOKENIZER,
                           deadline=time.monotonic() + 30)
    seed = Embeddings()
    report = asyncio.run(run_job(ledger, store, seed.providers()(), prepared, deadline=time.monotonic() + 30,
                                 limits=FAST, run_id=run_id))
    assert report.status == "complete" and seed.requests == []
    assert store.batches(report.job_id) == []  # type: ignore[arg-type]
    embeddings = Embeddings()
    result = ok(ask(world, embeddings, "already cached question", mode="dense", run_id=run_id, step=1))
    assert result.dense_status == "ok" and embeddings.requests == [] and embeddings.factory_calls == 0
