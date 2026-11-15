"""Exact BM25 over retained PostgreSQL English positions, exercised as the RLS runtime role."""
from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import text

from policyops.persistence.database import workspace_transaction
from policyops.persistence.retrieval import BM25_DF_CTE, RetrievalStore, Snapshot
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import World, documents


pytestmark = pytest.mark.postgres
KEY = "test-bm25"
BODIES = {"a": "alpha alpha beta", "b": "alpha beta beta beta", "c": "alpha gamma",
          "d": "alpha gamma", "e": "delta delta"}


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    value = World(shared_db, tmp_path)
    value.publish(documents([(key, "the", body) for key, body in BODIES.items()]), key=KEY)
    return value


def search(store: RetrievalStore, query: str, *, docs: tuple[UUID, ...] = (), limit: int = 20) -> Snapshot:
    return store.snapshot(corpus_key=KEY, mode="lexical", query=query, query_vector=None,
                          document_ids=docs, branch_documents=limit, chunks_per_document=2,
                          full_policy_max_chunks=16, lexical_mode="bm25")


def reference(bodies: dict[str, str], query: str) -> dict[str, float]:
    """Independent pure-Python Okapi, on this deliberately already-normalized, stopword-free corpus."""
    counts = {key: Counter(body.split()) for key, body in bodies.items()}
    n = len(counts)
    average = sum(sum(c.values()) for c in counts.values()) / n
    result = {}
    for key, terms in counts.items():
        score = 0.0
        for term in sorted(set(query.split())):
            df = sum(term in c for c in counts.values())
            tf = terms[term]
            if tf:
                idf = math.log1p((n - df + 0.5) / (df + 0.5))
                score += idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * sum(terms.values()) / average))
        if score:
            result[key] = score
    return result


@pytest.mark.parametrize("query", ["alpha beta", "alpha alpha beta beta", "alpha", "beta gamma delta",
                                 "delta missing", "missing"])
def test_hand_corpus_scores_and_total_order(world: World, query: str) -> None:
    store = RetrievalStore(world.engine, world.ws)
    result = search(store, query)
    expected = reference(BODIES, query)
    actual = {hit.source_uri.rsplit("/", 1)[-1]: float(hit.score) for hit in result.lexical}
    assert actual == pytest.approx(expected, rel=1e-12)
    assert list(actual) == sorted(expected, key=lambda key: (-expected[key], key))
    # N=5, dl=(3,4,2,2,2), avgdl=13/5; df(alpha)=4, df(beta)=2. Explicit hand calculation for a.
    if query == "alpha beta":
        denominator = 1.2 * (0.25 + 0.75 * 3 / 2.6)
        hand = math.log(1 + 1.5 / 4.5) * 4.4 / (2 + denominator)
        hand += math.log(1 + 3.5 / 2.5) * 2.2 / (1 + denominator)
        assert actual["a"] == pytest.approx(hand, rel=1e-12)
    # A cache hit must produce identical scores, not just the same ranking.
    assert search(store, query).lexical == result.lexical


def test_length_idf_ties_and_top_limit(world: World) -> None:
    store = RetrievalStore(world.engine, world.ws)
    alpha = search(store, "alpha")
    scores = {h.source_uri.rsplit("/", 1)[-1]: float(h.score) for h in alpha.lexical}
    assert scores["c"] == scores["d"] > scores["b"]  # tf=1; shorter wins
    rare = search(store, "gamma delta")
    assert rare.lexical[0].source_uri.endswith("/e")  # rarer delta wins over gamma at identical dl
    limited = search(store, "alpha", limit=2)
    assert limited.lexical == alpha.lexical[:2]


def test_statistics_cover_generation_not_allowlist_and_change_with_pointer(world: World) -> None:
    store = RetrievalStore(world.engine, world.ws)
    before = search(store, "alpha beta")
    only = before.lexical[-1].document_id
    filtered = search(store, "alpha beta", docs=(only,))
    assert filtered.lexical[0].score == next(h.score for h in before.lexical if h.document_id == only)
    world.publish(documents([("new", "the", "alpha alpha alpha beta")]), key=KEY)
    after = search(store, "alpha beta")
    assert after.generation_id != before.generation_id
    assert float(after.lexical[0].score) == pytest.approx(reference({"new": "alpha alpha alpha beta"},
                                                                  "alpha beta")["new"], rel=1e-12)


def test_df_counts_are_exact_under_runtime_rls(world: World) -> None:
    # Coordinator decision (G1b review): under forced chunk RLS the runtime role cannot use the GIN index for @@
    # (ts_match_vq is not leakproof), so df is a bounded scan of one generation (<= 10,000 chunks). Assert the counts
    # the runtime role computes, not the plan shape; latency is measured on the real corpus by the probe.
    generation = search(RetrievalStore(world.engine, world.ws), "alpha").generation_id
    with workspace_transaction(world.engine, world.ws) as connection:
        rows = connection.execute(text("WITH " + BM25_DF_CTE.rstrip(", ") + " SELECT * FROM df"),  # noqa: S608
                                  {"g": generation, "lexemes": ["alpha", "beta"]}).mappings().all()
        counted = {str(r["lexeme"]): int(r["frequency"]) for r in rows}
        direct = {lexeme: connection.execute(text(
            "SELECT count(*) FROM app.chunks WHERE generation_id = :g AND tsv @@ CAST(:q AS tsquery)"),
            {"g": generation, "q": lexeme}).scalar_one() for lexeme in ("alpha", "beta")}
        assert counted == direct


def test_postgres_position_caps_are_scored_as_stored(world: World) -> None:
    with workspace_transaction(world.engine, world.ws) as connection:
        # PostgreSQL keeps at most 255 positions per lexeme and merges clamped duplicate positions.
        capped = connection.execute(text("SELECT cardinality(positions) FROM "
            "unnest(to_tsvector('english', repeat('alpha ', 300)))")).scalar_one()
        merged = connection.execute(text("SELECT positions FROM unnest(CAST(:v AS tsvector))"),
                                    {"v": "alpha:16382,16383,16384,17000"}).scalar_one()
        assert capped == 255 and merged == [16382, 16383]
    world.publish(documents([("a", "the", "alpha " * 300), ("b", "the", "alpha " * 200)]), key=KEY)
    result = search(RetrievalStore(world.engine, world.ws), "alpha")
    expected = reference({"a": "alpha " * 255, "b": "alpha " * 200}, "alpha")
    assert {h.source_uri.rsplit("/", 1)[-1]: float(h.score) for h in result.lexical} == pytest.approx(expected)


def test_zero_length_vectors_and_english_normalization(world: World) -> None:
    world.publish(documents([("a", "the", "Refund refunds refunding"), ("b", "the", "the and of")]), key=KEY)
    store = RetrievalStore(world.engine, world.ws)
    simple = search(store, "refund")
    assert search(store, "refund refunds refunding").lexical == simple.lexical
    # The stopword-only chunk contributes N=1 and dl=0 to the two-chunk collection; avgdl=1.5.
    expected = math.log(2) * 3 * 2.2 / (3 + 1.2 * (0.25 + 0.75 * 3 / 1.5))
    assert float(simple.lexical[0].score) == pytest.approx(expected)
    world.publish(documents([("empty", "the", "the and of")]), key=KEY)
    assert search(store, "refund").lexical == []  # avgdl=0 does not divide by zero
