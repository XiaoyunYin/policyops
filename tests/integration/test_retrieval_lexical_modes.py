"""Runtime PostgreSQL lexical modes: parsing, ranking, bounds and trace identity."""
from __future__ import annotations

import asyncio
from pathlib import Path
import time

import pytest

from policyops.persistence.retrieval import MAX_ANY_TERM_LEXEMES, LexicalMode, RetrievalStore, StepRefused
from policyops_contracts.retrieval import (
    RetrievalConfig,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    RetrievalScope,
)
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import Embeddings, World, axis, documents


pytestmark = pytest.mark.postgres
KEY = "test-lexical-modes"


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    result = World(shared_db, tmp_path)
    result.publish(documents([("a", "Policy", "Refund card."), ("b", "Policy", "Refund."),
                              ("c", "Policy", "Shipping.")]), key=KEY)
    return result


def query(world: World, value: str, *, mode: str = "lexical") -> RetrievalQuery:
    return RetrievalQuery(text=value, run_id=world.run(), step=1, scope=RetrievalScope(corpus_key=KEY),
                          config=RetrievalConfig(mode=mode))  # type: ignore[arg-type]


def ask(world: World, request: RetrievalQuery, lexical_mode: LexicalMode = "all_terms") -> RetrievalResult:
    retriever = world.retriever(Embeddings({request.text: axis(0)}), lexical_mode=lexical_mode)
    result = asyncio.run(retriever.retrieve(request, deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalResult), result
    return result


def snapshot(world: World, value: str, lexical_mode: LexicalMode) -> object:
    return RetrievalStore(world.engine, world.ws).snapshot(corpus_key=KEY, mode="lexical", query=value,
        query_vector=None, document_ids=(), branch_documents=20, chunks_per_document=2,
        full_policy_max_chunks=16, lexical_mode=lexical_mode)


@pytest.mark.parametrize("mode", ["lexical", "hybrid"])
def test_any_terms_subset_and_more_matches_rank_higher(world: World, mode: str) -> None:
    result = ask(world, query(world, "refund card telescope", mode=mode), "any_terms")
    assert len(result.lexical) == 2
    assert float(result.lexical[0].score) > float(result.lexical[1].score)
    assert result.evidence[0].source_uri.endswith("/a")


def test_all_terms_default_and_websearch_semantics_unchanged(world: World) -> None:
    request = query(world, "refund card telescope")
    implicit = ask(world, request)
    explicit = ask(world, request, "all_terms")
    assert implicit.lexical == explicit.lexical == () and explicit.replayed
    assert implicit.config_sha256 == request.config.sha256()
    assert implicit.request_sha256 == request.request_sha256()
    assert len(ask(world, query(world, '"refund card"')).lexical) == 1
    assert len(ask(world, query(world, "refund OR shipping")).lexical) == 3


@pytest.mark.parametrize("value", ['"refund card"', 'refund & !card | shipping:*',
    "refund <-> card", "refund ' \\\" ( ) & | ! :* card", "refund'); DROP TABLE app.chunks; --"])
def test_any_terms_punctuation_cannot_create_query_operators(world: World, value: str) -> None:
    result = ask(world, query(world, value), "any_terms")
    plain = ask(world, query(world, "refund card shipping" if "shipping" in value else "refund card"), "any_terms")
    assert [d.document_id for d in result.lexical] == [d.document_id for d in plain.lexical]
    assert result.lexical_status == "ok"


@pytest.mark.parametrize("lexical_mode", ["all_terms", "any_terms"])
@pytest.mark.parametrize("value", ["", "   ", "the and of", "&|!:* '\""])
def test_empty_query_path(world: World, value: str, lexical_mode: LexicalMode) -> None:
    # Snapshot permits the empty text; the public request rejects blank text before persistence.
    result = RetrievalStore(world.engine, world.ws).snapshot(corpus_key=KEY, mode="lexical", query=value,
        query_vector=None, document_ids=(), branch_documents=20, chunks_per_document=2,
        full_policy_max_chunks=16, lexical_mode=lexical_mode)
    assert result.lexical_status == "empty_query" and result.lexical == [] and result.rows == {}


def test_distinct_normalized_lexeme_cap_boundary_and_no_truncation(world: World) -> None:
    terms = [str(100000 + i) for i in range(MAX_ANY_TERM_LEXEMES)]
    snapshot(world, " ".join(terms), "any_terms")
    snapshot(world, " ".join(terms + terms + ["the"]), "any_terms")  # duplicates and stops do not consume capacity
    with pytest.raises(StepRefused, match="lexical_query_too_many_lexemes"):
        snapshot(world, " ".join([*terms, "refund"]), "any_terms")
    snapshot(world, " ".join([*terms, "refund"]), "all_terms")  # legacy mode has no new cap
    request = query(world, " ".join([*terms, "refund"]))
    result = asyncio.run(world.retriever(Embeddings(), lexical_mode="any_terms").retrieve(
        request, deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalRefused) and result.code == "query_too_long"
    assert result.detail == "lexical_query_too_many_lexemes"
    assert world.count("app.retrieval_traces") == 0


def test_mode_is_bound_to_request_and_replay(world: World) -> None:
    request = query(world, "refund card telescope")
    first = ask(world, request, "any_terms")
    assert first.config_sha256 != request.config.sha256() and first.request_sha256 != request.request_sha256()
    again = ask(world, request, "any_terms")
    assert again.replayed and again.payload_sha256 == first.payload_sha256
    result = asyncio.run(world.retriever(Embeddings()).retrieve(request, deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalRefused) and result.code == "step_conflict"
