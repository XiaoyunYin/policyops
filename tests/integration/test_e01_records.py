"""E01 step-record export and query-plan diagnostics (T15a) on real PostgreSQL as the actual app runtime, with a
synthetic corpus and stored T13/T14 steps: exact delivered/candidate identities and the immutable intent's query and
configuration digests, historical generations after an activation, the applied-rerank delivery order, the full-policy
definition C = D, and refusals for another tenant, a tampered trace, a foreign corpus, an unlisted or altered document
mapping and a non-runtime engine. Diagnostics are local plan/timing samples, not performance claims."""

from __future__ import annotations

import asyncio
from pathlib import Path
import time
from typing import Any
from uuid import UUID

import pytest

from policyops.persistence.database import RuntimeRoleError
from policyops.persistence.roles import APP_MIGRATOR
from policyops.retrieval.diagnostics import DiagnosticRefused, explain
from policyops.retrieval.records import ExportError, SourceAllowlist, TraceExporter
from policyops_contracts.retrieval import RerankConfig, RetrievalConfig, RetrievalQuery, RetrievalResult, RetrievalScope
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import Embeddings, ScriptedRerankPort, World, axis, documents, embed_input


pytestmark = pytest.mark.postgres
KEY = "test-banking"
DOCS = [("a", "Refunds", "Refunds go back to the original payment method within ten days."),
        ("b", "Exchanges", "Exchanges keep the same product type and size; refunds differ."),
        ("c", "Gift cards", "Store credit and refunds are added to an existing gift card."),
        ("d", "Shipping", "Orders ship within five business days.")]
V2 = [(k, t, c.replace("ten days", "twenty days")) for k, t, c in DOCS]
VECTORS = {embed_input(t, c): axis(i) for i, (_, t, c) in enumerate(DOCS)}
ALLOW = SourceAllowlist(KEY, "banking_knowledge", frozenset(k for k, _, _ in DOCS), "f" * 64)


@pytest.fixture
def world(shared_db: AppDatabase, tmp_path: Path) -> World:
    world = World(shared_db, tmp_path)
    world.publish(documents(DOCS), key=KEY, embeddings=Embeddings(VECTORS))
    return world


def run_step(world: World, run: UUID, number: int, config: RetrievalConfig, *, text_value: str = "refunds",
             corpus_key: str = KEY, port: Any = None) -> RetrievalResult:
    query = RetrievalQuery(text=text_value, run_id=run, step=number, scope=RetrievalScope(corpus_key=corpus_key),
                           config=config)
    retriever = world.retriever(Embeddings({text_value: axis(0)}), rerank_port=port)
    result = asyncio.run(retriever.retrieve(query, deadline=time.monotonic() + 60))
    assert isinstance(result, RetrievalResult), result
    return result


def exporter(world: World, allow: SourceAllowlist = ALLOW) -> TraceExporter:
    return TraceExporter(world.engine, world.ws, allow)


def stems(result: RetrievalResult) -> list[str]:
    return [e.source_uri.rsplit("/", 1)[1] for e in result.evidence]


def test_exported_steps_carry_exact_identities_and_digests(world: World) -> None:
    run = world.run()
    lexical = run_step(world, run, 1, RetrievalConfig(mode="lexical"))
    hybrid = run_step(world, run, 2, RetrievalConfig(mode="hybrid"))
    for number, result, config in ((1, lexical, RetrievalConfig(mode="lexical")),
                                   (2, hybrid, RetrievalConfig(mode="hybrid"))):
        record = exporter(world).export_step(run_id=run, step=number)
        assert [d.stem for d in record.delivered] == stems(result)
        assert [d.document_id for d in record.delivered] == [e.document_id for e in result.evidence]
        assert [c.document_id for c in record.candidates] == [f.document_id for f in result.fused]
        assert record.ranked == tuple(c.stem for c in record.candidates)
        assert (record.trace_id, record.payload_sha256, record.request_sha256) == (
            result.trace_id, result.payload_sha256, result.request_sha256)
        assert record.config_sha256 == config.sha256() and record.mode == config.mode
        assert record.query_sha256 == RetrievalQuery(text="refunds", run_id=run, step=number,
                                                     scope=RetrievalScope(corpus_key=KEY), config=config).query_sha256()
        assert record.generation_current_at_export and record.evidence_tokens == result.evidence_tokens


def test_a_historical_generation_remains_exportable_after_an_activation(world: World) -> None:
    run = world.run()
    before = run_step(world, run, 1, RetrievalConfig(mode="lexical"))
    world.publish(documents(V2), key=KEY)
    record = exporter(world).export_step(run_id=run, step=1)
    assert not record.generation_current_at_export and record.generation_id == before.generation_id
    assert [d.stem for d in record.delivered] == stems(before)


def test_an_applied_rerank_order_is_the_delivery_order(world: World) -> None:
    run = world.run()
    result = run_step(world, run, 1, RetrievalConfig(mode="lexical", rerank=RerankConfig()),
                      port=ScriptedRerankPort())  # reverses the window
    record = exporter(world).export_step(run_id=run, step=1)
    assert result.rerank is not None and record.rerank_status == "applied"
    stem_of = {c.document_id: c.stem for c in record.candidates}
    assert record.ranked[:len(result.rerank.order)] == tuple(stem_of[d] for d in result.rerank.order)
    assert [c.document_id for c in record.candidates] == [f.document_id for f in result.fused]  # the baseline pool


def test_full_policy_candidates_are_the_delivered_documents(shared_db: AppDatabase, tmp_path: Path) -> None:
    retail = World(shared_db, tmp_path / "retail")
    retail.publish({"policy": b"# Retail\n\n## Returns\n\nReturns within 30 days.\n\n## Refunds\n\nRefunds go back."},
                   key="test-retail", domain="retail", render="identity")
    run = retail.run()
    result = run_step(retail, run, 1, RetrievalConfig(mode="full_policy"), corpus_key="test-retail")
    allow = SourceAllowlist("test-retail", "retail", frozenset({"policy"}), "f" * 64)
    record = TraceExporter(retail.engine, retail.ws, allow).export_step(run_id=run, step=1)
    assert record.ranked == () and [c.stem for c in record.candidates] == ["policy"]
    assert len(record.delivered) == len(result.evidence)


@pytest.mark.parametrize("break_it", ["other_tenant", "tampered_trace", "foreign_corpus", "unlisted",
                                      "altered_delivered_uri", "altered_candidate_uri", "no_step"])
def test_every_unproven_relationship_refuses(world: World, shared_db: AppDatabase, tmp_path: Path,
                                             break_it: str) -> None:
    run = world.run()
    result = run_step(world, run, 1, RetrievalConfig(mode="lexical", max_chunks=1))  # other fused documents undelivered
    candidate_only = next(f.document_id for f in result.fused if f.document_id != result.evidence[0].document_id)
    target, allow, step = world, ALLOW, 1
    if break_it == "other_tenant":
        target = World(shared_db, tmp_path / "other")
    elif break_it == "tampered_trace":
        with world.db.superuser() as conn:
            conn.execute("UPDATE app.retrieval_traces SET candidates = jsonb_set(candidates, '{evidence_tokens}', "
                         "'1') WHERE id = %s", (result.trace_id,))
    elif break_it == "foreign_corpus":
        allow = SourceAllowlist("other-corpus", "banking_knowledge", ALLOW.keys, "f" * 64)
    elif break_it == "unlisted":
        allow = SourceAllowlist(KEY, "banking_knowledge", frozenset({"d"}), "f" * 64)
    elif break_it.startswith("altered"):  # test fixture: bypass guards to alter a document's stable identity
        altered = result.evidence[0].document_id if break_it == "altered_delivered_uri" else candidate_only
        with world.db.superuser() as conn:
            conn.execute("SET session_replication_role = replica")
            conn.execute("UPDATE app.documents SET source_uri = 'tau2:banking_knowledge/zzz' WHERE id = %s",
                         (altered,))
            conn.execute("SET session_replication_role = DEFAULT")
    else:
        step = 2
    with pytest.raises(ExportError) as raised:
        TraceExporter(target.engine, target.ws, allow).export_step(run_id=run, step=step)
    # A delivered document's altered identity already breaks the immutable evidence-text digest (its source URI is in
    # the assembled evidence); a candidate-only document is caught by the scoped mapping check.
    expected = {"other_tenant": "trace_not_found", "tampered_trace": "trace_integrity",
                "foreign_corpus": "corpus_mismatch", "unlisted": "document_not_in_corpus",
                "altered_delivered_uri": "trace_integrity", "altered_candidate_uri": "document_not_in_corpus",
                "no_step": "trace_not_found"}[break_it]
    assert raised.value.code == expected


def test_the_exporter_and_diagnostics_run_only_as_the_app_runtime(world: World) -> None:
    with pytest.raises(RuntimeRoleError):
        TraceExporter(world.db.engine(APP_MIGRATOR), world.ws, ALLOW)
    with pytest.raises(RuntimeRoleError):
        explain(world.db.engine(APP_MIGRATOR), world.ws, KEY, "lexical_branch", query="refunds")


def test_query_plan_diagnostics_are_bounded_named_operations(world: World) -> None:
    lexical = explain(world.engine, world.ws, KEY, "lexical_branch", query="refunds", repeat=2)
    dense = explain(world.engine, world.ws, KEY, "dense_branch", vector=axis(0), repeat=2)
    for sample in (lexical, dense):
        assert sample.node_types and len(sample.planning_ms) == len(sample.execution_ms) == 2
        assert all(t >= 0 for t in sample.execution_ms) and sample.label.startswith("local diagnostic")
    assert lexical.rows >= 1 and dense.rows >= 1
    cases: list[dict[str, Any]] = [{"query": ""}, {"query": "x\x00"}, {"query": "q" * 2001}, {"repeat": 11},
                                   {"branch_documents": 0}]
    for kwargs in cases:
        arguments: dict[str, Any] = {"query": "refunds", **kwargs}
        with pytest.raises(DiagnosticRefused):
            explain(world.engine, world.ws, KEY, "lexical_branch", **arguments)
    with pytest.raises(DiagnosticRefused):
        explain(world.engine, world.ws, KEY, "dense_branch", vector=[0.0] * 1536)
    with pytest.raises(DiagnosticRefused):
        explain(world.engine, world.ws, KEY, "lexical_branch; DROP", query="refunds")  # type: ignore[arg-type]
