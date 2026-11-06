"""Retrieval contracts (T13): strict bounded configuration, scope and query; request fingerprints that change with
every request component; constant disclaimers; decimal score presentation of real database outputs; the typed trace
payload digest and the worst-case trace shape. Offline only."""

from __future__ import annotations

from uuid import UUID

from pydantic import ValidationError
import pytest

from policyops.retrieval.search import trace_id_for, valid_vector, worst_case_trace
from policyops_contracts.retrieval import (
    BranchDocument,
    RetrievalConfig,
    RetrievalQuery,
    RetrievalResult,
    RetrievalScope,
    TraceCandidates,
)


RUN = UUID(int=3)


def query(**changes: object) -> RetrievalQuery:
    base: dict[str, object] = {"text": "Can a refund go to a gift card?", "run_id": RUN, "step": 1,
                               "scope": RetrievalScope(corpus_key="test-retail"),
                               "config": RetrievalConfig(mode="hybrid")}
    return RetrievalQuery(**(base | changes))  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [
    {"branch_documents": 51}, {"chunks_per_document": 4}, {"max_chunks": 17}, {"max_evidence_tokens": 16001},
    {"full_policy_max_chunks": 17}, {"rrf_k": 0}, {"max_admission_attempts": 257}, {"branch_documents": 2.0},
    {"embedding_dimensions": 512}, {"fts_config": "simple"}, {"adjacent_chunks": 1}, {"mode": "rerank"},
])
def test_config_is_strict_and_bounded(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        RetrievalConfig(**({"mode": "hybrid"} | bad))  # type: ignore[arg-type]


def test_defaults_are_the_baseline() -> None:
    config = RetrievalConfig(mode="hybrid")
    assert (config.branch_documents, config.chunks_per_document, config.rrf_k, config.max_chunks,
            config.max_evidence_tokens, config.full_policy_max_chunks, config.dense_policy) == (
        20, 2, 60, 6, 4096, 16, "lexical_fallback")


@pytest.mark.parametrize("text", ["   \n\t", "a" + chr(1) + "b", "x" * 2001, ""])
def test_query_text_is_bounded_and_not_control_text(text: str) -> None:
    with pytest.raises(ValidationError):
        query(text=text)


def test_allowlist_is_sorted_unique_and_bounded() -> None:
    RetrievalScope(corpus_key="k", document_allowlist=("tau2:a/1", "tau2:a/2"))
    for allowlist in [("tau2:a/2", "tau2:a/1"), ("tau2:a/1", "tau2:a/1"), tuple(f"u{i:02d}" for i in range(33))]:
        with pytest.raises(ValidationError):
            RetrievalScope(corpus_key="k", document_allowlist=allowlist)


def test_the_request_fingerprint_binds_query_scope_and_config_but_not_the_step() -> None:
    base = query()
    variants = [query(text="Another question?"), query(scope=RetrievalScope(corpus_key="other")),
                query(config=RetrievalConfig(mode="hybrid", max_chunks=5)),
                query(config=RetrievalConfig(mode="lexical"))]
    assert len({base.request_sha256(), *(v.request_sha256() for v in variants)}) == 5
    assert query(step=2).request_sha256() == base.request_sha256()  # the step is the identity, not the request
    assert trace_id_for(UUID(int=1), RUN, 1) != trace_id_for(UUID(int=2), RUN, 1) != trace_id_for(UUID(int=1), RUN, 2)
    assert trace_id_for(UUID(int=1), RUN, 1) == trace_id_for(UUID(int=1), RUN, 1)


def test_results_always_disclaim_validation_and_authorization() -> None:
    fields = RetrievalResult.model_fields
    assert fields["current_policy_validated"].default is False and fields["claim_support_validated"].default is False
    assert fields["caller_authorized_scope"].default == "required"


@pytest.mark.parametrize("score", ["0", "0.1", "1e-05", "0.29289321881345254", "1.1102230246251565e-16",
                                   "-1.1102230246251565e-16", "2", "0.0303964"])
def test_decimal_scores_accept_real_database_outputs(score: str) -> None:
    BranchDocument(document_id=UUID(int=1), rank=1, score=score, chunk_ids=(UUID(int=2),))


@pytest.mark.parametrize("score", ["NaN", "Infinity", "0.1.2", "1e999999", ""])
def test_decimal_scores_refuse_non_numbers(score: str) -> None:
    with pytest.raises(ValidationError):
        BranchDocument(document_id=UUID(int=1), rank=1, score=score, chunk_ids=(UUID(int=2),))


def test_trace_payload_digest_covers_everything_but_itself() -> None:
    scope, candidates = worst_case_trace(query())
    record = TraceCandidates.model_validate_json(candidates)
    digest = record.computed_payload_sha256()
    assert record.model_copy(update={"payload_sha256": digest}).computed_payload_sha256() == digest
    assert record.model_copy(update={"evidence_tokens": 1}).computed_payload_sha256() != digest
    assert "Can a refund" not in scope + candidates  # no query text in a trace


def test_worst_case_shapes_follow_the_mode() -> None:
    ranked = TraceCandidates.model_validate_json(worst_case_trace(query())[1])
    full = TraceCandidates.model_validate_json(worst_case_trace(query(config=RetrievalConfig(mode="full_policy")))[1])
    assert (len(ranked.lexical), len(ranked.fused), len(ranked.delivered)) == (20, 40, 6)
    assert (len(full.lexical), len(full.fused), len(full.delivered)) == (0, 0, 16)


def test_query_vectors_are_validated() -> None:
    assert valid_vector([0.01] * 1536)
    for vector in ([0.0] * 1536, [1e-46] * 1536, [0.01] * 1535, [float("nan")] + [0.01] * 1535,
                   [float("inf")] + [0.01] * 1535):
        assert not valid_vector(vector)


def test_float32_overflow_is_an_invalid_vector_not_a_crash() -> None:
    assert not valid_vector([1e300] + [0.01] * 1535)  # finite in float64, outside float32
    assert valid_vector([3.0e38] + [0.01] * 1535)  # inside float32


class _Fake:
    def __init__(self, **attributes: object) -> None:
        self.__dict__.update(attributes)


def test_the_retriever_refuses_foreign_components_before_any_database_use() -> None:
    from policyops.providers.embedding_calls import BindingMismatch
    from policyops.retrieval.search import Retriever

    engine, other = object(), object()
    workspace = UUID(int=1)
    for embeddings in (_Fake(engine=other, workspace_id=workspace), _Fake(engine=engine, workspace_id=UUID(int=2))):
        with pytest.raises(BindingMismatch):
            Retriever(engine, workspace, embeddings=embeddings, ledger=_Fake(store=object()),  # type: ignore[arg-type]
                      providers=lambda: None, tokenizer=None)  # type: ignore[arg-type,return-value]
    with pytest.raises(BindingMismatch):  # an app ledger that is not the AppLedgerStore of this workspace
        Retriever(engine, workspace, embeddings=_Fake(engine=engine, workspace_id=workspace),  # type: ignore[arg-type]
                  ledger=_Fake(store=object()), providers=lambda: None, tokenizer=None)  # type: ignore[arg-type,return-value]


class _Connection:
    def __init__(self, options_fail: bool, close_fail: bool) -> None:
        self.options_fail, self.close_fail, self.closed = options_fail, close_fail, 0

    def execution_options(self, **options: object) -> _Connection:
        if self.options_fail:
            raise RuntimeError("options failed")
        return self

    def close(self) -> None:
        self.closed += 1
        if self.close_fail:
            raise OSError("close failed")


@pytest.mark.parametrize(("close_fail", "notes"), [
    (False, []), (True, ["snapshot connection close also failed: OSError"])])
def test_the_snapshot_owns_its_connection_from_acquisition(close_fail: bool, notes: list[str]) -> None:
    from policyops.persistence.retrieval import RetrievalStore

    connection = _Connection(options_fail=True, close_fail=close_fail)
    store = object.__new__(RetrievalStore)  # no database: the setup failure happens before any statement
    store.engine, store.workspace_id = _Fake(connect=lambda: connection), UUID(int=1)  # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="options failed") as failure:
        store.snapshot(corpus_key="k", mode="lexical", query="q", query_vector=None, document_ids=(),
                       branch_documents=20, chunks_per_document=2, full_policy_max_chunks=16)
    assert connection.closed == 1 and getattr(failure.value, "__notes__", []) == notes
