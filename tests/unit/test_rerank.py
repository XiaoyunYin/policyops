"""T14 rerank stage, pure parts (offline): the bounded input, labels and excerpts, the output schema, adversarial
ranking outputs, the exhaustive layer-A mapping, final ordering, the fail-fast preflight and the Retriever's wiring
guards (refused before any read, reservation, credential or factory use, observed with counting fakes). No byte cap
here is a tokenizer proof: the provider count admission (T11) decides."""

from __future__ import annotations

from fractions import Fraction
import json
import random
from typing import Any, get_args
from uuid import UUID, uuid4

import pytest

from policyops.budget.config import DEFAULT_ACTORS, ChatActor, Configuration
from policyops.budget.registry import REGISTRY, ChatModel
from policyops.providers import serialize
from policyops.providers.calls import AttemptRecord, CallReport
from policyops.providers.contract import ContractGap
from policyops.providers.schema import check_schema
from policyops.providers.serialize import prepare
from policyops.retrieval import rerank as r
from policyops.retrieval.rank import ChunkRow, Fused
from policyops.retrieval.search import Retriever
from policyops.runtime.clock import UnsafeTestHook
from policyops_contracts.model import ModelResult, ReportedUsage
from policyops_contracts.retrieval import RerankConfig, RerankModel, RetrievalConfig, RetrievalQuery, RetrievalScope
from policyops_testing.retrieval_fixtures import ScriptedRerankPort


SCHEMA_BYTES_N20 = 312  # measured: the serialized output schema of a 20-document window
WS, RUN = UUID(int=1), UUID(int=2)


def window(n: int, *, text: str = "Refunds take ten days.", chunks: int = 1, uri: str = "u") -> tuple[
        list[Fused], dict[UUID, ChunkRow]]:
    fused, rows = [], {}
    for i in range(n):
        document = UUID(int=100 + i)
        ids = tuple(UUID(int=1000 + 10 * i + k) for k in range(chunks))
        fused.append(Fused(document, f"{uri}{i}", i + 1, Fraction(1, 61 + i), i + 1, None, ids))
        for k, chunk in enumerate(ids):
            rows[chunk] = ChunkRow(chunk, document, UUID(int=5000 + i), f"{uri}{i}", 1, f"Heading {i}", 0,
                                   len(text), f"{text} part {k}")
    return fused, rows


def built(n: int = 3, *, query: str = "refund to my card", config: RerankConfig | None = None, **kwargs: Any
          ) -> r.RerankInput:
    fused, rows = window(n, **kwargs)
    return r.build_input(workspace_id=WS, run_id=RUN, step=4, request_sha256="a" * 64, query=query,
                         config=config or RerankConfig(), fused=fused, rows=rows, chunks_per_document=2)


def result(outcome: str, *, structured: str | None = None, reason: str | None = None) -> ModelResult:
    return ModelResult(outcome=outcome, provider="openai", requested_model="gpt-6-luna",  # type: ignore[arg-type]
                       usage=ReportedUsage(state="unknown"), structured_json=structured, reason_code=reason)


def report(status: str, *, outcome: ModelResult | None = None, reason: str | None = None,
           fate: str | None = None) -> CallReport:
    attempts = [] if fate is None else [AttemptRecord(uuid4(), "rerank.r0.a0", "a" * 64, fate=fate)]  # type: ignore[arg-type]
    return CallReport(outcome, status, reason, attempts)  # type: ignore[arg-type]


# -- contracts and constants ---------------------------------------------------------------------------------------

def test_the_rerank_model_literal_is_exactly_the_registry_chat_models() -> None:
    chat = {name for name, model in REGISTRY.models.items() if isinstance(model, ChatModel)}
    assert set(get_args(RerankModel)) == chat
    assert r.reranker_model(Configuration()) == DEFAULT_ACTORS["reranker"].model == "gpt-6-luna"


def test_keys_identities_and_labels_are_deterministic() -> None:
    assert r.invocation_key(WS, RUN, 4) == r.invocation_key(WS, RUN, 4) != r.invocation_key(WS, RUN, 5)
    assert [r.label(i) for i in (1, 9, 20)] == ["D01", "D09", "D20"]
    base = built()
    assert base.request_identity == built().request_identity
    assert built(query="other question").request_identity != base.request_identity
    assert built(config=RerankConfig(documents=2)).request_identity != base.request_identity


def test_no_rerank_configuration_keeps_its_t13_digest_and_rerank_changes_it() -> None:
    plain = RetrievalConfig(mode="hybrid")
    assert "rerank" not in plain.model_dump(mode="json") and "rerank" not in plain.model_dump_json()
    reranked = RetrievalConfig(mode="hybrid", rerank=RerankConfig())
    assert reranked.sha256() != plain.sha256()
    query = RetrievalQuery(text="q", run_id=RUN, step=1, scope=RetrievalScope(corpus_key="k"), config=reranked)
    assert RetrievalQuery.model_validate_json(query.model_dump_json()) == query


# -- input bounds --------------------------------------------------------------------------------------------------

def test_the_window_labels_headers_and_excerpts() -> None:
    value = built(3, chunks=3)
    assert value.skipped is None and value.labels == ("D01", "D02", "D03")
    assert value.window_document_ids == (UUID(int=100), UUID(int=101), UUID(int=102))
    first = value.candidates[0]
    assert first.header == "[D01] u0 | Heading 0"
    assert first.excerpt == "Refunds take ten days. part 0" + r.EXCERPT_JOIN + "Refunds take ten days. part 1"
    assert value.user_message.startswith("Question:\n<<<\nrefund to my card\n>>>\nCandidates:\n[D01] u0 | Heading 0\n")
    assert value.input_sha256 is not None and value.content_bytes() <= r.RERANK_MAX_CONTENT_BYTES


def test_cutting_is_code_point_safe_and_marked() -> None:
    text, cut = r.cut("\U0001f600" * 100, 70)
    assert cut and text.endswith(r.TRUNCATED) and len(text.encode()) <= 70 and "�" not in text
    assert r.cut("short", 70) == ("short", False)


def test_too_few_candidates_and_an_unfittable_prompt_are_skipped_without_a_call() -> None:
    assert built(1).skipped == "skipped_few_candidates" and built(0).skipped == "skipped_few_candidates"
    huge = built(20, query="\U0001f600" * 2000, uri="u" * 200)  # 8000 query bytes and twenty long headers
    assert huge.skipped == "skipped_input_bound" and huge.user_message == "" and huge.input_sha256 is None


def test_the_content_byte_cap_holds_over_seeds(seed: int) -> None:
    rng = random.Random(seed)  # noqa: S311 - a reproducible test seed, not cryptography
    alphabet = ["a", " ", "é", "€", "\U0001f600", "\n"]
    for _ in range(40):
        n = rng.randint(2, 20)
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 3000)))
        query = "".join(rng.choice(alphabet[:5]) for _ in range(rng.randint(1, 2000))).strip() or "q"
        value = built(n, query=query, text=text, chunks=rng.randint(1, 3), uri="\U0001f600" * rng.randint(1, 60),
                      config=RerankConfig(excerpt_bytes=rng.randint(64, 1000)))
        if value.skipped is None:
            assert value.content_bytes() <= r.RERANK_MAX_CONTENT_BYTES
            assert all(len(c.excerpt.encode()) <= 1000 for c in value.candidates)


def test_the_output_schema_is_supported_and_measured_and_the_prepared_body_is_bounded() -> None:
    labels = [r.label(i) for i in range(1, 21)]
    schema = r.output_schema(labels)
    assert len(schema.encode()) == SCHEMA_BYTES_N20
    check_schema(schema)
    fused, rows = window(20, text="\U0001f600" * 20000, uri="u" * 2000)
    value = r.build_input(workspace_id=WS, run_id=RUN, step=4, request_sha256="a" * 64, query="q" * 2000,
                          config=RerankConfig(excerpt_bytes=1000), fused=fused, rows=rows, chunks_per_document=3)
    assert value.skipped is None and value.excerpts_truncated == 20
    prepared = prepare(r.model_request(value), Configuration(), "reranker")
    assert value.content_bytes() <= r.RERANK_MAX_CONTENT_BYTES
    assert len(prepared.body) <= r.RERANK_MAX_CONTENT_BYTES + 1000  # content + schema + fixed request fields
    body = json.loads(prepared.body)
    assert body["max_output_tokens"] == 512 and body["text"]["format"]["strict"] is True
    assert body["model"] == "gpt-6-luna"


# -- adversarial output and mapping --------------------------------------------------------------------------------

LABELS = ("D01", "D02", "D03")


@pytest.mark.parametrize("payload", [
    None, "not json", "[]", "{}", '{"ranking": []}', '{"ranking": ["D04"]}', '{"ranking": ["D01", "D01"]}',
    '{"ranking": ["00000000-0000-0000-0000-000000000064"]}', '{"ranking": [1]}', '{"ranking": "D01"}',
    '{"ranking": null}', '{"ranking": [["D01"]]}', '{"ranking": [{"label": "D01"}]}',
    '{"ranking": ["D01"], "extra": 1}', '{"ranking": ["d01"]}', json.dumps({"ranking": ["D01"] * 10_000}),
    '{"ranking": ["D01", "D02", "D03", "D01"]}', "[" * 5000 + "]" * 5000,
])
def test_adversarial_rankings_are_rejected_whole(payload: str | None) -> None:
    assert r.parse_ranking(payload, LABELS) is None


def test_a_domain_valid_ranking_is_accepted_as_given() -> None:
    assert r.parse_ranking('{"ranking": ["D03", "D01"]}', LABELS) == ("D03", "D01")


@pytest.mark.parametrize(("call_report", "status"), [
    (report("result", outcome=result("structured", structured='{"ranking": ["D02"]}')), "applied"),
    (report("result", outcome=result("structured", structured='{"ranking": ["D09"]}')), "invalid_ranking"),
    (report("result", outcome=result("invalid_output", reason="schema_mismatch")), "invalid_output"),
    (report("result", outcome=result("completed")), "invalid_output"),
    (report("result", outcome=result("refused")), "refused"),
    (report("result", outcome=result("truncated")), "truncated"),
    (report("result", outcome=result("failed", reason="provider_failed")), "failed"),
    (report("contract_gap", outcome=result("contract_gap", reason="cache_write_under_none")), "contract_block"),
    (report("contract_gap", reason="no server credential for openai"), "integrity"),
    (report("budget", reason="run_calls", fate="not_reserved"), "budget"),
    (report("budget", reason="count_cap", fate="released"), "budget"),
    (report("deadline", reason="deadline"), "timeout_candidate"),
    (report("failed", reason="replayed_reserved", fate="replayed"), "prior_attempt"),
    (report("failed", reason="dispatching", fate="replayed"), "prior_attempt"),
    (report("failed", reason="count.http_500", fate="released"), "count_failed"),
    (report("failed", reason="count_rejected", fate="released"), "count_failed"),
    (report("failed", reason="count_not_admitted", fate="released"), "count_failed"),
    (report("failed", reason="run_not_active", fate="released"), "run_not_active"),
    (report("failed", reason="blocked_by_overrun", fate="released"), "budget"),
    (report("failed", reason="blocked_by_contract", fate="released"), "contract_block"),
    (report("failed", reason="timeout", fate="unresolved"), "failed"),
    (report("failed", reason="http_500", fate="settled"), "failed"),
])
def test_layer_a_maps_every_t11_report(call_report: CallReport, status: str) -> None:
    mapped, _, ranking = r.map_report(call_report, LABELS)
    assert mapped == status
    assert bool(ranking) == (status == "applied")


def test_reason_codes_are_bounded_slugs() -> None:
    assert r.slug_or_none("count.http_500") == "count.http_500" and r.slug_or_none(None) is None
    assert r.slug_or_none("No server credential for openai") is None and r.slug_or_none("x" * 300) == "x" * 64


def test_the_final_order_is_listed_then_unlisted_window_then_beyond() -> None:
    fused, _ = window(5)
    ids = [f.document_id for f in fused]
    order = r.reorder(fused, ids[:3], ("D03", "D01"))
    assert [f.document_id for f in order] == [ids[2], ids[0], ids[1], ids[3], ids[4]]
    assert [f.rank for f in order] == [3, 1, 2, 4, 5]  # the baseline fused records keep their own ranks


# -- preflight and wiring ------------------------------------------------------------------------------------------

def reranker(**changes: Any) -> Configuration:
    actors = dict(DEFAULT_ACTORS)
    base = actors["reranker"]
    assert isinstance(base, ChatActor)
    actors["reranker"] = ChatActor("reranker", base.model, base.effort, **changes)
    return Configuration(actors=actors)


def test_preflight_checks_the_actor_limit_and_prepares_a_maximal_template(monkeypatch: pytest.MonkeyPatch) -> None:
    r.preflight(Configuration())
    with pytest.raises(r.RerankConfigurationError):
        r.preflight(reranker(max_output=256))
    prepared: list[str] = []
    original = serialize.prepare

    def spy(request: Any, configuration: Any, actor: str) -> Any:
        prepared.append(actor)
        return original(request, configuration, actor)

    monkeypatch.setattr(r, "prepare", spy)
    r.preflight(Configuration())
    assert prepared == ["reranker"]

    def gap(*args: Any) -> Any:
        raise ContractGap("synthetic gap")

    monkeypatch.setattr(r, "prepare", gap)
    with pytest.raises(ContractGap):
        r.preflight(Configuration())


class Untouchable:
    """Records any use; the wiring guards must refuse before touching it."""

    def __init__(self, log: list[str], name: str) -> None:
        object.__setattr__(self, "_log", log)
        object.__setattr__(self, "_name", name)

    def __getattr__(self, attribute: str) -> Any:
        self._log.append(f"{self._name}.{attribute}")
        raise AssertionError(f"{self._name}.{attribute} was used")


class LedgerStub:
    def __init__(self, configuration: Configuration) -> None:
        self.configuration = configuration


@pytest.mark.parametrize(("port", "env", "configuration", "error"), [
    (ScriptedRerankPort(test_only=False), "test", Configuration(), UnsafeTestHook),
    (ScriptedRerankPort(), None, Configuration(), UnsafeTestHook),
    (ScriptedRerankPort(), "production", Configuration(), UnsafeTestHook),
    (ScriptedRerankPort(), "test", reranker(max_output=256), r.RerankConfigurationError),
    (None, None, reranker(max_output=256), r.RerankConfigurationError),
])
def test_wiring_guards_refuse_before_any_read_reservation_or_factory_use(
        port: Any, env: str | None, configuration: Configuration, error: type[Exception]) -> None:
    log: list[str] = []
    factory_calls: list[int] = []
    with pytest.raises(error):
        Retriever(Untouchable(log, "engine"), WS, embeddings=Untouchable(log, "embeddings"),  # type: ignore[arg-type]
                  ledger=LedgerStub(configuration), providers=lambda: factory_calls.append(1),  # type: ignore[arg-type,return-value]
                  tokenizer=Untouchable(log, "tokenizer"), rerank=port is None, rerank_port=port,  # type: ignore[arg-type]
                  env=env)
    assert log == [] and factory_calls == [] and (port is None or port.calls == [])
