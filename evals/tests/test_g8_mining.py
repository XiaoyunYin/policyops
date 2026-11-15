"""Train-only selection, exclusion and frozen hard-negative audits, without paid calls."""
from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import pytest

from policyops.providers.tokenizer import load as load_tokenizer
from policyops.retrieval.rank import Hit
from policyops_evals.cli import main, parser
from policyops_evals.datasets import multidoc2dial as md
from policyops_evals.qa_studies import g8_mining as g8


def dataset() -> md.Dataset:
    keys = [f"d/train-{i}" for i in range(120)]
    queries = [md.Query(f"q-{i}", "train", "d", key.split("/")[1], 1, f"history {i}", "unused", f"last {i}",
                        (0,), 0, "unused", "respond_solution", ("positive",)) for i, key in enumerate(keys)]
    validation = md.Query("official-val", "validation", "d", "val", 1, "unique val", "unused", "val last",
                          (0,), 0, "unused", "respond_solution", ("positive",))
    return md.Dataset((), (*queries, validation), {"train": tuple(keys), "validation": ("d/val",)}, {})


def test_pool_excludes_dev_all_official_validation_and_duplicates() -> None:
    data = dataset()
    pool = set(md.cohorts(data)["g8_pool"])
    duplicated = next(q for q in data.queries if q.dialogue_key in pool)
    validation = replace(data.queries[-1], last_turn=duplicated.last_turn)
    data = replace(data, queries=(*data.queries[:-1], validation))
    training, internal, audit = g8.partition(data)
    selected = training + internal
    assert duplicated.query_id not in {q.query_id for q in selected}
    assert all(q.split == "train" and q.dialogue_key in pool for q in selected)
    assert not {q.dialogue_key for q in training} & {q.dialogue_key for q in internal}
    assert audit["duplicate_exclusions"] == 1
    assert audit["internal_validation_pool_dialogues"] == 4
    assert audit["dev_or_official_validation_selected"] == 0
    assert g8.partition(data) == (training, internal, audit)


def test_query_caps_and_no_full_text_in_selection_manifest() -> None:
    training, internal, audit = g8.partition(dataset(), train_limit=8, validation_limit=2)
    assert len(training) == 8 and len(internal) == 2
    assert "query" not in audit and "history" not in str(audit)
    for train, valid in ((6001, 600), (1, 601), (0, 1)):
        with pytest.raises(ValueError, match="query_caps"):
            g8.partition(dataset(), train_limit=train, validation_limit=valid)


def passage(identity: str, start: int, end: int, spans: tuple[str, ...] = ("1",),
            document: str = "doc") -> md.Passage:
    return md.Passage(identity, "d", document, 1, spans, start, end, "heading", "body", False)


def test_mining_excludes_all_qrels_and_overlapping_positive_spans() -> None:
    query = replace(dataset().queries[0], passage_ids=("p1", "p2"))
    passages = {p.passage_id: p for p in [passage("p1", 0, 10), passage("p2", 30, 40, ("3",)),
        passage("overlap", 8, 20, ("2",)), passage("same-span", 50, 60, ("3",)),
        passage("safe1", 20, 30, ("2",)), passage("safe2", 0, 10, document="other")]}
    frozen = ["p1", "overlap", "p2", "same-span", "safe1", "safe2"]
    row = g8.triple(query, passages, frozen, list(reversed(frozen)), split="train")
    assert row is not None
    assert [n["id"] for n in row["negatives"]] == ["safe1", "safe2"]
    assert row["positive"]["id"] in {"p1", "p2"}
    assert row["known_positive_ids"] == ["p1", "p2"]
    assert all(p["relevant"] == (p["id"] in {"p1", "p2"}) for p in row["candidates"])
    assert g8.triple(query, passages, ["p1"], ["p1", "p2"], split="train") is None


def test_lexical_mode_adapter_forwards_without_silent_fallback() -> None:
    class Store:
        def snapshot(self, *, lexical_mode: str, **kwargs: Any) -> Any:
            return lexical_mode

    class OldStore:
        def snapshot(self, **kwargs: Any) -> Any:
            return kwargs["mode"]

    assert cast(Any, g8.lexical_snapshot(cast(Any, Store()), "c", "q", "v", "any_terms")) == "any_terms"
    assert cast(Any, g8.lexical_snapshot(cast(Any, OldStore()), "c", "q", "v", "all_terms")) == "hybrid"
    with pytest.raises(ValueError, match="G1a"):
        g8.lexical_snapshot(OldStore(), "c", "q", "v", "any_terms")  # type: ignore[arg-type]


def test_offline_preflight_and_caps() -> None:
    plan, job, configuration = g8.planning(dataset(), mode="any_terms", train_limit=8, validation_limit=2,
        max_usd=Decimal("0.25"), max_calls=100, max_tokens=10000, max_seconds=180)
    assert plan["queries"] == len(job.inputs) == 10
    assert plan["preflight_is_offline"] is True
    assert configuration.caps.operation_calls == 100
    with pytest.raises(ValueError, match="exceeds_caps"):
        g8.planning(dataset(), mode="any_terms", train_limit=8, validation_limit=2,
            max_usd=Decimal("0.25"), max_calls=100, max_tokens=1, max_seconds=180)


def test_cli_new_group_and_paid_opt_in_before_data_or_credentials(tmp_path: Path) -> None:
    args = ["g8", "mine", "--archive", str(tmp_path / "missing.zip"), "--out", str(tmp_path / "out"),
            "--app-dsn-file", str(tmp_path / "dsn"), "--workspace", "00000000-0000-0000-0000-000000000001",
            "--lexical-mode", "any_terms", "--max-usd", ".25", "--max-calls", "200",
            "--max-input-tokens", "7000000", "--max-seconds", "3600"]
    assert parser().parse_args(args).g8_command == "mine"
    assert main(args) == 1


def test_mine_freezes_selected_queries_and_ledger_configuration(tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from policyops.providers.embedding_calls import PreparedJob

    data = replace(dataset(), passages=(passage("positive", 0, 10), passage("negative", 20, 30, ("2",))))
    plan, job, configuration = g8.planning(data, mode="any_terms", train_limit=8, validation_limit=2,
        max_usd=Decimal("0.25"), max_calls=100, max_tokens=10000, max_seconds=180)
    tokenizer = load_tokenizer()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    generation = UUID(int=1)
    hit_positive = Hit(UUID(int=2), "md2d/positive", 2, "0.1", ())
    hit_negative = Hit(UUID(int=3), "md2d/negative", 1, "0.2", ())
    snapshot = SimpleNamespace(generation_id=generation, text_oversized=0, dense_nan_distance=0,
        embedding_model="text-embedding-3-small", dimension=1536, lexical=[hit_positive, hit_negative],
        dense=[hit_negative, hit_positive])
    requests: list[str] = []

    class Retriever:
        def snapshot(self, *, lexical_mode: str, **kwargs: Any) -> Any:
            requests.append(kwargs["query"])
            assert lexical_mode == "any_terms"
            return snapshot

    def executor(*args: Any, **kwargs: Any) -> Any:
        return SimpleNamespace(tokenizer=tokenizer, embeddings=object(), retrieval=Retriever(),
                               generation=generation, binding=lambda: {"generation": str(generation)})

    def embed(ledger: Any, store: Any, providers: Any, prepared: PreparedJob, **kwargs: Any) -> Any:
        assert ledger.configuration is configuration
        assert prepared.job.purpose == "g8-mining-v1"
        assert prepared.job.inputs == job.inputs
        return SimpleNamespace(job_id=UUID(int=4), status="complete", reason=None,
            vectors=[SimpleNamespace(position=i, vector=(0.1,)) for i in range(len(prepared.inputs))])

    monkeypatch.setattr(g8, "RetrieverExecutor", executor)
    monkeypatch.setattr(g8, "AppLedgerStore", lambda *args, **kwargs: object())
    monkeypatch.setattr(g8, "run_job_sync", embed)
    output = tmp_path / "mined"
    result = g8.mine(data, plan, job, configuration, engine=cast(Any, object()), workspace=UUID(int=5),
                     corpus="test", output=output, providers=cast(Any, object()))
    rows = [json.loads(raw) for raw in (output / "triples.jsonl").read_bytes().splitlines()]
    assert requests == list(job.inputs)
    assert len(rows) == 10 and result["counts"]["negatives"] == 10
    assert result["triples_sha256"] == g8.file_hash(output / "triples.jsonl")
    assert {r["partition"] for r in rows} == {"train", "internal_validation"}
    assert all(r["negatives"][0]["id"] == "negative" for r in rows)
