"""Small local random BERT; no downloaded models or provider calls in tests."""
from __future__ import annotations

from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
from typing import Any

import pytest
import torch
from transformers import BertConfig, BertForSequenceClassification, BertTokenizerFast

from policyops_reranker.model import canonical, configure_cpu, load, seal, sha256, verify
from policyops_reranker.score import MAX_LINE, pair, scores
from policyops_reranker.serve import request, worker
from policyops_reranker.train import (
    RECIPE,
    RECIPE_V2,
    Unstable,
    examples_for_recipe,
    fit,
    optimizer_steps,
    schedule_multiplier,
    train,
)


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    directory = tmp_path / "base"
    directory.mkdir()
    configure_cpu(1)
    torch.manual_seed(7)
    vocab = "[PAD]\n[UNK]\n[CLS]\n[SEP]\n[MASK]\nhello\nworld\ngood\nbad\nquery\n"
    (directory / "vocab.txt").write_bytes(vocab.encode())
    tokenizer = BertTokenizerFast(  # type: ignore[no-untyped-call]
        vocab_file=str(directory / "vocab.txt"), do_lower_case=True)
    tokenizer.save_pretrained(str(directory))
    config = BertConfig(vocab_size=10, hidden_size=16, intermediate_size=32,  # type: ignore[no-untyped-call]
        num_hidden_layers=1, num_attention_heads=2, num_labels=1, max_position_embeddings=512,
        hidden_dropout_prob=0.0, attention_probs_dropout_prob=0.0)
    model = BertForSequenceClassification(config)  # type: ignore[no-untyped-call]
    model.save_pretrained(str(directory), safe_serialization=True)
    seal(directory)
    return directory


def rows() -> list[dict[str, Any]]:
    return [{"partition": split, "query_id": str(i), "dialogue_id": str(i), "query": "hello query",
             "positive": {"id": "p", "text": "good world"}, "negatives": [{"id": "n", "text": "bad world"}],
             "known_positive_ids": ["p"], "candidates": [
                 {"id": "p", "text": "good world", "relevant": True},
                 {"id": "n", "text": "bad world", "relevant": False}]}
            for i, split in enumerate(("train", "internal_validation"))]


def test_hash_and_identity_refusal(artifact: Path) -> None:
    identity = verify(artifact)
    with pytest.raises(ValueError, match="identity"):
        load(artifact, expected_sha256="0" * 64)
    assert verify(artifact, identity) == identity
    with (artifact / "vocab.txt").open("ab") as handle:
        handle.write(b"changed")
    with pytest.raises(ValueError, match="file_hash"):
        load(artifact)


@pytest.mark.parametrize("filename", ["pytorch_model.bin", "model.pt", "extra.py"])
def test_pickle_and_extra_files_refused(artifact: Path, filename: str) -> None:
    (artifact / filename).write_bytes(b"never deserialize")
    with pytest.raises(ValueError, match="unexpected"):
        load(artifact)


def test_deterministic_scores_and_prefix_policy(artifact: Path) -> None:
    model, tokenizer, _ = load(artifact, threads=1)
    passages = [("a", "good world"), ("b", "bad world")]
    assert scores(model, tokenizer, "hello query", passages) == scores(model, tokenizer, "hello query", passages)
    tensors, record = pair(tokenizer, "hello " * 200, "world " * 800)
    assert record.query_tokens == 200 and record.query_used == 128
    assert record.passage_tokens == 800 and record.passage_used == 253
    assert len(tensors["input_ids"]) == 384
    assert tensors["token_type_ids"].count(1) == 254


@pytest.mark.parametrize("value", [
    {"query": "hi", "passages": [], "top_k": 1},
    {"query": "hi", "passages": [{"id": "p", "text": "x"}] * 51, "top_k": 1},
    {"query": "x" * 20001, "passages": [{"id": "p", "text": "x"}], "top_k": 1},
    {"query": "hi", "passages": [{"id": "p", "text": "x" * 20001}], "top_k": 1},
    {"query": "hi", "passages": [{"id": "p", "text": "x"}], "top_k": True},
    {"query": "hi", "passages": [{"id": "p", "text": "x"}], "top_k": 2},
    {"query": "hi", "passages": [{"id": "p", "text": "x", "extra": 1}], "top_k": 1},
    {"query": "hi", "passages": [{"id": "p", "text": "x"}], "top_k": 1, "other": 0},
])
def test_protocol_rejects_bounds(value: object) -> None:
    with pytest.raises(ValueError):
        request(canonical(value) + b"\n")


def test_worker_eof_invalid_and_oversized() -> None:
    def no_score(query: str, passages: list[tuple[str, str]]) -> list[dict[str, Any]]:
        raise AssertionError("invalid request must not score")

    sink = BytesIO()
    assert worker(BytesIO(b'{"query":"x","query":"y"}\n'), sink, "0" * 64, no_score) == 0
    assert json.loads(sink.getvalue())["error"]
    assert worker(BytesIO(b"x" * (MAX_LINE + 1)), BytesIO(), "0" * 64, no_score) == 2
    assert worker(BytesIO(), BytesIO(), "0" * 64, no_score) == 0


def test_train_tiny_end_to_end(artifact: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    triples = tmp_path / "triples.jsonl"
    triples.write_bytes(b"".join(canonical(r) + b"\n" for r in rows()))
    manifest = tmp_path / "mining.json"
    manifest.write_bytes(canonical({"triples_sha256": sha256(triples)}))
    identity = train(artifact, triples, manifest, tmp_path / "trained", threads=1, recipe_name="v2")
    result = tmp_path / "trained/artifact"
    assert verify(result, identity) == identity
    record = json.loads((result / "training-manifest.json").read_bytes())
    assert record["attempts"][0]["steps"] == 1
    assert record["recipe_name"] == "v2"
    assert record["recipe"] == RECIPE_V2
    assert len(record["attempts"]) == 1
    assert record["attempts"][0]["recipe_name"] == "v2"
    assert len(record["attempts"][0]["step_learning_rate"]) == record["attempts"][0]["steps"]
    model, tokenizer, _ = load(result, threads=1)
    assert len(scores(model, tokenizer, "hello", [("p", "world")])) == 1


def test_pairwise_step_changes_weights_and_nonfinite_refused(artifact: Path) -> None:
    model, tokenizer, _ = load(artifact, threads=1)
    original = deepcopy(model.state_dict())
    record: dict[str, Any] = {}
    fit(model, tokenizer, rows()[:1], rows()[1:], learning_rate=2e-5, recipe_name="v1", record=record)
    assert any(not torch.equal(original[k], v) for k, v in model.state_dict().items())
    assert record["step_learning_rate"] == [2e-5]
    with torch.no_grad():
        model.classifier.weight.fill_(float("nan"))
    with pytest.raises(ValueError, match="nonfinite"):
        fit(model, tokenizer, rows()[:1], rows()[1:], learning_rate=2e-5, record={})


def test_v1_recipe_and_constant_learning_rate_are_unchanged() -> None:
    assert RECIPE == {
        "dtype": "float32", "device": "cpu", "batch": 8, "accumulation": 4,
        "optimizer": "AdamW", "weight_decay": 0.01, "learning_rate": 2e-5,
        "retry_learning_rate": 1e-5, "epochs": 1, "seed": 20261114,
        "max_optimizer_steps": 1500, "checkpoint_every": 100,
        "truncation_policy": "g8.bert-prefix-query128-pair384/v1",
        "unstable": "nonfinite loss/gradient or final ndcg10 < initial - 0.02",
    }
    assert RECIPE["learning_rate"] == 2e-5
    assert RECIPE["retry_learning_rate"] == 1e-5


def test_v2_schedule_and_optimizer_step_count() -> None:
    assert schedule_multiplier(0, 100) == 0
    assert schedule_multiplier(10, 100) == 1
    assert schedule_multiplier(100, 100) == 0
    assert optimizer_steps(2 * 12_000) == 750


def test_v2_epoch_orders_are_deterministic_and_differ() -> None:
    train_rows = [
        {"query": f"query-{i}", "positive": {"text": f"positive-{i}"},
         "negatives": [{"text": f"negative-{i}"}]}
        for i in range(12)
    ]
    first = examples_for_recipe(train_rows, "v2")
    second = examples_for_recipe(train_rows, "v2")
    assert first == second
    assert first[:12] != first[12:]


def test_unstable_retry_is_single_and_recorded(artifact: Path, tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    import policyops_reranker.train as module

    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    triples = tmp_path / "triples.jsonl"
    triples.write_bytes(b"".join(canonical(r) + b"\n" for r in rows()))
    manifest = tmp_path / "mining.json"
    manifest.write_bytes(canonical({"triples_sha256": sha256(triples)}))

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise Unstable("nonfinite_loss")

    monkeypatch.setattr(module, "fit", fail)
    with pytest.raises(Unstable):
        train(artifact, triples, manifest, tmp_path / "unstable", threads=1, recipe_name="v1")
    attempts = json.loads((tmp_path / "unstable/attempts.json").read_bytes())["attempts"]
    assert [a["learning_rate"] for a in attempts] == [2e-5, 1e-5]
    assert [a["status"] for a in attempts] == ["unstable", "unstable"]


def test_v2_unstable_attempt_does_not_retry(artifact: Path, tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    import policyops_reranker.train as module

    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    triples = tmp_path / "triples.jsonl"
    triples.write_bytes(b"".join(canonical(r) + b"\n" for r in rows()))
    manifest = tmp_path / "mining.json"
    manifest.write_bytes(canonical({"triples_sha256": sha256(triples)}))

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise Unstable("nonfinite_loss")

    monkeypatch.setattr(module, "fit", fail)
    with pytest.raises(Unstable, match="nonfinite_loss"):
        train(artifact, triples, manifest, tmp_path / "unstable-v2", threads=1, recipe_name="v2")
    attempts = json.loads((tmp_path / "unstable-v2/attempts.json").read_bytes())
    assert attempts["recipe_name"] == "v2"
    assert attempts["recipe"] == RECIPE_V2
    assert len(attempts["attempts"]) == 1
    assert attempts["attempts"][0]["status"] == "unstable"


def test_selection_keeps_baseline_when_validation_never_improves(artifact: Path,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    import policyops_reranker.train as module

    model, tokenizer, _ = load(artifact, threads=1)
    original = deepcopy(model.state_dict())
    monkeypatch.setattr(module, "ndcg", lambda *args: 0.5)
    record: dict[str, Any] = {}
    selected = fit(model, tokenizer, rows()[:1], rows()[1:], learning_rate=2e-5,
                   recipe_name="v1", record=record)
    assert record["selected_step"] == 0
    assert record["selected_ndcg10"] == 0.5
    assert all(torch.equal(selected[k], original[k]) for k in selected)


def test_validation_drop_triggers_preregistered_instability(artifact: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import policyops_reranker.train as module

    model, tokenizer, _ = load(artifact, threads=1)
    values = iter([.8, .77])
    monkeypatch.setattr(module, "ndcg", lambda *args: next(values))
    with pytest.raises(Unstable, match="validation_drop"):
        fit(model, tokenizer, rows()[:1], rows()[1:], learning_rate=2e-5, record={})
