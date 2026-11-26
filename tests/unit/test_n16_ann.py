"""Offline regression tests for N16 provenance, sampling and report arithmetic."""
from __future__ import annotations

from collections import Counter
import gzip
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import n16_ann_data as ann_data
from scripts.bm25_latency_probe import percentile
from scripts.n16_ann_benchmark import digest
from scripts.n16_ann_data import DIMENSION, FILLER, SCOPES, K, Vector, cutoff_ties, split, tenant_layout, vector
from scripts.n16_ann_fetch import ARCHIVE, REVISION, SHA256, verify_sha
from scripts.n16_ann_report import read, recall_at_10, render, spread


def test_metrics_count_short_slots_as_misses_and_report_ties() -> None:
    truth = [(str(key), float(key)) for key in range(K)]
    ids = [key for key, _ in truth]
    assert recall_at_10(["0", "0", "1", "foreign"], ids) == 0.2
    assert recall_at_10([], ids) == 0
    assert percentile([5.0, 2.0, 3.0, 1.0, 4.0], 0.50) == 3
    assert percentile([5.0, 2.0, 3.0, 1.0, 4.0], 0.95) == 5
    assert percentile([], 0.95) is None
    assert spread([1.0, 3.0, 2.0], 2) == "2.00 [1.00, 3.00]"
    assert cutoff_ties([*truth, ("10", 10.0)]) == (False, False)
    assert cutoff_ties([*truth[:-1], ("9", 8.0), ("10", 10.0)]) == (True, False)
    assert cutoff_ties([*truth, ("10", 9.0)]) == (True, True)
    assert cutoff_ties(truth[:2]) == (False, False)


def test_split_and_tenant_counts_are_order_independent() -> None:
    packed = vector("seed", [1] + [0] * (DIMENSION - 1)).values
    rows = [Vector(f"source-{i}", packed) for i in range(2020)]
    base, queries = split(rows, 16, size=2000, n_queries=20)
    assert (base, queries) == split(reversed(rows), 16, size=2000, n_queries=20)
    assert {v.id for v in base}.isdisjoint(v.id for v in queries)
    assert split(rows, 16, size=1000, n_queries=20) == (base[:1000], queries)
    ids = [row.id for row in base]
    assignments = tenant_layout(ids, "filtered", 16)
    assert assignments == tenant_layout(ids[::-1], "filtered", 16)
    assert assignments != tenant_layout(ids, "filtered", 17)
    assert Counter(assignments.values()) == {
        FILLER: 1778, SCOPES[100].workspace: 200, SCOPES[10].workspace: 20, SCOPES[1].workspace: 2,
    }
    assert set(tenant_layout(ids, "single", 16).values()) == {SCOPES[1000].workspace}
    with pytest.raises(ValueError, match="duplicate_source_id"):
        split([*rows, rows[0]], 16, size=2000, n_queries=20)


@pytest.mark.parametrize("value", [0.0, float("inf"), float("nan"), 1e-100, 1e100])
def test_float32_vectors_refuse_unindexable_values(value: float) -> None:
    with pytest.raises(ValueError):
        vector("source", [value] + [0.0] * (DIMENSION - 1))


@pytest.mark.parametrize("key", ["text-embedding-ada-002", "embedding"])
def test_corpus_requires_the_archive_embedding_key(key: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    card = b"license: mit\n224,482 rows\n"
    licence = (b"the embeddings are published under MIT license\n"
               b"en.wikipedia.org/wiki/Wikipedia:Copyrights\nCopyright (c) 2023 Stephan Sturges\n")
    (tmp_path / "README.md").write_bytes(card)
    (tmp_path / "Original_License").write_bytes(licence)
    monkeypatch.setattr(ann_data, "ROWS", 1)
    # The production archive is too large for a unit test. Only its file-level pin is bypassed.
    monkeypatch.setattr(ann_data, "verify_archive", lambda _: None)
    (tmp_path / "source.json").write_text(json.dumps({
        "revision": REVISION, "sha256": SHA256, "rows": 1,
        "card_sha256": sha256(card).hexdigest(), "licence_sha256": sha256(licence).hexdigest(),
    }), encoding="utf-8")
    values = [1.0] + [0.0] * (DIMENSION - 1)
    with gzip.open(tmp_path / ARCHIVE, "wb") as archive:
        archive.write((json.dumps({"id": "fictional", key: values}) + "\n").encode())

    _, rows = ann_data.corpus(tmp_path)
    if key == "embedding":
        with pytest.raises(ValueError, match=r"^corpus_row_shape$"):
            list(rows)
    else:
        assert list(rows) == [vector("fictional", values)]


def test_fetch_verifier_rejects_a_bad_sha(tmp_path: Path) -> None:
    archive = tmp_path / "wiki_openai.ndjson.gz"
    content = b"synthetic corpus"
    archive.write_bytes(content)
    verify_sha(archive, sha256(content).hexdigest())
    with pytest.raises(ValueError, match="corpus_sha256_mismatch"):
        verify_sha(archive, "0" * 64)


def test_report_uses_named_index_and_retains_unstarted_passes(tmp_path: Path) -> None:
    layout, cell, query = "2000/single", "runtime-1000/off/natural/20", "q"
    identity = {"layout": layout, "build": 1, "pass": 1, "cell": cell}
    plan = {"Plan": {"Node Type": "Index Scan", "Actual Loops": 1, "Index Name": "n16_chunks_hnsw"}}
    hashes = digest(plan)
    rows: list[dict[str, Any]] = [
        {"kind": "run", "queries": 1, "mode": "fixture", "passes": 2, "config": {}, "dirty": False,
         "revision": "fixture", "hardware": {}, "real_corpus": "unverified", "schedule": [{
             "layout": layout, "size": 2000, "builds": [[16, 64]], "cells": [
                 {"id": cell, "scope": "runtime-1000", "method": "off", "planner": "natural",
                  "ef": 20, "visible": 2000, "per_mille": 1000},
             ],
         }]},
        {"kind": "corpus", "query_ids": [query]},
        {"kind": "truth", "layout": layout, "scope": "runtime-1000", "query": query,
         "rows": [["v1", 0.25]], "cutoff_tie": False, "crossing_tie": False},
        {"kind": "cell", **identity, "query_order": [query]},
        {"kind": "plan", **identity, "digest": hashes, "plan": plan, "query": query,
         "observed": "HNSW", "node": "Index Scan"},
        {"kind": "sample", **identity, "query": query, "rows": [["v1", 0.25]], "error": None,
         "elapsed_ms": 2.7, "plan_digest": hashes},
        {"kind": "finish", "status": "failed", "error": "SyntheticStop"},
    ]
    raw = tmp_path / "evidence.jsonl"
    raw.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    evidence = read(raw)
    report = render(evidence, "test")
    assert not evidence.complete()
    assert "0.100 [0.100, 0.100]" in report
    assert "| HNSW | Index Scan |" in report
    assert "unstarted" in report
    rows[4]["plan"]["Plan"]["Index Name"] = "different_index"
    rows[4]["digest"] = digest(rows[4]["plan"])
    raw.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    with pytest.raises(ValueError, match="plan_digest_or_classification_mismatch"):
        read(raw)
