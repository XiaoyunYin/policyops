"""Private materialization bindings and the public projection do not rely on text trust."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import runner as r

from .test_qa_runner import fixture_study
from .test_qa_study_config import parse
from .test_qa_study_registration import materialize_manifests


def test_private_hashes_gold_separation_and_corruption(tmp_path: Path) -> None:
    study, inputs = fixture_study()
    value = study.model_dump(mode="json")
    materialize_manifests(value, tmp_path)
    path = tmp_path / value["data"]["queries"]["path"]
    manifest = json.loads(path.read_bytes())
    selected = manifest["cohorts"]["dev"]
    selected["query_ids"] = list(inputs.queries)
    selected["query_ids_sha256"] = sha256_bytes("".join(q + "\n" for q in inputs.queries).encode())
    selected["dialogue_ids"] = ["fictional/dialogue"]
    private = tmp_path / "private"
    private.mkdir()
    rows: dict[str, list[dict[str, Any]]] = {
        "queries.jsonl": [{"query_id": q.question_id, "domain": "fictional", "dialogue_id": "dialogue",
            "retrieval": q.history, "last_turn": q.last_turn} for q in inputs.queries.values()],
        "references.jsonl": [{"query_id": q, "answer": "NEVER SENT TO RETRIEVAL", "target_act": "respond_solution",
                               "passage_ids": list(inputs.gold[q].passage_ids)} for q in inputs.queries],
        "passages.jsonl": [{"passage_id": "md2d.p/" + "a" * 64, "heading": "Fictional", "body": "A rule"}],
    }
    hashes = {}
    for name, records in rows.items():
        raw = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in records)
        hashes[name] = sha256_bytes(raw)
        (private / name).write_bytes(raw)
    manifest["materialization_sha256"] = hashes
    raw = canonical_bytes(manifest)
    path.write_bytes(raw)
    for ref in list(value["data"].values()) + [c["manifest"] for c in value["schedule"]["cohorts"]]:
        if isinstance(ref, dict) and "path" in ref:
            ref["sha256"] = sha256_bytes(raw)
    study = parse(value)
    loaded = r.load_inputs(study, private, root=tmp_path)
    assert loaded.queries == inputs.queries
    assert "NEVER SENT" not in repr(loaded.queries)
    assert "NEVER SENT" not in repr(loaded.gold)
    assert len(r.schedule(study, loaded)) == 12
    (private / "references.jsonl").write_bytes(b"{}\n")
    with pytest.raises(r.Refused, match="hash"):
        r.load_inputs(study, private, root=tmp_path)


def test_public_metrics_projection_drops_text_and_refuses_non_numbers() -> None:
    assert r.sanitized_metrics({"recall_at_5": "1/2", "answer": "private text"}) == {"recall_at_5": "1/2"}
    for raw in ("private text", "2", "1/0", "9" * 65):
        with pytest.raises(r.Refused, match="metric"):
            r.sanitized_metrics({"recall_at_5": raw})
