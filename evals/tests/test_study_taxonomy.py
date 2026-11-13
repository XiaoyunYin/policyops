"""Hash-linked taxonomy, complete denominators and content exclusion."""

from collections import Counter
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from policyops_evals import cli
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.studies import bundles, taxonomy

from .t32_support import frozen_fixture


def fixture(root: Path) -> tuple[Path, str, list[Path]]:
    frozen, snapshot = frozen_fixture()
    directory = root / "benchmarks/studies" / str(frozen.study_id)
    invocation = root / "benchmarks" / str(uuid4())
    files: list[Path] = []
    rows = []
    for i, row in enumerate(snapshot.trials):
        if i == 0:  # A scheduled slot without raw evidence stays in the denominator.
            rows.append(row)
            continue
        agent = {"conversation_id": str(uuid4()), "config_sha256": "1" * 64, "turns": 1,
            "model_calls": 2, "knowledge_steps": 0, "consecutive_invalid": 2,
            "terminal": "invalid_steps" if row.status == "error" else None,
            "transcript": [{"kind": "user", "text": "HIDDEN_TASK_CANARY"},
                           {"kind": "notice", "code": "text_with_tool_call"}]}
        target = invocation / f"{row.slot_id}-agent.json"
        bundles.write(target, canonical_bytes(agent))
        files.append(target)
        result = {"outcome": row.status, "error_class": "CANARY_IN_ERROR" if i == 1 else None,
            "agent_snapshot_sha256": sha256_bytes(target.read_bytes()), "transcript": "RAW_TRANSCRIPT_CANARY"}
        target = invocation / f"{row.slot_id}-result.json"
        raw = canonical_bytes(result)
        bundles.write(target, raw)
        files.append(target)
        rows.append(row.model_copy(update={"artifact_sha256": sha256_bytes(raw)}))
    digest = bundles.seal(directory, frozen, snapshot.model_copy(update={"trials": tuple(rows)}))
    entries = [{"path": f"{invocation.name}/{p.name}", "bytes": p.stat().st_size,
                "sha256": sha256_bytes(p.read_bytes())} for p in files]
    bundles.write(directory / f"private-inventory-{invocation.name}.json", canonical_bytes({
        "schema_version": "policyops.private-inventory/v1", "base": "benchmarks", "files": entries}))
    return directory / "study.json", digest, files


def test_taxonomy_counts_are_complete_sanitized_and_deterministic(monkeypatch: pytest.MonkeyPatch,
                                                                 tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    path, digest, _ = fixture(tmp_path)
    for key in ("POLICYOPS_EVAL_DATABASE_DSN", "POLICYOPS_EVAL_ACQUIRED", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    for name in ("one", "two"):
        assert cli.main(["taxonomy", "--study", str(path), "--snapshot", digest,
                         "--out", str(tmp_path / name)]) == 0
    for name in ("taxonomy.json", "taxonomy.md"):
        raw = (tmp_path / "one" / name).read_bytes()
        assert raw == (tmp_path / "two" / name).read_bytes()
        assert b"CANARY" not in raw and b"transcript" not in raw and b"\r" not in raw
    result = json.loads((tmp_path / "one/taxonomy.json").read_bytes())
    assert result["scheduled_trials"] == sum(r["count"] for r in result["counts"]) == 16
    assert sum(r["count"] for r in result["per_task"]) == 16
    assert any(r["agent_terminal_reason"] == "unavailable" for r in result["counts"])
    assert any(r["error_class"] == "unknown_error" for r in result["counts"])
    by_task: Counter[tuple[str, str]] = Counter()
    for row in result["per_task"]:
        by_task[row["task_id"], row["variant"]] += row["count"]
    assert set(by_task.values()) == {4}


@pytest.mark.parametrize("damage", ["result", "agent", "inventory_hash", "missing", "snapshot", "link", "path"])
def test_taxonomy_refuses_tamper_without_outputs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damage: str) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    path, digest, files = fixture(tmp_path)
    inv = next(path.parent.glob("private-inventory-*.json"))
    if damage in {"result", "agent"}:
        target = next(p for p in files if p.name.endswith(f"-{damage}.json"))
        target.write_bytes(target.read_bytes() + b" ")
    elif damage == "missing":
        files[0].unlink()
    elif damage == "snapshot":
        digest = "0" * 64
    else:
        body: Any = json.loads(inv.read_bytes())
        if damage == "inventory_hash":
            body["files"][0]["sha256"] = "0" * 64
        elif damage == "path":
            body["files"][0]["path"] = "../escape"
        else:
            # A self-consistent inventory cannot replace the sealed hash anchor.
            target = next(p for p in files if p.name.endswith("-result.json"))
            raw = canonical_bytes(json.loads(target.read_bytes()) | {"outcome": "aborted"})
            target.write_bytes(raw)
            entry = next(e for e in body["files"] if e["path"].endswith(target.name))
            entry.update(bytes=len(raw), sha256=sha256_bytes(raw))
        inv.write_bytes(canonical_bytes(body))
    assert cli.main(["taxonomy", "--study", str(path), "--snapshot", digest, "--out", str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists()


def test_taxonomy_empty_inventory_is_valid_only_for_slots_without_artifact_hashes(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    frozen, snapshot = frozen_fixture()
    directory = tmp_path / "benchmarks/studies" / str(frozen.study_id)
    digest = bundles.seal(directory, frozen, snapshot)
    result = taxonomy.render(directory / "study.json", snapshot=digest, out=tmp_path / "out")
    assert sum(r["count"] for r in result["counts"] if r["agent_terminal_reason"] == "unavailable") == 16
