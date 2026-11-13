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
from policyops_evals.studies.runner import provider_failures

from .t32_support import frozen_fixture


def fixture(root: Path, *, failures: list[dict[str, str]] | None = None,
            termination: object = None) -> tuple[Path, str, list[Path]]:
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
        if failures is not None:
            agent = {"schema_version": "policyops.study-agent/v1", "snapshot": agent,
                     "provider_failures": [f for f in failures if f["actor"] == "agent"]}
        target = invocation / f"{row.slot_id}-agent.json"
        bundles.write(target, canonical_bytes(agent))
        files.append(target)
        result: dict[str, Any] = {"outcome": row.status, "error_class": "CANARY_IN_ERROR" if i == 1 else None,
            "agent_snapshot_sha256": sha256_bytes(target.read_bytes()), "transcript": "RAW_TRANSCRIPT_CANARY"}
        if failures is not None:
            result["provider_failures"] = failures
        if termination is not None:
            result["simulation_termination"] = termination
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


def test_closed_attempt_codes_reach_result_agent_and_taxonomy(monkeypatch: pytest.MonkeyPatch,
                                                            tmp_path: Path) -> None:
    from policyops.providers.calls import AttemptRecord, CallReport

    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    records = [AttemptRecord(uuid4(), "agent", None, reason="http_529", dispatch_granted=True),
               AttemptRecord(uuid4(), "agent", None, reason="count.http_429"),
               AttemptRecord(uuid4(), "agent", None, reason="PRIVATE_BODY_CANARY")]
    failures = provider_failures([("agent", CallReport(None, "failed", "http_529", records))])
    assert [f["reason_code"] for f in failures] == ["http_529", "http_429"]
    assert [f["phase"] for f in failures] == ["inference", "count"]
    path, digest, files = fixture(tmp_path, failures=failures)
    for target in files:
        body = json.loads(target.read_bytes())
        assert body["provider_failures"] == failures
    result = taxonomy.render(path, snapshot=digest, out=tmp_path / "taxonomy")
    assert {r["reason_code"] for r in result["provider_failures"]} == {"http_429", "http_529"}
    assert sum(r["count"] for r in result["provider_failures"]) == 30
    assert {r["count"] for r in result["provider_failures"]} == {7, 8}
    assert b"CANARY" not in canonical_bytes(result)


def test_unknown_provider_codes_are_refused_before_taxonomy_output(monkeypatch: pytest.MonkeyPatch,
                                                                 tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    path, digest, _ = fixture(tmp_path, failures=[{"actor": "agent", "phase": "inference",
                                                "reason_code": "PRIVATE_BODY_CANARY"}])
    with pytest.raises(bundles.BundleRefused, match="private_failure_code"):
        taxonomy.render(path, snapshot=digest, out=tmp_path / "out")
    assert not (tmp_path / "out").exists()


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
    assert {r["simulation_termination"] for r in result["counts"]} == {"unavailable"}
    assert {r["simulation_termination"] for r in result["per_task"]} == {"unavailable"}
    by_task: Counter[tuple[str, str]] = Counter()
    for row in result["per_task"]:
        by_task[row["task_id"], row["variant"]] += row["count"]
    assert set(by_task.values()) == {4}


@pytest.mark.parametrize("code", ["too_many_errors", "user_stop", "PRIVATE_MESSAGE_CANARY", ["user_stop"]])
def test_simulation_termination_dimension_is_closed_and_hash_linked(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: object) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    path, digest, _ = fixture(tmp_path, termination=code)
    result = taxonomy.render(path, snapshot=digest, out=tmp_path / "out")
    expected = code if isinstance(code, str) and code in {"too_many_errors", "user_stop"} else "unknown"
    for dimension in ("counts", "per_task"):
        assert sum(r["count"] for r in result[dimension] if r["simulation_termination"] == expected) == 15
        assert sum(r["count"] for r in result[dimension] if r["simulation_termination"] == "unavailable") == 1
    markdown = (tmp_path / "out/taxonomy.md").read_bytes()
    assert b"simulation_termination" in markdown and b"CANARY" not in markdown


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
