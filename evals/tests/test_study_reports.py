"""Frozen reports are sanitized and sufficient without live dependencies."""

import builtins
from datetime import UTC, datetime
from decimal import Decimal
import json
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any
from uuid import uuid4, uuid5

import pytest

from policyops_evals import cli
from policyops_evals.canonical import canonical_bytes
from policyops_evals.studies import bundles, reports, snapshots
from policyops_evals.studies.report_models import AttemptRow, Snapshot

from .t32_support import frozen_fixture


def test_frozen_rerender_is_identical_without_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    frozen, snapshot = frozen_fixture()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    bundle = tmp_path / "bundle"
    digest = bundles.seal(bundle, frozen, snapshot)
    original_import = builtins.__import__

    def imports(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith(("tau2", "policyops.persistence", "policyops.providers", "policyops_evals.upstream")):
            pytest.fail("execution import on frozen report path: " + name)
        return original_import(name, *args, **kwargs)

    def blocked(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("live runtime accessed by frozen report")

    monkeypatch.setattr(builtins, "__import__", imports)
    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "POLICYOPS_EVAL_DATABASE_DSN", "POLICYOPS_EVAL_ACQUIRED"):
        monkeypatch.delenv(key, raising=False)
    from policyops_evals.studies import config, registration

    monkeypatch.setattr(config, "load_committed", blocked)
    monkeypatch.setattr(registration, "prices", blocked)
    for name in ("one", "two"):
        assert cli.main(["report", "--study", str(bundle / "study.json"), "--snapshot", digest,
                         "--out", str(tmp_path / name)]) == 0
    for filename in ("report.json", "report.md"):
        data = (tmp_path / "one" / filename).read_bytes()
        assert data == (tmp_path / "two" / filename).read_bytes()
        assert b"\r" not in data
        assert b"CANARY" not in data and b"postgresql://" not in data
    result = json.loads((tmp_path / "one/report.json").read_bytes())
    metric = next(m for m in result["metrics"] if m["scope"] == "db_nl" and m["k"] == 1)
    assert metric["strict"]["estimate"]["point"] == .75
    assert metric["db_component"]["estimate"]["point"] == 1
    assert metric["complete_case"]["estimate"]["point"] == 1
    assert result["decision"]["status"] == "descriptive"
    assert result["eligibility"]["denominator_before"] == result["eligibility"]["denominator_after"] == 16


def test_snapshots_are_numbered_immutable_and_explicit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    frozen, snapshot = frozen_fixture()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    root = tmp_path / "bundle"
    first = bundles.seal(root, frozen, snapshot)
    before = (root / "snapshot-000001/snapshot.json").read_bytes()
    second = bundles.seal(root, frozen, snapshot)
    assert first != second  # inventory paths bind the numbered snapshot
    assert before == (root / "snapshot-000001/snapshot.json").read_bytes()
    with pytest.raises(bundles.BundleRefused, match="explicit_snapshot"):
        bundles.load(root / "study.json")
    assert bundles.load(root / "study.json", first)[3] == first
    with pytest.raises(bundles.BundleRefused):
        bundles.write(root / "study.json", b"tampered")


def test_fresh_cli_process_has_no_live_import_or_credential_reads(monkeypatch: pytest.MonkeyPatch,
                                                                 tmp_path: Path) -> None:
    frozen, snapshot = frozen_fixture()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    root = tmp_path / "bundle"
    digest = bundles.seal(root, frozen, snapshot)
    script = '''
import builtins, os, socket, subprocess, sys
original_import = builtins.__import__
def imports(name, *args, **kwargs):
    if name.startswith(("tau2", "policyops.persistence", "policyops.providers", "policyops_evals.studies.runner")):
        raise AssertionError("live import")
    return original_import(name, *args, **kwargs)
def blocked(*args, **kwargs):
    raise AssertionError("live I/O")
original_get = os._Environ.__getitem__
def env_get(self, key):
    if key in {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "POLICYOPS_EVAL_DATABASE_DSN", "POLICYOPS_EVAL_ACQUIRED"}:
        raise AssertionError("credential read")
    return original_get(self, key)
builtins.__import__ = imports
socket.socket = blocked
subprocess.run = blocked
os._Environ.__getitem__ = env_get
from policyops_evals.cli import main
raise SystemExit(main(["report", "--study", sys.argv[1], "--snapshot", sys.argv[2], "--out", sys.argv[3]]))
'''
    result = subprocess.run([sys.executable, "-B", "-c", script, str(root / "study.json"), digest,
                             str(tmp_path / "fresh")], capture_output=True, encoding="utf-8", timeout=60)
    assert result.returncode == 0, result.stderr[-2000:]
    assert (tmp_path / "fresh/report.json").is_file()


@pytest.mark.parametrize("damage", ["bytes", "missing", "wrong-seed", "duplicate", "foreign", "stratum"])
def test_all_declared_damage_refused(damage: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    frozen, snapshot = frozen_fixture()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    root = tmp_path / "bundle"
    digest = bundles.seal(root, frozen, snapshot)
    if damage == "bytes":
        (root / "snapshot-000001/trials-0000.json").write_bytes(b"[]\n")
    elif damage == "missing":
        (root / "snapshot-000001/trials-0000.json").unlink()
    else:
        body = snapshot.model_dump(mode="json")
        if damage == "wrong-seed":
            body["trials"][0]["seed"] += 1
        elif damage == "duplicate":
            body["trials"][1] = body["trials"][0]
        elif damage == "foreign":
            body["trials"][0]["task_id"] = "foreign"
        else:
            body["trials"][0]["stratum"] = "db_only"
        broken = Snapshot.model_validate_json(canonical_bytes(body))
        digest = bundles.seal(root, frozen, broken)
    assert cli.main(["report", "--study", str(root / "study.json"), "--snapshot", digest,
                     "--out", str(tmp_path / "result")]) == 1


def test_raw_canaries_are_not_report_fields() -> None:
    frozen, _ = frozen_fixture()
    # SQL exports can contain arbitrary private scorer content. Only booleans,
    # fixed classes and hash/registry identities cross normalization.
    from .t29_study_support import StudyStore
    from .t32_support import StudyRepository

    store = StudyStore()
    repo = StudyRepository(store)
    raw = repo.export_study(frozen.study_id, None)  # type: ignore[arg-type]
    snapshot = snapshots.normalize(frozen, raw)
    assert len(snapshot.trials) == len(frozen.schedule)
    assert all(r.status == "pending" for r in snapshot.trials)
    trial = snapshot.trials[0]
    variant = next(v for v in frozen.variants if v.name == trial.variant)
    raw["trials"] = [{"id": trial.slot_id, "evaluation_run_id": uuid5(frozen.study_id, variant.config_sha256),
        "task_id": trial.task_id, "trial_index": trial.trial_index, "seed": trial.seed,
        "scenario_scope": trial.scenario_id, "state": "finalized", "outcome": "success", "reward": Decimal("1"),
        "components": {"private_prompt": "CANARY-password-transcript", "provider_request_id": "CANARY-provider",
            "environment": {"db_check": {"db_match": True}, "reasoning": "CANARY-db-reason"},
            "composite": None}, "error_class": "CANARY-arbitrary-exception"}]
    snapshot = snapshots.normalize(frozen, raw)
    observed = next(r for r in snapshot.trials if r.slot_id == trial.slot_id)
    assert observed.db_success is True and observed.composite_success is None
    assert observed.stratum == "db_nl" and observed.failure_class == "judge_unavailable"
    assert b"CANARY" not in canonical_bytes(snapshot.model_dump(mode="json"))
    assert reports.cell("<script>|`\n") == "&lt;script&gt;&#124;&#96; "


def test_billing_timing_and_contradictory_snapshots() -> None:
    frozen, snapshot = frozen_fixture()
    body = snapshot.model_dump(mode="json")
    row = body["trials"][0]
    attempt = {"id": str(uuid4()), "scenario_id": row["scenario_id"], "actor": "agent", "model": "gpt-6-luna",
        "state": "settled", "count_state": "admitted", "actual_usd": "0.001", "reserved_usd": "0.002624",
        "input_total": 100, "output": 20, "reasoning": 10, "cache_read": 30, "cache_write": 10, "usage_valid": True}
    body["attempts"] = [attempt]
    row["cost_usd"] = "0.001"
    for scope in body["scopes"]:
        if scope["id"] in {row["scenario_id"], str(frozen.study_id)}:
            scope.update(spent_usd="0.001", calls_consumed=1, counts_used=1)
    body["timings"] = [{"slot_id": row["slot_id"], "call_id": str(uuid4()), "actor": "agent",
        "started_at": "2026-11-12T00:00:00Z", "finished_at": "2026-11-12T00:00:00.020Z", "wall_ms": 20}]
    result = reports.build(frozen, Snapshot.model_validate_json(canonical_bytes(body)), "0" * 64, "1" * 64)
    assert result["accounting"]["discrepancies"] == []
    assert result["accounting"]["tokens"] == {"input_total": 100, "output": 20,
                                            "reasoning": 10, "cache_read": 30, "cache_write": 10}
    actor = next(v for v in result["variants"] if v["name"] == row["variant"])["actors"][0]
    assert actor["timing"]["mean_ms"] == actor["timing"]["p95_ms"] == 20
    assert result["accounting"]["settled_usd"] == "0.001"
    body["scopes"][-1]["spent_usd"] = "0"
    mismatch = reports.build(frozen, Snapshot.model_validate_json(canonical_bytes(body)), "0" * 64, "1" * 64)
    assert "ledger_scope_mismatch" in mismatch["accounting"]["discrepancies"]
    body["attempts"][0]["reasoning"] = 21
    with pytest.raises(ValueError):
        Snapshot.model_validate_json(canonical_bytes(body))


def test_unresolved_scored_trial_is_error_and_spend_is_an_upper_bound() -> None:
    frozen, snapshot = frozen_fixture()
    body = snapshot.model_dump(mode="json")
    row = body["trials"][0]
    row.update(cost_known=False, cost_usd=None, held_usd="0.002624")
    body["attempts"] = [{"id": str(uuid4()), "scenario_id": row["scenario_id"], "actor": "agent",
        "model": "gpt-6-luna", "state": "unresolved", "count_state": "admitted", "actual_usd": None,
        "reserved_usd": "0.002624", "usage_valid": False}]
    for scope in body["scopes"]:
        if scope["id"] in {row["scenario_id"], str(frozen.study_id)}:
            scope.update(held_usd="0.002624", calls_consumed=1, counts_used=1)
    result = reports.build(frozen, Snapshot.model_validate_json(canonical_bytes(body)), "0" * 64, "1" * 64)
    observed = next(r for r in result["trials"] if r["slot_id"] == row["slot_id"])
    assert observed["status"] == "error" and observed["composite_success"] is None
    assert not observed["cost_known"] and observed["cost_usd"] is None
    assert observed["upper_bound_usd"] == "0.002624"
    assert result["accounting"]["settled_usd"] == "0"
    assert result["accounting"]["held_usd"] == result["accounting"]["upper_bound_usd"] == "0.002624"
    assert result["decision"]["status"] == "descriptive"
    assert b"Upper-bound USD" in reports.markdown(result)


def test_timing_receipts_preserve_start_and_logical_end(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from policyops_evals.harness.timing import CallTimings, receipts

    timings = CallTimings(tmp_path, uuid4())
    call_id = uuid4()
    with pytest.raises(RuntimeError), timings.observe("judge", call_id):
        assert (tmp_path / f"{call_id}-timing-start.json").exists()
        raise RuntimeError("private-canary")
    start = json.loads((tmp_path / f"{call_id}-timing-start.json").read_bytes())
    end = json.loads((tmp_path / f"{call_id}-timing-end.json").read_bytes())
    assert start["wall_ms"] is None and end["wall_ms"] >= 0
    assert datetime.fromisoformat(end["finished_at"]).tzinfo == UTC
    assert b"canary" not in canonical_bytes(end)
    # Simulate a process lost after its start receipt was indexed. No end time
    # is guessed from billing or transcript timestamps.
    index_path = tmp_path / f"{timings.slot_id}-timings.json"
    index = json.loads(index_path.read_bytes())
    index[0]["end_sha256"] = None
    index_path.write_bytes(canonical_bytes(index))
    recovered = receipts(tmp_path, timings.slot_id)
    assert recovered[0]["wall_ms"] is None and recovered[0]["finished_at"] is None
    (tmp_path / f"{call_id}-timing-start.json").write_bytes(b"{}\n")
    with pytest.raises(bundles.BundleRefused):
        receipts(tmp_path, timings.slot_id)


def test_inventory_bounds_and_traversal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    for path in ("../secret.json", "C:/secret.json", "part/../secret.json", "part\\secret.json"):
        with pytest.raises(bundles.BundleRefused):
            bundles.child(tmp_path, path)
    with pytest.raises(bundles.BundleRefused):
        bundles.write(tmp_path / "oversize", b" " * (bundles.MAX_FILE + 1))


def test_postgres_numeric_zero_is_fixed_decimal() -> None:
    frozen, _ = frozen_fixture()
    from .t29_study_support import StudyStore
    from .t32_support import StudyRepository

    raw = StudyRepository(StudyStore()).export_study(frozen.study_id, None)  # type: ignore[arg-type]
    raw["scopes"] = [{"id": frozen.study_id, "kind": "study", "spent_usd": Decimal("0E-18"),
        "held_usd": Decimal("0E-18"), "calls_consumed": 0, "calls_held": 0, "counts_used": 0,
        "overrun": False, "contract_block": None}]
    snapshot = snapshots.normalize(frozen, raw)
    assert snapshot.scopes[0].held_usd == "0.000000000000000000"


def test_large_billed_overrun_is_not_rounded_in_rollup() -> None:
    row = {"id": str(uuid4()), "scenario_id": str(uuid4()), "actor": "agent", "model": "gpt-6-luna",
        "state": "settled", "count_state": "admitted", "actual_usd": "1234567890123.123456789012345678",
        "reserved_usd": "0.002624", "usage_valid": False}
    attempt = AttemptRow.model_validate_json(canonical_bytes(row))
    other = attempt.model_copy(update={"id": uuid4()})
    assert reports.amounts([attempt, other])["settled_usd"] == "2469135780246.246913578024691356"
