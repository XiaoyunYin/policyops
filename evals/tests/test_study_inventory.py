"""Private inventory scaling and failure-safe final snapshot/report regression tests."""

from collections.abc import Iterator
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from policyops.budget.ledger import Ledger
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository
from policyops_evals import cli
from policyops_evals.canonical import canonical_bytes
from policyops_evals.studies import bundles, runner, runner_v2, taxonomy

from .t29_study_support import StudyStore
from .t32_support import SOURCE, StudyRepository, example


def directories(root: Path) -> tuple[Path, Path]:
    directory, invocation = root / "benchmarks/studies/study", root / "benchmarks/invocation"
    directory.mkdir(parents=True)
    invocation.mkdir()
    return directory, invocation


@pytest.mark.parametrize("count", [8193, 16571])
def test_large_inventory_parts_are_deterministic_and_linked(count: int, monkeypatch: pytest.MonkeyPatch,
                                                           tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    directory, invocation = directories(tmp_path)
    raw = canonical_bytes({"fixture": True})
    for i in reversed(range(count)):
        (invocation / f"{i:06d}.json").write_bytes(raw)
    runner_v2.raw_inventory(directory, invocation)
    parts = sorted(directory.glob("private-inventory-*.json"))
    assert [p.name for p in parts] == [f"private-inventory-invocation-part{i}of{len(parts)}.json"
                                     for i in range(1, (count + 8191) // 8192 + 1)]
    entries: list[str] = []
    found = taxonomy.inventory(directory)
    assert sum(map(len, found.values())) == count
    for part in parts:
        body, data = bundles.read(part)
        assert len(data) <= bundles.MAX_FILE
        assert 1 <= len(body["files"]) <= 8192
        assert sum(e["bytes"] for e in body["files"]) <= bundles.MAX_BYTES
        entries.extend(e["path"] for e in body["files"])
        first = body["files"][0]
        linked, path = taxonomy.linked(found, Path(first["path"]).name, first["sha256"])
        assert linked == {"fixture": True} and path.parent == invocation
    assert entries == [f"invocation/{i:06d}.json" for i in range(count)]


@pytest.mark.parametrize("bound", ["referenced", "json"])
def test_parts_obey_both_byte_bounds(bound: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    directory, invocation = directories(tmp_path)
    monkeypatch.setattr(bundles, "MAX_BYTES" if bound == "referenced" else "MAX_FILE", 1024)
    raw = b" " * 700 if bound == "referenced" else b"{}"
    for i in range(12):
        (invocation / f"{i:02d}.json").write_bytes(raw)
    runner_v2.raw_inventory(directory, invocation)
    parts = sorted(directory.glob("private-inventory-*.json"))
    assert len(parts) > 1
    for path in parts:
        body, data = bundles.read(path)
        assert len(data) <= min(bundles.MAX_FILE, bundles.MAX_BYTES)
        assert sum(e["bytes"] for e in body["files"]) <= bundles.MAX_BYTES
    assert sum(map(len, taxonomy.inventory(directory).values())) == 12


def test_aggregate_byte_refusal_writes_no_parts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(bundles, "MAX_BYTES", 1024)
    directory, invocation = directories(tmp_path)
    for i in range(24):
        (invocation / f"{i:02d}.json").write_bytes(b" " * 700)
    with pytest.raises(bundles.BundleRefused, match=r"^raw_inventory_bounds$"):
        runner_v2.raw_inventory(directory, invocation)
    assert not list(directory.iterdir())


def test_aggregate_entry_refusal_bounds_discovery_before_sorting(monkeypatch: pytest.MonkeyPatch,
                                                              tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    directory, invocation = directories(tmp_path)
    consumed = 0
    original = Path.iterdir

    def discover(path: Path) -> Iterator[Path]:
        nonlocal consumed
        if path != invocation:
            yield from original(path)
            return
        for i in range(131074):
            consumed += 1
            yield invocation / f"{i:06d}.json"

    monkeypatch.setattr(Path, "iterdir", discover)
    with pytest.raises(bundles.BundleRefused, match=r"^raw_inventory_bounds$"):
        runner_v2.raw_inventory(directory, invocation)
    assert consumed == 131073
    assert not list(directory.iterdir())


def test_aggregate_bounds_include_previous_invocations(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(bundles, "MAX_BYTES", 1024)
    directory, invocation = directories(tmp_path)
    for i in range(23):
        (invocation / f"{i:02d}.json").write_bytes(b" " * 700)
    runner_v2.raw_inventory(directory, invocation)
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    next_invocation = invocation.with_name("next")
    next_invocation.mkdir()
    (next_invocation / "extra.json").write_bytes(b" " * 700)
    with pytest.raises(bundles.BundleRefused, match=r"^raw_inventory_bounds$"):
        runner_v2.raw_inventory(directory, next_invocation)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before


def test_inventory_file_count_bound_includes_previous_parts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    directory, invocation = directories(tmp_path)
    empty = canonical_bytes({"schema_version": "policyops.private-inventory/v1", "base": "benchmarks", "files": []})
    for i in range(1000):
        (directory / f"private-inventory-previous-{i}.json").write_bytes(empty)
    with pytest.raises(bundles.BundleRefused, match=r"^raw_inventory_bounds$"):
        runner_v2.raw_inventory(directory, invocation)
    assert len(list(directory.iterdir())) == 1000


@pytest.mark.parametrize("damage", ["symlink", "junction", "directory", "oversize"])
def test_inventory_keeps_alias_and_file_bounds(damage: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    directory, invocation = directories(tmp_path)
    target = invocation / "raw.json"
    target.write_bytes(b"{}")
    if damage in {"symlink", "junction"}:
        method = "is_" + damage
        original = getattr(Path, method)
        monkeypatch.setattr(Path, method, lambda p: p == target or original(p))
    elif damage == "directory":
        (invocation / "nested").mkdir()
    else:
        monkeypatch.setattr(bundles, "MAX_FILE", 1)
    with pytest.raises(bundles.BundleRefused, match=r"^raw_inventory_bounds$"):
        runner_v2.raw_inventory(directory, invocation)
    assert not list(directory.iterdir())


@pytest.mark.parametrize("primary_error", [False, True])
def test_inventory_failure_preserves_final_snapshot_report_and_error(primary_error: bool,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    study, store = example(), StudyStore()
    repository = StudyRepository(store)
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(runner_v2, "source_provenance", lambda: SOURCE)
    inputs = {t: runner.TrialInputs(SimpleNamespace(evaluation_criteria=SimpleNamespace(nl_assertions=[])))
              for t in study.tasks}
    monkeypatch.setattr(runner, "execute_trial", lambda *args: {
        "outcome": "success", "reward": "1", "error_class": None,
        "environment": {"db_check": {"db_match": True}}, "composite": {"reward": 1}})
    trial_failure = RuntimeError("finalization_failed_after_commit")
    original = repository.finalize

    def finalize(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        if primary_error and len(repository.terminals) == 16:
            raise trial_failure

    monkeypatch.setattr(repository, "finalize", finalize)
    inventory_failure = bundles.BundleRefused("raw_inventory_bounds")
    sealed = []

    def fail_inventory(directory: Path, invocation: Path) -> None:
        assert len(repository.terminals) == 16
        index = json.loads((directory / "snapshots.json").read_bytes())
        digest = index["snapshots"][-1]["sha256"]
        _, snapshot, _, _ = bundles.load(directory / "study.json", digest)
        assert len(snapshot.trials) == 16 and all(t.status == "success" for t in snapshot.trials)
        sealed.append((directory, digest))
        raise inventory_failure

    monkeypatch.setattr(runner_v2, "raw_inventory", fail_inventory)

    def run(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return runner.run_study(study, cast(EvaluationRepository, repository), cast(EvalLedgerStore, store),
            inputs=inputs, make_ledger=lambda variant, token: Ledger(store, study.configuration(variant)),
            make_providers=lambda _: lambda: None)  # type: ignore[arg-type,return-value]

    with pytest.raises(RuntimeError if primary_error else bundles.BundleRefused) as caught:
        run()
    assert caught.value is (trial_failure if primary_error else inventory_failure)
    if primary_error:
        assert "private inventory export unconfirmed" in caught.value.__notes__
    directory, digest = sealed.pop()
    report = json.loads((directory / f"report-{digest}/report.json").read_bytes())
    assert report["snapshot_sha256"] == digest and report["execution_status"] == "finalized"
    assert report["integrity_status"] == "valid"
    assert len(repository.terminals) == 16
    # The existing CLI must still return nonzero for the incomplete evidence chain.
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise inventory_failure

    monkeypatch.setattr(runner, "command", refuse)
    assert cli.main(["run", "--study", str(Path(__file__).parents[1] / "studies/offline-paired-v2.json")]) == 1


def test_empty_inventory_uses_part_name(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    directory, invocation = directories(tmp_path)
    runner_v2.raw_inventory(directory, invocation)
    assert [p.name for p in directory.iterdir()] == ["private-inventory-invocation-part1of1.json"]
    assert taxonomy.inventory(directory) == {}
    body, _ = bundles.read(next(directory.iterdir()))
    assert body["files"] == []
    runner_v2.raw_inventory(directory, invocation)
    assert len(list(directory.iterdir())) == 1
