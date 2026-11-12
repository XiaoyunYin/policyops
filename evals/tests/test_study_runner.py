"""Strict config/CLI gates and a separate fictional composed-runner interpreter."""

from dataclasses import replace
from decimal import Decimal
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from uuid import uuid4
import xml.etree.ElementTree as ET

import pytest

from policyops.budget.ledger import Scope
from policyops_evals import cli
from policyops_evals.studies import runner
from policyops_evals.studies.config import Study, load_study, preflight


EXAMPLE = Path(__file__).parents[1] / "studies/t29-luna-dev-smoke-v1.json"


def example() -> Study:
    return load_study(EXAMPLE)


def test_all_actor_estimate_and_ceiling_include_judge() -> None:
    study = example()
    result = preflight(study)
    assert study.tasks == ("0", "1", "24")
    assert result["planning_estimate_usd"] == "0.0684"
    assert Decimal(result["admission_ceiling_usd"]) == Decimal("0.228288")
    assert result["inference_ceiling"] == result["count_ceiling"] == 87
    assert result["physical_requests_ceiling"] == 174 and result["within_caps"]
    assert result["prior"] == "unverified" and result["authorizes_paid_execution"] is False
    assert {r["actor"] for r in result["actors"]} == {"agent", "simulator", "judge"}


def test_persisted_spend_holds_counts_contract_and_caps_are_in_admission() -> None:
    study = example()
    scope = Scope(uuid4(), "study", Decimal("0.30"), 96, Decimal("0.04"), Decimal("0.04"), 0, 0, False,
                  cap_counts=96)
    assert not preflight(study, snapshot=scope)["within_caps"]
    zero = replace(scope, spent_usd=Decimal(0), held_usd=Decimal(0))
    assert preflight(study, snapshot=zero)["within_caps"]
    for changed in (replace(zero, counts_used=10), replace(zero, calls_held=10),
                    replace(zero, overrun=True), replace(zero, contract_block="usage_unknown"),
                    replace(zero, cap_counts=100), replace(zero, cap_usd=Decimal("0.31"))):
        assert not preflight(study, snapshot=changed)["within_caps"]
    remaining: dict[str, tuple[tuple[str, int, int], ...]] = {"minimal": (("24", 0, 20261112),)}
    result = preflight(study, snapshot=scope, remaining=remaining)
    assert result["within_caps"] and result["inference_ceiling"] == 29
    assert result["scheduled_slots"] == 3 and result["remaining_slots"] == 1
    assert result["manifest_sha256"] == study.digest()
    assert result["remaining_work_sha256"] != preflight(study)["remaining_work_sha256"]


@pytest.mark.parametrize("change", [
    {"purpose": "holdout"}, {"retries": 1}, {"repairs": 1}, {"unknown": True}, {"tasks": ["0", "0"]},
    {"price_revision": "unknown"}, {"provider_mode": "fake"}, {"seeds": [True]},
])
def test_invalid_study_refused(change: dict[str, Any], tmp_path: Path) -> None:
    body = json.loads(EXAMPLE.read_bytes()) | change
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(ValueError):
        load_study(path)


def test_holdout_and_nonallowlisted_tasks_refused(tmp_path: Path) -> None:
    from policyops_evals.canonical import id_list_digest

    for task in ("2", "not-a-task"):
        body = json.loads(EXAMPLE.read_bytes()) | {"tasks": [task], "task_list_sha256": id_list_digest([task])}
        path = tmp_path / "invalid.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        with pytest.raises((ValueError, PermissionError)):
            load_study(path)


@pytest.mark.parametrize("body", [b"[" * 1000, b'{"purpose":"dev","purpose":"dev"}', b'{"x":NaN}', b" " * 60001])
def test_parse_work_is_bounded_and_duplicate_keys_refused(body: bytes, tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(body)
    with pytest.raises(ValueError):
        load_study(path)


def test_paid_cli_refuses_before_database_credentials_or_provider_factory(monkeypatch: pytest.MonkeyPatch,
                                                                         capsys: pytest.CaptureFixture[str]) -> None:
    def trap(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("credential/database/provider path reached without opt-in")

    monkeypatch.setattr(runner, "environment_repository", trap)
    monkeypatch.setattr(runner, "provider_factory", trap)
    assert cli.main(["run", "--study", str(EXAMPLE)]) == 1
    assert "paid_opt_in_required_before_credentials" in capsys.readouterr().err


def test_cli_preflight_is_offline_and_never_constructs_providers(monkeypatch: pytest.MonkeyPatch,
                                                               capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(runner, "environment_repository", lambda: None)
    assert cli.main(["preflight", "--study", str(EXAMPLE)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["admission_ceiling_usd"] == "0.22828800" and not data["authorizes_paid_execution"]


def test_cli_reports_recorded_aborts_as_unsuccessful_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "command", lambda *args, **kwargs: {"execution_complete": False,
                                                                  "scheduled": 3, "recorded": 3})
    assert cli.main(["run", "--study", str(EXAMPLE), "--allow-paid"]) == 1


def test_private_output_rejects_repository_root_and_alias(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from policyops_evals.studies.config import ROOT

    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(ROOT))
    with pytest.raises(runner.StudyRefused):
        runner.output_directory(uuid4())
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    output = runner.output_directory(uuid4())
    assert output.parent == tmp_path / "benchmarks"
    with pytest.raises(runner.StudyRefused):
        runner.output_directory(__import__("uuid").UUID(output.name))


def test_fictional_upstream_study_runner(tmp_path: Path) -> None:
    env = dict(os.environ)
    data = tmp_path / "empty-data"
    data.mkdir()
    env["TAU2_DATA_DIR"] = str(data)
    report = tmp_path / "child-junit.xml"
    args = [sys.executable, "-B", "-m", "pytest", "tests/t29_study_cases.py", "--basetemp", str(tmp_path / "child"),
            "--junitxml", str(report), "--tb=short", "-q", "-W", "ignore:'audioop' is deprecated:DeprecationWarning"]
    result = subprocess.run(args, cwd=Path(__file__).parents[1], env=env, capture_output=True,
                            encoding="utf-8", timeout=300)
    (tmp_path / "child.log").write_bytes((result.stdout + result.stderr).replace("\r\n", "\n").encode())
    assert result.returncode == 0, (result.stdout + result.stderr)[-14000:]
    suites = ET.parse(report).getroot()  # noqa: S314  # task-owned pytest report
    assert len(list(suites.iter("testcase"))) >= 6
    assert not list(suites.iter("failure")) and not list(suites.iter("error"))
