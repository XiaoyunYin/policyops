"""Run T29 composed checks in a fresh interpreter: no upstream imports in parent.

Other evaluator checks bind tau2's process-global data root to a reviewed fixture.
These fictional cases instead use an empty root and cannot open dataset tasks.
Child pytest uses the same network guard, real source paths and explicit reports.
"""

import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def test_inprocess_and_actor_scoring_components(tmp_path: Path) -> None:
    env = dict(os.environ)
    data = tmp_path / "empty-data"
    data.mkdir()
    env["TAU2_DATA_DIR"] = str(data)
    report = tmp_path / "child-junit.xml"
    args = [sys.executable, "-B", "-m", "pytest", "tests/t29_inprocess_cases.py", "tests/t29_scoring_cases.py",
            "--basetemp", str(tmp_path / "child-temp"), "--junitxml", str(report), "--tb=short", "-q",
            "-W", "ignore:'audioop' is deprecated:DeprecationWarning"]
    result = subprocess.run(args, cwd=Path(__file__).parents[1], env=env, capture_output=True,
                            encoding="utf-8", timeout=300)
    (tmp_path / "child.log").write_bytes((result.stdout + result.stderr).replace("\r\n", "\n").encode("utf-8"))
    assert result.returncode == 0, (result.stdout + result.stderr)[-18000:]
    suites = ET.parse(report).getroot()  # noqa: S314  # task-owned pytest output
    cases = list(suites.iter("testcase"))
    assert len(cases) == 32
    assert not list(suites.iter("failure")) and not list(suites.iter("error")) and not list(suites.iter("skipped"))
