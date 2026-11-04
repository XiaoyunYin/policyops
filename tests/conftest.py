"""Refuse to run unless temp/cache output is routed outside the checkout."""

import os
from pathlib import Path
import sys
import tempfile

import pytest


REPO = Path(__file__).resolve().parents[1]
pytest_plugins = ["policyops_testing.plugin"]
# Needs Node and the installed web dependencies; the web CI job runs it with unittest.
collect_ignore = ["web"]


def pytest_configure(config: pytest.Config) -> None:
    problems = []
    raw_root = os.environ.get("POLICYOPS_TEMP_DIR")
    if not raw_root:
        problems.append("POLICYOPS_TEMP_DIR is not set")
    else:
        root = Path(raw_root).resolve()
        if root == REPO or REPO in root.parents:
            problems.append("POLICYOPS_TEMP_DIR is inside the repository")
        temp = Path(tempfile.gettempdir()).resolve()
        if not (temp == root or root in temp.parents):
            problems.append(f"system temp directory {temp} is outside POLICYOPS_TEMP_DIR")
    if not sys.dont_write_bytecode:
        problems.append("Python bytecode writing is enabled (PYTHONDONTWRITEBYTECODE=1)")
    if problems:
        raise pytest.UsageError("; ".join(problems) + ". Run through scripts/devenv.py.")
