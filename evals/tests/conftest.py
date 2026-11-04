"""Refuse to run unless output is contained and upstream import side effects are disabled."""

import os
from pathlib import Path
import sys
import tempfile

import pytest


REPO = Path(__file__).resolve().parents[2]


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
    if os.environ.get("PYTHON_DOTENV_DISABLED") != "1":
        problems.append("PYTHON_DOTENV_DISABLED=1 is required (tau2 loads .env files at import)")
    if os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP", "").lower() != "true":
        problems.append("LITELLM_LOCAL_MODEL_COST_MAP=True is required (offline pricing map)")
    if problems:
        raise pytest.UsageError("; ".join(problems) + ". Run through scripts/devenv.py.")
