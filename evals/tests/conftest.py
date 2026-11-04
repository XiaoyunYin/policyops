"""Refuse to run unless output is contained and upstream import side effects are disabled."""

from collections.abc import Callable
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

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
    if not sys.flags.utf8_mode:
        problems.append("Python UTF-8 mode is required (PYTHONUTF8=1; upstream opens data without an encoding)")
    if problems:
        raise pytest.UsageError("; ".join(problems) + ". Run through scripts/devenv.py.")


SyntheticTree = Callable[[dict[str, bytes]], Any]


@pytest.fixture
def synthetic_tree(tmp_path: Path) -> SyntheticTree:
    """Factory: write files below a fresh tree and return a SourceTree pinning exactly those bytes."""
    from policyops_evals import upstream
    from policyops_evals.canonical import sha256_bytes
    from policyops_evals.sources import SCHEMA, SourceTree

    counter = iter(range(1000))

    def make(files: dict[str, bytes]) -> SourceTree:
        root = tmp_path / f"tree-{next(counter)}"
        for path, data in files.items():
            target = root.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        manifest = {"schema": SCHEMA, "commit": upstream.COMMIT,
                    "consumed": [{"path": path, "sha256": sha256_bytes(data)} for path, data in sorted(files.items())]}
        return SourceTree(root, manifest)

    return make
