"""The service's audited fixture root and the only way the service imports upstream retail code.

A fixture root contains exactly two files, copied from a verified upstream tree and checked against the reviewed
source manifest: `data/tau2/domains/retail/db.json` and `LICENSE`. `TAU2_DATA_DIR` points there, so task, split and
held-out files are not even present. Upstream modules are imported only after `prepare` (dotenv disabled, local
pricing map, the staged data directory). The service uses `RetailDB` and `RetailTools` directly. Importing the
`tau2` package eagerly imports many of its modules (runner, registry, evaluator, agents, voice utilities and the
`tau2.environment` toolkit); that is import-time only. No retail `Environment` is constructed and no `Task`, task
loader, registry runner, user simulator, judge or model client is called, and the staged data directory contains
no task files for any of them to read.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any
import warnings

from policyops_contracts.retail_service import FIXTURE_ID, FIXTURE_SHA256
from policyops_evals.upstream_runtime import prepare


REPO = Path(__file__).resolve().parents[4]
SOURCE_MANIFEST = REPO / "evals" / "manifests" / "tau2-19f13ea3" / "source.json"
DB_PATH = "data/tau2/domains/retail/db.json"
STAGED = (DB_PATH, "LICENSE")
MAX_FIXTURE_BYTES = 8 * 1024 * 1024


class FixtureError(RuntimeError):
    """The fixture is missing, altered or not the reviewed one. The message names paths only."""


@dataclass(frozen=True)
class Fixture:
    root: Path
    fixture_id: str
    sha256: str
    raw: bytes


def reviewed_digests() -> dict[str, str]:
    consumed = json.loads(SOURCE_MANIFEST.read_bytes())["consumed"]
    digests = {item["path"]: item["sha256"] for item in consumed if item["path"] in STAGED}
    if set(digests) != set(STAGED) or digests[DB_PATH] != FIXTURE_SHA256:
        raise FixtureError("the reviewed source manifest does not pin the retail fixture")
    return digests


def find_reviewed_tree(uv_cache_dir: Path) -> Path | None:
    """The tau2 checkout that `uv sync` materialized for the evals lock (byte-preserving cache generation), if any.
    `load`/`stage` still verify every staged byte against the reviewed manifest."""
    for candidate in sorted((uv_cache_dir / "git-v1" / "checkouts").glob("*/19f13ea")):
        if (candidate / DB_PATH).is_file() and (candidate / "LICENSE").is_file():
            return candidate
    return None


def stage(source_tree: Path, root: Path) -> Fixture:
    """Copy the two reviewed files from `source_tree` into a new `root` and verify them there."""
    reviewed_digests()  # the reviewed manifest must pin the fixture before anything is copied
    if root.exists():
        raise FixtureError(f"fixture root {root} already exists")
    for relative in STAGED:
        source = source_tree / relative
        if not source.is_file() or source.stat().st_size > MAX_FIXTURE_BYTES:
            raise FixtureError(f"{relative} is missing or too large in the source tree")
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return load(root)


def load(root: Path) -> Fixture:
    """Verify a staged root (exactly the two files, reviewed digests) and return the fixture bytes."""
    digests = reviewed_digests()
    present = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    if present != sorted(STAGED):
        raise FixtureError(f"fixture root {root} must contain exactly {', '.join(STAGED)}")
    raw = b""
    for relative in STAGED:
        data = (root / relative).read_bytes()
        if len(data) > MAX_FIXTURE_BYTES or hashlib.sha256(data).hexdigest() != digests[relative]:
            raise FixtureError(f"{relative} does not match the reviewed digest")
        if relative == DB_PATH:
            raw = data
    return Fixture(root, FIXTURE_ID, FIXTURE_SHA256, raw)


@dataclass(frozen=True)
class Upstream:
    """The two upstream classes the service uses, imported once after `prepare`."""

    retail_db: Any
    retail_tools: Any


_UPSTREAM: Upstream | None = None


def upstream(fixture: Fixture) -> Upstream:
    global _UPSTREAM
    if _UPSTREAM is None:
        prepare(fixture.root)
        with warnings.catch_warnings():
            # `import tau2` eagerly imports its voice utilities, which import the stdlib `audioop` module that
            # Python 3.12 deprecates. Only that one import-time warning is ignored; any other warning still applies.
            warnings.filterwarnings("ignore", message="'audioop' is deprecated", category=DeprecationWarning)
            from tau2.domains.retail.data_model import RetailDB
            from tau2.domains.retail.tools import RetailTools
        _UPSTREAM = Upstream(RetailDB, RetailTools)
    return _UPSTREAM
