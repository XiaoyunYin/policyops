"""Reviewed source manifest and a reader that only returns pinned bytes.

All dataset analysis reads upstream files through `SourceTree`, which refuses
paths outside the consumed scope and any file whose SHA-256 differs from the
reviewed `source.json`. Extra files under a consumed directory (for example an
injected document) are rejected as well, because they would change counts.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any

from policyops_evals import upstream
from policyops_evals.acquire import safe_target
from policyops_evals.canonical import ManifestError, sha256_bytes


SCHEMA = "policyops.tau2-source/v1"


def build_source_manifest(inventory: Mapping[str, Any]) -> dict[str, Any]:
    files = inventory["files"]
    modes: dict[str, int] = {}
    for item in files:
        modes[item["mode"]] = modes.get(item["mode"], 0) + 1
    consumed = [
        {"path": item["path"], "size": item["size"], "git_blob": item["git_blob"], "sha256": item["sha256"]}
        for item in files if upstream.is_consumed(item["path"])
    ]
    missing = [path for path in upstream.CONSUMED_FILES if path not in {item["path"] for item in consumed}]
    if missing:
        raise ManifestError(f"pinned commit lacks consumed files: {missing}")
    for prefix in upstream.CONSUMED_PREFIXES:
        if not any(item["path"].startswith(prefix) for item in consumed):
            raise ManifestError(f"pinned commit has no files under {prefix}")
    return {
        "schema": SCHEMA,
        "repository": inventory["repository"],
        "commit": inventory["commit"],
        "tree": inventory["tree"],
        "acquisition": {
            "command": "policyops-evals data fetch --dest <new empty directory>",
            "method": (
                "git fetch --depth=1 of the commit into a bare repository; commit, tree and blob objects "
                "re-hashed by policyops_evals.gitobjects; file bytes written from the object store without "
                "checkout, filters, hooks or line-ending conversion"
            ),
        },
        "tree_inventory": {
            "sha256": inventory["inventory_sha256"],
            "entries": len(files),
            "modes": dict(sorted(modes.items())),
            "unmaterialized": [{key: item[key] for key in ("path", "mode", "oid", "reason")}
                               for item in inventory["unmaterialized"]],
        },
        "consumed_scope": {"files": sorted(upstream.CONSUMED_FILES), "prefixes": sorted(upstream.CONSUMED_PREFIXES)},
        "consumed": consumed,
    }


class SourceTree:
    """Verified read access to the consumed files of one materialized tree."""

    def __init__(self, root: Path, manifest: Mapping[str, Any]) -> None:
        if manifest.get("schema") != SCHEMA or manifest.get("commit") != upstream.COMMIT:
            raise ManifestError("source manifest is not for the pinned upstream commit")
        self.root = root
        self.manifest = manifest
        self._expected = {item["path"]: item["sha256"] for item in manifest["consumed"]}
        for prefix in upstream.CONSUMED_PREFIXES:
            directory = safe_target(root, prefix.rstrip("/"))
            present = {
                f"{prefix}{path.relative_to(directory).as_posix()}"
                for path in directory.rglob("*") if path.is_file()
            } if directory.is_dir() else set()
            pinned = {path for path in self._expected if path.startswith(prefix)}
            if present != pinned:
                raise ManifestError(
                    f"{prefix}: {len(present - pinned)} unexpected and {len(pinned - present)} missing files")
        for path in self._expected:
            self.read(path)

    def read(self, path: str) -> bytes:
        expected = self._expected.get(path)
        if expected is None:
            raise ManifestError(f"{path} is outside the pinned consumed scope")
        target = safe_target(self.root, path)
        if not target.is_file():
            raise ManifestError(f"{path} is missing")
        data = target.read_bytes()
        if sha256_bytes(data) != expected:
            raise ManifestError(f"{path} does not match its pinned SHA-256")
        return data

    def json(self, path: str) -> Any:
        return json.loads(self.read(path).decode("utf-8"))

    def listing(self, prefix: str) -> list[str]:
        prefix = prefix.rstrip("/") + "/"
        return sorted(path for path in self._expected if path.startswith(prefix))

    def sha256(self, path: str) -> str:
        digest: str = self._expected[path]
        return digest
