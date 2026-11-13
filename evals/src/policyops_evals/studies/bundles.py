"""Bounded, hash inventoried immutable snapshots. Pure file-only report input."""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.studies.report_models import FrozenStudy, Snapshot


MAX_FILE = 4_000_000
MAX_BYTES = 64_000_000
MAX_FILES = 1100
TABLES = ("trials", "attempts", "scopes", "timings")


class BundleRefused(ValueError):
    """Only fixed codes, including when an untrusted bundle cannot parse."""


def output_path(path: Path) -> Path:
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    root = Path(raw)
    repo = Path(__file__).resolve().parents[4]
    if not raw or not root.is_absolute():
        raise BundleRefused("absolute_temporary_root_required")
    resolved = path.resolve()
    if (root.resolve() not in resolved.parents or resolved == repo or repo in resolved.parents
            or any(p.is_symlink() or p.is_junction() for p in (path, *path.parents))):
        raise BundleRefused("output_containment")
    return path


def write(path: Path, data: bytes, *, immutable: bool = True, byte_limit: int = MAX_FILE) -> None:
    output_path(path)
    if not 1 <= byte_limit <= MAX_BYTES or len(data) > byte_limit:
        raise BundleRefused("file_byte_bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    if immutable:
        if path.exists():
            if path.read_bytes() != data:
                raise BundleRefused("immutable_file_conflict")
            return
        with path.open("xb") as handle:
            handle.write(data)
    else:
        scratch = path.with_name("." + uuid4().hex + ".tmp")
        try:
            with scratch.open("xb") as handle:
                handle.write(data)
            scratch.replace(path)
        finally:
            scratch.unlink(missing_ok=True)


def read(path: Path) -> tuple[Any, bytes]:
    try:
        if path.is_symlink() or path.is_junction():
            raise BundleRefused("input_alias")
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise BundleRefused("file_byte_bound")
        depth, quoted, escaped = 0, False, False
        for c in raw:
            if quoted:
                if escaped:
                    escaped = False
                elif c == 92:
                    escaped = True
                elif c == 34:
                    quoted = False
            elif c == 34:
                quoted = True
            elif c in (91, 123):
                depth += 1
                if depth > 24:
                    raise BundleRefused("json_depth_bound")
            elif c in (93, 125):
                depth -= 1

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            body: dict[str, Any] = {}
            for key, value in items:
                if key in body:
                    raise BundleRefused("duplicate_json_key")
                body[key] = value
            return body

        body = json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(BundleRefused("nonfinite_json")))
        if canonical_bytes(body) != raw:
            raise BundleRefused("noncanonical_json")
        return body, raw
    except (OSError, ValueError, RecursionError):
        raise BundleRefused("invalid_bundle_file") from None


def seal(directory: Path, study: FrozenStudy, snapshot: Snapshot) -> str:
    """Caller owns study advisory lock. Older numbered evidence is never replaced."""
    study_bytes = canonical_bytes(study.model_dump(mode="json"))
    write(directory / "study.json", study_bytes)
    index_path = directory / "snapshots.json"
    index: dict[str, Any] = read(index_path)[0] if index_path.exists() else {
        "schema_version": "policyops.snapshot-index/v1", "snapshots": []}
    if len(index["snapshots"]) >= 1000:
        raise BundleRefused("snapshot_count_bound")
    # An interrupted seal may have written only a subset of its declared files.
    # Preserve it for diagnosis and allocate a fresh number; never repair bytes.
    for number in range(len(index["snapshots"]) + 1, 1001):
        prefix = f"snapshot-{number:06d}"
        target = directory / prefix
        output_path(target / "snapshot.json")
        try:
            target.mkdir()
            break
        except FileExistsError:
            continue
    else:
        raise BundleRefused("snapshot_count_bound")
    body = snapshot.model_dump(mode="json")
    inventory: list[dict[str, Any]] = []
    total_bytes = 0
    for table in TABLES:
        rows = body.pop(table)
        for offset in range(0, len(rows), 512):
            filename = f"{prefix}/{table}-{offset // 512:04d}.json"
            data = canonical_bytes(rows[offset:offset + 512])
            total_bytes += len(data)
            if total_bytes > MAX_BYTES or len(inventory) >= MAX_FILES:
                raise BundleRefused("snapshot_total_bound")
            inventory.append({"path": filename, "table": table, "rows": len(rows[offset:offset + 512]),
                "bytes": len(data), "sha256": sha256_bytes(data)})
            write(directory / filename, data)
    manifest = {"schema_version": "policyops.sealed-snapshot/v1", "study_sha256": sha256_bytes(study_bytes),
        "metadata": body, "files": inventory}
    data = canonical_bytes(manifest)
    digest = sha256_bytes(data)
    filename = f"{prefix}/snapshot.json"
    write(directory / filename, data)
    index["snapshots"].append({"path": filename, "sha256": digest})
    write(index_path, canonical_bytes(index), immutable=False)
    return digest


def child(directory: Path, relative: str) -> Path:
    part = PurePosixPath(relative)
    if (not relative or part.is_absolute() or ".." in part.parts or "\\" in relative or ":" in relative
            or len(part.parts) != 2):
        raise BundleRefused("inventory_path")
    path = directory.joinpath(*part.parts)
    if directory.resolve() not in path.resolve().parents or any(p.is_symlink() or p.is_junction()
        for p in (path, path.parent)):
        raise BundleRefused("inventory_alias")
    return path


def load(path: Path, digest: str | None = None) -> tuple[FrozenStudy, Snapshot, str, str]:
    """Validate only declared files, before deserializing bounded normalized rows."""
    directory = path.parent
    study_body, study_bytes = read(path)
    index, _ = read(directory / "snapshots.json")
    if (set(index) != {"schema_version", "snapshots"}
            or index["schema_version"] != "policyops.snapshot-index/v1"
            or not 1 <= len(index["snapshots"]) <= 1000):
        raise BundleRefused("snapshot_index")
    selected = [r for r in index["snapshots"] if digest is None or r.get("sha256") == digest]
    if len(selected) != 1:
        raise BundleRefused("explicit_snapshot_required")
    entry = selected[0]
    manifest, raw = read(child(directory, entry["path"]))
    study_hash = sha256_bytes(study_bytes)
    if (sha256_bytes(raw) != entry["sha256"] or manifest.get("study_sha256") != study_hash
            or set(manifest) != {"schema_version", "study_sha256", "metadata", "files"}
            or manifest["schema_version"] != "policyops.sealed-snapshot/v1"
            or len(manifest["files"]) > MAX_FILES):
        raise BundleRefused("snapshot_integrity")
    total = 0
    seen: set[str] = set()
    limits = {"trials": 16384, "attempts": 131072, "scopes": 16385, "timings": 131072}
    table_counts = dict.fromkeys(TABLES, 0)
    for item in manifest["files"]:
        if (set(item) != {"path", "table", "rows", "bytes", "sha256"} or item["path"] in seen
                or item["table"] not in TABLES or type(item["rows"]) is not int
                or not 1 <= item["rows"] <= 512 or type(item["bytes"]) is not int
                or not 0 < item["bytes"] <= MAX_FILE):
            raise BundleRefused("inventory_bounds")
        seen.add(item["path"])
        total += item["bytes"]
        table_counts[item["table"]] += item["rows"]
    if total > MAX_BYTES or any(table_counts[t] > limits[t] for t in TABLES):
        raise BundleRefused("snapshot_total_bound")
    body = dict(manifest["metadata"])
    if set(body) != {"schema_version", "created_at", "db_version"}:
        raise BundleRefused("snapshot_metadata")
    body.update({t: [] for t in TABLES})
    for item in manifest["files"]:
        rows, data = read(child(directory, item["path"]))
        if (len(data) != item["bytes"] or sha256_bytes(data) != item["sha256"]
                or not isinstance(rows, list) or len(rows) != item["rows"]):
            raise BundleRefused("declared_file_integrity")
        body[item["table"]].extend(rows)
    try:
        study = FrozenStudy.model_validate_json(canonical_bytes(study_body))
        snapshot = Snapshot.model_validate_json(canonical_bytes(body))
    except ValueError:
        raise BundleRefused("frozen_schema_invalid") from None
    return study, snapshot, study_hash, entry["sha256"]
