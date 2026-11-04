"""Canonical JSON and digests shared by every manifest.

Manifests are written as UTF-8, LF line endings, sorted keys, two-space indent
and a trailing newline, so the same inputs always produce identical bytes.
Each manifest carries `manifest_sha256`, the SHA-256 of its canonical form with
that field removed; editing a manifest without regenerating it is detectable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json
from pathlib import Path
from typing import Any


SELF_DIGEST = "manifest_sha256"


class ManifestError(ValueError):
    """A manifest is malformed, tampered with or disagrees with its inputs."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def id_list_digest(ids: Iterable[str]) -> str:
    """SHA-256 of IDs joined by LF in the given order (upstream frame_digest convention)."""
    return sha256_bytes("\n".join(ids).encode("utf-8"))


def with_self_digest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    body = {key: value for key, value in manifest.items() if key != SELF_DIGEST}
    return {**body, SELF_DIGEST: sha256_bytes(canonical_bytes(body))}


def verify_self_digest(manifest: Mapping[str, Any]) -> None:
    recorded = manifest.get(SELF_DIGEST)
    body = {key: value for key, value in manifest.items() if key != SELF_DIGEST}
    if recorded != sha256_bytes(canonical_bytes(body)):
        raise ManifestError("manifest_sha256 does not match the manifest contents")


def load_manifest(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    manifest = json.loads(data.decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ManifestError(f"{path.name}: not a JSON object")
    verify_self_digest(manifest)
    if canonical_bytes(manifest) != data:
        raise ManifestError(f"{path.name}: not in canonical form")
    return manifest


def write_manifest(path: Path, manifest: Mapping[str, Any]) -> bytes:
    data = canonical_bytes(with_self_digest(manifest))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data
