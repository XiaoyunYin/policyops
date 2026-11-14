"""Fictional title-run JSONL and a metadata-only manifest for structural ingestion tests."""

from __future__ import annotations

from collections.abc import Sequence
import hashlib
from pathlib import Path
from typing import Any

from policyops.retrieval.sources import canonical_json, sha256_hex
from policyops_testing.corpus_fixtures import REVISION


KEY = "multidoc2dial-v1-struct"


def passage(number: int = 0, *, body: str = "Refunds return to the original card.", heading: str = "Refunds",
            heading_only: bool = False) -> dict[str, Any]:
    return {"passage_id": "md2d.p/" + hashlib.sha256(str(number).encode()).hexdigest(), "domain": "dmv",
            "document_id": "Original document:#1", "heading": heading, "body": body, "start": 17,
            "end": 17 + len(body), "span_ids": [str(number)], "heading_only": heading_only,
            "run_ordinal": number}


def write(root: Path, rows: Sequence[dict[str, Any]], **overrides: Any) -> tuple[bytes, str]:
    root.mkdir(parents=True, exist_ok=True)
    data = b"".join(canonical_json(row) + b"\n" for row in rows)
    (root / "passages.jsonl").write_bytes(data)
    manifest = {"schema": "policyops.structural-ingest/v1", "corpus_key": KEY, "domain": "multidoc2dial",
                "publisher": "Synthetic", "license": "CC0", "license_scope": "Fictional test passages only.",
                "derivation": REVISION, "derivation_version": "md2d.title-runs/v1", "archive_sha256": "a" * 64,
                "passages_path": "passages.jsonl", "passages_sha256": sha256_hex(data),
                "passages_bytes": len(data), "passage_count": len(rows)} | overrides
    raw = canonical_json(manifest)
    return raw, sha256_hex(raw)
