"""Per-file rights and provenance audit of the pinned commit.

What it does: every consumed file is scanned over its full content for license,
copyright, SPDX, named-license, rights-reserved, URL and e-mail markers (counts
only; matched text is never copied into the report). Every other materialized
file gets only a notice-like file-name check and a license-marker scan of its
first HEADER_BYTES bytes. Binary content is flagged, and each consumed file gets
a category with PolicyOps's redistribution decision.

What it cannot do: a text scan does not establish who authored data or whether a
file was derived from third-party material. The only explicit grant found is the
root MIT LICENSE (and `license = "MIT"` in pyproject.toml); the pinned repository
contains no statement about how the retail data or banking documents were
created. That uncertainty is reported, not resolved.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
import re
from typing import Any

from policyops_evals import upstream


SCHEMA = "policyops.rights-audit/v1"
MARKERS = {
    "license_word": re.compile(r"\blicen[cs]e", re.IGNORECASE),
    "copyright": re.compile(r"copyright|©|\(c\)\s*(?:19|20)\d\d", re.IGNORECASE),
    "spdx": re.compile(r"SPDX-License-Identifier", re.IGNORECASE),
    "named_license": re.compile(
        r"apache license|gnu (?:affero |lesser )?general public|creative commons|\bcc[- ]by\b|mozilla public"
        r"|\bbsd[- ](?:2|3)|\bmit license", re.IGNORECASE),
    "rights_reserved": re.compile(r"all rights reserved|proprietary|confidential", re.IGNORECASE),
    "url": re.compile(r"https?://", re.IGNORECASE),
    # Anchored at "@" so matching stays linear on long unbroken text.
    "email": re.compile(r"(?<=[A-Za-z0-9._%+-])@[A-Za-z0-9-]{1,63}\.[A-Za-z]"),
}
# Unconsumed files: notice-like file names plus a bounded header scan for license markers.
HEADER_BYTES = 65536
NOTICE_NAME = re.compile(r"^(?:licen[cs]e|notice|copying|copyright|authors|patents)(?:[._-].*)?$", re.IGNORECASE)
LICENSE_MARKERS = ("copyright", "spdx", "named_license", "rights_reserved")
ROOT_GRANT = "root LICENSE: MIT License, Copyright (c) 2025 Sierra Research"


def scan(data: bytes, names: tuple[str, ...] = tuple(MARKERS)) -> dict[str, Any]:
    if b"\0" in data[:8192]:
        return {"binary": True, "markers": {}}
    text = data.decode("utf-8", errors="replace")
    found = {name: len(MARKERS[name].findall(text)) for name in names}
    return {"binary": False, "markers": {name: count for name, count in found.items() if count}}


def category(path: str) -> tuple[str, str]:
    """(category, PolicyOps redistribution decision) for a consumed file."""
    if path == upstream.LICENSE:
        return "license-text", "reproduced in THIRD_PARTY_NOTICES.md"
    if path in {upstream.README, upstream.PYPROJECT}:
        return "upstream-metadata", "not redistributed; read for provenance only"
    if path.startswith(upstream.RETAIL_ISSUES_DIR + "/"):
        return ("upstream-review-trajectory",
                "not redistributed and not used as a fixture; issue metadata contains an upstream contributor "
                "e-mail address, which no PolicyOps manifest copies")
    if path.startswith(upstream.BANKING_DOCUMENTS_DIR + "/"):
        return ("banking-knowledge-document",
                "not redistributed in Git; local retrieval corpus; no file-level terms or provenance statement")
    if path in {upstream.RETAIL_TASKS, upstream.EN_RETAIL_TASKS, upstream.BANKING_TASKS_AGGREGATE} or path.startswith(
            upstream.BANKING_TASKS_DIR + "/"):
        return ("benchmark-task-definition",
                "not redistributed; hidden criteria stay evaluator-side; only task IDs and hashes are published")
    if path in {upstream.RETAIL_DB, upstream.BANKING_DB}:
        return ("simulated-business-database",
                "not redistributed in Git; any later simulator-image staging (T38) must carry the MIT notice")
    if path == upstream.RETAIL_POLICY:
        return "domain-policy", "not redistributed in Git; local policy corpus; MIT notice required if shipped"
    return "benchmark-metadata", "not redistributed; IDs and hashes published in split manifests"


def build_rights_audit(inventory: Mapping[str, Any], contents: Iterable[tuple[str, bytes]]) -> dict[str, Any]:
    """contents yields (path, bytes) for every materialized file, already hash-verified by the caller.

    Consumed files: every marker over the full content. Other files: notice-like
    file names, and license markers within the first HEADER_BYTES bytes only.
    """
    by_path = {item["path"]: item for item in inventory["files"]}
    consumed, flagged, notice_files, summary = [], [], [], Counter[str]()
    binaries = header_only = 0
    for path, data in contents:
        if NOTICE_NAME.match(path.rsplit("/", 1)[-1]):
            notice_files.append(path)
        if upstream.is_consumed(path):
            result = scan(data)
        else:
            result = scan(data[:HEADER_BYTES], LICENSE_MARKERS)
            header_only += 1
        binaries += result["binary"]
        for name in result["markers"]:
            summary[name] += 1
        if any(name in result["markers"] for name in LICENSE_MARKERS) and path != upstream.LICENSE:
            flagged.append({"path": path, "consumed": upstream.is_consumed(path),
                            "markers": sorted(name for name in result["markers"] if name in LICENSE_MARKERS)})
        if upstream.is_consumed(path):
            kind, decision = category(path)
            consumed.append({"path": path, "sha256": by_path[path]["sha256"], "category": kind,
                             "binary": result["binary"], "markers": result["markers"], "decision": decision})
    consumed.sort(key=lambda item: item["path"])
    kinds = Counter(item["category"] for item in consumed)
    consumed_flags = [item["path"] for item in consumed
                      if any(name in item["markers"] for name in LICENSE_MARKERS) and item["path"] != upstream.LICENSE]
    return {
        "schema": SCHEMA,
        "commit": upstream.COMMIT,
        "license_basis": {
            "grant": ROOT_GRANT,
            "license_sha256": by_path[upstream.LICENSE]["sha256"],
            "pyproject_license_field": "MIT",
            "scope_statement": "The root license is the only explicit grant found. It does not by itself prove "
                               "the provenance of every data file or linked asset.",
        },
        "method": {
            "inventory_files": len(by_path), "markers": sorted(MARKERS),
            "license_markers": list(LICENSE_MARKERS),
            "consumed_files": "full content, all markers",
            "unconsumed_files": f"notice-like file names; license markers in the first {HEADER_BYTES} bytes only "
                                "(not an exhaustive rights review of files PolicyOps does not use)",
            "unconsumed_files_header_scanned": header_only,
            "note": "marker counts only; matched text is not copied; binary files are not text-scanned",
        },
        "whole_tree": {
            "notice_like_file_names": sorted(notice_files),
            "files_with_marker": dict(sorted(summary.items())),
            "binary_files": binaries,
            "files_with_license_markers_other_than_root_license": sorted(flagged, key=lambda item: item["path"]),
            "unmaterialized": [{key: item[key] for key in ("path", "mode", "oid", "reason")}
                               for item in inventory["unmaterialized"]],
        },
        "consumed_summary": {
            "files": len(consumed), "categories": dict(sorted(kinds.items())),
            "consumed_files_with_license_markers": consumed_flags,
            "consumed_files_with_email_marker": sum("email" in item["markers"] for item in consumed),
            "consumed_files_with_url_marker": sum("url" in item["markers"] for item in consumed),
        },
        "remaining_uncertainty": [
            "No statement in the pinned repository says how retail database records, task scenarios or banking "
            "documents were authored; whether any text derives from third-party material is unknown.",
            "Names, addresses and e-mail-like strings in simulated data are presumed fictional benchmark content; "
            "this audit cannot prove that none belongs to a real person.",
            "URLs inside data files point to external resources whose terms were not audited; PolicyOps does not "
            "fetch them.",
            "Upstream Python dependencies (litellm, openai and others) have their own licenses; their audit "
            "belongs to T37.",
        ],
        "publication_decision": "PolicyOps publishes only reviewed metadata, hashes and task IDs. No upstream data "
                                "file, task payload or document text is committed.",
        "consumed": consumed,
    }
