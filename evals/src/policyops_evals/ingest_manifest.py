"""Build or check the committed ingestion manifest (`policyops.ingest-manifest/v1`) from the committed T03
manifests only: no acquisition tree, no document text, no network.

    python -m policyops_evals.ingest_manifest [--manifests DIR] [--check]

Two corpora:

- `tau2-banking-knowledge` (domain `banking_knowledge`, render `tau2-banking/v1`): every consumed
  `banking_knowledge/documents/*.json` file, keyed by its file stem (the document's JSON `id`, which ingestion
  verifies); the rendered-list digest is T03's `rendered_document_sha256_list_digest`;
- `tau2-retail-policy` (domain `retail`, render `identity`): the retail `policy.md`; its rendered body is the raw
  file, so the digest list is that file's SHA-256 (cross-checked against T03's `retail_policy_sha256`).

Paths, git blobs, SHA-256 digests and sizes come from `source.json`; the license scope statement is the rights
audit's, verbatim. The source revision (repository, commit, tree and source-manifest digest) is per manifest: a
future revision gets its own manifest with its own values. The application never imports this module.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path
import sys
from typing import Any

from policyops_evals import upstream
from policyops_evals.build import RIGHTS, SOURCE, TOKENS, default_manifest_dir
from policyops_evals.canonical import ManifestError, canonical_bytes, id_list_digest, load_manifest


SCHEMA = "policyops.ingest-manifest/v1"
FILE_NAME = "ingest-corpora.json"
PUBLISHER = "Sierra Research"
LICENSE = "MIT (tau2-bench root grant)"


def _documents(consumed: Sequence[Mapping[str, Any]], prefix: str) -> list[dict[str, Any]]:
    found = []
    for entry in consumed:
        path = entry["path"]
        if not path.startswith(prefix + "/"):
            continue
        name = path[len(prefix) + 1:]
        if "/" in name or not name.endswith(".json"):
            raise ManifestError(f"unexpected banking document path {path}")
        found.append({"document_key": name[: -len(".json")], "path": path, "git_blob": entry["git_blob"],
                      "sha256": entry["sha256"], "size": entry["size"]})
    return sorted(found, key=lambda d: d["document_key"])


def build(source: Mapping[str, Any], tokens: Mapping[str, Any], rights: Mapping[str, Any]) -> dict[str, Any]:
    extraction, sizes = tokens["extraction"], tokens["sizes"]
    if tokens["source_commit"] != source["commit"]:
        raise ManifestError("the token report and the source manifest name different commits")
    basis = rights["license_basis"]
    scope = f"{basis['grant']}. {basis['scope_statement']}"
    banking = _documents(source["consumed"], upstream.BANKING_DOCUMENTS_DIR)
    if len(banking) != extraction["banking_documents"]:
        raise ManifestError("the banking document count differs from the token report")
    if sum(d["size"] for d in banking) != sizes["banking_document_files_bytes"]:
        raise ManifestError("the banking document bytes differ from the token report")
    retail = [entry for entry in source["consumed"] if entry["path"] == upstream.RETAIL_POLICY]
    if len(retail) != 1 or retail[0]["sha256"] != extraction["retail_policy_sha256"]:
        raise ManifestError("the retail policy differs from the token report")
    policy = retail[0]
    common = {"publisher": PUBLISHER, "license": LICENSE, "license_scope": scope}
    return {
        "schema": SCHEMA,
        "source": {"repository": source["repository"], "commit": source["commit"], "tree": source["tree"],
                   "source_manifest_sha256": source["manifest_sha256"]},
        "corpora": [
            {"corpus_key": "tau2-banking-knowledge", "domain": "banking_knowledge", **common,
             "render": "tau2-banking/v1",
             "rendered_list_sha256": extraction["rendered_document_sha256_list_digest"], "documents": banking},
            {"corpus_key": "tau2-retail-policy", "domain": "retail", **common, "render": "identity",
             "rendered_list_sha256": id_list_digest([policy["sha256"]]),
             "documents": [{"document_key": "policy", "path": policy["path"], "git_blob": policy["git_blob"],
                            "sha256": policy["sha256"], "size": policy["size"]}]},
        ],
    }


def build_from(directory: Path) -> bytes:
    manifest = build(load_manifest(directory / SOURCE), load_manifest(directory / TOKENS),
                     load_manifest(directory / RIGHTS))
    return canonical_bytes(manifest)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m policyops_evals.ingest_manifest", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifests", type=Path, default=default_manifest_dir())
    parser.add_argument("--check", action="store_true", help="compare with the committed file instead of writing")
    args = parser.parse_args(argv)
    try:
        data = build_from(args.manifests)
    except (ManifestError, OSError, KeyError) as exc:
        print(f"ingest_manifest: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    target = args.manifests / FILE_NAME
    if args.check:
        same = target.is_file() and target.read_bytes() == data
        print(f"{FILE_NAME}: {'unchanged' if same else 'DIFFERS'}")
        return 0 if same else 1
    target.write_bytes(data)
    print(f"{FILE_NAME}: written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
