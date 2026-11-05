"""The committed ingestion manifest (`ingest-corpora.json`): rebuilt from the committed T03 manifests only, it is
byte-identical to the committed file, metadata-only, and agrees with the T03 source, token and rights reports."""

import json
from typing import Any

import pytest

from policyops_evals import ingest_manifest, upstream
from policyops_evals.build import RIGHTS, SOURCE, TOKENS, default_manifest_dir
from policyops_evals.canonical import ManifestError, load_manifest


DIRECTORY = default_manifest_dir()


def committed() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((DIRECTORY / ingest_manifest.FILE_NAME).read_bytes())
    return data


def test_the_committed_manifest_is_exactly_the_rebuild() -> None:
    assert ingest_manifest.build_from(DIRECTORY) == (DIRECTORY / ingest_manifest.FILE_NAME).read_bytes()
    assert ingest_manifest.main(["--check"]) == 0


def test_the_manifest_agrees_with_t03_and_holds_no_document_text() -> None:
    manifest = committed()
    source, tokens = load_manifest(DIRECTORY / SOURCE), load_manifest(DIRECTORY / TOKENS)
    assert manifest["schema"] == "policyops.ingest-manifest/v1"
    assert manifest["source"] == {"repository": source["repository"], "commit": source["commit"],
                                  "tree": source["tree"], "source_manifest_sha256": source["manifest_sha256"]}
    banking, retail = manifest["corpora"]
    assert banking["corpus_key"] == "tau2-banking-knowledge" and retail["corpus_key"] == "tau2-retail-policy"
    assert banking["rendered_list_sha256"] == tokens["extraction"]["rendered_document_sha256_list_digest"]
    assert len(banking["documents"]) == 698 == tokens["extraction"]["banking_documents"]
    consumed = {entry["path"]: entry for entry in source["consumed"]}
    for corpus in manifest["corpora"]:
        keys = [d["document_key"] for d in corpus["documents"]]
        assert keys == sorted(keys) and len(set(keys)) == len(keys)
        for document in corpus["documents"]:
            assert set(document) == {"document_key", "path", "git_blob", "sha256", "size"}
            entry = consumed[document["path"]]
            assert (document["git_blob"], document["sha256"], document["size"]) == (
                entry["git_blob"], entry["sha256"], entry["size"])
    assert retail["documents"][0]["path"] == upstream.RETAIL_POLICY
    scope = load_manifest(DIRECTORY / RIGHTS)["license_basis"]["scope_statement"]
    assert scope in banking["license_scope"] and scope in retail["license_scope"]


def test_inconsistent_t03_inputs_are_refused() -> None:
    source, tokens, rights = (load_manifest(DIRECTORY / name) for name in (SOURCE, TOKENS, RIGHTS))
    other_commit = {**tokens, "source_commit": "0" * 40}
    with pytest.raises(ManifestError, match="different commits"):
        ingest_manifest.build(source, other_commit, rights)
    fewer = {**source, "consumed": [e for e in source["consumed"] if not e["path"].endswith("_001.json")]}
    with pytest.raises(ManifestError, match="banking document count"):
        ingest_manifest.build(fewer, tokens, rights)
