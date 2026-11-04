"""Build, check and cross-validate the public manifests in evals/manifests/.

`build_core` derives source, split, rights and audit manifests from one verified
acquisition with pure Python (no upstream import). `validate_manifests` checks
the committed manifests without any upstream data: self-digests, pinned
identities, split disjointness/coverage, recomputed ID digests, group integrity
and a re-run of the seeded group assignment from the recorded groups.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from policyops_evals import banking, upstream
from policyops_evals.acquire import TREE_DIR, safe_target, verify_materialized
from policyops_evals.canonical import (
    ManifestError,
    canonical_bytes,
    id_list_digest,
    load_manifest,
    verify_self_digest,
    with_self_digest,
)
from policyops_evals.projection import SplitGuard
from policyops_evals.retail import build_retail_audit, build_retail_split
from policyops_evals.rights import build_rights_audit
from policyops_evals.sources import SourceTree, build_source_manifest


SOURCE = "source.json"
RETAIL_SPLIT = "retail-split.json"
BANKING_SPLIT = "banking-split.json"
RIGHTS = "rights-audit.json"
RETAIL_AUDIT = "retail-audit.json"
UPSTREAM = "upstream-verification.json"
TOKENS = "corpus-tokens.json"
CORE = (SOURCE, RETAIL_SPLIT, BANKING_SPLIT, RIGHTS, RETAIL_AUDIT)
ALL = (*CORE, UPSTREAM, TOKENS)


def default_manifest_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "manifests" / f"tau2-{upstream.COMMIT[:8]}"


def build_core(acquired: Path) -> dict[str, dict[str, Any]]:
    inventory = verify_materialized(acquired, commit=upstream.COMMIT, tree=upstream.TREE)
    source = build_source_manifest(inventory)
    root = acquired / TREE_DIR
    tree = SourceTree(root, source)
    retail_split = build_retail_split(tree)
    skipped = {item["path"] for item in inventory["unmaterialized"]}

    def contents() -> Iterator[tuple[str, bytes]]:
        for item in inventory["files"]:
            if item["path"] not in skipped:
                yield item["path"], safe_target(root, item["path"]).read_bytes()

    return {
        SOURCE: source,
        RETAIL_SPLIT: retail_split,
        BANKING_SPLIT: banking.build_banking_split(tree),
        RIGHTS: build_rights_audit(inventory, contents()),
        RETAIL_AUDIT: {"schema": "policyops.retail-audit/v1", "commit": upstream.COMMIT,
                       **build_retail_audit(tree, retail_split)},
    }


def emit(manifests: Mapping[str, Mapping[str, Any]], directory: Path, *, check: bool) -> list[str]:
    """Write manifests (or, with check, list those whose committed bytes differ)."""
    differing = []
    for name, manifest in manifests.items():
        data = canonical_bytes(with_self_digest(manifest))
        path = directory / name
        if check:
            if not path.is_file() or path.read_bytes() != data:
                differing.append(name)
        else:
            directory.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    return differing


def load_committed(directory: Path, names: tuple[str, ...] = ALL) -> dict[str, dict[str, Any]]:
    """Load and self-verify the named manifests; every one must exist.

    The default is the complete T03 set. Pass names=CORE only to bootstrap the
    upstream-verification manifest, which is generated from the core manifests.
    """
    missing = [name for name in names if not (directory / name).is_file()]
    if missing:
        raise ManifestError(f"required manifests are missing: {', '.join(missing)}")
    return {name: load_manifest(directory / name) for name in names}


def tree_for(acquired: Path, directory: Path) -> SourceTree:
    """Verified access to an acquisition, checked against the committed source manifest."""
    inventory = verify_materialized(acquired, commit=upstream.COMMIT, tree=upstream.TREE)
    source = load_manifest(directory / SOURCE)
    if inventory["inventory_sha256"] != source["tree_inventory"]["sha256"]:
        raise ManifestError("acquired tree inventory differs from the committed source manifest")
    return SourceTree(acquired / TREE_DIR, source)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def validate_manifests(manifests: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Offline consistency checks over the complete committed manifest set; raises ManifestError on the first failure.

    The upstream-verification and corpus-token manifests are checked for their
    pinned identities and for every link to the other manifests that offline data
    allows (frame digests, sizes, policy digest, document count, binding). Their
    counts were produced by the data-backed commands and are not recomputed here.
    """
    for name in ALL:
        _require(name in manifests, f"{name} is missing")
    for manifest in manifests.values():
        verify_self_digest(manifest)
    source = manifests[SOURCE]
    _require(source["commit"] == upstream.COMMIT and source["tree"] == upstream.TREE, "source is not the pin")
    consumed = {item["path"]: item["sha256"] for item in source["consumed"]}
    _require(set(upstream.CONSUMED_FILES) <= set(consumed), "consumed files are missing from source.json")
    _require(all(upstream.is_consumed(path) for path in consumed), "source.json lists files outside the scope")
    _require(consumed[upstream.RETAIL_50] == upstream.RETAIL_50_SHA256, "retail_50 digest is not the pinned value")

    retail = manifests[RETAIL_SPLIT]
    frame = retail["frame"]["task_ids"]
    holdout = retail["splits"]["holdout"]["task_ids"]
    dev = retail["splits"]["dev"]["task_ids"]
    _require(len(frame) == retail["frame"]["size"] == 114 and len(set(frame)) == 114, "retail frame is not 114")
    _require(id_list_digest(frame) == retail["frame"]["digest"] == retail["upstream_subset"]["frame_digest"],
             "retail frame digest mismatch")
    _require(len(holdout) == 50 and len(dev) == 64, "retail split is not 64 dev / 50 holdout")
    _require(not set(holdout) & set(dev), "retail dev and holdout overlap")
    _require(set(holdout) | set(dev) == set(frame), "retail splits do not cover the frame")
    _require(dev == [task_id for task_id in frame if task_id not in set(holdout)], "retail dev is not the complement")
    for side, ids in (("holdout", holdout), ("dev", dev)):
        section = retail["splits"][side]
        _require(section["count"] == len(ids) and section["digest"] == id_list_digest(ids), f"retail {side} digest")
    _require(retail["source"]["retail_50_sha256"] == upstream.RETAIL_50_SHA256, "retail split retail_50 digest")
    _require(retail["source"]["tasks_json_sha256"] == consumed[upstream.RETAIL_TASKS], "retail tasks digest")
    _require(retail["upstream_subset"]["seed"] == 42 and retail["upstream_subset"]["stratifier"] == "write_profile",
             "retail draw metadata")
    strata = retail["upstream_subset"]["strata"]
    _require(sum(item["drawn"] for item in strata) == 50 and sum(item["frame_size"] for item in strata) == 114,
             "retail strata totals")
    _require(sum(retail["dev_strata_by_subtraction"].values()) == 64, "retail dev strata total")

    bank = manifests[BANKING_SPLIT]
    bank_frame = bank["frame"]["task_ids"]
    _require(len(bank_frame) == bank["frame"]["size"] == bank["labels"]["eligible_tasks"], "banking frame size")
    _require(id_list_digest(bank_frame) == bank["frame"]["digest"], "banking frame digest")
    task_paths = [path for path in sorted(consumed) if path.startswith(upstream.BANKING_TASKS_DIR + "/")]
    _require([banking.stem(path) for path in task_paths] == bank_frame, "banking frame differs from task files")
    _require(bank["source"]["task_files_sha256"] == id_list_digest(consumed[path] for path in task_paths),
             "banking task file digest")
    doc_paths = [path for path in sorted(consumed) if path.startswith(upstream.BANKING_DOCUMENTS_DIR + "/")]
    _require(len(doc_paths) == bank["labels"]["document_files"], "banking document count")
    _require(bank["source"]["document_files_sha256"] == id_list_digest(consumed[path] for path in doc_paths),
             "banking document digest")
    _require(not bank["labels"]["unmatched_ids"], "banking labels have unmatched IDs")
    members = bank["grouping"]["members"]
    grouped = [task_id for group in members for task_id in group["task_ids"]]
    _require(sorted(grouped) == sorted(bank_frame) and len(grouped) == len(set(grouped)),
             "banking groups do not partition the frame")
    _require(len(members) == bank["grouping"]["groups"], "banking group count")
    groups = [group["task_ids"] for group in members]
    _require(all(group["group"] == group["task_ids"][0] == min(group["task_ids"]) for group in members),
             "banking group identifiers")
    reassigned = banking.assign_groups(groups, seed=bank["assignment"]["seed"],
                                       fraction=bank["assignment"]["dev_fraction"])
    _require(all(reassigned[group["group"]] == group["split"] for group in members),
             "banking group assignment is not reproducible from the seed")
    split_ids = bank["splits"]
    _require(set(split_ids) == {"dev", "test"}, "banking splits must be dev and test")
    for side, section in split_ids.items():
        expected = [task_id for task_id in bank_frame
                    if any(task_id in group["task_ids"] and group["split"] == side for group in members)]
        _require(section["task_ids"] == expected, f"banking {side} membership differs from its groups")
        _require(section["count"] == len(expected) and section["digest"] == id_list_digest(expected),
                 f"banking {side} digest")
        _require(section["groups"] == sum(group["split"] == side for group in members), f"banking {side} groups")
    _require(not set(split_ids["dev"]["task_ids"]) & set(split_ids["test"]["task_ids"]), "banking splits overlap")
    _require(split_ids["dev"]["count"] <= bank["assignment"]["target_dev_tasks"], "banking dev exceeds target")

    rights = manifests[RIGHTS]
    _require({item["path"]: item["sha256"] for item in rights["consumed"]} == consumed,
             "rights audit does not cover exactly the consumed files")
    _require(rights["commit"] == upstream.COMMIT, "rights audit is not for the pinned commit")
    _require(rights["license_basis"]["license_sha256"] == consumed[upstream.LICENSE], "rights audit license digest")

    audit = manifests[RETAIL_AUDIT]
    _require(audit["commit"] == upstream.COMMIT, "retail audit is not for the pinned commit")
    _require(audit["dev"]["count"] == len(dev) and audit["holdout"]["count"] == len(holdout), "retail audit counts")
    replaced = audit["english_text_binding_replacements"]
    _require(replaced["replaced_tasks"] == len(holdout) and replaced["replaced_dev_tasks"] == 0,
             "retail audit replacement counts")

    verified = manifests[UPSTREAM]
    _require(verified["schema"] == "policyops.upstream-verification/v1" and verified["commit"] == upstream.COMMIT,
             "upstream verification is not for the pinned commit")
    draws = verified["draws"]
    _require(draws["retail_50"] == {**draws["retail_50"], "frame_digest": retail["frame"]["digest"],
                                    "frame_size": len(frame), "selected": len(holdout)}, "retail draw verification")
    _require(draws["banking_knowledge_97"] == {**draws["banking_knowledge_97"], "frame_digest": bank["frame"]["digest"],
                                               "frame_size": len(bank_frame), "selected": len(bank_frame)},
             "banking draw verification")
    _require(verified["english_retail_text_binding"]["binding_revision"] == upstream.RETAIL_EN_TEXT_BINDING
             == retail["upstream_subset"]["benchmark"]["en_retail_binding_revision"], "English retail binding")
    loader = verified["banking_loader_labels"]
    _require(loader["tasks"] == len(bank_frame) and loader["per_task_ordered_equal"] is True, "banking loader labels")
    package = verified["installed_package"]
    _require(package["direct_url_commit"] == upstream.COMMIT and package["all_match_record_and_commit"] is True
             and package["installed_files_hashed"] > 0, "installed package parity")
    replay = verified["dev_reference_replay"]
    _require([item["task_id"] for item in replay["per_task"]] == dev and replay["tasks"] == len(dev),
             "dev reference replay does not cover exactly the dev tasks")

    tokens = manifests[TOKENS]
    _require(tokens["schema"] == "policyops.corpus-tokens/v1" and tokens["source_commit"] == upstream.COMMIT,
             "corpus tokens are not for the pinned commit")
    _require(tokens["extraction"]["retail_policy_sha256"] == consumed[upstream.RETAIL_POLICY],
             "corpus tokens policy digest differs from the pinned policy file")
    _require(tokens["extraction"]["banking_documents"] == len(doc_paths), "corpus tokens document count")
    sizes = {item["path"]: item["size"] for item in source["consumed"]}
    _require(tokens["sizes"]["banking_document_files_bytes"] == sum(sizes[path] for path in doc_paths)
             and tokens["sizes"]["retail_policy_bytes"] == sizes[upstream.RETAIL_POLICY], "corpus tokens sizes")
    _require(tokens["tokenizer"]["installed_model_mapping"].get("text-embedding-3-small") == "cl100k_base"
             and set(tokens["counts_by_encoding"]) == {"cl100k_base", "o200k_base"}, "corpus tokens tokenizer record")
    SplitGuard({"retail": retail, "banking_knowledge": bank})
    return {
        "retail": {"frame": len(frame), "dev": len(dev), "holdout": len(holdout)},
        "banking": {"frame": len(bank_frame), "dev": split_ids["dev"]["count"], "test": split_ids["test"]["count"],
                    "groups": len(members), "distinct_required_ids": bank["labels"]["distinct_required_ids"],
                    "document_files": bank["labels"]["document_files"]},
        "consumed_files": len(consumed),
    }
