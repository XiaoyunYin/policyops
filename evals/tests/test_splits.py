"""Retail and banking split derivation on synthetic trees, and the committed manifests themselves."""

from collections.abc import Callable
import copy
import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from policyops_evals import banking, upstream
from policyops_evals.build import (
    ALL,
    BANKING_SPLIT,
    CORE,
    RETAIL_AUDIT,
    RETAIL_SPLIT,
    RIGHTS,
    SOURCE,
    TOKENS,
    UPSTREAM,
    default_manifest_dir,
    load_committed,
    validate_manifests,
)
from policyops_evals.canonical import ManifestError, canonical_bytes, id_list_digest, sha256_bytes, with_self_digest
from policyops_evals.retail import build_retail_audit, build_retail_split
from policyops_evals.sources import SourceTree


SyntheticTree = Callable[[dict[str, bytes]], SourceTree]


def encode(value: Any) -> bytes:
    return json.dumps(value, indent=2).encode("utf-8")


def retail_task(task_id: str, text: str, *, nl: bool = False, issues: bool = False) -> dict[str, Any]:
    task: dict[str, Any] = {
        "id": task_id, "description": {"purpose": None}, "initial_state": None,
        "user_scenario": {"persona": None, "instructions": {"task_instructions": text, "known_info": "x"}},
        "evaluation_criteria": {"actions": [{"action_id": f"{task_id}_0", "name": "get_order_details",
                                             "arguments": {"order_id": "#W1"}}],
                                "nl_assertions": ["asserted"] if nl else None,
                                "reward_basis": ["DB", "NL_ASSERTION"], "communicate_info": []},
    }
    if issues:
        task["issues"] = [{"id": "issue_1", "status": "open", "created_at": "2026-01-01",
                           "author_email": "person@example.invalid", "simulation_file": "task_issues/t.json"}]
    return task


def retail_files(monkeypatch: pytest.MonkeyPatch) -> dict[str, bytes]:
    tasks = [retail_task(str(i), f"scenario number {i} " + "word " * (i % 7), nl=i % 3 == 0, issues=i == 1)
             for i in range(114)]
    ids = [task["id"] for task in tasks]
    holdout = [task_id for task_id in ids if int(task_id) % 2 == 0][:50]
    subset = {"name": "retail_50", "domain": "retail", "strategy": "stratified", "stratifier": "write_profile",
              "seed": 42, "frame": {"task_set": "retail", "task_split": "base", "size": 114,
                                    "digest": id_list_digest(ids)},
              "strata": [{"key": "all/1", "frame_size": 114, "drawn": 50}], "created": "2026-01-01",
              "git_commit": None, "task_ids": holdout}
    subset_bytes = encode(subset)
    monkeypatch.setattr(upstream, "RETAIL_50_SHA256", sha256_bytes(subset_bytes))
    monkeypatch.setattr(upstream, "RETAIL_EN_TEXT_BINDING", "b" * 64)
    replacements = [{**task, "user_scenario": {"persona": None, "instructions": {"task_instructions": "reviewed"}}}
                    for task in tasks if task["id"] in holdout]
    return {
        upstream.RETAIL_TASKS: encode(tasks),
        upstream.RETAIL_50: subset_bytes,
        upstream.RETAIL_114: encode({"task_ids": ids, "frame": {"digest": id_list_digest(ids)}}),
        upstream.TEXT_BENCHMARK: encode({
            "benchmark_version": "text-v1", "revision": "r",
            "task_subsets": {"retail": {"name": "retail_50", "sha256": sha256_bytes(subset_bytes)}},
            "cells": [{"language": "en", "domain": "retail", "binding_revision": "b" * 64}]}),
        upstream.RETAIL_UPSTREAM_SPLITS: encode({"train": ids[:74], "test": ids[74:], "base": ids}),
        upstream.EN_RETAIL_TASKS: encode(replacements),
        upstream.EN_RETAIL_METADATA: encode({task_id: {"canonical_task_id": task_id} for task_id in holdout}),
        f"{upstream.RETAIL_ISSUES_DIR}/t.json": b"{}",
    }


def test_retail_split_is_the_exact_complement(synthetic_tree: SyntheticTree, monkeypatch: pytest.MonkeyPatch) -> None:
    split = build_retail_split(synthetic_tree(retail_files(monkeypatch)))
    holdout, dev = split["splits"]["holdout"]["task_ids"], split["splits"]["dev"]["task_ids"]
    assert len(holdout) == 50 and len(dev) == 64
    assert not set(holdout) & set(dev)
    assert dev == [task_id for task_id in split["frame"]["task_ids"] if task_id not in holdout]
    assert split["splits"]["dev"]["digest"] == id_list_digest(dev)


def test_retail_subset_with_other_bytes_is_rejected(synthetic_tree: SyntheticTree,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    files = retail_files(monkeypatch)
    monkeypatch.setattr(upstream, "RETAIL_50_SHA256", "0" * 64)
    with pytest.raises(ManifestError, match="released subset"):
        build_retail_split(synthetic_tree(files))


def test_tampered_source_file_is_rejected(synthetic_tree: SyntheticTree, monkeypatch: pytest.MonkeyPatch) -> None:
    tree = synthetic_tree(retail_files(monkeypatch))
    target = tree.root.joinpath(*upstream.RETAIL_50.split("/"))
    target.write_bytes(target.read_bytes().replace(b'"6"', b'"7"'))
    with pytest.raises(ManifestError, match="pinned SHA-256"):
        build_retail_split(tree)


def test_retail_audit_reports_replacements_issues_and_never_copies_contacts(
        synthetic_tree: SyntheticTree, monkeypatch: pytest.MonkeyPatch) -> None:
    tree = synthetic_tree(retail_files(monkeypatch))
    audit = build_retail_audit(tree, build_retail_split(tree))
    replacements = audit["english_text_binding_replacements"]
    assert replacements["replaced_task_ids_equal_holdout"] and replacements["replaced_dev_tasks"] == 0
    assert replacements["fields_differing_from_tasks_json"] == {"user_scenario": 50}
    assert audit["upstream_issue_annotations"][0]["split"] == "dev"
    assert b"example.invalid" not in canonical_bytes(audit)
    assert audit["holdout"]["count"] == 50 and "reference_action_count" not in audit["holdout"]


def bank_task(task_id: str, docs: list[str], text: str) -> dict[str, Any]:
    return {"id": task_id, "description": {"purpose": f"Task: {task_id}"}, "initial_state": None,
            "user_scenario": {"persona": None, "instructions": text}, "annotations": None, "user_tools": [],
            "evaluation_criteria": {"actions": [], "reward_basis": ["DB"]}, "required_documents": docs}


def bank_files(tasks: list[dict[str, Any]], docs: list[str]) -> dict[str, bytes]:
    files = {f"{upstream.BANKING_TASKS_DIR}/{task['id']}.json": encode(task) for task in tasks}
    files.update({f"{upstream.BANKING_DOCUMENTS_DIR}/{doc}.json": encode({"id": doc, "title": doc, "content": "c"})
                  for doc in docs})
    ids = [task["id"] for task in tasks]
    files[upstream.BANKING_97] = encode({"task_ids": ids, "frame": {"digest": id_list_digest(ids)}})
    files[upstream.BANKING_TASKS_AGGREGATE] = encode(
        [{**task, "required_documents": ["doc_11"]} if task["id"] == "task_003" else task
         for task in tasks])
    return files


DOCS = [f"doc_{i:02d}" for i in range(30)]


def bank_tasks() -> list[dict[str, Any]]:
    tasks = [
        bank_task("task_001", ["doc_00", "doc_01", "doc_02"], "alpha scenario about cards"),
        bank_task("task_002", ["doc_00", "doc_01", "doc_02", "doc_03"], "completely different words here"),
        bank_task("task_003", ["doc_10"], "the customer wants to dispute a charge on the gold card today"),
        bank_task("task_004", ["doc_11"], "the customer wants to dispute a charge on the gold card now"),
    ]
    tasks += [bank_task(f"task_{i:03d}", [DOCS[i + 15]], f"unique {i} " + chr(65 + i) * 12) for i in range(5, 15)]
    return tasks


def test_banking_groups_link_label_and_scenario_duplicates(synthetic_tree: SyntheticTree) -> None:
    split = banking.build_banking_split(synthetic_tree(bank_files(bank_tasks(), DOCS)))
    groups = {tuple(group["task_ids"]) for group in split["grouping"]["members"]}
    assert ("task_001", "task_002") in groups and ("task_003", "task_004") in groups
    dev, test = split["splits"]["dev"]["task_ids"], split["splits"]["test"]["task_ids"]
    assert not set(dev) & set(test) and len(dev) + len(test) == 14
    assert len(dev) <= round(0.4 * 14)
    for group in split["grouping"]["members"]:
        assert set(group["task_ids"]) <= set(dev if group["split"] == "dev" else test)
    aggregate = split["aggregate_tasks_json"]
    assert aggregate["required_documents_differ_for"] == ["task_003"]
    assert aggregate["ids_only_in_canonical"] == ["doc_10"] and aggregate["ids_only_in_aggregate"] == []


def test_group_assignment_is_seeded_and_deterministic() -> None:
    groups = [["a", "b"], ["c"], ["d", "e", "f"], ["g"], ["h"], ["i", "j"]]
    first = banking.assign_groups(groups, seed=42)
    assert first == banking.assign_groups(list(reversed(groups)), seed=42)
    assert sum(len(group) for group in groups if first[group[0]] == "dev") <= round(0.4 * 10)


@pytest.mark.parametrize("problem", ["unmatched", "duplicate", "empty", "stem", "extra-file"])
def test_banking_label_and_document_defects_are_rejected(synthetic_tree: SyntheticTree, problem: str) -> None:
    tasks, docs = bank_tasks(), list(DOCS)
    files = bank_files(tasks, docs)
    if problem == "unmatched":
        files[f"{upstream.BANKING_TASKS_DIR}/task_005.json"] = encode(bank_task("task_005", ["doc_missing"], "u"))
    elif problem == "duplicate":
        files[f"{upstream.BANKING_TASKS_DIR}/task_005.json"] = encode(bank_task("task_005", ["doc_05", "doc_05"], "u"))
    elif problem == "empty":
        files[f"{upstream.BANKING_TASKS_DIR}/task_005.json"] = encode(bank_task("task_005", [], "u"))
    elif problem == "stem":
        files[f"{upstream.BANKING_DOCUMENTS_DIR}/doc_05.json"] = encode({"id": "other", "title": "t", "content": "c"})
    tree = synthetic_tree(files)
    if problem == "extra-file":
        injected = tree.root.joinpath(*upstream.BANKING_DOCUMENTS_DIR.split("/"), "doc_injected.json")
        injected.write_bytes(b"{}")
        with pytest.raises(ManifestError, match="unexpected"):
            type(tree)(tree.root, tree.manifest)
        return
    with pytest.raises(ManifestError):
        banking.build_banking_split(tree)


@pytest.fixture
def committed() -> dict[str, dict[str, Any]]:
    return load_committed(default_manifest_dir())


def test_committed_manifests_are_consistent(committed: dict[str, dict[str, Any]]) -> None:
    summary = validate_manifests(committed)
    assert summary["retail"] == {"frame": 114, "dev": 64, "holdout": 50}
    assert summary["banking"]["frame"] == 97 and summary["banking"]["document_files"] == 698
    assert summary["banking"]["distinct_required_ids"] == 218
    assert summary["banking"]["dev"] + summary["banking"]["test"] == 97
    aggregate = committed[BANKING_SPLIT]["aggregate_tasks_json"]["aggregate_label_statistics"]
    assert aggregate["distinct_required_ids"] == 215


def test_committed_manifest_files_are_canonical() -> None:
    for path in sorted(default_manifest_dir().glob("*.json")):
        data = path.read_bytes()
        assert b"\r" not in data and data == canonical_bytes(json.loads(data)), path.name


def resealed(manifests: dict[str, dict[str, Any]], name: str, edit: Any) -> dict[str, dict[str, Any]]:
    changed = copy.deepcopy(manifests)
    edit(changed[name])
    changed[name] = with_self_digest(changed[name])
    return changed


def move_holdout_to_dev(manifest: dict[str, Any]) -> None:
    manifest["splits"]["dev"]["task_ids"].append(manifest["splits"]["holdout"]["task_ids"][0])


def flip_group(manifest: dict[str, Any]) -> None:
    group = manifest["grouping"]["members"][0]
    group["split"] = "test" if group["split"] == "dev" else "dev"


def straddle_group(manifest: dict[str, Any]) -> None:
    group = next(group for group in manifest["grouping"]["members"] if len(group["task_ids"]) > 1)
    other = "test" if group["split"] == "dev" else "dev"
    moved = group["task_ids"][0]
    manifest["splits"][group["split"]]["task_ids"].remove(moved)
    manifest["splits"][other]["task_ids"].append(moved)


def drop_rights_entry(manifest: dict[str, Any]) -> None:
    manifest["consumed"].pop()


def swap_document_hash(manifest: dict[str, Any]) -> None:
    entry = next(item for item in manifest["consumed"] if item["path"].startswith(upstream.BANKING_DOCUMENTS_DIR))
    entry["sha256"] = "0" * 64


@pytest.mark.parametrize(("name", "edit"), [
    (RETAIL_SPLIT, move_holdout_to_dev),
    (BANKING_SPLIT, flip_group),
    (BANKING_SPLIT, straddle_group),
    (RIGHTS, drop_rights_entry),
    (SOURCE, swap_document_hash),
])
def test_resealed_semantic_tampering_is_detected(committed: dict[str, dict[str, Any]], name: str, edit: Any) -> None:
    with pytest.raises(ManifestError):
        validate_manifests(resealed(committed, name, edit))


def test_unsealed_edit_fails_the_self_digest(committed: dict[str, dict[str, Any]], tmp_path: Path) -> None:
    changed = copy.deepcopy(committed)
    changed[RETAIL_SPLIT]["splits"]["dev"]["count"] = 63
    with pytest.raises(ManifestError, match="manifest_sha256"):
        validate_manifests(changed)


@pytest.mark.parametrize("name", ALL)
def test_every_required_manifest_must_be_present(tmp_path: Path, name: str) -> None:
    for path in default_manifest_dir().glob("*.json"):
        if path.name != name:
            shutil.copyfile(path, tmp_path / path.name)
    with pytest.raises(ManifestError, match="missing"):
        load_committed(tmp_path)
    if name in (UPSTREAM, TOKENS):
        assert set(load_committed(tmp_path, CORE)) == set(CORE)  # bootstrap of generated manifests
    complete = load_committed(default_manifest_dir())
    with pytest.raises(ManifestError, match="missing"):
        validate_manifests({key: value for key, value in complete.items() if key != name})


def set_path(manifest: dict[str, Any], dotted: str, value: Any) -> None:
    *parents, last = dotted.split(".")
    for key in parents:
        manifest = manifest[key]
    manifest[last] = value


@pytest.mark.parametrize(("name", "dotted", "value"), [
    (TOKENS, "source_commit", "0" * 40),
    (TOKENS, "extraction.retail_policy_sha256", "0" * 64),
    (TOKENS, "extraction.banking_documents", 697),
    (TOKENS, "sizes.banking_document_files_bytes", 1),
    (UPSTREAM, "commit", "0" * 40),
    (UPSTREAM, "english_retail_text_binding.binding_revision", "a37c0112" + "0" * 56),
    (UPSTREAM, "draws.retail_50.frame_digest", "0" * 64),
    (UPSTREAM, "banking_loader_labels.per_task_ordered_equal", False),
    (UPSTREAM, "installed_package.direct_url_commit", "0" * 40),
    (UPSTREAM, "dev_reference_replay.tasks", 63),
    (RETAIL_AUDIT, "commit", "0" * 40),
    (RIGHTS, "commit", "0" * 40),
])
def test_resealed_wrong_pin_or_cross_reference_is_detected(committed: dict[str, dict[str, Any]], name: str,
                                                            dotted: str, value: Any) -> None:
    with pytest.raises(ManifestError):
        validate_manifests(resealed(committed, name, lambda manifest: set_path(manifest, dotted, value)))


def test_replay_must_cover_exactly_the_dev_tasks(committed: dict[str, dict[str, Any]]) -> None:
    def swap_in_holdout(manifest: dict[str, Any]) -> None:
        manifest["dev_reference_replay"]["per_task"][0]["task_id"] = committed[RETAIL_SPLIT]["splits"]["holdout"][
            "task_ids"][0]
    with pytest.raises(ManifestError, match="dev tasks"):
        validate_manifests(resealed(committed, UPSTREAM, swap_in_holdout))
