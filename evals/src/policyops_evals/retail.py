"""Retail 64-dev / 50-holdout split and its distribution and known-issue audit.

Holdout = every task ID in the released upstream `retail_50` subset (verified by
byte digest). Dev = the complement within the 114-task canonical frame, in
upstream order. Holdout reads are restricted to scoring metadata (IDs,
`reward_basis`, whether NL assertions exist, issue annotations and scenario text
for the dev/holdout near-duplicate check) plus a whole-record equality
comparison with the reviewed English replacement, which compares nested
criteria for equality and reports only field names. Holdout reference actions
and assertion text are never replayed, counted or individually inspected.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import re
import statistics
from typing import Any

from policyops_evals import upstream
from policyops_evals.canonical import ManifestError, id_list_digest
from policyops_evals.sources import SourceTree


SPLIT_SCHEMA = "policyops.retail-split/v1"
NEAR_DUPLICATE_THRESHOLDS = (0.5, 0.7, 0.9)


def _tasks(tree: SourceTree) -> list[dict[str, Any]]:
    tasks = tree.json(upstream.RETAIL_TASKS)
    if not isinstance(tasks, list) or not all(isinstance(task, dict) for task in tasks):
        raise ManifestError("retail tasks.json is not a list of objects")
    return tasks


def build_retail_split(tree: SourceTree) -> dict[str, Any]:
    tasks = _tasks(tree)
    frame = [str(task["id"]) for task in tasks]
    if len(set(frame)) != len(frame):
        raise ManifestError("duplicate retail task IDs")
    subset_bytes = tree.read(upstream.RETAIL_50)
    if tree.sha256(upstream.RETAIL_50) != upstream.RETAIL_50_SHA256:
        raise ManifestError("retail_50.json is not the released subset bytes")
    subset = tree.json(upstream.RETAIL_50)
    benchmark = tree.json(upstream.TEXT_BENCHMARK)
    if benchmark["task_subsets"]["retail"] != {"name": "retail_50", "sha256": upstream.RETAIL_50_SHA256}:
        raise ManifestError("text benchmark does not pin the same retail_50 bytes")
    bindings = [cell["binding_revision"] for cell in benchmark["cells"]
                if cell["language"] == "en" and cell["domain"] == "retail"]
    if bindings != [upstream.RETAIL_EN_TEXT_BINDING]:
        raise ManifestError("English retail binding revision differs from the pinned value")
    census = tree.json(upstream.RETAIL_114)
    expected = {"name": "retail_50", "domain": "retail", "strategy": "stratified", "stratifier": "write_profile",
                "seed": 42}
    if {key: subset.get(key) for key in expected} != expected:
        raise ManifestError("retail_50 metadata differs from the reviewed draw description")
    if subset["frame"] != {"task_set": "retail", "task_split": "base", "size": len(frame),
                           "digest": id_list_digest(frame)}:
        raise ManifestError("retail_50 frame does not match the canonical 114-task frame")
    if census["task_ids"] != frame or census["frame"]["digest"] != id_list_digest(frame):
        raise ManifestError("retail_114 census disagrees with tasks.json order")
    holdout = [str(task_id) for task_id in subset["task_ids"]]
    if len(set(holdout)) != len(holdout) or not set(holdout) <= set(frame):
        raise ManifestError("retail_50 IDs are duplicated or outside the frame")
    if sum(stratum["drawn"] for stratum in subset["strata"]) != len(holdout) or len(holdout) != 50:
        raise ManifestError("retail_50 strata do not account for 50 drawn tasks")
    holdout_set = set(holdout)
    dev = [task_id for task_id in frame if task_id not in holdout_set]
    upstream_split = tree.json(upstream.RETAIL_UPSTREAM_SPLITS)
    return {
        "schema": SPLIT_SCHEMA,
        "domain": "retail",
        "source": {
            "commit": upstream.COMMIT,
            "tasks_json_sha256": tree.sha256(upstream.RETAIL_TASKS),
            "retail_50_sha256": tree.sha256(upstream.RETAIL_50),
            "text_benchmark_sha256": tree.sha256(upstream.TEXT_BENCHMARK),
            "retail_50_bytes": len(subset_bytes),
        },
        "frame": {"size": len(frame), "digest": id_list_digest(frame), "order": "upstream tasks.json order",
                  "task_ids": frame},
        "upstream_subset": {
            "name": subset["name"], "strategy": subset["strategy"], "stratifier": subset["stratifier"],
            "seed": subset["seed"], "frame_digest": subset["frame"]["digest"], "created": subset.get("created"),
            "strata": subset["strata"],
            "benchmark": {"version": benchmark["benchmark_version"], "revision": benchmark["revision"],
                          "en_retail_binding_revision": bindings[0]},
        },
        "splits": {
            "holdout": {
                "count": len(holdout), "digest": id_list_digest(holdout), "order": "retail_50 order",
                "use": "untouched project holdout; final paired evaluation only", "task_ids": holdout,
            },
            "dev": {
                "count": len(dev), "digest": id_list_digest(dev), "order": "upstream tasks.json order",
                "use": "development, tuning, smoke and demo scenarios", "task_ids": dev,
            },
        },
        "dev_strata_by_subtraction": {
            stratum["key"]: stratum["frame_size"] - stratum["drawn"] for stratum in subset["strata"]
        },
        "upstream_split_not_used": {
            "path": upstream.RETAIL_UPSTREAM_SPLITS, "sha256": tree.sha256(upstream.RETAIL_UPSTREAM_SPLITS),
            "sizes": {name: len(ids) for name, ids in sorted(upstream_split.items())},
        },
    }


def _scenario_text(task: Mapping[str, Any]) -> str:
    instructions = task["user_scenario"]["instructions"]
    if isinstance(instructions, str):
        return instructions
    return "\n".join(str(instructions.get(key) or "") for key in sorted(instructions))


def shingles(text: str, size: int = 5) -> set[str]:
    normalized = re.sub(r"\s+", " ", text.casefold()).strip()
    return {normalized[i:i + size] for i in range(max(1, len(normalized) - size + 1))}


def jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _nl_present(task: Mapping[str, Any]) -> bool:
    return bool(task["evaluation_criteria"].get("nl_assertions"))


def _scoring_profile(tasks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    nl = sum(_nl_present(task) for task in tasks)
    return {
        "count": len(tasks),
        "reward_basis": {"+".join(basis): count for basis, count in sorted(Counter(
            tuple(task["evaluation_criteria"]["reward_basis"]) for task in tasks).items())},
        "nl_assertions_nonempty": nl,
        "nl_assertions_empty_or_null": len(tasks) - nl,
        "initial_state_present": sum(task.get("initial_state") is not None for task in tasks),
        "upstream_issue_annotations": sum(bool(task.get("issues")) for task in tasks),
    }


def build_retail_audit(tree: SourceTree, split: Mapping[str, Any]) -> dict[str, Any]:
    tasks = {str(task["id"]): task for task in _tasks(tree)}
    dev_ids = split["splits"]["dev"]["task_ids"]
    holdout_ids = split["splits"]["holdout"]["task_ids"]
    dev = [tasks[task_id] for task_id in dev_ids]
    holdout = [tasks[task_id] for task_id in holdout_ids]
    action_counts = [len(task["evaluation_criteria"].get("actions") or []) for task in dev]
    tools = Counter(action["name"] for task in dev for action in task["evaluation_criteria"].get("actions") or [])
    issues = []
    issue_files = set(tree.listing(upstream.RETAIL_ISSUES_DIR))
    for task_id, task in tasks.items():
        for issue in task.get("issues") or []:
            linked = f"{upstream.RETAIL_DIR}/{issue.get('simulation_file')}"
            issues.append({
                "task_id": task_id, "split": "holdout" if task_id in set(holdout_ids) else "dev",
                "issue_id": issue.get("id"), "status": issue.get("status"), "created_at": issue.get("created_at"),
                "linked_trajectory_present": linked in issue_files,
            })
    dev_text = {task_id: shingles(_scenario_text(tasks[task_id])) for task_id in dev_ids}
    holdout_text = {task_id: shingles(_scenario_text(tasks[task_id])) for task_id in holdout_ids}
    replacements = tree.json(upstream.EN_RETAIL_TASKS)
    replacement_metadata = tree.json(upstream.EN_RETAIL_METADATA)
    replaced_ids = [str(task["id"]) for task in replacements]
    if set(replaced_ids) != set(replacement_metadata) or len(set(replaced_ids)) != len(replaced_ids):
        raise ManifestError("English pack retail tasks and metadata disagree")
    replaced_fields: Counter[str] = Counter()
    criteria_identical = 0
    for task in replacements:
        canonical = tasks[str(task["id"])]
        for key in sorted(set(task) | set(canonical)):
            if task.get(key) != canonical.get(key):
                replaced_fields[key] += 1
        criteria_identical += task.get("evaluation_criteria") == canonical.get("evaluation_criteria")
    for task in replacements:
        holdout_text[f"en:{task['id']}"] = shingles(_scenario_text(task))
    nearest = {}
    for dev_id, dev_shingles in dev_text.items():
        score, other = max((jaccard(dev_shingles, text), holdout_id) for holdout_id, text in holdout_text.items())
        nearest[dev_id] = (round(score, 4), other)
    within_dev = []
    ordered = list(dev_text)
    for index, left in enumerate(ordered):
        for right in ordered[index + 1:]:
            within_dev.append(jaccard(dev_text[left], dev_text[right]))
    nl_inconsistent = [str(task["id"]) for task in dev
                       if "NL_ASSERTION" in task["evaluation_criteria"]["reward_basis"] and not _nl_present(task)]
    return {
        "dev": {
            **_scoring_profile(dev),
            "reference_action_count": {
                "min": min(action_counts), "median": statistics.median(action_counts), "max": max(action_counts),
                "mean": round(statistics.mean(action_counts), 4),
            },
            "reference_tools_used": dict(sorted(tools.items())),
            "nl_assertion_in_reward_basis_but_no_assertions": {"count": len(nl_inconsistent),
                                                                "task_ids": nl_inconsistent},
        },
        "holdout": {
            **_scoring_profile(holdout),
            "fields_read": ["id", "evaluation_criteria.reward_basis", "presence of evaluation_criteria.nl_assertions",
                            "initial_state presence", "issues", "user_scenario.instructions (similarity only)",
                            "whole-record equality with the English replacement (field names only)"],
        },
        "upstream_issue_annotations": issues,
        "english_text_binding_replacements": {
            "path": upstream.EN_RETAIL_TASKS,
            "replaced_task_ids_equal_holdout": set(replaced_ids) == set(holdout_ids),
            "replaced_dev_tasks": len(set(replaced_ids) & set(dev_ids)),
            "replaced_tasks": len(replaced_ids),
            "fields_differing_from_tasks_json": dict(sorted(replaced_fields.items())),
            "evaluation_criteria_identical": criteria_identical,
            "consequence": "under the text-v1 English binding, held-out tasks use reviewed user scenarios; dev "
                           "tasks keep the unreviewed registry scenarios from tasks.json",
        },
        "dev_holdout_scenario_similarity": {
            "method": "Jaccard similarity of casefolded, whitespace-normalized character 5-gram sets of "
                      "user_scenario.instructions; nearest holdout scenario (registry or reviewed English "
                      "replacement) per dev task",
            "dev_tasks_with_nearest_holdout_at_or_above": {
                str(threshold): sum(score >= threshold for score, _ in nearest.values())
                for threshold in NEAR_DUPLICATE_THRESHOLDS
            },
            "pairs_at_or_above_0.7": sorted(
                [{"dev": dev_id, "holdout": other.removeprefix("en:"), "jaccard": score}
                 for dev_id, (score, other) in nearest.items() if score >= 0.7],
                key=lambda item: (-float(item["jaccard"]), str(item["dev"]))),
            "max_nearest": max(score for score, _ in nearest.values()),
            "median_nearest": statistics.median(score for score, _ in nearest.values()),
            "within_dev_pairs_at_or_above_0.7": sum(score >= 0.7 for score in within_dev),
        },
    }
