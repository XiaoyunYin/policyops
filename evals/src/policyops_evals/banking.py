"""Banking-knowledge label validation and the grouped 40/60 dev/test split.

Canonical tasks are the per-task files in `tasks/`, which upstream
`banking_knowledge.environment.get_tasks` loads; the aggregated `tasks.json` is
compared but not used. `required_documents` are task-level labels for a whole
multi-turn trajectory, never per-turn or per-chunk relevance.

Grouping (evaluator-side only): tasks are linked when their required-document
sets have Jaccard >= 0.5 or their user-scenario texts share >= 0.5 of their
character 5-grams; connected components are groups, so tasks that are near
duplicates under this heuristic never straddle dev and test. Semantic duplicates
the heuristic misses are not validated. Groups are ordered by SHA-256 of
`"<seed>|banking_knowledge|<group id>"` and assigned to dev while the dev task
count stays within round(0.4 * N); the remaining groups are test. Thresholds and
seed were fixed before any retrieval run; there are no outcomes to tune on yet.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import statistics
from typing import Any

from policyops_evals import upstream
from policyops_evals.acquire import safe_target
from policyops_evals.canonical import ManifestError, id_list_digest
from policyops_evals.retail import jaccard, shingles
from policyops_evals.sources import SourceTree


SPLIT_SCHEMA = "policyops.banking-split/v1"
SEED = 42
DEV_FRACTION = 0.4
LABEL_JACCARD = 0.5
SCENARIO_JACCARD = 0.5
DOCUMENT_KEYS = {"id", "title", "content"}


def stem(path: str) -> str:
    return path.rsplit("/", 1)[1].removesuffix(".json")


def load_tasks(tree: SourceTree) -> list[dict[str, Any]]:
    tasks = []
    for path in tree.listing(upstream.BANKING_TASKS_DIR):
        name = path.rsplit("/", 1)[1]
        if not (name.startswith("task_") and name.endswith(".json")):
            raise ManifestError(f"unexpected file in banking tasks directory: {name}")
        task = tree.json(path)
        if task.get("id") != stem(path):
            raise ManifestError(f"{name}: task id does not match its file name")
        tasks.append(task)
    return tasks


def load_documents(tree: SourceTree) -> dict[str, dict[str, str]]:
    documents = {}
    for path in tree.listing(upstream.BANKING_DOCUMENTS_DIR):
        if not path.endswith(".json"):
            raise ManifestError(f"unexpected non-JSON document file {path}")
        document = tree.json(path)
        if set(document) != DOCUMENT_KEYS or not all(isinstance(document[key], str) for key in DOCUMENT_KEYS):
            raise ManifestError(f"{stem(path)}: document is not exactly {{id, title, content}} strings")
        if document["id"] != stem(path):
            raise ManifestError(f"{stem(path)}: document id differs from its file stem")
        documents[stem(path)] = document
    return documents


def labels(tasks: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    result = {}
    for task in tasks:
        required = task.get("required_documents")
        if not isinstance(required, list) or not required or not all(isinstance(item, str) for item in required):
            raise ManifestError(f"{task['id']}: required_documents must be a non-empty list of IDs")
        if len(set(required)) != len(required):
            raise ManifestError(f"{task['id']}: duplicate required document IDs")
        result[str(task["id"])] = list(required)
    return result


def label_statistics(required: Mapping[str, Sequence[str]], stems: set[str]) -> dict[str, Any]:
    counts = [len(ids) for ids in required.values()]
    distinct = set().union(*map(set, required.values())) if required else set()
    frequency = Counter(doc for ids in required.values() for doc in ids)
    top = frequency.most_common(1)[0] if frequency else ("", 0)
    return {
        "tasks": len(required),
        "distinct_required_ids": len(distinct),
        "unmatched_ids": sorted(distinct - stems),
        "required_per_task": {"min": min(counts, default=0), "max": max(counts, default=0),
                              "mean": round(statistics.mean(counts), 4) if counts else 0.0,
                              "median": statistics.median(counts) if counts else 0},
        "tasks_requiring_more_than_5": sum(count > 5 for count in counts),
        "most_frequent_document": {"id": top[0], "tasks": top[1]},
    }


def compare_aggregate(canonical: Sequence[Mapping[str, Any]], aggregate: Sequence[Mapping[str, Any]],
                      stems: set[str]) -> dict[str, Any]:
    by_id = {str(task["id"]): task for task in aggregate}
    if [str(task["id"]) for task in aggregate] != [str(task["id"]) for task in canonical]:
        raise ManifestError("tasks.json and tasks/ list different task IDs")
    differing = {}
    for task in canonical:
        other = by_id[str(task["id"])]
        fields = sorted(key for key in set(task) | set(other) if task.get(key) != other.get(key))
        if fields:
            differing[str(task["id"])] = fields
    canonical_ids = set().union(*(set(ids) for ids in labels(canonical).values()))
    aggregate_ids = set().union(*(set(ids) for ids in labels(aggregate).values()))
    return {
        "path": upstream.BANKING_TASKS_AGGREGATE,
        "read_by_upstream_code": False,
        "tasks_differing": len(differing),
        "differing_fields": dict(sorted(differing.items())),
        "required_documents_differ_for": sorted(task for task, fields in differing.items()
                                                if "required_documents" in fields),
        "aggregate_label_statistics": label_statistics(labels(aggregate), stems),
        "ids_only_in_canonical": sorted(canonical_ids - aggregate_ids),
        "ids_only_in_aggregate": sorted(aggregate_ids - canonical_ids),
    }


def group_tasks(tasks: Sequence[Mapping[str, Any]]) -> list[list[str]]:
    ids = [str(task["id"]) for task in tasks]
    required = {task_id: set(docs) for task_id, docs in labels(tasks).items()}
    text = {str(task["id"]): shingles(str(task["user_scenario"]["instructions"])) for task in tasks}
    parent = {task_id: task_id for task_id in ids}

    def find(task_id: str) -> str:
        while parent[task_id] != task_id:
            parent[task_id] = parent[parent[task_id]]
            task_id = parent[task_id]
        return task_id

    for index, left in enumerate(ids):
        for right in ids[index + 1:]:
            if (jaccard(required[left], required[right]) >= LABEL_JACCARD
                    or jaccard(text[left], text[right]) >= SCENARIO_JACCARD):
                a, b = sorted((find(left), find(right)))
                parent[b] = a
    groups: dict[str, list[str]] = {}
    for task_id in ids:
        groups.setdefault(find(task_id), []).append(task_id)
    return sorted((sorted(members) for members in groups.values()), key=lambda members: members[0])


def assign_groups(groups: Sequence[Sequence[str]], *, seed: int = SEED,
                  fraction: float = DEV_FRACTION) -> dict[str, str]:
    total = sum(len(group) for group in groups)
    target = round(fraction * total)
    order = sorted(groups, key=lambda group: hashlib.sha256(
        f"{seed}|banking_knowledge|{group[0]}".encode()).hexdigest())
    assignment, dev = {}, 0
    for group in order:
        side = "dev" if dev + len(group) <= target else "test"
        dev += len(group) if side == "dev" else 0
        assignment[group[0]] = side
    return assignment


def _split_profile(task_ids: Sequence[str], tasks: Mapping[str, Mapping[str, Any]],
                   required: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    counts = [len(required[task_id]) for task_id in task_ids]
    return {
        "tasks": len(task_ids),
        "distinct_required_ids": len(set().union(*(set(required[task_id]) for task_id in task_ids))),
        "required_per_task_mean": round(statistics.mean(counts), 4),
        "required_per_task_max": max(counts),
        "tasks_requiring_more_than_5": sum(count > 5 for count in counts),
        "reward_basis": {"+".join(basis): count for basis, count in sorted(Counter(
            tuple(tasks[task_id]["evaluation_criteria"]["reward_basis"]) for task_id in task_ids).items())},
        "tasks_with_user_tools": sum(bool(tasks[task_id].get("user_tools")) for task_id in task_ids),
    }


def build_banking_split(tree: SourceTree) -> dict[str, Any]:
    tasks = load_tasks(tree)
    documents = load_documents(tree)
    stems = set(documents)
    required = labels(tasks)
    statistics_ = label_statistics(required, stems)
    if statistics_["unmatched_ids"]:
        raise ManifestError(f"{len(statistics_['unmatched_ids'])} required IDs have no document file")
    frame = [str(task["id"]) for task in tasks]
    census = tree.json(upstream.BANKING_97)
    if census["task_ids"] != frame or census["frame"]["digest"] != id_list_digest(frame):
        raise ManifestError("banking_knowledge_97 census disagrees with the tasks/ directory")
    groups = group_tasks(tasks)
    assignment = assign_groups(groups)
    by_id = {str(task["id"]): task for task in tasks}
    split_ids = {side: [task_id for group in groups if assignment[group[0]] == side for task_id in group]
                 for side in ("dev", "test")}
    for side in split_ids:
        split_ids[side].sort(key=frame.index)
    dev_docs = set().union(*(set(required[task_id]) for task_id in split_ids["dev"]))
    test_docs = set().union(*(set(required[task_id]) for task_id in split_ids["test"]))
    sizes = Counter(len(group) for group in groups)
    return {
        "schema": SPLIT_SCHEMA,
        "domain": "banking_knowledge",
        "source": {
            "commit": upstream.COMMIT,
            "canonical_tasks": upstream.BANKING_TASKS_DIR + "/task_*.json (upstream get_tasks loader)",
            "task_files_sha256": id_list_digest(tree.sha256(path) for path in tree.listing(upstream.BANKING_TASKS_DIR)),
            "document_files_sha256": id_list_digest(
                tree.sha256(path) for path in tree.listing(upstream.BANKING_DOCUMENTS_DIR)),
            "census_sha256": tree.sha256(upstream.BANKING_97),
        },
        "labels": {
            "kind": "task-level required document IDs for the whole multi-turn trajectory; not per-turn "
                    "or per-chunk relevance",
            "eligible_tasks": len(frame),
            "document_files": len(stems),
            "document_id_equals_file_stem": len(stems),
            **statistics_,
        },
        "aggregate_tasks_json": compare_aggregate(tasks, tree.json(upstream.BANKING_TASKS_AGGREGATE), stems),
        "frame": {"size": len(frame), "digest": id_list_digest(frame), "order": "sorted task file names",
                  "task_ids": frame},
        "grouping": {
            "label_jaccard_threshold": LABEL_JACCARD, "scenario_5gram_jaccard_threshold": SCENARIO_JACCARD,
            "groups": len(groups), "group_sizes": {str(size): count for size, count in sorted(sizes.items())},
            "members": [{"group": group[0], "split": assignment[group[0]], "task_ids": group} for group in groups],
        },
        "assignment": {"seed": SEED, "dev_fraction": DEV_FRACTION, "target_dev_tasks": round(DEV_FRACTION * len(frame)),
                       "method": "groups ordered by sha256('<seed>|banking_knowledge|<group id>'); a group joins "
                                 "dev while the dev task count stays <= target"},
        "splits": {
            side: {
                "count": len(ids), "groups": sum(assignment[group[0]] == side for group in groups),
                "digest": id_list_digest(ids),
                "use": "retrieval development and tuning" if side == "dev"
                       else "held-out retrieval evaluation; untouched for tuning",
                "task_ids": ids,
                "profile": _split_profile(ids, by_id, required),
            }
            for side, ids in split_ids.items()
        },
        "document_overlap": {
            "required_by_dev_only": len(dev_docs - test_docs),
            "required_by_test_only": len(test_docs - dev_docs),
            "required_by_both": len(dev_docs & test_docs),
            "never_required": len(stems - dev_docs - test_docs),
            "note": "the corpus is shared by design; labels and answers are not",
        },
    }


# -- dev-only label access (T15a) -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class DevLabels:
    """Task-level required-document stems of the DEV split only, with each task's heuristic group.

    Built by `dev_labels`, which selects the dev task IDs from the reviewed split manifest first and then opens and
    verifies exactly those task files (pinned SHA-256 from the source manifest). No test or aggregate payload is read,
    and nothing but `id` and `required_documents` is kept from a task: these are evaluator-side labels and never cross
    into the application runtime, prompts or records."""

    labels: Mapping[str, tuple[str, ...]]
    groups: Mapping[str, str]
    split_digest: str

    def digest(self) -> str:
        body = {"labels": {t: list(self.labels[t]) for t in sorted(self.labels)},
                "groups": {t: self.groups[t] for t in sorted(self.groups)}, "split_digest": self.split_digest}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def dev_labels(acquired_root: Path, split_manifest: Mapping[str, Any],
               source_manifest: Mapping[str, Any]) -> DevLabels:
    """Dev labels from a materialized pinned tree (the caller validated both committed manifests)."""
    dev = split_manifest["splits"]["dev"]
    task_ids = [str(t) for t in dev["task_ids"]]
    if id_list_digest(task_ids) != dev["digest"] or len(task_ids) != dev["count"]:
        raise ManifestError("the dev task list does not match its recorded digest and count")
    test_ids = {str(t) for t in split_manifest["splits"]["test"]["task_ids"]}
    if test_ids & set(task_ids):
        raise ManifestError("the dev and test splits overlap")
    pinned = {item["path"]: item["sha256"] for item in source_manifest["consumed"]}
    labelled: dict[str, tuple[str, ...]] = {}
    for task_id in task_ids:  # the split was chosen before any task file is opened
        path = f"{upstream.BANKING_TASKS_DIR}/{task_id}.json"
        expected = pinned.get(path)
        if expected is None:
            raise ManifestError(f"{path} is outside the pinned consumed scope")
        data = safe_target(acquired_root, path).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ManifestError(f"{path} does not match its pinned SHA-256")
        task = json.loads(data.decode("utf-8"))
        if task.get("id") != task_id:
            raise ManifestError(f"{path}: task id does not match its file name")
        labelled[task_id] = tuple(sorted(labels([task])[task_id]))
        del task, data
    groups: dict[str, str] = {}
    for member in split_manifest["grouping"]["members"]:
        if member["split"] == "dev":
            for task_id in member["task_ids"]:
                groups[str(task_id)] = str(member["group"])
    if set(groups) != set(labelled):
        raise ManifestError("every dev task belongs to exactly one dev group")
    return DevLabels(labelled, groups, dev["digest"])
