"""Checks that run pinned upstream code against the verified materialized data.

Importing tau2 has side effects (python-dotenv at import, litellm pricing map),
so `prepare` force-sets PYTHON_DOTENV_DISABLED=1 and
LITELLM_LOCAL_MODEL_COST_MAP=True and points TAU2_DATA_DIR at the verified tree
before the first tau2 import. No model, simulator or judge is called.

Every comparison fails closed: a reproduced draw, loader label, binding revision
or installed-file hash that disagrees raises instead of returning a false flag.
Reference-action replay runs only for dev retail tasks (SplitGuard enforces it);
held-out reference actions are never executed here. Replay errors are recorded
as audit findings, not failures.
"""

from __future__ import annotations

import base64
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import sys
from typing import Any

from policyops_evals import banking, upstream
from policyops_evals.canonical import ManifestError, id_list_digest, sha256_bytes
from policyops_evals.projection import Purpose, SplitGuard
from policyops_evals.sources import SourceTree


SCHEMA = "policyops.upstream-verification/v1"


def prepare(tree_root: Path) -> None:
    # Upstream loaders call open() without an encoding; outside UTF-8 mode a
    # non-UTF-8 locale (e.g. GBK on Windows) makes get_tasks skip task_100 with
    # only a warning. Refuse to run rather than verify a silently smaller frame.
    if not sys.flags.utf8_mode:
        raise ManifestError("upstream checks require Python UTF-8 mode (PYTHONUTF8=1; set by scripts/devenv.py)")
    data_root = (tree_root / "data").resolve()
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    os.environ["TAU2_DATA_DIR"] = str(data_root)
    loaded = sys.modules.get("tau2.utils.utils")
    if loaded is not None and Path(loaded.DATA_DIR).resolve() != data_root:
        raise ManifestError("tau2 was already imported with a different data directory")


def record_sha256(value: str) -> str:
    """Hex SHA-256 from a wheel RECORD entry (urlsafe base64 without padding)."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).hex()


def package_parity(installed: Iterable[tuple[str, str | None, str]], tree_files: Mapping[str, str]) -> dict[str, Any]:
    """installed yields (package-relative path, RECORD sha256 or None, sha256 of the actual installed bytes).

    Every installed file must hash to its RECORD entry and to the blob at
    src/<path> in the pinned commit; any difference raises.
    """
    matched = 0
    problems: list[str] = []
    for path, recorded, actual in installed:
        expected = tree_files.get(f"src/{path}")
        if recorded is None:
            problems.append(f"{path}: no RECORD hash")
        elif actual != recorded:
            problems.append(f"{path}: installed bytes differ from RECORD")
        elif expected is None:
            problems.append(f"{path}: not present in the pinned commit")
        elif expected != actual:
            problems.append(f"{path}: installed bytes differ from the pinned commit")
        else:
            matched += 1
    if problems:
        raise ManifestError(f"installed tau2 differs from the pinned commit ({len(problems)}): {problems[:5]}")
    if matched == 0:
        raise ManifestError("no installed tau2 files were compared")
    return {"installed_files_hashed": matched, "all_match_record_and_commit": True}


def installed_package_parity(tree_files: Mapping[str, str], root_license: bytes) -> dict[str, Any]:
    distribution = metadata.distribution("tau2")
    files = [file for file in distribution.files or [] if file.as_posix().startswith("tau2/")]

    def entries() -> Iterator[tuple[str, str | None, str]]:
        for file in files:
            recorded = record_sha256(file.hash.value) if file.hash and file.hash.mode == "sha256" else None
            yield file.as_posix(), recorded, sha256_bytes(Path(str(file.locate())).read_bytes())

    parity = package_parity(entries(), tree_files)
    installed = {f"src/{file.as_posix()}" for file in files}
    license_file = next((file for file in distribution.files or [] if file.as_posix().endswith("licenses/LICENSE")),
                        None)
    dist_license = Path(str(license_file.locate())).read_bytes() if license_file else b""
    direct_url = json.loads(distribution.read_text("direct_url.json") or "{}")
    if direct_url.get("vcs_info", {}).get("commit_id") != upstream.COMMIT:
        raise ManifestError("installed tau2 direct_url.json does not name the pinned commit")
    return {
        "distribution": f"tau2 {distribution.version}",
        "direct_url_commit": direct_url["vcs_info"]["commit_id"],
        **parity,
        "commit_src_tau2_files_not_installed": sum(
            1 for path in tree_files if path.startswith("src/tau2/") and path not in installed),
        "dist_info_license_sha256": sha256_bytes(dist_license),
        "dist_info_license_text_equals_root_license_ignoring_line_endings":
            dist_license.replace(b"\r\n", b"\n").strip() == root_license.replace(b"\r\n", b"\n").strip(),
        "assurance": "SHA-256 of every installed tau2/ file's actual bytes equals its RECORD entry and the pinned "
                     "commit's src/tau2/ blob; benchmark data is not part of the wheel",
    }


def labels_digest(labels: Mapping[str, Sequence[str]]) -> str:
    return id_list_digest(f"{task}\t{chr(31).join(ids)}" for task, ids in labels.items())


def compare_labels(loader: Mapping[str, Sequence[str]], source: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    """Exact per-task, ordered equality of required_documents; raises on any difference."""
    if list(loader) != list(source):
        raise ManifestError("upstream loader and verified source list different banking tasks or orders")
    differing = [task for task in source if list(loader[task]) != list(source[task])]
    if differing:
        raise ManifestError(f"upstream loader labels differ for {len(differing)} tasks: {differing[:5]}")
    return {"tasks": len(source), "per_task_ordered_equal": True, "labels_digest": labels_digest(source)}


def _hash(value: str | None) -> str | None:
    return None if value is None else hashlib.sha256(value.encode()).hexdigest()[:16]


def replay_dev_reference_actions(guard: SplitGuard, dev_ids: list[str]) -> dict[str, Any]:
    from tau2.registry import registry

    constructor = registry.get_env_constructor("retail")
    tasks = {task.id: task for task in registry.get_tasks_loader("retail")(task_split_name="base")}

    def replay(task: Any) -> tuple[str | None, list[tuple[str, str]]]:
        environment = constructor()
        environment.set_state(initialization_data=None, initialization_actions=None, message_history=[])
        errors = []
        for action in task.evaluation_criteria.actions or []:
            try:
                environment.make_tool_call(tool_name=action.name, requestor=action.requestor, **action.arguments)
            except Exception as exc:  # upstream's gold replay also catches every exception
                errors.append((action.name, type(exc).__name__))
        return environment.get_db_hash(), errors

    baseline = constructor()
    baseline.set_state(initialization_data=None, initialization_actions=None, message_history=[])
    initial_hash = baseline.get_db_hash()
    results, error_classes = [], Counter[str]()
    for task_id in dev_ids:
        guard.require("retail", task_id, Purpose.DEV_EVALUATION)
        first, errors = replay(tasks[task_id])
        second, _ = replay(tasks[task_id])
        error_classes.update(f"{name}:{kind}" for name, kind in errors)
        results.append({
            "task_id": task_id, "actions": len(tasks[task_id].evaluation_criteria.actions or []),
            "errors": len(errors), "db_changed": first != initial_hash, "deterministic": first == second,
            "final_db_hash_prefix": _hash(first),
        })
    return {
        "scope": "dev retail tasks only; upstream registry tasks; fresh environment per replay; each replayed twice",
        "determinism": "equality of the final database hash across the two replays only; tool outputs and error "
                       "sequences are not compared",
        "tasks": len(results),
        "tasks_with_action_errors": [item["task_id"] for item in results if item["errors"]],
        "action_error_classes": dict(sorted(error_classes.items())),
        "tasks_without_db_change": [item["task_id"] for item in results if not item["db_changed"]],
        "nondeterministic_tasks": [item["task_id"] for item in results if not item["deterministic"]],
        "per_task": results,
    }


def build_upstream_verification(tree: SourceTree, tree_files: Mapping[str, str],
                                retail_split: Mapping[str, Any], banking_split: Mapping[str, Any]) -> dict[str, Any]:
    prepare(tree.root)
    from tau2.runner.presets import binding_revision, load_cell_language
    from tau2.task_subsets.store import load_frame, load_subset, verify_subset

    retail_frame = load_frame("retail", "base")
    banking_frame = load_frame("banking_knowledge", "base")
    if retail_frame.task_ids != retail_split["frame"]["task_ids"]:
        raise ManifestError("upstream retail loader order differs from the split frame")
    if banking_frame.task_ids != banking_split["frame"]["task_ids"]:
        raise ManifestError("upstream banking loader order differs from the split frame")
    retail_check = verify_subset(load_subset("retail_50"), frame=retail_frame)
    banking_check = verify_subset(load_subset("banking_knowledge_97"), frame=banking_frame)
    loader_labels = {task.id: list(task.required_documents or []) for task in banking_frame.tasks}
    labels = compare_labels(loader_labels, banking.labels(banking.load_tasks(tree)))
    loaded = load_cell_language("en", "retail", "text")
    english_binding = binding_revision(loaded)
    if english_binding != upstream.RETAIL_EN_TEXT_BINDING:
        raise ManifestError(f"recomputed English retail binding {english_binding} differs from the pin")
    guard = SplitGuard({"retail": retail_split, "banking_knowledge": banking_split})
    return {
        "schema": SCHEMA,
        "commit": upstream.COMMIT,
        "draws": {
            name: {"reproduced_by": "tau2.task_subsets.store.verify_subset (raises on any drift)",
                   "frame_size": check.frame_size, "selected": check.selected_size, "frame_digest": check.frame_digest}
            for name, check in (("retail_50", retail_check), ("banking_knowledge_97", banking_check))
        },
        "banking_loader_labels": {
            "loader": "tau2.task_subsets.store.load_frame('banking_knowledge') -> registry tasks loader",
            "compared_with": "required_documents parsed from SourceTree-verified tasks/ files",
            **labels,
        },
        "english_retail_text_binding": {
            "recomputed_by": "tau2.runner.presets.binding_revision(load_cell_language('en', 'retail', 'text'))",
            "binding_revision": english_binding,
        },
        "installed_package": installed_package_parity(tree_files, tree.read(upstream.LICENSE)),
        "dev_reference_replay": replay_dev_reference_actions(guard, list(retail_split["splits"]["dev"]["task_ids"])),
    }
