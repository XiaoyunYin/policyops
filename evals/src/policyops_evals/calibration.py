"""Retail dev calibration allowlist and metadata-only demo seeds (T04).

Derived only from committed, self-verified T03 manifests; no task payload is
read. The official 64-dev / 50-holdout split is unchanged: this narrows which
dev tasks may serve demos, smoke runs and tuning.

Exclusions (each sourced from a manifest field whose manifest digest is recorded):
  near_holdout_scenario   nearest held-out scenario Jaccard >= 0.7 (retail-audit)
  open_upstream_issue     upstream issue annotation with status "open" on the dev task (retail-audit)
  reference_action_error  a reference action raised during dev replay (upstream-verification)

Tags on allowed tasks (from the dev replay): `mutation` when the reference
actions changed the database without errors and deterministically, `read_only`
when they changed nothing. Seeds carry only a neutral label ("Retail demo <id>")
and the tag; tags and seeds are operator/server metadata and never enter the
runtime task view. Customer bindings are produced separately (seed-bindings) and
are not public.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from policyops_contracts.seeds import DemoSeed
from policyops_evals import upstream
from policyops_evals.build import RETAIL_AUDIT, RETAIL_SPLIT, UPSTREAM
from policyops_evals.canonical import SELF_DIGEST, ManifestError, id_list_digest


SCHEMA = "policyops.retail-calibration/v1"
CALIBRATION = "retail-calibration.json"
NEAR_THRESHOLD = 0.7


def build_calibration(manifests: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    split, audit, verified = manifests[RETAIL_SPLIT], manifests[RETAIL_AUDIT], manifests[UPSTREAM]
    dev = list(split["splits"]["dev"]["task_ids"])
    holdout = set(split["splits"]["holdout"]["task_ids"])
    replay = {item["task_id"]: item for item in verified["dev_reference_replay"]["per_task"]}
    if list(replay) != dev:
        raise ManifestError("dev replay does not cover exactly the dev frame")
    similarity = audit["dev_holdout_scenario_similarity"]
    reasons: dict[str, set[str]] = {}
    for pair in similarity["pairs_at_or_above_0.7"]:
        if pair["jaccard"] < NEAR_THRESHOLD or pair["holdout"] not in holdout:
            raise ManifestError("near-holdout pair is inconsistent with the split")
        reasons.setdefault(pair["dev"], set()).add("near_holdout_scenario")
    for issue in audit["upstream_issue_annotations"]:
        if issue["split"] == "dev" and issue["status"] == "open":
            reasons.setdefault(issue["task_id"], set()).add("open_upstream_issue")
    for task_id in verified["dev_reference_replay"]["tasks_with_action_errors"]:
        reasons.setdefault(task_id, set()).add("reference_action_error")
    if not set(reasons) <= set(dev):
        raise ManifestError("an exclusion names a task outside the dev frame")
    allowed = [task_id for task_id in dev if task_id not in reasons]
    allowlist_digest = id_list_digest(allowed)
    tags: dict[str, str] = {}
    for task_id in allowed:
        item = replay[task_id]
        if not item["deterministic"]:
            raise ManifestError(f"dev task {task_id} replay is not deterministic")
        if item["db_changed"] and item["errors"] == 0:
            tags[task_id] = "mutation"
        elif not item["db_changed"]:
            tags[task_id] = "read_only"
        else:  # pragma: no cover - errored tasks are excluded above
            raise ManifestError(f"dev task {task_id} has an unexpected replay outcome")
    seeds = [DemoSeed(seed_id=f"retail-demo-{task_id}", label=f"Retail demo {task_id}", domain="retail",
                      upstream_task_id=task_id, kind="mutation" if tags[task_id] == "mutation" else "read_only",
                      allowlist_sha256=allowlist_digest).model_dump(mode="json") for task_id in allowed]
    return {
        "schema": SCHEMA,
        "commit": upstream.COMMIT,
        "sources": {name: manifests[name][SELF_DIGEST] for name in (RETAIL_SPLIT, RETAIL_AUDIT, UPSTREAM)},
        "official_split_unchanged": {"dev": len(dev), "holdout": len(holdout),
                                     "dev_digest": split["splits"]["dev"]["digest"]},
        "exclusion_rules": {
            "near_holdout_scenario": f"{RETAIL_AUDIT}: dev_holdout_scenario_similarity.pairs_at_or_above_0.7 "
                                     f"(nearest held-out scenario Jaccard >= {NEAR_THRESHOLD})",
            "open_upstream_issue": f"{RETAIL_AUDIT}: upstream_issue_annotations with split dev and status open",
            "reference_action_error": f"{UPSTREAM}: dev_reference_replay.tasks_with_action_errors",
        },
        "excluded": [{"task_id": task_id, "reasons": sorted(reasons[task_id])}
                     for task_id in dev if task_id in reasons],
        "allowlist": {"count": len(allowed), "digest": allowlist_digest, "order": "dev frame order",
                      "task_ids": allowed},
        "tags": {
            "mutation": [task_id for task_id in allowed if tags[task_id] == "mutation"],
            "read_only": [task_id for task_id in allowed if tags[task_id] == "read_only"],
            "basis": f"{UPSTREAM}: dev_reference_replay.per_task (db_changed, errors, deterministic)",
        },
        "seeds": seeds,
        "visibility": "operator/server metadata; tags, seeds and bindings never enter the runtime task view",
    }


def validate_calibration(calibration: Mapping[str, Any], manifests: Mapping[str, Mapping[str, Any]]) -> None:
    expected = build_calibration(manifests)
    body = {key: value for key, value in calibration.items() if key != SELF_DIGEST}
    if body != expected:
        raise ManifestError("retail calibration does not match a rebuild from the committed T03 manifests")
    for seed in calibration["seeds"]:
        DemoSeed.model_validate(seed)
