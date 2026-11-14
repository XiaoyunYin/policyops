"""Frozen E03 holdout configuration and offline admission contract."""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
from typing import Any

from policyops_evals import upstream
from policyops_evals.build import RETAIL_SPLIT, default_manifest_dir
from policyops_evals.canonical import canonical_bytes, load_manifest, sha256_bytes
from policyops_evals.retail_sim import fixture
from policyops_evals.studies import registration
from policyops_evals.studies.config import StudyV3, load_study, preflight

from .t32_support import SOURCE


ROOT = Path(__file__).parents[1]
V6 = ROOT / "studies/e03-dev-luna-haiku-v6.json"
HOLDOUT = ROOT / "studies/e03-holdout-luna-haiku-v1.json"


def _holdout() -> StudyV3:
    study = load_study(HOLDOUT)
    assert isinstance(study, StudyV3)
    return study


def _changes(before: Any, after: Any, prefix: str = "") -> set[str]:
    if isinstance(before, dict) and isinstance(after, dict):
        paths: set[str] = set()
        for key in before.keys() | after.keys():
            path = f"{prefix}.{key}" if prefix else key
            if key not in before or key not in after:
                paths.add(path)
            else:
                paths.update(_changes(before[key], after[key], path))
        return paths
    if isinstance(before, list) and isinstance(after, list):
        if prefix == "variants" and len(before) == len(after):
            return set().union(*(_changes(left, right, f"{prefix}[{i}]")
                                 for i, (left, right) in enumerate(zip(before, after, strict=True))))
        return set() if before == after else {prefix}
    return set() if before == after else {prefix}


def test_holdout_config_is_v6_protocol_with_only_prespecified_changes() -> None:
    dev = load_study(V6)
    study = _holdout()
    study.validate_data()

    split = load_manifest(default_manifest_dir() / RETAIL_SPLIT)["splits"]["holdout"]
    assert list(study.tasks) == split["task_ids"]
    assert len(study.tasks) == 50
    assert list(study.seeds) == [20261116, 20261117, 20261118, 20261119]

    old = dev.model_dump(mode="json")
    new = study.model_dump(mode="json")
    permitted = {
        "study_key", "purpose", "split_id", "tasks", "task_list_sha256", "seeds",
        "pairing.order_seed", "statistics.bootstrap_seed", "preregistration_sha256", "notes",
        "variants[0].actors.simulator.logical_calls", "variants[0].actors.simulator.planning_input",
        "variants[0].actors.simulator.planning_output", "variants[1].actors.simulator.logical_calls",
        "variants[1].actors.simulator.planning_input", "variants[1].actors.simulator.planning_output",
        "limits.study_usd", "limits.invocation_usd", "limits.study_calls", "limits.study_counts",
        "limits.invocation_calls", "limits.invocation_counts", "limits.study_input_tokens",
        "limits.study_output_tokens",
    }
    assert _changes(old, new) == permitted
    assert study.purpose == study.split_id == "holdout"
    assert study.pairing.order_seed == study.statistics.bootstrap_seed == 20261116
    for variant in study.variants:
        assert variant.actors.simulator.logical_calls == 16
        assert variant.actors.simulator.planning_input == 80000
        assert variant.actors.simulator.planning_output == 2667


def test_holdout_strata_preflight_and_registration_payload_are_offline() -> None:
    study = _holdout()
    # Same source as the retail-simulator tests: an explicit tree, else the checkout `uv sync` materialized (CI).
    explicit = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
    tree = Path(explicit) if explicit else fixture.find_reviewed_tree(Path(os.environ.get("UV_CACHE_DIR", "")))
    assert tree is not None, "no verified tau2 checkout: run through scripts/devenv.py after `uv sync`"
    rows = json.loads((tree / upstream.RETAIL_TASKS).read_bytes())
    selected = [row for row in rows if row["id"] in study.tasks]
    assert {row["id"] for row in selected} == set(study.tasks)
    strata = Counter("db_nl" if row.get("evaluation_criteria", {}).get("nl_assertions") else "db_only"
                     for row in selected)
    assert strata == {"db_only": 34, "db_nl": 16}

    plan = preflight(study)
    assert plan["scheduled_slots"] == 400
    assert plan["within_caps"] is True
    assert plan["authorizes_paid_execution"] is False
    assert plan["inference_ceiling"] == plan["count_ceiling"] == 19600
    assert plan["planning_estimate_usd"] == "10.0534000"
    assert plan["admission_ceiling_usd"] == "71.91040000"
    assert plan["study_cap_usd"] == "75"

    payload = registration.registration_payload(study, SOURCE)
    digest = sha256_bytes(canonical_bytes(payload))
    assert len(digest) == 64
    assert set(payload["source"]) == {"source_head", "dirty_sha256", "lock_sha256"}
