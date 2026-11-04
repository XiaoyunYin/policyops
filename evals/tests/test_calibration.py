"""Retail calibration allowlist, metadata-only seeds, projection canaries and policy tracing (T04)."""

from collections.abc import Iterator, Mapping
import copy
import hashlib
import json
import re
from typing import Any

from pydantic import ValidationError
import pytest

from policyops_contracts.policy import RETAIL_POLICY, PolicyRef, PolicyRule
from policyops_contracts.seeds import DemoSeed
from policyops_evals import policy_trace
from policyops_evals.build import RETAIL_AUDIT, RETAIL_SPLIT, UPSTREAM, default_manifest_dir, load_committed
from policyops_evals.calibration import CALIBRATION, build_calibration, validate_calibration
from policyops_evals.canonical import ManifestError, load_manifest, with_self_digest
from policyops_evals.projection import Purpose, RuntimeTaskView, SplitGuard, project_task


EXCLUDED = ["2", "3", "4", "5", "7", "10", "12", "31", "35", "37", "46", "54", "55", "62", "67", "72", "82", "101"]


@pytest.fixture(scope="module")
def committed() -> dict[str, dict[str, Any]]:
    return load_committed(default_manifest_dir())


@pytest.fixture(scope="module")
def calibration() -> dict[str, Any]:
    return load_manifest(default_manifest_dir() / CALIBRATION)


def test_committed_calibration_rebuilds_from_t03_manifests(committed: dict[str, dict[str, Any]],
                                                           calibration: dict[str, Any]) -> None:
    validate_calibration(calibration, committed)
    assert calibration["sources"] == {name: committed[name]["manifest_sha256"]
                                      for name in (RETAIL_SPLIT, RETAIL_AUDIT, UPSTREAM)}


def test_allowlist_is_the_dev_frame_minus_the_sourced_exclusions(committed: dict[str, dict[str, Any]],
                                                                 calibration: dict[str, Any]) -> None:
    dev = committed[RETAIL_SPLIT]["splits"]["dev"]["task_ids"]
    holdout = set(committed[RETAIL_SPLIT]["splits"]["holdout"]["task_ids"])
    excluded = [item["task_id"] for item in calibration["excluded"]]
    allowed = calibration["allowlist"]["task_ids"]
    assert excluded == EXCLUDED and len(allowed) == 46 and len(dev) == 64
    assert allowed == [task_id for task_id in dev if task_id not in set(excluded)]
    assert not set(allowed) & holdout and calibration["official_split_unchanged"]["holdout"] == 50
    reasons = {item["task_id"]: set(item["reasons"]) for item in calibration["excluded"]}
    assert reasons["4"] == {"open_upstream_issue", "reference_action_error"}
    assert reasons["5"] == reasons["7"] == {"near_holdout_scenario", "open_upstream_issue"}
    assert calibration["tags"]["read_only"] == ["24", "57"] and len(calibration["tags"]["mutation"]) == 44
    replay = {item["task_id"]: item for item in committed[UPSTREAM]["dev_reference_replay"]["per_task"]}
    for task_id in calibration["tags"]["mutation"]:
        assert replay[task_id]["db_changed"] and replay[task_id]["errors"] == 0 and replay[task_id]["deterministic"]


def test_seeds_are_neutral_dev_only_metadata(committed: dict[str, dict[str, Any]], calibration: dict[str, Any]) -> None:
    guard = SplitGuard({"retail": committed[RETAIL_SPLIT], "banking_knowledge": committed["banking-split.json"]})
    kinds = {task_id: kind for kind in ("mutation", "read_only") for task_id in calibration["tags"][kind]}
    for raw in calibration["seeds"]:
        seed = DemoSeed.model_validate(raw)
        assert set(raw) == {"seed_id", "label", "domain", "upstream_task_id", "kind", "allowlist_sha256"}
        assert seed.label == f"Retail demo {seed.upstream_task_id}" and seed.kind == kinds[seed.upstream_task_id]
        assert seed.allowlist_sha256 == calibration["allowlist"]["digest"]
        assert guard.require("retail", seed.upstream_task_id, Purpose.DEMO) == "dev"
    text = (default_manifest_dir() / CALIBRATION).read_text(encoding="utf-8")
    assert '"user_id"' not in text and not re.search(r"\b[a-z]+_[a-z]+_\d{1,6}\b", text)


@pytest.mark.parametrize("label", ["Retail demo: return delivered items", "Exchange demo 0", "Retail demo 1"])
def test_seed_labels_cannot_carry_intent(label: str) -> None:
    with pytest.raises(ValidationError):
        DemoSeed(seed_id="retail-demo-0", label=label, domain="retail", upstream_task_id="0", kind="mutation",
                 allowlist_sha256="0" * 64)


def _resealed(manifests: Mapping[str, dict[str, Any]], name: str, edit: Any) -> dict[str, dict[str, Any]]:
    changed = copy.deepcopy(dict(manifests))
    edit(changed[name])
    changed[name] = with_self_digest(changed[name])
    return changed


def test_only_open_issue_annotations_exclude(committed: dict[str, dict[str, Any]]) -> None:
    def close_issues(audit: dict[str, Any]) -> None:
        for issue in audit["upstream_issue_annotations"]:
            issue["status"] = "closed"

    rebuilt = build_calibration(_resealed(committed, RETAIL_AUDIT, close_issues))
    reasons = {item["task_id"]: item["reasons"] for item in rebuilt["excluded"]}
    assert reasons["5"] == reasons["7"] == ["near_holdout_scenario"]
    assert reasons["4"] == ["reference_action_error"]
    assert rebuilt["allowlist"]["task_ids"] == build_calibration(committed)["allowlist"]["task_ids"]


def test_calibration_tampering_and_source_drift_are_detected(committed: dict[str, dict[str, Any]],
                                                             calibration: dict[str, Any]) -> None:
    holdout_id = committed[RETAIL_SPLIT]["splits"]["holdout"]["task_ids"][0]
    forged = copy.deepcopy(calibration)
    forged["allowlist"]["task_ids"].append(holdout_id)
    with pytest.raises(ManifestError):
        validate_calibration(forged, committed)
    relabelled = copy.deepcopy(calibration)
    relabelled["seeds"][0]["kind"] = "read_only"
    with pytest.raises(ManifestError):
        validate_calibration(relabelled, committed)
    drifted = _resealed(committed, RETAIL_AUDIT, lambda audit: audit["upstream_issue_annotations"].clear())
    with pytest.raises(ManifestError):
        validate_calibration(calibration, drifted)
    rebuilt = build_calibration(drifted)
    # Tasks 4, 5 and 7 also have a second exclusion reason, so only their reasons change.
    assert len(rebuilt["allowlist"]["task_ids"]) == 46
    assert {item["task_id"]: item["reasons"] for item in rebuilt["excluded"]}["7"] == ["near_holdout_scenario"]


class SeedPoisonTask(Mapping[str, Any]):
    """A task record carrying seed metadata and hidden fields; projection may read only id and initial_state."""

    def __init__(self, task_id: str) -> None:
        self._data = {"id": task_id, "initial_state": None}
        self._poison = {"kind", "seed_label", "customer_binding", "user_id", "evaluation_criteria", "user_scenario"}

    def __getitem__(self, key: str) -> Any:
        if key in self._poison:
            raise AssertionError(f"projection read {key}")
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("projection iterated the record")

    def __len__(self) -> int:
        raise AssertionError("projection sized the record")

    def __contains__(self, key: object) -> bool:
        return key in self._data or key in self._poison


def test_seed_tags_and_bindings_never_reach_the_runtime_task_view(committed: dict[str, dict[str, Any]],
                                                                  calibration: dict[str, Any]) -> None:
    guard = SplitGuard({"retail": committed[RETAIL_SPLIT], "banking_knowledge": committed["banking-split.json"]})
    assert set(RuntimeTaskView.model_fields) == {"schema_version", "domain", "task_id", "split", "purpose"}
    for seed in calibration["seeds"]:
        view = project_task(SeedPoisonTask(seed["upstream_task_id"]), domain="retail", guard=guard,
                            purpose=Purpose.DEMO)
        dumped = view.model_dump_json()
        assert seed["kind"] not in dumped and "Retail demo" not in dumped and calibration["allowlist"]["digest"] \
            not in dumped


def _policy(lines: list[str]) -> bytes:
    return "\n".join(lines).encode("utf-8")


def test_policy_trace_verifies_anchors_and_rejects_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy(["# Title", "", "Only pending orders.", "Data model prose.", ""])
    clause = hashlib.sha256(b"Only pending orders.").hexdigest()
    rule = PolicyRule(rule_id="cancel.pending_only", line_start=3, line_end=3, clause_sha256=clause,
                      enforcement="deterministic", interpretation="Cancel requires pending.")
    ref = PolicyRef(source_commit=RETAIL_POLICY.source_commit, path=RETAIL_POLICY.path,
                    sha256=hashlib.sha256(policy).hexdigest())
    monkeypatch.setattr("policyops_evals.policy_trace.RETAIL_POLICY", ref)
    monkeypatch.setattr("policyops_evals.policy_trace.RETAIL_RULES", (rule,))
    report = policy_trace.trace_policy(policy)
    assert report["verified"] == 1 and report["uncovered_content_lines"] == [4]
    with pytest.raises(ManifestError, match="pinned retail policy"):
        policy_trace.trace_policy(policy + b" ")
    shifted = rule.model_copy(update={"line_start": 4, "line_end": 4})
    monkeypatch.setattr("policyops_evals.policy_trace.RETAIL_RULES", (shifted,))
    with pytest.raises(ManifestError, match="clause hash"):
        policy_trace.trace_policy(policy)


def test_calibration_manifest_is_canonical() -> None:
    data = (default_manifest_dir() / CALIBRATION).read_bytes()
    assert data == (json.dumps(json.loads(data), sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
