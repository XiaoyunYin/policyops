"""Byte binding, fixed point and immutable, prior database registration."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import subprocess
from typing import Any, cast
from uuid import UUID

import pytest

from policyops.persistence.evaluation import EvaluationRepository
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import registration as reg
from policyops_evals.qa_studies.config import PLACEHOLDER, QAStudy

from .test_qa_study_config import body, parse


SOURCE: dict[str, Any] = {"source_head": "a" * 40, "dirty_sha256": "b" * 64,
                          "lock_sha256": {"uv.lock": "0" * 64, "evals/uv.lock": "0" * 64}}
SCOPE = UUID("6e01bfcb-a539-483b-a2be-280c3d449da2")


class MemoryRepository:
    """Only read-side registration behavior is faked; writes are covered in PG."""

    def __init__(self) -> None:
        self.configs: dict[UUID, dict[str, Any]] = {}
        self.prior = True

    def run_configuration(self, run_id: UUID) -> dict[str, Any] | None:
        return self.configs.get(run_id)

    def registration_precedes_claims(self, scope_id: UUID, at: datetime) -> bool:
        assert scope_id == SCOPE and at.tzinfo is not None
        return self.prior

    def repository(self) -> EvaluationRepository:
        return cast(EvaluationRepository, self)


def bound(value: dict[str, Any] | None = None) -> tuple[QAStudy, MemoryRepository]:
    data = body() if value is None else deepcopy(value)
    data["example"] = False
    data["purpose"] = "sealed_test"
    data["schedule"]["cohorts"][0]["split"] = "validation"
    study = parse(data)
    data["registration_sha256"] = reg.registration_digest(study, SOURCE)
    study = parse(data)
    repository = MemoryRepository()
    receipt = {"sha256": study.registration_sha256, "payload": reg.registration_payload(study, SOURCE),
               "created_at": "2026-11-14T12:00:00+00:00"}
    for record in reg.run_records(study, SCOPE, SOURCE):
        repository.configs[record.id] = json.loads(record.config_json) | {"registration": receipt}
    return study, repository


def materialize_manifests(value: dict[str, Any], root: Path) -> None:
    """Small synthetic dataset metadata, independent of G0.1 implementation."""
    cohorts = {}
    for cohort in value["schedule"]["cohorts"]:
        questions = sorted(f"md2d.q/{cohort['split']}/fixture/q-{i}" for i in range(cohort["question_count"]))
        cohorts[cohort["manifest_cohort"]] = {
            "query_ids": questions,
            "query_ids_sha256": sha256_bytes("".join(q + "\n" for q in questions).encode("utf-8")),
            "dialogue_ids": [f"fixture/d-{i}" for i in range(cohort["dialogue_count"])],
            "queries": cohort["question_count"], "dialogues": cohort["dialogue_count"]}
    raw = canonical_bytes({"schema": "policyops.multidoc2dial/v1", "cohorts": cohorts,
        "source": {"archive_sha256": value["data"]["archive_sha256"],
                   "member_sha256": {m["name"]: m["sha256"] for m in value["data"]["members"]}}})
    refs = [value["data"][k] for k in ("corpus", "passages", "queries", "qrels", "references", "splits", "sampling")]
    refs.extend(c["manifest"] for c in value["schedule"]["cohorts"])
    for ref in refs:
        ref["sha256"] = sha256_bytes(raw)
        target = root / ref["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def test_digest_excludes_only_own_field() -> None:
    value = body()
    digest = reg.registration_digest(parse(value), SOURCE)
    for replacement in (None, PLACEHOLDER, digest, "f" * 64):
        value["registration_sha256"] = replacement
        assert reg.registration_digest(parse(value), SOURCE) == digest
    value["name"] = "another-name"
    assert reg.registration_digest(parse(value), SOURCE) != digest


@pytest.mark.parametrize("group", ["identity", "data", "arms", "schedule", "analysis", "execution", "provenance",
                                    "source", "dirty", "locks", "prices", "judge"])
def test_changed_binding_refused(group: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from .test_qa_study_config import answer_body

    study, repository = bound(answer_body())
    value = study.model_dump(mode="json")
    source = deepcopy(SOURCE)
    if group == "identity":
        value["protocol_version"] = "changed-v2"
    elif group == "data":
        value["data"]["qrels"]["sha256"] = "f" * 64
    elif group == "arms":
        value["arms"][0]["retrieval"]["configuration_sha256"] = "f" * 64
    elif group == "schedule":
        value["schedule"]["balanced_order_seed"] += 1
    elif group == "analysis":
        value["analysis"]["comparisons"][0]["alpha"] = "0.01"
    elif group == "execution":
        value["execution"]["cumulative_caps"]["usd"] = "6"
    elif group == "provenance":
        value["provenance"]["machine"] = "changed-machine"
    elif group == "source":
        source["source_head"] = "f" * 40
    elif group == "dirty":
        source["dirty_sha256"] = "f" * 64
    elif group == "locks":
        source["lock_sha256"]["uv.lock"] = "f" * 64
    elif group == "judge":
        value["judge"]["selection_receipt_sha256"] = "f" * 64
    else:
        monkeypatch.setattr(reg, "prices", lambda: {"changed": True})
    changed = parse(value)
    with pytest.raises(ValueError, match=r"registration|source/lock"):
        reg.registered(changed, repository.repository(), SCOPE, source)


@pytest.mark.parametrize("value", [None, PLACEHOLDER])
def test_placeholder_is_schema_valid_but_cannot_register(value: str | None) -> None:
    data = body()
    data.update(registration_sha256=value, example=False)
    study = parse(data)
    with pytest.raises(ValueError, match="placeholder"):
        reg.register(study, MemoryRepository().repository(), SCOPE, SOURCE, cast(Any, None))


def test_registration_is_prior_and_all_arms_share_receipt() -> None:
    study, repository = bound()
    assert reg.registered(study, repository.repository(), SCOPE, SOURCE) is not None
    repository.prior = False
    with pytest.raises(ValueError, match="registration_after_claim"):
        reg.registered(study, repository.repository(), SCOPE, SOURCE)
    repository.prior = True
    config = next(iter(repository.configs.values()))
    config["registration"] = dict(config["registration"], created_at="2026-11-14T12:00:01+00:00")
    with pytest.raises(ValueError, match="binding"):
        reg.registered(study, repository.repository(), SCOPE, SOURCE)


def test_timestamp_and_missing_registration_refused() -> None:
    study, repository = bound()
    for config in repository.configs.values():
        config["registration"]["created_at"] = "2026-11-14T12:00:00"
    with pytest.raises(ValueError, match="UTC"):
        reg.registered(study, repository.repository(), SCOPE, SOURCE)
    repository.configs.clear()
    with pytest.raises(ValueError, match="before claims"):
        reg.registered(study, repository.repository(), SCOPE, SOURCE)


def test_normalizer_preserves_every_other_byte() -> None:
    raw = (b'{ "schema_version": "policyops.qa-study/v1", "registration_sha256" : null, '
           b'"nested": {"registration_sha256":"x"}}\n')
    normalized = reg.normalize_digest_field(raw)
    assert normalized == raw
    assert reg.normalize_digest_field(raw.replace(b"null", ('"' + "a" * 64 + '"').encode())) == normalized
    assert reg.normalize_digest_field(raw + b" ") != normalized
    assert reg.normalize_digest_field(raw.replace(b'"nested"', b'"different"')) != normalized
    assert reg.normalize_digest_field(raw.replace(b"qa-study/v1", b"study/v2")) == raw.replace(
        b"qa-study/v1", b"study/v2")


def test_committed_placeholder_digest_has_clean_tree_fixed_point(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, timeout=15)

    git("init")
    (tmp_path / "evals").mkdir()
    (tmp_path / "uv.lock").write_bytes(b"app-lock\n")
    (tmp_path / "evals/uv.lock").write_bytes(b"evals-lock\n")
    data = body()
    data["registration_sha256"] = PLACEHOLDER
    for lock in data["provenance"]["locks"]:
        lock["sha256"] = sha256_bytes((tmp_path / lock["path"]).read_bytes())
    path = tmp_path / "evals/study.json"
    path.write_bytes(canonical_bytes(data))
    git("add", ".")
    git("-c", "user.name=QA Test", "-c", "user.email=qa@example.invalid", "-c", "core.hooksPath=none",
        "commit", "-m", "placeholder")
    source = reg.source_provenance(tmp_path)
    digest = reg.registration_digest(parse(data), source)
    data["registration_sha256"] = digest
    path.write_bytes(canonical_bytes(data))
    assert reg.source_provenance(tmp_path) == source
    assert reg.registration_digest(parse(data), reg.source_provenance(tmp_path)) == digest
    path.write_bytes(path.read_bytes() + b" ")
    assert reg.source_provenance(tmp_path)["dirty_sha256"] != source["dirty_sha256"]
    (tmp_path / "untracked.py").write_bytes(b"# bound too\n")
    assert reg.registration_digest(parse(data), reg.source_provenance(tmp_path)) != digest


def test_manifest_bytes_are_verified_independently_of_code(tmp_path: Path) -> None:
    value = body()
    materialize_manifests(value, tmp_path)
    ref = value["schedule"]["cohorts"][0]["manifest"]
    study = parse(value)
    study.validate_data(tmp_path)
    (tmp_path / ref["path"]).write_bytes(b"{ }\n")
    with pytest.raises(ValueError, match="byte binding"):
        study.validate_data(tmp_path)


def test_manifest_counts_cannot_understate_registered_work(tmp_path: Path) -> None:
    value = body()
    materialize_manifests(value, tmp_path)
    value["schedule"]["cohorts"][0]["question_count"] -= 1
    value["analysis"]["comparisons"][0]["required_questions"] -= 1
    with pytest.raises(ValueError, match="identity/count"):
        parse(value).validate_data(tmp_path)


@pytest.mark.parametrize("corruption", ["hash", "query", "missing_hash", "order"])
def test_manifest_query_ids_must_agree_with_hash(tmp_path: Path, corruption: str) -> None:
    value = body()
    materialize_manifests(value, tmp_path)
    parse(value).validate_data(tmp_path)
    ref = value["schedule"]["cohorts"][0]["manifest"]
    target = tmp_path / ref["path"]
    manifest = json.loads(target.read_bytes())
    cohort = manifest["cohorts"]["dev"]
    if corruption == "hash":
        cohort["query_ids_sha256"] = "0" * 64
    elif corruption == "query":
        cohort["query_ids"][-1] += "-changed"
    elif corruption == "missing_hash":
        del cohort["query_ids_sha256"]
    else:
        cohort["query_ids"].reverse()
    raw = canonical_bytes(manifest)
    target.write_bytes(raw)
    # Rebind all outer byte hashes so only the inner list/hash contract can reject this.
    for section in value["data"].values():
        if isinstance(section, dict) and section.get("path") == ref["path"]:
            section["sha256"] = sha256_bytes(raw)
    ref["sha256"] = sha256_bytes(raw)
    with pytest.raises(ValueError, match="query IDs/hash mismatch"):
        parse(value).validate_data(tmp_path)


def test_slot_ids_are_deterministic_and_include_all_dimensions() -> None:
    study = parse(body())
    assert study.slot_id("dev", "q1", "rrf", 0) == study.slot_id("dev", "q1", "rrf", 0)
    assert study.slot_id("dev", "q1", "rrf", 0) != study.slot_id("dev", "q2", "rrf", 0)
    assert study.slot_id("dev", "q1", "rrf", 0) != study.slot_id("dev", "q1", "fts", 0)
    with pytest.raises(ValueError, match="schedule"):
        study.slot_id("dev", "q1", "rrf", 1)
    first = study.arm_order("dev", 0, 0)
    assert study.arm_order("dev", 1, 0) == first[1:] + first[:1]
    assert study.arm_order("dev", 2, 0) == first


def test_joint_multiarm_spec_fits_existing_registration_records() -> None:
    from policyops.persistence.evaluation import EvaluationRun

    from .test_qa_study_config import answer_body

    value = answer_body()
    for i in range(8):
        name = f"extra-{i}"
        value["arms"].append(dict(value["arms"][0], name=name))
        value["schedule"]["assignments"].append({"arm": name, "cohort": "dev"})
        for stage in value["execution"]["stages"][1:3]:
            value["execution"]["stages"].append(dict(stage, name=name + "-" + stage["role"], arm=name))
    comparison = value["analysis"]["comparisons"][0]
    value["analysis"]["comparisons"] = [dict(comparison, name=f"claim-{i}") for i in range(4)]
    value["execution"]["artifact_max_observations"] = 100000
    study = parse(value)
    receipt = {"sha256": reg.registration_digest(study, SOURCE), "payload": reg.registration_payload(study, SOURCE),
               "created_at": "2026-11-14T12:00:00.123456+00:00"}
    for record in reg.run_records(study, SCOPE, SOURCE):
        persisted = record.model_dump()
        persisted["config_json"] = json.dumps(json.loads(record.config_json) | {"registration": receipt})
        assert EvaluationRun.model_validate(persisted).dataset_revision == SOURCE["source_head"]
