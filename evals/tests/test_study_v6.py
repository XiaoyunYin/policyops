"""Preregistered tool-error protocol, legacy identity and closed diagnostics."""

from decimal import Decimal
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.studies import registration, reports
from policyops_evals.studies.config import Limits, StudyV3, load_study, preflight
from policyops_evals.studies.termination import SIMULATION_TERMINATIONS, closed_termination

from .t32_support import SOURCE, frozen_fixture


CONFIG = Path(__file__).parents[1] / "studies/e03-dev-luna-haiku-v6.json"


@pytest.mark.parametrize("value", [0, -1, 101, True, 1.5, "10", None])
def test_tool_error_limit_refuses_noninteger_or_out_of_bounds(value: Any) -> None:
    body = load_study(CONFIG).limits.model_dump(mode="json") | {"max_tool_errors": value}
    with pytest.raises(ValueError):
        Limits.model_validate_json(canonical_bytes(body))


@pytest.mark.parametrize("value", [1, 10, 100])
def test_tool_error_limit_is_explicit_and_hash_bound(value: int) -> None:
    previous = load_study(CONFIG.with_name("e03-dev-luna-haiku-v5.json"))
    body = previous.model_dump(mode="json")
    body["limits"]["max_tool_errors"] = value
    study = StudyV3.model_validate_json(canonical_bytes(body))
    assert study.limits.tool_error_limit == study.limits.max_tool_errors == value
    assert study.digest() != previous.digest()
    assert study.variant_digest(study.variants[0]) != previous.variant_digest(previous.variants[0])
    frozen = registration.freeze(study, uuid4(), SOURCE, dict.fromkeys(study.tasks, "db_only"), None)
    assert frozen.limits.model_dump(mode="json")["max_tool_errors"] == value
    assert frozen.specification["limits"]["max_tool_errors"] == value


@pytest.mark.parametrize(("name", "file_hash"), [
    ("e03-dev-luna-haiku-frozen-draft-v2.json", "0a05398502041b61e5a157e53a0c2cedf6bd25aa3bb4714a31d5d2ad6ba1a204"),
    ("e03-dev-luna-haiku-v3.json", "3d0f23fcc2f486cae8b66d575ca2095e141e822dcaad2aab5603306cd40c023f"),
    ("e03-dev-luna-haiku-v4.json", "404a2e5a4ee80a593a667ba51e5c4ee361f8d865016f2017e9a8f55a41a4cfec"),
    ("e03-dev-luna-haiku-v5.json", "9f6a379e0e736756b3cf7bbd50cfd0562ccc67a835db404bcce5aee10cb7a0e0"),
])
def test_legacy_files_and_canonical_study_hashes_are_unchanged(name: str, file_hash: str) -> None:
    path = CONFIG.with_name(name)
    assert sha256_bytes(path.read_bytes()) == file_hash
    study = load_study(path)
    legacy = json.loads(path.read_bytes()) | {"scripted_outputs": []}
    assert study.model_dump(mode="json") == legacy
    assert study.digest() == sha256_bytes(canonical_bytes(legacy))
    assert study.limits.tool_error_limit == 1
    assert preflight(study)["max_tool_errors"] == 1


def test_v6_changes_only_the_preregistered_fields_and_keeps_admission() -> None:
    old = json.loads(CONFIG.with_name("e03-dev-luna-haiku-v5.json").read_bytes())
    body = json.loads(CONFIG.read_bytes())
    assert body.pop("study_key") == "e03-dev-luna-haiku-v6"
    old.pop("study_key")
    notes = body.pop("notes")
    assert notes.startswith(old.pop("notes"))
    assert all(text in notes for text in ("Before any v6 data", "160/160", "one unresolved bill", "22/160",
                                        "undocumented max_errors=1", "upstream default 10 model-neutrally"))
    assert body["limits"].pop("max_tool_errors") == 10
    assert body == old
    plan = preflight(load_study(CONFIG))
    assert plan["max_tool_errors"] == 10 and plan["within_caps"]
    assert plan["scheduled_slots"] == 160 and plan["prior"] == "unverified"
    assert not plan["authorizes_paid_execution"]
    assert Decimal(plan["planning_estimate_usd"]) == Decimal("3.6480")
    assert Decimal(plan["admission_ceiling_usd"]) == Decimal("27.0848")
    assert Decimal(plan["study_cap_usd"]) == Decimal("28")


@pytest.mark.parametrize("value", [None, "PRIVATE_MESSAGE_CANARY", "unavailable", 10, [], {}])
def test_unknown_termination_never_exports_content(value: object) -> None:
    assert closed_termination(value) == "unknown"


def test_report_summary_resolves_legacy_tool_limit_without_changing_frozen_bytes() -> None:
    frozen, snapshot = frozen_fixture()
    original = canonical_bytes(frozen.model_dump(mode="json"))
    result = reports.build(frozen, snapshot, "1" * 64, "2" * 64)
    assert result["execution"]["limits"]["max_tool_errors"] == 1
    assert canonical_bytes(frozen.model_dump(mode="json")) == original
    assert "max_tool_errors" not in frozen.limits.model_dump(mode="json")


def test_closed_termination_codes_are_retained() -> None:
    assert all(closed_termination(code) == code for code in SIMULATION_TERMINATIONS)


def test_upstream_enum_members_become_plain_codes() -> None:
    from tau2.data_model.simulation import TerminationReason

    for reason in TerminationReason:
        code = closed_termination(reason)
        assert type(code) is str and str(code) == f"{code}" == reason.value
