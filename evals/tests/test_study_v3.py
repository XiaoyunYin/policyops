"""Explicit agent limits and the pre-data E03 v3 freeze."""

from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from policyops_contracts.conversation import AgentLimits
from policyops_evals.canonical import canonical_bytes
from policyops_evals.studies import bundles, registration
from policyops_evals.studies.config import StudyV3, load_study, preflight

from .t32_support import SOURCE, frozen_fixture


CONFIG = Path(__file__).parents[1] / "studies/e03-dev-luna-haiku-v3.json"


def test_v3_preserves_design_and_enforces_explicit_agent_limits(monkeypatch: pytest.MonkeyPatch,
                                                              tmp_path: Path) -> None:
    study = load_study(CONFIG)
    assert isinstance(study, StudyV3)
    pilot = load_study(CONFIG.with_name("e03-dev-luna-haiku-frozen-draft-v2.json"))
    for field in ("tasks", "seeds", "pairing", "statistics", "decision", "eligibility"):
        assert getattr(study, field) == getattr(pilot, field)
    for variant in study.variants:
        limits = study.agent_limits(variant)
        assert (limits.model_calls, limits.steps_per_turn, limits.consecutive_invalid) == (32, 12, 2)
        assert limits.model_fields_set == set(AgentLimits.model_fields)
        assert variant.actors.simulator == pilot.variants[0].actors.simulator
    assert study.limits.scenario_calls == study.limits.scenario_counts == 64
    assert study.limits.scenario_usd == Decimal("0.20") and study.limits.study_usd == Decimal(20)
    plan = preflight(study)
    assert {r["actor"] for r in plan["actors"]} == {"agent", "simulator", "judge"}
    assert plan["inference_ceiling"] == plan["count_ceiling"] == 7200
    # The run must resolve the reservation conflict without undercounting actors.
    assert Decimal(plan["admission_ceiling_usd"]) == Decimal("18.8928")
    assert plan["within_caps"]
    registration.validate_implementation(study)
    frozen = registration.freeze(study, uuid4(), SOURCE, dict.fromkeys(study.tasks, "db_only"), None)
    assert frozen.specification["notes"] == study.notes
    # V3 is also readable by the immutable file-only bundle/report stack.
    _, snapshot = frozen_fixture()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    digest = bundles.seal(tmp_path / "bundle", frozen, snapshot)
    assert bundles.load(tmp_path / "bundle/study.json", digest)[0] == frozen


@pytest.mark.parametrize("damage", ["missing", "calls", "output", "protocol", "notes", "knowledge", "opening"])
def test_v3_refuses_implicit_or_inconsistent_limits(damage: str) -> None:
    body: Any = load_study(CONFIG).model_dump(mode="json")
    if damage == "notes":
        body.pop("notes")
    else:
        for variant in body["variants"]:
            limits = variant["agent_limits"]
            if damage == "missing":
                limits.pop("steps_per_turn")
            elif damage == "calls":
                limits["model_calls"] = 16
            elif damage == "output":
                limits["max_output_tokens"] = 1024
            elif damage == "knowledge":
                limits["knowledge_steps"] = 1
            elif damage == "opening":
                limits["transcript_messages"] = 256
            else:
                variant["agent_protocol"] = "strict"
    with pytest.raises(ValueError):
        StudyV3.model_validate_json(canonical_bytes(body))
