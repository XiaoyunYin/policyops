"""Model-neutral limits and pre-data E03 v4 freeze."""

from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from policyops_contracts.conversation import AgentLimits
from policyops_evals.canonical import canonical_bytes
from policyops_evals.studies.config import StudyV3, load_study, preflight


CONFIG = Path(__file__).parents[1] / "studies/e03-dev-luna-haiku-v4.json"
PREVIOUS = CONFIG.with_name("e03-dev-luna-haiku-v3.json")


def test_v4_preserves_design_and_raises_only_the_decided_limits() -> None:
    study = load_study(CONFIG)
    previous = load_study(PREVIOUS)
    assert isinstance(study, StudyV3)
    assert isinstance(previous, StudyV3)
    for field in ("tasks", "seeds", "pairing", "statistics", "decision", "eligibility"):
        assert getattr(study, field) == getattr(previous, field)
    assert study.decision.metric == previous.decision.metric == "pass^1"
    assert study.decision.guard_metrics == previous.decision.guard_metrics == ("pass^4",)
    assert study.decision.margin == previous.decision.margin == Decimal("0.10")
    assert study.study_key != previous.study_key
    assert study.limits.trial_seconds == 600
    for variant, old_variant in zip(study.variants, previous.variants, strict=True):
        assert variant.name == old_variant.name
        assert variant.actors.agent.model == old_variant.actors.agent.model
        limits = study.agent_limits(variant)
        assert (limits.model_calls, limits.steps_per_turn, limits.consecutive_invalid) == (32, 12, 2)
        assert limits.model_fields_set == set(AgentLimits.model_fields)
        assert variant.actors.agent.max_input == 32000
        assert variant.actors.simulator == old_variant.actors.simulator
        assert variant.actors.judge == old_variant.actors.judge
    assert study.limits.scenario_calls == previous.limits.scenario_calls == 64
    assert study.limits.scenario_counts == previous.limits.scenario_counts == 64
    assert study.limits.scenario_usd == previous.limits.scenario_usd == Decimal("0.20")
    plan = preflight(study)
    assert {row["actor"] for row in plan["actors"]} == {"agent", "simulator", "judge"}
    assert plan["within_caps"]
    ceiling = Decimal(plan["admission_ceiling_usd"])
    assert Decimal(plan["planning_estimate_usd"]) == Decimal("3.6480")
    assert ceiling == Decimal("27.08480000")
    assert ceiling <= study.limits.study_usd
    assert ceiling <= study.limits.invocation_usd
    assert study.limits.study_usd == study.limits.invocation_usd
    assert study.limits.study_usd == ceiling.to_integral_value(rounding="ROUND_CEILING")
    assert study.limits.invocation_usd == Decimal("28")
    assert "116/160" in study.notes and "unknowable billing" in study.notes
    assert "Three Haiku trials" in study.notes and "Both are limits" in study.notes


@pytest.mark.parametrize("damage", ["missing", "calls", "input", "output", "protocol", "notes", "knowledge", "opening"])
def test_v4_refuses_implicit_or_inconsistent_limits(damage: str) -> None:
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
            elif damage == "input":
                variant["actors"]["agent"]["max_input"] = 32001
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
