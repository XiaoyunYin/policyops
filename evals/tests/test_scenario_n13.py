"""Offline verification of N13 registration and scoring denominators."""

from collections import Counter
from decimal import Decimal
from uuid import uuid4

import httpx2
import pytest

from policyops.providers.results import openai_evidence, openai_result
from policyops.providers.serialize import prepare
from policyops.providers.tokenizer import load
from policyops.providers.tools import retail_tool_spec
from policyops_contracts.model import Message, ModelRequest, TextPart
from policyops_contracts.retail import CancelPendingOrder, FindUserIdByEmail
from policyops_evals.scenarios import n13_acceptance as acceptance
from policyops_evals.scenarios.n13_fixtures import generate
from policyops_evals.scenarios.n13_panel import Observation, metrics
from policyops_evals.scenarios.runtime import Slot, configuration

from .scenario_support import pinned as pinned


def test_registration_excludes_spent_data_and_places_the_sole_cancellation_first(pinned: tuple[bytes, bytes]) -> None:
    raw, _ = pinned
    panel = generate(raw)
    assert panel == generate(raw)
    assert (panel.census["historical_held_out_customers"], panel.census["fresh_customers"]) == (256, 116)
    assert panel.census["historical_resolvable_design_blocks"] == 56
    assert panel.census["historical_resolvable_pool"] == 149
    assert Counter(trial.group for trial in panel.trials) == {
        "A": 7, "A-prime": 2, "B1": 2, "B2": 2, "B3": 2, "C1": 2, "C2": 2, "C3": 2}
    first, second, third = panel.live
    assert (first.group, second.group, third.group) == ("B2", "B1", "B1")
    assert isinstance(first.action, CancelPendingOrder) and first.scenario.gold.order_id_form == "absent"
    assert second.scenario.gold.order_id_form == third.scenario.gold.order_id_form == "hash"
    scheduled = {trial.scenario.world.customer_id for trial in panel.trials}
    assert len({trial.scenario.world.customer_id for trial in panel.live} - scheduled) == 3
    for trial in (*panel.trials, *panel.live):
        trial.scenario.verify(raw)
    preflight = acceptance.preflight(panel.live, Decimal("0.05"))
    assert preflight["worst_usd"] == Decimal("0.036288")
    assert (preflight["calls_per_slot"], preflight["input_per_call"], preflight["output_per_call"],
            preflight["seconds_per_slot"]) == (8, 10_000, 1024, 120)
    for cap in (Decimal("0.03"), Decimal("0.051"), Decimal("NaN")):
        with pytest.raises(ValueError, match="USD cap"):
            acceptance.preflight(panel.live, cap)


def test_panel_metrics_count_refusals_and_effects_over_registered_attempts() -> None:
    rows = (
        Observation("A", "cancel", 0, True, False), Observation("A", "cancel", 0, False, False),
        Observation("A-prime", "cancel", 1, False, True),
        Observation("B1", "return", 1, False, True), Observation("B2", "return", 0, True, False),
        Observation("B3", "cancel", 0, True, False), Observation("C1", "cancel", 0, True, False),
        Observation("C2", "return", 0, True, False), Observation("C3", "return", 1, False, True),
    )
    assert metrics(rows) == {
        "wrong_target_effects_A_Aprime": (1, 3), "false_blocks_B1_B2": (1, 2),
        "design_blocks_B3": (1, 1), "clean_refusals_A": (1, 2), "refusals_without_effect_C1": (1, 1),
        "refusals_without_effect_C2_synthetic": (1, 1), "verified_commits_C3": (1, 1),
    }


def test_scripted_acceptance_reply_passes_provider_and_usage_validation(pinned: tuple[bytes, bytes]) -> None:
    trial = generate(pinned[0]).live[0]
    request = ModelRequest(instructions="Follow the retail policy.", max_output_tokens=1024,
                           messages=(Message(role="user", parts=(TextPart(text=trial.scenario.visible.message),)),),
                           tools=(retail_tool_spec(FindUserIdByEmail, "Authenticate the customer."),))
    prepared = prepare(request, configuration(), "agent")
    respond = acceptance.scripted(load(), trial, Slot(uuid4(), uuid4()))
    count = respond(httpx2.Request("POST", "https://api.openai.com/v1/responses/input_tokens",
                                   content=prepared.count_body)).json()
    raw = respond(httpx2.Request("POST", "https://api.openai.com/v1/responses", content=prepared.body)).json()
    evidence = openai_evidence(raw, prepared, "none")
    assert evidence.block is None and evidence.usage is not None
    assert evidence.usage.input_total == count["input_tokens"]
    result = openai_result(raw, prepared, evidence)
    assert result.outcome == "completed"
    [lookup] = result.tool_calls
    assert lookup.name == "find_user_id_by_email"
