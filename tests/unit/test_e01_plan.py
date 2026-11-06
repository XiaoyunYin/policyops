"""E01 planning (T15a), pure: envelopes from the actual actor reservations, finite slot enumeration and derived
identities, reservation ceilings, the selection decision table and contract bounds. A manifest is a proposal;
nothing here is a measurement."""

from __future__ import annotations

import ast
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter, ValidationError
import pytest

from policyops.budget.config import Configuration
from policyops.studies import e01_plan as plan
from policyops_contracts.e01 import DeltaText, E01Manifest, E01Selection, Envelope, Interval, UnitText, slot_id_for
from policyops_contracts.retrieval import RetrievalConfig


STUDY = UUID(int=15)
TASKS = [f"task_{i:03d}" for i in range(1, 40)]  # 39 synthetic dev task IDs


def banking() -> E01Manifest:
    return plan.banking_manifest(study_id=STUDY, split_manifest_sha256="a" * 64, dev_task_ids=TASKS,
                                 dev_task_ids_digest="b" * 64, configuration=Configuration(), seeds=(1, 2, 3, 4),
                                 bootstrap_seed=20261105)


def interval(lower: str, estimate: str = "0") -> Interval:
    return Interval(estimate=estimate, lower=lower, upper="1", resamples=10_000, clusters="task")


def test_envelopes_derive_from_the_actual_reservations() -> None:
    configuration = Configuration()
    chat, embedding = (configuration.reservation(a).worst_usd for a in ("agent", "embedding"))
    assert (chat, embedding) == (Decimal("0.002624"), Decimal("0.00016384"))  # 16000/2048 Luna; 8192-token batch
    insitu = plan.envelope(configuration, plan.DEFAULT_BOUNDS, "banking_insitu")
    replay = plan.envelope(configuration, plan.DEFAULT_BOUNDS, "replay_provider")
    retail = plan.envelope(configuration, plan.DEFAULT_BOUNDS, "retail")
    assert (insitu.cap_calls, insitu.cap_usd, insitu.chat_calls, insitu.embedding_batches) == (48, "0.1013504", 38, 10)
    assert (replay.cap_calls, replay.cap_usd) == (20, "0.0278784")
    assert (retail.cap_calls, retail.cap_usd) == (38, "0.0751104")
    assert insitu.max_input_tokens_per_embedding_batch == 8192 and insitu.max_input_tokens_per_chat_call == 16000


def test_the_banking_manifest_is_finite_with_derived_identities_and_common_envelopes() -> None:
    m = banking()
    phases: dict[tuple[str, str, str], int] = {}
    for s in m.slots:
        phases[(s.phase, s.arm_id, s.plan)] = phases.get((s.phase, s.arm_id, s.plan), 0) + 1
        assert s.slot_id == slot_id_for(STUDY, s.phase, s.arm_id, s.task_id, s.trial)
    assert phases == {("acquisition", "A2", "scheduled"): 156, ("replay", "A0", "scheduled"): 156,
                      ("replay", "A1", "scheduled"): 156, ("replay", "A2", "scheduled"): 156,
                      ("replay", "A3", "scheduled"): 156, ("confirmation", "A0", "declared_optional"): 156,
                      ("confirmation", "A1", "declared_optional"): 156,
                      ("confirmation", "A3", "declared_optional"): 156}
    assert all(s.envelope == "banking_insitu" for s in m.slots if s.phase in ("acquisition", "confirmation"))
    assert all((s.envelope is None) == (s.arm_id == "A0") for s in m.slots if s.phase == "replay")
    assert m.status == "proposed" and m.price_revision == "pricing.2026-11-05.v1" and m.digest() == banking().digest()


def test_ceilings_are_reservation_sums_of_activatable_slots() -> None:
    per, total = plan.ceilings(banking())
    rows = {c.phase: c for c in per}
    assert rows["acquisition"].usd == Decimal("15.8106624") and rows["replay"].usd == Decimal("13.0470912")
    assert rows["confirmation"].usd == Decimal("31.6213248") and rows["confirmation"].slots == 312
    assert total == Decimal("60.4790784")
    assert rows["replay"].slots == 624 and rows["replay"].chat_calls == 3 * 156 * 10
    retail = plan.retail_manifest(study_id=STUDY, split_manifest_sha256="a" * 64,
                                  dev_task_ids=[f"r{i}" for i in range(64)], dev_task_ids_digest="b" * 64,
                                  configuration=Configuration(), seeds=(1,), bootstrap_seed=1)
    assert plan.ceilings(retail)[1] == Decimal("9.6141312")


@pytest.mark.parametrize(("a0", "a1", "a3", "expected"), [
    ("-0.04", "0.2", "0.01", ("A0", "A3")),   # simplest non-inferior arm, plus a replay-positive rerank
    ("-0.06", "-0.05", "0", ("A1",)),         # A0 outside the margin, A1 exactly at it; A3 not > 0
    ("-0.2", "-0.2", "-0.1", ()),
])
def test_the_replay_screen_only_proposes_confirmations(a0: str, a1: str, a3: str, expected: tuple[str, ...]) -> None:
    replay = {"A0": interval(a0), "A1": interval(a1), "A3": interval(a3)}
    assert plan.confirmation_arms(replay, "0.05") == expected  # type: ignore[arg-type]
    with pytest.raises(plan.PlanError):
        plan.confirmation_arms({"A0": interval(a0), "A3": interval(a3)}, "0.05")


@pytest.mark.parametrize(("confirmed", "in_situ", "final"), [
    (("A0", "A3"), {"A0": "-0.01", "A3": "0.02"}, "A3"),
    (("A0", "A3"), {"A0": "-0.01", "A3": "0"}, "A0"),   # rerank not confirmed in-situ: never chosen from replay
    (("A1",), {"A1": "-0.06"}, "A2"),                   # simpler arm not non-inferior in-situ
    ((), {}, "A2"),
])
def test_the_final_arm_needs_paired_in_situ_evidence(confirmed: tuple[str, ...], in_situ: dict[str, str],
                                                     final: str) -> None:
    chosen = E01Selection(manifest_sha256="a" * 64, replay_report_sha256="b" * 64,
                          confirmation_arms=confirmed)  # type: ignore[arg-type]
    assert plan.final_arm(chosen, {a: interval(v) for a, v in in_situ.items()}, "0.05") == final  # type: ignore[misc]
    if confirmed:
        with pytest.raises(plan.PlanError):
            plan.final_arm(chosen, {}, "0.05")


@pytest.mark.parametrize("arms", [("A0", "A1"), ("A2",), ("A3", "A0"), ("A3", "A3")])
def test_illegal_selections_are_refused(arms: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        E01Selection(manifest_sha256="a" * 64, replay_report_sha256="b" * 64, confirmation_arms=arms)  # type: ignore[arg-type]


@pytest.mark.parametrize(("adapter", "good", "bad"), [
    (UnitText, ["0", "1", "0.05", "0.999999999999"], ["1.5", "-0.5", "-0", "1.0000000000001", "2"]),
    (DeltaText, ["-1", "-0.5", "0", "1"], ["1.5", "-1.5", "-0", "-1.000000000001"]),
])
def test_bounded_ratio_and_difference_texts(adapter: Any, good: list[str], bad: list[str]) -> None:
    checker = TypeAdapter(adapter)
    for value in good:
        checker.validate_python(value)
    for value in bad:
        with pytest.raises(ValidationError):
            checker.validate_python(value)


def test_a_provider_envelope_needs_a_positive_usd_cap_and_consistent_calls() -> None:
    base = plan.envelope(Configuration(), plan.DEFAULT_BOUNDS, "banking_insitu").model_dump()
    for change in ({"cap_usd": "0"}, {"cap_calls": 47}):
        with pytest.raises(ValidationError):
            Envelope.model_validate(base | change)


def test_manifest_structure_is_closed() -> None:
    m = banking()
    data = m.model_dump()
    duplicate = data | {"slots": (*data["slots"], data["slots"][0])}
    with pytest.raises(ValidationError, match="unique"):
        E01Manifest.model_validate(duplicate)
    forged = list(data["slots"])
    forged[0] = forged[0] | {"slot_id": UUID(int=1)}
    with pytest.raises(ValidationError, match="derived identity"):
        E01Manifest.model_validate(data | {"slots": tuple(forged)})
    with pytest.raises(ValidationError, match="optional"):
        E01Manifest.model_validate(data | {"slots": (data["slots"][0] | {"plan": "declared_optional"},)})
    bad_arm = data["arms"][0] | {"config": RetrievalConfig(mode="hybrid").model_dump()}
    with pytest.raises(ValidationError):
        E01Manifest.model_validate(data | {"arms": (bad_arm, *data["arms"][1:])})


def test_the_planner_imports_no_persistence_provider_or_database_layer() -> None:
    source = Path(plan.__file__).read_text(encoding="utf-8")
    modules = {n.module for n in ast.walk(ast.parse(source)) if isinstance(n, ast.ImportFrom) and n.module}
    modules |= {a.name for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Import) for a in n.names}
    forbidden = ("policyops.persistence", "policyops.providers", "policyops.retrieval", "sqlalchemy", "psycopg",
                 "httpx", "openai", "anthropic", "policyops_evals")
    assert not [m for m in modules if m.startswith(forbidden)]


# -- review regressions (fixed-c2-envelope-ceiling-finding-1) --------------------------------------------------------

def small(tasks: int = 2) -> E01Manifest:
    return plan.banking_manifest(study_id=STUDY, split_manifest_sha256="a" * 64,
                                 dev_task_ids=[f"t{i}" for i in range(tasks)], dev_task_ids_digest="b" * 64,
                                 configuration=Configuration(), seeds=(1,), bootstrap_seed=1)


def edited(m: E01Manifest, keep: Any = lambda s: True, change: Any = lambda s: s) -> dict[str, Any]:
    data = m.model_dump()
    return data | {"slots": tuple(change(s) for s in data["slots"] if keep(s))}


def test_a_mixed_envelope_confirmation_manifest_is_refused_at_admission() -> None:
    # The reproduced edit: the A0 confirmation cohort moved to the replay envelope (internally consistent cohort).
    data = edited(small(), change=lambda s: s | {"envelope": "replay_provider"}
                  if (s["phase"], s["arm_id"]) == ("confirmation", "A0") else s)
    with pytest.raises(ValidationError, match="common envelope"):
        E01Manifest.model_validate(data)


@pytest.mark.parametrize("break_it", ["confirmation_scheduled", "replay_a0_provider", "replay_a1_insitu",
                                      "acquisition_a1", "confirmation_a2", "retail_phase_in_banking", "purpose"])
def test_every_phase_follows_its_admission_policy(break_it: str) -> None:
    m = small()
    if break_it == "purpose":
        with pytest.raises(ValidationError, match="purpose"):
            E01Manifest.model_validate(m.model_dump() | {"purpose": "retail_dev_control"})
        return

    def change(s: dict[str, Any]) -> dict[str, Any]:
        key = (s["phase"], s["arm_id"])
        if break_it == "confirmation_scheduled" and s["phase"] == "confirmation":
            return s | {"plan": "scheduled"}
        if break_it == "replay_a0_provider" and key == ("replay", "A0"):
            return s | {"provider_path": True, "envelope": "replay_provider"}
        if break_it == "replay_a1_insitu" and key == ("replay", "A1"):
            return s | {"envelope": "banking_insitu"}
        return s

    data = edited(m, change=change)
    if break_it in ("acquisition_a1", "confirmation_a2", "retail_phase_in_banking"):
        phase, arm_id = {"acquisition_a1": ("acquisition", "A1"), "confirmation_a2": ("confirmation", "A2"),
                         "retail_phase_in_banking": ("retail_control", "R0")}[break_it]
        group = "replay_provider" if phase == "replay" else "banking_insitu"
        extra = tuple(plan._slot(STUDY, phase, arm_id, t, 0, optional=phase == "confirmation",  # type: ignore[arg-type]
                                 group=group).model_dump() for t in m.task_ids)  # type: ignore[arg-type]
        data = data | {"slots": (*data["slots"], *extra)}
    with pytest.raises(ValidationError):
        E01Manifest.model_validate(data)


def test_coherent_partial_studies_stay_valid_and_ceilings_sum_the_legal_maximum() -> None:
    m = small()
    insitu = Decimal(plan.envelope(Configuration(), plan.DEFAULT_BOUNDS, "banking_insitu").cap_usd)
    replay_only = E01Manifest.model_validate(edited(m, keep=lambda s: s["phase"] == "replay"))
    rows, total = plan.ceilings(replay_only)
    assert [r.phase for r in rows] == ["replay"] and total == 2 * 3 * Decimal("0.0278784")  # A0 has no scope
    for arms, cohorts in ((("A0", "A1"), 1), (("A1", "A3"), 2), (("A0",), 1), (("A3",), 1), (("A0", "A1", "A3"), 2)):
        partial = E01Manifest.model_validate(edited(
            m, keep=lambda s, a=arms: s["phase"] != "confirmation" or s["arm_id"] in a))
        confirmation = {r.phase: r for r in plan.ceilings(partial)[0]}["confirmation"]
        assert confirmation.usd == cohorts * 2 * insitu and confirmation.slots == cohorts * 2, arms
    assert plan.ceilings(m)[1] == plan.ceilings(E01Manifest.model_validate(m.model_dump()))[1]
