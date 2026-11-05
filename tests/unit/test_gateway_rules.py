"""Every policy rule case runs through the real gateway, and the coverage map is derived from those cases (T17)."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from policyops.domain.retail_rules import Allowed, rules_for
from policyops_contracts.gateway import (
    HandoffObservation,
    LookupObservation,
    ProposalPreview,
    ReadObservation,
    ToolError,
)
from policyops_contracts.policy import RETAIL_RULES, RULES_BY_ID
from policyops_contracts.presentation import render_effect
from policyops_contracts.retail import ToolName
from policyops_testing.gateway_cases import CASES, CONTRACT, COVERAGE, LINKED_TESTS, RuleCase, coverage_bytes, execute


REPO = Path(__file__).resolve().parents[2]
KINDS: dict[str, type[Any]] = {"preview": ProposalPreview, "read": ReadObservation, "lookup": LookupObservation,
         "handoff": HandoffObservation, "error": ToolError}


@pytest.mark.parametrize("case", CASES, ids=[case.case_id for case in CASES])
def test_rule_case(case: RuleCase) -> None:
    execution = execute(case)
    result = execution.last
    observation: Any = result.observation
    if case.expect.kind == "message":
        assert observation is None
    else:
        assert isinstance(observation, KINDS[case.expect.kind]), observation
    if isinstance(observation, ToolError):
        assert (observation.code, observation.rule_id) == (case.expect.code, case.expect.rule_id)
        assert result.decision is None or not isinstance(result.decision, Allowed)
        expected_category = "escalate" if observation.code == "policy_unsupported" else "deny"
        assert case.outcome == expected_category
    else:
        assert case.outcome == "allow"
    if isinstance(observation, ProposalPreview):
        assert isinstance(result.decision, Allowed)
        assert observation.presentation == render_effect(result.decision.effect)
        assert observation.actionable is False
        assert result.rule_ids == rules_for(ToolName(observation.tool))
        assert case.rule_id in result.rule_ids
    if isinstance(observation, LookupObservation):
        assert observation.outcome == "authenticated"
        assert len(execution.sessions.records) == 1
    if case.same_each_step:
        assert len({r.observation.model_dump_json() for r in execution.results if r.observation is not None}) == 1
    if case.via == CONTRACT:
        assert execution.retail.calls == []


def _by_rule() -> dict[str, list[RuleCase]]:
    grouped: dict[str, list[RuleCase]] = {rule.rule_id: [] for rule in RETAIL_RULES}
    for case in CASES:
        grouped[case.rule_id].append(case)
    return grouped


def test_case_ids_are_unique_and_name_real_rules() -> None:
    assert len({case.case_id for case in CASES}) == len(CASES)
    assert all(case.rule_id in RULES_BY_ID for case in CASES)


def test_every_rule_kind_has_its_required_executed_coverage() -> None:
    grouped = _by_rule()
    for rule in RETAIL_RULES:
        outcomes = {case.outcome for case in grouped[rule.rule_id]}
        if rule.enforcement == "deterministic":
            assert {"allow", "deny"} <= outcomes, rule.rule_id
        elif rule.enforcement == "escalate":
            assert "escalate" in outcomes, rule.rule_id
        elif rule.enforcement in ("presentation", "protocol"):
            assert LINKED_TESTS.get(rule.rule_id), rule.rule_id
        else:
            assert not grouped[rule.rule_id] and rule.rule_id not in LINKED_TESTS, rule.rule_id
    for case in CASES:
        if case.outcome != "allow" and case.expect.rule_id != case.rule_id:
            assert case.via, f"{case.case_id} asserts {case.expect.rule_id} for {case.rule_id} without a reason"


def test_once_only_allows_run_only_with_the_labelled_test_history() -> None:
    once_allows = [case for case in CASES if case.outcome == "allow" and case.history_label != "not_used"]
    assert once_allows and all(case.history_label == "test_only_complete" for case in once_allows)
    assert any(case.history_label == "production_incomplete" and case.outcome == "escalate" for case in CASES)


def test_linked_tests_exist() -> None:
    for nodes in LINKED_TESTS.values():
        for node in nodes:
            path, name = node.split("::")
            tree = ast.parse((REPO / path).read_text(encoding="utf-8"))
            assert name in {item.name for item in tree.body if isinstance(item, ast.FunctionDef)}, node


def test_coverage_map_is_regenerated_from_the_executed_cases() -> None:
    assert COVERAGE.read_bytes() == coverage_bytes()
    document = json.loads(COVERAGE.read_bytes())
    assert document["case_count"] == len(CASES)
    assert [rule["rule_id"] for rule in document["rules"]] == [rule.rule_id for rule in RETAIL_RULES]
    uncovered = [rule["rule_id"] for rule in document["rules"] if rule["enforcement"] == "not_codified"]
    assert uncovered == ["grounding.no_fabrication", "time.est_database"]
    assert all("uncovered_reason" in rule and not rule["cases"] for rule in document["rules"]
               if rule["enforcement"] == "not_codified")
