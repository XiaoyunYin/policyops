"""The rule/source coverage map (T17): which executed gateway cases exercise each source-traced policy rule.

The document is generated from two inputs:
- the pinned rule table (`RETAIL_RULES`): the policy lines, the clause digest, the enforcement kind and the tools;
- the executable case table that the gateway rule tests run (`tests/support/policyops_testing/gateway_cases.py`).

For each rule the document lists those cases, each with:
- the outcome it asserts (`allow`, `deny` or `escalate`);
- the asserted error code and rule ID;
- for a case whose asserted rule ID differs from the covered rule, the stated reason (`via`);
- which operation history it ran with. `test_only_complete` is an injected test fake: before T19 the production
  history is incomplete, so a once-per-order tool escalates and is never allowed end to end.

**Other rule kinds:**
- `presentation` and `protocol` rules also name the existing executed tests that check them.
- `not_codified` rules are listed with their recorded reason and counted as uncovered.

A listed case is covered evidence only because the parametrized test executes every case and asserts exactly
these values. The document records the mapping; it is not proof on its own.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
from typing import Literal

from policyops_contracts.policy import RETAIL_POLICY, RETAIL_RULES


CaseOutcome = Literal["allow", "deny", "escalate"]
CASE_TEST = "tests/unit/test_gateway_rules.py::test_rule_case"


@dataclass(frozen=True)
class CoverageCase:
    case_id: str
    rule_id: str
    outcome: CaseOutcome
    tool: str
    asserted_code: str | None
    asserted_rule_id: str | None
    via: str | None = None
    history: Literal["not_used", "production_incomplete", "test_only_complete"] = "not_used"


def document(cases: Iterable[CoverageCase], linked_tests: Mapping[str, tuple[str, ...]]) -> dict[str, object]:
    cases = tuple(cases)
    rules = []
    for rule in RETAIL_RULES:
        own = sorted((case for case in cases if case.rule_id == rule.rule_id), key=lambda case: case.case_id)
        outcomes = sorted({case.outcome for case in own})
        entry: dict[str, object] = {
            "rule_id": rule.rule_id, "enforcement": rule.enforcement, "policy_lines": [rule.line_start, rule.line_end],
            "clause_sha256": rule.clause_sha256, "tools": [str(tool) for tool in rule.tools],
            "case_outcomes": outcomes,
            "cases": [{"case_id": case.case_id, "outcome": case.outcome, "tool": case.tool,
                       "asserted_code": case.asserted_code, "asserted_rule_id": case.asserted_rule_id,
                       "via": case.via, "history": case.history} for case in own],
            "linked_tests": list(linked_tests.get(rule.rule_id, ())),
        }
        if rule.enforcement == "not_codified":
            entry["uncovered_reason"] = rule.interpretation
        rules.append(entry)
    counts: dict[str, int] = {}
    for rule in RETAIL_RULES:
        counts[rule.enforcement] = counts.get(rule.enforcement, 0) + 1
    return {
        "schema": "policyops.policy-coverage/v1",
        "policy": RETAIL_POLICY.model_dump(mode="json"),
        "case_test": CASE_TEST,
        "case_source": "tests/support/policyops_testing/gateway_cases.py",
        "rule_counts": dict(sorted(counts.items())),
        "case_count": len(cases),
        "rules": rules,
    }


def render(cases: Iterable[CoverageCase], linked_tests: Mapping[str, tuple[str, ...]]) -> bytes:
    return (json.dumps(document(cases, linked_tests), indent=2, sort_keys=True) + "\n").encode("utf-8")
