"""Verify the shared policy rule table against the pinned retail policy bytes.

Every rule's 1-based line range must hash (UTF-8, lines joined by "\\n") to its
recorded `clause_sha256`, and the policy file must be the pinned blob. The
report also lists non-blank, non-heading policy lines that no rule cites, so
reviewers can see what is intentionally uncovered (mostly data-model prose).
"""

from __future__ import annotations

from typing import Any

from policyops_contracts.policy import RETAIL_POLICY, RETAIL_RULES
from policyops_evals import upstream
from policyops_evals.canonical import ManifestError, sha256_bytes


def trace_policy(policy: bytes) -> dict[str, Any]:
    if RETAIL_POLICY.source_commit != upstream.COMMIT or RETAIL_POLICY.path != upstream.RETAIL_POLICY:
        raise ManifestError("the contract policy reference is not the pinned upstream policy")
    if sha256_bytes(policy) != RETAIL_POLICY.sha256:
        raise ManifestError("policy bytes are not the pinned retail policy")
    lines = policy.decode("utf-8").split("\n")
    covered: set[int] = set()
    for rule in RETAIL_RULES:
        if rule.line_end > len(lines):
            raise ManifestError(f"{rule.rule_id}: line range is outside the policy")
        text = "\n".join(lines[rule.line_start - 1:rule.line_end])
        if sha256_bytes(text.encode("utf-8")) != rule.clause_sha256:
            raise ManifestError(f"{rule.rule_id}: clause hash does not match the pinned policy lines")
        covered.update(range(rule.line_start, rule.line_end + 1))
    uncovered = [number for number, line in enumerate(lines, 1)
                 if line.strip() and not line.startswith("#") and number not in covered]
    enforcement: dict[str, int] = {}
    for rule in RETAIL_RULES:
        enforcement[rule.enforcement] = enforcement.get(rule.enforcement, 0) + 1
    return {"policy_sha256": RETAIL_POLICY.sha256, "rules": len(RETAIL_RULES), "verified": len(RETAIL_RULES),
            "enforcement": dict(sorted(enforcement.items())), "uncovered_content_lines": uncovered}
