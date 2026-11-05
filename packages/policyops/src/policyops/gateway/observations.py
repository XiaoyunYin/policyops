"""Mapping deterministic outcomes to the model-facing `ToolObservation` (T17).

Every detail is fixed text, or domain text built only from validated identifiers and enumerated statuses.
Upstream free text (retail error detail, model text) is never forwarded.
"""

from __future__ import annotations

from policyops.domain.retail_rules import Denied, Escalated
from policyops.domain.session import Deny
from policyops.gateway.facts import FactsRefused
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import ToolError


def error(code: ErrorCode, detail: str, *, rule_id: str | None = None, retryable: bool = False) -> ToolError:
    return ToolError(code=code, rule_id=rule_id, detail=detail, retryable=retryable)


def denied(outcome: Deny | Denied) -> ToolError:
    return error(outcome.code, outcome.detail, rule_id=outcome.rule_id)


def escalated(outcome: Escalated) -> ToolError:
    """Outside what the policy or the pinned simulator supports: refuse and recommend a handoff."""
    return error(ErrorCode.POLICY_UNSUPPORTED, f"hand off to a human agent: {outcome.detail}", rule_id=outcome.rule_id)


def facts_refused(refusal: FactsRefused) -> ToolError:
    return error(refusal.code, refusal.detail, rule_id=refusal.rule_id, retryable=refusal.retryable)
