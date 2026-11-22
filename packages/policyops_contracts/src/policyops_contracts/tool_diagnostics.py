"""Bounded metadata describing a rejected tool argument."""

from typing import Literal

from policyops_contracts.base import WireModel
from policyops_contracts.retail import ToolName


ConstraintKind = Literal["pattern", "missing", "extra_field", "type", "enum", "too_long", "too_short", "range", "shape"]


DiagnosticTool = ToolName | Literal["finish_answer"]
ArgumentField = Literal[
    "arguments", "email", "first_name", "last_name", "zip", "user_id", "order_id", "product_id",
    "item_id", "expression", "summary", "reason", "address1", "address2", "city", "state", "country",
    "payment_method_id", "item_ids", "new_item_ids", "v", "outcome", "assertions", "assertions.text",
    "assertions.policy_dependent", "assertions.citations", "assertions.citations.step",
    "assertions.citations.evidence_id", "assertions.citations.quote", "assertions.citations.start",
    "assertions.citations.end", "abstention", "abstention.reason", "abstention.detail",
]


class ToolArgumentIssue(WireModel):
    tool: DiagnosticTool
    field: ArgumentField
    constraint: ConstraintKind
