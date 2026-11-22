"""Allowlisted paths and fixed feedback for workbench argument validation."""

from pydantic import ValidationError

from policyops_contracts.retail import ToolName
from policyops_contracts.tool_diagnostics import ArgumentField, ConstraintKind, DiagnosticTool, ToolArgumentIssue


_ADDRESS: tuple[ArgumentField, ...] = ("address1", "address2", "city", "state", "country", "zip")
_ITEM_WRITE: tuple[ArgumentField, ...] = ("order_id", "item_ids", "payment_method_id")
_FIELDS: dict[DiagnosticTool, tuple[ArgumentField, ...]] = {
    ToolName.FIND_USER_ID_BY_EMAIL: ("email",),
    ToolName.FIND_USER_ID_BY_NAME_ZIP: ("first_name", "last_name", "zip"),
    ToolName.GET_USER_DETAILS: ("user_id",),
    ToolName.GET_ORDER_DETAILS: ("order_id",),
    ToolName.GET_PRODUCT_DETAILS: ("product_id",),
    ToolName.GET_ITEM_DETAILS: ("item_id",),
    ToolName.LIST_ALL_PRODUCT_TYPES: (),
    ToolName.CALCULATE: ("expression",),
    ToolName.TRANSFER_TO_HUMAN_AGENTS: ("summary",),
    ToolName.CANCEL_PENDING_ORDER: ("order_id", "reason"),
    ToolName.MODIFY_PENDING_ORDER_ADDRESS: ("order_id", *_ADDRESS),
    ToolName.MODIFY_PENDING_ORDER_PAYMENT: ("order_id", "payment_method_id"),
    ToolName.MODIFY_PENDING_ORDER_ITEMS: (*_ITEM_WRITE, "new_item_ids"),
    ToolName.RETURN_DELIVERED_ORDER_ITEMS: _ITEM_WRITE,
    ToolName.EXCHANGE_DELIVERED_ORDER_ITEMS: (*_ITEM_WRITE, "new_item_ids"),
    ToolName.MODIFY_USER_ADDRESS: ("user_id", *_ADDRESS),
    "finish_answer": (
        "v", "outcome", "assertions", "assertions.text", "assertions.policy_dependent", "assertions.citations",
        "assertions.citations.step", "assertions.citations.evidence_id", "assertions.citations.quote",
        "assertions.citations.start", "assertions.citations.end", "abstention", "abstention.reason",
        "abstention.detail",
    ),
}
_ERROR_KINDS: dict[str, ConstraintKind] = {
    "string_pattern_mismatch": "pattern",
    "missing": "missing",
    "extra_forbidden": "extra_field",
    "string_type": "type",
    "int_type": "type",
    "bool_type": "type",
    "tuple_type": "type",
    "model_type": "type",
    "json_invalid": "type",
    "literal_error": "enum",
    "string_too_long": "too_long",
    "too_long": "too_long",
    "string_too_short": "too_short",
    "too_short": "too_short",
    "greater_than_equal": "range",
    "less_than_equal": "range",
    "value_error": "shape",
}
_GUIDANCE: dict[ConstraintKind, str] = {
    "pattern": "Use the required format.",
    "missing": "Provide the required field.",
    "extra_field": "Use only the listed fields.",
    "type": "Use the JSON type in the tool schema.",
    "enum": "Use one of the listed values.",
    "too_long": "Shorten the value or list.",
    "too_short": "Provide a nonempty value or list.",
    "range": "Use a value within the allowed range.",
    "shape": "Check how the arguments fit together.",
}
ORDER_ID_DESCRIPTION = "For order IDs, include the leading #, e.g. #W0000000."
USER_ID_DESCRIPTION = "For user IDs, use the user_id returned by the authenticated lookup."
_FIELD_GUIDANCE: dict[tuple[ArgumentField, ConstraintKind], str] = {
    ("order_id", "pattern"): ORDER_ID_DESCRIPTION,
    ("user_id", "pattern"): USER_ID_DESCRIPTION,
    ("zip", "pattern"): "Use a five-digit ZIP as a string.",
    ("assertions.citations.evidence_id", "pattern"): "Use the evidence ID from search_policy.",
    ("assertions.citations", "shape"): "Omit both offsets or provide both offsets spanning the quote.",
}
NOTICE_TABLE = {
    (tool, field, kind): f"[runtime notice] {tool}.{field} ({kind}). "
                         + _FIELD_GUIDANCE.get((field, kind), guidance)
    for tool, fields in _FIELDS.items()
    for field in ("arguments", *fields)
    for kind, guidance in _GUIDANCE.items()
}


def argument_issue(name: str, error: ValidationError | None = None, *,
                   constraint: ConstraintKind = "type") -> ToolArgumentIssue | None:
    tool: DiagnosticTool
    try:
        tool = "finish_answer" if name == "finish_answer" else ToolName(name)
    except ValueError:
        return None
    if error is None:
        return ToolArgumentIssue(tool=tool, field="arguments", constraint=constraint)
    issue = error.errors(include_url=False, include_context=False, include_input=False)[0]
    kind = _ERROR_KINDS.get(issue["type"], "type")
    location = issue["loc"] if tool == "finish_answer" else issue["loc"][1:]
    if kind == "extra_field":
        location = location[:-1]  # the last segment is an untrusted key
    path = ".".join(part for part in location if isinstance(part, str))
    field: ArgumentField = next((field for field in _FIELDS[tool] if field == path), "arguments")
    return ToolArgumentIssue(tool=tool, field=field, constraint=kind)
