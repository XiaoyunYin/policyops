"""Fixed read surface and strict, bounded argument/result contracts."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError
import pytest

from policyops.mcp.contracts import TOOLS, Result, arguments, bounded, input_schema
from policyops_contracts.gateway import ReadObservation, ToolError
from policyops_contracts.retail_service import ProductType, ProductTypesOutput


def test_exact_fixed_read_list() -> None:
    assert set(TOOLS) == {"find_user_id_by_email", "find_user_id_by_name_zip", "get_user_details",
                          "get_order_details", "get_product_details", "get_item_details",
                          "list_all_product_types", "search_policy"}
    for name in TOOLS:
        schema = input_schema(name)
        assert schema["additionalProperties"] is False
        assert not {"tool", "tenant", "workspace_id", "principal_id", "role", "run_id"} & schema["properties"].keys()


@pytest.mark.parametrize("name,values", [
    ("get_order_details", {"order_id": 42}),
    ("get_order_details", {"order_id": "#W1006327", "role": "admin"}),
    ("get_order_details", {"order_id": "#W1006327", "tenant": "foreign"}),
    ("get_order_details", {"order_id": "#W1006327", "tool": "get_order_details"}),
    ("get_order_details", {}),
    ("search_policy", {"query": "x" * 2049}),
    ("search_policy", {"query": "x" * 100000}),
    ("search_policy", {"query": 42}),
    ("search_policy", {"query": "\x00"}),
    ("search_policy", {"query": [0] * 10000}),
    ("search_policy", {"query": "x", "corpus_key": "foreign"}),
])
def test_invalid_arguments(name: str, values: dict[str, Any]) -> None:
    result = arguments(name, values)
    assert isinstance(result, Result) and isinstance(result.result, ToolError)
    assert result.result.code == "invalid_input"


@pytest.mark.parametrize("name", ["unknown", "cancel_pending_order", "calculate", "transfer_to_human_agents"])
def test_unknown_and_nonread_tools(name: str) -> None:
    result = arguments(name, {})
    assert isinstance(result, Result) and isinstance(result.result, ToolError)
    assert result.result.code == "policy_unsupported"


def test_result_size_limit_does_not_truncate_or_leak_data() -> None:
    result = Result(result=ReadObservation(tool="list_all_product_types", case_version=1,
        output=ProductTypesOutput(types=tuple(ProductType(name="\U0001f600" * 190, product_id=str(1000000000 + i))
                                             for i in range(200)))))
    limited = bounded(result)
    assert isinstance(limited.result, ToolError)
    assert limited.result.detail == "result_invalid_or_too_large"


def test_result_rejects_actionable_proposal() -> None:
    with pytest.raises(ValidationError):
        Result.model_validate({"result": {"kind": "proposal_preview", "tool": "cancel_pending_order",
                                         "presentation": "do it", "actionable": False}})
