"""Startup-fixed tool contracts; identity is deliberately absent from all arguments."""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, StringConstraints, TypeAdapter, ValidationError

from policyops.gateway import observations
from policyops.providers.canonical import CanonicalError, canonical_bytes, canonical_size
from policyops_contracts.base import WireModel
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import LookupObservation, ReadObservation, ToolError
from policyops_contracts.retail import (
    FindUserIdByEmail,
    FindUserIdByNameZip,
    GetItemDetails,
    GetOrderDetails,
    GetProductDetails,
    GetUserDetails,
    ListAllProductTypes,
)
from policyops_contracts.retrieval import SourceUri
from policyops_contracts.scalars import Sha256Hex


MAX_ARGUMENT_BYTES = 8192
MAX_RESULT_BYTES = 65536
MAX_FRAME_CHARS = 16384
RetailCall = (FindUserIdByEmail | FindUserIdByNameZip | GetUserDetails | GetOrderDetails | GetProductDetails
              | GetItemDetails | ListAllProductTypes)


class SearchPolicy(WireModel):
    query: Annotated[str, StringConstraints(min_length=1, max_length=2048, pattern=r"^[^\x00]+$")]


class Citation(WireModel):
    document_version_id: UUID
    chunk_id: UUID
    source_uri: SourceUri
    version: Annotated[int, Field(ge=1)]
    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(ge=0)]
    text: Annotated[str, StringConstraints(max_length=20000)]
    text_sha256: Sha256Hex


class PolicyObservation(WireModel):
    kind: Literal["policy"] = "policy"
    tool: Literal["search_policy"] = "search_policy"
    generation_id: UUID
    citations: Annotated[tuple[Citation, ...], Field(max_length=4)]
    claim_support_validated: Literal[False] = False


ReadObservationType = ReadObservation | LookupObservation | PolicyObservation | ToolError


class Result(WireModel):
    result: Annotated[ReadObservationType, Field(discriminator="kind")]


_RETAIL = TypeAdapter(RetailCall)
TOOLS: MappingProxyType[str, type[BaseModel]] = MappingProxyType({
    "find_user_id_by_email": FindUserIdByEmail,
    "find_user_id_by_name_zip": FindUserIdByNameZip,
    "get_user_details": GetUserDetails,
    "get_order_details": GetOrderDetails,
    "get_product_details": GetProductDetails,
    "get_item_details": GetItemDetails,
    "list_all_product_types": ListAllProductTypes,
    "search_policy": SearchPolicy,
})


def error(code: ErrorCode, detail: str, *, retryable: bool = False) -> Result:
    return Result(result=observations.error(code, detail, retryable=retryable))


def arguments(name: str, values: dict[str, Any]) -> RetailCall | SearchPolicy | Result:
    if name not in TOOLS:
        return error(ErrorCode.POLICY_UNSUPPORTED, "unsupported_tool")
    try:
        canonical_size(values, limit=MAX_ARGUMENT_BYTES, max_nodes=256)
        # The discriminator belongs to the server, even if it matches the requested tool.
        if "tool" in values:
            raise ValueError("extra field")
        raw = canonical_bytes(values if name == "search_policy" else {**values, "tool": name})
        if name == "search_policy":
            return SearchPolicy.model_validate_json(raw)
        return _RETAIL.validate_json(raw)
    except (CanonicalError, ValidationError, ValueError):
        return error(ErrorCode.INVALID_INPUT, "arguments_invalid")


def bounded(result: Result) -> Result:
    try:
        canonical_size(result.model_dump(mode="json"), limit=MAX_RESULT_BYTES, max_nodes=8192)
        return Result.model_validate_json(result.model_dump_json())
    except (CanonicalError, ValidationError, ValueError):
        return error(ErrorCode.UNAVAILABLE, "result_invalid_or_too_large")


def input_schema(name: str) -> dict[str, Any]:
    schema = TOOLS[name].model_json_schema()
    schema["properties"].pop("tool", None)
    return schema
