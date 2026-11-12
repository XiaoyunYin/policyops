"""Server-owned aggregate preparation limits, checked before provider histories or JSON decoding."""

from collections.abc import Iterable
from types import MappingProxyType

from pydantic import BaseModel

from policyops.providers.canonical import CanonicalError, canonical_size
from policyops.providers.contract import ContractGap
from policyops_contracts.model import Message, ModelRequest, ToolSpec


REQUEST_BOUNDS = MappingProxyType({"messages": 256, "parts": 2048, "nodes": 32768,
                                  "content_bytes": 256 * 1024, "body_bytes": 512 * 1024})


def _json_nodes(text: str) -> int:
    """Lexical upper-level work accounting before a JSON decoder allocates containers. Validation follows later."""
    nodes = depth = 0
    quoted = escaped = token = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            nodes += 1
            quoted, token = True, False
        elif char in "[{":
            nodes += 1
            depth += 1
            token = False
        elif char in "]}":
            depth -= 1
            token = False
        elif char in ",: \r\n\t":
            token = False
        elif not token:
            nodes += 1
            token = True
        if depth > 64 or nodes > REQUEST_BOUNDS["nodes"]:
            raise ContractGap("aggregate request structural bound exceeded")
    return nodes


def preflight_fields(instructions: str, messages: Iterable[Message], tools: Iterable[ToolSpec],
                     output: BaseModel | None = None) -> None:
    """Walk DTO fields without model_dump, provider dictionary construction or JSON/schema parsing."""
    content = parts = escaped = 0
    nodes = 16  # request framing, field names and fixed scalar controls

    def visit(item: object, field: str = "") -> None:
        nonlocal content, nodes, escaped
        nodes += 1
        if nodes > REQUEST_BOUNDS["nodes"]:
            raise ContractGap("aggregate request structural bound exceeded")
        if isinstance(item, str):
            for start in range(0, len(item), 1024):
                try:
                    content += len(item[start:start + 1024].encode("utf-8"))
                except UnicodeEncodeError:
                    raise ContractGap("invalid UTF-8 request text") from None
                if content > REQUEST_BOUNDS["content_bytes"]:
                    raise ContractGap("aggregate request content bound exceeded")
            if field.endswith("_json"):
                nodes += _json_nodes(item)
            try:
                escaped += canonical_size(item, limit=REQUEST_BOUNDS["body_bytes"])
            except CanonicalError as error:
                raise ContractGap("aggregate request escaped byte bound exceeded") from error
        elif isinstance(item, BaseModel):
            nodes += len(type(item).model_fields)  # object keys as well as values
            for name in type(item).model_fields:
                visit(getattr(item, name), name)
        elif isinstance(item, tuple):
            for child in item:
                visit(child)
        if nodes > REQUEST_BOUNDS["nodes"] or escaped > REQUEST_BOUNDS["body_bytes"]:
            raise ContractGap("aggregate request structural or escaped byte bound exceeded")

    visit(instructions)
    for count, message in enumerate(messages, start=1):
        parts += len(message.parts)
        if (not 1 <= len(message.parts) <= 64 or count > REQUEST_BOUNDS["messages"]
                or parts > REQUEST_BOUNDS["parts"]):
            raise ContractGap("aggregate request message or part bound exceeded")
        visit(message)
    for count, tool in enumerate(tools, start=1):
        if count > 32:
            raise ContractGap("aggregate request tool bound exceeded")
        visit(tool)
    visit(output)


def preflight(request: ModelRequest) -> None:
    preflight_fields(request.instructions, request.messages, request.tools, request.output)
