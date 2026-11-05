"""Check actual HTTP responses against the committed OpenAPI document (T08).

`check_response` requires that the status is documented for the operation, that a JSON body validates against
the documented schema (and that undocumented responses have no body), and that the response headers the API
uses for its contract (ETag, Location, Idempotent-Replayed, Set-Cookie) are documented for that status. The
schema evaluator is deliberately small: it implements the keywords the exported document uses and raises on any
other keyword, so it cannot silently pass a schema it does not understand.
"""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Protocol
from uuid import UUID


DOCUMENT_PATH = Path(__file__).resolve().parents[3] / "packages" / "policyops" / "openapi" / "v1.json"
DOCUMENT: dict[str, Any] = json.loads(DOCUMENT_PATH.read_text(encoding="utf-8"))
ANNOTATIONS = {"title", "description", "default"}
KEYWORDS = {"$ref", "additionalProperties", "anyOf", "const", "enum", "format", "items", "maxLength", "maximum",
            "minLength", "minimum", "pattern", "properties", "required", "type"} | ANNOTATIONS
CONTRACT_HEADERS = ("etag", "location", "idempotent-replayed", "set-cookie")
TYPES: dict[str, type | tuple[type, ...]] = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
                                            "object": dict, "array": list}


class Reply(Protocol):
    """The parts of a test-client response the checks use (Starlette's TestClient returns httpx2 responses)."""

    @property
    def status_code(self) -> int: ...
    @property
    def headers(self) -> Any: ...
    @property
    def content(self) -> bytes: ...
    @property
    def text(self) -> str: ...
    def json(self) -> Any: ...


class SchemaMismatch(AssertionError):
    pass


def resolve(ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaMismatch(f"non-local $ref {ref}")
    node: Any = DOCUMENT
    for part in ref[2:].split("/"):
        node = node[part]
    return node  # type: ignore[no-any-return]


def _type_ok(name: str, value: Any) -> bool:
    if name == "null":
        return value is None
    if name in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, TYPES[name])


def _format_ok(name: str, value: str) -> bool:
    try:
        if name == "uuid":
            return str(UUID(value)) == value
        if name == "date-time":
            return datetime.fromisoformat(value).utcoffset() is not None
    except ValueError:
        return False
    raise SchemaMismatch(f"unsupported format {name}")


def validate(schema: dict[str, Any], value: Any, where: str = "$") -> None:
    unknown = set(schema) - KEYWORDS
    if unknown:
        raise SchemaMismatch(f"{where}: unsupported schema keywords {sorted(unknown)}")
    if "$ref" in schema:
        validate(resolve(schema["$ref"]), value, where)
    if "anyOf" in schema:
        failures = []
        for option in schema["anyOf"]:
            try:
                validate(option, value, where)
                break
            except SchemaMismatch as exc:
                failures.append(str(exc))
        else:
            raise SchemaMismatch(f"{where}: no anyOf branch matches ({'; '.join(failures)})")
    if "type" in schema and not _type_ok(schema["type"], value):
        raise SchemaMismatch(f"{where}: expected {schema['type']}, got {type(value).__name__}")
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        raise SchemaMismatch(f"{where}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaMismatch(f"{where}: {value!r} not in enum")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise SchemaMismatch(f"{where}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise SchemaMismatch(f"{where}: longer than {schema['maxLength']}")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise SchemaMismatch(f"{where}: does not match {schema['pattern']}")
        if "format" in schema and not _format_ok(schema["format"], value):
            raise SchemaMismatch(f"{where}: not a valid {schema['format']}")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaMismatch(f"{where}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaMismatch(f"{where}: above {schema['maximum']}")
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            validate(schema["items"], item, f"{where}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        missing = set(schema.get("required", ())) - set(value)
        if missing:
            raise SchemaMismatch(f"{where}: missing {sorted(missing)}")
        extra = set(value) - set(properties)
        if extra and schema.get("additionalProperties", True) is False:
            raise SchemaMismatch(f"{where}: undocumented properties {sorted(extra)}")
        for name, item in value.items():
            if name in properties:
                validate(properties[name], item, f"{where}.{name}")


def check_response(response: Reply, method: str, template: str) -> str:
    """Raise `SchemaMismatch` unless the response matches the documented operation; return its operationId."""
    operation = DOCUMENT["paths"][template][method.lower()]
    documented = operation["responses"].get(str(response.status_code))
    if documented is None:
        raise SchemaMismatch(f"{method} {template}: status {response.status_code} is not documented")
    content = documented.get("content")
    if content is None:
        if response.content:
            raise SchemaMismatch(f"{method} {template} {response.status_code}: undocumented body")
    elif "text/event-stream" in content:
        if not str(response.headers.get("content-type", "")).startswith("text/event-stream"):
            raise SchemaMismatch(f"{method} {template} {response.status_code}: not text/event-stream")
    else:
        if response.headers.get("content-type") != "application/json":
            raise SchemaMismatch(f"{method} {template} {response.status_code}: not application/json")
        validate(content["application/json"]["schema"], response.json(), f"{operation['operationId']}")
    headers = {name.lower() for name in documented.get("headers", {})}
    present = {name for name in CONTRACT_HEADERS if name in response.headers}
    if present - headers:
        raise SchemaMismatch(f"{method} {template} {response.status_code}: undocumented headers "
                             f"{sorted(present - headers)}")
    return str(operation["operationId"])
