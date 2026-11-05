r"""Local JSON Schema checking and validation for tool arguments and structured results (T11).

The pinned `jsonschema` 4.26.0 validates with the Draft 2020-12 rules. The local validator is the authority: an SDK
response object or a provider's "strict" mode is never taken as proof that output matches.

**Domain schemas** (for example a pydantic model's `model_json_schema()`) are refused when registered unless they
stay inside a bounded, supported subset:
- **Keywords:** only the ones listed in `DOMAIN_KEYWORDS`; anything else is refused, never silently ignored.
- **References:** only local `#/$defs/<name>`, with no remote, file or URL resolution, and no `$id`.
- **Objects:** every object has `additionalProperties: false`, and every property is required (what the providers'
  strict modes need).
- **Size:** depth ≤ 16, ≤ 8 `anyOf` branches, ≤ 256 enum values, canonical size ≤ 64 KiB.
- **Patterns:** a `pattern` is ≤ 200 characters and is matched by **pydantic-core's Rust regex engine**, never
  Python's backtracking `re`. That engine runs in linear time; for example `^(a+)+$` against 5000 `a` and a `!` is
  immediate. It refuses lookaround and backreferences, so such a schema is refused when it is registered.
  - Matching is a search, as JSON Schema's `pattern` is: anchor with `^…$`.
  - Character classes follow the Rust engine; for example `\d` includes Unicode digits. That is the same engine
    pydantic uses when the retail DTOs validate the same fields.
- **Numbers:** integer literals only (the strict canonical subset). Instances follow the dialect: an integral
  number such as `1.0` is an integer, a bool is never a number, and nothing is coerced.

**Wire projection.** Each provider receives a documented projection: local references inlined, and value
constraints the wire form does not carry (`pattern`, lengths, bounds, `uniqueItems`, `title`, `default`) removed.
The projection and its list of removed keywords are part of the prepared request. The full domain schema is always
validated locally on the result, and the final domain DTO validation follows on top. A projection is never
presented as the full original.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
import re
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import SchemaError, ValidationError
from pydantic_core import SchemaError as PatternError
from pydantic_core import SchemaValidator, core_schema
from referencing import Registry

from policyops.providers.canonical import CanonicalError, canonical_bytes, fresh


def _is_integer(_checker: object, instance: object) -> bool:
    # JSON Schema: an integer is any mathematically integral number; a bool is never a number.
    if isinstance(instance, bool):
        return False
    if isinstance(instance, int):
        return True
    return isinstance(instance, Decimal) and instance.is_finite() and instance == instance.to_integral_value()


def _is_number(_checker: object, instance: object) -> bool:
    if isinstance(instance, bool):
        return False
    return isinstance(instance, int) or (isinstance(instance, Decimal) and instance.is_finite())


# Model output is parsed with exact decimals (`canonical.strict_loads`), never binary floats, so nothing is rounded
# before validation; `const`/`enum` use jsonschema's equality, which keeps true distinct from 1.
@lru_cache(maxsize=256)
def _engine(pattern: str) -> SchemaValidator:
    """The linear-time Rust regex engine of pydantic-core (search semantics). Raises for unsupported syntax."""
    return SchemaValidator(core_schema.str_schema(pattern=pattern))


def _pattern(validator: Any, pattern: str, instance: object, schema: object) -> Any:
    if isinstance(instance, str) and not _engine(pattern).isinstance_python(instance):
        yield ValidationError("does not match the pattern")


ExactValidator = validators.extend(
    Draft202012Validator,
    validators={"pattern": _pattern},  # never Python's backtracking `re`
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine_many({"integer": _is_integer, "number": _is_number}))


class SchemaGap(ValueError):
    """The schema uses something outside the supported subset; it is refused before any request is sent."""


DOMAIN_KEYWORDS = frozenset({
    "$schema", "$defs", "$ref", "type", "properties", "required", "additionalProperties", "items", "enum", "const",
    "anyOf", "description", "title", "default", "pattern", "minLength", "maxLength", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "minItems", "maxItems", "uniqueItems",
})
WIRE_KEYWORDS = frozenset({"type", "properties", "required", "additionalProperties", "items", "enum", "const",
                           "anyOf", "description"})
DIALECT = "https://json-schema.org/draft/2020-12/schema"
MAX_DEPTH, MAX_BRANCHES, MAX_ENUM, MAX_BYTES, MAX_PATTERN = 16, 8, 256, 65_536, 200
LOCAL_REF = re.compile(r"#/\$defs/([A-Za-z0-9_.-]{1,64})")


def _walk(node: object, defs: Mapping[str, object], depth: int, *, at_root: bool = False) -> None:
    if depth > MAX_DEPTH:
        raise SchemaGap("schema nested too deeply")
    if not isinstance(node, dict):
        raise SchemaGap("every subschema is an object")
    unknown = set(node) - DOMAIN_KEYWORDS
    if unknown:
        raise SchemaGap(f"unsupported keywords {sorted(unknown)}")
    if "$schema" in node and (not at_root or node["$schema"] != DIALECT):
        raise SchemaGap("only the Draft 2020-12 dialect, declared at the root")
    if "$defs" in node and not at_root:
        raise SchemaGap("$defs only at the root")
    if "$ref" in node:
        ref = node["$ref"]
        match = LOCAL_REF.fullmatch(ref) if isinstance(ref, str) else None
        if match is None or match.group(1) not in defs:
            raise SchemaGap("only local #/$defs references")
        if set(node) - {"$ref", "description", "title", "default"}:
            raise SchemaGap("a reference has no sibling constraints")
    kind = node.get("type")
    if kind == "object" or "properties" in node:
        properties = node.get("properties", {})
        if node.get("additionalProperties") is not False:
            raise SchemaGap("every object sets additionalProperties: false")
        if not isinstance(properties, dict) or sorted(node.get("required", [])) != sorted(properties):
            raise SchemaGap("every object property is required")
        for child in properties.values():
            _walk(child, defs, depth + 1)
    if "items" in node:
        _walk(node["items"], defs, depth + 1)
    if "anyOf" in node:
        branches = node["anyOf"]
        if not isinstance(branches, list) or not 1 <= len(branches) <= MAX_BRANCHES:
            raise SchemaGap(f"anyOf has 1-{MAX_BRANCHES} branches")
        for branch in branches:
            _walk(branch, defs, depth + 1)
    if "enum" in node and (not isinstance(node["enum"], list) or len(node["enum"]) > MAX_ENUM):
        raise SchemaGap(f"enum has at most {MAX_ENUM} values")
    if "pattern" in node:
        pattern = node["pattern"]
        if not isinstance(pattern, str) or len(pattern) > MAX_PATTERN:
            raise SchemaGap(f"a pattern has at most {MAX_PATTERN} characters")
        try:
            _engine(pattern)
        except PatternError as error:
            raise SchemaGap("the pattern is not supported by the linear-time regex engine") from error


def _inline(node: object, defs: Mapping[str, object], depth: int) -> object:
    """The wire projection: local references inlined, only wire keywords kept."""
    if depth > MAX_DEPTH:
        raise SchemaGap("schema nested too deeply")
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        match = LOCAL_REF.fullmatch(node["$ref"])
        if match is None:
            raise SchemaGap("only local #/$defs references")
        target = dict(defs[match.group(1)])  # type: ignore[call-overload]
        if "description" in node:
            target["description"] = node["description"]
        return _inline(target, defs, depth + 1)
    out: dict[str, object] = {}
    for key, value in node.items():
        if key not in WIRE_KEYWORDS:
            continue
        if key == "properties":
            out[key] = {name: _inline(child, defs, depth + 1) for name, child in value.items()}
        elif key == "items":
            out[key] = _inline(value, defs, depth + 1)
        elif key == "anyOf":
            out[key] = [_inline(branch, defs, depth + 1) for branch in value]
        else:
            out[key] = value
    return out


def _dropped(node: object, found: set[str]) -> None:
    if isinstance(node, dict):
        found.update(key for key in node if key not in WIRE_KEYWORDS and key not in ("$defs", "$ref", "$schema"))
        for value in node.values():
            _dropped(value, found)
    elif isinstance(node, list):
        for value in node:
            _dropped(value, found)


@dataclass(frozen=True)
class CheckedSchema:
    """A registered domain schema: canonical bytes, its wire projection and what the projection leaves out."""

    domain: bytes
    wire: bytes
    projected_away: tuple[str, ...]

    def validator(self) -> Any:
        # An empty registry: nothing outside this document can be resolved, and nothing is fetched.
        return ExactValidator(fresh(self.domain), registry=Registry())


def check_schema(schema_json: str) -> CheckedSchema:
    try:
        schema = fresh(schema_json.encode())
        domain = canonical_bytes(schema)
    except CanonicalError as error:
        raise SchemaGap(f"schema outside the canonical subset: {error}") from error
    if len(domain) > MAX_BYTES:
        raise SchemaGap("schema too large")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise SchemaGap("the root schema is an object")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        raise SchemaGap("not a valid Draft 2020-12 schema") from error
    defs = schema.get("$defs", {})
    if not isinstance(defs, dict):
        raise SchemaGap("$defs is an object")
    for definition in defs.values():
        _walk(definition, MappingProxyType(defs), 1)
    _walk(schema, MappingProxyType(defs), 0, at_root=True)
    found: set[str] = set()
    _dropped(schema, found)
    wire = canonical_bytes(_inline(schema, defs, 0))
    return CheckedSchema(domain, wire, tuple(sorted(found)))


def validation_errors(checked: CheckedSchema, instance: Any, *, limit: int = 5) -> tuple[str, ...]:
    """Error locations and failed keywords only: never the instance's content."""
    errors = []
    for error in checked.validator().iter_errors(instance):
        path = "/".join(str(part) for part in error.absolute_path)
        errors.append(f"{error.validator}@/{path}")
        if len(errors) >= limit:
            break
    return tuple(errors)
