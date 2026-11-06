"""Upstream tool descriptors → strict `ToolDescriptor`/`ToolCatalog`, and the reverse argument mapping (T29).

Upstream `Tool.openai_schema` parameters are pydantic `model_json_schema()` output: objects are not closed, omittable
parameters are simply absent from `required` (usually with a `default`), and `title` annotations appear everywhere.
The providers' strict modes (and the application's T11 `check_schema`, which stays the runtime authority) need every
object closed and every property required. This module maps one onto the other without changing meaning, or refuses:

- **Bounded intake before any transformation.** A schema arrives as a mapping or as JSON text. Text is size-checked
  and nesting-checked, then parsed with duplicate keys, NaN/infinity literals and non-finite numbers (such as
  `1e400`) refused. Every input is then copied by an iterative walk that bounds depth, node count, collection sizes
  and total string bytes, refuses cycles and refuses text that is not representable as UTF-8 (unpaired surrogates).
  No recursive transformation or canonicalization ever sees an unbounded input, and the source is only read.
- **Per-kind keyword allowlists.** Each schema node may carry only the keywords that apply to its kind (object,
  array, string, integer/number, boolean/null, an untyped `enum`/`const`, a reference or a union). Everything is
  copied; any other keyword refuses the schema. Nothing is silently dropped except `default`, whose meaning becomes
  the omission plan.
- **Strictification.** Every object is closed (`additionalProperties: false`) and every property becomes required.
  Requiredness comes from the source `required` list, never from the presence of a `default`.
  - An originally omittable property that does not admit `null` becomes `anyOf[original, {"type": "null"}]`, and
    `null` then means "omit it" (upstream's own default applies).
  - An originally omittable property that already admits `null` is accepted **only at the parameters root** (a
    Python function parameter) and only with `default: null`. There, omitting the argument and passing `None` bind
    the same value, so `null` keeps one meaning. Anywhere nested (inside a dict value), presence can matter to the
    consumer, so it is refused, as is any other default.
  - A required property that admits `null` keeps `null` as a real value; the reverse mapping never drops it.
- **Also refused:** type lists, open or free-form objects, arrays without `items`, the untyped `{}` schema, non-integer
  numbers outside `default`, `enum`/`const` with non-scalar members, non-local or dangling references, `$defs` below
  the root, reference cycles, nested unions and unions with more than one object branch (or with several array
  branches when any of them has an omission plan; branches are classified after resolving every reference, with
  per-definition memos so classification work stays linear), and a resolved size
  (references inlined, as the wire projection does) beyond the bound. A description over 1,024 characters refuses
  the tool, and any refused tool refuses the whole catalog.
- **The reverse mapping** `to_upstream_arguments` parses the canonical arguments with the same strict parser and
  walks the immutable omission plan. It drops exactly the `null` values of originally omittable properties, at every
  object position (nested objects, array elements, references and nullable unions), and nothing else. It checks only
  what the plan needs (shape, finite numbers, encodable text): the values' schema constraints were validated by the
  application's T11 before they became an `AgentToolCall`. Banking's discoverable-tool `arguments` stays a string.

The local limits mirror T11's published ones (64 KiB, depth 16, 8 `anyOf` branches, 256 enum values, 200-character
patterns) so a refusal happens early, with a typed reason. They are not a copy of T11's validator: the application's
`prepare`/`check_schema` re-validates every descriptor at construction.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import math
from types import MappingProxyType
from typing import Literal

from pydantic import TypeAdapter, ValidationError

from policyops_contracts.conversation import MAX_SCHEMA_BYTES, ToolCatalog, ToolDescriptor
from policyops_contracts.model import Name


MAX_INPUT_BYTES = 65_536
MAX_DEPTH = 16
MAX_NODES = 4096
MAX_RESOLVED_NODES = 4096
MAX_COLLECTION = 256
MAX_STRING = 8192
MAX_PATTERN = 200
MAX_BRANCHES = 8
MAX_DEFS = 64
MAX_TOOLS = 64
MAX_DESCRIPTION = 1024
MAX_ARGUMENTS_BYTES = 65_536

RefusalCode = Literal[
    "input_type", "too_large", "too_deep", "too_many_nodes", "collection_too_large", "string_too_long", "cycle",
    "duplicate_key", "malformed_json", "non_finite", "unrepresentable_text", "float_number", "unsupported_keyword",
    "unsupported_type", "free_form_object", "open_object", "free_form_array", "required_invalid", "ref_invalid",
    "ref_cycle", "ref_expansion", "ambiguous_union", "nullable_default_mismatch", "nullable_omittable_nested",
    "pattern_too_long", "description_invalid", "name_invalid", "tool_type_invalid", "duplicate_tool",
    "too_many_tools", "catalog_invalid",
]
ArgumentsCode = Literal["too_large", "too_deep", "malformed_json", "duplicate_key", "non_finite",
                        "unrepresentable_text", "shape", "unknown_tool"]

ANNOTATIONS = frozenset({"title", "description", "default"})
KIND_KEYWORDS: Mapping[str, frozenset[str]] = MappingProxyType({
    "object": frozenset({"type", "properties", "required", "additionalProperties"}),
    "array": frozenset({"type", "items", "minItems", "maxItems", "uniqueItems"}),
    "string": frozenset({"type", "pattern", "minLength", "maxLength", "enum", "const"}),
    "integer": frozenset({"type", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "const"}),
    "number": frozenset({"type", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "const"}),
    "boolean": frozenset({"type", "enum", "const"}),
    "null": frozenset({"type", "enum", "const"}),
    "literal": frozenset({"enum", "const"}),     # an untyped node constrained only by enum/const
    "ref": frozenset({"$ref"}),
    "union": frozenset({"anyOf"}),
})
INTEGER_KEYWORDS = frozenset({"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength",
                              "minItems", "maxItems"})
ROOT_EXTRA = frozenset({"$defs", "$schema"})
DIALECT = "https://json-schema.org/draft/2020-12/schema"
REF_PREFIX = "#/$defs/"
READ_ONLY_TYPES = frozenset({"read"})  # only upstream ToolType.READ; its classification is conceptual, not proof
TOOL_TYPES = frozenset({"read", "write", "think", "generic"})

Json = None | bool | int | float | str | list["Json"] | dict[str, "Json"]
_NAME: TypeAdapter[str] = TypeAdapter(Name)


class SchemaRefused(ValueError):
    """A schema or tool cannot be represented faithfully. The message names a code and a bounded JSON path only."""

    def __init__(self, code: RefusalCode, path: str = "") -> None:
        self.code: RefusalCode = code
        self.path = path[:256].encode("utf-8", "replace").decode("utf-8")
        super().__init__(f"{code} at {self.path or '/'}")


class CatalogRefused(ValueError):
    """At least one tool was refused; no partial catalog is produced."""

    def __init__(self, refusals: Sequence[tuple[str, RefusalCode]]) -> None:
        self.refusals = tuple(refusals)[:MAX_TOOLS]
        super().__init__("; ".join(f"{name}: {code}" for name, code in self.refusals))


class ArgumentsRefused(ValueError):
    """Model arguments cannot be mapped back onto the upstream call (fixed code, no argument content)."""

    def __init__(self, code: ArgumentsCode) -> None:
        self.code: ArgumentsCode = code
        super().__init__(code)


# -- bounded intake --------------------------------------------------------------------------------------------

def _utf8_size(text: str, path: str = "") -> int:
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise SchemaRefused("unrepresentable_text", path) from None


def _scan_depth(text: str) -> None:
    """Container nesting of JSON text, outside strings, before any parse."""
    depth, in_string, escaped = 0, False, False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH + 1:
                raise SchemaRefused("too_deep")
        elif char in "]}":
            depth -= 1


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaRefused("duplicate_key")
        result[key] = value
    return result


def _no_constant(name: str) -> object:
    raise SchemaRefused("non_finite")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):  # an overflowing literal such as 1e400
        raise SchemaRefused("non_finite")
    return value


def parse_json_text(text: object, *, limit: int = MAX_INPUT_BYTES) -> object:
    """Strict, bounded JSON parse: size, encodability and nesting first; then duplicate keys, NaN/infinity literals
    and non-finite numbers are refused."""
    if not isinstance(text, str):
        raise SchemaRefused("input_type")
    if len(text) > limit or _utf8_size(text) > limit:
        raise SchemaRefused("too_large")
    _scan_depth(text)
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant, parse_float=_finite_float)
    except SchemaRefused:
        raise
    except (ValueError, RecursionError):
        raise SchemaRefused("malformed_json") from None


def bounded_copy(value: object) -> Json:
    """A fresh, plain JSON copy of `value`, built by an iterative walk that bounds everything before any recursion.
    Containers already on the current path are refused as cycles; the source is only read."""
    budget = {"nodes": 0, "bytes": 0}

    def scalar(item: object, path: str) -> Json:
        if item is None or isinstance(item, bool | int):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise SchemaRefused("non_finite", path)
            return item
        if isinstance(item, str):
            if len(item) > MAX_STRING:
                raise SchemaRefused("string_too_long", path)
            budget["bytes"] += _utf8_size(item, path)
            if budget["bytes"] > MAX_INPUT_BYTES:
                raise SchemaRefused("too_large", path)
            return item
        raise SchemaRefused("input_type", path)

    def container(item: object) -> bool:
        return isinstance(item, dict | list | tuple)

    if not container(value):
        return scalar(value, "")
    root: Json = {} if isinstance(value, dict) else []
    # Each frame: (source, target, path, depth, ancestors-by-id).
    stack: list[tuple[object, Json, str, int, frozenset[int]]] = [(value, root, "", 1, frozenset({id(value)}))]
    while stack:
        source, target, path, depth, ancestors = stack.pop()
        if depth > MAX_DEPTH + 1:
            raise SchemaRefused("too_deep", path)
        items: list[tuple[str | int, object]] = []
        if isinstance(source, dict):
            if len(source) > MAX_COLLECTION:
                raise SchemaRefused("collection_too_large", path)
            for key in source:
                if not isinstance(key, str):
                    raise SchemaRefused("input_type", path)
                items.append((key, source[key]))
        elif isinstance(source, list | tuple):
            if len(source) > MAX_COLLECTION:
                raise SchemaRefused("collection_too_large", path)
            items = list(enumerate(source))
        for key, child in items:
            budget["nodes"] += 1
            if budget["nodes"] > MAX_NODES:
                raise SchemaRefused("too_many_nodes", path)
            child_path = f"{path}/{key}"
            if isinstance(key, str):
                scalar(key, child_path)
            copied: Json
            if container(child):
                if id(child) in ancestors:
                    raise SchemaRefused("cycle", child_path)
                copied = {} if isinstance(child, dict) else []
                stack.append((child, copied, child_path, depth + 1, ancestors | {id(child)}))
            else:
                copied = scalar(child, child_path)
            if isinstance(target, dict):
                target[str(key)] = copied
            elif isinstance(target, list):
                target.append(copied)
    return root


def canonical_text(value: Json) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


# -- omission plans (immutable) -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class ScalarPlan:
    """No omittable position below: the value is copied as it is."""


@dataclass(frozen=True)
class FieldPlan:
    name: str
    omittable: bool  # originally omittable: `null` here means "omit"
    value: Plan


@dataclass(frozen=True)
class ObjectPlan:
    fields: tuple[FieldPlan, ...]

    def names(self) -> frozenset[str]:
        return frozenset(field.name for field in self.fields)


@dataclass(frozen=True)
class ArrayPlan:
    items: Plan


@dataclass(frozen=True)
class UnionPlan:
    nullable: bool
    object_branch: Plan | None  # at most one object branch (possibly a reference)
    array_branch: Plan | None   # the only array branch, when it has an omission plan


@dataclass(frozen=True)
class RefPlan:
    name: str


Plan = ScalarPlan | ObjectPlan | ArrayPlan | UnionPlan | RefPlan
SCALAR = ScalarPlan()


def resolve(plan: Plan, defs: Mapping[str, Plan]) -> Plan:
    """Follow a reference chain to its final plan (definitions are acyclic and at most `MAX_DEFS` long)."""
    for _ in range(MAX_DEFS + 1):
        if not isinstance(plan, RefPlan):
            return plan
        plan = defs[plan.name]
    raise SchemaRefused("ref_cycle")  # pragma: no cover - cycles are refused before any plan exists


def trivial(plan: Plan, defs: Mapping[str, Plan], memo: dict[str, bool] | None = None) -> bool:
    """True when no originally omittable property exists anywhere below (references resolved).

    Memoized per definition: each definition is classified once, so the work is linear in the plans themselves and
    never in their inlined expansion (a shared-definition DAG cannot make it exponential)."""
    memo = {} if memo is None else memo
    if isinstance(plan, RefPlan):
        if plan.name not in memo:
            memo[plan.name] = trivial(defs[plan.name], defs, memo)
        return memo[plan.name]
    if isinstance(plan, ScalarPlan):
        return True
    if isinstance(plan, ObjectPlan):
        return all(not f.omittable and trivial(f.value, defs, memo) for f in plan.fields)
    if isinstance(plan, ArrayPlan):
        return trivial(plan.items, defs, memo)
    return all(branch is None or trivial(branch, defs, memo) for branch in (plan.object_branch, plan.array_branch))


# -- strictification ---------------------------------------------------------------------------------------------

@dataclass
class _Context:
    defs_source: Mapping[str, Json]
    def_plans: dict[str, Plan]
    def_out: dict[str, Json]
    trivial_memo: dict[str, bool] = field(default_factory=dict)   # per definition, so classification stays linear
    null_memo: dict[str, bool] = field(default_factory=dict)


def _ref_name(ref: object, context: _Context, path: str) -> str:
    if not isinstance(ref, str) or not ref.startswith(REF_PREFIX):
        raise SchemaRefused("ref_invalid", path)
    name = ref[len(REF_PREFIX):]
    if name not in context.defs_source:
        raise SchemaRefused("ref_invalid", path)
    return name


def _admits_null(node: Json, context: _Context, hops: int = 0) -> bool:
    if hops > MAX_DEFS or not isinstance(node, dict):
        return False
    if node.get("type") == "null":
        return True
    if isinstance(node.get("enum"), list) and None in node["enum"]:  # type: ignore[operator]
        return True
    if "const" in node and node["const"] is None:
        return True
    if "$ref" in node:
        name = _ref_name(node["$ref"], context, "")
        if name not in context.null_memo:  # memoized per definition: linear, never per inlined path
            context.null_memo[name] = _admits_null(context.defs_source.get(name), context, hops + 1)
        return context.null_memo[name]
    branches = node.get("anyOf")
    return isinstance(branches, list) and any(_admits_null(b, context, hops) for b in branches)


def _kind(node: dict[str, Json], path: str) -> str:
    if "$ref" in node:
        return "ref"
    if "anyOf" in node:
        return "union"
    declared = node.get("type")
    if declared is None:
        if "properties" in node:
            return "object"
        if "enum" in node or "const" in node:
            return "literal"
        raise SchemaRefused("unsupported_type", path)  # the untyped `{}` (Any) schema
    if not isinstance(declared, str) or declared not in KIND_KEYWORDS or declared in ("literal", "ref", "union"):
        raise SchemaRefused("unsupported_type", f"{path}/type")
    return declared


def _literal(value: object, path: str) -> None:
    if isinstance(value, float):
        raise SchemaRefused("float_number", path)
    if isinstance(value, dict | list):
        raise SchemaRefused("unsupported_type", path)


def _node(node: Json, path: str, context: _Context, *, root: bool = False) -> tuple[Json, Plan]:
    if not isinstance(node, dict):
        raise SchemaRefused("unsupported_type", path)
    kind = _kind(node, path)
    allowed = KIND_KEYWORDS[kind] | ANNOTATIONS | (ROOT_EXTRA if root else frozenset())
    unknown = set(node) - allowed
    if unknown:
        raise SchemaRefused("unsupported_keyword", f"{path}/{sorted(unknown)[0]}")
    out: dict[str, Json] = {}
    item_plan: Plan = SCALAR
    for key in ("title", "description"):
        if key in node:
            if not isinstance(node[key], str):
                raise SchemaRefused("unsupported_type", f"{path}/{key}")
            out[key] = node[key]
    if kind == "ref":
        name = _ref_name(node["$ref"], context, path)
        out["$ref"] = REF_PREFIX + name
        return out, RefPlan(name)
    if kind == "union":
        return _union(node, out, path, context)
    if kind == "object":
        return _object(node, out, path, context, root=root)
    for key in sorted(KIND_KEYWORDS[kind] & set(node)):  # copy every applicable keyword; none is dropped
        value = node[key]
        key_path = f"{path}/{key}"
        if key in INTEGER_KEYWORDS:
            if isinstance(value, bool) or not isinstance(value, int):
                raise SchemaRefused("float_number", key_path)
        elif key == "uniqueItems":
            if not isinstance(value, bool):
                raise SchemaRefused("unsupported_type", key_path)
        elif key == "pattern":
            if not isinstance(value, str):
                raise SchemaRefused("unsupported_type", key_path)
            if len(value) > MAX_PATTERN:
                raise SchemaRefused("pattern_too_long", key_path)
        elif key == "enum":
            if not isinstance(value, list) or not value or len(value) > MAX_COLLECTION:
                raise SchemaRefused("collection_too_large", key_path)
            for index, item in enumerate(value):
                _literal(item, f"{key_path}/{index}")
        elif key == "const":
            _literal(value, key_path)
        elif key == "items":
            out["items"], item_plan = _node(value, key_path, context)
            continue
        out[key] = value
    if kind == "array":
        if "items" not in node:
            raise SchemaRefused("free_form_array", path)
        return out, ArrayPlan(item_plan)
    return out, SCALAR


def _branch_kind(plan: Plan, context: _Context) -> str:
    final = resolve(plan, context.def_plans)
    if isinstance(final, ObjectPlan):
        return "object"
    if isinstance(final, ArrayPlan):
        return "array"
    if isinstance(final, UnionPlan):
        return "union"
    return "scalar"


def _union(node: dict[str, Json], out: dict[str, Json], path: str, context: _Context) -> tuple[Json, Plan]:
    branches = node["anyOf"]
    if not isinstance(branches, list) or not 1 <= len(branches) <= MAX_BRANCHES:
        raise SchemaRefused("collection_too_large", f"{path}/anyOf")
    converted: list[Json] = []
    nullable = False
    objects: list[Plan] = []
    arrays: list[Plan] = []
    for index, branch in enumerate(branches):
        branch_path = f"{path}/anyOf/{index}"
        schema, plan = _node(branch, branch_path, context)
        converted.append(schema)
        nullable = nullable or _admits_null(branch, context)
        kind = _branch_kind(plan, context)  # classified after every reference is resolved
        if kind == "union":
            raise SchemaRefused("ambiguous_union", branch_path)
        if kind == "object":
            objects.append(plan)
        elif kind == "array":
            arrays.append(plan)
    if len(objects) > 1:
        raise SchemaRefused("ambiguous_union", f"{path}/anyOf")
    planned = [plan for plan in arrays if not trivial(plan, context.def_plans, context.trivial_memo)]
    if planned and len(arrays) > 1:
        # Array type alone cannot select the branch a value belongs to: with an omission plan in play, a value legal in
        # another array branch (for example an explicit required null) could lose a field. Refused, not guessed.
        raise SchemaRefused("ambiguous_union", f"{path}/anyOf")
    out["anyOf"] = converted
    return out, UnionPlan(nullable, objects[0] if objects else None, planned[0] if planned else None)


def _object(node: dict[str, Json], out: dict[str, Json], path: str, context: _Context, *, root: bool
            ) -> tuple[Json, Plan]:
    if node.get("additionalProperties", False) is not False:
        raise SchemaRefused("open_object", path)
    properties = node.get("properties")
    if properties is None:
        raise SchemaRefused("free_form_object", path)
    if not isinstance(properties, dict):
        raise SchemaRefused("unsupported_type", f"{path}/properties")
    required = node.get("required", [])
    if (not isinstance(required, list) or any(not isinstance(name, str) for name in required)
            or len(set(required)) != len(required) or not set(required) <= set(properties)):
        raise SchemaRefused("required_invalid", f"{path}/required")
    fields: list[FieldPlan] = []
    converted: dict[str, Json] = {}
    for name, child in properties.items():
        child_path = f"{path}/properties/{name}"
        schema, plan = _node(child, child_path, context)
        omittable = name not in required
        if omittable:
            if _admits_null(child, context):
                # `null` is already a legal value: one meaning only where omission provably binds the same value.
                if not root:
                    raise SchemaRefused("nullable_omittable_nested", child_path)
                if not (isinstance(child, dict) and "default" in child and child["default"] is None):
                    raise SchemaRefused("nullable_default_mismatch", child_path)
            else:
                schema = {"anyOf": [schema, {"type": "null"}]}
        converted[name] = schema
        fields.append(FieldPlan(name, omittable, plan))
    out.update(type="object", properties=converted, required=list(properties), additionalProperties=False)
    return out, ObjectPlan(tuple(fields))


def _ref_order(context: _Context) -> list[str]:
    """Definitions in dependency order; a reference cycle (including self-reference) is refused."""
    graph: dict[str, set[str]] = {}
    for name, schema in context.defs_source.items():
        refs: set[str] = set()
        pending: list[Json] = [schema]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                ref = item.get("$ref")
                if ref is not None:
                    refs.add(_ref_name(ref, context, f"/$defs/{name}"))
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        graph[name] = refs
    order: list[str] = []
    state: dict[str, int] = {}
    for start in graph:
        if state.get(start) == 2:
            continue
        stack: list[tuple[str, list[str]]] = [(start, sorted(graph[start]))]
        state[start] = 1
        while stack:
            name, todo = stack[-1]
            if todo:
                child = todo.pop()
                if state.get(child) == 1:
                    raise SchemaRefused("ref_cycle", f"/$defs/{child}")
                if state.get(child) != 2:
                    state[child] = 1
                    stack.append((child, sorted(graph[child])))
            else:
                state[name] = 2
                order.append(name)
                stack.pop()
    return order


def _resolved_size(root: dict[str, Json], defs_out: Mapping[str, Json], order: Sequence[str]) -> None:
    """Nodes and depth of the schema with every reference inlined (what a wire projection materializes), computed
    from per-definition memos so a tiny DAG with heavy fan-out is refused before anything expands it."""
    sizes: dict[str, tuple[int, int]] = {}

    def measure(node: Json) -> tuple[int, int]:
        count, depth = 0, 0
        pending: list[tuple[Json, int]] = [(node, 1)]
        while pending:
            item, level = pending.pop()
            if not isinstance(item, dict):
                continue
            ref = item.get("$ref")
            if isinstance(ref, str):
                inner_count, inner_depth = sizes[ref[len(REF_PREFIX):]]
                count += inner_count
                depth = max(depth, level + inner_depth)
            else:
                count += 1
                depth = max(depth, level)
                properties = item.get("properties")
                if isinstance(properties, dict):
                    pending.extend((child, level + 1) for child in properties.values())
                if "items" in item:
                    pending.append((item["items"], level + 1))
                branches = item.get("anyOf")
                if isinstance(branches, list):
                    pending.extend((child, level + 1) for child in branches)
            if count > MAX_RESOLVED_NODES or depth > MAX_DEPTH:
                raise SchemaRefused("ref_expansion")
        return count, depth

    for name in order:
        sizes[name] = measure(defs_out[name])
    measure({key: value for key, value in root.items() if key != "$defs"})


@dataclass(frozen=True)
class StrictSchema:
    schema_json: str                     # canonical text of the strict schema
    plan: ObjectPlan
    defs: Mapping[str, Plan]             # read-only
    source_sha256: str                   # canonical source schema


def strictify(source: object) -> StrictSchema:
    """The strict schema and omission plan for an upstream parameters schema (a mapping or JSON text)."""
    parsed = parse_json_text(source) if isinstance(source, str) else source
    root = bounded_copy(parsed)
    if not isinstance(root, dict):
        raise SchemaRefused("unsupported_type")
    if "$schema" in root and root["$schema"] != DIALECT:
        raise SchemaRefused("unsupported_keyword", "/$schema")
    source_text = canonical_text(root)
    if _utf8_size(source_text) > MAX_INPUT_BYTES:
        raise SchemaRefused("too_large")
    defs_source = root.get("$defs", {})
    if not isinstance(defs_source, dict) or len(defs_source) > MAX_DEFS:
        raise SchemaRefused("collection_too_large", "/$defs")
    context = _Context(defs_source, {}, {})
    order = _ref_order(context)
    for name in order:
        if not name or "/" in name or "~" in name:
            raise SchemaRefused("ref_invalid", f"/$defs/{name}")
        if isinstance(defs_source[name], dict) and set(defs_source[name]) & ROOT_EXTRA:  # type: ignore[arg-type]
            raise SchemaRefused("unsupported_keyword", f"/$defs/{name}")
        schema, plan = _node(defs_source[name], f"/$defs/{name}", context)
        context.def_out[name] = schema
        context.def_plans[name] = plan
    body = dict(root)
    if body.get("type", "object") != "object" or "anyOf" in body or "$ref" in body:
        raise SchemaRefused("unsupported_type", "/type")
    body.setdefault("type", "object")
    schema, plan = _node(body, "", context, root=True)
    if not isinstance(plan, ObjectPlan) or not isinstance(schema, dict):
        raise SchemaRefused("unsupported_type")  # pragma: no cover - the root is an object node
    schema.pop("$schema", None)
    if context.def_out:
        schema["$defs"] = dict(context.def_out)
    _resolved_size(schema, context.def_out, order)
    text = canonical_text(schema)
    if _utf8_size(text) > MAX_SCHEMA_BYTES:
        raise SchemaRefused("too_large")
    return StrictSchema(text, plan, MappingProxyType(dict(context.def_plans)),
                        hashlib.sha256(source_text.encode("utf-8")).hexdigest())


# -- tools and catalogs ------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolMapping:
    descriptor: ToolDescriptor
    tool_type: str
    schema: StrictSchema


@dataclass(frozen=True)
class CatalogMapping:
    catalog: ToolCatalog
    tools: Mapping[str, ToolMapping]     # read-only, by name

    def digest(self) -> str:
        return self.catalog.digest()


def map_tool(name: object, description: object, parameters: object, tool_type: object) -> ToolMapping:
    """One upstream tool's name, description (verbatim), parameters schema and upstream `ToolType` value."""
    if not isinstance(tool_type, str) or tool_type not in TOOL_TYPES:
        raise SchemaRefused("tool_type_invalid")
    if not isinstance(description, str) or not description or "\x00" in description \
            or len(description) > MAX_DESCRIPTION:
        raise SchemaRefused("description_invalid")
    try:
        _utf8_size(description)
    except SchemaRefused:
        raise SchemaRefused("description_invalid") from None
    try:
        checked_name = _NAME.validate_python(name, strict=True)
    except ValidationError:
        raise SchemaRefused("name_invalid") from None
    strict = strictify(parameters)
    try:
        descriptor = ToolDescriptor(name=checked_name, description=description,
                                    parameters_schema_json=strict.schema_json,
                                    read_only=tool_type in READ_ONLY_TYPES)
    except ValidationError:  # pragma: no cover - every field is checked above
        raise SchemaRefused("catalog_invalid") from None
    return ToolMapping(descriptor, tool_type, strict)


def upstream_tool_fields(tool: object) -> tuple[object, object, object, object]:
    """(name, description, parameters, tool type) from an upstream `Tool`, read without calling it: its
    `openai_schema` (what upstream sends to models) and its function's `__tool_type__` mark."""
    schema = getattr(tool, "openai_schema", None)
    function = schema.get("function") if isinstance(schema, dict) else None
    if not isinstance(function, dict) or function.get("name") != getattr(tool, "name", None):
        raise SchemaRefused("input_type")
    kind = getattr(getattr(tool, "_func", None), "__tool_type__", None)
    return function.get("name"), function.get("description"), function.get("parameters"), getattr(kind, "value", None)


def _label(name: object) -> str:
    """A refusal label: the tool name when it is a valid name, otherwise a fixed placeholder (never raw input)."""
    try:
        return _NAME.validate_python(name, strict=True)
    except ValidationError:
        return "?"


def map_upstream_tools(tools: Sequence[object], *, knowledge_tool: bool = False) -> CatalogMapping:
    """A descriptor catalog from upstream `Tool` objects (never called). Any refusal refuses the whole catalog."""
    if len(tools) > MAX_TOOLS:
        raise CatalogRefused([("*", "too_many_tools")])
    entries: list[tuple[object, object, object, object]] = []
    refusals: list[tuple[str, RefusalCode]] = []
    for tool in tools:
        try:
            entries.append(upstream_tool_fields(tool))
        except SchemaRefused as refusal:
            refusals.append((_label(getattr(tool, "name", None)), refusal.code))
    if refusals:
        raise CatalogRefused(refusals)
    return map_catalog(entries, knowledge_tool=knowledge_tool)


def map_catalog(tools: Sequence[tuple[object, object, object, object]], *, knowledge_tool: bool = False
                ) -> CatalogMapping:
    """A descriptor catalog from (name, description, parameters, tool type) entries. Any refusal refuses all."""
    if len(tools) > MAX_TOOLS:
        raise CatalogRefused([("*", "too_many_tools")])
    refusals: list[tuple[str, RefusalCode]] = []
    mapped: dict[str, ToolMapping] = {}
    for name, description, parameters, tool_type in tools:
        label = _label(name)
        if label in mapped:
            refusals.append((label, "duplicate_tool"))
            continue
        try:
            mapped[label] = map_tool(name, description, parameters, tool_type)
        except SchemaRefused as refusal:
            refusals.append((label, refusal.code))
    if refusals:
        raise CatalogRefused(refusals)
    try:
        catalog = ToolCatalog(mode="descriptor", tools=tuple(m.descriptor for m in mapped.values()),
                              knowledge_tool=knowledge_tool)
    except ValidationError:
        raise CatalogRefused([("*", "catalog_invalid")]) from None
    return CatalogMapping(catalog, MappingProxyType(mapped))


# -- reverse argument mapping ------------------------------------------------------------------------------------

def _copy_value(value: object, depth: int) -> object:
    if depth > MAX_DEPTH * 2:
        raise ArgumentsRefused("too_deep")
    if isinstance(value, dict):
        return {key: _copy_value(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_value(item, depth + 1) for item in value]
    if isinstance(value, float) and not math.isfinite(value):  # pragma: no cover - refused by the parser
        raise ArgumentsRefused("non_finite")
    return value


def _apply(value: object, plan: Plan, defs: Mapping[str, Plan], depth: int) -> object:
    if depth > MAX_DEPTH * 2:
        raise ArgumentsRefused("too_deep")
    plan = resolve(plan, defs)
    if isinstance(plan, ScalarPlan):
        return _copy_value(value, depth)
    if isinstance(plan, ObjectPlan):
        if not isinstance(value, dict) or set(value) != plan.names():
            raise ArgumentsRefused("shape")
        result: dict[str, object] = {}
        for field in plan.fields:
            item = value[field.name]
            if field.omittable and item is None:
                continue  # originally omittable: null means omit (upstream's default applies)
            result[field.name] = _apply(item, field.value, defs, depth + 1)
        return result
    if isinstance(plan, ArrayPlan):
        if not isinstance(value, list):
            raise ArgumentsRefused("shape")
        return [_apply(item, plan.items, defs, depth + 1) for item in value]
    if isinstance(plan, UnionPlan):
        if value is None:
            if not plan.nullable:
                raise ArgumentsRefused("shape")
            return None
        if isinstance(value, dict) and plan.object_branch is not None:
            return _apply(value, plan.object_branch, defs, depth + 1)
        if isinstance(value, list) and plan.array_branch is not None:
            return _apply(value, plan.array_branch, defs, depth + 1)
        return _copy_value(value, depth)
    raise ArgumentsRefused("shape")  # pragma: no cover - resolved plans are never references


def _check_text(value: object) -> None:
    """Every decoded key and string must be representable as UTF-8 (a JSON `\ud800` escape decodes to an unpaired
    surrogate). Iterative; the parse already bounded size and nesting."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                raise ArgumentsRefused("unrepresentable_text") from None


_ARGUMENT_CODES: Mapping[str, ArgumentsCode] = MappingProxyType({
    "too_large": "too_large", "too_deep": "too_deep", "duplicate_key": "duplicate_key", "non_finite": "non_finite",
    "unrepresentable_text": "unrepresentable_text",
})


def to_upstream_arguments(mapping: CatalogMapping, name: str, arguments_json: str) -> dict[str, object]:
    """The upstream `ToolCall.arguments` dict for canonical model arguments: strict parse, then the omission plan."""
    tool = mapping.tools.get(name)
    if tool is None:
        raise ArgumentsRefused("unknown_tool")
    try:
        parsed = parse_json_text(arguments_json, limit=MAX_ARGUMENTS_BYTES)
    except SchemaRefused as refusal:
        raise ArgumentsRefused(_ARGUMENT_CODES.get(refusal.code, "malformed_json")) from None
    _check_text(parsed)
    result = _apply(parsed, tool.schema.plan, tool.schema.defs, 0)
    if not isinstance(result, dict):  # pragma: no cover - the root plan is an object plan
        raise ArgumentsRefused("shape")
    return result
