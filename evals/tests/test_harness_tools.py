"""T29 tool-descriptor compatibility: strict schemas with exact omission semantics, bounded intake, honest refusals,
and the actual pinned upstream retail and banking (no_knowledge) tool inventories.

Pure checks run in-process and never import upstream. The pinned inventory is built in a fresh isolated interpreter
(upstream import side effects disabled, an empty TAU2_DATA_DIR, the network guard installed, file opens audited and
every upstream tool call trapped) so this module can never fix upstream's data directory for later evaluator tests.
"""

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from policyops_evals.harness import tools
from policyops_evals.harness.tools import (
    ArgumentsRefused,
    CatalogRefused,
    SchemaRefused,
    map_catalog,
    map_tool,
    strictify,
    to_upstream_arguments,
)


REPO = Path(__file__).resolve().parents[2]

# The child is a fresh isolated interpreter whose venv `.pth` entries point at whichever checkout the venv was built
# from. CHILD_PRELUDE routes first-party imports to the checkout that holds THESE tests (the roots in argv[1]), drops
# every other sys.path entry that provides a first-party package, refuses preloaded first-party modules, and reports
# each exercised module's file and SHA-256 so the parent can prove the bytes it tested.
CHILD_PRELUDE = r"""
import hashlib, json, os, sys
ROOTS = [os.path.realpath(root) for root in json.loads(sys.argv[1])]
FIRST_PARTY = ("policyops_evals", "policyops_contracts", "policyops_testing", "policyops")
assert not [m for m in sys.modules if m.split(".")[0] in FIRST_PARTY], "a first-party module was preloaded"
def _provides(entry):
    return any(os.path.isdir(os.path.join(entry, name)) for name in FIRST_PARTY)
sys.path[:] = ROOTS + [p for p in sys.path if os.path.realpath(p or ".") not in ROOTS and not _provides(p or ".")]
def binding(names):
    report = {}
    for name in names:
        path = os.path.realpath(sys.modules[name].__file__)
        with open(path, "rb") as handle:
            report[name] = {"file": path, "sha256": hashlib.sha256(handle.read()).hexdigest()}
    return report
"""
ROOTS = [REPO / "evals" / "src", REPO / "packages" / "policyops_contracts" / "src", REPO / "tests" / "support"]


def child_argv(script: str) -> list[str]:
    return [sys.executable, "-I", "-B", "-X", "utf8", "-c", CHILD_PRELUDE + script, json.dumps([str(r) for r in ROOTS])]


def assert_bound_to_this_checkout(report: dict[str, Any], expected: set[str]) -> None:
    """Every exercised first-party module came from this checkout, with exactly the bytes beside these tests."""
    assert set(report) == expected
    for name, entry in report.items():
        path = Path(entry["file"])
        assert any(path.is_relative_to(root.resolve()) for root in ROOTS), (name, entry["file"])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], name


def obj(properties: dict[str, Any], required: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"type": "object", "properties": properties, **extra}
    if required is not None:
        body["required"] = required
    return body


def strict(schema: object) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(strictify(schema).schema_json)
    return loaded


def refused(schema: object) -> str:
    with pytest.raises(SchemaRefused) as caught:
        strictify(schema)
    return caught.value.code


def catalog_of(parameters: dict[str, Any], name: str = "act") -> tools.CatalogMapping:
    return map_catalog([(name, "Act (fictional).", parameters, "write")])


def back(parameters: dict[str, Any], arguments: object) -> dict[str, object]:
    return to_upstream_arguments(catalog_of(parameters), "act", json.dumps(arguments))


# -- strictification and omission semantics ------------------------------------------------------------------------

def test_every_object_is_closed_and_required_while_original_omittability_becomes_null_means_omit() -> None:
    source = obj({"a": {"type": "string", "title": "A"}, "b": {"type": "integer", "default": 3}}, ["a"],
                 title="parameters")
    out = strict(source)
    assert out == {"type": "object", "title": "parameters", "additionalProperties": False, "required": ["a", "b"],
                   "properties": {"a": {"type": "string", "title": "A"},
                                  "b": {"anyOf": [{"type": "integer"}, {"type": "null"}]}}}
    assert back(source, {"a": "x", "b": None}) == {"a": "x"}  # upstream's default (3) then applies
    assert back(source, {"a": "x", "b": 4}) == {"a": "x", "b": 4}
    assert back(source, {"a": None, "b": 4}) == {"a": None, "b": 4}  # never dropped: `a` was required


def test_requiredness_comes_from_the_source_list_not_from_a_default_annotation() -> None:
    source = obj({"a": {"type": "string", "default": "x"}}, ["a"])
    assert strict(source)["properties"]["a"] == {"type": "string"}  # required stays required, default consumed
    assert back(source, {"a": "y"}) == {"a": "y"}
    with pytest.raises(ArgumentsRefused, match="shape"):
        back(source, {})


def test_nested_optional_arguments_round_trip_at_every_object_position() -> None:
    inner = obj({"v": {"type": "string"}, "w": {"type": "string", "default": "z"}}, ["v"])
    source = obj({"payload": {"$ref": "#/$defs/Inner"},
                  "rows": {"type": "array", "items": {"$ref": "#/$defs/Inner"}},
                  "grid": {"type": "array", "items": {"type": "array", "items": {"$ref": "#/$defs/Inner"}}}},
                 ["payload", "rows", "grid"], **{"$defs": {"Inner": inner}})
    out = strict(source)
    assert out["$defs"]["Inner"]["required"] == ["v", "w"]
    assert out["$defs"]["Inner"]["properties"]["w"] == {"anyOf": [{"type": "string"}, {"type": "null"}]}
    arguments = {"payload": {"v": "1", "w": None}, "rows": [{"v": "2", "w": None}, {"v": "3", "w": "q"}],
                 "grid": [[{"v": "4", "w": None}]]}
    assert back(source, arguments) == {"payload": {"v": "1"}, "rows": [{"v": "2"}, {"v": "3", "w": "q"}],
                                       "grid": [[{"v": "4"}]]}


def test_required_null_is_a_real_value_and_root_default_null_is_the_only_accepted_omittable_null() -> None:
    nullable = {"anyOf": [{"type": "string"}, {"type": "null"}]}
    required_null = obj({"n": nullable}, ["n"])
    assert back(required_null, {"n": None}) == {"n": None}
    root_default = obj({"n": {**nullable, "default": None}}, [])
    assert strict(root_default)["properties"]["n"] == nullable  # already nullable: no second null branch
    assert back(root_default, {"n": None}) == {}  # a Python parameter defaulting to None binds the same value
    assert refused(obj({"n": {**nullable, "default": "x"}}, [])) == "nullable_default_mismatch"
    assert refused(obj({"n": nullable}, [])) == "nullable_default_mismatch"


def test_a_nested_omittable_nullable_property_is_refused_because_presence_can_matter() -> None:
    """Review regression (draft finding 2): {payload: {value: null}} must never silently become {payload: {}}."""
    inner = obj({"value": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None}}, [])
    assert refused(obj({"payload": inner}, ["payload"])) == "nullable_omittable_nested"
    assert refused(obj({"payload": {"$ref": "#/$defs/I"}}, ["payload"], **{"$defs": {"I": inner}})) == \
        "nullable_omittable_nested"


def test_reference_chains_inside_unions_keep_their_omission_plan() -> None:
    """Review regression (draft finding 3): anyOf[ref A, null] with A -> ref B -> object."""
    b = obj({"value": {"type": "string"}}, [])
    source = obj({"payload": {"anyOf": [{"$ref": "#/$defs/A"}, {"type": "null"}]}}, ["payload"],
                 **{"$defs": {"A": {"$ref": "#/$defs/B"}, "B": b}})
    assert back(source, {"payload": {"value": None}}) == {"payload": {}}
    assert back(source, {"payload": {"value": "x"}}) == {"payload": {"value": "x"}}
    assert back(source, {"payload": None}) == {"payload": None}  # the union's own null is a real value
    arrays = obj({"xs": {"anyOf": [{"type": "array", "items": {"$ref": "#/$defs/A"}}, {"type": "null"}]}}, ["xs"],
                 **{"$defs": {"A": {"$ref": "#/$defs/B"}, "B": b}})
    assert back(arrays, {"xs": [{"value": None}, {"value": "y"}]}) == {"xs": [{}, {"value": "y"}]}


def test_ambiguous_unions_are_refused_after_resolving_references() -> None:
    a, b = obj({"x": {"type": "string"}}, ["x"]), obj({"y": {"type": "string"}}, ["y"])
    assert refused(obj({"u": {"anyOf": [{"$ref": "#/$defs/A"}, {"$ref": "#/$defs/B"}]}}, ["u"],
                       **{"$defs": {"A": a, "B": b}})) == "ambiguous_union"
    assert refused(obj({"u": {"anyOf": [{"$ref": "#/$defs/U"}, {"type": "null"}]}}, ["u"],
                       **{"$defs": {"U": {"anyOf": [{"type": "string"}, {"type": "integer"}]}}})) == "ambiguous_union"
    planned = obj({"o": {"type": "string", "default": "d"}}, [])
    assert refused(obj({"u": {"anyOf": [{"type": "array", "items": planned},
                                        {"type": "array", "items": {"$ref": "#/$defs/P"}}]}}, ["u"],
                       **{"$defs": {"P": planned}})) == "ambiguous_union"
    scalar_union = obj({"u": {"anyOf": [{"type": "string"}, {"type": "integer"}]}}, ["u"])
    assert back(scalar_union, {"u": 3}) == {"u": 3}


def test_applicable_constraints_are_copied_and_inapplicable_or_unsupported_ones_refuse() -> None:
    """Review regression (draft finding 1): nothing that constrains a value may be silently dropped."""
    source = obj({"s": {"type": "string", "pattern": "^[a-z]+$", "minLength": 1, "maxLength": 9, "enum": ["ab", "c"]},
                  "i": {"type": "integer", "minimum": 0, "maximum": 5, "const": 3},
                  "xs": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 4,
                         "uniqueItems": True},
                  "lit": {"enum": ["only"]}}, ["s", "i", "xs", "lit"])
    out = strict(source)["properties"]
    for name, schema in source["properties"].items():
        assert out[name] == schema, name  # every applicable keyword survives exactly
    for bad, code in [({"type": "array", "items": {"type": "string"}, "enum": [["allowed"]]}, "unsupported_keyword"),
                      ({"type": "array", "items": {"type": "string"}, "const": ["allowed"]}, "unsupported_keyword"),
                      ({"type": "string", "minimum": 1}, "unsupported_keyword"),
                      ({"type": "integer", "pattern": "^1$"}, "unsupported_keyword"),
                      ({"type": "string", "format": "email"}, "unsupported_keyword"),
                      ({"type": "number", "minimum": 0.5}, "float_number"),
                      ({"type": "string", "enum": [["x"]]}, "unsupported_type"),
                      ({"type": ["string", "null"]}, "unsupported_type"),
                      ({}, "unsupported_type"),
                      ({"type": "object"}, "free_form_object"),
                      (obj({}, additionalProperties=True), "open_object"),
                      ({"type": "array"}, "free_form_array"),
                      ({"type": "string", "pattern": "a" * 201}, "pattern_too_long")]:
        assert refused(obj({"p": bad}, ["p"])) == code, bad
    assert refused(obj({"p": {"type": "string"}}, ["q"])) == "required_invalid"


def test_references_must_be_local_acyclic_and_bounded_when_resolved() -> None:
    defs = {"$defs": {"A": {"type": "string"}}}
    assert refused(obj({"p": {"$ref": "https://example.invalid/s#/A"}}, ["p"], **defs)) == "ref_invalid"
    assert refused(obj({"p": {"$ref": "#/$defs/Missing"}}, ["p"], **defs)) == "ref_invalid"
    assert refused(obj({"p": {"$ref": "#/$defs/A", "minLength": 1}}, ["p"], **defs)) == "unsupported_keyword"
    assert refused(obj({"p": obj({"q": {"type": "string"}}, ["q"], **defs)}, ["p"])) == "unsupported_keyword"
    self_ref = {"$defs": {"N": obj({"next": {"$ref": "#/$defs/N"}}, ["next"])}}
    assert refused(obj({"p": {"$ref": "#/$defs/N"}}, ["p"], **self_ref)) == "ref_cycle"
    mutual = {"$defs": {"A": obj({"b": {"$ref": "#/$defs/B"}}, ["b"]), "B": obj({"a": {"$ref": "#/$defs/A"}}, ["a"])}}
    assert refused(obj({"p": {"$ref": "#/$defs/A"}}, ["p"], **mutual)) == "ref_cycle"
    # Repeated fan-out: 13 tiny definitions, each referencing the next twice, inline to over 2**12 nodes.
    fan = {f"D{i}": obj({"l": {"$ref": f"#/$defs/D{i + 1}"}, "r": {"$ref": f"#/$defs/D{i + 1}"}}, ["l", "r"])
           for i in range(12)} | {"D12": {"type": "string"}}
    source = obj({"p": {"$ref": "#/$defs/D0"}}, ["p"], **{"$defs": fan})
    assert len(json.dumps(source)) < 2000 and refused(source) == "ref_expansion"
    shallow = {f"D{i}": obj({"l": {"$ref": f"#/$defs/D{i + 1}"}}, ["l"]) for i in range(5)} | {"D5": {"type": "string"}}
    assert strict(obj({"p": {"$ref": "#/$defs/D0"}}, ["p"], **{"$defs": shallow}))["required"] == ["p"]


def test_several_array_branches_are_refused_when_any_of_them_has_an_omission_plan() -> None:
    """Review regression (findings-c1-1, 1): {rows: [{x: null}]} is legal in the required-null branch, so choosing the
    omitting branch by array type alone would drop `x`."""
    omitting = {"type": "array", "items": obj({"x": {"type": "string"}}, [])}
    required_null = {"type": "array", "items": obj({"x": {"anyOf": [{"type": "string"}, {"type": "null"}]}}, ["x"])}
    assert refused(obj({"rows": {"anyOf": [omitting, required_null]}}, ["rows"])) == "ambiguous_union"
    assert refused(obj({"rows": {"anyOf": [required_null, omitting]}}, ["rows"])) == "ambiguous_union"
    nullable_array = obj({"rows": {"anyOf": [omitting, {"type": "null"}]}}, ["rows"])
    assert back(nullable_array, {"rows": [{"x": None}, {"x": "a"}]}) == {"rows": [{}, {"x": "a"}]}
    assert back(nullable_array, {"rows": None}) == {"rows": None}
    plain_arrays = obj({"v": {"anyOf": [{"type": "array", "items": {"type": "string"}},
                                        {"type": "array", "items": required_null["items"]}]}}, ["v"])
    assert back(plain_arrays, {"v": [{"x": None}]}) == {"v": [{"x": None}]}  # no omission plan: copied as it is


def test_plan_classification_work_is_linear_in_shared_definitions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review regression (findings-c1-1, 2): six 8-way layers of shared definitions under a nullable array would
    revisit subplans exponentially; with per-definition memos the work stays tiny and the configured resolved-size
    refusal follows. A hard visit cap aborts instead of expanding if that ever regresses."""
    layers = {f"L{i}": obj({f"f{j}": {"$ref": f"#/$defs/L{i + 1}"} for j in range(8)}, [f"f{j}" for j in range(8)])
              for i in range(6)} | {"L6": {"type": "string"}}
    source = obj({"rows": {"anyOf": [{"type": "array", "items": {"$ref": "#/$defs/L0"}}, {"type": "null"}]}},
                 ["rows"], **{"$defs": layers})
    assert len(json.dumps(source)) < 4000
    visits = {"trivial": 0, "_admits_null": 0}

    def capped(name: str) -> Any:
        original = getattr(tools, name)

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            visits[name] += 1
            if visits[name] > 500:
                raise AssertionError(f"{name} exceeded the visit cap")
            return original(*args, **kwargs)
        return wrapper

    for name in visits:
        monkeypatch.setattr(tools, name, capped(name))
    assert refused(source) == "ref_expansion"
    assert 0 < visits["trivial"] <= 100 and visits["_admits_null"] <= 100, visits


# -- bounded intake ------------------------------------------------------------------------------------------------

def nested(depth: int) -> dict[str, Any]:
    node: dict[str, Any] = {"type": "string"}
    for _ in range(depth):
        node = obj({"x": node}, ["x"])
    return node


def test_malformed_duplicate_oversize_deep_cyclic_and_non_finite_inputs_are_refused_before_work() -> None:
    assert refused('{"type": "object", "properties": {}, "type": "object"}') == "duplicate_key"
    assert refused('{"type": "object", "properties": {') == "malformed_json"
    assert refused('{"a": NaN}') == "non_finite"
    assert refused('{"a": 1e400}') == "non_finite"  # draft finding 6: overflow is not a number
    assert refused(" " * (tools.MAX_INPUT_BYTES + 1)) == "too_large"
    assert refused("[" * 40 + "]" * 40) == "too_deep"
    assert refused(nested(30)) == "too_deep"
    cyclic: dict[str, Any] = obj({}, [])
    cyclic["properties"]["self"] = cyclic
    assert refused(cyclic) == "cycle"
    assert refused(obj({f"p{i}": {"type": "string"} for i in range(300)}, [])) == "collection_too_large"
    wide = obj({f"p{i}": {"type": "string", "enum": list(range(200))} for i in range(30)}, [])
    assert refused(wide) == "too_many_nodes"
    assert refused(obj({"p": {"type": "string", "description": "x" * (tools.MAX_STRING + 1)}}, ["p"])) == \
        "string_too_long"
    assert refused(obj({"p": {"type": "number", "default": float("inf")}}, [])) == "non_finite"
    assert refused(obj({"p": {"type": "string", "title": "\ud800"}}, ["p"])) == "unrepresentable_text"
    assert refused(obj({"\udfff": {"type": "string"}}, [])) == "unrepresentable_text"  # draft finding 5
    assert refused('{"type": "object", "properties": {"p": {"type": "string", "title": "\\ud800"}}}') == \
        "unrepresentable_text"
    assert refused([1]) == "unsupported_type" and refused(object()) == "input_type"


def test_the_source_schema_is_never_mutated_and_results_are_immutable() -> None:
    source = obj({"a": {"type": "string", "default": "x", "title": "A"}, "b": {"$ref": "#/$defs/B"}}, ["b"],
                 **{"$defs": {"B": obj({"c": {"type": "integer", "default": 1}}, [])}})
    before = copy.deepcopy(source)
    mapped = strictify(source)
    assert source == before
    with pytest.raises(FrozenInstanceError):
        mapped.schema_json = "{}"  # type: ignore[misc]
    with pytest.raises(TypeError):
        mapped.defs["B"] = tools.SCALAR  # type: ignore[index]
    assert strictify(json.dumps(source)) == mapped  # text and mapping inputs agree exactly


# -- tools, catalogs and argument refusals ------------------------------------------------------------------------

PARAMS = obj({"order_id": {"type": "string"}}, ["order_id"])


def test_tool_identity_and_read_only_classification_are_exact() -> None:
    description = "Get the order.\n\nArgs: the order id (fictional)."
    expected = {"read": True, "write": False, "generic": False, "think": False}  # draft finding 4: READ only
    for kind, read_only in expected.items():
        mapped = map_tool("get_order", description, PARAMS, kind)
        assert (mapped.descriptor.name, mapped.descriptor.description, mapped.descriptor.read_only, mapped.tool_type) \
            == ("get_order", description, read_only, kind)
    for name, desc, kind, code in [("get_order", description, "admin", "tool_type_invalid"),
                                   ("get_order", "x" * 1025, "read", "description_invalid"),
                                   ("get_order", "", "read", "description_invalid"),
                                   ("get_order", "bad\ud800", "read", "description_invalid"),
                                   ("9bad name", description, "read", "name_invalid")]:
        with pytest.raises(SchemaRefused) as caught:
            map_tool(name, desc, PARAMS, kind)
        assert caught.value.code == code


def test_any_refused_tool_refuses_the_whole_catalog_and_limits_include_the_knowledge_tool() -> None:
    good = ("get_order", "Get the order.", PARAMS, "read")
    with pytest.raises(CatalogRefused) as caught:
        map_catalog([good, ("open", "Open.", {"type": "object"}, "write"), good])
    assert caught.value.refusals == (("open", "free_form_object"), ("get_order", "duplicate_tool"))
    many = [(f"t{i}", "T.", PARAMS, "read") for i in range(32)]
    assert len(map_catalog(many).catalog.all_tools()) == 32
    with pytest.raises(CatalogRefused, match="catalog_invalid"):
        map_catalog(many, knowledge_tool=True)
    assert map_catalog(many[:31], knowledge_tool=True).catalog.all_tools()[-1].name == "search_policy"


def test_argument_mapping_refuses_malformed_or_mismatched_arguments_with_fixed_codes() -> None:
    mapping = catalog_of(obj({"a": {"type": "number"}, "b": {"type": "string", "default": "d"}}, ["a"]))
    assert to_upstream_arguments(mapping, "act", '{"a": 1.5, "b": null}') == {"a": 1.5}
    for text, code in [('{"a": 1, "b": null, "c": 2}', "shape"), ('{"a": 1}', "shape"), ("[1]", "shape"),
                       ('{"a": 1, "a": 2, "b": null}', "duplicate_key"), ('{"a": NaN, "b": null}', "non_finite"),
                       ('{"a": 1e400, "b": null}', "non_finite"), ('{"a": 1, "b": "\\ud800"}', "unrepresentable_text"),
                       ("{", "malformed_json"), (" " * 70_000, "too_large")]:
        with pytest.raises(ArgumentsRefused) as caught:
            to_upstream_arguments(mapping, "act", text)
        assert caught.value.code == code, text
    with pytest.raises(ArgumentsRefused, match="unknown_tool"):
        to_upstream_arguments(mapping, "search_policy", "{}")


# -- the actual pinned upstream inventories -----------------------------------------------------------------------

INVENTORY = r"""
import warnings
from policyops_testing import network
network.install()
OPENS, ACTIVE = [], [False]
def audit(event, args):
    if ACTIVE[0] and event == "open" and isinstance(args[0], (str, bytes)):
        OPENS.append(os.fsdecode(args[0]))
sys.addaudithook(audit)
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from tau2.environment.tool import Tool
    from tau2.domains.retail.tools import RetailTools
    from tau2.domains.banking_knowledge.retrieval_toolkits import KnowledgeToolsPlain
    from tau2.domains.banking_knowledge.tools import KnowledgeUserTools
CALLS = []
Tool.__call__ = lambda self, *a, **k: CALLS.append(self.name)
Tool._call = lambda self, *a, **k: CALLS.append(self.name)
from policyops_evals.harness import tools as T
ACTIVE[0] = True
result = {}
for label, kit in (("retail", RetailTools(None)), ("banking_agent", KnowledgeToolsPlain(None)),
                   ("banking_user", KnowledgeUserTools(None))):
    upstream = list(kit.get_tools().values())
    before = [json.dumps(t.openai_schema, sort_keys=True) for t in upstream]
    mapping = T.map_upstream_tools(upstream, knowledge_tool=label == "banking_agent")
    entries = {}
    for tool, raw in zip(upstream, before):
        m = mapping.tools[tool.name]
        function = json.loads(raw)["function"]
        entries[tool.name] = {
            "kit_type": kit.tool_type(tool.name).value, "type": m.tool_type, "read_only": m.descriptor.read_only,
            "description_verbatim": m.descriptor.description == function["description"],
            "description_len": len(function["description"]),
            "schema_bytes": len(m.descriptor.parameters_schema_json.encode()),
            "omittable": sorted(f.name for f in m.schema.plan.fields if f.omittable),
            "required_source": sorted(function["parameters"].get("required", [])),
            "properties": sorted(function["parameters"]["properties"]),
            "strict": json.loads(m.descriptor.parameters_schema_json)}
    result[label] = {"names": [t.name for t in upstream], "catalog_sha256": mapping.digest(),
                     "catalog_tools": [t.name for t in mapping.catalog.all_tools()], "entries": entries,
                     "unchanged": before == [json.dumps(t.openai_schema, sort_keys=True) for t in upstream]}
    if label == "banking_agent":
        result[label]["call_omitted"] = T.to_upstream_arguments(
            mapping, "call_discoverable_agent_tool", '{"agent_tool_name":"x","arguments":null}')
        result[label]["call_kept"] = T.to_upstream_arguments(
            mapping, "call_discoverable_agent_tool", '{"agent_tool_name":"x","arguments":"{\\"a\\":1}"}')
ACTIVE[0] = False
print(json.dumps({"inventory": result, "opens": OPENS, "tool_calls": CALLS, "binding": binding(
    ["policyops_evals", "policyops_evals.harness", "policyops_evals.harness.tools", "policyops_contracts",
     "policyops_contracts.conversation", "policyops_testing.network"])}))
"""


def run_upstream(script: str, data_dir: Path) -> dict[str, Any]:
    env = {**os.environ, "TAU2_DATA_DIR": str(data_dir)}
    done = subprocess.run(child_argv(script), env=env, cwd=data_dir, capture_output=True, text=True,
                          encoding="utf-8", timeout=300, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    loaded: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    return loaded


@pytest.fixture(scope="module")
def pinned(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    empty = tmp_path_factory.mktemp("empty-tau2-data")
    loaded = run_upstream(INVENTORY, empty)
    # Retained evidence (written before any binding assertion): the child's exact module sources and hashes.
    record = {"id": "inventory", "source_root": str(REPO), "modules": loaded["binding"]}
    (empty / "child-binding-inventory.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    return loaded


def test_the_pinned_inventories_map_completely_without_data_execution_or_mutation(pinned: dict[str, Any]) -> None:
    assert_bound_to_this_checkout(pinned["binding"], {
        "policyops_evals", "policyops_evals.harness", "policyops_evals.harness.tools", "policyops_contracts",
        "policyops_contracts.conversation", "policyops_testing.network"})
    assert pinned["opens"] == [] and pinned["tool_calls"] == []
    inventory = pinned["inventory"]
    assert {label: part["catalog_sha256"] for label, part in inventory.items()} == {
        "retail": "81f711b32afdb7d6dbc27c7f707c6c44ca7ad461aac341de85b663f199698bc0",
        "banking_agent": "f72abea31212879109d32f2cfcc423319e052d79666bbbf34cafe5df87d3882e",
        "banking_user": "c3e126f7b48d08c1d6629563da5b553083704145d273a2a5c215b47904547548",
    }
    assert {label: len(part["names"]) for label, part in inventory.items()} == \
        {"retail": 16, "banking_agent": 14, "banking_user": 6}
    for label, part in inventory.items():
        assert part["unchanged"], label
        assert part["catalog_tools"][:len(part["names"])] == part["names"]  # upstream order and names, exactly
        for name, entry in part["entries"].items():
            assert entry["type"] == entry["kit_type"] and entry["description_verbatim"], name
            assert entry["read_only"] is (entry["kit_type"] == "read"), name
            assert entry["description_len"] <= 1024 and entry["schema_bytes"] <= 16_384, name
            assert entry["omittable"] == sorted(set(entry["properties"]) - set(entry["required_source"])), name
            strict_schema = entry["strict"]
            assert strict_schema["additionalProperties"] is False, name
            assert sorted(strict_schema["required"]) == entry["properties"], name
    assert inventory["banking_agent"]["catalog_tools"][-1] == "search_policy"
    assert {label: max(e["description_len"] for e in part["entries"].values()) for label, part in inventory.items()} \
        == {"retail": 548, "banking_agent": 350, "banking_user": 328}


def test_pinned_optional_arguments_keep_upstream_semantics(pinned: dict[str, Any]) -> None:
    agent = pinned["inventory"]["banking_agent"]
    omittable = {name: e["omittable"] for name, e in agent["entries"].items() if e["omittable"]}
    assert omittable == {"call_discoverable_agent_tool": ["arguments"], "give_discoverable_user_tool": ["arguments"],
                         "transfer_to_human_agents": ["reason"]}
    arguments = agent["entries"]["call_discoverable_agent_tool"]["strict"]["properties"]["arguments"]
    assert arguments["anyOf"][0]["type"] == "string" and arguments["anyOf"][1] == {"type": "null"}
    assert agent["call_omitted"] == {"agent_tool_name": "x"}  # upstream's own default "{}" then applies
    assert agent["call_kept"] == {"agent_tool_name": "x", "arguments": '{"a":1}'}  # still a JSON string
    reason = agent["entries"]["transfer_to_human_agents"]["strict"]["properties"]["reason"]
    assert len(reason["anyOf"][0]["enum"]) == 19 and reason["anyOf"][1] == {"type": "null"}
    assert pinned["inventory"]["banking_user"]["entries"]["apply_for_credit_card"]["omittable"] == \
        ["rho_bank_subscription"]
    assert all(not e["omittable"] for e in pinned["inventory"]["retail"]["entries"].values())


def test_the_child_prelude_routes_first_party_imports_away_from_the_venv_checkout(tmp_path: Path) -> None:
    """Selftest: a fake package under the given roots wins over the venv's editable `.pth` checkout, which a plain
    isolated child (no prelude) would import instead."""
    fake = tmp_path / "fake-checkout"
    (fake / "policyops_evals").mkdir(parents=True)
    (fake / "policyops_evals" / "__init__.py").write_text('MARK = "fake-checkout"\n', encoding="utf-8")
    probe = ("import json, policyops_evals\n"
             "print(json.dumps([policyops_evals.__file__, policyops_evals.__dict__.get('MARK')]))")
    routed = subprocess.run([sys.executable, "-I", "-B", "-X", "utf8", "-c", CHILD_PRELUDE + probe,
                             json.dumps([str(fake)])],
                            capture_output=True, text=True, encoding="utf-8", timeout=120, check=False)
    assert routed.returncode == 0, routed.stderr[-1000:]
    routed_file, mark = json.loads(routed.stdout.strip().splitlines()[-1])
    assert Path(routed_file).resolve().is_relative_to(fake.resolve()) and mark == "fake-checkout"
    plain = subprocess.run([sys.executable, "-I", "-B", "-X", "utf8", "-c", probe], capture_output=True, text=True,
                           encoding="utf-8", timeout=120, check=False)
    assert plain.returncode == 0, plain.stderr[-1000:]
    plain_file, plain_mark = json.loads(plain.stdout.strip().splitlines()[-1])
    assert plain_mark is None and not Path(plain_file).resolve().is_relative_to(fake.resolve())
