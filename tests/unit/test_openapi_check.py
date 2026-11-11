"""The response-schema evaluator behind `check_response`: exact oneOf/discriminator/item bounds, and refusal (never a
silent pass) of anything it cannot decide. Pure; the real HTTP responses are checked by the integration tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest

from policyops.domain.examples import World
from policyops.domain.retail_rules import propose
from policyops.persistence.repositories import ProposalRow
from policyops.services import proposal_views as views
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import CancelPendingOrder, ModifyPendingOrderItems
from policyops_testing import openapi_check
from policyops_testing.openapi_check import DOCUMENT, FORMATS, KEYWORDS, SchemaMismatch, UnsupportedSchema, validate


INTEGER = {"type": "integer"}
STRING = {"type": "string"}
NUMBER = {"type": "number"}


def refused(schema: dict[str, Any], value: Any) -> str:
    with pytest.raises(SchemaMismatch) as caught:
        validate(schema, value)
    assert not isinstance(caught.value, UnsupportedSchema), "a decidable mismatch was reported as unsupported"
    return str(caught.value)


def undecidable(schema: dict[str, Any], value: Any) -> None:
    with pytest.raises(UnsupportedSchema):
        validate(schema, value)


# -- anyOf / oneOf cardinality ---------------------------------------------------------------------------------------

def test_one_of_requires_exactly_one_matching_branch() -> None:
    validate({"oneOf": [INTEGER, STRING]}, 1)
    validate({"oneOf": [INTEGER, STRING]}, "x")
    assert "0 oneOf branches match" in refused({"oneOf": [INTEGER, STRING]}, None)
    assert "2 oneOf branches match" in refused({"oneOf": [INTEGER, NUMBER]}, 1)  # 1 is both an integer and a number
    refused({"oneOf": []}, 1)


def test_any_of_accepts_one_or_more_matches_and_refuses_none() -> None:
    validate({"anyOf": [INTEGER, NUMBER]}, 1)
    validate({"anyOf": [INTEGER, {"type": "null"}]}, None)
    assert "no anyOf branch matches" in refused({"anyOf": [INTEGER, STRING]}, None)


UNSUPPORTED_BRANCHES = {
    "keyword": {"not": INTEGER},
    "nested keyword": {"type": "object", "properties": {"a": {"allOf": [INTEGER]}}},
    "format": {"type": "string", "format": "email"},
    "type": {"type": "decimal"},
    "non-local ref": {"$ref": "https://example.test/schema.json"},
    "unresolvable ref": {"$ref": "#/components/schemas/NoSuchSchema"},
}


@pytest.mark.parametrize("keyword", ("oneOf", "anyOf"))
@pytest.mark.parametrize("branch", UNSUPPORTED_BRANCHES.values(), ids=UNSUPPORTED_BRANCHES)
def test_an_undecidable_branch_is_an_error_even_after_a_branch_matched(keyword: str, branch: dict[str, Any]) -> None:
    """A branch that cannot be evaluated is not a non-match: with it, neither 'exactly one' nor 'at least one' is
    established, so the unsupported branch must surface whatever the value and whichever branch comes first."""
    value = {"a": 1}
    matching = {"type": "object", "required": ["a"]}
    undecidable({keyword: [matching, branch]}, value)
    undecidable({keyword: [branch, matching]}, value)
    # The same branches are fine to leave out: the schema is the problem, not the value.
    validate({keyword: [matching]}, value)


def test_a_format_it_does_not_know_is_refused_even_for_a_value_the_format_would_ignore() -> None:
    undecidable({"type": "string", "format": "email"}, "someone@example.test")
    undecidable({"format": "email"}, 7)
    refused({"type": "string", "format": "uuid"}, "not-a-uuid")
    validate({"type": "string", "format": "uuid"}, "00000000-0000-0000-0000-000000000001")
    refused({"type": "string", "format": "date-time"}, "2026-01-01T00:00:00")  # no offset: not a UTC-bearing instant
    validate({"type": "string", "format": "date-time"}, "2026-01-01T00:00:00Z")


def test_additional_properties_other_than_a_boolean_is_not_silently_ignored() -> None:
    undecidable({"type": "object", "additionalProperties": INTEGER}, {"a": "not an integer"})
    refused({"type": "object", "additionalProperties": False}, {"a": 1})
    validate({"type": "object", "additionalProperties": True}, {"a": 1})


# -- discriminator ---------------------------------------------------------------------------------------------------

@pytest.fixture
def tagged(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Branches told apart by their required keys, not by the tag, so the discriminator is what must agree with the
    body: `A` needs `n`, `B` needs `m`, and `C` is mapped but not one of the oneOf branches."""
    schemas = {
        "A": {"type": "object", "required": ["n"], "properties": {"n": INTEGER}},
        "B": {"type": "object", "required": ["m"], "properties": {"m": INTEGER}},
        "C": {"type": "object"},
    }
    monkeypatch.setattr(openapi_check, "DOCUMENT", {"components": {"schemas": schemas}})
    refs = {name: f"#/components/schemas/{name}" for name in schemas}
    return {"oneOf": [{"$ref": refs["A"]}, {"$ref": refs["B"]}],
            "discriminator": {"propertyName": "kind", "mapping": {"a": refs["A"], "b": refs["B"], "c": refs["C"]}}}


def test_the_discriminator_selects_the_branch_the_value_must_match(tagged: dict[str, Any]) -> None:
    validate(tagged, {"kind": "a", "n": 1})
    validate(tagged, {"kind": "b", "m": 1})
    # Exactly one oneOf branch matches each of these, but the tag does not name a documented branch ...
    assert "not a documented branch" in refused(tagged, {"kind": "z", "n": 1})
    assert "not a documented branch" in refused(tagged, {"n": 1})
    assert "not a documented branch" in refused(tagged, {"kind": 7, "n": 1})
    # ... or names the other branch, so the tagged branch is what the body is held to.
    assert "missing ['m']" in refused(tagged, {"kind": "b", "n": 1})
    assert "missing ['n']" in refused(tagged, {"kind": "a", "m": 1})


def test_a_mapped_tag_that_is_not_a_one_of_branch_is_a_schema_defect(tagged: dict[str, Any]) -> None:
    """`c` is mapped but is not among the oneOf branches: the document contradicts itself, so it is not a mismatch."""
    undecidable(tagged, {"kind": "c", "n": 1})


def test_a_discriminator_needs_one_of_and_an_explicit_mapping(tagged: dict[str, Any]) -> None:
    undecidable({"discriminator": tagged["discriminator"]}, {"kind": "a", "n": 1})
    undecidable({"oneOf": tagged["oneOf"], "discriminator": {"propertyName": "kind"}}, {"kind": "a", "n": 1})


# -- array bounds ----------------------------------------------------------------------------------------------------

def test_array_item_bounds_are_enforced_at_both_ends() -> None:
    bounded = {"type": "array", "items": INTEGER, "minItems": 1, "maxItems": 2}
    validate(bounded, [1])
    validate(bounded, [1, 2])
    assert "fewer than 1" in refused(bounded, [])
    assert "more than 2" in refused(bounded, [1, 2, 3])
    refused(bounded, [1, "2"])  # the items schema still applies inside the bounds


# -- the committed document ------------------------------------------------------------------------------------------

def schema_nodes(node: Any) -> Any:
    """Every schema object below `node` (a schema position, not a property name or example value)."""
    if not isinstance(node, dict):
        return
    yield node
    for key in ("items", "additionalProperties"):
        yield from schema_nodes(node.get(key))
    for key in ("anyOf", "oneOf"):
        for branch in node.get(key, ()):
            yield from schema_nodes(branch)
    for branch in node.get("properties", {}).values():
        yield from schema_nodes(branch)


def test_the_committed_document_stays_inside_the_evaluators_supported_subset() -> None:
    """If a regenerated document starts using a keyword, format or reference form the evaluator does not know,
    this fails here rather than only when some response happens to reach the new construct."""
    seen = 0
    for schema in DOCUMENT["components"]["schemas"].values():
        for node in schema_nodes(schema):
            seen += 1
            assert set(node) <= KEYWORDS, sorted(set(node) - KEYWORDS)
            assert node.get("format", "uuid") in FORMATS
            assert all(ref.startswith("#/") for ref in ([node["$ref"]] if "$ref" in node else []))
            for option in node.get("oneOf", ()):
                assert "$ref" in option or "type" in option
    assert seen > 100


# -- a real proposal detail, end to end through check_response ---------------------------------------------------------

@dataclass
class Reply:
    body: Any
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=lambda: {"content-type": "application/json"})
    content: bytes = b"{}"
    text: str = "{}"

    def json(self) -> Any:
        return self.body


def sealed(world: World, call: Any) -> ActionProposal:
    result = propose(proposal_id=UUID(int=500), proposal_version=1, session=world.session(), call=call,
                     facts=world.facts(), evidence=(), rationale="Customer request.", now=world.now)
    assert isinstance(result, ActionProposal)
    return result


def detail(world: World, proposal: ActionProposal) -> dict[str, Any]:
    row = ProposalRow(row_id=UUID(int=600), workspace_id=proposal.scope.workspace_id, case_id=proposal.scope.case_id,
                      run_id=proposal.scope.run_id, proposal_id=proposal.proposal_id,
                      proposal_version=proposal.proposal_version, action_digest=proposal.action_digest,
                      intent_digest=proposal.intent_digest, status="created", created_at=proposal.created_at,
                      expires_at=proposal.expires_at, presented_at=None)
    view = views.detail_view(row=row, proposal=proposal, presentation=None, consent=None, consent_message=None,
                             decision=None, now=world.now + timedelta(seconds=1))
    return view.model_dump(mode="json")


def check(body: Any) -> str:
    return openapi_check.check_response(Reply(body), "GET", "/api/v1/proposals/{proposal_id}")


def test_actual_proposal_details_validate_through_the_discriminated_action_and_effect(world: World) -> None:
    for call in (CancelPendingOrder(order_id=world.order_id, reason="no longer needed"),
                 ModifyPendingOrderItems(order_id=world.order_id, item_ids=(world.item_a,),
                                         new_item_ids=(world.item_c,), payment_method_id=world.card)):
        body = detail(world, sealed(world, call))
        assert check(body) == "get_proposal"
        assert body["proposal"]["action"]["tool"] == call.tool


def test_a_proposal_detail_whose_action_or_effect_disagrees_with_its_tag_is_refused(world: World) -> None:
    good = detail(world, sealed(world, CancelPendingOrder(order_id=world.order_id, reason="no longer needed")))
    assert check(good) == "get_proposal"

    def altered(path: tuple[str, ...], value: Any) -> dict[str, Any]:
        body = detail(world, sealed(world, CancelPendingOrder(order_id=world.order_id, reason="no longer needed")))
        node = body
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        return body

    for body in (altered(("proposal", "action", "tool"), "modify_pending_order_items"),  # tag names another branch
                 altered(("proposal", "action", "tool"), "no_such_tool"),
                 altered(("proposal", "effect", "kind"), "return_delivered_order_items"),
                 altered(("proposal", "action", "order_id"), "not-a-uuid"),
                 altered(("state",), "approved_and_executed")):
        with pytest.raises(SchemaMismatch):
            check(body)
