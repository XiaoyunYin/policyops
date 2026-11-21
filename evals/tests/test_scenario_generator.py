"""Pinned-data checks; failures report invariants without printing manifests."""

from collections import Counter
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path

from pydantic import TypeAdapter
import pytest

from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail import HANDOFF_MESSAGE, CancelPendingOrder, ModifyUserAddress, ReturnDeliveredOrderItems
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_evals.retail_sim.fixture import DB_PATH, find_reviewed_tree
from policyops_evals.scenarios.cases import POSITIVES, STRATA, Gold, VisibleCase
from policyops_evals.scenarios.generator import (
    GROUPS,
    REASONS,
    REPO,
    VISIBLE_LEAK,
    Candidate,
    FixtureData,
    Generation,
    Rendering,
    Selector,
    _scenario,
    _spans,
    cancellation_proof,
    family_ids,
    generate,
    quotas,
    selectors,
    verified_fixture,
    write_manifests,
)


@pytest.fixture(scope="module")
def pinned() -> tuple[bytes, bytes]:
    explicit = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
    tree = Path(explicit) if explicit else find_reviewed_tree(Path(os.environ.get("UV_CACHE_DIR", "")))
    assert tree is not None, "the audited tau2 checkout is required"
    return (tree / DB_PATH).read_bytes(), (tree / RETAIL_POLICY.path).read_bytes()


@pytest.fixture(scope="module")
def generation(pinned: tuple[bytes, bytes]) -> Generation:
    return generate(*pinned)


def test_reproducible_manifests_and_pinned_inputs(pinned: tuple[bytes, bytes], generation: Generation) -> None:
    db, policy = pinned
    assert sha256(db).hexdigest() == FIXTURE_SHA256
    assert sha256(policy).hexdigest() == RETAIL_POLICY.sha256
    with pytest.raises(ValueError, match="fixture digest"):
        generate(db + b" ", policy)
    with pytest.raises(ValueError, match="policy bytes"):
        generate(db, policy + b" ")
    manifests = generation.manifests()
    assert bool(manifests == generate(db, policy).manifests())
    fixture = verified_fixture(db)
    assert len(fixture.users) == 500
    assert len(fixture.orders) == 1000
    visible_schema, gold_schema = TypeAdapter(VisibleCase), TypeAdapter(Gold)
    for split, cases in generation.cases.items():
        visible = manifests[f"{split}.visible.jsonl"].splitlines()
        gold = manifests[f"{split}.gold.jsonl"].splitlines()
        assert len(visible) == len(gold) == len(cases)
        for expected, v_record, g_record in zip(cases, visible, gold, strict=True):
            assert set(json.loads(v_record)) == {"key", "lookup_email", "message"}
            found_visible = visible_schema.validate_json(v_record)
            found_gold = gold_schema.validate_json(g_record)
            assert bool(expected.visible == found_visible and expected.gold == found_gold)


def test_split_closure_family_quotas_and_census(generation: Generation) -> None:
    closures: dict[str, set[str]] = {}
    customers: set[str] = set()
    families: dict[str, set[str]] = {}
    keys: set[str] = set()
    for split, cases in generation.cases.items():
        closures[split] = set()
        families[split] = set()
        assert len(cases) == (128 if split == "dev" else 256)
        for stratum in STRATA:
            group = GROUPS[stratum]
            subset = [case for case in cases if case.gold.stratum == stratum]
            assert len(subset) == quotas(split, stratum)
            expected = {f"{group}-v1-{i:02}" for i in family_ids(group, split)}
            assert bool({case.gold.family for case in subset} == expected)
            families[split].update(expected)
            forms = Counter(case.gold.order_id_form for case in subset)
            if stratum in {"cancel", "return", "delivered_refusal", "missing_reason"}:
                assert forms["hash"] == forms["bare"] == len(subset) // 2
            else:
                assert forms == {"absent": len(subset)}
        for case in cases:
            assert bool(case.key not in keys and case.world.customer_id not in customers)
            assert bool(closures[split].isdisjoint(case.world.order_closure))
            closures[split].update(case.world.order_closure)
            customers.add(case.world.customer_id)
            keys.add(case.key)
    assert bool(closures["dev"].isdisjoint(closures["held-out"]))
    assert bool(families["dev"].isdisjoint(families["held-out"]))
    assert len(families["dev"]) == 20
    assert len(families["held-out"]) == 40
    assert {
        name: (row.eligible, sum(row.rejected.values()), row.eligible_customers, row.outside_order_count)
        for name, row in generation.census.items()
    } == {
        "cancel": (423, 577, 274, 0), "return": (373, 627, 282, 0), "default_address": (500, 0, 500, 0),
        "multi_resolvable": (261, 875, 149, 255), "delivered_refusal": (373, 627, 282, 0),
        "missing_reason": (423, 577, 274, 0), "multi_ambiguous": (56, 1080, 37, 255), "handoff": (500, 0, 500, 0),
    }


def test_openers_and_construction_witnesses(pinned: tuple[bytes, bytes], generation: Generation) -> None:
    db, _ = pinned
    fixture = verified_fixture(db)
    for cases in generation.cases.values():
        for case in cases:
            case.verify(db)
            message, gold = case.visible.message, case.gold
            assert bool(case.visible.lookup_email in message and not VISIBLE_LEAK.search(message))
            assert bool(HANDOFF_MESSAGE not in message)
            expected_id = case.world.order_id
            if expected_id is not None and gold.order_id_form != "absent":
                assert bool((expected_id in message) == (gold.order_id_form == "hash"))
                assert bool(expected_id.removeprefix("#") in message)
            elif gold.stratum in {"multi_ambiguous", "multi_resolvable", "default_address"}:
                assert bool(case.world.customer_id in message)
                assert bool(all(oid.removeprefix("#") not in message for oid in case.world.order_closure))
            proof = gold.proof
            assert proof is not None
            if gold.stratum in POSITIVES:
                assert bool(proof.solutions == (gold.action,))
            if isinstance(gold.action, ReturnDeliveredOrderItems):
                raw = fixture.orders[gold.action.order_id]
                assert bool(Counter(gold.action.item_ids) == Counter(i["item_id"] for i in raw["items"]))
                assert bool(gold.action.payment_method_id == raw["payment_history"][0]["payment_method_id"])
            elif isinstance(gold.action, ModifyUserAddress):
                address = gold.action.address().model_dump()
                assert bool(address != fixture.users[case.world.customer_id]["address"])
                assert bool(all(str(value) in message for value in address.values()))
            elif gold.stratum == "delivered_refusal":
                assert bool(proof.failed_precondition == "cancel.pending_only" and not proof.solutions)
            elif gold.stratum == "missing_reason":
                assert bool(proof.missing_field == "reason" and proof.allowed_values == REASONS and not proof.solutions)
            elif gold.stratum == "handoff":
                assert bool(proof.failed_precondition == "scope.supported_requests" and not proof.solutions)
            if gold.stratum in {"multi_ambiguous", "multi_resolvable"}:
                assert 2 <= len(case.world.order_closure) <= 3
                assert bool({r.order_id for r in gold.order_reads} == set(case.world.order_closure))
                assert proof.selector is not None
                attr, value = proof.selector
                assert bool(value.lower() in message.lower() or attr == "payment_kind")
                user = fixture.users[case.world.customer_id]
                matching = {oid for oid in case.world.order_closure
                            if proof.selector in selectors(user, fixture.orders[oid])}
                assert bool(matching == set(proof.referents))
                if gold.stratum == "multi_ambiguous":
                    assert bool(gold.action is None and len(proof.solutions) == 2)
                    assert bool(all(isinstance(w, CancelPendingOrder) for w in proof.solutions))
                    assert len(set(proof.referents)) == 2
                    assert bool(set(proof.referents) <= set(case.world.order_closure))


def test_cancel_status_flip_and_missing_reason(pinned: tuple[bytes, bytes], generation: Generation) -> None:
    fixture = verified_fixture(pinned[0])
    case = next(case for case in generation.cases["dev"] if case.gold.stratum == "cancel")
    assert isinstance(case.gold.action, CancelPendingOrder)
    oid, reason = case.gold.action.order_id, case.gold.action.reason
    candidate = Candidate(case.world.customer_id, oid)
    renderer = Rendering(0, 0, reason, 0, "hash")
    delivery = {**fixture.orders[oid], "status": "delivered"}
    counterfactual = replace(fixture, orders={**fixture.orders, oid: delivery})
    spans = _spans(pinned[1])
    before = _scenario(fixture, "cancel", candidate, renderer, spans)
    after = _scenario(counterfactual, "delivered_refusal", candidate, renderer, spans)
    assert bool(before.visible.message.encode() == after.visible.message.encode())
    assert before.gold.disposition == "propose" and after.gold.disposition == "refuse"
    assert before.gold.action is not None and after.gold.action is None
    assert after.gold.proof is not None
    assert after.gold.proof.failed_precondition == "cancel.pending_only"
    missing = cancellation_proof(fixture, candidate, None)
    assert missing.allowed_values == REASONS and not missing.solutions


def test_multi_attribute_flip_keeps_opener_byte_identical(pinned: tuple[bytes, bytes]) -> None:
    fixture = verified_fixture(pinned[0])
    customer, candidate, matched, other = _two_pending_distinct_cities(fixture)
    renderer = Rendering(0, 0, REASONS[0], 0, "absent")
    modified = {**fixture.orders[other], "address": {**fixture.orders[other]["address"],
                                                    "city": fixture.orders[matched]["address"]["city"]}}
    counterfactual = replace(fixture, orders={**fixture.orders, other: modified})
    spans = _spans(pinned[1])
    before = _scenario(fixture, "multi_resolvable", candidate, renderer, spans)
    after = _scenario(counterfactual, "multi_ambiguous", candidate, renderer, spans)
    assert bool(before.visible.message.encode() == after.visible.message.encode())
    assert before.gold.disposition == "propose" and after.gold.disposition == "insufficient_information"
    assert before.gold.action is not None and after.gold.action is None
    assert after.gold.proof is not None and len(after.gold.proof.solutions) == 2
    assert bool(set(after.gold.proof.referents) == {matched, other} and candidate.customer == customer)


def _two_pending_distinct_cities(fixture: FixtureData) -> tuple[str, Candidate, str, str]:
    for customer, user in fixture.users.items():
        if len(user["orders"]) != 2:
            continue
        matched, other = user["orders"]
        order, alternate = fixture.orders[matched], fixture.orders[other]
        city = order["address"]["city"]
        if order["status"] == alternate["status"] == "pending" and city != alternate["address"]["city"]:
            candidate = Candidate(customer, selector=Selector("shipping_city", city))
            return customer, candidate, matched, other
    raise AssertionError("pinned fixture needs two pending orders in different cities")


def test_manifest_output_refuses_checkout_and_overwrite(generation: Generation, tmp_path: Path) -> None:
    manifests = generation.manifests()
    with pytest.raises(ValueError, match="outside the repository"):
        write_manifests(REPO / "must-not-create", manifests)
    digests = write_manifests(tmp_path, manifests)
    for name, payload in manifests.items():
        assert digests[name] == sha256(payload).hexdigest()
        assert bool((tmp_path / name).read_bytes() == payload)
    with pytest.raises(ValueError, match="already exists"):
        write_manifests(tmp_path, manifests)


@pytest.mark.parametrize("leak", ["cancel.pending_only", "finish_answer", "cancel_pending_order", "respond in JSON",
                                  "gold", "delivered"])
def test_label_leak_scan_rejects_internal_hints(leak: str) -> None:
    assert VISIBLE_LEAK.search(f"Please act on {leak}.")
