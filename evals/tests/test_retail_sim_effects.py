"""retail-simulator engine on the real audited fixture: upstream tools on isolated candidates, the per-tool actual
effect projection, exact money, customer scope, reads and the codec. No database, network, provider or task data.

The fixture tree is the reviewed upstream checkout that `uv sync` already materialized byte-for-byte (the evals
cache, `UV_CACHE_DIR`), or `POLICYOPS_RETAIL_FIXTURE_TREE`; its two files are verified against the source manifest.
"""

from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path
import sys
from typing import Any

import pytest

from policyops_contracts.money import Money
from policyops_contracts.retail import (
    Calculate,
    ExchangeDeliveredOrderItems,
    FindUserIdByEmail,
    GetItemDetails,
    GetOrderDetails,
    GetProductDetails,
    GetUserDetails,
    ItemChangeLine,
    ItemsEffect,
    ModifyPendingOrderItems,
)
from policyops_contracts.retail_service import OrderOutput, ProductOutput, UserOutput, VariantOutput
from policyops_evals.retail_sim import codec, engine, fixture
from policyops_evals.retail_sim.effects import EffectMismatch, changed_paths, project


CUSTOMER = "james_johnson_9321"
ORDER = "#W1006327"
CARD = "credit_card_4998749"
FORBIDDEN_OPENS: list[str] = []


def _audit(event: str, args: tuple[Any, ...]) -> None:
    if event == "open" and isinstance(args[0], str | bytes):
        path = os.fsdecode(args[0]).replace("\\", "/")
        if path.endswith("/tasks.json") or "/task_" in path or "split_tasks" in path or "task_subsets" in path:
            FORBIDDEN_OPENS.append(path)


def source_tree() -> Path:
    explicit = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
    if explicit:
        return Path(explicit)
    found = fixture.find_reviewed_tree(Path(os.environ.get("UV_CACHE_DIR", "")))
    if found is not None:
        return found
    pytest.fail("no verified tau2 checkout: run through scripts/devenv.py after `uv sync` (or set "
                "POLICYOPS_RETAIL_FIXTURE_TREE)")


@pytest.fixture(scope="module")
def staged(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[fixture.Fixture, fixture.Upstream]]:
    sys.addaudithook(_audit)  # process-wide; it only records
    item = fixture.stage(source_tree(), tmp_path_factory.mktemp("fixture") / "root")
    yield item, fixture.upstream(item)


def line(old: str, new: str, product: str, before: int, after: int) -> ItemChangeLine:
    return ItemChangeLine(item_id=old, new_item_id=new, product_id=product, price_before=Money(amount_minor=before),
                          price_after=Money(amount_minor=after))


def items_effect(kind: str, order: str, lines: list[ItemChangeLine], method: str) -> ItemsEffect:
    statuses = {"modify_pending_order_items": ("pending", "pending (item modified)"),
                "exchange_delivered_order_items": ("delivered", "exchange requested")}[kind]
    return ItemsEffect(kind=kind, order_id=order, changes=tuple(lines),  # type: ignore[arg-type]
                       price_difference=Money(amount_minor=sum(x.price_after.amount_minor - x.price_before.amount_minor
                                                               for x in lines)),
                       payment_method_id=method, status_before=statuses[0], status_after=statuses[1])  # type: ignore


# -- fixture isolation and codec ---------------------------------------------------------------------------------

def test_the_fixture_root_holds_exactly_the_two_reviewed_files(staged: Any, tmp_path: Path) -> None:
    item, _ = staged
    assert sorted(p.relative_to(item.root).as_posix() for p in item.root.rglob("*") if p.is_file()) == \
        ["LICENSE", fixture.DB_PATH]
    assert item.sha256 == fixture.reviewed_digests()[fixture.DB_PATH] and len(item.raw) == 2_811_616
    tampered = tmp_path / "tampered"
    fixture.stage(item.root, tampered)
    (tampered / fixture.DB_PATH).write_bytes(item.raw + b" ")
    with pytest.raises(fixture.FixtureError):
        fixture.load(tampered)
    (tampered / fixture.DB_PATH).write_bytes(item.raw)
    (tampered / "data/tau2/domains/retail/extra.txt").write_bytes(b"x")
    with pytest.raises(fixture.FixtureError):
        fixture.load(tampered)


def test_the_codec_round_trips_the_fixture_exactly_within_the_cap(staged: Any) -> None:
    item, upstream = staged
    raw = codec.encode(codec.decode(item.raw, upstream.retail_db), verify=upstream.retail_db)
    assert len(raw) < codec.MAX_STATE_BYTES and codec.encode(codec.decode(raw, upstream.retail_db)) == raw
    with pytest.raises(codec.StateTooLarge):
        codec.decode(b" " * (codec.MAX_STATE_BYTES + 1), upstream.retail_db)


# -- the reviewer's executed upstream controls as service oracles ------------------------------------------------

def test_a_single_item_modification_with_an_exact_payment_commits(staged: Any) -> None:
    item, upstream = staged
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id=CARD)
    expected = items_effect(call.tool, ORDER, [line("5172162216", "4068787148", "1808611083", 4851, 5201)], CARD)
    attempt = engine.mutate(upstream, item.raw, call, expected, CUSTOMER)
    assert attempt.outcome == "committed" and attempt.effect == expected
    assert expected.price_difference.amount_minor == 350
    assert attempt.changed == frozenset({("order", ORDER)}) and attempt.state is not None
    after = codec.decode(attempt.state, upstream.retail_db).orders[ORDER]
    assert after.status == "pending (item modified)"


def test_a_float_payment_drift_is_money_unrepresentable(staged: Any) -> None:
    item, upstream = staged
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5925362855",), new_item_ids=("6117189161",),
                                   payment_method_id=CARD)
    expected = items_effect(call.tool, ORDER, [line("5925362855", "6117189161", "3377618313", 50351, 48150)], CARD)
    attempt = engine.mutate(upstream, item.raw, call, expected, CUSTOMER)
    assert (attempt.outcome, attempt.state, attempt.effect) == ("money_unrepresentable", None, None)


def test_two_distinct_targets_with_an_exact_aggregate_are_an_effect_mismatch(staged: Any) -> None:
    item, upstream = staged
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5925362855", "1994478369"),
                                   new_item_ids=("6117189161", "8886009523"), payment_method_id=CARD)
    expected = items_effect(call.tool, ORDER, [line("5925362855", "6117189161", "3377618313", 50351, 48150),
                                               line("1994478369", "8886009523", "6066914160", 202551, 194402)], CARD)
    assert expected.price_difference.amount_minor == -10350
    attempt = engine.mutate(upstream, item.raw, call, expected, CUSTOMER)
    assert (attempt.outcome, attempt.code, attempt.state) == ("effect_mismatch", "item_target_mismatch", None)


def test_a_two_target_exchange_records_only_the_request(staged: Any) -> None:
    item, upstream = staged
    call = ExchangeDeliveredOrderItems(order_id="#W1067251", item_ids=("6452271382", "7848293342"),
                                       new_item_ids=("1646531091", "3876764226"),
                                       payment_method_id="credit_card_3362387")
    state = codec.dump(codec.decode(item.raw, upstream.retail_db))
    prices = {i["item_id"]: (i["product_id"], i["price"]) for i in state["orders"]["#W1067251"]["items"]}

    def target(old: str, new: str) -> ItemChangeLine:
        product, before = prices[old]
        after = state["products"][product]["variants"][new]["price"]
        return line(old, new, product, round(before * 100), round(after * 100))
    expected = items_effect(call.tool, "#W1067251", [target("6452271382", "1646531091"),
                                                     target("7848293342", "3876764226")], "credit_card_3362387")
    assert expected.price_difference.amount_minor == 1241
    attempt = engine.mutate(upstream, item.raw, call, expected, "raj_sanchez_2970")
    assert attempt.outcome == "committed" and attempt.changed == frozenset({("order", "#W1067251")})
    assert attempt.state is not None
    after = codec.dump(codec.decode(attempt.state, upstream.retail_db))
    before_order, after_order = state["orders"]["#W1067251"], after["orders"]["#W1067251"]
    assert after_order["items"] == before_order["items"]
    assert after_order["payment_history"] == before_order["payment_history"]
    assert after["users"]["raj_sanchez_2970"] == state["users"]["raj_sanchez_2970"]


def test_an_effect_different_from_the_approved_one_is_refused(staged: Any) -> None:
    item, upstream = staged
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id=CARD)
    wrong = items_effect(call.tool, ORDER, [line("5172162216", "4068787148", "1808611083", 4851, 5202)], CARD)
    attempt = engine.mutate(upstream, item.raw, call, wrong, CUSTOMER)
    assert (attempt.outcome, attempt.code) == ("effect_mismatch", "differs_from_expected")


def test_an_upstream_business_error_discards_the_candidate(staged: Any) -> None:
    item, upstream = staged
    call = ExchangeDeliveredOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                       payment_method_id=CARD)  # the order is pending, not delivered
    expected = items_effect(call.tool, ORDER, [line("5172162216", "4068787148", "1808611083", 4851, 5201)], CARD)
    attempt = engine.mutate(upstream, item.raw, call, expected, CUSTOMER)
    assert (attempt.outcome, attempt.state) == ("upstream_rejected", None)


def test_a_changed_catalog_or_unlisted_path_is_an_effect_mismatch(staged: Any) -> None:
    item, upstream = staged
    before = codec.dump(codec.decode(item.raw, upstream.retail_db))
    after = codec.dump(codec.decode(item.raw, upstream.retail_db))
    product = next(iter(after["products"]))
    after["products"][product]["name"] = "changed"
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id=CARD)
    with pytest.raises(EffectMismatch) as refused:
        project(call, before, after, CUSTOMER)
    assert refused.value.code == "catalog_changed"
    assert list(changed_paths(before, after)) == [("products", product, "name")]


def test_an_unapproved_item_field_change_is_an_effect_mismatch(staged: Any) -> None:
    """Reviewer oracle (C1 effect-field): the approved target change projects exactly; renaming the item as well is
    outside the change and is refused."""
    item, upstream = staged
    before = codec.dump(codec.decode(item.raw, upstream.retail_db))
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id=CARD)
    expected = items_effect(call.tool, ORDER, [line("5172162216", "4068787148", "1808611083", 4851, 5201)], CARD)
    after = codec.dump(codec.decode(item.raw, upstream.retail_db))
    order = after["orders"][ORDER]
    position = next(i for i, x in enumerate(order["items"]) if x["item_id"] == "5172162216")
    target = after["products"]["1808611083"]["variants"]["4068787148"]
    order["items"][position].update(item_id="4068787148", price=target["price"], options=dict(target["options"]))
    order["status"] = "pending (item modified)"
    order["payment_history"].append({"transaction_type": "payment", "payment_method_id": CARD, "amount": 3.5})
    assert project(call, before, after, CUSTOMER) == expected  # control: exactly the approved change
    assert "name" in order["items"][position]
    order["items"][position]["name"] = "UNAPPROVED-ITEM-RENAME"
    with pytest.raises(EffectMismatch) as refused:
        project(call, before, after, CUSTOMER)
    assert refused.value.code == "unexpected_change"


# -- scope and required versions -------------------------------------------------------------------------------

def test_another_customers_order_or_payment_method_is_out_of_scope(staged: Any) -> None:
    item, upstream = staged
    state = codec.dump(codec.decode(item.raw, upstream.retail_db))
    foreign = next(oid for oid, order in state["orders"].items() if order["user_id"] != CUSTOMER)
    call = ModifyPendingOrderItems(order_id=foreign, item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id=CARD)
    expected = items_effect(call.tool, foreign, [line("5172162216", "4068787148", "1808611083", 4851, 5201)], CARD)
    with pytest.raises(engine.NotInScope):
        engine.mutate(upstream, item.raw, call, expected, CUSTOMER)
    own = call.model_copy(update={"order_id": ORDER, "payment_method_id": "credit_card_3362387"})
    with pytest.raises(engine.NotInScope):
        engine.check_scope(state, own, CUSTOMER)


def test_required_versions_cover_order_user_and_each_catalog_product(staged: Any) -> None:
    item, upstream = staged
    state = codec.dump(codec.decode(item.raw, upstream.retail_db))
    call = ModifyPendingOrderItems(order_id=ORDER, item_ids=("5925362855", "1994478369"),
                                   new_item_ids=("6117189161", "8886009523"), payment_method_id=CARD)
    assert engine.required_versions(state, call, CUSTOMER) == frozenset(
        {("order", ORDER), ("user", CUSTOMER), ("product", "3377618313"), ("product", "6066914160")})


def test_reads_are_typed_exact_and_limited_to_the_customer(staged: Any) -> None:
    item, upstream = staged
    state = codec.dump(codec.decode(item.raw, upstream.retail_db))
    output, shown = engine.read(upstream, item.raw, GetOrderDetails(order_id=ORDER), CUSTOMER, lambda r: 3)
    assert output.kind == "order" and output.order.version == 3 and shown == frozenset({("order", ORDER)})
    assert all(isinstance(i.price.amount_minor, int) for i in output.order.items)
    user, _ = engine.read(upstream, item.raw, GetUserDetails(user_id=CUSTOMER), CUSTOMER, lambda r: 1)
    assert user.kind == "user" and user.user.user_id == CUSTOMER
    other = next(u for u in state["users"].values() if u["user_id"] != CUSTOMER)
    for call in (GetUserDetails(user_id=other["user_id"]), FindUserIdByEmail(email=other["email"]),
                 GetOrderDetails(order_id=next(o for o, v in state["orders"].items() if v["user_id"] != CUSTOMER))):
        with pytest.raises(engine.NotInScope):
            engine.read(upstream, item.raw, call, CUSTOMER, lambda r: 1)
    found, _ = engine.read(upstream, item.raw, FindUserIdByEmail(email=state["users"][CUSTOMER]["email"]),
                           CUSTOMER, lambda r: 1)
    assert found.kind == "user_id" and found.user_id == CUSTOMER
    calc, _ = engine.read(upstream, item.raw, Calculate(expression="12 * 7"), CUSTOMER, lambda r: 1)
    assert calc.kind == "calculation" and calc.value == "84.0"


def test_no_task_split_or_holdout_file_was_opened(staged: Any) -> None:
    """Import-time modules are inventoried, not banned (`import tau2` loads its runner and registry eagerly); what
    matters is that no task data was read and no environment, task or runner object was created."""
    assert FORBIDDEN_OPENS == []
    loaded = sorted(name for name in sys.modules if name == "tau2" or name.startswith("tau2."))
    assert "tau2.domains.retail.tools" in loaded and "tau2.domains.retail.data_model" in loaded
    import gc

    from tau2.data_model.tasks import Task
    from tau2.environment.environment import Environment
    assert not any(isinstance(obj, Task | Environment) for obj in gc.get_objects())


# -- read details (D13): enough to choose a variant and to show what is being approved -------------------------

def test_product_and_item_reads_carry_each_variants_options(staged: Any) -> None:
    item, upstream = staged
    state = codec.dump(codec.decode(item.raw, upstream.retail_db))
    product, _ = engine.read(upstream, item.raw, GetProductDetails(product_id="1808611083"), CUSTOMER, lambda r: 1)
    assert isinstance(product, ProductOutput) and product.name == state["products"]["1808611083"]["name"]
    combos = [tuple((o.name, o.value) for o in v.options) for v in product.variants]
    assert len(combos) == len(set(combos)) > 1 and all(combos)  # each opaque ID maps to a distinct option combination
    expected = (("difficulty level", "intermediate"), ("pieces", "500"), ("theme", "art"))
    chosen = next(v for v in product.variants if v.item_id == "4068787148")
    assert tuple((o.name, o.value) for o in chosen.options) == expected and chosen.price.amount_minor == 5201
    variant, shown = engine.read(upstream, item.raw, GetItemDetails(item_id="4068787148"), CUSTOMER, lambda r: 1)
    assert isinstance(variant, VariantOutput) and variant.variant == chosen
    assert shown == frozenset({("product", "1808611083")})
    assert variant.variant.to_snapshot().price == chosen.price  # explicit projection to the minimal snapshot


def test_order_and_user_reads_show_items_and_only_the_customers_own_orders(staged: Any) -> None:
    item, upstream = staged
    state = codec.dump(codec.decode(item.raw, upstream.retail_db))
    order, _ = engine.read(upstream, item.raw, GetOrderDetails(order_id=ORDER), CUSTOMER, lambda r: 2)
    assert isinstance(order, OrderOutput)
    raw_items = state["orders"][ORDER]["items"]
    assert [(i.item_id, i.name, {o.name: o.value for o in i.options}) for i in order.order.items] == \
        [(i["item_id"], i["name"], i["options"]) for i in raw_items]
    assert all(isinstance(i.price.amount_minor, int) for i in order.order.items)
    snapshot = order.order.to_snapshot()
    assert snapshot.version == 2 and [i.item_id for i in snapshot.items] == [i["item_id"] for i in raw_items]
    user, _ = engine.read(upstream, item.raw, GetUserDetails(user_id=CUSTOMER), CUSTOMER, lambda r: 1)
    assert isinstance(user, UserOutput)
    owned = {oid for oid, o in state["orders"].items() if o["user_id"] == CUSTOMER}
    assert set(user.user.order_ids) == owned and ORDER in owned
    assert (user.user.first_name, user.user.email) == (state["users"][CUSTOMER]["name"]["first_name"],
                                                       state["users"][CUSTOMER]["email"])
    assert user.user.to_snapshot().user_id == CUSTOMER
    # Masked descriptors tell same-kind cards apart ("the Visa ending 1234"); exact balances stay Money.
    cards = [m for u in state["users"].values() for m in u["payment_methods"].values() if m["source"] == "credit_card"]
    holder = next(u for u in state["users"].values()
                  if sum(m["source"] == "credit_card" for m in u["payment_methods"].values()) > 1)
    many, _ = engine.read(upstream, item.raw, GetUserDetails(user_id=holder["user_id"]), holder["user_id"],
                          lambda r: 1)
    assert isinstance(many, UserOutput) and cards
    described = [(m.brand, m.last_four) for m in many.user.payment_methods if m.kind == "credit_card"]
    assert len(described) > 1 and len(set(described)) == len(described) and all(all(d) for d in described)
    assert all(m.gift_card_balance is None or isinstance(m.gift_card_balance.amount_minor, int)
               for m in many.user.payment_methods)
    again, _ = engine.read(upstream, item.raw, GetUserDetails(user_id=CUSTOMER), CUSTOMER, lambda r: 1)
    assert again == user  # deterministic; the read persisted nothing


def test_an_exchange_request_is_shown_as_a_request_with_an_exact_difference(staged: Any) -> None:
    item, upstream = staged
    call = ExchangeDeliveredOrderItems(order_id="#W1067251", item_ids=("6452271382", "7848293342"),
                                       new_item_ids=("1646531091", "3876764226"),
                                       payment_method_id="credit_card_3362387")
    state = codec.dump(codec.decode(item.raw, upstream.retail_db))
    prices = {i["item_id"]: (i["product_id"], i["price"]) for i in state["orders"]["#W1067251"]["items"]}
    lines = []
    for old, new in zip(call.item_ids, call.new_item_ids, strict=True):
        product, before = prices[old]
        after = state["products"][product]["variants"][new]["price"]
        lines.append(line(old, new, product, round(before * 100), round(after * 100)))
    expected = items_effect(call.tool, "#W1067251", lines, "credit_card_3362387")
    attempt = engine.mutate(upstream, item.raw, call, expected, "raj_sanchez_2970")
    assert attempt.state is not None
    order, _ = engine.read(upstream, attempt.state, GetOrderDetails(order_id="#W1067251"), "raj_sanchez_2970",
                           lambda r: 2)
    assert isinstance(order, OrderOutput)
    request = order.order.exchange_request
    assert order.order.status == "exchange requested" and request is not None and order.order.return_request is None
    assert request.price_difference.amount_minor == 1241 and request.item_ids == tuple(sorted(call.item_ids))
    assert [i.item_id for i in order.order.items] == [i["item_id"] for i in state["orders"]["#W1067251"]["items"]]
