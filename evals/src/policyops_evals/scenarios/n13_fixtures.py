"""Deterministic N13 cases selected from unused closures in the pinned retail fixture."""

from argparse import ArgumentParser
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Literal

from policyops_contracts.retail import CancelPendingOrder, ModifyPendingOrderAddress, ReturnDeliveredOrderItems
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_evals.scenarios import generator as gen
from policyops_evals.scenarios.cases import SCENARIOS, STRATA, Gold, OrderRead, Scenario, VisibleCase, World


type Class = Literal["A", "A-prime", "B1", "B2", "B3", "C1", "C2", "C3"]
type Status = Literal["pending", "delivered"]
type Action = CancelPendingOrder | ReturnDeliveredOrderItems
SEED = 13250
LIVE_SLOTS = 16


@dataclass(frozen=True)
class Trial:
    group: Class
    scenario: Scenario
    action: Action
    sibling: str | None = None
    unrelated_change: ReturnDeliveredOrderItems | ModifyPendingOrderAddress | None = None

    @property
    def admitted(self) -> bool:
        return self.group in {"B1", "B2", "C1", "C2", "C3"}


@dataclass(frozen=True)
class Panel:
    trials: tuple[Trial, ...]
    live: tuple[Trial, ...]
    census: dict[str, int]


def _action(fixture: gen.FixtureData, customer: str, order_id: str, status: Status) -> Action | None:
    order = fixture.orders[order_id]
    payment = gen._payment(fixture.users[customer], order)
    if payment is None:
        return None
    if status == "pending":
        return CancelPendingOrder(order_id=order_id, reason="no longer needed")
    if not order["items"]:
        return None
    return ReturnDeliveredOrderItems(order_id=order_id, item_ids=(order["items"][0]["item_id"],),
                                     payment_method_id=payment)


def _trial(fixture: gen.FixtureData, group: Class, customer: str, action: Action, *,
           stated: str = "", description: str = "", sibling: str | None = None,
           unrelated: ReturnDeliveredOrderItems | ModifyPendingOrderAddress | None = None) -> Trial:
    user = fixture.users[customer]
    order = fixture.orders[action.order_id]
    email: str = user["email"]
    closure = tuple(sorted(user["orders"]))
    key = gen._rank(SEED, group, customer, action.order_id, action.tool).hex()[:24]
    # The no-ID acceptance opener contains the reason and lets the model discover its target.
    target = f"order {stated}" if stated else "my order"
    if description:
        target = f"{target} {description}"
    item = "an item" if group in {"A", "A-prime"} else f"the {order['items'][0]['name']}"
    request = (f"Please cancel {target} because I no longer need it." if isinstance(action, CancelPendingOrder)
               else f"Please return {item} from {target} to my original payment method.")
    world = World(customer, action.order_id, order["status"], gen._payment(user, order), closure)
    read_ids = (action.order_id,) if stated else closure
    reads = tuple(OrderRead(oid, fixture.orders[oid]["status"]) for oid in read_ids)
    positive = group in {"B1", "B2", "C1", "C2", "C3"}
    gold = Gold("propose" if positive else "insufficient_information", action if positive else None,
                ("identity", "profile", "order") if not stated else ("identity", "order"),
                gen.CLAUSES["cancel" if isinstance(action, CancelPendingOrder) else "return"],
                key=key, customer_world=customer, order_reads=reads, order_id_form="hash" if stated else "absent")
    return Trial(group, Scenario(key, world, VisibleCase(email, f"My account email is {email}. {request}", key), gold),
                 action, sibling, unrelated)


def _unrelated_change(fixture: gen.FixtureData, customer: str, siblings: tuple[str, ...]
                      ) -> ReturnDeliveredOrderItems | ModifyPendingOrderAddress | None:
    for oid in siblings:
        status = fixture.orders[oid]["status"]
        if status == "pending":
            address = gen._new_address(customer)
            if address.model_dump() != fixture.orders[oid]["address"]:
                return ModifyPendingOrderAddress(order_id=oid, **address.model_dump())
        if status == "delivered":
            action = _action(fixture, customer, oid, "delivered")
            if isinstance(action, ReturnDeliveredOrderItems):
                return action
    return None


def _unambiguous_live_item(fixture: gen.FixtureData, trial: Trial) -> bool:
    if isinstance(trial.action, CancelPendingOrder):
        return True
    names: list[str] = [item["name"] for item in fixture.orders[trial.action.order_id]["items"]]
    return names.count(names[0]) == 1


def generate(raw: bytes) -> Panel:
    fixture = gen.verified_fixture(raw)
    pools = {stratum: gen._pool(fixture, stratum)[0] for stratum in STRATA}
    allocation = gen._allocate(pools)
    spent = {candidate.customer for split in allocation.values() for _, candidate in split}
    spent.update(case.world.customer_id for case in SCENARIOS)
    fresh = sorted(fixture.users.keys() - spent, key=lambda customer: gen._rank(SEED, customer))
    resolvable = pools["multi_resolvable"]
    design_blocks = sum(
        sum(fixture.orders[oid]["status"] == "pending" for oid in fixture.users[customer]["orders"]) > 1
        for customer in resolvable
    )
    census = Counter({"fixture_customers": len(fixture.users), "fixture_orders": len(fixture.orders),
                      "historical_dev_customers": len(allocation["dev"]),
                      "historical_held_out_customers": len(allocation["held-out"]), "fresh_customers": len(fresh),
                      "historical_resolvable_pool": len(resolvable),
                      "historical_resolvable_design_blocks": design_blocks})
    trials: list[Trial] = []
    live_pools: list[list[tuple[Trial, ...]]] = []
    statuses: tuple[Status, ...] = ("pending", "delivered")
    for status in statuses:
        by_group: dict[Class, list[tuple[Trial, ...]]] = {key: [] for key in
                                                         ("A", "A-prime", "B1", "B2", "B3", "C1", "C2", "C3")}
        for customer in fresh:
            ids = tuple(sorted(fixture.users[customer]["orders"]))
            eligible = tuple(oid for oid in ids if fixture.orders[oid]["status"] == status)
            candidates = (_action(fixture, customer, oid, status) for oid in eligible)
            actions = tuple(action for action in candidates if action is not None)
            census[f"{status}_sole_customers"] += len(eligible) == 1
            census[f"{status}_multiple_customers"] += len(eligible) > 1
            if not actions:
                continue
            first = actions[0]
            if len(eligible) > 1:
                if len(actions) == len(eligible):
                    by_group["A"].append(tuple(_trial(fixture, "A", customer, action) for action in actions))
                    by_group["A-prime"].append((_trial(fixture, "A-prime", customer, actions[1],
                                                       stated=first.order_id),))
                by_group["B1"].append((_trial(fixture, "B1", customer, first, stated=first.order_id),))
                matches = gen._multi_choices(fixture, customer)
                for selector, referents in sorted(matches.items()):
                    if referents == (first.order_id,):
                        by_group["B3"].append((_trial(fixture, "B3", customer, first, description=selector.wording()),))
                        break
            else:
                by_group["B2"].append((_trial(fixture, "B2", customer, first),))
                by_group["C1"].append((_trial(fixture, "C1", customer, first),))
                siblings = tuple(oid for oid in ids if oid != first.order_id)
                if siblings:
                    by_group["C2"].append((_trial(fixture, "C2", customer, first, sibling=siblings[0]),))
                if (unrelated := _unrelated_change(fixture, customer, siblings)) is not None:
                    by_group["C3"].append((_trial(fixture, "C3", customer, first, unrelated=unrelated),))
        for group, choices in by_group.items():
            census[f"{status}_{group}_pool"] = len(choices)
            if not choices:
                raise ValueError(f"pinned fixture has no fresh {status}/{group} case")
            trials.extend(choices[0])
        live_pools.extend((by_group["B2"], by_group["B1"]))
    used = {trial.scenario.world.customer_id for trial in trials}
    live: list[Trial] = []
    # Interleave equally across both authority paths and both tools.
    for index in range(LIVE_SLOTS):
        choices = live_pools[index % len(live_pools)]
        selected = next((row for (row,) in choices if row.scenario.world.customer_id not in used
                         and _unambiguous_live_item(fixture, row)), None)
        if selected is None:
            raise ValueError("pinned fixture has no fresh live acceptance case")
        live.append(selected)
        used.add(selected.scenario.world.customer_id)
    return Panel(tuple(trials), tuple(live), dict(census))


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("db_json", type=Path)
    panel = generate(parser.parse_args().db_json.read_bytes())
    print(json.dumps({"fixture_sha256": FIXTURE_SHA256, "seed": SEED, "census": panel.census,
                      "attempts": Counter(trial.group for trial in panel.trials)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
