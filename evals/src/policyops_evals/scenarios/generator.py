"""Offline N2 manifest generator. Stdout contains digests and aggregate counts only."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Literal, NamedTuple
from uuid import UUID

from pydantic import BaseModel

from policyops.domain.retail_rules import Allowed, Denied, RetailFacts, evaluate_write
from policyops.domain.session import Authenticated, CustomerSession, apply_lookup
from policyops_contracts.conversation import KNOWLEDGE_TOOL
from policyops_contracts.policy import RETAIL_POLICY, RETAIL_RULES
from policyops_contracts.retail import (
    Address,
    CancelPendingOrder,
    CancelReason,
    FindUserIdByEmail,
    ModifyUserAddress,
    ReturnDeliveredOrderItems,
    ToolName,
    WriteToolCall,
)
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding
from policyops_evals.policy_trace import trace_policy
from policyops_evals.retail_sim.engine import order_detail, user_detail
from policyops_evals.scenarios import templates_v1 as templates
from policyops_evals.scenarios.cases import (
    POSITIVES,
    STRATA,
    Construction,
    Disposition,
    Gold,
    OrderIdForm,
    OrderRead,
    PolicySpan,
    Scenario,
    Stratum,
    VisibleCase,
    World,
)


REPO = Path(__file__).resolve().parents[4]
Split = Literal["dev", "held-out"]
SPLITS: tuple[Split, ...] = ("dev", "held-out")
FIXTURE_SEED, FAMILY_SEED, RENDER_SEED = 2101, 2102, 2103
REASONS: tuple[CancelReason, ...] = ("no longer needed", "ordered by mistake")
PAYMENT_NAMES = {"paypal": "PayPal", "credit_card": "a credit card", "gift_card": "a gift card"}
GROUPS: dict[Stratum, str] = {
    "cancel": "cancel", "delivered_refusal": "cancel", "missing_reason": "cancel",
    "multi_resolvable": "multi", "multi_ambiguous": "multi", "return": "return",
    "default_address": "address", "handoff": "handoff",
}
FAMILIES = {"cancel": templates.CANCEL, "return": templates.RETURN, "multi": templates.MULTI,
            "address": templates.ADDRESS, "handoff": templates.HANDOFF}
CANCEL_CLAUSES = ("cancel.pending_only", "cancel.order_and_reason")
CLAUSES: dict[Stratum, tuple[str, ...]] = {
    "cancel": CANCEL_CLAUSES, "multi_resolvable": CANCEL_CLAUSES,
    "return": ("return.delivered_only", "return.order_and_items", "return.refund_method_required",
               "return.refund_destination"),
    "default_address": ("user_address.supported",),
    "delivered_refusal": ("cancel.pending_only",), "missing_reason": ("cancel.order_and_reason",),
    "multi_ambiguous": ("cancel.order_and_reason",), "handoff": ("escalation.transfer",),
}
DISTRACTORS: dict[Stratum, tuple[str, ...]] = {
    "delivered_refusal": ("return.delivered_only",), "default_address": ("modify.allowed_fields",),
    "return": ("exchange.delivered_only_all_items",), "multi_resolvable": ("modify.pending_only",),
    "multi_ambiguous": ("modify.pending_only",),
}
FIXED_SCOPE = RunScope(workspace_id=UUID(int=1), case_id=UUID(int=2), run_id=UUID(int=3))
FIXED_TIME = datetime(2026, 1, 1, tzinfo=UTC)
VISIBLE_LEAK = re.compile(
    r"(?<![\w.])(?:" + "|".join(re.escape(word) for word in (
        *(rule.rule_id for rule in RETAIL_RULES), *(tool.value for tool in ToolName), KNOWLEDGE_TOOL, "finish_answer",
        "held-out", "held_out", "gold", "ground truth", "respond in JSON", "say exactly", "pending",
        "delivered", "processed", "system prompt", "evaluator", "required_reads", "payment_history",
    )) + r")(?!\w)", re.I,
)


def _rank(seed: int, *values: str) -> bytes:
    return sha256(json.dumps([seed, *values], separators=(",", ":")).encode()).digest()


def _number(seed: int, *values: str) -> int:
    return int.from_bytes(_rank(seed, *values), "big")


def quotas(split: Split, stratum: Stratum) -> int:
    return (24 if stratum in POSITIVES else 8) * (1 if split == "dev" else 2)


@dataclass(frozen=True)
class FixtureData:
    users: Mapping[str, dict[str, Any]]
    orders: Mapping[str, dict[str, Any]]


def verified_fixture(raw: bytes) -> FixtureData:
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError("retail fixture digest mismatch")
    body = json.loads(raw)
    fixture = FixtureData(body["users"], body["orders"])
    declared: dict[str, str] = {}
    for customer, user in fixture.users.items():
        if customer != user["user_id"]:
            raise ValueError("retail profile identity mismatch")
        for order_id in user["orders"]:
            if order_id in declared:
                raise ValueError("retail order closures overlap")
            declared[order_id] = customer
    if declared != {oid: order["user_id"] for oid, order in fixture.orders.items()} or any(
        oid != order["order_id"] for oid, order in fixture.orders.items()
    ):
        raise ValueError("retail order closure differs from ownership")
    if len({user["email"] for user in fixture.users.values()}) != len(fixture.users):
        raise ValueError("retail lookup email is ambiguous")
    return fixture


class Selector(NamedTuple):
    attribute: Literal["shipping_city", "item_count", "payment_kind"]
    value: str

    def wording(self) -> str:
        if self.attribute == "shipping_city":
            return f"with the shipping address in {self.value}"
        if self.attribute == "payment_kind":
            return f"I paid for with {PAYMENT_NAMES[self.value]}"
        noun = "item" if self.value == "1" else "items"
        return f"with {self.value} {noun} in it"


@dataclass(frozen=True)
class Candidate:
    customer: str
    order_id: str | None = None
    selector: Selector | None = None


@dataclass(frozen=True)
class Census:
    unit: Literal["order", "customer", "customer_selector"]
    eligible: int
    rejected: Mapping[str, int]
    eligible_customers: int
    outside_order_count: int = 0


def _payment(user: Mapping[str, Any], order: Mapping[str, Any]) -> str | None:
    history = order["payment_history"]
    if len(history) == 1 and history[0]["transaction_type"] == "payment":
        method: str = history[0]["payment_method_id"]
        kind = user["payment_methods"].get(method, {}).get("source")
        if kind in PAYMENT_NAMES and method.startswith(kind + "_"):
            return method
    return None


def selectors(user: Mapping[str, Any], order: Mapping[str, Any]) -> tuple[Selector, ...]:
    fields = (Selector("shipping_city", order["address"]["city"]), Selector("item_count", str(len(order["items"]))))
    kinds = {user["payment_methods"].get(record["payment_method_id"], {}).get("source")
             for record in order["payment_history"] if record["transaction_type"] == "payment"}
    return (*fields, *(Selector("payment_kind", kind) for kind in sorted(kinds & PAYMENT_NAMES.keys())))


def _multi_choices(fixture: FixtureData, customer: str) -> dict[Selector, tuple[str, ...]]:
    user = fixture.users[customer]
    matches: dict[Selector, list[str]] = defaultdict(list)
    for oid in sorted(user["orders"]):
        for selector in selectors(user, fixture.orders[oid]):
            matches[selector].append(oid)
    return {selector: tuple(orders) for selector, orders in matches.items()}


def _multi_pool(fixture: FixtureData, stratum: Stratum, choices: list[Candidate], rejects: Counter[str]) -> int:
    count = 1 if stratum == "multi_resolvable" else 2
    outside = 0
    for customer, user in fixture.users.items():
        if not 2 <= len(user["orders"]) <= 3:
            outside += 1
            continue
        matching = _multi_choices(fixture, customer)
        for selector, order_ids in matching.items():
            if len(order_ids) != count:
                rejects["selector_matches_other_cardinality"] += 1
            elif any(fixture.orders[oid]["status"] != "pending" for oid in order_ids):
                rejects["match_not_pending"] += 1
            elif any(_payment(user, fixture.orders[oid]) is None for oid in order_ids):
                rejects["match_without_one_supported_payment"] += 1
            else:
                choices.append(Candidate(customer, selector=selector))
    return outside


def _new_address(customer: str) -> Address:
    unit = _number(RENDER_SEED, "address", customer) % 9000 + 1000
    return Address(address1="418 Juniper Sample Lane", address2=f"Apt {unit}", city="Portland", state="OR",
                   zip="97205", country="USA")


def _pool(fixture: FixtureData, stratum: Stratum) -> tuple[dict[str, Candidate], Census]:
    choices: list[Candidate] = []
    rejects: Counter[str] = Counter()
    outside = 0
    unit: Literal["order", "customer", "customer_selector"] = "order"
    if stratum in {"multi_resolvable", "multi_ambiguous"}:
        unit = "customer_selector"
        outside = _multi_pool(fixture, stratum, choices, rejects)
    elif stratum in {"default_address", "handoff"}:
        unit = "customer"
        for customer, user in fixture.users.items():
            if stratum == "default_address" and _new_address(customer).model_dump() == user["address"]:
                rejects["same_default_address"] += 1
            else:
                choices.append(Candidate(customer))
    else:
        status = "delivered" if stratum in {"return", "delivered_refusal"} else "pending"
        for oid, order in fixture.orders.items():
            customer = order["user_id"]
            if order["status"] != status:
                rejects[f"status_{order['status']}"] += 1
            elif _payment(fixture.users[customer], order) is None:
                rejects["without_one_supported_payment"] += 1
            elif stratum == "return" and not 1 <= len(order["items"]) <= 50:
                rejects["unrepresentable_item_multiset"] += 1
            else:
                choices.append(Candidate(customer, oid))
    chosen: dict[str, Candidate] = {}
    for candidate in sorted(choices, key=lambda c: _rank(FIXTURE_SEED, stratum, c.customer, c.order_id or "",
                                                         *(c.selector or ()))):
        chosen.setdefault(candidate.customer, candidate)
    return chosen, Census(unit, len(choices), dict(rejects), len(chosen), outside)


def _allocate(pools: Mapping[Stratum, Mapping[str, Candidate]]) -> dict[Split, list[tuple[Stratum, Candidate]]]:
    """Fill all quotas with one customer closure per case using augmenting paths."""
    slots = [(split, stratum, i) for split in SPLITS for stratum in STRATA for i in range(quotas(split, stratum))]
    edges = {(split, stratum): sorted(pools[stratum], key=lambda c: _rank(FIXTURE_SEED, split, stratum, c))
             for split in SPLITS for stratum in STRATA}
    slots.sort(key=lambda s: (len(edges[s[:2]]), _rank(FIXTURE_SEED, s[0], s[1], str(s[2]))))
    owners: dict[str, tuple[Split, Stratum, int]] = {}

    def claim(slot: tuple[Split, Stratum, int], visited: set[str]) -> bool:
        split, stratum, _ = slot
        # Prefer unclaimed customers before moving another slot.
        for customer in edges[split, stratum]:
            if customer not in owners:
                owners[customer] = slot
                return True
        for customer in edges[split, stratum]:
            if customer not in visited:
                visited.add(customer)
                if claim(owners[customer], visited):
                    owners[customer] = slot
                    return True
        return False

    for slot in slots:
        if not claim(slot, set()):
            raise ValueError(f"fixture closure matching cannot fill the {slot[0]} {slot[1]} quota")
    result: dict[Split, list[tuple[Stratum, Candidate]]] = {split: [] for split in SPLITS}
    for customer, (split, stratum, _) in owners.items():
        result[split].append((stratum, pools[stratum][customer]))
    return result


def family_ids(group: str, split: Split) -> tuple[int, ...]:
    ordered = sorted(range(len(FAMILIES[group])), key=lambda i: _rank(FAMILY_SEED, group, str(i)))
    return tuple(ordered[:4] if split == "dev" else ordered[4:])


def _session(fixture: FixtureData, customer: str) -> CustomerSession:
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=FIXED_SCOPE.workspace_id, case_id=FIXED_SCOPE.case_id),
                                  seed_id="retail-demo-0000", user_id=customer, bound_at=FIXED_TIME)
    call = FindUserIdByEmail(email=fixture.users[customer]["email"])
    result = apply_lookup(CustomerSession(binding, FIXED_SCOPE), call, customer, step_sequence=1, now=FIXED_TIME)
    if not isinstance(result, Authenticated):
        raise ValueError("fixture identity cannot authenticate")
    return result.session


def cancellation_proof(
    fixture: FixtureData, candidate: Candidate, reason: CancelReason | None,
) -> Construction:
    """Enumerate matching orders, then test permission with the same production preconditions as the gateway."""
    if candidate.selector is not None:
        referents = _multi_choices(fixture, candidate.customer).get(candidate.selector, ())
    else:
        referents = (candidate.order_id,) if candidate.order_id is not None else ()
    if reason is None:
        return Construction(referents, (), missing_field="reason", allowed_values=REASONS)
    user = fixture.users[candidate.customer]
    session = _session(fixture, candidate.customer)
    profile = user_detail({"orders": fixture.orders}, user, 1).to_snapshot()
    solutions: list[CancelPendingOrder] = []
    failed: set[str] = set()
    for oid in referents:
        call = CancelPendingOrder(tool="cancel_pending_order", order_id=oid, reason=reason)
        order = order_detail(fixture.orders[oid], 1).to_snapshot()
        result = evaluate_write(call, session, RetailFacts(profile, order))
        if isinstance(result, Allowed):
            solutions.append(call)
        elif isinstance(result, Denied):
            failed.add(result.rule_id)
        else:
            raise ValueError("cancellation reference path escalates")
    failed_precondition = next(iter(failed)) if len(failed) == 1 else None
    return Construction(referents, tuple(solutions), failed_precondition=failed_precondition,
                        selector=candidate.selector)


def _proof(
    fixture: FixtureData, stratum: Stratum, candidate: Candidate, reason: CancelReason | None,
) -> Construction:
    if stratum == "handoff":
        return Construction((), (), failed_precondition="scope.supported_requests")
    if GROUPS[stratum] in {"cancel", "multi"}:
        return cancellation_proof(fixture, candidate, reason)
    user = fixture.users[candidate.customer]
    profile = user_detail({"orders": fixture.orders}, user, 1).to_snapshot()
    call: WriteToolCall
    if stratum == "default_address":
        call = ModifyUserAddress(tool="modify_user_address", user_id=candidate.customer,
                                 **_new_address(candidate.customer).model_dump())
        facts = RetailFacts(profile)
        referent = candidate.customer
    else:
        oid = candidate.order_id
        if oid is None:
            raise ValueError("return needs an order")
        raw_order = fixture.orders[oid]
        payment = _payment(user, raw_order)
        if payment is None:
            raise ValueError("return needs one original payment")
        order = order_detail(raw_order, 1).to_snapshot()
        call = ReturnDeliveredOrderItems(tool="return_delivered_order_items", order_id=oid,
                                         item_ids=tuple(sorted(item.item_id for item in order.items)),
                                         payment_method_id=payment)
        facts = RetailFacts(profile, order)
        referent = oid
    if not isinstance(evaluate_write(call, _session(fixture, candidate.customer), facts), Allowed):
        raise ValueError("positive fixture reference path denied")
    return Construction((referent,), (call,))


@dataclass(frozen=True)
class Rendering:
    family: int
    lookup: int
    reason: CancelReason | None
    variant: int
    id_form: OrderIdForm

    def message(self, stratum: Stratum, fixture: FixtureData, candidate: Candidate, *, masked: bool = False) -> str:
        group = GROUPS[stratum]
        email = fixture.users[candidate.customer]["email"]
        sections = [templates.LOOKUPS[self.lookup].format(email="{email}" if masked else email)]
        if group in {"multi", "address"}:
            sections.append(templates.ACCOUNT[self.variant % len(templates.ACCOUNT)].format(
                customer="{customer}" if masked else candidate.customer))
        order = candidate.order_id or ""
        if self.id_form == "bare":
            order = order.removeprefix("#")
        address_line = "{address}"
        if group == "address" and not masked:
            address = _new_address(candidate.customer)
            address_line = (f"{address.address1}, {address.address2}, {address.city}, "
                            f"{address.state} {address.zip}, {address.country}")
        sections.append(FAMILIES[group][self.family].format(
            order="{order}" if masked else order, address=address_line,
            description="{description}" if masked or candidate.selector is None else candidate.selector.wording(),
        ))
        if self.reason is not None:
            reasons = templates.NO_LONGER_NEEDED if self.reason == REASONS[0] else templates.ORDERED_BY_MISTAKE
            sections.append(reasons[self.variant % len(reasons)])
        return " ".join(sections)


def _renderings(stratum: Stratum, family: int, candidate: Candidate, order_form: OrderIdForm) -> list[Rendering]:
    group = GROUPS[stratum]
    reasons: Sequence[CancelReason | None] = (
        REASONS if group in {"cancel", "multi"} and stratum != "missing_reason" else (None,)
    )
    variants = 3 if group in {"cancel", "multi", "address"} else 1
    options = [Rendering(family, i, reason, j, order_form) for i in range(len(templates.LOOKUPS))
               for reason in reasons for j in range(variants)]
    return sorted(options, key=lambda r: _rank(RENDER_SEED, candidate.customer, str(family), str(r.lookup),
                                                r.reason or "", str(r.variant)))


def _spans(raw: bytes) -> dict[str, PolicySpan]:
    trace_policy(raw)
    lines = raw.decode().split("\n")
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line) + 1)
    return {r.rule_id: PolicySpan(r.rule_id, starts[r.line_start - 1], "\n".join(lines[r.line_start - 1:r.line_end]))
            for r in RETAIL_RULES}


def _scenario(fixture: FixtureData, stratum: Stratum, candidate: Candidate, rendering: Rendering,
              spans: Mapping[str, PolicySpan]) -> Scenario:
    customer = candidate.customer
    email = fixture.users[customer]["email"]
    key = _rank(FIXTURE_SEED, "scenario-v1", customer).hex()[:24]
    visible = VisibleCase(email, rendering.message(stratum, fixture, candidate), key)
    if VISIBLE_LEAK.search(visible.message):
        raise ValueError("visible scenario text contains evaluation metadata or hidden status")
    proof = _proof(fixture, stratum, candidate, rendering.reason)
    expected = 1 if stratum in POSITIVES else 2 if stratum == "multi_ambiguous" else 0
    if len(proof.solutions) != expected or (stratum == "delivered_refusal" and
                                           proof.failed_precondition != "cancel.pending_only"):
        raise ValueError(f"construction failed for {stratum}")
    disposition: Disposition = "propose"
    if stratum == "delivered_refusal":
        disposition = "refuse"
    elif stratum in {"missing_reason", "multi_ambiguous"}:
        disposition = "insufficient_information"
    elif stratum == "handoff":
        disposition = "handoff"
    closure = tuple(sorted(fixture.users[customer]["orders"]))
    oid = candidate.order_id
    if stratum == "multi_resolvable":
        oid = proof.referents[0]
    order = fixture.orders[oid] if oid is not None else None
    world = World(customer, oid, order["status"] if order is not None else None,
                  _payment(fixture.users[customer], order) if order is not None else None, closure)
    reads = ("identity",) if stratum != "handoff" else ()
    order_ids = (oid,) if oid is not None else ()
    if GROUPS[stratum] == "multi":
        reads = (*reads, "profile")
        order_ids = closure
    if order_ids:
        reads = (*reads, "order")
    gold = Gold(disposition, proof.solutions[0] if disposition == "propose" else None, reads, CLAUSES[stratum],
                key=key, stratum=stratum, customer_world=customer,
                order_reads=tuple(OrderRead(o, order_detail(fixture.orders[o], 1).status) for o in order_ids),
                policy_sha256=RETAIL_POLICY.sha256, clause_spans=tuple(spans[c] for c in CLAUSES[stratum]),
                distractor_spans=tuple(spans[c] for c in DISTRACTORS.get(stratum, ())), proof=proof,
                family=f"{GROUPS[stratum]}-v1-{rendering.family:02}", order_id_form=rendering.id_form)
    return Scenario(key, world, visible, gold)


@dataclass(frozen=True)
class Generation:
    cases: Mapping[Split, tuple[Scenario, ...]]
    census: Mapping[Stratum, Census]
    masked_collisions: int

    def manifests(self) -> dict[str, bytes]:
        return {f"{split}.{kind}.jsonl": _jsonl([asdict(getattr(case, kind)) for case in cases])
                for split, cases in self.cases.items() for kind in ("visible", "gold")}


def generate(fixture_bytes: bytes, policy_bytes: bytes) -> Generation:
    fixture = verified_fixture(fixture_bytes)
    spans = _spans(policy_bytes)
    pools, census = {}, {}
    for stratum in STRATA:
        pools[stratum], census[stratum] = _pool(fixture, stratum)
    allocated = _allocate(pools)
    masked_texts: set[str] = set()
    collisions = 0
    cases: dict[Split, tuple[Scenario, ...]] = {}
    for split, chosen in allocated.items():
        by_stratum: Counter[Stratum] = Counter()
        rendered: list[Scenario] = []
        for stratum, candidate in sorted(chosen, key=lambda x: _rank(RENDER_SEED, split, x[1].customer)):
            ids = family_ids(GROUPS[stratum], split)
            index = by_stratum[stratum]
            by_stratum[stratum] += 1
            family = ids[index % len(ids)]
            form: OrderIdForm = "absent"
            if candidate.order_id is not None:
                form = "hash" if index % 2 == 0 else "bare"
            for rendering in _renderings(stratum, family, candidate, form):
                masked = rendering.message(stratum, fixture, candidate, masked=True)
                if masked in masked_texts:
                    collisions += 1
                    continue
                masked_texts.add(masked)
                rendered.append(_scenario(fixture, stratum, candidate, rendering, spans))
                break
            else:
                raise ValueError(f"unique wording exhausted for {split} {stratum}")
        cases[split] = tuple(rendered)
    return Generation(cases, census, collisions)


def _encode_model(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError("unexpected manifest value")


def _jsonl(rows: Sequence[object]) -> bytes:
    return "".join(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
                              default=_encode_model) + "\n" for row in rows).encode("utf-8")


def write_manifests(out: Path, manifests: Mapping[str, bytes]) -> dict[str, str]:
    if set(manifests) != {f"{split}.{kind}.jsonl" for split in SPLITS for kind in ("visible", "gold")}:
        raise ValueError("unexpected manifest filenames")
    target = out.resolve()
    if any(path == REPO or (path / ".git").exists() for path in (target, *target.parents)):
        raise ValueError("manifest output must be outside the repository")
    target.mkdir(parents=True, exist_ok=True)
    paths = {target / name: data for name, data in manifests.items()}
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ValueError("manifest output already exists")
    created: list[Path] = []
    try:
        for path, data in paths.items():
            with path.open("xb") as handle:
                created.append(path)
                handle.write(data)
    except OSError:
        for path in created:
            path.unlink()
        raise
    return {path.name: sha256(data).hexdigest() for path, data in paths.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = generate(args.db.read_bytes(), args.policy.read_bytes())
        digests = write_manifests(args.out, result.manifests())
    except (OSError, ValueError) as exc:
        # ValidationError and OS diagnostics may contain fixture fields or a sensitive path.
        parser.exit(1, f"Scenario generation failed ({type(exc).__name__}).\n")
    print(json.dumps({"sha256": digests, "census": {name: asdict(row) for name, row in result.census.items()},
                      "masked_collisions": result.masked_collisions}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
