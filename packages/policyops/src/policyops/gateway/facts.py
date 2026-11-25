"""Coherent, bounded fact collection for one write decision (T17).

The facts for one decision are read in a fixed order through the scope-bound retail port:
1. the bound customer (`get_user_details`);
2. the target order (`get_order_details`), for an order write;
3. each distinct replacement item (`get_item_details`), for an item modification or exchange, so the product of a
   replacement is the service's answer and never assumed from the call.

**Each read must be the read that was asked for.** It must be the expected output kind and name the requested
user, order or item. It must list exactly the one resource version that the detail itself carries. Anything else
is a contract violation by the service and is refused at once (`facts_invalid`), without retrying.

**All reads must report the same `case_version`.** A different one means a write committed between two reads.
The whole collection is then repeated, at most `MAX_COLLECTIONS` times in total, and after that refused with a
fixed retryable `facts_inconsistent`. A mixed-version fact set is never evaluated.

**No retries hide inside a read.** `Unknown` and refusals are mapped, not retried here, and no database transaction
is open while reading. This is not a guarantee against a later concurrent write: the service's expected-version
check under its case lock stays authoritative at commit.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from policyops.adapters.retail_client import Refused, Unknown
from policyops.domain.retail_rules import MAX_SIBLING_READS, ONCE_PER_ORDER, ORDER_TARGETS, RetailFacts, TargetSelection
from policyops.gateway.ports import GatewayScope, HistoryPort, RetailPort
from policyops_contracts.errors import ErrorCode
from policyops_contracts.retail import (
    ExchangeDeliveredOrderItems,
    GetItemDetails,
    GetOrderDetails,
    GetUserDetails,
    ModifyPendingOrderItems,
    ModifyUserAddress,
    ResourceVersion,
    ToolName,
    WriteToolCall,
)
from policyops_contracts.retail_service import OrderOutput, ReadResult, UserOutput, VariantOutput


MAX_COLLECTIONS = 3  # the initial collection plus at most two complete recollections


@dataclass(frozen=True)
class Collected:
    facts: RetailFacts
    case_version: int
    resource_versions: tuple[ResourceVersion, ...]
    collections: int
    reads: int


@dataclass(frozen=True)
class FactsRefused:
    code: ErrorCode
    rule_id: str | None
    detail: str
    retryable: bool


class _Stop(Exception):
    def __init__(self, refusal: FactsRefused) -> None:
        self.refusal = refusal


INVALID = FactsRefused(ErrorCode.UNAVAILABLE, None, "facts_invalid", False)
INCONSISTENT = FactsRefused(ErrorCode.UNAVAILABLE, None, "facts_inconsistent", True)
UNAVAILABLE = FactsRefused(ErrorCode.UNAVAILABLE, None, "retail_unavailable", True)
REFUSED = FactsRefused(ErrorCode.UNAVAILABLE, None, "retail_refused", False)
SIBLING_LIMIT = FactsRefused(ErrorCode.UNAVAILABLE, None, "target_selection_read_limit", False)
ORDER_NOT_FOUND = FactsRefused(ErrorCode.NOT_FOUND, "scope.single_customer", "order_not_found", False)
NOT_FOUND_STATUSES = frozenset({404})
REJECTED = frozenset({"not_found", "upstream_rejected"})


def _version(kind: str, resource_id: str, version: int) -> tuple[ResourceVersion, ...]:
    return (ResourceVersion(kind=kind, resource_id=resource_id, version=version),)  # type: ignore[arg-type]


def _read(retail: RetailPort, call: Any, absent: FactsRefused) -> ReadResult:
    try:
        result = retail.read(call)
    except Refused as refused:
        if refused.status in NOT_FOUND_STATUSES or refused.code in REJECTED:
            raise _Stop(absent) from None
        raise _Stop(REFUSED) from None
    if isinstance(result, Unknown):
        raise _Stop(UNAVAILABLE)
    if not isinstance(result, ReadResult):
        raise _Stop(INVALID)
    return result


def _item_prefix(call: WriteToolCall) -> str:
    return "items" if isinstance(call, ModifyPendingOrderItems) else "exchange"


def _read_order(retail: RetailPort, order_id: str, absent: FactsRefused) -> tuple[OrderOutput, ReadResult]:
    result = _read(retail, GetOrderDetails(order_id=order_id), absent)
    output = result.output
    if not isinstance(output, OrderOutput) or output.order.order_id != order_id or \
            result.resource_versions != _version("order", order_id, output.order.version):
        raise _Stop(INVALID)
    return output, result


def _collect_once(retail: RetailPort, scope: GatewayScope, call: WriteToolCall, *,
                  stated_ids: frozenset[str] | None, sibling_budget: int
                  ) -> tuple[RetailFacts, list[ReadResult], list[ReadResult]]:
    customer_id = scope.customer_user_id
    results: list[ReadResult] = []
    user_result = _read(retail, GetUserDetails(user_id=customer_id), INVALID)
    output = user_result.output
    if not isinstance(output, UserOutput) or output.user.user_id != customer_id or \
            user_result.resource_versions != _version("user", customer_id, output.user.version):
        raise _Stop(INVALID)
    results.append(user_result)
    customer = output.user.to_snapshot()
    if isinstance(call, ModifyUserAddress):
        return RetailFacts(customer=customer), results, []
    order_output, order_result = _read_order(retail, call.order_id, ORDER_NOT_FOUND)
    results.append(order_result)
    order = order_output.order
    siblings: list[ReadResult] = []
    selection = TargetSelection(stated_ids) if stated_ids is not None else None
    if stated_ids == frozenset() and order.user_id == customer_id:
        order_ids = output.user.order_ids
        if len(set(order_ids)) != len(order_ids):
            raise _Stop(INVALID)
        if user_result.case_version == order_result.case_version and call.order_id not in order_ids:
            raise _Stop(INVALID)
        sibling_ids = tuple(oid for oid in order_ids if oid != call.order_id)
        if len(sibling_ids) > sibling_budget:
            raise _Stop(SIBLING_LIMIT)
        required, _ = ORDER_TARGETS[ToolName(call.tool)]
        eligible = {call.order_id} if order.status == required else set()
        for sibling_id in sibling_ids:
            sibling, sibling_result = _read_order(retail, sibling_id, INVALID)
            siblings.append(sibling_result)
            if sibling.order.user_id != customer_id:
                raise _Stop(INVALID)
            if sibling.order.status == required:
                eligible.add(sibling_id)
        selection = TargetSelection(stated_ids, frozenset(eligible))
    variants = []
    if isinstance(call, ModifyPendingOrderItems | ExchangeDeliveredOrderItems):
        absent = FactsRefused(ErrorCode.NOT_FOUND, f"{_item_prefix(call)}.same_product_other_option",
                              "replacement_item_not_found", False)
        for item_id in dict.fromkeys(call.new_item_ids):
            item_result = _read(retail, GetItemDetails(item_id=item_id), absent)
            item_output = item_result.output
            if not isinstance(item_output, VariantOutput) or item_output.variant.item_id != item_id or \
                    item_result.resource_versions != _version("product", item_output.variant.product_id,
                                                              item_output.variant.product_version):
                raise _Stop(INVALID)
            results.append(item_result)
            variants.append(item_output.variant.to_snapshot())
    return RetailFacts(customer=customer, order=order.to_snapshot(), variants=tuple(variants),
                       target_selection=selection), results, siblings


def collect(retail: RetailPort, scope: GatewayScope, call: WriteToolCall, history: HistoryPort, *,
            stated_ids: frozenset[str] | None = None) -> Collected | FactsRefused:
    reads = 0
    sibling_budget = MAX_SIBLING_READS
    for attempt in range(1, MAX_COLLECTIONS + 1):
        try:
            facts, results, siblings = _collect_once(retail, scope, call, stated_ids=stated_ids,
                                                     sibling_budget=sibling_budget)
        except _Stop as stop:
            return stop.refusal
        sibling_budget -= len(siblings)
        reads += len(results) + len(siblings)
        case_versions = {result.case_version for result in (*results, *siblings)}
        if len(case_versions) != 1:
            continue
        (case_version,) = case_versions
        if facts.order is not None and ToolName(call.tool) in ONCE_PER_ORDER:
            recorded = history.history(facts.order.order_id, case_version=case_version)
            if recorded.order_id != facts.order.order_id:
                return INVALID
            facts = replace(facts, history=recorded)
        versions = tuple(sorted({version for result in results for version in result.resource_versions},
                                key=lambda v: (v.kind, v.resource_id)))
        return Collected(facts=facts, case_version=case_version, resource_versions=versions, collections=attempt,
                         reads=reads)
    return INCONSISTENT
