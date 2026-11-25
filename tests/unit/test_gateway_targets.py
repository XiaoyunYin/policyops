"""Target authority, bounded sibling collection and preserved mutation version coverage."""

import pytest

from policyops.domain.retail_rules import MAX_SIBLING_READS, Denied, Escalated, TargetSelection, select_order_target
from policyops.gateway.facts import INCONSISTENT, INVALID, SIBLING_LIMIT, Collected, collect
from policyops.gateway.ports import IncompleteHistory
from policyops.gateway.stores import stated_order_ids
from policyops_contracts.errors import ErrorCode
from policyops_contracts.retail import CancelPendingOrder, GetOrderDetails, ResourceVersion, ToolName
from policyops_contracts.retail_service import OrderOutput, ReadResult, UserOutput
from policyops_testing.gateway_cases import SCOPE, FakeRetail, W, order_detail, state, user_detail


TARGET = W.order_id
OTHER = "#W9999999"
CALL = CancelPendingOrder(order_id=TARGET, reason="no longer needed")
REFUSED = Denied(ErrorCode.POLICY_DENIED, "cancel.order_and_reason", "target_clarification_required")
INCOMPLETE = Escalated("cancel.order_and_reason", "target_selection_facts_incomplete")


@pytest.mark.parametrize(("messages", "cutoff", "eligible", "expected"), [
    ([("seeded", 1, f"Order {TARGET}.")], None, None, "customer_stated"),
    ([("simulated_customer", 1, f"({TARGET[1:]})")], None, None, "customer_stated"),
    ([("operator_entered_customer", 1, f"{OTHER} and {TARGET}")], None, None, "customer_stated"),
    ([("seeded", 1, OTHER)], None, frozenset({TARGET}), REFUSED),
    ([(source, i, TARGET) for i, source in enumerate(("agent", "staff_note", "helpdesk_ticket", "tool"), 1)],
     None, frozenset({TARGET, OTHER}), REFUSED),
    ([("operator_entered_customer", 2, TARGET), ("simulated_customer", 3, TARGET)], 2,
     frozenset({TARGET, OTHER}), REFUSED),
    ([("seeded", 1, f"x{TARGET} {TARGET}0 {TARGET}x ##{TARGET[1:]}")], None, frozenset({OTHER}), REFUSED),
    ([], None, frozenset({TARGET}), "sole_eligible"),
    ([], None, frozenset(), REFUSED),
    ([], None, None, INCOMPLETE),
    ([], None, frozenset(f"#W{9_000_000 + n}" for n in range(MAX_SIBLING_READS + 2)), INCOMPLETE),
])
def test_select_order_target(messages: list[tuple[str, int, str]], cutoff: int | None,
                             eligible: frozenset[str] | None, expected: str | Denied | Escalated) -> None:
    stated = stated_order_ids(messages, before_sequence=cutoff)
    assert select_order_target(ToolName.CANCEL_PENDING_ORDER, TARGET, TargetSelection(stated, eligible)) == expected


class OrderProfile(FakeRetail):
    def __init__(self, siblings: tuple[str, ...], *, mismatch: bool = False, foreign: bool = False,
                 omitted: bool = False, duplicate: bool = False) -> None:
        super().__init__(state())
        self.siblings, self.mismatch, self.foreign = siblings, mismatch, foreign
        self.omitted, self.duplicate = omitted, duplicate

    def _answer(self, call: object) -> ReadResult:
        if isinstance(call, GetOrderDetails) and call.order_id in self.siblings:
            order = order_detail(self.state).model_copy(update={"order_id": call.order_id, "status": "delivered",
                                                                "user_id": "another_customer" if self.foreign
                                                                else self.customer_id})
            return ReadResult(output=OrderOutput(order=order), case_version=self.state.case_version + self.mismatch,
                              resource_versions=(ResourceVersion(kind="order", resource_id=order.order_id,
                                                                 version=order.version),))
        reply = super()._answer(call)
        if isinstance(reply.output, UserOutput):
            own = () if self.omitted else (TARGET, TARGET) if self.duplicate else (TARGET,)
            output = UserOutput(user=user_detail(self.state).model_copy(update={"order_ids": own + self.siblings}))
            return reply.model_copy(update={"output": output})
        return reply


def test_siblings_are_coherent_eligibility_facts_and_do_not_enter_mutation_versions() -> None:
    retail = OrderProfile((OTHER,))
    result = collect(retail, SCOPE, CALL, IncompleteHistory(), stated_ids=frozenset())
    assert isinstance(result, Collected)
    assert result.facts.target_selection == TargetSelection(frozenset(), frozenset({TARGET}))
    assert result.reads == len(retail.calls) == 3
    assert {version.resource_id for version in result.resource_versions} == {W.user_id, TARGET}


def test_sibling_reads_fail_closed_and_respect_the_total_cap() -> None:
    many = tuple(f"#W{9_000_000 + n}" for n in range(MAX_SIBLING_READS + 1))
    for retail, expected, reads in [
        (OrderProfile(many), SIBLING_LIMIT, 2),
        (OrderProfile(many[:9], mismatch=True), SIBLING_LIMIT, 13),
        (OrderProfile((OTHER,), mismatch=True), INCONSISTENT, 9),
        (OrderProfile((OTHER,), foreign=True), INVALID, 3),
        (OrderProfile((), omitted=True), INVALID, 2),
        (OrderProfile((), duplicate=True), INVALID, 2),
    ]:
        assert collect(retail, SCOPE, CALL, IncompleteHistory(), stated_ids=frozenset()) == expected
        assert len(retail.calls) == reads
    retail = OrderProfile(many)
    result = collect(retail, SCOPE, CALL, IncompleteHistory(), stated_ids=frozenset({TARGET}))
    assert isinstance(result, Collected) and len(retail.calls) == 2
