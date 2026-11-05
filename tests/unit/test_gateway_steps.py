"""Gateway scope binding, lookup persistence, read checks, coherent facts and closed dispatch (T17, offline)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import TypeAdapter
import pytest

from policyops.adapters.retail_client import Refused, Unknown
from policyops.domain.retail_rules import Allowed
from policyops.gateway.facts import MAX_COLLECTIONS
from policyops.gateway.ports import GatewayScope, IncompleteHistory, ScopeMismatch
from policyops.gateway.steps import Gateway, parse_result
from policyops.persistence.customer_authentications import AuthenticationConflict
from policyops_contracts.agent import AgentStep, MessageStep, ToolCallStep
from policyops_contracts.clock import FixedClock
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import LookupObservation, ProposalPreview, ReadObservation, ToolError, ToolObservation
from policyops_contracts.retail import (
    HANDOFF_MESSAGE,
    FindUserIdByEmail,
    GetItemDetails,
    GetOrderDetails,
    GetUserDetails,
    ResourceVersion,
)
from policyops_contracts.retail_service import FIXTURE_SHA256, OrderOutput, ReadResult, UserIdOutput, VariantOutput
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding
from policyops_testing.gateway_cases import (
    EMAIL,
    INJECTION,
    SCOPE,
    FakeRetail,
    MemorySessions,
    Setup,
    TestOnlyCompleteHistory,
    TripwireRetail,
    W,
    authenticated_sessions,
    cancel,
    exchange,
    gateway_for,
    items,
    message,
    order_address,
    payment,
    state,
    tool,
    user_address,
)


STEP: TypeAdapter[ToolCallStep | MessageStep] = TypeAdapter(AgentStep)
OBSERVATION: TypeAdapter[Any] = TypeAdapter(ToolObservation)


def run(gateway: Gateway, raw: Any, *, previous: Any = None, sequence: int = 2) -> Any:
    parsed = parse_result(raw)
    assert not isinstance(parsed, ToolError), parsed
    return gateway.step(parsed, previous=previous, sequence=sequence)


# -- scope binding before any contact -----------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["tenant_id", "case_id", "customer_id", "fixture_sha256"])
def test_a_client_bound_to_anything_else_is_refused_before_contact(field: str) -> None:
    foreign: dict[str, Any] = {"tenant_id": UUID(int=91), "case_id": UUID(int=92), "customer_id": W.other_user,
               "fixture_sha256": "0" * 64}
    retail = TripwireRetail(state(), **{field: foreign[field]})
    with pytest.raises(ScopeMismatch):
        Gateway(SCOPE, retail=retail, sessions=authenticated_sessions(), clock=FixedClock(W.now))


def test_a_scope_cannot_pair_a_run_with_another_cases_binding() -> None:
    other_case = CaseCustomerBinding(scope=CaseScope(workspace_id=W.workspace, case_id=UUID(int=77)),
                                     seed_id="retail-demo-9999", user_id=W.user_id, bound_at=W.now)
    with pytest.raises(ScopeMismatch):
        GatewayScope(run=W.run_scope, binding=other_case, fixture_sha256=FIXTURE_SHA256)


@pytest.mark.parametrize("raw", [tool("get_user_details", user_id=W.other_user), user_address(W.other_user)])
def test_a_model_supplied_customer_is_compared_never_adopted(raw: Any) -> None:
    gateway, retail, _ = gateway_for(Setup())
    result = run(gateway, raw)
    assert isinstance(result.observation, ToolError)
    assert (result.observation.code, result.observation.rule_id) == (ErrorCode.CUSTOMER_MISMATCH,
                                                                     "scope.single_customer")
    assert retail.calls == []


# -- lookup authentication ---------------------------------------------------------------------------------------

def test_only_a_successful_lookup_of_the_bound_customer_is_recorded_once() -> None:
    gateway, retail, sessions = gateway_for(Setup(authenticated=False))
    first = run(gateway, tool("find_user_id_by_email", email=EMAIL), sequence=4)
    assert first.observation == LookupObservation(tool="find_user_id_by_email", outcome="authenticated")
    (recorded,) = sessions.records.values()
    assert (recorded.scope, recorded.user_id, recorded.step_sequence) == (W.run_scope, W.user_id, 4)
    again = run(gateway, tool("find_user_id_by_name_zip", first_name="Example", last_name="User", zip="00001"),
                sequence=9)
    assert isinstance(again.observation, LookupObservation) and again.observation.outcome == "authenticated"
    assert list(sessions.records.values()) == [recorded] and sessions.writes == 1  # first write wins
    assert retail.calls == [FindUserIdByEmail(email=EMAIL), retail.calls[1]]


@pytest.mark.parametrize(("answer", "expected"), [
    (Refused(422, "upstream_rejected"), "not_found"),
    (Refused(404, "not_found"), "not_found"),
])
def test_an_unsuccessful_lookup_records_nothing(answer: Exception, expected: Any) -> None:
    def refuse(call: Any, result: Any, n: int) -> Any:
        raise answer

    gateway, _, sessions = gateway_for(Setup(authenticated=False), retail=FakeRetail(state(), tamper=refuse))
    result = run(gateway, tool("find_user_id_by_email", email=EMAIL))
    assert result.observation == LookupObservation(tool="find_user_id_by_email", outcome=expected)
    assert sessions.records == {} and sessions.writes == 0
    follow = run(gateway, tool("get_order_details", order_id=W.order_id))
    assert isinstance(follow.observation, ToolError) and follow.observation.code == "customer_not_authenticated"


def test_a_lookup_answering_another_customer_is_a_mismatch_and_not_recorded() -> None:
    def other(call: Any, result: ReadResult, n: int) -> Any:
        return result.model_copy(update={"output": UserIdOutput(user_id=W.other_user)})

    gateway, _, sessions = gateway_for(Setup(authenticated=False), retail=FakeRetail(state(), tamper=other))
    result = run(gateway, tool("find_user_id_by_email", email=EMAIL))
    assert isinstance(result.observation, ToolError)
    assert (result.observation.code, result.observation.rule_id) == ("customer_mismatch", "scope.single_customer")
    assert W.other_user not in result.observation.model_dump_json()
    assert sessions.records == {}


@pytest.mark.parametrize("answer", [Unknown("timeout"), Refused(401, "bad_signature")])
def test_an_unknown_or_refused_lookup_is_not_authentication(answer: Any) -> None:
    def fail(call: Any, result: Any, n: int) -> Any:
        if isinstance(answer, Exception):
            raise answer
        return answer

    gateway, _, sessions = gateway_for(Setup(authenticated=False), retail=FakeRetail(state(), tamper=fail))
    result = run(gateway, tool("find_user_id_by_email", email=EMAIL))
    assert isinstance(result.observation, ToolError) and result.observation.code == "unavailable"
    assert result.observation.retryable is isinstance(answer, Unknown)
    assert sessions.records == {}


def test_a_concurrent_conflicting_first_write_is_refused_not_adopted() -> None:
    class Raced(MemorySessions):
        def record(self, authentication: Any) -> Any:
            raise AuthenticationConflict("the run is already authenticated as someone else")

    gateway, _, _ = gateway_for(Setup(authenticated=False), sessions=Raced())
    result = run(gateway, tool("find_user_id_by_email", email=EMAIL))
    assert isinstance(result.observation, ToolError)
    assert (result.observation.code, result.observation.detail) == ("customer_mismatch", "authentication_conflict")


def test_a_stored_authentication_of_another_identity_fails_closed() -> None:
    authentication = W.session().authentication
    assert authentication is not None
    foreign = authentication.model_copy(update={"user_id": W.other_user})
    gateway, retail, _ = gateway_for(Setup(), sessions=MemorySessions(foreign))
    result = run(gateway, tool("get_order_details", order_id=W.order_id))
    assert isinstance(result.observation, ToolError) and result.observation.code == "customer_mismatch"
    assert retail.calls == []


def test_a_lookup_result_listing_resource_versions_is_invalid() -> None:
    def listed(call: Any, result: ReadResult, n: int) -> Any:
        return result.model_copy(update={"resource_versions": (
            ResourceVersion(kind="user", resource_id=W.user_id, version=3),)})

    gateway, _, sessions = gateway_for(Setup(authenticated=False), retail=FakeRetail(state(), tamper=listed))
    result = run(gateway, tool("find_user_id_by_email", email=EMAIL))
    assert isinstance(result.observation, ToolError) and result.observation.detail == "facts_invalid"
    assert sessions.records == {}


# -- typed reads must be the requested resource ----------------------------------------------------------------------

def _wrong_order(call: Any, result: ReadResult, n: int) -> Any:
    if isinstance(call, GetOrderDetails):
        order = result.output.order.model_copy(update={"order_id": "#W0000002"})  # type: ignore[union-attr]
        return result.model_copy(update={"output": OrderOutput(order=order)})
    return result


def _versions(*listed: tuple[str, str, int]) -> Any:
    def tamper(call: Any, result: ReadResult, n: int) -> Any:
        if isinstance(call, GetOrderDetails | GetItemDetails):
            return result.model_copy(update={"resource_versions": tuple(
                ResourceVersion(kind=k, resource_id=r, version=v) for k, r, v in listed)})  # type: ignore[arg-type]
        return result
    return tamper


WRONG_READS = {
    "wrong-order-identity": _wrong_order,
    "missing-version": _versions(),
    "wrong-version-number": _versions(("order", W.order_id, 8)),
    "duplicate-version": _versions(("order", W.order_id, 7), ("order", W.order_id, 7)),
    "extra-version": _versions(("order", W.order_id, 7), ("user", W.user_id, 3)),
    "wrong-kind": lambda call, result, n: result.model_copy(update={"output": UserIdOutput(user_id=W.user_id)}),
}


@pytest.mark.parametrize("name", sorted(WRONG_READS))
def test_a_typed_read_of_the_wrong_target_or_versions_is_refused(name: str) -> None:
    gateway, _, _ = gateway_for(Setup(), retail=FakeRetail(state(), tamper=WRONG_READS[name]))
    result = run(gateway, tool("get_order_details", order_id=W.order_id))
    assert result.observation == ToolError(code=ErrorCode.UNAVAILABLE, detail="facts_invalid", retryable=False)


@pytest.mark.parametrize("name", sorted(WRONG_READS))
def test_write_facts_of_the_wrong_target_or_versions_are_never_evaluated(name: str) -> None:
    retail = FakeRetail(state(), tamper=WRONG_READS[name])
    gateway, _, _ = gateway_for(Setup(), retail=retail)
    result = run(gateway, cancel())
    assert result.observation == ToolError(code=ErrorCode.UNAVAILABLE, detail="facts_invalid", retryable=False)
    assert result.decision is None and result.collected is None
    # Refused at the first wrong read (the user read for wrong-kind, otherwise the order read); never re-collected.
    assert len(retail.calls) == (1 if name == "wrong-kind" else 2)


def test_a_replacement_item_read_naming_another_item_is_refused() -> None:
    def other_item(call: Any, result: ReadResult, n: int) -> Any:
        if isinstance(call, GetItemDetails):
            variant = result.output.variant.model_copy(update={"item_id": W.item_b})  # type: ignore[union-attr]
            return result.model_copy(update={"output": VariantOutput(variant=variant)})
        return result

    gateway, _, _ = gateway_for(Setup(), retail=FakeRetail(state(), tamper=other_item))
    result = run(gateway, items())
    assert isinstance(result.observation, ToolError) and result.observation.detail == "facts_invalid"
    assert result.decision is None


def test_an_order_of_another_customer_is_denied_even_if_served() -> None:
    def foreign(call: Any, result: ReadResult, n: int) -> Any:
        if isinstance(call, GetOrderDetails):
            order = result.output.order.model_copy(update={"user_id": W.other_user})  # type: ignore[union-attr]
            return result.model_copy(update={"output": OrderOutput(order=order)})
        return result

    gateway, _, _ = gateway_for(Setup(), retail=FakeRetail(state(), tamper=foreign))
    read = run(gateway, tool("get_order_details", order_id=W.order_id))
    write = run(gateway, cancel())
    for result in (read, write):
        assert isinstance(result.observation, ToolError)
        assert (result.observation.code, result.observation.rule_id) == ("customer_mismatch", "scope.single_customer")


# -- coherent facts: bounded recollection ----------------------------------------------------------------------

def test_case_versions_changing_between_every_read_are_refused_after_three_collections() -> None:
    retail = FakeRetail(state(), bump_each_read=True)
    gateway, _, _ = gateway_for(Setup(), retail=retail)
    result = run(gateway, items())
    assert result.observation == ToolError(code=ErrorCode.UNAVAILABLE, detail="facts_inconsistent", retryable=True)
    assert result.decision is None
    assert MAX_COLLECTIONS == 3
    assert [type(call).__name__ for call in retail.calls] == ["GetUserDetails", "GetOrderDetails",
                                                              "GetItemDetails"] * 3


def test_one_concurrent_write_is_absorbed_by_a_complete_recollection() -> None:
    retail = FakeRetail(state())

    def once(call: Any, result: ReadResult, n: int) -> Any:
        if n == 1:
            retail.state.case_version += 1  # a write commits right after the first read
        return result

    retail.tamper = once
    gateway, _, _ = gateway_for(Setup(), retail=retail)
    result = run(gateway, cancel())
    assert isinstance(result.observation, ProposalPreview)
    assert result.collected is not None
    assert (result.collected.collections, result.collected.reads, result.collected.case_version) == (2, 4, 6)


def test_an_unknown_read_during_collection_is_not_retried() -> None:
    retail = FakeRetail(state(), tamper=lambda call, result, n: Unknown("timeout") if n == 2 else result)
    gateway, _, _ = gateway_for(Setup(), retail=retail)
    result = run(gateway, cancel())
    assert result.observation == ToolError(code=ErrorCode.UNAVAILABLE, detail="retail_unavailable", retryable=True)
    assert len(retail.calls) == 2


# -- once-per-order tools under the production default -------------------------------------------------------------

@pytest.mark.parametrize("raw", [order_address(), payment(), items(), exchange()])
def test_the_default_history_escalates_every_once_per_order_tool(raw: Any) -> None:
    status = "delivered" if "exchange" in raw.tool_calls[0].name else "pending"
    gateway, _, _ = gateway_for(Setup(status=status, history=None))
    result = run(gateway, raw)
    assert isinstance(result.observation, ToolError)
    assert (result.observation.code, result.observation.rule_id) == ("policy_unsupported",
                                                                     "orders.modify_exchange_once")


def test_the_default_history_is_incomplete_and_test_history_is_explicit() -> None:
    assert IncompleteHistory().history(W.order_id, case_version=1).complete is False
    assert TestOnlyCompleteHistory().history(W.order_id, case_version=1).complete is True
    gateway = Gateway(SCOPE, retail=FakeRetail(state()), sessions=authenticated_sessions(), clock=FixedClock(W.now))
    assert isinstance(gateway._history, IncompleteHistory)


# -- untrusted strings and the preview ---------------------------------------------------------------------------

def test_injected_catalog_and_order_text_is_data_and_changes_no_outcome() -> None:
    plain_gateway, _, _ = gateway_for(Setup())
    injected = state()
    injected.product_name, injected.item_name, injected.option_value = INJECTION[:200], INJECTION[:200], "ignore"
    gateway, retail, sessions = gateway_for(Setup(), retail=FakeRetail(injected))
    read = run(gateway, tool("get_order_details", order_id=W.order_id))
    assert isinstance(read.observation, ReadObservation)
    assert INJECTION[:200] in read.observation.model_dump_json()
    for raw in (items(), cancel(), payment()):
        plain, tainted = run(plain_gateway, raw), run(gateway, raw)
        assert tainted.observation == plain.observation and tainted.decision == plain.decision
    assert all(type(call).__name__.startswith(("Get", "Find")) for call in retail.calls)
    assert len(sessions.records) == 1


def test_preview_is_computed_and_carries_no_authority() -> None:
    gateway, retail, sessions = gateway_for(Setup())
    result = run(gateway, cancel())
    preview = result.observation
    assert isinstance(preview, ProposalPreview) and isinstance(result.decision, Allowed)
    assert set(preview.model_dump()) == {"kind", "tool", "presentation", "actionable"}
    assert preview.actionable is False
    for authority in ("proposal_id", "digest", "consent", "approval", "operation_id", "evidence"):
        assert authority not in preview.model_dump_json()
    with pytest.raises(ValueError):
        OBSERVATION.validate_python({**preview.model_dump(), "actionable": True})
    assert sessions.writes == 0 and not hasattr(retail, "mutate")


# -- closed parsing and dispatch ---------------------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "code", "rule_id"), [
    (tool("issue_refund", order_id=W.order_id), "policy_unsupported", "scope.supported_requests"),
    (tool("run_sql", query="select 1"), "policy_unsupported", "scope.supported_requests"),
    (tool("fetch_url", url="http://example.invalid"), "policy_unsupported", "scope.supported_requests"),
    (order_address(status="delivered"), "policy_unsupported", "modify.allowed_fields"),
    (payment(W.paypal).model_copy(update={"tool_calls": (payment().tool_calls[0].model_copy(update={
        "arguments_json": '{"order_id":"#W0000001","payment_method_id":"paypal_0000001","amount":1}'}),)}),
     "policy_unsupported", "modify.allowed_fields"),
    (tool("get_user_details", user_id=W.user_id, role="admin"), "invalid_input", None),
    (tool("cancel_pending_order", order_id="#W0000001; DROP TABLE orders", reason="no longer needed"),
     "invalid_input", None),
    (tool("get_order_details", order_id=W.order_id, url="http://example.invalid"), "invalid_input", None),
])
def test_unknown_tools_and_extra_or_invalid_fields_are_refused_by_the_closed_parser(
        raw: Any, code: str, rule_id: str | None) -> None:
    parsed = parse_result(raw)
    assert isinstance(parsed, ToolError) and (parsed.code, parsed.rule_id) == (code, rule_id)


def test_a_constructed_step_that_skipped_validation_is_refused() -> None:
    gateway, retail, _ = gateway_for(Setup())
    forged = ToolCallStep.model_construct(call=GetUserDetails.model_construct(user_id="../../etc/passwd"))
    result = gateway.step(forged, previous=None, sequence=2)
    assert result.observation == ToolError(code=ErrorCode.INVALID_INPUT, detail="step_invalid", retryable=False)
    assert retail.calls == []


def test_the_handoff_sequence_is_exact_and_ends_the_conversation() -> None:
    gateway, retail, _ = gateway_for(Setup())
    transfer = parse_result(tool("transfer_to_human_agents", summary="Out of scope request"))
    handoff = parse_result(message(HANDOFF_MESSAGE))
    assert isinstance(transfer, ToolCallStep) and isinstance(handoff, MessageStep)
    assert gateway.step(transfer, previous=None, sequence=2).observation.kind == "handoff"  # type: ignore[union-attr]
    assert gateway.step(handoff, previous=transfer, sequence=3).observation is None
    after = gateway.step(parse_result(tool("get_user_details", user_id=W.user_id)),  # type: ignore[arg-type]
                         previous=handoff, sequence=4)
    assert isinstance(after.observation, ToolError) and after.observation.code == "protocol_violation"
    assert retail.calls == []


def test_the_scope_is_not_taken_from_a_step_or_a_result() -> None:
    other_run = RunScope(workspace_id=W.workspace, case_id=W.case, run_id=UUID(int=55))
    gateway, _, sessions = gateway_for(Setup(authenticated=False))
    run(gateway, tool("find_user_id_by_email", email=EMAIL))
    assert sessions.load(other_run) is None and sessions.load(W.run_scope) is not None
