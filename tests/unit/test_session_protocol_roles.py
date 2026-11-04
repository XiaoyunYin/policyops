"""Seed binding versus lookup authentication, one-action-per-turn protocol, roles, money and scalars."""

from datetime import UTC, datetime, timedelta, timezone
import json
import math
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter, ValidationError
import pytest

from policyops.domain.examples import World
from policyops.domain.protocol import sequence_violation
from policyops.domain.roles import PERMISSIONS, Action, Role, is_allowed
from policyops.domain.session import (
    Authenticated,
    CustomerMismatch,
    Deny,
    LookupFailed,
    Permit,
    apply_lookup,
    authorize_call,
    order_belongs,
)
from policyops_contracts.agent import AgentStep, MessageStep, ToolCallStep
from policyops_contracts.errors import ErrorCode
from policyops_contracts.money import Money, MoneyError, money_from_upstream
from policyops_contracts.retail import (
    HANDOFF_MESSAGE,
    Calculate,
    FindUserIdByNameZip,
    GetOrderDetails,
    GetUserDetails,
    ListAllProductTypes,
    ToolCall,
    TransferToHumanAgents,
)
from policyops_contracts.scalars import UtcDatetime


def test_lookup_authenticates_only_the_bound_customer_and_never_rebinds(world: World) -> None:
    session = world.session(authenticated=False)
    lookup = FindUserIdByNameZip(first_name="Example", last_name="User", zip="00001")
    assert isinstance(apply_lookup(session, lookup, None, step_sequence=1, now=world.now), LookupFailed)
    mismatch = apply_lookup(session, lookup, world.other_user, step_sequence=1, now=world.now)
    assert isinstance(mismatch, CustomerMismatch) and not session.authenticated
    outcome = apply_lookup(session, lookup, world.user_id, step_sequence=2, now=world.now)
    assert isinstance(outcome, Authenticated) and outcome.session.binding == session.binding
    assert outcome.session.authentication is not None
    assert outcome.session.authentication.lookup_tool == "find_user_id_by_name_zip"
    again = apply_lookup(outcome.session, lookup, world.other_user, step_sequence=3, now=world.now)
    assert isinstance(again, CustomerMismatch)


def test_reads_wait_for_authentication_and_stay_within_the_customer(world: World) -> None:
    before = world.session(authenticated=False)
    always: tuple[ToolCall, ...] = (TransferToHumanAgents(summary="Customer needs a human."),
                                    Calculate(expression="(19.99 + 25) * 2"))
    for call in always:
        assert isinstance(authorize_call(before, call), Permit)
    gated: tuple[ToolCall, ...] = (GetOrderDetails(order_id=world.order_id), ListAllProductTypes(),
                                   GetUserDetails(user_id=world.user_id))
    for call in gated:
        denied = authorize_call(before, call)
        assert isinstance(denied, Deny) and denied.code is ErrorCode.CUSTOMER_NOT_AUTHENTICATED
    after = world.session()
    assert isinstance(authorize_call(after, GetUserDetails(user_id=world.user_id)), Permit)
    other = authorize_call(after, GetUserDetails(user_id=world.other_user))
    assert isinstance(other, Deny) and other.rule_id == "scope.single_customer"
    assert isinstance(order_belongs(after, world.order(user_id=world.other_user)), Deny)
    assert isinstance(order_belongs(after, world.order()), Permit)


def steps(*items: Any) -> list[Any]:
    adapter: TypeAdapter[AgentStep] = TypeAdapter(AgentStep)
    return [adapter.validate_json(json.dumps(item)) for item in items]


TRANSFER = {"kind": "tool_call", "call": {"tool": "transfer_to_human_agents", "summary": "Out of scope request."}}
HANDOFF = {"kind": "message", "text": HANDOFF_MESSAGE}


def test_transfer_must_be_followed_by_the_exact_handoff_message() -> None:
    assert sequence_violation(steps({"kind": "message", "text": "Hello"}, TRANSFER, HANDOFF)) is None
    assert sequence_violation(steps(TRANSFER, {"kind": "message", "text": "Transferring you now."})) == (
        1, "a transfer must be followed by the exact handoff message")
    assert sequence_violation(steps(HANDOFF))[0] == 0  # type: ignore[index]
    assert sequence_violation(steps(TRANSFER, HANDOFF, {"kind": "message", "text": "Anything else?"}))[0] == 2  # type: ignore[index]


def test_a_step_is_exactly_one_tool_call_or_one_message() -> None:
    adapter: TypeAdapter[AgentStep] = TypeAdapter(AgentStep)
    both = {"kind": "message", "text": "Checking.", "call": {"tool": "list_all_product_types"}}
    for bad in (both, {"kind": "tool_call"}, {"kind": "tool_calls", "calls": []}, {"kind": "message", "text": ""}):
        with pytest.raises(ValidationError):
            adapter.validate_json(json.dumps(bad))
    assert isinstance(steps({"kind": "tool_call", "call": {"tool": "list_all_product_types"}})[0], ToolCallStep)
    assert isinstance(steps({"kind": "message", "text": "Hi"})[0], MessageStep)


@pytest.mark.parametrize("expression", ["9**9**9", "2**64", "7//2", "1e999", "10000000000 * 2",
                                        "-(" * 13 + "1" + ")" * 13, "__import__('os')", "1 % 2", "1 +", ""])
def test_calculator_grammar_rejects_power_floor_division_and_oversized_input(expression: str) -> None:
    # Validation only: nothing is evaluated.
    with pytest.raises(ValidationError):
        Calculate(expression=expression)


def test_calculator_grammar_accepts_plain_arithmetic() -> None:
    assert Calculate(expression="(19.99 + 25.01) * 2 / 4 - -1").expression


def test_role_matrix() -> None:
    assert is_allowed(frozenset({Role.REVIEWER}), Action.DECIDE_PROPOSAL)
    assert not is_allowed(frozenset({Role.ADMIN}), Action.DECIDE_PROPOSAL)
    assert is_allowed(frozenset({Role.ADMIN}), Action.MANAGE_MEMBERSHIP)
    assert not is_allowed(frozenset({Role.REVIEWER, Role.ANALYST}), Action.MANAGE_MEMBERSHIP)
    assert PERMISSIONS[Role.AUDITOR] == frozenset({Action.VIEW_CASE, Action.READ_AUDIT, Action.READ_EVALUATIONS})
    assert not is_allowed(frozenset(), Action.VIEW_CASE)
    with pytest.raises(TypeError):
        PERMISSIONS[Role.ANALYST] = frozenset(Action)  # type: ignore[index]


@pytest.mark.parametrize(("value", "minor"), [(54.04, 5404), (100, 10000), (0.1, 10), (-12.5, -1250), (0, 0),
                                              (1234567.89, 123456789)])
def test_upstream_money_converts_exactly(value: float, minor: int) -> None:
    assert money_from_upstream(value) == Money(amount_minor=minor)


@pytest.mark.parametrize("value", [True, False, math.nan, math.inf, -math.inf, 0.1 + 0.2, 1.005, 19.999, "54.04",
                                   None, 10**13])
def test_upstream_money_rejects_non_exact_values(value: Any) -> None:
    with pytest.raises(MoneyError):
        money_from_upstream(value)


@pytest.mark.parametrize("payload", ['{"amount_minor": 1.5}', '{"amount_minor": "150"}', '{"amount_minor": true}',
                                     '{"amount_minor": 1, "currency": "EUR"}', '{"amount_minor": 1000000000001}'])
def test_money_wire_format_is_strict(payload: str) -> None:
    with pytest.raises(ValidationError):
        Money.model_validate_json(payload)


def test_money_display_and_arithmetic() -> None:
    assert Money(amount_minor=123450).display() == "$1,234.50"
    assert Money(amount_minor=-300).display() == "-$3.00"
    assert (Money(amount_minor=5) - Money(amount_minor=7)).amount_minor == -2


def test_timestamps_must_be_aware_utc() -> None:
    adapter: TypeAdapter[datetime] = TypeAdapter(UtcDatetime)
    assert adapter.validate_python(datetime(2026, 1, 1, tzinfo=UTC))
    for bad in (datetime(2026, 1, 1), datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=-5)))):
        with pytest.raises(ValidationError):
            adapter.validate_python(bad)
    assert adapter.validate_json('"2026-01-01T00:00:00Z"').tzinfo is not None
    with pytest.raises(ValidationError):
        adapter.validate_json('"2026-01-01T00:00:00"')


def test_unused_world_ids_are_fictional() -> None:
    world = World()
    assert world.order_id == "#W0000001" and UUID(int=1) == world.workspace
