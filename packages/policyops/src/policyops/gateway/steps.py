"""The policy and tool gateway (T17): the only path from a run's agent step to the retail service.

**Construction.** `Gateway` is constructed for one server-derived `GatewayScope`. It checks that the retail client
is bound to exactly that tenant, case, customer and fixture before any contact. Identity in a step (a `user_id` or
`order_id` argument) is only compared with the scope, never adopted.

**Dispatch.** Dispatch is a closed match on the validated typed call. Nothing in a step, a tool argument or a read
result can select a handler, a URL, SQL, a shell command, a scope or an authority record.

- **Lookup:** authorize, read, then `apply_lookup`. Only an actual successful lookup of the bound customer in this
  run is recorded durably (`SessionStore`, first write wins). A different identity is refused, never adopted.
- **Read:** authorize, read, then check that the result is the requested resource with exactly its own version.
  The typed detail is returned as untrusted data.
- **Write:** authorize, collect coherent facts (`facts.collect`), then `evaluate_write`. An allowed write is
  returned only as a computed, non-actionable `ProposalPreview`: nothing is persisted, dispatched or assigned an
  operation ID.
- **Transfer:** the handoff observation. The next step must be the exact handoff message
  (`protocol.step_violation`).
- **Message:** the protocol check only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, get_args

from pydantic import TypeAdapter, ValidationError

from policyops.adapters.retail_client import Refused, Unknown
from policyops.domain.protocol import step_violation
from policyops.domain.retail_rules import Allowed, Denied, Escalated, evaluate_write
from policyops.domain.session import (
    Authenticated,
    CustomerMismatch,
    CustomerSession,
    Deny,
    LookupFailed,
    apply_lookup,
    authorize_call,
    order_belongs,
)
from policyops.gateway import observations
from policyops.gateway.facts import Collected, FactsRefused, collect
from policyops.gateway.ports import (
    GatewayScope,
    HistoryPort,
    IncompleteHistory,
    RetailPort,
    SessionStore,
    check_retail_binding,
)
from policyops.persistence.customer_authentications import AuthenticationConflict
from policyops.providers.canonical import CanonicalError, strict_loads
from policyops.providers.tools import StepRefused, to_agent_step
from policyops.telemetry import annotate, observed
from policyops_contracts.agent import AgentStep, MessageStep, ToolCallStep
from policyops_contracts.clock import Clock
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import (
    HandoffObservation,
    LookupObservation,
    ProposalPreview,
    ReadObservation,
    ToolError,
    ToolObservation,
)
from policyops_contracts.model import ModelResult
from policyops_contracts.presentation import render_effect
from policyops_contracts.retail import (
    TOOL_KINDS,
    Calculate,
    FindUserIdByEmail,
    FindUserIdByNameZip,
    GetItemDetails,
    GetOrderDetails,
    GetProductDetails,
    GetUserDetails,
    ListAllProductTypes,
    ResourceVersion,
    ToolCall,
    ToolKind,
    ToolName,
    TransferToHumanAgents,
)
from policyops_contracts.retail_service import (
    CalculationOutput,
    OrderOutput,
    ProductOutput,
    ProductTypesOutput,
    ReadResult,
    UserIdOutput,
    UserOutput,
    VariantOutput,
)


_STEP: TypeAdapter[ToolCallStep | MessageStep] = TypeAdapter(AgentStep)
_DTOS: dict[str, Any] = {cls.model_fields["tool"].default: cls for cls in get_args(get_args(ToolCall)[0])}
ORDER_MODIFICATIONS = frozenset({ToolName.MODIFY_PENDING_ORDER_ADDRESS, ToolName.MODIFY_PENDING_ORDER_PAYMENT,
                                 ToolName.MODIFY_PENDING_ORDER_ITEMS})
PROTOCOL_REFUSALS = frozenset({"several_tool_calls", "text_with_tool_call"})
RETAIL_ABSENT = frozenset({"not_found", "upstream_rejected"})
INVALID_RESULT = observations.error(ErrorCode.UNAVAILABLE, "facts_invalid")


@dataclass(frozen=True)
class StepResult:
    """What one step produced. `observation` is what the model sees (`None`: the message step may be delivered).
    `decision`, `rule_ids` and `collected` are server-side audit detail and are never shown to the model."""

    observation: ToolObservation | None
    decision: Allowed | Denied | Escalated | None = None
    rule_ids: tuple[str, ...] = ()
    collected: Collected | None = None


def parse_result(result: ModelResult) -> ToolCallStep | MessageStep | ToolError:
    """One provider result to one typed step, or a fixed refusal (the T11 bridge, with the policy mapping).

    An unknown tool is out of the supported scope, and an extra field on an order modification is a change the
    policy does not allow; both are refused and recommend a handoff. Every other refusal is fixed invalid input.
    """
    try:
        return to_agent_step(result)
    except StepRefused as refused:
        code = refused.code
    if code in PROTOCOL_REFUSALS:
        return observations.error(ErrorCode.PROTOCOL_VIOLATION, code, rule_id="protocol.one_action_per_turn")
    if code.startswith("outcome_"):
        return observations.error(ErrorCode.UNAVAILABLE, "model_step_incomplete", retryable=True)
    if code == "arguments_invalid" and len(result.tool_calls) == 1:
        (call,) = result.tool_calls
        dto = _DTOS.get(call.name)
        if dto is None:
            return observations.error(ErrorCode.POLICY_UNSUPPORTED, "unsupported_tool",
                                      rule_id="scope.supported_requests")
        if call.name in ORDER_MODIFICATIONS:
            try:
                arguments = strict_loads(call.arguments_json)
            except CanonicalError:  # pragma: no cover - to_agent_step already parsed it
                arguments = None
            if isinstance(arguments, dict) and set(arguments) - set(dto.model_fields):
                return observations.error(ErrorCode.POLICY_UNSUPPORTED, "unsupported_field",
                                          rule_id="modify.allowed_fields")
    return observations.error(ErrorCode.INVALID_INPUT, code)


def _versions(kind: str, resource_id: str, version: int) -> tuple[ResourceVersion, ...]:
    return (ResourceVersion(kind=kind, resource_id=resource_id, version=version),)  # type: ignore[arg-type]


class Gateway:
    def __init__(self, scope: GatewayScope, *, retail: RetailPort, sessions: SessionStore, clock: Clock,
                 history: HistoryPort | None = None) -> None:
        check_retail_binding(scope, retail)  # before any request
        self.scope = scope
        self._retail, self._sessions, self._clock = retail, sessions, clock
        self._history = history if history is not None else IncompleteHistory()

    def session(self) -> CustomerSession:
        """The run's session from the durable authentication (`ValueError` if a stored record does not match)."""
        return CustomerSession(binding=self.scope.binding, run=self.scope.run,
                               authentication=self._sessions.load(self.scope.run))

    @observed("gateway.step")
    def step(self, step: AgentStep, *, previous: AgentStep | None, sequence: int) -> StepResult:
        annotate(run_id=self.scope.run.run_id)
        result = self._step(step, previous=previous, sequence=sequence)
        annotate(outcome="refused" if isinstance(result.observation, ToolError) else "completed")
        return result

    def _step(self, step: AgentStep, *, previous: AgentStep | None, sequence: int) -> StepResult:
        try:  # re-validated: a constructed object that bypassed validation is not trusted
            step = _STEP.validate_json(step.model_dump_json())
            if previous is not None:
                previous = _STEP.validate_json(previous.model_dump_json())
        except (ValidationError, AttributeError, TypeError):
            return StepResult(observations.error(ErrorCode.INVALID_INPUT, "step_invalid"))
        violation = step_violation(previous, step)
        if violation is not None:
            return StepResult(observations.error(ErrorCode.PROTOCOL_VIOLATION, "handoff_sequence",
                                                 rule_id="escalation.transfer"))
        if isinstance(step, MessageStep):
            return StepResult(None)
        call = step.call
        annotate(tool=call.tool, access="write" if TOOL_KINDS[ToolName(call.tool)] == ToolKind.WRITE else "read")
        try:
            session = self.session()
        except ValueError:
            return StepResult(observations.error(ErrorCode.CUSTOMER_MISMATCH, "stored_authentication_mismatch",
                                                 rule_id="scope.single_customer"))
        permit = authorize_call(session, call)
        if isinstance(permit, Deny):
            return StepResult(observations.denied(permit))
        if isinstance(call, TransferToHumanAgents):
            return StepResult(HandoffObservation())
        if isinstance(call, FindUserIdByEmail | FindUserIdByNameZip):
            return StepResult(self._lookup(session, call, sequence))
        if isinstance(call, GetUserDetails | GetOrderDetails | GetProductDetails | GetItemDetails
                      | ListAllProductTypes | Calculate):
            return StepResult(self._read(session, call))
        return self._write(session, call)

    # -- lookups ---------------------------------------------------------------------------------------------

    def _lookup(self, session: CustomerSession, call: FindUserIdByEmail | FindUserIdByNameZip,
                sequence: int) -> ToolObservation:
        try:
            result = self._retail.read(call)
        except Refused as refused:
            if refused.status == 404 or refused.code in RETAIL_ABSENT:  # nobody, or someone outside this case
                return LookupObservation(tool=call.tool, outcome="not_found")
            return observations.error(ErrorCode.UNAVAILABLE, "retail_refused")
        if isinstance(result, Unknown):
            return observations.error(ErrorCode.UNAVAILABLE, "retail_unavailable", retryable=True)
        if not isinstance(result, ReadResult) or not isinstance(result.output, UserIdOutput) or \
                result.resource_versions:
            return INVALID_RESULT
        outcome = apply_lookup(session, call, result.output.user_id, step_sequence=sequence, now=self._clock.now())
        if isinstance(outcome, LookupFailed):
            return LookupObservation(tool=call.tool, outcome="not_found")
        if isinstance(outcome, CustomerMismatch):
            return observations.error(ErrorCode.CUSTOMER_MISMATCH, "lookup_identity_mismatch",
                                      rule_id=outcome.rule_id)
        if not isinstance(outcome, Authenticated) or outcome.session.authentication is None:  # pragma: no cover
            raise TypeError("unexpected lookup outcome")
        if session.authentication is None:
            try:
                self._sessions.record(outcome.session.authentication)
            except AuthenticationConflict:
                return observations.error(ErrorCode.CUSTOMER_MISMATCH, "authentication_conflict",
                                          rule_id="scope.single_customer")
        return LookupObservation(tool=call.tool, outcome="authenticated")

    # -- reads -----------------------------------------------------------------------------------------------

    def _read(self, session: CustomerSession, call: GetUserDetails | GetOrderDetails | GetProductDetails
              | GetItemDetails | ListAllProductTypes | Calculate) -> ToolObservation:
        try:
            result = self._retail.read(call)
        except Refused as refused:
            if refused.status == 404 or refused.code in RETAIL_ABSENT:
                return observations.error(ErrorCode.NOT_FOUND, "not_found")
            return observations.error(ErrorCode.UNAVAILABLE, "retail_refused")
        if isinstance(result, Unknown):
            return observations.error(ErrorCode.UNAVAILABLE, "retail_unavailable", retryable=True)
        if not isinstance(result, ReadResult) or not self._is_requested(call, result):
            return INVALID_RESULT
        if isinstance(result.output, OrderOutput):
            belongs = order_belongs(session, result.output.order.to_snapshot())
            if isinstance(belongs, Deny):
                return observations.denied(belongs)
        return ReadObservation(tool=call.tool, output=result.output, case_version=result.case_version)

    @staticmethod
    def _is_requested(call: Any, result: ReadResult) -> bool:
        """The result is the requested resource and lists exactly its own version (nothing else, nothing missing)."""
        output, listed = result.output, result.resource_versions
        if isinstance(call, GetUserDetails):
            return isinstance(output, UserOutput) and output.user.user_id == call.user_id and \
                listed == _versions("user", call.user_id, output.user.version)
        if isinstance(call, GetOrderDetails):
            return isinstance(output, OrderOutput) and output.order.order_id == call.order_id and \
                listed == _versions("order", call.order_id, output.order.version)
        if isinstance(call, GetProductDetails):
            if not isinstance(output, ProductOutput) or output.product_id != call.product_id or len(listed) != 1:
                return False
            version = listed[0].version
            return listed == _versions("product", call.product_id, version) and all(
                (variant.product_id, variant.product_version) == (call.product_id, version)
                for variant in output.variants)
        if isinstance(call, GetItemDetails):
            return isinstance(output, VariantOutput) and output.variant.item_id == call.item_id and \
                listed == _versions("product", output.variant.product_id, output.variant.product_version)
        if isinstance(call, ListAllProductTypes):
            return isinstance(output, ProductTypesOutput) and not listed
        return isinstance(call, Calculate) and isinstance(output, CalculationOutput) and not listed

    # -- writes ----------------------------------------------------------------------------------------------

    def _write(self, session: CustomerSession, call: Any) -> StepResult:
        collected = collect(self._retail, self.scope, call, self._history)
        if isinstance(collected, FactsRefused):
            return StepResult(observations.facts_refused(collected))
        decision = evaluate_write(call, session, collected.facts)
        if isinstance(decision, Denied):
            return StepResult(observations.denied(decision), decision=decision, collected=collected)
        if isinstance(decision, Escalated):
            return StepResult(observations.escalated(decision), decision=decision, collected=collected)
        preview = ProposalPreview(tool=call.tool, presentation=render_effect(decision.effect))
        return StepResult(preview, decision=decision, rule_ids=decision.rule_ids, collected=collected)
