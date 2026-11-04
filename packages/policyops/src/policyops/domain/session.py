"""Seed binding versus policy authentication, and pre-call authorization.

The case's server-side `CaseCustomerBinding` fixes which customer the run may
serve. The pinned policy additionally requires an identity lookup (email, or
name + ZIP) in the conversation, even when a user ID is offered. A lookup that
returns the bound customer authenticates the session; one that returns anyone
else is a mismatch to deny and audit. Nothing here can change the binding.
"""

from dataclasses import dataclass, replace
from datetime import datetime

from policyops_contracts.digest import canonical_bytes, sha256_hex
from policyops_contracts.errors import ErrorCode
from policyops_contracts.retail import (
    LOOKUP_TOOLS,
    Calculate,
    FindUserIdByEmail,
    FindUserIdByNameZip,
    GetUserDetails,
    ModifyUserAddress,
    OrderSnapshot,
    ToolCall,
    TransferToHumanAgents,
)
from policyops_contracts.scalars import RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication


@dataclass(frozen=True)
class CustomerSession:
    binding: CaseCustomerBinding
    run: RunScope
    authentication: CustomerAuthentication | None = None

    def __post_init__(self) -> None:
        if (self.run.workspace_id, self.run.case_id) != (self.binding.scope.workspace_id, self.binding.scope.case_id):
            raise ValueError("run and binding belong to different cases")
        if self.authentication is not None and (
                self.authentication.scope != self.run or self.authentication.user_id != self.binding.user_id):
            raise ValueError("authentication does not match this run's binding")

    @property
    def authenticated(self) -> bool:
        return self.authentication is not None


@dataclass(frozen=True)
class Permit:
    rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class Deny:
    code: ErrorCode
    rule_id: str
    detail: str


@dataclass(frozen=True)
class Authenticated:
    session: CustomerSession


@dataclass(frozen=True)
class LookupFailed:
    """The lookup found nobody (or was ambiguous upstream); the session is unchanged."""


@dataclass(frozen=True)
class CustomerMismatch:
    """The lookup found a different customer; deny further help for that identity and audit it."""

    rule_id: str = "scope.single_customer"


LookupOutcome = Authenticated | LookupFailed | CustomerMismatch


def apply_lookup(session: CustomerSession, call: FindUserIdByEmail | FindUserIdByNameZip,
                 returned_user_id: str | None, *, step_sequence: int, now: datetime) -> LookupOutcome:
    if call.tool not in LOOKUP_TOOLS:
        raise ValueError("not an identity lookup")
    if returned_user_id is None:
        return LookupFailed()
    if returned_user_id != session.binding.user_id:
        return CustomerMismatch()
    if session.authentication is not None:
        return Authenticated(session)
    authentication = CustomerAuthentication.model_validate({
        "scope": session.run.model_dump(), "user_id": returned_user_id, "lookup_tool": call.tool,
        "lookup_call_sha256": sha256_hex(canonical_bytes(call)), "step_sequence": step_sequence,
        "authenticated_at": now,
    })
    return Authenticated(replace(session, authentication=authentication))


def authorize_call(session: CustomerSession, call: ToolCall) -> Permit | Deny:
    """Static checks before any tool call; resource ownership needs snapshots (see order_belongs)."""
    if isinstance(call, FindUserIdByEmail | FindUserIdByNameZip | TransferToHumanAgents | Calculate):
        return Permit(())
    if not session.authenticated:
        return Deny(ErrorCode.CUSTOMER_NOT_AUTHENTICATED, "auth.lookup_required",
                    "authenticate the customer by email or name and ZIP first")
    if isinstance(call, GetUserDetails | ModifyUserAddress) and call.user_id != session.binding.user_id:
        return Deny(ErrorCode.CUSTOMER_MISMATCH, "scope.single_customer", "only the authenticated customer is served")
    return Permit(("auth.lookup_required", "auth.reads_after_authentication"))


def order_belongs(session: CustomerSession, order: OrderSnapshot) -> Permit | Deny:
    if not session.authenticated:
        return Deny(ErrorCode.CUSTOMER_NOT_AUTHENTICATED, "auth.lookup_required", "customer not authenticated")
    if order.user_id != session.binding.user_id:
        return Deny(ErrorCode.CUSTOMER_MISMATCH, "scope.single_customer", "the order belongs to another customer")
    return Permit(("scope.single_customer",))
