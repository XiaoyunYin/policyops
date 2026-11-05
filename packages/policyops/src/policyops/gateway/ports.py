"""The gateway's server-derived scope and its narrow typed ports (T17).

`GatewayScope` is built by the server only, from the persisted run and case and the case's server-side customer
binding; it is never read from a model step, a tool argument, a header or a read result. Every port the gateway
uses is bound to that scope before the first contact.

Ports and their implementations:

| Port | Supplies | Production implementation |
|---|---|---|
| `RetailPort` | typed retail reads | `policyops.adapters.retail_client.RetailClient`, one per (tenant, case) |
| `SessionStore` | the run's durable lookup authentication | `PgSessionStore` (`app.customer_authentications`) |
| `HistoryPort` | the order's recorded operation history | `IncompleteHistory` until T19's receipt ledger |
| `MembershipPort` | the principal's *current* workspace roles | `PgMembership` (memberships) |
| `DecisionStore` | persisted proposal, consent and approval records | none before T18 (the precheck refuses) |
| `EvidencePort` | whether a proposal's evidence reference is current | none yet: a proposal with evidence is refused |
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from sqlalchemy import Engine

from policyops.adapters.retail_client import Unknown
from policyops.domain.roles import Role
from policyops.persistence import customer_authentications
from policyops.persistence.database import workspace_transaction
from policyops.persistence.repositories import get_case, scoped_roles
from policyops.persistence.runs import get_run
from policyops_contracts.consent import ApprovalDecision, CustomerConsent
from policyops_contracts.proposal import ActionProposal, EvidenceRef
from policyops_contracts.retail import OrderOperationHistory
from policyops_contracts.retail_service import ReadCall, ReadResult
from policyops_contracts.scalars import RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication


class ScopeMismatch(ValueError):
    """A port, client or record is bound to a different tenant, case, run, customer or fixture than the scope."""


@dataclass(frozen=True)
class GatewayScope:
    run: RunScope
    binding: CaseCustomerBinding
    fixture_sha256: str

    def __post_init__(self) -> None:
        if (self.run.workspace_id, self.run.case_id) != (self.binding.scope.workspace_id,
                                                         self.binding.scope.case_id):
            raise ScopeMismatch("the run and the customer binding belong to different cases")

    @property
    def customer_user_id(self) -> str:
        return self.binding.user_id


def load_scope(engine: Engine, *, workspace_id: UUID, run_id: UUID, binding: CaseCustomerBinding,
               fixture_sha256: str) -> GatewayScope:
    """The scope of a persisted run, checked against the persisted case: the binding supplied by the trusted seed
    path must name that run's case and the customer the case row is bound to."""
    with workspace_transaction(engine, workspace_id) as connection:
        run = get_run(connection, run_id)
        case = None if run is None else get_case(connection, run.case_id)
    if run is None or case is None or run.workspace_id != workspace_id or case.workspace_id != workspace_id:
        raise ScopeMismatch("no such run in this workspace")
    if (binding.scope.workspace_id, binding.scope.case_id) != (workspace_id, case.id):
        raise ScopeMismatch("the binding is for another case")
    if case.customer_user_id is None or case.customer_user_id != binding.user_id:
        raise ScopeMismatch("the case is not bound to this customer")
    return GatewayScope(run=RunScope(workspace_id=workspace_id, case_id=case.id, run_id=run.id), binding=binding,
                        fixture_sha256=fixture_sha256)


class RetailPort(Protocol):
    """The typed read side of the retail client. `read` returns a result or `Unknown`, and raises `Refused` for a
    definite refusal (see `policyops.adapters.retail_client`)."""

    tenant_id: UUID
    case_id: UUID
    customer_id: str
    fixture_sha256: str

    def read(self, call: ReadCall) -> ReadResult | Unknown: ...


def check_retail_binding(scope: GatewayScope, retail: RetailPort) -> None:
    """Refuse a client bound to anything but this scope. Called before the first request."""
    if (retail.tenant_id, retail.case_id, retail.customer_id, retail.fixture_sha256) != (
            scope.run.workspace_id, scope.run.case_id, scope.customer_user_id, scope.fixture_sha256):
        raise ScopeMismatch("the retail client is bound to another tenant, case, customer or fixture")


class SessionStore(Protocol):
    def load(self, run: RunScope) -> CustomerAuthentication | None: ...

    def record(self, authentication: CustomerAuthentication) -> CustomerAuthentication: ...


class PgSessionStore:
    """Durable lookup authentication in `app.customer_authentications`, one short workspace transaction per call
    (never held across a retail request). `record` raises `AuthenticationConflict` for a different identity."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def load(self, run: RunScope) -> CustomerAuthentication | None:
        with workspace_transaction(self._engine, run.workspace_id) as connection:
            return customer_authentications.load(connection, run)

    def record(self, authentication: CustomerAuthentication) -> CustomerAuthentication:
        with workspace_transaction(self._engine, authentication.scope.workspace_id) as connection:
            return customer_authentications.record(connection, authentication)


class HistoryPort(Protocol):
    def history(self, order_id: str, *, case_version: int) -> OrderOperationHistory: ...


class IncompleteHistory:
    """No authoritative operation ledger exists before T19, so every once-per-order tool escalates
    (`orders.modify_exchange_once`). `case_version` is accepted so the T19 ledger can bind its answer to it."""

    def history(self, order_id: str, *, case_version: int) -> OrderOperationHistory:
        del case_version
        return OrderOperationHistory(order_id=order_id, complete=False, successful_tools=())


class MembershipPort(Protocol):
    def roles(self, workspace_id: UUID, principal_id: UUID) -> frozenset[Role]: ...


class PgMembership:
    """The principal's current, unrevoked roles in the workspace, read when asked (revocation takes effect at once)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def roles(self, workspace_id: UUID, principal_id: UUID) -> frozenset[Role]:
        with workspace_transaction(self._engine, workspace_id) as connection:
            return frozenset(Role(role) for role in scoped_roles(connection, principal_id))


class DecisionStore(Protocol):
    """Persisted authority records of one run, by identity. Implemented by T18; none exists before it."""

    def proposal(self, run: RunScope, proposal_id: UUID, proposal_version: int) -> ActionProposal | None: ...

    def consent(self, run: RunScope, consent_id: UUID) -> CustomerConsent | None: ...

    def approval(self, run: RunScope, approval_id: UUID) -> ApprovalDecision | None: ...


class EvidencePort(Protocol):
    def is_current(self, workspace_id: UUID, reference: EvidenceRef) -> bool: ...
