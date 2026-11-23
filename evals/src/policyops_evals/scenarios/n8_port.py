"""N8 carriers at existing seams: a scope-preserving RetailPort wrapper and a second, staff-note case message.

C-tool: the wrapper is installed through `Profile._run(bind_spec=...)`, the precedent in `arms.py`. It rewrites
only `items[0].name` of the scenario's own order in a `get_order_details` result. `OrderDetail.to_snapshot` drops
item names, so gateway facts, snapshots, resource versions and decisions are those of the clean run.

C-msg: `CaseService.post_message` bumps the case version, while the locked `Profile._run` starts each run at case
version 1. The note is therefore seeded through the same repository append path as the runtime's own seed
(`create_case` then `append_message`), before `_run`, with source `staff_note` and the slot's scenario operator as
author. `_run` then finds the existing case and its seeded opener unchanged.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import json
from uuid import UUID, uuid5

from sqlalchemy import text

from policyops.adapters.retail_client import Unknown
from policyops.gateway.ports import GatewayScope, RetailPort
from policyops.persistence.database import workspace_transaction
from policyops.persistence.records import NewCase
import policyops.persistence.repositories as repo
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.runtime.investigation import InvestigationExecutor
from policyops.runtime.spec import RuntimeSpec
from policyops_contracts.clock import SystemClock
from policyops_contracts.retail import GetOrderDetails
from policyops_contracts.retail_service import OrderOutput, ReadCall, ReadResult
from policyops_contracts.retrieval import canonical_sha256
from policyops_contracts.scalars import CaseScope
from policyops_evals.scenarios import Refused
from policyops_evals.scenarios.n8_attacks import Stimulus
from policyops_evals.scenarios.runtime import Profile, Slot


CARRIER_VERSION = "policyops.n8-carrier/v1"


@dataclass
class CarrierPort:
    """Delegate every read; replace one order's first item label. Scope attributes are the inner port's."""

    inner: RetailPort
    order_id: str
    name: str
    tenant_id: UUID
    case_id: UUID
    customer_id: str
    fixture_sha256: str
    rewrites: int = 0

    @classmethod
    def wrap(cls, inner: RetailPort, order_id: str, name: str) -> CarrierPort:
        return cls(inner, order_id, name, inner.tenant_id, inner.case_id, inner.customer_id, inner.fixture_sha256)

    def read(self, call: ReadCall) -> ReadResult | Unknown:
        result = self.inner.read(call)
        if not (isinstance(call, GetOrderDetails) and call.order_id == self.order_id
                and isinstance(result, ReadResult) and isinstance(result.output, OrderOutput)
                and result.output.order.order_id == self.order_id):
            return result
        data = json.loads(result.model_dump_json())
        data["output"]["order"]["items"][0]["name"] = self.name
        self.rewrites += 1
        return ReadResult.model_validate_json(json.dumps(data))  # revalidates ShortText and every invariant


def config_digest(base: str, manifest_sha256: str, stimulus_sha256: str | None) -> str:
    return canonical_sha256({"v": CARRIER_VERSION, "base": base, "attack_manifest": manifest_sha256,
                             "stimulus": stimulus_sha256})


def binder(stimulus: Stimulus, manifest_sha256: str) -> Callable[[RuntimeSpec], RuntimeSpec]:
    """Install the carrier wrapper (a pass-through for clean and C-msg slots) and bind the manifest digest."""
    carrier = (stimulus.carrier_order, stimulus.text) if stimulus.channel == "C-tool" else None
    if carrier is not None and (carrier[0] is None or carrier[1] is None):
        raise Refused("N8 C-tool stimulus has no carrier")

    def bind(spec: RuntimeSpec) -> RuntimeSpec:
        executor = spec.executor
        if not isinstance(executor, InvestigationExecutor):
            raise Refused("N8 carriers require the investigation executor")
        inner = executor.retail

        def retail(scope: GatewayScope) -> RetailPort:
            port = inner(scope)
            if carrier is None or carrier[0] is None or carrier[1] is None:
                return port
            return CarrierPort.wrap(port, carrier[0], carrier[1])

        config = config_digest(spec.config_sha256, manifest_sha256, stimulus.sha256)
        return replace(spec, config_sha256=config, executor=replace(executor, retail=retail, config_sha256=config))

    return bind


def note_id(slot: Slot) -> UUID:
    return uuid5(slot.id, "n8-staff-note")


def seed_note(profile: Profile, slot: Slot, case_customer: str, opener: str, note: str) -> None:
    """Create the slot case with the seeded opener and the staff note, or verify an earlier identical seed."""
    author = profile._operator(slot, SystemClock()).session.principal_id
    scope = CaseScope(workspace_id=slot.workspace, case_id=slot.case)
    with workspace_transaction(profile.app, slot.workspace) as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": str(slot.case)})
        if repo.get_case(connection, slot.case) is None:
            now = DatabaseLeaseClock().now(connection)
            repo.create_case(connection, NewCase(id=slot.case, workspace_id=slot.workspace, scenario="retail",
                                                 customer_user_id=case_customer, created_by=None, created_at=now))
            repo.append_message(connection, message_id=slot.message, scope=scope, source="seeded", entered_by=None,
                                text_value=opener, created_at=now)
            repo.append_message(connection, message_id=note_id(slot), scope=scope, source="staff_note",
                                entered_by=author, text_value=note, created_at=now)
        case = repo.get_case(connection, slot.case)
        messages = repo.list_messages(connection, scope, limit=8)
    shape = [(m.message_id, m.source, m.entered_by, m.text) for m in messages]
    if (case is None or case.version != 1 or case.customer_user_id != case_customer
            or shape != [(slot.message, "seeded", None, opener), (note_id(slot), "staff_note", author, note)]):
        raise Refused("N8 staff-note case input changed")
