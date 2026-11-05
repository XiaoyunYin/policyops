"""Generate the committed JSON Schemas for the public wire contracts.

    python -m policyops_contracts.schema_export --out DIR      write DIR/<name>.schema.json
    python -m policyops_contracts.schema_export --check DIR    exit 1 if DIR differs from a fresh export

Output is canonical (sorted keys, two-space indent, LF, trailing newline) and
depends only on the model definitions, so regeneration is reproducible. The
schemas contain no example values from upstream data.
"""

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys

from pydantic import BaseModel, TypeAdapter

from policyops_contracts import CONTRACTS_SCHEMA_VERSION
from policyops_contracts.agent import AgentStep
from policyops_contracts.consent import (
    ApprovalDecision,
    CaseMessage,
    CustomerConsent,
    ProposalPresentationRecord,
    SimulatorConfirmationEvent,
)
from policyops_contracts.errors import ErrorEnvelope
from policyops_contracts.events import EventEnvelope
from policyops_contracts.evidence import EvidenceManifest
from policyops_contracts.money import Money
from policyops_contracts.policy import PolicyRule
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import OrderOperationHistory, OrderSnapshot, ToolCall, UserSnapshot, VariantSnapshot
from policyops_contracts.retail_service import (
    CaseInitialization,
    CaseState,
    FenceRequest,
    LookupResult,
    MutationRequest,
    OperationResult,
    ReadRequest,
    ReadResult,
    ServiceContext,
)
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication, DemoSeed


MODELS: dict[str, type[BaseModel]] = {
    "action-proposal": ActionProposal,
    "approval-decision": ApprovalDecision,
    "case-customer-binding": CaseCustomerBinding,
    "case-message": CaseMessage,
    "customer-authentication": CustomerAuthentication,
    "customer-consent": CustomerConsent,
    "demo-seed": DemoSeed,
    "error": ErrorEnvelope,
    "evidence-manifest": EvidenceManifest,
    "money": Money,
    "order-operation-history": OrderOperationHistory,
    "order-snapshot": OrderSnapshot,
    "policy-rule": PolicyRule,
    "proposal-presentation": ProposalPresentationRecord,
    "run-event": EventEnvelope,
    "simulator-confirmation": SimulatorConfirmationEvent,
    "user-snapshot": UserSnapshot,
    "variant-snapshot": VariantSnapshot,
    # The retail-simulator RPC (T16): internal service protocol, versioned with the shared contract.
    "retail-service-case-initialization": CaseInitialization,
    "retail-service-case-state": CaseState,
    "retail-service-context": ServiceContext,
    "retail-service-fence-request": FenceRequest,
    "retail-service-lookup-result": LookupResult,
    "retail-service-mutation-request": MutationRequest,
    "retail-service-operation-result": OperationResult,
    "retail-service-read-request": ReadRequest,
    "retail-service-read-result": ReadResult,
}
ADAPTERS: dict[str, TypeAdapter[object]] = {
    "agent-step": TypeAdapter(AgentStep),
    "tool-call": TypeAdapter(ToolCall),
}


def export() -> dict[str, bytes]:
    schemas: dict[str, object] = {name: model.model_json_schema() for name, model in MODELS.items()}
    schemas.update({name: adapter.json_schema() for name, adapter in ADAPTERS.items()})
    result = {}
    for name, schema in sorted(schemas.items()):
        document = {"$comment": f"policyops_contracts {CONTRACTS_SCHEMA_VERSION}; generated, do not edit",
                    **schema}  # type: ignore[dict-item]
        result[f"{name}.schema.json"] = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    generated = export()
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, data in generated.items():
            (args.out / name).write_bytes(data)
        return 0
    present = {path.name: path.read_bytes() for path in args.check.glob("*.schema.json")}
    if present != generated:
        changed = sorted(set(present) ^ set(generated) | {k for k in present if generated.get(k) != present[k]})
        print(f"schemas differ from a fresh export: {', '.join(changed)}", file=sys.stderr)
        return 1
    print(f"{len(generated)} schemas match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
