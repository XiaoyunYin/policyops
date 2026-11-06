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
from policyops_contracts.conversation import (
    AgentConfig,
    ConversationSnapshot,
    Entry,
    KnowledgeResult,
    PolicyContext,
    ToolCatalog,
    TurnOutcome,
)
from policyops_contracts.e01 import E01Manifest, E01Report, E01Selection, TrajectoryRecord
from policyops_contracts.errors import ErrorEnvelope
from policyops_contracts.events import EventEnvelope
from policyops_contracts.evidence import EvidenceManifest
from policyops_contracts.gateway import ToolObservation
from policyops_contracts.grounding import (
    CitationBundle,
    GroundedAnswer,
    GroundingRefused,
    ReconcileOutcome,
    RecordOutcome,
    ValidatedAnswer,
)
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
from policyops_contracts.retrieval import (
    RetrievalConfig,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    TraceCandidates,
    TraceScope,
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
    # Retrieval steps (T13): the step request, its result or refusal, and the typed trace records.
    "retrieval-config": RetrievalConfig,
    "retrieval-query": RetrievalQuery,
    "retrieval-refused": RetrievalRefused,
    "retrieval-result": RetrievalResult,
    "retrieval-trace-candidates": TraceCandidates,
    "retrieval-trace-scope": TraceScope,
    # Grounding (T14): the model-facing answer, the deterministic validation, the citation claims and their recording.
    "grounded-answer": GroundedAnswer,
    "validated-answer": ValidatedAnswer,
    "grounding-refused": GroundingRefused,
    "citation-bundle": CitationBundle,
    "citation-record": RecordOutcome,
    "citation-reconcile": ReconcileOutcome,
    # E01 retrieval selection (T15a offline machinery): proposed manifests, the selection decision, records, reports.
    "e01-manifest": E01Manifest,
    "e01-selection": E01Selection,
    "e01-trajectory": TrajectoryRecord,
    "e01-report": E01Report,
    # The minimal agent baseline (T20): configuration identity, its bound inputs, one turn and a state snapshot.
    "agent-config": AgentConfig,
    "agent-policy-context": PolicyContext,
    "agent-tool-catalog": ToolCatalog,
    "agent-knowledge-result": KnowledgeResult,
    "agent-turn-outcome": TurnOutcome,
    "agent-conversation-snapshot": ConversationSnapshot,
}
ADAPTERS: dict[str, TypeAdapter[object]] = {
    "agent-step": TypeAdapter(AgentStep),
    "tool-call": TypeAdapter(ToolCall),
    # What the agent sees after one gateway step (T17); a computed preview is distinct from a pending proposal.
    "tool-observation": TypeAdapter(ToolObservation),
    "agent-transcript-entry": TypeAdapter(Entry),
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
