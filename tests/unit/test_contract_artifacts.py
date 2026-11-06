"""Committed JSON Schemas and examples are reproducible; the policy rule table is well formed."""

from pathlib import Path

from pydantic import BaseModel, TypeAdapter

from policyops.domain.examples import build_examples
from policyops.domain.retail_rules import rules_for
from policyops_contracts.agent import AgentStep
from policyops_contracts.consent import ApprovalDecision, CaseMessage, CustomerConsent, ProposalPresentationRecord
from policyops_contracts.e01 import TrajectoryRecord
from policyops_contracts.errors import ErrorEnvelope
from policyops_contracts.events import EventEnvelope
from policyops_contracts.evidence import EvidenceManifest
from policyops_contracts.gateway import ToolObservation
from policyops_contracts.grounding import GroundedAnswer, ValidatedAnswer
from policyops_contracts.policy import RETAIL_POLICY, RETAIL_RULES, RULES_BY_ID
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import WRITE_TOOLS, ToolName
from policyops_contracts.retail_service import LookupResult, MutationRequest, OperationResult
from policyops_contracts.retrieval import RetrievalQuery, RetrievalResult
from policyops_contracts.schema_export import export
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication, DemoSeed


CONTRACTS = Path(__file__).resolve().parents[2] / "packages" / "policyops_contracts"
EXAMPLE_MODELS: dict[str, type[BaseModel]] = {
    "action-proposal.exchange": ActionProposal, "proposal-presentation": ProposalPresentationRecord,
    "case-message.operator-entered-yes": CaseMessage, "customer-consent": CustomerConsent,
    "approval-decision": ApprovalDecision, "run-event.proposal-presented": EventEnvelope,
    "error.consent-ambiguous": ErrorEnvelope, "evidence-manifest.failed-run": EvidenceManifest,
    "case-customer-binding": CaseCustomerBinding,
    "customer-authentication": CustomerAuthentication, "demo-seed": DemoSeed,
    "retail-service-mutation-request.modify-items": MutationRequest,
    "retail-service-operation-result.committed": OperationResult,
    "retail-service-lookup-result.unknown": LookupResult,
    "retrieval-query.hybrid": RetrievalQuery, "retrieval-result.hybrid": RetrievalResult,
    "retrieval-query.hybrid-rerank": RetrievalQuery, "grounded-answer.answer": GroundedAnswer,
    "validated-answer.grounded": ValidatedAnswer, "e01-trajectory.fictional": TrajectoryRecord,
}
HIDDEN_FIELD_NAMES = ("user_scenario", "instructions", "known_info", "unknown_info", "reason_for_call",
                      "evaluation_criteria", "nl_assertions", "reward_basis", "required_documents", "initial_state")


def committed(directory: str) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted((CONTRACTS / directory).glob("*.json"))}


def test_schemas_regenerate_byte_for_byte() -> None:
    assert committed("schemas") == export()


def test_examples_regenerate_and_validate_strictly() -> None:
    examples = committed("examples")
    assert examples == build_examples()
    for name, data in examples.items():
        stem = name.removesuffix(".json")
        if stem.startswith("agent-step."):
            TypeAdapter(AgentStep).validate_json(data)
        elif stem.startswith("tool-observation."):
            TypeAdapter(ToolObservation).validate_json(data)
        else:
            EXAMPLE_MODELS[stem].model_validate_json(data)
        text = data.decode("utf-8")
        assert not any(f'"{field}"' in text for field in HIDDEN_FIELD_NAMES), name
        assert b"\r" not in data


def test_rule_table_is_well_formed_and_covers_every_write() -> None:
    ids = [rule.rule_id for rule in RETAIL_RULES]
    assert len(ids) == len(set(ids)) == len(RULES_BY_ID)
    assert RETAIL_POLICY.sha256 == "2c9652afbce57d6e087768d37cda64d31c53d50b3e3225cfdb791bac66466467"
    for rule in RETAIL_RULES:
        assert 1 <= rule.line_start <= rule.line_end <= 137, rule.rule_id
        assert rule.enforcement != "not_codified" or not rule.tools or rule.rule_id == "grounding.no_fabrication"
    consent = RULES_BY_ID["consent.explicit_yes"]
    assert set(consent.tools) == set(WRITE_TOOLS)
    for tool in WRITE_TOOLS:
        covering = [RULES_BY_ID[rule_id] for rule_id in rules_for(tool)]
        assert any(rule.enforcement == "deterministic" for rule in covering), tool
        assert any(rule.enforcement == "presentation" for rule in covering), tool
    assert all(rule_id in RULES_BY_ID for tool in ToolName for rule_id in rules_for(tool))
    once = RULES_BY_ID["orders.modify_exchange_once"]
    assert once.ambiguity is not None and ToolName.CANCEL_PENDING_ORDER not in once.tools
