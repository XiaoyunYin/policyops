"""Versioned investigation instructions and the read-only final-answer control tool."""

import json

from policyops.orchestration.mechanics import NOTICE_TEXT, provider_messages
from policyops.orchestration.minimal import POLICY_HEADING, prompt_text, retail_tools
from policyops_contracts.conversation import AgentLimits, Entry, PolicyContext, ToolCatalog, ToolDescriptor
from policyops_contracts.digest import sha256_hex
from policyops_contracts.grounding import GroundedAnswer
from policyops_contracts.model import ModelRequest, ToolSpec


VERSION = "policyops.investigation-prompt/v1"
FINISH = "finish_answer"
PROMPT = prompt_text(knowledge_tool=True) + """
- Investigate with one action per reply. Writes only prepare a proposal for human review and customer consent.
- Finish with finish_answer: every assertion needs exact quotes from search_policy, with its step and evidence ID.
- If evidence is insufficient, finish with an abstention. Plain prose is treated as insufficient evidence.
- After transfer_to_human_agents, send exactly the required handoff message."""
FINISH_TOOL = ToolDescriptor(name=FINISH, description="Finish with cited assertions or abstain. Control only.",
                             parameters_schema_json=json.dumps(GroundedAnswer.model_json_schema(), sort_keys=True),
                             read_only=True)
_CATALOG = ToolCatalog(mode="retail", tools=(*retail_tools(), FINISH_TOOL), knowledge_tool=True)


def catalog() -> ToolCatalog:
    return _CATALOG


def digest() -> str:
    return sha256_hex(json.dumps({"version": VERSION, "prompt": PROMPT, "heading": POLICY_HEADING,
                                  "notices": NOTICE_TEXT, "catalog": catalog().model_dump(mode="json")},
                                 sort_keys=True, separators=(",", ":")).encode())


def request(policy: PolicyContext, limits: AgentLimits, transcript: tuple[Entry, ...]) -> ModelRequest:
    return ModelRequest(instructions=PROMPT + POLICY_HEADING + policy.text, messages=provider_messages(transcript),
                        tools=tuple(ToolSpec(name=t.name, description=t.description,
                                             parameters_schema_json=t.parameters_schema_json)
                                    for t in catalog().all_tools()),
                        tool_choice="auto", max_output_tokens=limits.max_output_tokens, stream=False)
