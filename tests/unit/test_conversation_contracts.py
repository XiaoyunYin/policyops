"""T20 conversation contracts: policy binding, catalog limits (the knowledge tool included), coherent limits and a
closed, strict input surface."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
import pytest

from policyops_contracts.conversation import (
    KNOWLEDGE_DESCRIPTOR,
    KNOWLEDGE_TOOL,
    MAX_CATALOG_SCHEMA_BYTES,
    MAX_SCHEMA_BYTES,
    AgentLimits,
    AgentMessage,
    KnowledgeResult,
    PendingToolOutcome,
    PolicyContext,
    ToolCatalog,
    ToolDescriptor,
    ToolResult,
    TurnOutcome,
    UserMessage,
)
from policyops_contracts.digest import text_sha256
from policyops_contracts.policy import RETAIL_POLICY


def schema(**properties: Any) -> str:
    props = properties or {"account_id": {"type": "string"}}
    return json.dumps({"type": "object", "additionalProperties": False, "required": sorted(props),
                       "properties": props}, sort_keys=True)


def tool(name: str, *, schema_json: str | None = None) -> ToolDescriptor:
    return ToolDescriptor(name=name, description="Read an account (fictional).",
                          parameters_schema_json=schema_json or schema(), read_only=True)


def test_a_policy_is_bound_to_its_text_and_the_pinned_retail_source_to_the_pinned_digest() -> None:
    text = "Fictional policy."
    assert PolicyContext(domain="retail", source="fictional", text=text, sha256=text_sha256(text)).sha256
    with pytest.raises(ValidationError, match="digest"):
        PolicyContext(domain="retail", source="harness_domain_policy", text=text, sha256="0" * 64)
    # The pinned source accepts only the exact pinned upstream text (not copied into this repository, so the positive
    # case and the pinned-domain check are not exercised offline).
    with pytest.raises(ValidationError, match="pinned"):
        PolicyContext(domain="retail", source="pinned_retail_policy", text=text, sha256=text_sha256(text))
    with pytest.raises(ValidationError, match="digest"):
        PolicyContext(domain="retail", source="pinned_retail_policy", text=text, sha256=RETAIL_POLICY.sha256)


def test_the_knowledge_tool_counts_toward_every_catalog_limit_and_its_name_is_reserved() -> None:
    tools = tuple(tool(f"tool_{i:02d}") for i in range(31))
    assert len(ToolCatalog(mode="descriptor", tools=tools, knowledge_tool=True).all_tools()) == 32
    assert ToolCatalog(mode="descriptor", tools=(*tools, tool("tool_31"))).all_tools()[-1].name == "tool_31"
    with pytest.raises(ValidationError, match="knowledge tool included"):
        ToolCatalog(mode="descriptor", tools=(*tools, tool("tool_31")), knowledge_tool=True)
    with pytest.raises(ValidationError, match="reserved"):
        ToolCatalog(mode="descriptor", tools=(tool(KNOWLEDGE_TOOL),))
    with pytest.raises(ValidationError, match="unique"):
        ToolCatalog(mode="descriptor", tools=(tool("a"), tool("a")))


def test_schema_bytes_are_bounded_per_tool_and_in_total_with_the_knowledge_schema() -> None:
    def sized(name: str, size: int) -> ToolDescriptor:
        base = schema(account_id={"type": "string", "description": ""})
        pad = size - len(base.encode())
        return tool(name, schema_json=schema(account_id={"type": "string", "description": "x" * pad}))

    assert len(sized("a", MAX_SCHEMA_BYTES).parameters_schema_json.encode()) == MAX_SCHEMA_BYTES
    with pytest.raises(ValidationError, match="at most"):
        sized("a", MAX_SCHEMA_BYTES + 1)
    knowledge = len(KNOWLEDGE_DESCRIPTOR.parameters_schema_json.encode())
    full = tuple(sized(f"t{i}", MAX_SCHEMA_BYTES) for i in range(MAX_CATALOG_SCHEMA_BYTES // MAX_SCHEMA_BYTES))
    assert ToolCatalog(mode="descriptor", tools=full)
    with pytest.raises(ValidationError, match="total"):
        ToolCatalog(mode="descriptor", tools=full, knowledge_tool=True)
    room = (*full[:-1], sized("last", MAX_SCHEMA_BYTES - knowledge))
    assert ToolCatalog(mode="descriptor", tools=room, knowledge_tool=True)


def test_limits_are_finite_and_default_to_no_knowledge_steps() -> None:
    assert AgentLimits().knowledge_steps == 0
    assert AgentLimits(knowledge_steps=10).knowledge_steps == 10
    for field, value in (("model_calls", 0), ("model_calls", 65), ("consecutive_invalid", 5),
                         ("transcript_bytes", 120_001), ("max_output_tokens", 2049), ("knowledge_steps", 33),
                         ("steps_per_turn", True)):
        with pytest.raises(ValidationError):
            AgentLimits(**{field: value})


def test_the_input_surface_refuses_unknown_fields_and_coercion() -> None:
    for hidden in ("user_scenario", "instructions", "required_documents", "evaluation_criteria"):
        with pytest.raises(ValidationError, match="Extra inputs"):
            UserMessage.model_validate({"text": "hi", hidden: "canary-7f3a"})
    with pytest.raises(ValidationError):
        UserMessage(text="")
    with pytest.raises(ValidationError):
        UserMessage(text="a\x00b")
    with pytest.raises(ValidationError):
        ToolResult(call_id="c1", content="")  # an empty result is a port contract failure, never padded
    with pytest.raises(ValidationError):
        ToolResult(call_id="c1", content="x" * 32_001)
    with pytest.raises(ValidationError):
        KnowledgeResult.model_validate({"content": "x", "call_id": "c1"})  # content only
    with pytest.raises(ValidationError):
        ToolResult.model_validate({"call_id": "c1", "content": "x", "is_error": 1})


def test_a_turn_ends_with_exactly_one_message_or_terminal() -> None:
    base: dict[str, Any] = {"conversation_id": uuid4(), "turn": 0, "config_sha256": "0" * 64, "appended": (),
                            "model_calls": 1, "invalid_steps": 0, "counts_claimed": 1, "inferences_dispatched": 1,
                            "cleanup_unconfirmed": False}
    assert TurnOutcome(**base, message=AgentMessage(text="Done.")).terminal is None
    assert TurnOutcome(**base, terminal="cancelled",
                       pending_tool=PendingToolOutcome(call_id="c1", name="x", read_only=False)).pending_tool
    with pytest.raises(ValidationError, match="exactly one"):
        TurnOutcome(**base)
    with pytest.raises(ValidationError, match="exactly one"):
        TurnOutcome(**base, message=AgentMessage(text="Done."), terminal="handoff")
    with pytest.raises(ValidationError, match="only a terminal"):
        TurnOutcome(**base, message=AgentMessage(text="Done."),
                    pending_tool=PendingToolOutcome(call_id="c1", name="x", read_only=True))
