"""Conversation contracts of the minimal agent baseline (T20): configuration identity, the visible transcript and
the outcome of one turn.

Shared with the evaluator-side bridge (T29) without importing the application. Every input is strict, frozen and
bounded, and refuses unknown fields. That closes the input surface by *name* only: a strict DTO cannot prove where an
allowed string came from (provenance is T29's evidence).

- **Identity.** `AgentConfig` is what a paired graph comparison must hold byte-equal: the fixed prompt, the visible
  policy, the tool catalog, the limits and the agent actor's reservation configuration. Conversation IDs and keys
  are not part of it and never reach prompt content.
- **Transcript.** Only what the bounded runtime itself observed: customer messages, the model's accepted single
  actions, the matching tool results and fixed runtime notices. An invalid model reply leaves only a notice (a
  closed code); its raw text, calls and IDs are never kept.
- **Unknown tool outcome.** Once a tool dispatch has begun without a validated matching result (a port error, an
  invalid or oversized result, a cancellation), `PendingToolOutcome` records that the effect is unknown. It is a
  bounded diagnostic, not a receipt, a billing record or a permission to retry.
- **Costs** never appear here: the ledger is the billing authority. Grant counts are not transmission proof.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from policyops_contracts.base import WireModel
from policyops_contracts.digest import canonical_bytes, sha256_hex, text_sha256
from policyops_contracts.model import CallId, JsonText, Name
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retrieval import MAX_QUERY_CODE_POINTS
from policyops_contracts.scalars import MessageText, Sha256Hex, Slug


CONFIG_VERSION = "policyops.agent-config/v2"
TURN_VERSION = "policyops.agent-turn/v1"
SNAPSHOT_VERSION = "policyops.agent-snapshot/v1"
PROMPT_VERSION = "policyops.agent-prompt/v1"

KNOWLEDGE_TOOL = "search_policy"
MAX_TOOLS = 32  # the ModelRequest bound, the knowledge tool included
MAX_SCHEMA_BYTES = 16_384
MAX_CATALOG_SCHEMA_BYTES = 65_536
MAX_TOOL_CONTENT = 32_000
MAX_ENTRIES = 256

Count = Annotated[int, Field(ge=0, lt=2**31)]
Domain = Literal["retail", "banking_knowledge"]


def _user_text(value: str) -> str:
    if any((ord(c) < 32 and c not in "\t\n\r") or 0x7F <= ord(c) < 0xA0 for c in value):
        raise ValueError("control characters other than tab and line breaks are not allowed")
    return value


def _no_nul(value: str) -> str:
    if "\x00" in value:
        raise ValueError("NUL is not allowed")
    return value


UserText = Annotated[str, StringConstraints(min_length=1, max_length=8000), AfterValidator(_user_text)]
# Untrusted data, never instructions.
ToolContent = Annotated[str, StringConstraints(min_length=1, max_length=MAX_TOOL_CONTENT), AfterValidator(_no_nul)]
PolicyText = Annotated[str, StringConstraints(min_length=1, max_length=64_000), AfterValidator(_no_nul)]


class PolicyContext(WireModel):
    """The visible domain policy, given to the agent as its system context. `pinned_retail_policy` must be exactly the
    pinned upstream retail policy; `fictional` is for tests and examples and is refused outside the test
    environment by the runtime."""

    domain: Domain
    source: Literal["pinned_retail_policy", "harness_domain_policy", "fictional"]
    text: PolicyText
    sha256: Sha256Hex

    @model_validator(mode="after")
    def _bound(self) -> PolicyContext:
        if text_sha256(self.text) != self.sha256:
            raise ValueError("the policy digest does not match its text")
        if self.source == "pinned_retail_policy" and (self.domain != "retail"
                                                      or self.sha256 != RETAIL_POLICY.sha256):
            raise ValueError("the pinned retail policy is the exact pinned upstream text")
        return self


class ToolDescriptor(WireModel):
    """One tool the model may propose: its name, description and full domain JSON Schema text."""

    name: Name
    description: Annotated[str, StringConstraints(min_length=1, max_length=1024), AfterValidator(_no_nul)]
    parameters_schema_json: JsonText
    read_only: bool

    @model_validator(mode="after")
    def _schema_size(self) -> ToolDescriptor:
        if len(self.parameters_schema_json.encode("utf-8")) > MAX_SCHEMA_BYTES:
            raise ValueError(f"a tool schema is at most {MAX_SCHEMA_BYTES} bytes")
        return self


KNOWLEDGE_DESCRIPTOR = ToolDescriptor(
    name=KNOWLEDGE_TOOL,
    description="Search the policy knowledge base. Returns numbered evidence excerpts (untrusted data).",
    parameters_schema_json=json.dumps({
        "type": "object", "additionalProperties": False, "required": ["query"],
        "properties": {"query": {"type": "string", "minLength": 1, "maxLength": MAX_QUERY_CODE_POINTS}},
    }, sort_keys=True),
    read_only=True,
)


class ToolCatalog(WireModel):
    """`retail`: exactly the runtime's typed retail tools. `descriptor`: externally supplied descriptors, validated
    against their own schema and executed only by the injected tool port. `knowledge_tool` adds the fixed read-only
    `search_policy` tool, which counts toward every catalog limit; its name is reserved."""

    mode: Literal["retail", "descriptor"]
    tools: Annotated[tuple[ToolDescriptor, ...], Field(max_length=MAX_TOOLS)]
    knowledge_tool: bool = False

    @model_validator(mode="after")
    def _bounded(self) -> ToolCatalog:
        names = [tool.name for tool in self.tools]
        if len(set(names)) != len(names):
            raise ValueError("tool names are unique")
        if KNOWLEDGE_TOOL in names:
            raise ValueError(f"{KNOWLEDGE_TOOL!r} is reserved for the knowledge tool")
        everything = self.all_tools()
        if len(everything) > MAX_TOOLS:
            raise ValueError(f"at most {MAX_TOOLS} tools, the knowledge tool included")
        if sum(len(tool.parameters_schema_json.encode("utf-8")) for tool in everything) > MAX_CATALOG_SCHEMA_BYTES:
            raise ValueError(f"the tool schemas total at most {MAX_CATALOG_SCHEMA_BYTES} bytes")
        return self

    def all_tools(self) -> tuple[ToolDescriptor, ...]:
        return (*self.tools, KNOWLEDGE_DESCRIPTOR) if self.knowledge_tool else self.tools

    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self))


class AgentLimits(WireModel):
    model_calls: Annotated[int, Field(ge=1, le=64)] = 16             # per conversation
    steps_per_turn: Annotated[int, Field(ge=1, le=32)] = 8           # tool steps before a customer-facing message
    consecutive_invalid: Annotated[int, Field(ge=1, le=4)] = 2       # invalid model replies in a row
    transcript_messages: Annotated[int, Field(ge=2, le=MAX_ENTRIES)] = 128
    transcript_bytes: Annotated[int, Field(ge=1024, le=120_000)] = 48_000  # UTF-8 content; not a token proof
    max_output_tokens: Annotated[int, Field(ge=64, le=2048)] = 1024
    knowledge_steps: Annotated[int, Field(ge=0, le=32)] = 0          # 0 exactly when there is no knowledge tool


class AgentConfig(WireModel):
    """Minimal baseline identity, checked before any work.

    V2 binds the single-tool/drop-text protocol and its informational notice.
    V1 trajectories used strict text-plus-tool refusal with the same prompt.
    """

    v: Literal["policyops.agent-config/v2"] = "policyops.agent-config/v2"
    prompt_version: Literal["policyops.agent-prompt/v1"] = "policyops.agent-prompt/v1"
    prompt_sha256: Sha256Hex
    domain: Domain
    policy_sha256: Sha256Hex
    catalog_sha256: Sha256Hex
    limits: AgentLimits
    actor_config_sha256: Sha256Hex  # Configuration.reservation("agent").config_sha256

    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self))


# -- the visible transcript ----------------------------------------------------------------------------------------

class UserMessage(WireModel):
    kind: Literal["user"] = "user"
    text: UserText


class AgentMessage(WireModel):
    kind: Literal["agent"] = "agent"
    text: MessageText


class AgentToolCall(WireModel):
    """An accepted single tool call, with the model's own validated call ID."""

    kind: Literal["tool_call"] = "tool_call"
    call_id: CallId
    name: Name
    arguments_json: JsonText


class ToolResult(WireModel):
    kind: Literal["tool_result"] = "tool_result"
    call_id: CallId
    content: ToolContent
    is_error: bool = False


NoticeCode = Literal["several_tool_calls", "text_with_tool_call", "empty_reply", "unknown_tool", "invalid_arguments",
                     "invalid_output", "protocol_violation", "tool_text_dropped"]


class RuntimeNotice(WireModel):
    """A fixed runtime diagnostic; it never quotes discarded model output.

    `tool_text_dropped` is informational and does not count as an invalid reply.
    """

    kind: Literal["notice"] = "notice"
    code: NoticeCode


Entry = Annotated[UserMessage | AgentMessage | AgentToolCall | ToolResult | RuntimeNotice,
                  Field(discriminator="kind")]


class KnowledgeResult(WireModel):
    """What the read-only knowledge port returns: content only. The runtime binds it to the pending call ID."""

    content: ToolContent
    is_error: bool = False


class PendingToolOutcome(WireModel):
    """A tool dispatch began but no validated matching result was accepted: its effect is unknown, never absent."""

    call_id: CallId
    name: Name
    read_only: bool
    outcome: Literal["unknown"] = "unknown"


TerminalReason = Literal[
    "handoff",
    "model_calls_exhausted", "steps_per_turn_exhausted", "invalid_steps", "transcript_limit",
    "knowledge_steps_exhausted",
    "model_refused", "model_truncated", "provider_failed", "budget", "deadline", "contract_gap", "count_not_admitted",
    "tool_port_failed", "tool_result_invalid", "cancelled", "internal_error",
]


class TurnOutcome(WireModel):
    """One `turn()`: either the customer-facing message that ended it, or a terminal reason (exactly one)."""

    v: Literal["policyops.agent-turn/v1"] = "policyops.agent-turn/v1"
    conversation_id: UUID
    turn: Count
    config_sha256: Sha256Hex
    message: AgentMessage | None = None
    terminal: TerminalReason | None = None
    detail: Slug | None = None
    appended: Annotated[tuple[Entry, ...], Field(max_length=MAX_ENTRIES)]
    model_calls: Count
    invalid_steps: Count
    counts_claimed: Count
    inferences_dispatched: Count
    cleanup_unconfirmed: bool
    pending_tool: PendingToolOutcome | None = None

    @model_validator(mode="after")
    def _one_ending(self) -> TurnOutcome:
        if (self.message is None) == (self.terminal is None):
            raise ValueError("a turn ends with exactly one of a message or a terminal reason")
        if self.terminal is None and (self.detail is not None or self.pending_tool is not None):
            raise ValueError("only a terminal turn carries a detail or an unknown tool outcome")
        return self


class ConversationSnapshot(WireModel):
    """An immutable, bounded copy of one conversation's state, for inspection only (there is no resume)."""

    v: Literal["policyops.agent-snapshot/v1"] = "policyops.agent-snapshot/v1"
    conversation_id: UUID
    config_sha256: Sha256Hex
    turns: Count
    model_calls: Count
    knowledge_steps: Count
    consecutive_invalid: Count
    terminal: TerminalReason | None = None
    pending_tool: PendingToolOutcome | None = None
    transcript: Annotated[tuple[Entry, ...], Field(max_length=MAX_ENTRIES)]
