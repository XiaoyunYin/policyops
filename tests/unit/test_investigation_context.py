"""Whole-unit fitting and bounded provider preparation, using synthetic text only."""

from datetime import UTC, datetime
import json
from typing import Any
from uuid import uuid4

import pytest

from policyops.budget.config import Configuration
from policyops.orchestration.context import fit
from policyops.orchestration.mechanics import provider_messages
from policyops.orchestration.state import CriticalFact, InvestigationState, InvestigationStopped
from policyops.providers import serialize
from policyops.providers.bounds import preflight
from policyops.providers.canonical import CanonicalError, canonical_bytes, canonical_size
from policyops.providers.contract import ContractGap
from policyops_contracts.conversation import AgentLimits, AgentToolCall, Entry, RuntimeNotice, ToolResult, UserMessage
from policyops_contracts.model import Message, ModelRequest, TextPart, ToolSpec
from policyops_contracts.stops import StopReason
from policyops_testing.agent_fakes import fictional_policy


def seed(entries: tuple[Entry, ...], **fields: Any) -> InvestigationState:
    return InvestigationState(state_version=2, workspace_id=uuid4(), case_id=uuid4(), run_id=uuid4(),
        graph_sha256="1" * 64, prompt_sha256="2" * 64, config_sha256="3" * 64, transcript=entries, **fields)


def pair(index: int, text: str = "result") -> tuple[AgentToolCall, ToolResult]:
    call_id = f"call{index}"
    return (AgentToolCall(call_id=call_id, name="calculate", arguments_json='{"expression":"1+1"}'),
            ToolResult(call_id=call_id, content=text))


def test_oldest_pairs_then_notices_and_stable_idempotency() -> None:
    user = UserMessage(text='Keep verbatim: "yes" 雪\\\n')
    notice = RuntimeNotice(code="invalid_arguments")
    state = seed((user, notice, *pair(0, "x" * 800), *pair(1, "y" * 800), *pair(2, "z" * 800)))
    fitted = fit(state, fictional_policy(), AgentLimits(transcript_bytes=1800))
    assert fitted.terminal is None and fitted.trimmed_pairs == 2 and fitted.trimmed_notices == 0
    assert fitted.transcript == (user, notice, *pair(2, "z" * 800))
    assert fit(fitted, fictional_policy(), AgentLimits(transcript_bytes=1800)) == fitted
    assert fit(state, fictional_policy(), AgentLimits(transcript_bytes=1800)) == fitted
    provider_messages(fitted.transcript)


def test_evidence_quotes_and_trusted_facts_survive_exactly() -> None:
    quote = 'Exact "terms" 雪\\\n' * 25
    fact = CriticalFact(proposal_id=uuid4(), proposal_version=7, action_digest="a" * 64, status="presented",
        expires_at=datetime(2030, 1, 1, tzinfo=UTC), presentation_message_id=uuid4(), presentation_text=quote,
        presentation_sha256="b" * 64, consent_id=uuid4(), decision_id=uuid4())
    state = seed((UserMessage(text="Original consent"), *pair(0, quote), *pair(1, "x" * 2500)),
                 evidence_call_ids=("call0",), critical_facts=(fact,))
    fitted = fit(state, fictional_policy(), AgentLimits(transcript_bytes=2400))
    assert fitted.terminal is None and fitted.trimmed_pairs == 1
    assert fitted.transcript == state.transcript[:3] and fitted.critical_facts == (fact,)
    assert fitted.transcript[2] == pair(0, quote)[1]


def test_pins_alone_stop_without_shortening_or_clearing_pending() -> None:
    from policyops_contracts.conversation import PendingToolOutcome

    call, _ = pair(1)
    state = seed((UserMessage(text="x" * 1500), call),
                 pending_tool=PendingToolOutcome(call_id=call.call_id, name=call.name, read_only=True))
    fitted = fit(state, fictional_policy(), AgentLimits(transcript_bytes=1024))
    assert isinstance(fitted.terminal, InvestigationStopped)
    assert fitted.terminal.details.reason == StopReason.CONTEXT_LIMIT
    assert fitted.pending_tool == state.pending_tool and fitted.transcript == state.transcript


def test_repeated_large_results_bound_every_checkpoint_and_keep_adjacency() -> None:
    limits = AgentLimits(transcript_bytes=6000)
    state = seed((UserMessage(text="Original request"),))
    for index in range(20):
        state = fit(state, fictional_policy(), limits, append=pair(index, '"雪\\\n' * 300))
        assert state.terminal is None
        assert canonical_size([e.model_dump(mode="json") for e in state.transcript], limit=6000) <= 6000
        provider_messages(state.transcript)
    assert state.trimmed_pairs > 10


def test_user_parts_are_split_without_loss() -> None:
    entries = tuple(UserMessage(text=str(i)) for i in range(130))
    messages = provider_messages(entries)
    assert tuple(len(message.parts) for message in messages) == (64, 64, 2)
    fitted = fit(seed(entries), fictional_policy(), AgentLimits(transcript_messages=256, transcript_bytes=20000))
    assert fitted.terminal is None and fitted.transcript == entries


def test_old_notices_are_evicted_after_pairs_with_stable_order() -> None:
    user = UserMessage(text="Keep")
    notices = (RuntimeNotice(code="invalid_arguments"), RuntimeNotice(code="empty_reply"),
               RuntimeNotice(code="protocol_violation"))
    state = seed((user, notices[0], *pair(1), *notices[1:]))
    fitted = fit(state, fictional_policy(), AgentLimits(transcript_messages=2))
    assert fitted.transcript == (user, notices[-1])
    assert fitted.trimmed_pairs == 1 and fitted.trimmed_notices == 2


def test_mismatched_pairs_remain_integrity_errors() -> None:
    from policyops.orchestration.mechanics import TranscriptInvariant

    call, _ = pair(1)
    with pytest.raises(TranscriptInvariant):
        fit(seed((UserMessage(text="q"), call, ToolResult(call_id="other", content="wrong"))),
            fictional_policy(), AgentLimits())


@pytest.mark.parametrize("text", ['雪☃"\\\n\t\x01', "a" * 5000, ""])
def test_canonical_measurement_matches_utf8_and_escaping(text: str) -> None:
    value = {"x": [text, True, False, None, -12], "empty": {}}
    size = len(canonical_bytes(value))
    assert canonical_size(value, limit=size) == size
    with pytest.raises(CanonicalError):
        canonical_size(value, limit=size - 1)


def request(messages: tuple[Message, ...], *, instructions: str = "i",
            tools: tuple[ToolSpec, ...] = ()) -> ModelRequest:
    return ModelRequest(instructions=instructions, messages=messages, tools=tools, max_output_tokens=64)


@pytest.mark.parametrize("kind", ["content", "parts", "nodes", "schema", "escaped"])
def test_preflight_refuses_before_decoding_schema_or_building_provider_bodies(
        kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    text = "x"
    if kind == "content":
        text = "雪" * 90000
    elif kind == "escaped":
        text = "\x01" * 100000
    messages: tuple[Message, ...] = (Message(role="user", parts=(TextPart(text=text),)),)
    tools: tuple[ToolSpec, ...] = ()
    if kind == "parts":
        messages = tuple(Message(role="user", parts=tuple(TextPart(text="x") for _ in range(64))) for _ in range(33))
    elif kind == "nodes":
        schema = '{"type":"object","x":[' + ','.join('0' for _ in range(20000)) + ']}'
        tools = tuple(ToolSpec(name=f"t{i}", description="test", parameters_schema_json=schema) for i in range(2))
    elif kind == "schema":
        tools = tuple(ToolSpec(name=f"t{i}", description="test", parameters_schema_json='"' + "x" * 65000 + '"')
                      for i in range(5))
    value = request(messages, tools=tools)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must refuse before decoding/materializing")

    for name in ("_arguments", "_schemas", "_openai_body", "_anthropic_body", "canonical_bytes"):
        monkeypatch.setattr(serialize, name, forbidden)
    with pytest.raises(ContractGap):
        serialize.prepare(value, Configuration(), "agent")


def test_policy_overflow_and_message_overflow_stop_before_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from policyops.orchestration import investigation_prompt as prompt

    policy = fictional_policy().model_copy(update={"text": "雪" * 100000})
    fitted = fit(seed((UserMessage(text="q"),)), policy, AgentLimits())
    assert isinstance(fitted.terminal, InvestigationStopped)
    value = request((Message(role="user", parts=(TextPart(text="x"),)),))
    oversized = value.model_copy(update={"messages": value.messages * 257})
    with pytest.raises(ContractGap):
        preflight(oversized)
    # Fitting does not modify prompt/catalog identity or policy text to make the request pass.
    assert len(policy.text) == 100000 and prompt.catalog().tools


def test_early_exit_happens_before_a_large_string_is_fully_encoded(monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.dumps
    sizes: list[int] = []

    def bounded(value: Any, **kwargs: Any) -> str:
        if isinstance(value, str):
            sizes.append(len(value))
            assert len(value) <= 1024
        return original(value, **kwargs)

    monkeypatch.setattr(json, "dumps", bounded)
    with pytest.raises(CanonicalError):
        canonical_size("\x01" * 1000000, limit=512 * 1024)
    assert len(sizes) < 100
