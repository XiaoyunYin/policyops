"""Pure deterministic fitting. Whole evidence pairs and original inputs are never shortened."""

import json
from typing import cast

from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.mechanics import TranscriptInvariant
from policyops.orchestration.profile import InvestigationProfile
from policyops.orchestration.state import InvestigationState, InvestigationStopped, state_from_json
from policyops.providers.canonical import CanonicalError, canonical_size
from policyops.providers.contract import ContractGap
from policyops_contracts.conversation import (
    AgentLimits,
    AgentMessage,
    AgentToolCall,
    Entry,
    PolicyContext,
    RuntimeNotice,
    ToolResult,
)
from policyops_contracts.stops import StopDetails, StopReason


def fit(state: InvestigationState, policy: PolicyContext, limits: AgentLimits, *,
        append: tuple[Entry, ...] = (), profile: InvestigationProfile = InvestigationProfile.BASELINE
        ) -> InvestigationState:
    entries = (*state.transcript, *append)
    pairs: list[tuple[int, int]] = []
    notices: list[tuple[int, ...]] = []
    pending = (state.pending_tool.call_id if state.pending_tool is not None else
               state.next_action.call.call_id if state.next_action is not None and state.next_action.call is not None
               else None)
    index = 0
    while index < len(entries):
        entry = entries[index]
        if isinstance(entry, AgentToolCall):
            if index + 1 < len(entries) and isinstance(entries[index + 1], ToolResult):
                result = cast(ToolResult, entries[index + 1])
                if result.call_id != entry.call_id:
                    raise TranscriptInvariant("mismatched completed context pair")
                if entry.call_id not in state.evidence_call_ids and entry.call_id != pending:
                    pairs.append((index, index + 1))
                index += 2
                continue
            if index != len(entries) - 1 or entry.call_id != pending:
                raise TranscriptInvariant("dangling context call")
        elif isinstance(entry, ToolResult):
            raise TranscriptInvariant("orphaned context result")
        elif isinstance(entry, RuntimeNotice | AgentMessage):
            notices.append((index,))
        index += 1
    removed: set[int] = set()
    pair_count = notice_count = 0

    def fits(candidate: tuple[Entry, ...]) -> bool:
        if len(candidate) > min(256, limits.transcript_messages):
            return False
        # Include framing, escaping, pending arguments and trusted facts in the transcript allowance.
        content = [entry.model_dump(mode="json") for entry in candidate]
        facts = [fact.model_dump(mode="json") for fact in state.critical_facts]
        try:
            canonical_size({"transcript": content, "critical_facts": facts}, limit=limits.transcript_bytes)
            canonical_size(state.model_dump(mode="json") | {"transcript": content}, limit=262144)
            # The pending action is pinned but is not a provider history until its result exists.
            history = candidate[:-1] if candidate and isinstance(candidate[-1], AgentToolCall) else candidate
            prompt.request(policy, limits, history, facts_text=json.dumps(facts, ensure_ascii=False,
                                                                         separators=(",", ":")), profile=profile)
        except (CanonicalError, ContractGap, TranscriptInvariant, ValueError):
            return False
        return True

    candidate = entries
    for unit in (*pairs, *notices):
        if fits(candidate):
            break
        removed.update(unit)
        pair_count += len(unit) == 2
        notice_count += len(unit) == 1
        candidate = tuple(entry for i, entry in enumerate(entries) if i not in removed)
    if not fits(candidate):
        # No oversized output enters a synchronous checkpoint. Preserve the already fitted prior state/pins.
        return state.model_copy(update={"terminal": InvestigationStopped(
            details=StopDetails(reason=StopReason.CONTEXT_LIMIT, cleanup_unconfirmed=state.cleanup_unconfirmed))})
    return state_from_json(state.model_dump(mode="json") | {
        "transcript": [entry.model_dump(mode="json") for entry in candidate],
        "trimmed_pairs": state.trimmed_pairs + pair_count,
        "trimmed_notices": state.trimmed_notices + notice_count})
