"""Pure stop classification and fixed user-facing text."""

from policyops_contracts.stops import StopDetails, StopReason


class InvestigationStop(Exception):
    def __init__(self, details: StopDetails) -> None:
        self.details = details
        super().__init__(details.reason.value)


def stop_reason(reason: str | None) -> StopReason:
    aliases = {"blocked_by_overrun": StopReason.OVERRUN, "blocked_by_contract": StopReason.CONTRACT_BLOCK,
               "count_exceeded": StopReason.INPUT_TOKENS, "count_rejected": StopReason.INPUT_TOKENS,
               "count_not_admitted": StopReason.INPUT_TOKENS,
               "plan_exceeds_caps": StopReason.INPUT_TOKENS, "deadline": StopReason.ACTIVE_TIME,
               "deadline_passed": StopReason.ACTIVE_TIME}
    if reason in aliases:
        return aliases[reason]
    try:
        return StopReason(reason or "")
    except (ValueError, TypeError):
        return StopReason.CONTRACT_BLOCK


_LABELS = {
    StopReason.USD_CAP: "the cost limit was reached",
    StopReason.CALL_CAP: "the model call limit was reached",
    StopReason.COUNT_CAP: "the token-count call limit was reached",
    StopReason.INPUT_TOKENS: "the input token limit was reached",
    StopReason.ACTIVE_TIME: "the active investigation time limit was reached",
    StopReason.TOOL_CAP: "the tool step limit was reached",
    StopReason.RETRIEVAL_CAP: "the policy retrieval limit was reached",
    StopReason.INVALID_CAP: "the limit on consecutive invalid model replies was reached",
    StopReason.CONTEXT_LIMIT: "the required context does not fit",
    StopReason.OVERRUN: "provider usage exceeded its reservation",
    StopReason.CONTRACT_BLOCK: "the provider request or accounting contract was blocked",
    StopReason.USAGE_UNCONFIRMED: "provider usage could not be confirmed",
}


def stop_text(details: StopDetails) -> str:
    text = f"Investigation stopped: {_LABELS[details.reason]}. No further actions will run."
    if details.usage_unconfirmed:
        text += " Some provider usage is unconfirmed; reserved cost remains held."
    if details.cleanup_unconfirmed:
        text += " Provider cleanup is unconfirmed."
    return text + " Start a new investigation to continue."
