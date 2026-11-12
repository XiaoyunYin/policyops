"""Closed investigation stop facts; no prompt, arguments or exception diagnostics."""

from enum import StrEnum

from pydantic import model_validator

from policyops_contracts.base import WireModel


class StopReason(StrEnum):
    USD_CAP = "usd_cap"
    CALL_CAP = "call_cap"
    COUNT_CAP = "count_cap"
    INPUT_TOKENS = "input_tokens"
    ACTIVE_TIME = "active_time"
    TOOL_CAP = "tool_cap"
    CONTEXT_LIMIT = "context_limit"
    OVERRUN = "overrun"
    CONTRACT_BLOCK = "contract_block"
    USAGE_UNCONFIRMED = "usage_unconfirmed"


class StopDetails(WireModel):
    reason: StopReason
    usage_unconfirmed: bool = False
    cleanup_unconfirmed: bool = False

    @model_validator(mode="after")
    def truthful(self) -> "StopDetails":
        if self.reason == StopReason.USAGE_UNCONFIRMED and not self.usage_unconfirmed:
            raise ValueError("unconfirmed usage must be explicit")
        return self

    @property
    def failed(self) -> bool:
        return self.reason in {StopReason.CONTEXT_LIMIT, StopReason.CONTRACT_BLOCK, StopReason.USAGE_UNCONFIRMED}
