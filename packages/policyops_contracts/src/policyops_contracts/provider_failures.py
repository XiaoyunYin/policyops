"""Shared closed diagnostic codes; no SDK/runtime imports or sensitive values."""

import re


_HTTP = re.compile(r"http_[345][0-9]{2}\Z")
_CODES = frozenset({"timeout", "connection", "malformed", "provider_error", "cancelled"})
_MALFORMED = frozenset({"count_not_json", "count_malformed", "response_not_json", "response_not_object",
    "response_malformed", "result_unrepresentable", "usage_malformed", "unexpected_status", "unexpected_stop",
    "stream_without_final_response", "text_not_unicode", "text_too_large", "output_malformed",
    "tool_call_malformed", "tool_arguments_not_json", "unexpected_output_item", "unexpected_content_block",
    "too_large", "too_many_events", "tool_arguments_too_large", "line_too_large",
    "line_too_long", "response_too_large"})


def failure_code(reason: str | None) -> str | None:
    """Map only known internal diagnostics, with the count phase kept separately."""
    if reason is None:
        return None
    code = reason.removeprefix("count.")
    if code in _CODES or _HTTP.fullmatch(code):
        return code
    if code in {"deadline", "attempt_timeout", "deadline_already_passed"}:
        return "timeout"
    if code in _MALFORMED:
        return "malformed"
    if code == "provider_failed":
        return "provider_error"
    return None


def closed_failure_code(value: object) -> str | None:
    """Validate already normalized artifact values without echoing unknown strings."""
    return value if isinstance(value, str) and (value in _CODES or _HTTP.fullmatch(value)) else None
