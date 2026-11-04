"""Scripted fake model provider for default tests (no SDK, no network, no retries).

A test lists the exact requests it expects, in order, with the response for each. Any other request, an extra
request, or leftover script entries fail the test. Only a matching request advances the script; a mismatched or
extra request is recorded, so `assert_exhausted()` still fails if the code under test caught the error. Responses
cover text, tool calls, refusals, truncation and timeouts, with explicit usage. The real provider port arrives in
T10/T11; this fake is shaped so an adapter can wrap it without changing tests' expectations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal, NoReturn


class UnexpectedRequest(AssertionError):
    """The code under test sent a request the script did not expect (or sent one too many)."""


class FakeProviderTimeout(TimeoutError):
    """Scripted provider timeout; the fake never retries on the caller's behalf.

    `billed` is the usage the script says the provider charged before failing, or None when it is unknown.
    """

    def __init__(self, message: str, billed: Usage | None) -> None:
        super().__init__(message)
        self.billed = billed


@dataclass(frozen=True)
class FakeRequest:
    model: str
    messages: tuple[str, ...]
    tools: tuple[str, ...] = ()
    max_output_tokens: int = 1024


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int = 0
    reasoning_tokens: int = 0

    def __post_init__(self) -> None:
        values = (self.input_tokens, self.output_tokens, self.cached_input_tokens, self.reasoning_tokens)
        if any(isinstance(value, bool) or value < 0 for value in values):
            raise ValueError("token counts must be non-negative integers")
        if self.cached_input_tokens > self.input_tokens or self.reasoning_tokens > self.output_tokens:
            raise ValueError("cached/reasoning tokens are included in, so cannot exceed, input/output totals")


@dataclass(frozen=True)
class FakeResponse:
    kind: Literal["text", "tool_call", "refusal", "truncated"]
    usage: Usage
    text: str = ""
    tool_name: str | None = None
    tool_arguments_json: str | None = None

    def __post_init__(self) -> None:
        if (self.kind == "tool_call") != (self.tool_name is not None and self.tool_arguments_json is not None):
            raise ValueError("tool_call responses, and only they, carry a tool name and JSON arguments")


@dataclass(frozen=True)
class Timeout:
    """Scripted timeout: the provider is assumed to have consumed `billed` usage before failing."""

    billed: Usage | None = None


@dataclass(frozen=True)
class Step:
    request: FakeRequest
    result: FakeResponse | Timeout


@dataclass
class FakeProvider:
    script: Sequence[Step]
    calls: list[FakeRequest] = field(default_factory=list)  # every attempted request, matched or not
    consumed: int = 0  # script steps matched so far
    unexpected: list[str] = field(default_factory=list)

    def complete(self, request: FakeRequest) -> FakeResponse:
        self.calls.append(request)
        attempt = len(self.calls)
        if self.consumed >= len(self.script):
            self._reject(f"request #{attempt} was not scripted: {request!r}")
        step = self.script[self.consumed]
        if request != step.request:
            self._reject(f"request #{attempt} differs from script step #{self.consumed + 1}:\n"
                         f"  expected {step.request!r}\n  received {request!r}")
        self.consumed += 1
        if isinstance(step.result, Timeout):
            raise FakeProviderTimeout(f"scripted timeout on request #{attempt}", step.result.billed)
        return step.result

    def _reject(self, message: str) -> NoReturn:
        self.unexpected.append(message)
        raise UnexpectedRequest(message)

    @property
    def remaining(self) -> int:
        return len(self.script) - self.consumed

    def assert_exhausted(self) -> None:
        if self.unexpected:
            raise UnexpectedRequest(f"{len(self.unexpected)} unexpected request(s), even if the code under test "
                                    f"caught the error; first: {self.unexpected[0]}")
        if self.remaining:
            raise UnexpectedRequest(f"{self.remaining} scripted request(s) were never sent")
