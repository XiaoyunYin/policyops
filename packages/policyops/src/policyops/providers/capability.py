"""The provider capability record and the future live smoke manifest (T11). Data only: nothing here calls anything.

The record separates the kinds of evidence:
- **`offline_contract`**: exercised by the offline tests through the real SDK clients over a scripted mock transport.
  It says the code serializes, bounds and maps those shapes. It says nothing about any account, model behaviour,
  price or counting accuracy.
- **`live`**: every live cell is `not_run`. A live result needs a separately approved, bounded smoke run (the
  manifest below) and is recorded with its artifacts. A mock is never a capability result, and full T11 acceptance
  stays open until those cells hold real results.

The protocol choices are recorded so later comparisons state them: Haiku runs with `thinking: disabled` at effort
`low` (reviewer primary verification of the effort guide, 2026-11-05); Luna runs at effort `low`.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal

from policyops.budget.config import ChatActor, Configuration
from policyops.budget.pricing import worst_case


LiveState = Literal["not_run", "attempted", "supported", "refused", "unavailable"]
CELLS = ("text", "tool_call", "structured_output", "streaming", "counting", "count_vs_usage", "cache_none")

PROTOCOL = {
    "openai": {"model": "gpt-6-luna", "api": "responses", "effort": "low", "service_tier": "default",
               "cache_none": "prompt_cache_options.mode=explicit, no breakpoints", "store": False},
    "anthropic": {"model": "claude-haiku-5-5", "api": "messages", "effort": "low", "thinking": "disabled",
                  "service_tier": "standard_only", "speed": "standard", "anthropic_version": "2026-10-21",
                  "cache_none": "no cache_control, no replayed thinking, no per-message effort change"},
}
NOT_IMPLEMENTED = {"openai": ["cache 12h (SDK documents 30m only)"],
                   "anthropic": ["cache 5m", "cache 1h", "adaptive thinking continuation"]}


def capability_record() -> dict[str, Any]:
    live: dict[str, dict[str, LiveState]] = {provider: dict.fromkeys(CELLS, "not_run") for provider in PROTOCOL}
    return {
        "v": "policyops.provider-capability/v1",
        "sdk": {"openai": "3.40.0", "anthropic": "2.3.0"},
        "protocol": PROTOCOL,
        "not_implemented": NOT_IMPLEMENTED,
        "offline_contract": {provider: [*CELLS[:5], "unknown_usage_hold", "contract_block"]
                             for provider in PROTOCOL},
        "live": live,
        "live_note": "No live call has been made. Live cells need a separately approved smoke run.",
    }


# PRELIMINARY data only: not an enforceable plan and never an approval. A live smoke needs a reviewed driver (with a
# persisted budget, a mandatory count per attempt and enforced repair/retry limits) and separate explicit approval.
# These bounds (2000 input / 256 output) differ from the default actors (16000 / 2048); a driver must use actor
# configurations with exactly its own bounds.
SMOKE_MANIFEST: dict[str, Any] = {
    "v": "policyops.provider-smoke-manifest/v1",
    "status": "preliminary_not_enforceable",
    "approved": False,
    "per_provider": {
        "requests": [
            {"purpose": "count", "kind": "count", "input_tokens_max": 2000},
            {"purpose": "tool_call_with_schema", "kind": "inference", "stream": False, "input_tokens_max": 2000,
             "max_output_tokens": 256},
            {"purpose": "structured_output_streaming", "kind": "inference", "stream": True,
             "input_tokens_max": 2000, "max_output_tokens": 256},
        ],
        "physical_inference_attempts_max": 4,
        "count_calls_max": 2,
        "retries_per_request": 0,
        "request_timeout_seconds": 30,
    },
    "total_usd_cap": "0.01",
    "artifacts": "sanitized: request digests, status codes, usage counts, reason codes; never prompts, keys, headers",
}


def smoke_preflight(configuration: Configuration | None = None) -> dict[str, Any]:
    """The worst-case cost of the smoke manifest at the installed price snapshot, against its cap. Never an
    approval: `authorizes_live_calls` is always False."""
    configuration = configuration or Configuration()
    plan = SMOKE_MANIFEST["per_provider"]
    total = Decimal(0)
    per_provider = {}
    for actor_name, provider in (("agent", "openai"), ("judge", "anthropic")):
        actor = configuration.actors[actor_name]  # type: ignore[index]
        if not isinstance(actor, ChatActor):
            raise TypeError("smoke actors are chat actors")
        price = configuration.registry.snapshot.price(actor.model)
        one = worst_case(price, max_input=2000, max_output=256, cache_mode=actor.cache_mode)
        cost = one * plan["physical_inference_attempts_max"]
        per_provider[provider] = {"model": actor.model, "worst_usd_per_attempt": str(one), "worst_usd": str(cost)}
        total += cost
    cap = Decimal(SMOKE_MANIFEST["total_usd_cap"])
    return {"per_provider": per_provider, "worst_total_usd": str(total), "cap_usd": str(cap),
            "within_cap": total <= cap, "authorizes_live_calls": False}
