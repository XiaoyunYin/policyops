"""Exact usage cost and worst-case reservation amounts (T10). Pure: no I/O.

- `Usage` is a provider's reported counts for one request: the whole prompt (`input_total`), the parts of it read
  from cache and written to cache per lifetime, and the billed output, which already includes any reasoning
  (`reasoning` is informational and never added again). Ordinary input is `input_total - cache_read - writes`.
- `cost` prices actual usage at the tier its whole prompt falls in, exactly (Decimal, never rounded or truncated).
- `worst_case` (decision D4) is what a request may at most cost before it is sent: at the most expensive tier its
  admitted maximum prompt can reach, with every prompt token written cold to cache at the request's cache lifetime
  (or ordinary input without caching), plus the maximum billed output.
Contradictory or invalid counts are refused, never coerced into plausible values.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from types import MappingProxyType

from policyops.budget.prices import ModelPrice, Tier, UnknownPrice


class InvalidUsage(ValueError):
    """Counts that cannot all be true (negative, non-integer, or parts larger than their total)."""


def _count(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidUsage(f"{what} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class Usage:
    input_total: int
    cache_read: int = 0
    cache_writes: Mapping[str, int] = field(default_factory=dict)
    output: int = 0
    reasoning: int | None = 0  # informational (inside `output`); None means the provider did not report it

    def __post_init__(self) -> None:
        for name in ("input_total", "cache_read", "output"):
            _count(getattr(self, name), name)
        if self.reasoning is not None:
            _count(self.reasoning, "reasoning")
        writes = {str(ttl): _count(n, f"cache write {ttl}") for ttl, n in dict(self.cache_writes).items()}
        object.__setattr__(self, "cache_writes", MappingProxyType(writes))
        if self.reasoning is not None and self.reasoning > self.output:
            raise InvalidUsage("reasoning is part of the billed output, so cannot exceed it")
        if self.cache_read + sum(writes.values()) > self.input_total:
            raise InvalidUsage("cache reads and writes are parts of the prompt, so cannot exceed it")

    @property
    def ordinary_input(self) -> int:
        return self.input_total - self.cache_read - sum(self.cache_writes.values())


@dataclass(frozen=True)
class Priced:
    usd: Decimal
    tier: str


def _per_million(amount: Decimal) -> Decimal:
    return amount.scaleb(-6)  # exact: rates and counts are finite decimals


def cost(price: ModelPrice, usage: Usage) -> Priced:
    tier = price.tier_for(usage.input_total)
    if price.kind == "embedding":
        if usage.cache_read or usage.cache_writes or usage.output or usage.reasoning:
            raise InvalidUsage("an embedding request has input tokens only")
        return Priced(_per_million(usage.input_total * tier.input), tier.name)
    unknown = set(usage.cache_writes) - set(tier.cache_writes)
    if unknown:
        raise UnknownPrice(f"no {price.model} price for cache lifetimes {sorted(unknown)}")
    if usage.cache_read and tier.cache_read is None:
        raise UnknownPrice(f"no {price.model} cache read price")
    if tier.output is None:  # validated for chat prices
        raise UnknownPrice(f"no {price.model} output price")
    amount = (usage.ordinary_input * tier.input + usage.cache_read * (tier.cache_read or Decimal(0))
              + sum((n * tier.cache_writes[ttl] for ttl, n in usage.cache_writes.items()), Decimal(0))
              + usage.output * tier.output)
    return Priced(_per_million(amount), tier.name)


def _cold_input_rate(price: ModelPrice, tier: Tier, cache_mode: str) -> Decimal:
    if cache_mode == "none":
        return tier.input
    rate = tier.cache_writes.get(cache_mode)
    if rate is None:
        raise UnknownPrice(f"no {price.model} price for cache lifetime {cache_mode!r} in tier {tier.name}")
    return max(rate, tier.input)


def worst_case(price: ModelPrice, *, max_input: int, max_output: int = 0, cache_mode: str = "none") -> Decimal:
    _count(max_input, "max_input")
    _count(max_output, "max_output")
    if max_input < 1:
        raise InvalidUsage("a request has at least one input token")
    if price.kind == "embedding":
        if max_output or cache_mode != "none":
            raise InvalidUsage("an embedding request has input tokens only")
        return max(_per_million(max_input * tier.input) for tier in price.tiers_up_to(max_input))
    candidates = []
    for tier in price.tiers_up_to(max_input):
        if tier.output is None:
            raise UnknownPrice(f"no {price.model} output price")
        candidates.append(_per_million(max_input * _cold_input_rate(price, tier, cache_mode)
                                       + max_output * tier.output))
    return max(candidates)
