"""The immutable, dated price snapshot (T10).

Standard first-party text-token rates in USD per 1,000,000 tokens, read from the public pricing and model pages
listed in `SOURCES` on the checked date. They are dated evidence, not a claim about any account's access or invoices.
A request is priced by the tier its **whole prompt** falls in (cache reads and writes included):

- Haiku 5.5: at most 100000 prompt tokens is the short tier, above it the long tier.
- Luna: at most 272000 is the short tier, above it the long tier. "More than 272K input tokens" is interpreted as
  decimal 272000. The long rates are the documented multipliers (input and cache x2, output x1.5) written out.

Cache writes are priced per lifetime (OpenAI 30m/12h, Anthropic 5m/1h); they are total write rates, not surcharges
on top of ordinary input. Every construction path copies, freezes and validates its mappings.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
import re
from types import MappingProxyType
from typing import Literal


Provider = Literal["openai", "anthropic"]
ModelKind = Literal["chat", "embedding"]
CACHE_TTLS: Mapping[str, frozenset[str]] = MappingProxyType({
    "openai": frozenset({"30m", "12h"}), "anthropic": frozenset({"5m", "1h"})})
REVISION = re.compile(r"[a-z][a-z0-9_.-]{0,99}")


class UnknownPrice(ValueError):
    """No price is known for this model, tier or cache mode; nothing may be reserved or dispatched."""


def _rate(value: Decimal | str, what: str) -> Decimal:
    rate = Decimal(value) if isinstance(value, str) else value
    if not isinstance(rate, Decimal) or not rate.is_finite() or rate < 0:
        raise ValueError(f"{what} must be a finite non-negative Decimal")
    return rate


@dataclass(frozen=True)
class Tier:
    name: str
    max_prompt_tokens: int | None  # inclusive upper bound of the whole prompt; None: unbounded (the last tier)
    input: Decimal
    output: Decimal | None = None
    cache_read: Decimal | None = None
    cache_writes: Mapping[str, Decimal] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_prompt_tokens is not None and (isinstance(self.max_prompt_tokens, bool)
                                                   or self.max_prompt_tokens < 1):
            raise ValueError("a tier bound is a positive token count")
        object.__setattr__(self, "input", _rate(self.input, "input"))
        if self.output is not None:
            object.__setattr__(self, "output", _rate(self.output, "output"))
        if self.cache_read is not None:
            object.__setattr__(self, "cache_read", _rate(self.cache_read, "cache_read"))
        object.__setattr__(self, "cache_writes", MappingProxyType(
            {str(ttl): _rate(rate, f"cache write {ttl}") for ttl, rate in dict(self.cache_writes).items()}))


@dataclass(frozen=True)
class ModelPrice:
    model: str
    provider: Provider
    kind: ModelKind
    tiers: tuple[Tier, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "tiers", tuple(self.tiers))
        if not self.tiers or self.tiers[-1].max_prompt_tokens is not None:
            raise ValueError("tiers must end with an unbounded tier")
        bounds = [tier.max_prompt_tokens for tier in self.tiers[:-1]]
        if any(b is None for b in bounds):
            raise ValueError("only the last tier may be unbounded")
        known = [b for b in bounds if b is not None]
        if known != sorted(known) or len(set(known)) != len(known):
            raise ValueError("tier bounds must be strictly increasing")
        for tier in self.tiers:
            if self.kind == "embedding" and (tier.output is not None or tier.cache_read is not None
                                             or tier.cache_writes):
                raise ValueError("an embedding price has input tokens only")
            if self.kind == "chat" and tier.output is None:
                raise ValueError("a chat price needs an output rate")
            if not set(tier.cache_writes) <= CACHE_TTLS[self.provider]:
                raise ValueError(f"cache lifetimes {sorted(tier.cache_writes)} are not {self.provider}'s")

    def tier_for(self, prompt_tokens: int) -> Tier:
        return next(tier for tier in self.tiers
                    if tier.max_prompt_tokens is None or prompt_tokens <= tier.max_prompt_tokens)

    def tiers_up_to(self, prompt_tokens: int) -> tuple[Tier, ...]:
        """Every tier a prompt of at most `prompt_tokens` can fall in."""
        reachable = []
        for tier in self.tiers:
            reachable.append(tier)
            if tier.max_prompt_tokens is None or prompt_tokens <= tier.max_prompt_tokens:
                break
        return tuple(reachable)


@dataclass(frozen=True)
class PriceSnapshot:
    revision: str
    checked_utc: str
    sources: tuple[str, ...]
    models: Mapping[str, ModelPrice]

    def __post_init__(self) -> None:
        if not REVISION.fullmatch(self.revision):
            raise ValueError("a price revision is a slug")
        snapshot = dict(self.models)
        if any(not isinstance(price, ModelPrice) or key != price.model for key, price in snapshot.items()):
            raise ValueError("each price must be keyed by its own model ID")
        object.__setattr__(self, "sources", tuple(self.sources))
        object.__setattr__(self, "models", MappingProxyType(snapshot))

    def price(self, model: str) -> ModelPrice:
        found = self.models.get(model)
        if found is None:
            raise UnknownPrice(f"no price for model {model!r} in {self.revision}")
        return found


SOURCES = (
    "https://developers.openai.com/api/docs/models/gpt-6-luna",
    "https://developers.openai.com/api/docs/pricing",
    "https://developers.openai.com/api/docs/guides/prompt-caching",
    "https://developers.openai.com/api/docs/models/text-embedding-3-small",
    "https://platform.claude.com/docs/en/models/haiku-5-5/overview",
    "https://platform.claude.com/docs/en/about-claude/pricing",
)

SNAPSHOT_2026_11_05 = PriceSnapshot(
    revision="pricing.2026-11-05.v1", checked_utc="2026-11-05T03:16:05Z", sources=SOURCES, models={
        "gpt-6-luna": ModelPrice("gpt-6-luna", "openai", "chat", (
            Tier("short", 272_000, Decimal("0.10"), Decimal("0.50"), Decimal("0.01"),
                 {"30m": Decimal("0.125"), "12h": Decimal("0.25")}),
            Tier("long", None, Decimal("0.20"), Decimal("0.75"), Decimal("0.02"),
                 {"30m": Decimal("0.25"), "12h": Decimal("0.50")}))),
        "claude-haiku-5-5": ModelPrice("claude-haiku-5-5", "anthropic", "chat", (
            Tier("short", 100_000, Decimal("0.10"), Decimal("0.50"), Decimal("0.01"),
                 {"5m": Decimal("0.125"), "1h": Decimal("0.20")}),
            Tier("long", None, Decimal("0.50"), Decimal("2.50"), Decimal("0.05"),
                 {"5m": Decimal("0.625"), "1h": Decimal("1")}))),
        "text-embedding-3-small": ModelPrice("text-embedding-3-small", "openai", "embedding", (
            Tier("standard", None, Decimal("0.02")),)),
    })
