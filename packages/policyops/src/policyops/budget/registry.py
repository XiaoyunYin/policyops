"""The immutable allowed-model registry (T10): which models, efforts, cache modes and request bounds may be used.

There is no fallback: a model, effort or cache mode that is not listed is refused before anything is reserved, and
nothing defaults to a flagship or a deprecated model. Chat bounds (effort, output, cache) do not apply to the
embedding model, which has its own request limits from the provider's primary documentation (checked 2026-11-05:
at most 8192 tokens per input, 300000 tokens and 2048 inputs per request, no empty input). Every construction path
copies, freezes and validates.

A chat actor's cache mode `"none"` is reserved as ordinary input only. That is valid only if the later request
serializer (T11) really disables caching, which `CACHE_NONE_CONTRACT` records per provider. For OpenAI, omitting the
cache options does **not** disable caching (implicit caching writes at the 30m lifetime). The serializer must send
`prompt_cache_options.mode = "explicit"` with no breakpoints, or else reserve as a permitted cold write. The contract
is part of every actor configuration digest, so changing it changes the attempt identity.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from policyops.budget.prices import SNAPSHOT_2026_11_05, SNAPSHOT_2026_11_15, PriceSnapshot


CACHE_NONE_CONTRACT: Mapping[str, str] = MappingProxyType({
    # https://developers.openai.com/api/docs/guides/prompt-caching (checked 2026-11-05 by the reviewer)
    "openai": "prompt_cache_options.mode=explicit; no breakpoints; omission means implicit 30m writes",
    # To be confirmed against the primary documentation by the T11 serializer before any request is sent.
    "anthropic": "no cache_control markers (request-level or per block); unverified until T11",
    "bedrock": "no cache_control markers; text-only InvokeModel via US profile from us-west-2",
})


def bedrock_model_refusal(model: str) -> str:
    """Value-free refusals for AWS IDs and their registry-qualified forms."""
    identifier = model.removeprefix("bedrock:")
    if identifier.startswith("global."):
        return "bedrock.global_profile_unsupported"
    if identifier in {"anthropic.claude-haiku-5-5", "claude-haiku-5-5"}:
        return "bedrock.on_demand_unsupported"
    return "bedrock.model_unsupported"


class NotAllowed(ValueError):
    """The model, or a parameter of it, is not in the registry."""


@dataclass(frozen=True)
class ChatModel:
    model: str
    efforts: frozenset[str]
    cache_modes: frozenset[str]  # "none" plus lifetimes the price snapshot prices

    def __post_init__(self) -> None:
        object.__setattr__(self, "efforts", frozenset(self.efforts))
        object.__setattr__(self, "cache_modes", frozenset(self.cache_modes))
        if not self.efforts or "none" not in self.cache_modes:
            raise ValueError("a chat model needs efforts and the 'none' cache mode")


@dataclass(frozen=True)
class EmbeddingModel:
    model: str
    dimensions: frozenset[int]
    per_input_max_tokens: int
    request_max_tokens: int
    request_max_inputs: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "dimensions", frozenset(self.dimensions))
        if not self.dimensions or min(self.per_input_max_tokens, self.request_max_tokens, self.request_max_inputs) < 1:
            raise ValueError("embedding limits must be positive")


ModelSpec = ChatModel | EmbeddingModel


@dataclass(frozen=True)
class Registry:
    snapshot: PriceSnapshot
    models: Mapping[str, ModelSpec]

    def __post_init__(self) -> None:
        listed = dict(self.models)
        for key, spec in listed.items():
            if not isinstance(spec, ChatModel | EmbeddingModel) or key != spec.model:
                raise ValueError("each model must be keyed by its own ID")
            price = self.snapshot.price(spec.model)  # every allowed model is priced
            if isinstance(spec, ChatModel):
                if price.kind != "chat":
                    raise ValueError(f"{spec.model} is priced as {price.kind}")
                priced = set().union(*(tier.cache_writes for tier in price.tiers))
                if not spec.cache_modes - {"none"} <= priced:
                    raise ValueError(f"{spec.model} allows unpriced cache modes")
            elif price.kind != "embedding":
                raise ValueError(f"{spec.model} is priced as {price.kind}")
        object.__setattr__(self, "models", MappingProxyType(listed))

    def chat(self, model: str, *, effort: str, cache_mode: str) -> ChatModel:
        spec = self.models.get(model)
        if not isinstance(spec, ChatModel):
            if model.startswith(("bedrock:", "global.", "anthropic.", "us.")):
                raise NotAllowed(bedrock_model_refusal(model))
            raise NotAllowed(f"{model!r} is not an allowed chat model")
        if effort not in spec.efforts:
            raise NotAllowed(f"effort {effort!r} is not allowed for {model}")
        if cache_mode not in spec.cache_modes:
            raise NotAllowed(f"cache mode {cache_mode!r} is not allowed for {model}")
        return spec

    def embedding(self, model: str, *, dimensions: int) -> EmbeddingModel:
        spec = self.models.get(model)
        if not isinstance(spec, EmbeddingModel):
            raise NotAllowed(f"{model!r} is not an allowed embedding model")
        if dimensions not in spec.dimensions:
            raise NotAllowed(f"{dimensions} dimensions are not allowed for {model}")
        return spec


REGISTRY = Registry(SNAPSHOT_2026_11_05, {
    # E03 compares low effort with none where supported; Luna is the initial agent, simulator and reranker.
    "gpt-6-luna": ChatModel("gpt-6-luna", frozenset({"low", "none"}), frozenset({"none", "30m", "12h"})),
    # The required comparison and independent diagnostic judge, always with explicit low effort.
    "claude-haiku-5-5": ChatModel("claude-haiku-5-5", frozenset({"low"}), frozenset({"none", "5m", "1h"})),
    "text-embedding-3-small": EmbeddingModel("text-embedding-3-small", frozenset({1536}), per_input_max_tokens=8192,
                                             request_max_tokens=300_000, request_max_inputs=2048),
})

BEDROCK_REGISTRY = Registry(SNAPSHOT_2026_11_15, {
    **REGISTRY.models,
    "bedrock:us.anthropic.claude-haiku-5-5": ChatModel(
        "bedrock:us.anthropic.claude-haiku-5-5", frozenset({"low"}), frozenset({"none"})),
})
