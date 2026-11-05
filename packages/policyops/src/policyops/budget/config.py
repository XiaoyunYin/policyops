"""Server-owned actor configuration and budget caps (T10).

Defaults follow PLAN §2 and §6.3:
- the agent, user simulator and reranker use Luna with low effort;
- the diagnostic judge uses Haiku with low effort;
- embeddings use text-embedding-3-small at 1536 dimensions.

The caps are:

| Scope | Calls | USD |
|---|---|---|
| Workbench run (all actors, including the simulator, retries, repairs and reranking) | 12 | 0.05 |
| Evaluator scenario (all actors) | | 0.20 |
| Evaluator invocation | | 5 |
| Study (unless a named manifest declares another finite ceiling) | | 5 |

A chat request is capped at 16000 input and 2048 output tokens. Embeddings have their own request bounds instead
(a conservative 8192 tokens and 64 inputs per request, inside the provider's 300000 / 2048 limits). Non-run
operations (future ingestion) get an explicit finite budget, so no fake run is needed.

`BudgetSettings` reads optional overrides from `POLICYOPS_BUDGET_*` environment variables only (no `.env`, no keys).
Every value is validated against the registry and the caps. Nothing here is a browser or run parameter.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from decimal import Decimal
import hashlib
import json
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict

from policyops.budget.prices import ModelPrice
from policyops.budget.pricing import worst_case
from policyops.budget.registry import CACHE_NONE_CONTRACT, REGISTRY, NotAllowed, Registry
from policyops.persistence.records import exact_usd


Actor = Literal["agent", "simulator", "judge", "reranker", "embedding"]
CHAT_ACTORS: tuple[Actor, ...] = ("agent", "simulator", "judge", "reranker")


@dataclass(frozen=True)
class ChatActor:
    actor: Actor
    model: str
    effort: str
    cache_mode: str = "none"
    max_input: int = 16_000
    max_output: int = 2048
    # A counted prompt is admitted only if tokens + max(percent of tokens, minimum) fit max_input (T11 counting).
    count_headroom_percent: int = 10
    count_headroom_min: int = 256

    def __post_init__(self) -> None:
        if self.actor not in CHAT_ACTORS:
            raise ValueError(f"{self.actor!r} is not a chat actor")
        _headroom(self.count_headroom_percent, self.count_headroom_min)


@dataclass(frozen=True)
class EmbeddingActor:
    model: str
    dimensions: int
    max_request_tokens: int
    max_inputs: int
    actor: Actor = "embedding"
    count_headroom_percent: int = 0  # embedding inputs are counted with the model's own tokenizer (T12)
    count_headroom_min: int = 0

    def __post_init__(self) -> None:
        if self.actor != "embedding":
            raise ValueError("only the embedding actor has an embedding configuration")
        _headroom(self.count_headroom_percent, self.count_headroom_min)


ActorConfig = ChatActor | EmbeddingActor


def _headroom(percent: object, minimum: object) -> None:
    for value, what in ((percent, "count_headroom_percent"), (minimum, "count_headroom_min")):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{what} must be a non-negative integer")
    if isinstance(percent, int) and percent > 100:
        raise ValueError("count_headroom_percent is at most 100")


def _positive(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{what} must be a positive integer")
    return value


def _usd(value: Decimal, what: str) -> Decimal:
    if not isinstance(value, Decimal):
        raise ValueError(f"{what} must be a Decimal")
    exact_usd(value, what)
    if value <= 0:
        raise ValueError(f"{what} must be positive")
    return value


@dataclass(frozen=True)
class Caps:
    run_calls: int = 12
    run_usd: Decimal = Decimal("0.05")
    request_max_input: int = 16_000
    request_max_output: int = 2048
    active_seconds: int = 180
    scenario_usd: Decimal = Decimal("0.20")
    invocation_usd: Decimal = Decimal("5")
    study_usd: Decimal = Decimal("5")
    scenario_calls: int = 200
    invocation_calls: int = 20_000
    study_calls: int = 20_000
    operation_calls: int = 64
    operation_usd: Decimal = Decimal("0.05")

    def __post_init__(self) -> None:
        for name in ("run_calls", "request_max_input", "request_max_output", "active_seconds", "scenario_calls",
                     "invocation_calls", "study_calls", "operation_calls"):
            _positive(getattr(self, name), name)
        for name in ("run_usd", "scenario_usd", "invocation_usd", "study_usd", "operation_usd"):
            _usd(getattr(self, name), name)


DEFAULT_ACTORS: Mapping[Actor, ActorConfig] = MappingProxyType({
    "agent": ChatActor("agent", "gpt-6-luna", "low"),
    "simulator": ChatActor("simulator", "gpt-6-luna", "low"),
    "judge": ChatActor("judge", "claude-haiku-5-5", "low"),
    "reranker": ChatActor("reranker", "gpt-6-luna", "low"),
    "embedding": EmbeddingActor("text-embedding-3-small", 1536, max_request_tokens=8192, max_inputs=64),
})


@dataclass(frozen=True)
class Reservation:
    """What one request of an actor may at most cost, and the immutable intent it is reserved under."""

    actor: Actor
    provider: str
    model: str
    price_revision: str
    cache_mode: str
    max_input: int
    max_output: int
    worst_usd: Decimal
    config_sha256: str  # the full actor configuration, including effort, dimensions and the input count


def config_digest(config: ActorConfig, provider: str, price_revision: str) -> str:
    """A canonical digest of the server-owned actor configuration an attempt is reserved under. It is not a
    request fingerprint: the serialized provider request belongs to T11."""
    body = {"v": "policyops.actor-config/v1", "type": type(config).__name__, **asdict(config), "provider": provider,
            "price_revision": price_revision, "cache_none_contract": CACHE_NONE_CONTRACT[provider]}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Configuration:
    registry: Registry = REGISTRY
    actors: Mapping[Actor, ActorConfig] = field(default_factory=lambda: DEFAULT_ACTORS)
    caps: Caps = field(default_factory=Caps)

    def __post_init__(self) -> None:
        actors = dict(self.actors)
        if set(actors) != {"agent", "simulator", "judge", "reranker", "embedding"}:
            raise ValueError("every actor needs exactly one configuration")
        for name, config in actors.items():
            if config.actor != name:
                raise ValueError(f"the {name} configuration names actor {config.actor}")
            if not isinstance(config, EmbeddingActor if name == "embedding" else ChatActor):
                raise ValueError(f"the {name} actor has the wrong configuration type")
            if isinstance(config, ChatActor):
                self.registry.chat(config.model, effort=config.effort, cache_mode=config.cache_mode)
                _positive(config.max_input, "max_input")
                _positive(config.max_output, "max_output")
                if config.max_input > self.caps.request_max_input or config.max_output > self.caps.request_max_output:
                    raise NotAllowed(f"the {name} request limits exceed the per-request caps")
            elif isinstance(config, EmbeddingActor):
                spec = self.registry.embedding(config.model, dimensions=config.dimensions)
                _positive(config.max_request_tokens, "max_request_tokens")
                _positive(config.max_inputs, "max_inputs")
                if (config.max_request_tokens > spec.request_max_tokens
                        or config.max_inputs > spec.request_max_inputs):
                    raise NotAllowed("the embedding request limits exceed the provider's request limits")
            else:
                raise ValueError(f"{name} has an unknown configuration type")
        object.__setattr__(self, "actors", MappingProxyType(actors))

    def price(self, actor: Actor) -> ModelPrice:
        return self.registry.snapshot.price(self.actors[actor].model)

    def reservation(self, actor: Actor) -> Reservation:
        config = self.actors[actor]
        price = self.price(actor)
        revision = self.registry.snapshot.revision
        digest = config_digest(config, price.provider, revision)
        if isinstance(config, ChatActor):
            worst = worst_case(price, max_input=config.max_input, max_output=config.max_output,
                               cache_mode=config.cache_mode)
            return Reservation(actor, price.provider, config.model, revision, config.cache_mode, config.max_input,
                               config.max_output, worst, digest)
        return Reservation(actor, price.provider, config.model, revision, "none", config.max_request_tokens, 0,
                           worst_case(price, max_input=config.max_request_tokens), digest)


Name = Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r"^[a-z0-9][a-z0-9._-]*$")]


class BudgetSettings(BaseSettings):
    """Optional `POLICYOPS_BUDGET_*` overrides; anything not set keeps the PLAN default."""

    model_config = SettingsConfigDict(env_prefix="POLICYOPS_BUDGET_", env_file=None, extra="forbid", frozen=True,
                                      hide_input_in_errors=True)

    # None means unset (keep the default); a value that is present, even empty, must itself be valid.
    agent_model: Name | None = None
    agent_effort: Name | None = None
    simulator_model: Name | None = None
    simulator_effort: Name | None = None
    judge_model: Name | None = None
    judge_effort: Name | None = None
    reranker_model: Name | None = None
    reranker_effort: Name | None = None
    run_calls: int | None = None
    run_usd: Decimal | None = None
    scenario_usd: Decimal | None = None
    invocation_usd: Decimal | None = None
    study_usd: Decimal | None = None

    def configuration(self, registry: Registry = REGISTRY) -> Configuration:
        actors: dict[Actor, ActorConfig] = dict(DEFAULT_ACTORS)
        for actor in CHAT_ACTORS:
            base = actors[actor]
            if not isinstance(base, ChatActor):
                raise TypeError(f"the {actor} default is not a chat configuration")
            model, effort = getattr(self, f"{actor}_model"), getattr(self, f"{actor}_effort")
            actors[actor] = replace(base, model=base.model if model is None else model,
                                    effort=base.effort if effort is None else effort)
        overrides = {name: getattr(self, name) for name in ("run_calls", "run_usd", "scenario_usd", "invocation_usd",
                                                            "study_usd") if getattr(self, name) is not None}
        return Configuration(registry=registry, actors=actors, caps=replace(Caps(), **overrides))
