"""The offline evaluation cost preflight (T10). Pure and offline: it reads no key, calls no provider and never
authorizes paid execution (`authorizes_paid_execution` is the constant False). Runtime reservations stay the
authority.

The manifest declares the upper bounds of one study (its tasks and trials) for each actor:
- the request bounds;
- the maximum **logical** calls per scenario;
- the maximum repairs per logical call (at most 1, PLAN);
- the maximum retries per request.

Each request (the original or a repair) may be retried, so the attempt bound per logical call is
`(1 + max_repairs) x (1 + retries_per_request)`. Each attempt is priced at its worst case (`pricing.worst_case`).

The plan is then checked against every cap:
- per scenario: calls and USD;
- per invocation: the whole manifest, run as one invocation;
- per study: against its ceiling (the manifest's declared finite ceiling, else the server default).

For the study, the persisted spend and **all** holds (active and unresolved) are added when a ledger snapshot is
given. The snapshot's immutable caps (USD and calls) must equal the manifest's ceiling and the configured call cap,
and a study blocked by an overrun is reported as `blocked_by_overrun`, whatever its headroom. Without a snapshot, the
prior spend is reported as unverified, never as zero, and the verdict says so.
"""

from __future__ import annotations

from decimal import Decimal
import hashlib
import json
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from policyops.budget.config import Actor, Caps
from policyops.budget.ledger import Scope
from policyops.budget.pricing import worst_case
from policyops.budget.registry import REGISTRY, Registry
from policyops.persistence.records import exact_usd
from policyops_contracts.base import WireModel


Name = Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")]
TaskId = Annotated[str, StringConstraints(min_length=1, max_length=100)]
Count = Annotated[int, Field(ge=0, le=1000)]


class ChatBound(WireModel):
    kind: Literal["chat"] = "chat"
    actor: Literal["agent", "simulator", "judge", "reranker"]
    model: Name
    effort: Name
    cache_mode: Name = "none"
    max_input: Annotated[int, Field(ge=1)]
    max_output: Annotated[int, Field(ge=1)]
    logical_calls: Count
    max_repairs: Annotated[int, Field(ge=0, le=1)]
    retries_per_request: Annotated[int, Field(ge=0, le=10)]


class EmbeddingBound(WireModel):
    kind: Literal["embedding"] = "embedding"
    actor: Literal["embedding"] = "embedding"
    model: Name
    dimensions: Annotated[int, Field(ge=1)]
    max_request_tokens: Annotated[int, Field(ge=1)]
    max_inputs: Annotated[int, Field(ge=1)]
    logical_calls: Count
    retries_per_request: Annotated[int, Field(ge=0, le=10)]

    @property
    def max_repairs(self) -> int:
        return 0


class Manifest(WireModel):
    v: Literal["policyops.eval-budget-manifest/v1"]
    name: Name
    version: Name
    code_revision: Name
    dataset: Name
    dataset_revision: Name
    split_id: Name
    prompt_revision: Name
    price_revision: Name
    tasks: Annotated[tuple[TaskId, ...], Field(min_length=1, max_length=10_000)]
    trials_per_task: Annotated[int, Field(ge=1, le=1000)]
    study_ceiling_usd: Decimal | None = None
    actors: Annotated[tuple[ChatBound | EmbeddingBound, ...], Field(min_length=1, max_length=5)]

    @model_validator(mode="after")
    def _consistent(self) -> Manifest:
        if len(set(self.tasks)) != len(self.tasks):
            raise ValueError("task IDs must be unique")
        if len({bound.actor for bound in self.actors}) != len(self.actors):
            raise ValueError("each actor is bounded once")
        if self.study_ceiling_usd is not None:
            exact_usd(self.study_ceiling_usd, "study_ceiling_usd")
            if self.study_ceiling_usd <= 0:
                raise ValueError("a study ceiling is positive")
        return self

    def digest(self) -> str:
        body = self.model_dump(mode="json")
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ActorEstimate(WireModel):
    actor: Actor
    model: str
    attempts_per_scenario: int
    usd_per_attempt: Decimal
    usd_per_scenario: Decimal


class Check(WireModel):
    scope: Literal["scenario", "invocation", "study"]
    measure: Literal["calls", "usd"]
    planned: Decimal
    cap: Decimal
    ok: bool


class StudyPosition(WireModel):
    """The study ceiling against the persisted ledger, or `unverified` without a snapshot."""

    ceiling_usd: Decimal
    prior: Literal["ledger_snapshot", "unverified"]
    prior_spent_usd: Decimal | None
    prior_held_usd: Decimal | None
    projected_usd: Decimal | None
    available_usd: Decimal | None
    blocked_by_overrun: bool | None


Verdict = Literal["within_caps", "within_caps_prior_unverified", "exceeds_caps", "blocked_by_overrun"]


class Preflight(WireModel):
    v: Literal["policyops.eval-budget-preflight/v1"] = "policyops.eval-budget-preflight/v1"
    manifest_sha256: str
    price_revision: str
    actors: tuple[ActorEstimate, ...]
    scenarios: int
    scenario_calls: int
    scenario_usd: Decimal
    total_calls: int
    new_study_usd: Decimal
    checks: tuple[Check, ...]
    study: StudyPosition
    verdict: Verdict
    authorizes_paid_execution: Literal[False] = False


class PreflightError(ValueError):
    """The manifest is not consistent with the registry, the price snapshot or the request caps."""


def _attempt_usd(bound: ChatBound | EmbeddingBound, registry: Registry, caps: Caps) -> Decimal:
    if isinstance(bound, ChatBound):  # the registry first: an unlisted model is refused, not merely unpriced
        registry.chat(bound.model, effort=bound.effort, cache_mode=bound.cache_mode)
        price = registry.snapshot.price(bound.model)
        if bound.max_input > caps.request_max_input or bound.max_output > caps.request_max_output:
            raise PreflightError(f"the {bound.actor} bounds exceed the per-request caps")
        return worst_case(price, max_input=bound.max_input, max_output=bound.max_output, cache_mode=bound.cache_mode)
    spec = registry.embedding(bound.model, dimensions=bound.dimensions)
    price = registry.snapshot.price(bound.model)
    if bound.max_request_tokens > spec.request_max_tokens or bound.max_inputs > spec.request_max_inputs:
        raise PreflightError("the embedding bounds exceed the provider's request limits")
    return worst_case(price, max_input=bound.max_request_tokens)


def preflight(manifest: Manifest, caps: Caps, *, registry: Registry = REGISTRY,
              study_snapshot: Scope | None = None) -> Preflight:
    if manifest.price_revision != registry.snapshot.revision:
        raise PreflightError(f"the manifest prices {manifest.price_revision!r}, the registry is "
                             f"{registry.snapshot.revision!r}")
    estimates = []
    for bound in manifest.actors:
        per_attempt = _attempt_usd(bound, registry, caps)
        attempts = bound.logical_calls * (1 + bound.max_repairs) * (1 + bound.retries_per_request)
        estimates.append(ActorEstimate(actor=bound.actor, model=bound.model, attempts_per_scenario=attempts,
                                       usd_per_attempt=per_attempt, usd_per_scenario=attempts * per_attempt))
    scenarios = len(manifest.tasks) * manifest.trials_per_task
    scenario_calls = sum(e.attempts_per_scenario for e in estimates)
    scenario_usd = sum((e.usd_per_scenario for e in estimates), Decimal(0))
    total_calls, new_usd = scenarios * scenario_calls, scenarios * scenario_usd
    ceiling = caps.study_usd if manifest.study_ceiling_usd is None else manifest.study_ceiling_usd

    if study_snapshot is None:
        position = StudyPosition(ceiling_usd=ceiling, prior="unverified", prior_spent_usd=None, prior_held_usd=None,
                                 projected_usd=None, available_usd=None, blocked_by_overrun=None)
        study_usd, prior_calls = new_usd, 0
    else:
        if study_snapshot.kind != "study":
            raise PreflightError("the snapshot is not a study scope")
        if study_snapshot.cap_usd != ceiling:
            raise PreflightError("the persisted study cap differs from the manifest's ceiling")
        if study_snapshot.cap_calls != caps.study_calls:
            raise PreflightError("the persisted study call cap differs from the configured one")
        projected = study_snapshot.spent_usd + study_snapshot.held_usd + new_usd
        position = StudyPosition(ceiling_usd=ceiling, prior="ledger_snapshot",
                                 prior_spent_usd=study_snapshot.spent_usd, prior_held_usd=study_snapshot.held_usd,
                                 projected_usd=projected, available_usd=study_snapshot.available_usd,
                                 blocked_by_overrun=study_snapshot.overrun)
        study_usd = projected
        prior_calls = study_snapshot.calls_consumed + study_snapshot.calls_held

    def check(scope: Literal["scenario", "invocation", "study"], measure: Literal["calls", "usd"],
              planned: Decimal | int, cap: Decimal | int) -> Check:
        return Check(scope=scope, measure=measure, planned=Decimal(planned), cap=Decimal(cap), ok=planned <= cap)

    checks = (check("scenario", "calls", scenario_calls, caps.scenario_calls),
              check("scenario", "usd", scenario_usd, caps.scenario_usd),
              check("invocation", "calls", total_calls, caps.invocation_calls),
              check("invocation", "usd", new_usd, caps.invocation_usd),
              check("study", "calls", prior_calls + total_calls, caps.study_calls),
              check("study", "usd", study_usd, ceiling))
    verdict: Verdict
    if study_snapshot is not None and study_snapshot.overrun:
        verdict = "blocked_by_overrun"  # the ledger refuses every new hold in this study
    elif not all(c.ok for c in checks):
        verdict = "exceeds_caps"
    else:
        verdict = "within_caps_prior_unverified" if study_snapshot is None else "within_caps"
    return Preflight(manifest_sha256=manifest.digest(), price_revision=registry.snapshot.revision,
                     actors=tuple(estimates), scenarios=scenarios, scenario_calls=scenario_calls,
                     scenario_usd=scenario_usd, total_calls=total_calls, new_study_usd=new_usd, checks=checks,
                     study=position, verdict=verdict)
