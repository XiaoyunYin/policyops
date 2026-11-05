"""The T10 price snapshot, exact cost calculator, model registry, actor configuration and offline preflight.

The pricing cases are the dated rates worked by hand (whole-prompt tiers, disjoint cache parts, reasoning inside
the billed output); they do not depend on the implementation's tables.
"""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import json
from typing import Any, cast
from uuid import uuid4

from pydantic import ValidationError
import pytest

from policyops.budget.config import (
    DEFAULT_ACTORS,
    BudgetSettings,
    Caps,
    ChatActor,
    Configuration,
    EmbeddingActor,
    config_digest,
)
from policyops.budget.ledger import Intent, Ledger, OperationBinding, Scope, ScopeRef, Settlement, lock_order
from policyops.budget.preflight import Manifest, PreflightError, preflight
from policyops.budget.prices import SNAPSHOT_2026_11_05, ModelPrice, PriceSnapshot, Tier, UnknownPrice
from policyops.budget.pricing import InvalidUsage, Usage, cost, worst_case
from policyops.budget.registry import REGISTRY, ChatModel, NotAllowed, Registry


def price(model: str) -> ModelPrice:
    return SNAPSHOT_2026_11_05.price(model)


# (id, model, usage, expected USD, tier)
CASES: list[tuple[str, str, Usage, str, str]] = [
    ("luna-normal-workbench", "gpt-6-luna", Usage(16000, output=2048), "0.002624", "short"),
    ("luna-cold-30m", "gpt-6-luna", Usage(16000, cache_writes={"30m": 16000}, output=2048), "0.003024", "short"),
    ("luna-cold-12h", "gpt-6-luna", Usage(16000, cache_writes={"12h": 16000}, output=2048), "0.005024", "short"),
    ("luna-disjoint-cache-components", "gpt-6-luna",
     Usage(16000, cache_read=8000, cache_writes={"30m": 4000}, output=2048, reasoning=1024), "0.002004", "short"),
    ("haiku-mixed-ttl", "claude-haiku-5-5",
     Usage(16000, cache_read=8000, cache_writes={"5m": 2000, "1h": 2000}, output=2048), "0.002154", "short"),
    ("haiku-exact-short-boundary", "claude-haiku-5-5", Usage(100000), "0.01", "short"),
    ("haiku-next-token-whole-request-tier", "claude-haiku-5-5", Usage(100001), "0.0500005", "long"),
    ("haiku-cached-input-still-selects-tier", "claude-haiku-5-5", Usage(100001, cache_read=100000, output=1),
     "0.005003", "long"),
    ("luna-interpreted-exact-short-boundary", "gpt-6-luna", Usage(272000), "0.0272", "short"),
    ("luna-next-token-whole-request-tier", "gpt-6-luna", Usage(272001, output=1), "0.05440095", "long"),
    ("embedding-sub-micro-dollar", "text-embedding-3-small", Usage(1), "0.00000002", "standard"),
    ("luna-read-sub-micro-dollar", "gpt-6-luna", Usage(1, cache_read=1), "0.00000001", "short"),
]


@pytest.mark.parametrize(("case_id", "model", "usage", "expected", "tier"), CASES, ids=[c[0] for c in CASES])
def test_cost_is_exact_at_the_whole_prompt_tier(case_id: str, model: str, usage: Usage, expected: str,
                                                tier: str) -> None:
    priced = cost(price(model), usage)
    assert (priced.usd, priced.tier) == (Decimal(expected), tier), case_id
    assert isinstance(priced.usd, Decimal)


@pytest.mark.parametrize("make", [
    lambda: Usage(-1),
    lambda: Usage(True),
    lambda: Usage(10.0),  # type: ignore[arg-type]
    lambda: Usage(10, output=5, reasoning=6),  # reasoning is part of the billed output
    lambda: Usage(10, cache_read=6, cache_writes={"30m": 5}),  # cache parts larger than the prompt
    lambda: Usage(10, cache_writes={"30m": -1}),
])
def test_contradictory_usage_is_refused(make: Any) -> None:
    with pytest.raises(InvalidUsage):
        make()


def test_unpriced_cache_lifetimes_and_embedding_extras_are_refused() -> None:
    with pytest.raises(UnknownPrice):  # an Anthropic lifetime on an OpenAI model
        cost(price("gpt-6-luna"), Usage(100, cache_writes={"5m": 10}))
    with pytest.raises(InvalidUsage):
        cost(price("text-embedding-3-small"), Usage(100, output=1))
    with pytest.raises(InvalidUsage):
        cost(price("text-embedding-3-small"), Usage(100, cache_read=1))
    with pytest.raises(UnknownPrice):
        SNAPSHOT_2026_11_05.price("gpt-unknown")


def test_worst_case_is_cold_at_the_highest_reachable_tier() -> None:
    luna = price("gpt-6-luna")
    assert worst_case(luna, max_input=16000, max_output=2048) == Decimal("0.002624")
    assert worst_case(luna, max_input=16000, max_output=2048, cache_mode="12h") == Decimal("0.005024")
    # A bound past the short tier is priced at the long tier for the whole prompt.
    assert worst_case(luna, max_input=272001, max_output=1) == Decimal("0.05440095")
    assert worst_case(price("claude-haiku-5-5"), max_input=800, max_output=200, cache_mode="5m") == Decimal("0.0002")
    assert worst_case(price("text-embedding-3-small"), max_input=8192) == Decimal("0.00016384")
    with pytest.raises(UnknownPrice):
        worst_case(luna, max_input=10, cache_mode="1h")
    with pytest.raises(InvalidUsage):
        worst_case(luna, max_input=0)
    with pytest.raises(InvalidUsage):
        worst_case(price("text-embedding-3-small"), max_input=10, max_output=1)


def test_snapshot_and_usage_copy_and_freeze_their_mappings() -> None:
    writes = {"30m": 10}
    usage = Usage(100, cache_writes=writes)
    writes["30m"] = 1000
    assert usage.cache_writes == {"30m": 10}
    with pytest.raises(TypeError):
        usage.cache_writes["30m"] = 5  # type: ignore[index]
    rates = {"30m": Decimal("0.125")}
    tier = Tier("only", None, Decimal("0.10"), Decimal("0.50"), Decimal("0.01"), rates)
    rates["30m"] = Decimal("0")
    assert tier.cache_writes["30m"] == Decimal("0.125")
    models = {"m": ModelPrice("m", "openai", "chat", (tier,))}
    snapshot = PriceSnapshot("pricing.test.v1", "2026-11-05T00:00:00Z", ("https://example.invalid",), models)
    models.clear()
    assert set(snapshot.models) == {"m"}
    with pytest.raises(TypeError):
        snapshot.models["x"] = models  # type: ignore[index]


@pytest.mark.parametrize("make", [
    lambda: Tier("bad", None, 0.1),  # type: ignore[arg-type]  # a float rate
    lambda: Tier("bad", None, Decimal("NaN")),
    lambda: Tier("bad", None, Decimal("-1")),
    lambda: ModelPrice("m", "openai", "chat", (Tier("t", 10, Decimal(1), Decimal(1)),)),  # no unbounded tier
    lambda: ModelPrice("m", "openai", "chat", (Tier("t", None, Decimal(1)),)),  # chat without output
    lambda: ModelPrice("m", "openai", "chat", (Tier("t", None, Decimal(1), Decimal(1), None, {"5m": Decimal(1)}),)),
    lambda: ModelPrice("m", "openai", "embedding", (Tier("t", None, Decimal(1), Decimal(1)),)),
    lambda: PriceSnapshot("Bad Revision", "x", (), {}),
    lambda: PriceSnapshot("pricing.x", "x", (), {"a": SNAPSHOT_2026_11_05.price("gpt-6-luna")}),  # wrong key
])
def test_invalid_prices_are_refused(make: Any) -> None:
    with pytest.raises(ValueError):  # each construction names its own reason
        make()


def test_registry_refuses_unlisted_models_efforts_and_cache_modes() -> None:
    assert REGISTRY.chat("gpt-6-luna", effort="none", cache_mode="30m").model == "gpt-6-luna"
    for call in (lambda: REGISTRY.chat("gpt-6-flagship", effort="low", cache_mode="none"),
                 lambda: REGISTRY.chat("claude-haiku-5-5", effort="high", cache_mode="none"),
                 lambda: REGISTRY.chat("claude-haiku-5-5", effort="low", cache_mode="30m"),
                 lambda: REGISTRY.chat("text-embedding-3-small", effort="low", cache_mode="none"),
                 lambda: REGISTRY.embedding("text-embedding-3-small", dimensions=512),
                 lambda: REGISTRY.embedding("gpt-6-luna", dimensions=1536)):
        with pytest.raises(NotAllowed):
            call()
    spec = REGISTRY.embedding("text-embedding-3-small", dimensions=1536)
    assert (spec.per_input_max_tokens, spec.request_max_tokens, spec.request_max_inputs) == (8192, 300_000, 2048)
    with pytest.raises(ValueError, match="unpriced cache modes"):
        Registry(SNAPSHOT_2026_11_05, {"gpt-6-luna": ChatModel("gpt-6-luna", frozenset({"low"}),
                                                               frozenset({"none", "5m"}))})
    with pytest.raises(UnknownPrice):
        Registry(SNAPSHOT_2026_11_05, {"gpt-x": ChatModel("gpt-x", frozenset({"low"}), frozenset({"none"}))})


def test_default_configuration_and_reservations() -> None:
    configuration = Configuration()
    caps = configuration.caps
    assert (caps.run_calls, caps.run_usd, caps.request_max_input, caps.request_max_output, caps.active_seconds) == (
        12, Decimal("0.05"), 16000, 2048, 180)
    assert (caps.scenario_usd, caps.invocation_usd, caps.study_usd) == (Decimal("0.20"), Decimal(5), Decimal(5))
    agent = configuration.reservation("agent")
    assert (agent.model, agent.provider, agent.worst_usd, agent.price_revision) == (
        "gpt-6-luna", "openai", Decimal("0.002624"), "pricing.2026-11-05.v1")
    assert configuration.reservation("judge").model == "claude-haiku-5-5"
    embedding = configuration.reservation("embedding")
    assert (embedding.worst_usd, embedding.max_input, embedding.max_output, embedding.cache_mode) == (
        Decimal("0.00016384"), 8192, 0, "none")


def test_actor_roles_and_configuration_types_must_pair() -> None:
    with pytest.raises(ValueError, match="not a chat actor"):
        ChatActor("embedding", "gpt-6-luna", "low")
    with pytest.raises(ValueError, match="only the embedding actor"):
        EmbeddingActor("text-embedding-3-small", 1536, 8192, 64, actor="agent")
    luna = DEFAULT_ACTORS["agent"]
    with pytest.raises(ValueError, match="names actor"):
        Configuration(actors={**DEFAULT_ACTORS, "simulator": luna})
    with pytest.raises(ValueError, match="every actor"):
        Configuration(actors={k: v for k, v in DEFAULT_ACTORS.items() if k != "judge"})
    with pytest.raises(NotAllowed):  # per-request caps bind every chat actor
        Configuration(actors={**DEFAULT_ACTORS, "agent": ChatActor("agent", "gpt-6-luna", "low", max_input=16001)})
    with pytest.raises(NotAllowed):
        Configuration(actors={**DEFAULT_ACTORS,
                              "embedding": EmbeddingActor("text-embedding-3-small", 1536, 300_001, 64)})
    source = dict(DEFAULT_ACTORS)
    configuration = Configuration(actors=source)
    source["agent"] = ChatActor("agent", "claude-haiku-5-5", "low")
    assert configuration.actors["agent"].model == "gpt-6-luna"  # copied on construction
    with pytest.raises(TypeError):
        configuration.actors["agent"] = luna  # type: ignore[index]


def test_the_actor_configuration_digest_binds_every_field() -> None:
    base = ChatActor("agent", "gpt-6-luna", "low")
    digests = {config_digest(config, "openai", "pricing.2026-11-05.v1") for config in (
        base, replace(base, effort="none"), replace(base, max_input=8000), replace(base, max_output=1024),
        replace(base, cache_mode="30m"))}
    assert len(digests) == 5
    embedding = EmbeddingActor("text-embedding-3-small", 1536, 8192, 64)
    assert config_digest(embedding, "openai", "r") != config_digest(replace(embedding, max_inputs=32), "openai", "r")
    # An effort change prices the same but is still a different intent.
    plain = Configuration().reservation("agent")
    none = Configuration(actors={**DEFAULT_ACTORS, "agent": replace(base, effort="none")}).reservation("agent")
    assert plain.worst_usd == none.worst_usd and plain.config_sha256 != none.config_sha256


def intent(**changes: Any) -> Intent:
    r = Configuration().reservation("agent")
    values: dict[str, Any] = {"actor": r.actor, "provider": r.provider, "model": r.model,
                              "price_revision": r.price_revision,
              "config_sha256": r.config_sha256, "cache_mode": r.cache_mode, "max_input": r.max_input,
              "max_output": r.max_output, "operation_id": "op-1", "reserved_usd": r.worst_usd,
              "scope_ids": (uuid4(),)} | changes
    return Intent(**values)


def test_intent_and_settlement_digests() -> None:
    first = intent()
    assert first.digest() == replace(first, reserved_usd=Decimal("0.0026240")).digest()  # the same amount
    for change in ({"operation_id": "op-2"}, {"config_sha256": "0" * 64}, {"max_output": 1},
                   {"scope_ids": (uuid4(),)}, {"reserved_usd": Decimal("0.002625")}):
        assert replace(first, **change).digest() != first.digest(), change
    usage = Usage(10, output=2)
    assert Settlement(usage, "req-1").digest() == Settlement(Usage(10, output=2), "req-1").digest()
    assert Settlement(usage, "req-1").digest() != Settlement(usage, "req-2").digest()
    assert Settlement(usage).digest() != Settlement(Usage(10, output=3)).digest()
    with pytest.raises(ValueError, match="provider request"):
        Settlement(usage, "")


def test_one_price_revision_names_one_price_table() -> None:
    current = SNAPSHOT_2026_11_05
    assert Ledger(cast(Any, None), Configuration(), (current,)).snapshots[current.revision] is current
    cheaper = PriceSnapshot(current.revision, current.checked_utc, current.sources,
                            {"gpt-6-luna": ModelPrice("gpt-6-luna", "openai", "chat", (
                                Tier("short", None, Decimal("0.01"), Decimal("0.01")),))})
    older = replace(cheaper, revision="pricing.2026-01-01.v1")
    for earlier in ((cheaper,), (older, replace(older, sources=("https://example.invalid",)))):
        with pytest.raises(ValueError, match="different prices"):
            Ledger(cast(Any, None), Configuration(), earlier)
    assert set(Ledger(cast(Any, None), Configuration(), (older, older)).snapshots) == {older.revision,
                                                                                     current.revision}


def test_scope_lock_order_is_kind_rank_then_id() -> None:
    a, b = sorted((uuid4(), uuid4()), key=str)
    refs = [ScopeRef.of("scenario", a), ScopeRef.of("invocation", b), ScopeRef.of("study", b),
            ScopeRef.of("scenario", a)]
    assert [(r.kind, r.id) for r in lock_order(refs)] == [("study", b), ("invocation", b), ("scenario", a)]
    with pytest.raises(ValueError, match="slug"):
        OperationBinding("Bad Kind", "k")
    with pytest.raises(ValueError, match="1-200"):
        OperationBinding("ingestion", "")


def test_settings_overrides_are_validated_and_none_means_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    assert BudgetSettings().configuration().actors["agent"].model == "gpt-6-luna"
    monkeypatch.setenv("POLICYOPS_BUDGET_AGENT_EFFORT", "none")
    monkeypatch.setenv("POLICYOPS_BUDGET_RUN_USD", "0.04")
    configuration = BudgetSettings().configuration()
    assert configuration.actors["agent"] == ChatActor("agent", "gpt-6-luna", "none")
    assert configuration.caps.run_usd == Decimal("0.04")
    for name, value in (("POLICYOPS_BUDGET_AGENT_MODEL", ""), ("POLICYOPS_BUDGET_JUDGE_EFFORT", ""),
                        ("POLICYOPS_BUDGET_RUN_CALLS", "1.5")):
        monkeypatch.setenv(name, value)
        with pytest.raises(ValidationError):
            BudgetSettings()
        monkeypatch.delenv(name)
    for name, value in (("POLICYOPS_BUDGET_JUDGE_MODEL", "gpt-6-flagship"),
                        ("POLICYOPS_BUDGET_JUDGE_EFFORT", "high")):
        monkeypatch.setenv(name, value)
        with pytest.raises(NotAllowed):
            BudgetSettings().configuration()
        monkeypatch.delenv(name)
    for value in ("NaN", "-1", "0", "0.0000000000000000001"):
        monkeypatch.setenv("POLICYOPS_BUDGET_RUN_USD", value)
        with pytest.raises((ValueError, ValidationError)):
            BudgetSettings().configuration()


# -- preflight ---------------------------------------------------------------------------------------------------

def manifest(**changes: Any) -> Manifest:
    """Two tasks x four trials; agent: 3 logical calls, 1 repair, 2 retries per request, cold 500 in / 1000 out at
    30m; judge: 1 logical call, 1 retry, 800 in / 200 out at 5m."""
    body: dict[str, Any] = {
        "v": "policyops.eval-budget-manifest/v1", "name": "fixture-study", "version": "1", "code_revision": "abc",
        "dataset": "fixture", "dataset_revision": "r1", "split_id": "dev", "prompt_revision": "p1",
        "price_revision": "pricing.2026-11-05.v1", "tasks": ["t0", "t1"], "trials_per_task": 4,
        "actors": [
            {"kind": "chat", "actor": "agent", "model": "gpt-6-luna", "effort": "low", "cache_mode": "30m",
             "max_input": 500, "max_output": 1000, "logical_calls": 3, "max_repairs": 1, "retries_per_request": 2},
            {"kind": "chat", "actor": "judge", "model": "claude-haiku-5-5", "effort": "low", "cache_mode": "5m",
             "max_input": 800, "max_output": 200, "logical_calls": 1, "max_repairs": 0, "retries_per_request": 1},
        ]} | changes
    return Manifest.model_validate_json(json.dumps(body, default=str))  # manifests arrive as JSON


def study(spent: str, held: str, cap: str = "5", *, cap_calls: int = 20_000, overrun: bool = False) -> Scope:
    return Scope(uuid4(), "study", Decimal(cap), cap_calls, Decimal(spent), Decimal(held), 0, 0, overrun)


def test_preflight_multiplies_repairs_and_retries_and_never_authorizes() -> None:
    result = preflight(manifest(), Caps())
    agent, judge = result.actors
    # (1 + repairs) x (1 + retries) per logical call, not 1 + repairs + retries (which would give 12).
    assert (agent.attempts_per_scenario, judge.attempts_per_scenario) == (18, 2)
    assert (agent.usd_per_attempt, judge.usd_per_attempt) == (Decimal("0.0005625"), Decimal("0.0002"))
    assert (result.scenarios, result.scenario_calls, result.scenario_usd) == (8, 20, Decimal("0.010525"))
    assert (result.total_calls, result.new_study_usd) == (160, Decimal("0.0842"))
    assert result.study.prior == "unverified" and result.study.projected_usd is None  # never a claimed zero
    assert result.verdict == "within_caps_prior_unverified"
    assert result.authorizes_paid_execution is False
    assert len(result.manifest_sha256) == 64 and result.manifest_sha256 == manifest().digest()


def test_preflight_counts_all_holds_against_the_study() -> None:
    caps = Caps()
    refused = preflight(manifest(), caps, study_snapshot=study("4.70", "0.22"))
    assert refused.study.projected_usd == Decimal("5.0042") and refused.verdict == "exceeds_caps"
    assert [(c.scope, c.measure) for c in refused.checks if not c.ok] == [("study", "usd")]
    assert refused.authorizes_paid_execution is False
    # Ignoring the 0.22 of active and unresolved holds would wrongly fit.
    fits = preflight(manifest(), caps, study_snapshot=study("4.70", "0"))
    assert fits.verdict == "within_caps" and fits.study.available_usd == Decimal("0.30")
    with pytest.raises(PreflightError, match="cap differs"):
        preflight(manifest(), caps, study_snapshot=study("0", "0", cap="6"))
    declared = preflight(manifest(study_ceiling_usd=Decimal("6")), caps, study_snapshot=study("4.70", "0.22", "6"))
    assert declared.verdict == "within_caps"
    with pytest.raises(PreflightError, match="call cap differs"):  # a tighter persisted call cap is not ignored
        preflight(manifest(), caps, study_snapshot=study("0", "0", cap_calls=100))
    # A sticky overrun blocks the study whatever its headroom.
    blocked = preflight(manifest(), caps, study_snapshot=study("0.01", "0", overrun=True))
    assert blocked.verdict == "blocked_by_overrun" and blocked.study.blocked_by_overrun is True
    assert all(check.ok for check in blocked.checks) and blocked.authorizes_paid_execution is False


def test_preflight_refuses_inconsistent_manifests() -> None:
    with pytest.raises(PreflightError, match="prices"):
        preflight(manifest(price_revision="pricing.2026-01-01.v1"), Caps())
    agent = manifest().actors[0].model_dump()
    for change in ({"model": "gpt-6-flagship"}, {"effort": "high"}, {"cache_mode": "5m"}):
        with pytest.raises(NotAllowed):
            preflight(manifest(actors=[agent | change]), Caps())
    with pytest.raises(PreflightError, match="per-request"):
        preflight(manifest(actors=[agent | {"max_input": 16001}]), Caps())
    bad: dict[str, Any]
    for bad in ({"tasks": ["t0", "t0"]}, {"tasks": []}, {"actors": [agent | {"max_repairs": 2}]},
                {"actors": [agent, agent]}, {"study_ceiling_usd": Decimal("0")}, {"trials_per_task": 0},
                {"actors": [agent | {"logical_calls": True}]}):
        with pytest.raises(ValidationError):
            manifest(**bad)
    over = preflight(manifest(actors=[agent | {"logical_calls": 40}]), Caps())  # 240 attempts > 200 per scenario
    assert over.verdict == "exceeds_caps" and ("scenario", "calls") in [(c.scope, c.measure) for c in over.checks
                                                                       if not c.ok]
