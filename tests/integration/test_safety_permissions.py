"""E05 uses real PostgreSQL runtime roles, T22 review jobs and owned retail HTTP."""

from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest

from policyops.budget.ledger import EvalBinding
from policyops.persistence.budget import build_eval_ledger
from policyops.persistence.roles import EVAL_RUNTIME
from policyops_testing.safety import e05, e05_provider, sensitivity
from policyops_testing.safety.config import digest, load_e05_config
from policyops_testing.safety.e05_cli import run_row
from policyops_testing.safety.e05_reports import assert_gateway, classify
from policyops_testing.safety.environment import Env
from policyops_testing.safety.fixtures import safety_env as safety_env
from policyops_testing.safety.fixtures import safety_live as safety_live


pytestmark = pytest.mark.postgres
CONFIG = load_e05_config()


@pytest.mark.parametrize("fixture", CONFIG.fixtures, ids=lambda f: f.fixture_id + "-" + f.scenario)
def test_frozen_gateway_permissions(safety_env: Env, fixture: Any) -> None:
    row = run_row(safety_env, fixture, "gateway", e05.candidate(fixture))
    assert_gateway(row, fixture)
    assert row.error is None
    if fixture.category == "stale_replay":
        assert row.race_reached


@pytest.mark.parametrize("kind", ["compliant", "malicious", "malformed", "multi_call", "timeout", "usage_error"])
def test_scripted_sdk_ledger_direct_and_exact_replay(safety_env: Env, kind: str) -> None:
    fixture = CONFIG.fixtures[0].model_copy(update={"scripted_kind": kind})
    settings = e05_provider.configuration(CONFIG)
    ledger, store = build_eval_ledger(env="test", engine=safety_env.db.engine(EVAL_RUNTIME), configuration=settings)
    study = store.ensure_study("e05-test-" + uuid4().hex, digest(CONFIG.model_dump(mode="json")),
                               cap_usd=Decimal("0.12"), cap_calls=60)
    invocation = store.ensure_invocation(study, uuid4(), settings.caps)
    scenario = store.ensure_scenario(study, fixture.fixture_id, 0,
                                     digest(CONFIG.model_dump(mode="json")), settings.caps)
    result, billing, stop = e05_provider.complete(CONFIG, fixture, "scripted", ledger,
                                               EvalBinding(study, invocation, scenario))
    direct = run_row(safety_env, fixture, "prompt_only", result, billing)
    replay = run_row(safety_env, fixture, "replay_gateway", result)
    assert direct.proposed == replay.proposed
    assert billing["attempts"][0]["count_granted"]
    assert billing["attempts"][0]["dispatch_granted"]
    snapshot = store.scope(study)
    assert snapshot is not None and snapshot.calls_consumed == 1 and snapshot.counts_used == 1
    if kind == "malicious":
        assert classify(direct, fixture)["forbidden_effects"] == 1
        assert_gateway(replay, fixture)
    elif kind in ("timeout", "usage_error"):
        assert stop and not classify(direct, fixture)["confirmed_block"]
        assert snapshot.held_usd > 0 or snapshot.contract_block is not None
    else:
        assert not classify(direct, fixture)["forbidden_effects"]


def test_stale_and_once_only_guard_removal_changes_same_assertion(safety_env: Env) -> None:
    controls = sensitivity.e05_controls(safety_env)
    assert len(controls) == 2
    assert all(c.detected for c in controls), controls
