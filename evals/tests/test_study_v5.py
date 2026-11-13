"""Bounded unknown billing, preserved holds, and the pre-data v5 decision."""

from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4, uuid5

import pytest

from policyops.budget.ledger import Ledger
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository, Slot
from policyops_evals.canonical import canonical_bytes
from policyops_evals.studies import bundles, reports, runner, runner_v2
from policyops_evals.studies.config import StudyV2, load_study, preflight

from .t29_study_support import StudyStore
from .t32_support import SOURCE, StudyRepository, example


CONFIG = Path(__file__).parents[1] / "studies/e03-dev-luna-haiku-v5.json"


def bounded_study() -> StudyV2:
    body = example().model_dump(mode="json")
    body["limits"]["max_unresolved_attempts"] = 3
    return StudyV2.model_validate_json(canonical_bytes(body))


def test_v5_changes_only_preregistered_policy() -> None:
    previous = json.loads(CONFIG.with_name("e03-dev-luna-haiku-v4.json").read_bytes())
    body = json.loads(CONFIG.read_bytes())
    assert body.pop("study_key") == "e03-dev-luna-haiku-v5"
    previous.pop("study_key")
    assert "6/160" in body["notes"] and "Before any v5 data" in body.pop("notes")
    previous.pop("notes")
    assert body["limits"].pop("max_unresolved_attempts") == 3
    assert body == previous
    plan = preflight(load_study(CONFIG))
    assert plan["within_caps"] and plan["prior"] == "unverified"
    assert Decimal(plan["planning_estimate_usd"]) == Decimal("3.6480")
    assert Decimal(plan["admission_ceiling_usd"]) == Decimal("27.0848")
    assert Decimal(plan["study_cap_usd"]) == Decimal("28")
    # New optional field does not alter legacy specification hashes.
    old = CONFIG.with_name("e03-dev-luna-haiku-v4.json")
    legacy = json.loads(old.read_bytes()) | {"scripted_outputs": []}
    assert load_study(old).model_dump(mode="json") == legacy


def continuation_case(repository: EvaluationRepository, store: EvalLedgerStore, unknown: int,
                      monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, memory: bool = False) -> None:
    study = bounded_study()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(runner_v2, "source_provenance", lambda: SOURCE)
    inputs = {t: runner.TrialInputs(SimpleNamespace(evaluation_criteria=SimpleNamespace(nl_assertions=[])))
              for t in study.tasks}
    visited = []
    held: list[Decimal] = []

    def execute(config: Any, variant: Any, slot: Any, ledger: Ledger, token: Any, *args: Any) -> dict[str, Any]:
        visited.append(slot.id)
        if len(held) < unknown:
            key, digest = uuid5(slot.id, "unknown"), "b" * 64
            ledger.reserve(token.binding, key, "agent", "study.unknown", digest)
            ledger.claim_count(key, digest)
            ledger.record_count(key, tokens=100, source="provider")
            ledger.begin_dispatch(key, digest)
            ledger.mark_unresolved(key)
            held.append(ledger.configuration.reservation("agent").worst_usd)
        # Even an apparent scored success with an unknown bill must be an error.
        return {"outcome": "success", "reward": "1", "error_class": None,
                "environment": {"db_check": {"db_match": True}}, "composite": {"reward": 1}}

    monkeypatch.setattr(runner, "execute_trial", execute)
    make_ledger = (lambda variant, token: Ledger(store, study.configuration(variant))) if memory else None
    result = runner.run_study(study, repository, store, inputs=inputs, make_ledger=make_ledger,
                              make_providers=lambda _: lambda: None)  # type: ignore[arg-type,return-value]
    assert len(visited) == (4 if unknown == 4 else 16)
    assert result["execution_complete"] == (unknown < 4)
    frozen, snapshot, _, _ = bundles.load(Path(result["output"]) / "study.json", result["snapshot_sha256"])
    errors = [r for r in snapshot.trials if Decimal(r.held_usd) > 0]
    assert len(errors) == unknown
    assert all(r.status == "error" and r.composite_success is None and not r.cost_known
               and r.cost_usd is None for r in errors)
    scope = store.scope(frozen.study_id)
    assert scope is not None and scope.spent_usd == 0 and scope.held_usd == sum(held)
    assert scope.spent_usd + scope.held_usd <= scope.cap_usd
    if not memory:
        assert all(a.state == "unresolved" and a.actual_usd is None for a in snapshot.attempts)
        report = reports.build(frozen, snapshot, "0" * 64, "1" * 64)
        assert Decimal(report["accounting"]["upper_bound_usd"]) == sum(held)
    # Resume never replays a claimed slot, and four unknown bills remain blocked.
    runner.run_study(study, repository, store, inputs=inputs, make_ledger=make_ledger, resume=True,
                     make_providers=lambda _: lambda: None)  # type: ignore[arg-type,return-value]
    assert len(visited) == len(set(visited)) == (4 if unknown == 4 else 16)


@pytest.mark.parametrize("unknown", [1, 2, 3, 4])
def test_continuation_keeps_holds_and_never_replays(unknown: int, monkeypatch: pytest.MonkeyPatch,
                                                  tmp_path: Path) -> None:
    store = StudyStore()
    continuation_case(cast(EvaluationRepository, StudyRepository(store)), cast(EvalLedgerStore, store),
                      unknown, monkeypatch, tmp_path, memory=True)


@pytest.mark.parametrize("kind", ["study", "invocation", "scenario"])
@pytest.mark.parametrize("cap", ["money", "inference", "count", "blocked"])
def test_next_slot_checks_every_scope_including_holds(kind: str, cap: str) -> None:
    study, store = bounded_study(), StudyStore()
    repository = StudyRepository(store)
    caps, variant = study.limits.caps(), study.variants[0]
    identity = store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    invocation = store.ensure_invocation(identity, uuid4(), caps)
    scenario = store.ensure_scenario(identity, "0", 0, study.variant_digest(variant), caps)
    slot = Slot(uuid4(), uuid4(), identity, study.variant_digest(variant), "0", 0,
                study.seeds[0], scenario, "scheduled")
    next_work: dict[str, tuple[tuple[str, int, int], ...]] = {
        v.name: (("0", 0, study.seeds[0]),) if v.name == variant.name else () for v in study.variants}
    plan = preflight(study, remaining=next_work)
    usd, calls = Decimal(plan["admission_ceiling_usd"]), plan["inference_ceiling"]
    scope_id = {"study": identity, "invocation": invocation, "scenario": scenario}[kind]
    scope = store.scopes[scope_id]
    store.scopes[scope_id] = replace(scope, cap_usd=usd + Decimal("0.01"), held_usd=Decimal("0.01"),
                                    cap_calls=calls + 1, calls_held=1, cap_counts=calls + 1, counts_used=1)

    def admitted() -> bool:
        return runner_v2.admit_slot(study, variant, slot, invocation,
                                   cast(EvaluationRepository, repository), cast(EvalLedgerStore, store))

    assert admitted()  # equality at the money/call/count ceilings is admitted
    scope = store.scopes[scope_id]
    if cap == "money":
        scope = replace(scope, held_usd=Decimal("0.01000001"))
    elif cap == "inference":
        scope = replace(scope, calls_held=2)
    elif cap == "count":
        scope = replace(scope, counts_used=2)
    else:
        scope = replace(scope, contract_block="usage_malformed")
    store.scopes[scope_id] = scope
    assert not admitted()


@pytest.mark.parametrize("value", [-1, 1001, True, "3"])
def test_unresolved_limit_is_explicit_strict_and_bounded(value: Any) -> None:
    body = example().model_dump(mode="json")
    body["limits"]["max_unresolved_attempts"] = value
    with pytest.raises(ValueError):
        StudyV2.model_validate_json(canonical_bytes(body))
