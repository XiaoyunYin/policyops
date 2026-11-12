"""Real upstream build/run/score, with a fictional DB and language scaffolding.

No public dataset/task payloads are opened. Language resolution and user prompt
scaffolding use fictional values; factories, converters, T20, T11, environment,
orchestrator and ALL scoring are the real pinned implementations.
"""

from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest

from policyops.budget.ledger import Ledger, LedgerConflict
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository, Slot
from policyops_evals.studies import runner
from policyops_evals.studies.config import Study, load_study

from .t29_inprocess_cases import fixture
from .t29_study_support import Repository, StudyStore
from .t29_support import CANARY, Routes, judgement, tool


@pytest.fixture
def composed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    from tau2.data_model.language import LanguageTaskInfo
    from tau2.data_model.tasks import Task
    from tau2.domains.retail.data_model import RetailDB
    from tau2.multilingual import runtime
    from tau2.runner import build
    from tau2.user import user_simulator

    data = fixture()
    study = load_study(Path(__file__).parents[1] / "studies/t29-luna-dev-smoke-v1.json")
    study = Study.model_validate_json(json.dumps(study.model_dump(mode="json") | {"provider_mode": "scripted"}))
    language = LanguageTaskInfo(language="en", mode="text", cross_lingual=False, pack_revision="fictional-v1",
        pack_sha256="0" * 64, domain_revision="fictional-v1", tasks_sha256="0" * 64,
        metadata_sha256="0" * 64, task_sha256="0" * 64, canonical_task_id="fictional",
        agent_greeting="Welcome to the fictional shop.", agent_language_clause="Use English.",
        caller_gender=None, persona=None, guideline_template_version="fictional-v1")
    monkeypatch.setattr(runtime, "task_context", lambda *args, **kw: language)
    monkeypatch.setattr(build, "_build_env_kwargs", lambda *args, **kw: {
        "db": RetailDB.model_validate(data["db"]), "policy": data["policy"]})
    monkeypatch.setattr(user_simulator, "simulation_guidelines", lambda *args, **kw: data["simulator_guidelines"])
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(runner, "source_provenance", lambda: {"source_head": "fixture", "dirty_sha256": "0" * 64})
    inputs = {}
    for task_id in study.tasks:
        task = Task.model_validate(data["task"] | {"id": task_id})
        inputs[task_id] = runner.TrialInputs(task, {"db": RetailDB.model_validate(data["db"]),
                                                  "policy": data["policy"]})
    store = StudyStore()
    repository = Repository(store)
    action = data["task"]["evaluation_criteria"]["actions"][0]
    outputs = [data["visible_request"], tool(action["name"], action["arguments"]),
               "Your address has been changed.", "###STOP###", judgement()]

    def run(config: Study = study, *, resume: bool = False, route: Routes | None = None) -> dict[str, Any]:
        routes = route or Routes(outputs * 3)
        return runner.run_study(config, cast(EvaluationRepository, repository), cast(EvalLedgerStore, store),
            resume=resume, inputs=inputs, make_providers=lambda _: routes.providers,
            make_ledger=lambda variant, token: Ledger(store, config.configuration(variant)))

    return study, repository, store, outputs, run


def test_three_slot_real_upstream_scored_study(composed: Any) -> None:
    _, repository, store, outputs, run = composed
    routes = Routes(outputs * 3)
    summary = run(route=routes)
    assert summary["scheduled"] == summary["recorded"] == summary["successes"] == 3
    assert summary["strict_success_lower_bound"] == summary["complete_case_success"] == 1
    assert len(summary["trials"]) == 3 and summary["execution_complete"]
    assert summary["study_usage"]["counts_used"] == 15
    assert repository.claims == 3 and len(store.attempts) == 15
    assert all(a.state == "settled" for a in store.attempts.values())
    for result in repository.terminals.values():
        details = json.loads(result.components_json)
        assert details["models_returned"] == {a: ["gpt-6-luna"] for a in ("agent", "simulator", "judge")}
        assert details["environment"]["db_check"]["db_match"]
        assert details["composite"]["nl_assertions"][0]["met"]
        snapshot = Path(summary["output"]) / f"{result.id}-agent.json"
        assert CANARY not in snapshot.read_text(encoding="utf-8")
    assert not routes.outputs


def test_resume_skips_finished_slots_with_no_new_inference(composed: Any) -> None:
    _, repository, store, _, run = composed
    run()
    count = len(store.attempts)
    routes = Routes([])
    summary = run(resume=True, route=routes)
    assert summary["recorded"] == 3 and repository.claims == 3
    assert len(store.attempts) == count and not routes.seen
    with pytest.raises(runner.StudyRefused, match="existing_study_requires_resume"):
        run()


def test_interrupted_trial_records_abort_and_all_scheduled_slots_in_denominator(
        composed: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _, repository, _, outputs, run = composed
    original = runner.execute_trial

    def interrupt(*args: Any, **kwargs: Any) -> Any:
        original(*args, **kwargs)  # one real upstream trajectory before interruption
        raise KeyboardInterrupt()

    monkeypatch.setattr(runner, "execute_trial", interrupt)
    routes = Routes(outputs * 3)
    summary = run(route=routes)
    assert summary["scheduled"] == summary["recorded"] == 3 and summary["successes"] == 0
    assert summary["strict_success_lower_bound"] == 0 and summary["complete_case_success"] is None
    assert all(r.reward is None for r in repository.terminals.values())
    assert all(s.state == "finalized" for s in repository.schedule_rows.values())


def test_restart_aborts_abandoned_claim_without_replaying_it(composed: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _, repository, store, _, run = composed
    original = repository.claim
    interrupted = False

    def crash(*args: Any, **kwargs: Any) -> Any:
        nonlocal interrupted
        token = original(*args, **kwargs)
        if not interrupted:
            interrupted = True
            raise RuntimeError("process_lost_after_claim")
        return token

    monkeypatch.setattr(repository, "claim", crash)
    with pytest.raises(RuntimeError, match="process_lost"):
        run()
    assert not store.attempts
    monkeypatch.setattr(repository, "claim", original)
    result = run(resume=True)
    assert result["recorded"] == 3 and result["successes"] == 2
    assert sum(r.outcome == "aborted" for r in repository.terminals.values()) == 1
    assert len(store.attempts) == 10


def test_preflight_refuses_before_provider_construction(composed: Any) -> None:
    study, repository, store, _, _ = composed
    config = Study.model_validate_json(json.dumps(study.model_dump(mode="json") | {
        "limits": study.limits.model_dump(mode="json") | {"study_usd": "0.01"}}))

    def trap(*args: Any) -> Any:
        pytest.fail("providers constructed before preflight")

    with pytest.raises(runner.StudyRefused, match="preflight_refused"):
        runner.run_study(config, cast(EvaluationRepository, repository), cast(EvalLedgerStore, store),
                         make_providers=trap)
    assert not repository.schedule_rows and not store.attempts


def test_persisted_preflight_failure_refuses_before_credentials(composed: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, store, _, run = composed
    original = store.ensure_study

    def spent(*args: Any, **kwargs: Any) -> Any:
        identity = original(*args, **kwargs)
        store.scopes[identity] = replace(store.scopes[identity], held_usd=Decimal("0.10"))
        return identity

    monkeypatch.setattr(store, "ensure_study", spent)
    routes = Routes([])
    with pytest.raises(runner.StudyRefused, match="ledger_preflight_refused"):
        run(route=routes)
    assert not routes.seen


def test_immutable_config_conflicts_before_provider_work(composed: Any) -> None:
    study, _, store, _, run = composed
    run()
    changed = Study.model_validate_json(json.dumps(study.model_dump(mode="json") | {"seeds": [7]}))
    with pytest.raises(LedgerConflict, match="immutable_study_conflict"):
        run(changed, resume=True, route=Routes([]))
    assert len(store.attempts) == 15


def test_duplicate_claim_and_result_do_not_replace_terminal(composed: Any) -> None:
    _, repository, _, _, run = composed
    run()
    result = next(iter(repository.terminals.values()))
    slot = repository.schedule_rows[result.id]
    with repository.study_lock(slot.study_id) as lease:
        assert repository.claim(cast(Slot, slot), uuid4(), lease) is None
        repository.finalize(result, repository.tokens[result.id], lease)
        with pytest.raises(LedgerConflict, match="terminal_result_conflict"):
            repository.finalize(result.model_copy(update={"reward": Decimal("0")}), repository.tokens[result.id], lease)
    assert len(repository.terminals) == 3


def test_resume_refuses_a_changed_source_binding(composed: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, store, _, run = composed
    run()
    monkeypatch.setattr(runner, "source_provenance", lambda: {"source_head": "different", "dirty_sha256": "0" * 64})
    with pytest.raises(AssertionError):  # the double's immutable-run assertion
        run(resume=True)
    assert len(store.attempts) == 15
