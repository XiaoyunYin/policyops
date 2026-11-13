"""Composed v2 crash/resume on real PostgreSQL; no provider or task payloads."""

from collections.abc import Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid5

import pytest

from policyops.budget.ledger import Ledger, Settlement
from policyops.budget.pricing import Usage
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.database import TransactionOutcomeUnknown
import policyops.persistence.evaluation as evaluation
from policyops.persistence.evaluation import EvaluationRepository
from policyops.persistence.roles import EVAL_RUNTIME
from policyops_evals.studies import runner, runner_v2
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.postgres import OwnedPostgres

from .t32_support import SOURCE, bill_fixture_inference, example
from .test_study_v5 import continuation_case


pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("unknown", [1, 2, 3, 4])
def test_bounded_continuation_with_persisted_holds(unknown: int, db: AppDatabase,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repository = EvaluationRepository(db.engine(EVAL_RUNTIME))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    continuation_case(repository, store, unknown, monkeypatch, tmp_path)


@pytest.fixture
def db(postgres: OwnedPostgres) -> Iterator[AppDatabase]:
    database = AppCluster.provision(postgres).create_database("study_v2")
    database.upgrade()
    try:
        yield database
    finally:
        database.dispose()


@pytest.mark.parametrize("crash", ["after_claim", "after_bill", "after_artifact", "ambiguous_finalize",
                                   "simultaneous_resume"])
def test_crash_never_replays_a_claimed_inference(crash: str, db: AppDatabase,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    study = example()
    repository = EvaluationRepository(db.engine(EVAL_RUNTIME, pool_size=6))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(runner_v2, "source_provenance", lambda: SOURCE)
    inputs = {t: runner.TrialInputs(SimpleNamespace(evaluation_criteria=SimpleNamespace(nl_assertions=[])))
              for t in study.tasks}
    calls = []

    def execute(config: Any, variant: Any, slot: Any, ledger: Ledger, token: Any, *args: Any) -> dict[str, Any]:
        calls.append(slot.id)
        if crash == "simultaneous_resume" and len(calls) == 1:
            with pytest.raises(evaluation.ClaimRefused, match="study_already_running"):
                run(resume=True)
        bill_fixture_inference(slot.id, ledger, token.binding)
        return {"outcome": "success", "reward": "1", "error_class": None,
            "environment": {"db_check": {"db_match": True}}, "composite": {"reward": 1}}

    monkeypatch.setattr(runner, "execute_trial", execute)
    original_claim, original_finalize, original_artifact = repository.claim, repository.finalize, runner.artifact
    fired = False

    def claim(*args: Any, **kwargs: Any) -> Any:
        nonlocal fired
        result = original_claim(*args, **kwargs)
        if crash == "after_claim" and not fired:
            fired = True
            raise RuntimeError("lost_after_claim")
        return result

    def artifact(*args: Any, **kwargs: Any) -> Any:
        nonlocal fired
        if str(args[1]).endswith("-result.json") and crash == "after_bill" and not fired:
            fired = True
            raise RuntimeError("lost_after_bill")
        return original_artifact(*args, **kwargs)

    def finalize(*args: Any, **kwargs: Any) -> Any:
        nonlocal fired
        if crash == "after_artifact" and not fired:
            fired = True
            raise RuntimeError("lost_after_artifact")
        return original_finalize(*args, **kwargs)

    monkeypatch.setattr(repository, "claim", claim)
    monkeypatch.setattr(repository, "finalize", finalize)
    monkeypatch.setattr(runner, "artifact", artifact)
    if crash == "ambiguous_finalize":
        original_transaction = evaluation.transaction  # type: ignore[attr-defined]

        @contextmanager
        def ambiguous(*args: Any, **kwargs: Any) -> Iterator[Any]:
            nonlocal fired
            with original_transaction(*args, **kwargs) as connection:
                yield connection
            if not fired:
                fired = True
                raise TransactionOutcomeUnknown("fixture_commit_unknown")

        # Install only inside finalize: other setup/claim/export transactions
        # keep their real behavior and the committed-result readback is real.
        def ambiguous_finalize(*args: Any, **kwargs: Any) -> Any:
            with monkeypatch.context() as scoped:
                scoped.setattr(evaluation, "transaction", ambiguous)
                return original_finalize(*args, **kwargs)

        monkeypatch.setattr(repository, "finalize", ambiguous_finalize)

    def run(resume: bool = False) -> dict[str, Any]:
        return runner.run_study(study, repository, store, resume=resume, inputs=inputs,
                               make_providers=lambda _: lambda: None)  # type: ignore[arg-type,return-value]

    if crash in {"ambiguous_finalize", "simultaneous_resume"}:
        assert run()["execution_complete"]
    else:
        with pytest.raises(RuntimeError, match="lost_after"):
            run()
    monkeypatch.setattr(repository, "claim", original_claim)
    monkeypatch.setattr(repository, "finalize", original_finalize)
    monkeypatch.setattr(runner, "artifact", original_artifact)
    assert run(resume=True)["execution_complete"]
    assert len(set(calls)) == len(calls)
    assert len(calls) == (15 if crash == "after_claim" else 16)
    scope = store.study_by_key(study.study_key)
    assert scope is not None and scope.held_usd == 0 and scope.spent_usd > Decimal(0)


def test_unknown_billing_blocks_resume_and_late_settlement_creates_new_snapshot(db: AppDatabase,
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    study = example()
    repository = EvaluationRepository(db.engine(EVAL_RUNTIME, pool_size=6))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(runner_v2, "source_provenance", lambda: SOURCE)
    inputs = {t: runner.TrialInputs(SimpleNamespace(evaluation_criteria=SimpleNamespace(nl_assertions=[])))
              for t in study.tasks}
    held: list[Any] = []

    def execute(config: Any, variant: Any, slot: Any, ledger: Ledger, token: Any, *args: Any) -> dict[str, Any]:
        key, digest = uuid5(slot.id, "unknown"), "b" * 64
        ledger.reserve(token.binding, key, "agent", "study.unknown", digest)
        ledger.claim_count(key, digest)
        ledger.record_count(key, tokens=100, source="provider")
        ledger.begin_dispatch(key, digest)
        ledger.mark_unresolved(key)
        held.append((ledger, key))
        return {"outcome": "error", "reward": None, "error_class": "trial_deadline", "stop": True}

    monkeypatch.setattr(runner, "execute_trial", execute)

    def run(*, close: bool = False, resume: bool = False) -> dict[str, Any]:
        return runner.run_study(study, repository, store, inputs=inputs, resume=resume, close_unclaimed=close,
                               make_providers=lambda _: lambda: None)  # type: ignore[arg-type,return-value]

    first = run()
    with pytest.raises(runner.StudyRefused, match="ledger_preflight_refused"):
        run(resume=True)
    closed = run(close=True, resume=True)
    assert len(held) == 1
    ledger, key = held[0]
    ledger.settle(key, Settlement(Usage(100, output=10), provider_request_id="private-late-bill"))
    settled = run(close=True, resume=True)
    assert len(held) == 1 and first["snapshot_sha256"] != closed["snapshot_sha256"] != settled["snapshot_sha256"]
    from policyops_evals.studies import bundles

    directory = Path(settled["output"])
    _, old, _, _ = bundles.load(directory / "study.json", closed["snapshot_sha256"])
    _, new, _, _ = bundles.load(directory / "study.json", settled["snapshot_sha256"])
    assert any(s.held_usd != "0" and Decimal(s.held_usd) > 0 for s in old.scopes)
    assert all(Decimal(s.held_usd) == 0 for s in new.scopes)
