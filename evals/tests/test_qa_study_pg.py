"""QA registration through the real runtime repository; selected by coordinator."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from policyops.budget.config import Caps as BudgetCaps
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import ClaimRefused, EvaluationRepository, Slot
from policyops.persistence.roles import EVAL_RUNTIME
from policyops_evals.qa_studies import registration as reg
from policyops_evals.qa_studies.config import QAStudy
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.postgres import OwnedPostgres

from .test_qa_study_config import body, parse
from .test_qa_study_registration import SOURCE, materialize_manifests


pytestmark = pytest.mark.postgres


@pytest.fixture
def qa_db(postgres: OwnedPostgres) -> Iterator[AppDatabase]:
    database = AppCluster.provision(postgres).create_database("qa_registration")
    database.upgrade()
    try:
        yield database
    finally:
        database.dispose()


def pg_study(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> QAStudy:
    value: dict[str, Any] = body()
    value.update(example=False, purpose="sealed_test", study_id=str(uuid4()))
    value["schedule"]["cohorts"][0]["split"] = "validation"
    materialize_manifests(value, tmp_path)
    study = parse(value)
    value["registration_sha256"] = reg.registration_digest(study, SOURCE)
    original = QAStudy.validate_data
    monkeypatch.setattr(QAStudy, "validate_data", lambda self: original(self, tmp_path))
    return parse(value)


def test_qa_registration_timestamp_replay_and_changed_binding(qa_db: AppDatabase, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    study = pg_study(tmp_path, monkeypatch)
    repository = EvaluationRepository(qa_db.engine(EVAL_RUNTIME))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    cap = study.execution.cumulative_caps
    scope = store.ensure_study(str(study.study_id), study.digest(), cap_usd=cap.usd, cap_calls=cap.calls)
    with repository.study_lock(scope) as lease:
        first = reg.register(study, repository, scope, SOURCE, lease)
        assert reg.register(study, repository, scope, SOURCE, lease) == first
        assert reg.registered(study, repository, scope, SOURCE) == first
        assert first["created_at"] and first["sha256"] == study.registration_sha256
        changed = dict(SOURCE, dirty_sha256="f" * 64)
        with pytest.raises(ValueError, match="binding"):
            reg.registered(study, repository, scope, changed)


def test_qa_registration_after_claim_is_refused(qa_db: AppDatabase, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    study = pg_study(tmp_path, monkeypatch)
    repository = EvaluationRepository(qa_db.engine(EVAL_RUNTIME))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    cap = study.execution.cumulative_caps
    scope = store.ensure_study(str(study.study_id), study.digest(), cap_usd=cap.usd, cap_calls=cap.calls)
    # A different existing run has already made a claim in this scope. None
    # of the intended registration arms exists, isolating the prior-claim gate.
    record = reg.run_records(study, scope, SOURCE)[0].model_copy(update={"id": uuid4()})
    repository.ensure_run(record)
    limits = BudgetCaps(study_usd=cap.usd, invocation_usd=cap.usd,
                        study_calls=cap.calls, invocation_calls=cap.calls)
    invocation = store.ensure_invocation(scope, uuid4(), limits)
    scenario = store.ensure_scenario(scope, "q1", 0, record.config_sha256, limits)
    slot = Slot(id=uuid4(), run_id=record.id, study_id=scope, config_sha256=record.config_sha256,
                task_id="q1", trial_index=0, seed=1, scenario_id=scenario, state="scheduled")
    repository.schedule(slot)
    with repository.study_lock(scope) as lease:
        assert repository.claim(slot, invocation, lease) is not None
        with pytest.raises(ClaimRefused, match="registration_after_claim"):
            reg.register(study, repository, scope, SOURCE, lease)
