"""Real evaluation claims/finalization across a CE incident stop/resume."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository
from policyops.persistence.roles import EVAL_RUNTIME
from policyops.providers.calls import Providers
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies.config import QAStudy
from policyops_evals.qa_studies.registration import run_id
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import TOKENIZER

from .test_qa_answers import Candidates, answer_study
from .test_qa_runner import Memory
from .test_qa_runner_pg import qa_runner_db
from .test_qa_sealed import GUARDS
from .test_qa_study_config import parse
from .test_qa_study_registration import materialize_manifests


__all__ = ["qa_runner_db"]
pytestmark = pytest.mark.postgres


def test_incident_finalization_and_resume_no_reissue(qa_runner_db: AppDatabase, tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs, receipt, source = answer_study(tmp_path)
    value = study.model_dump(mode="json")
    value["execution"]["incident_guards"] = GUARDS
    value["schedule"]["repetitions"] = 2
    materialize_manifests(value, tmp_path)
    study = parse(value)
    validate = QAStudy.validate_data
    monkeypatch.setattr(QAStudy, "validate_data", lambda self: validate(self, tmp_path))
    repository = EvaluationRepository(qa_runner_db.engine(EVAL_RUNTIME, pool_size=5))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    calls: list[str] = []
    fail = True

    def execute(self: r.AnswerExecutor, arm: Any, query: Any, *args: Any, **kwargs: Any) -> None:
        calls.append(str(self.item.id))
        if arm.name == "rrf-bm25-base-ce":
            args[3].rerank_metadata["ce_failed"] = fail
            if fail:
                raise r.Refused("cross_encoder_failure")

    monkeypatch.setattr(r.AnswerExecutor, "execute", execute)
    def run(resume: bool) -> dict[str, Any]:
        return r.run(study, inputs, repository, store, Candidates(cast(Memory, None)), allow_paid=True,
                     resume=resume, source=source, providers=lambda: cast(Providers, None), tokenizer=TOKENIZER,
                     selection_receipt=receipt)
    first = run(False)
    assert first["abort_reason"] == "consecutive_ce_failures" and not first["execution_complete"]
    scope = store.study_by_key(str(study.study_id))
    assert scope is not None
    identity = run_id(study, scope.id, "rrf-bm25-base-ce")
    failed = {row["id"]: json.dumps(row, default=str, sort_keys=True) for row in repository.results(identity)}
    assert len(failed) == 3
    fail = False
    before = set(calls)
    assert run(True)["execution_complete"]
    assert len(calls) == len(set(calls)) == 20 and before < set(calls)
    after = {row["id"]: json.dumps(row, default=str, sort_keys=True) for row in repository.results(identity)}
    assert all(after[key] == row for key, row in failed.items())
