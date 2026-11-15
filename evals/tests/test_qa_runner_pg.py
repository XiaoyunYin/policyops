"""Real structural ingest -> dual-ledger query embeddings -> QA slots -> resume/export."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository
from policyops.persistence.roles import EVAL_RUNTIME
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies.registration import run_id
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.retrieval_fixtures import Embeddings, World, axis
from policyops_testing.structural_fixtures import KEY, passage

from .test_qa_runner import fixture_study
from .test_qa_study_config import parse
from .test_qa_study_registration import SOURCE, materialize_manifests


pytestmark = pytest.mark.postgres


@pytest.fixture
def qa_runner_db(postgres: OwnedPostgres) -> Iterator[AppDatabase]:
    database = AppCluster.provision(postgres).create_database("qa_runner")
    database.upgrade()
    try:
        yield database
    finally:
        database.dispose()


def test_structural_dev_run_resume_cache_and_export(qa_runner_db: AppDatabase, tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    from decimal import Decimal

    from policyops.retrieval.ingest import PaidCaps, Request, ingest
    from policyops_testing.retrieval_fixtures import TOKENIZER
    from policyops_testing.structural_fixtures import write

    world = World(qa_runner_db, tmp_path)
    provider = Embeddings({"Refunds\n\nRefunds return to the original card.": axis(0),
        "user: earlier [SEP] user: refunds": axis(0), "user: refunds": axis(0)})
    raw, digest = write(tmp_path / "corpus", [passage()])
    result = ingest(Request(world.ws, KEY, raw, digest, tmp_path / "corpus", "execute",
        PaidCaps("text-embedding-3-small", 1536, Decimal("1"), 90, 600000, 3600), "structural"),
        engine=world.engine, tokenizer=TOKENIZER, providers=provider.providers(), env="test")
    assert result.outcome == "activated"
    study, inputs = fixture_study()
    value = study.model_dump(mode="json")
    materialize_manifests(value, tmp_path)
    study = parse(value)
    from policyops_evals.qa_studies.config import QAStudy

    validate = QAStudy.validate_data
    monkeypatch.setattr(QAStudy, "validate_data", lambda self: validate(self, tmp_path))
    gold = r.Gold((passage()["passage_id"],), "responding")
    inputs = r.Inputs(inputs.queries, dict.fromkeys(inputs.queries, gold), inputs.cohorts)
    # The runner holds two advisory-lock sessions (program + study) while it works, like the CLI's default pool of 5.
    repository = EvaluationRepository(qa_runner_db.engine(EVAL_RUNTIME, pool_size=5))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    executor = r.RetrieverExecutor(world.engine, world.ws, KEY, providers=provider.providers(),
                                    tokenizer=TOKENIZER, env="test")
    run = r.run(study, inputs, repository, store, executor, allow_paid=True, resume=False, source=SOURCE)
    assert run["execution_complete"] and run["recorded"] == 12
    assert len(provider.requests) == 3  # ingest plus two distinct query profiles; dense/RRF/repeats hit cache
    assert r.run(study, inputs, repository, store, executor, allow_paid=True, resume=True,
                 source=SOURCE)["execution_complete"]
    assert len(provider.requests) == 3
    scope = store.study_by_key(str(study.study_id))
    assert scope is not None and scope.calls_consumed == 2 and scope.held_usd == 0
    public = r.export(study, r.schedule(study, inputs), repository,
                      {a.name: run_id(study, scope.id, a.name) for a in study.arms})
    assert len(public["slots"]) == 12
    assert all(s["outcome"] == "success" for s in public["slots"])
    assert all(s["metrics"]["recall_at_1"] == "1" for s in public["slots"] if s["arm"].startswith("dense"))
    assert all(set(s) <= {"slot_id", "cohort", "question_id", "arm", "repetition", "outcome", "metrics",
                          "cost_usd", "cost_status", "held_liability_usd", "latency_ms", "failure_code",
                          "metric_failures", "outcome_code"}
               for s in public["slots"])
    # The per-metric flags and outcome codes added for stage-scoped missingness stay text-free.
    assert all(s["outcome_code"] is None and all(type(v) is bool for v in s["metric_failures"].values())
               for s in public["slots"])
