"""T32 registration and consistent claim-first exports as the actual PG role."""

from datetime import UTC, datetime
import json
from uuid import uuid4

import pytest

from policyops.persistence.evaluation import ClaimRefused, EvaluationRepository, EvaluationRun, registration_digest
from policyops_testing.app_database import AppDatabase, NewDatabase

from .test_evaluation_claims import scheduled


pytestmark = pytest.mark.postgres


@pytest.fixture
def db(new_app_database: NewDatabase) -> AppDatabase:
    return new_app_database("study_exports")


def test_export_includes_pending_running_and_aborted_without_artifacts(db: AppDatabase) -> None:
    repository, _, _, slots, invocation = scheduled(db, tasks=3)
    study = slots[0].study_id
    with repository.study_lock(study) as lease:
        assert repository.claim(slots[0], invocation, lease) is not None
        repository.abort(slots[1], lease)
        raw = repository.export_study(study, lease)
        assert len(raw["trials"]) == 3
        assert sorted(r["state"] for r in raw["trials"]) == ["finalized", "running", "scheduled"]
        assert {r["outcome"] for r in raw["trials"]} == {None, "aborted"}
        assert all("latency_ms" in r for r in raw["trials"])
        assert all(r["artifact_sha256"] is None for r in raw["trials"])
        assert raw["attempts"] == []
        assert len(raw["scopes"]) == 4
        assert repository.study_manifest(study) == "c" * 64


def test_registration_rejects_existing_unregistered_claims(db: AppDatabase) -> None:
    repository, _, _, slots, _ = scheduled(db)
    with repository.study_lock(slots[0].study_id) as lease, pytest.raises(ClaimRefused):
        repository.register([EvaluationRun(id=uuid4(), study_scope=slots[0].study_id, dataset="tau2-retail",
            dataset_revision="1" * 40, split_id="holdout", config_sha256="a" * 64,
            config_json='{"fixture":"registration"}', created_at=datetime.now(UTC))],
            {"version": "fixture"}, registration_digest({"version": "fixture"}), lease)


def test_atomic_two_arm_registration_exact_replay_and_timestamp(db: AppDatabase) -> None:
    from policyops.persistence.budget import EvalLedgerStore
    from policyops.persistence.roles import EVAL_RUNTIME

    engine = db.engine(EVAL_RUNTIME, pool_size=6)
    repository = EvaluationRepository(engine)
    store = EvalLedgerStore(engine, env="test")
    from policyops.budget.config import Caps

    caps = Caps()
    study = store.ensure_study("registration-" + uuid4().hex, "e" * 64,
        cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    runs = [EvaluationRun(id=uuid4(), study_scope=study, dataset="tau2-retail", dataset_revision="1" * 40,
        split_id="holdout", config_sha256=digest * 64, config_json=json.dumps({"variant": digest}),
        created_at=datetime.now(UTC)) for digest in ("a", "b")]
    before = datetime.now(UTC)
    payload = {"fixture": "registration"}
    digest = registration_digest(payload)
    with repository.study_lock(study) as lease:
        receipt = repository.register(runs, payload, digest, lease)
        assert repository.register(runs, payload, digest, lease) == receipt
        assert before <= datetime.fromisoformat(receipt["created_at"]) <= datetime.now(UTC)
        assert repository.registration_precedes_claims(study, datetime.fromisoformat(receipt["created_at"]))
        assert all(repository.run_configuration(run.id)["registration"] == receipt for run in runs)  # type: ignore[index]
        assert repository.export_study(study, lease)["attempts"] == []
        with pytest.raises(ClaimRefused, match="registration_conflict"):
            changed = {"fixture": "changed"}
            repository.register(runs, changed, registration_digest(changed), lease)
