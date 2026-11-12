"""Terminal COMMIT reconciliation without provider replay; SQL properties use PG tests."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy import Engine

from policyops.budget.ledger import EvalBinding
from policyops.persistence import evaluation, repositories
from policyops.persistence.database import TransactionOutcomeUnknown
from policyops.persistence.evaluation import ClaimRefused, EvaluationClaimToken, EvaluationRepository, StudyLock
from policyops.persistence.records import EvaluationTrial


@pytest.mark.parametrize("durable", ["same", "absent", "conflicting"])
def test_terminal_commit_unknown_reads_same_identity_once_and_never_reinserts(
        monkeypatch: pytest.MonkeyPatch, durable: str) -> None:
    binding = EvalBinding(uuid4(), uuid4(), uuid4())
    identity, owner = uuid4(), uuid4()
    token = EvaluationClaimToken(identity, owner, binding, 100)
    result = EvaluationTrial(id=identity, evaluation_run_id=uuid4(), task_id="24", trial_index=0, seed=7,
        outcome="aborted", reward=None, components_json='{"reason":"interrupted"}', cost_status="unknown",
        cost_usd=None, error_class="interrupted", created_at=datetime.now(UTC))
    claim = {"id": identity, "owner_token": owner, "study_scope": binding.study_id,
             "scenario_scope": binding.scenario_id, "invocation_scope": binding.invocation_id, "state": "running"}
    stored: str | None = None
    inserts, commits, hash_reads = 0, 0, 0

    class Query:
        def __init__(self, row: Any = None, scalar: Any = None) -> None:
            self.row, self.scalar = row, scalar

        def mappings(self) -> Query:
            return self

        def one(self) -> Any:
            return claim

        def first(self) -> Any:
            return claim

        def scalar_one(self) -> Any:
            return True  # lock ownership observation

        def scalar_one_or_none(self) -> Any:
            return self.scalar

    class Connection:
        def execute(self, sql: Any, params: Any = None) -> Query:
            nonlocal hash_reads
            if "SELECT result_sha256" in str(sql):
                assert params["id"] == identity
                hash_reads += 1
                return Query(scalar=stored)
            return Query()

    @contextmanager
    def transaction(engine: Any) -> Any:
        nonlocal commits, stored
        yield Connection()
        commits += 1
        if commits == 1:
            if durable == "absent":
                stored = None
            elif durable == "conflicting":
                stored = "e" * 64
            raise TransactionOutcomeUnknown()

    def insert(connection: Any, trial: EvaluationTrial) -> None:
        nonlocal stored, inserts
        inserts += 1
        stored = evaluation.result_digest(trial)

    monkeypatch.setattr(evaluation, "transaction", transaction)
    monkeypatch.setattr(evaluation, "verify_runtime_role", lambda *args: None)
    monkeypatch.setattr(repositories, "add_trial", insert)
    repository = EvaluationRepository(cast(Engine, object()))
    if durable == "same":
        repository.finalize(result, token, StudyLock(binding.study_id, 100))
    elif durable == "absent":
        with pytest.raises(TransactionOutcomeUnknown):
            repository.finalize(result, token, StudyLock(binding.study_id, 100))
    else:
        with pytest.raises(ClaimRefused, match="terminal_result_conflict"):
            repository.finalize(result, token, StudyLock(binding.study_id, 100))
    assert inserts == 1 and hash_reads == 2 and commits == 2


def test_result_hash_normalizes_component_key_order_and_refuses_changed_payload() -> None:
    result = EvaluationTrial(id=uuid4(), evaluation_run_id=uuid4(), task_id="24", trial_index=0, seed=7,
        outcome="aborted", reward=None, components_json='{"a":1,"b":2}', cost_status="unknown",
        cost_usd=None, error_class="interrupted", created_at=datetime.now(UTC))
    assert evaluation.result_digest(result) == evaluation.result_digest(
        result.model_copy(update={"components_json": '{"b": 2, "a": 1}'}))
    assert evaluation.result_digest(result) != evaluation.result_digest(result.model_copy(update={"seed": 8}))


def test_study_lock_initialization_failure_releases_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class Connection:
        def execution_options(self, **kwargs: Any) -> Any:
            raise ValueError("scripted_initialization_failure")

        def invalidate(self) -> None:
            calls.append("invalidate")

        def close(self) -> None:
            calls.append("close")

    class FakeEngine:
        def connect(self) -> Connection:
            return Connection()

    monkeypatch.setattr(evaluation, "verify_runtime_role", lambda *args: None)
    repository = EvaluationRepository(cast(Engine, FakeEngine()))
    with pytest.raises(ValueError, match="scripted_initialization_failure"), repository.study_lock(uuid4()):
        pytest.fail("initialization must fail before yielding")
    assert calls == ["invalidate", "close"]
