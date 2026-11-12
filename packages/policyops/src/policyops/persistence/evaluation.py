"""Trusted offline evaluation persistence. Claim -> scope -> attempt is the lock order.

A session advisory lock serializes study invocations/recovery without a long
transaction. Tokens bind its backend PID as well as immutable slot identities.
The row lock is acquired even for settlement; only admission requires running.
No simulation/provider work is retried after a claim or an ambiguous commit.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
import hashlib
import json
import os
from typing import Any
from uuid import UUID, uuid4

import psycopg
from sqlalchemy import Connection, Engine, text

from policyops.budget.ledger import EvalBinding, LedgerConflict, ScopeRef
from policyops.persistence.database import (
    RUNTIME_CONNECT_OPTIONS,
    TransactionOutcomeUnknown,
    make_engine,
    transaction,
    verify_runtime_role,
)
from policyops.persistence.records import EvaluationRun, EvaluationTrial
from policyops.persistence.roles import EVAL_RUNTIME


class ClaimRefused(LedgerConflict):
    pass


def study_lock_key(study_id: UUID) -> int:
    return int.from_bytes(hashlib.sha256(study_id.bytes).digest()[:8], "big", signed=True)


def check_study_lock(connection: Connection, study_id: UUID, pid: int) -> None:
    key = study_lock_key(study_id) & ((1 << 64) - 1)
    if not connection.execute(text(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND pid = :pid "
        "AND classid::bigint = :hi AND objid::bigint = :lo AND objsubid = 1 AND granted)"),
        {"pid": pid, "hi": key >> 32, "lo": key & 0xFFFFFFFF}).scalar_one():
        raise ClaimRefused("study_lock_lost")


@dataclass(frozen=True)
class StudyLock:
    study_id: UUID
    pid: int

    def check(self, connection: Connection) -> None:
        check_study_lock(connection, self.study_id, self.pid)


@dataclass(frozen=True)
class EvaluationClaimToken:
    slot_id: UUID
    owner: UUID
    binding: EvalBinding
    lock_pid: int


@dataclass(frozen=True)
class Slot:
    id: UUID
    run_id: UUID
    study_id: UUID
    config_sha256: str
    task_id: str
    trial_index: int
    seed: int
    scenario_id: UUID
    state: str


def lock_claim(connection: Connection, token: EvaluationClaimToken) -> dict[str, Any]:
    row = connection.execute(text(
        "SELECT id, study_scope, scenario_scope, invocation_scope, owner_token, state "
        "FROM evaluation.trial_claims WHERE id = :id FOR UPDATE"), {"id": token.slot_id}).mappings().first()
    if (row is None or row["owner_token"] != token.owner or row["study_scope"] != token.binding.study_id
            or row["scenario_scope"] != token.binding.scenario_id
            or row["invocation_scope"] != token.binding.invocation_id):
        raise ClaimRefused("claim_binding_changed")
    return dict(row)


def check_claim_admission(connection: Connection, token: EvaluationClaimToken,
                          refs: Sequence[ScopeRef]) -> None:
    row = lock_claim(connection, token)
    check_study_lock(connection, token.binding.study_id, token.lock_pid)
    expected = {token.binding.study_id, token.binding.invocation_id, token.binding.scenario_id}
    if row["state"] != "running" or {r.id for r in refs} != expected:
        raise ClaimRefused("claim_not_running")


def result_digest(result: EvaluationTrial) -> str:
    body = result.model_dump(mode="json")
    body["components_json"] = json.loads(result.components_json)
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def _slot(row: Any) -> Slot:
    return Slot(row["id"], row["evaluation_run_id"], row["study_scope"], row["config_sha256"], row["task_id"],
                row["trial_index"], row["seed"], row["scenario_scope"], row["state"])


class EvaluationRepository:
    def __init__(self, engine: Engine) -> None:
        verify_runtime_role(engine, EVAL_RUNTIME)
        self.engine = engine

    @contextmanager
    def study_lock(self, study_id: UUID) -> Iterator[StudyLock]:
        # AUTOCOMMIT avoids an idle transaction for the duration of a trial.
        # Always invalidate: a failed unlock must never return a locked session
        # to the pool, and disconnect itself releases the session lock.
        connection = self.engine.connect()
        primary: BaseException | None = None
        try:
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            connection.execute(text("SELECT set_config('statement_timeout', '5000', false)"))
            locked = connection.execute(text("SELECT pg_try_advisory_lock(:key)"),
                                        {"key": study_lock_key(study_id)}).scalar_one()
            if not locked:
                raise ClaimRefused("study_already_running")
            pid = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
            yield StudyLock(study_id, pid)
        except BaseException as error:
            primary = error
            raise
        finally:
            uncertain = False
            for cleanup in (connection.invalidate, connection.close):
                try:
                    cleanup()
                except BaseException:
                    uncertain = True
            if uncertain:
                if primary is not None:
                    primary.add_note("study lock cleanup unconfirmed")
                else:
                    raise ClaimRefused("study_lock_cleanup_unconfirmed")

    def ensure_run(self, run: EvaluationRun) -> UUID:
        from policyops.persistence.repositories import create_evaluation_run

        with transaction(self.engine) as connection:
            # Serialize same-study immutable creation; no provider work here.
            connection.execute(text("SELECT id FROM evaluation.budget_scopes WHERE id = :id FOR UPDATE"),
                               {"id": run.study_scope})
            row = connection.execute(text(
                "SELECT id, config, dataset, dataset_revision, split_id FROM evaluation.evaluation_runs "
                "WHERE study_scope = :study AND config_sha256 = :config"),
                {"study": run.study_scope, "config": run.config_sha256}).mappings().first()
            if row is None:
                create_evaluation_run(connection, run)
                return run.id
            if (row["config"] != json.loads(run.config_json) or row["dataset"] != run.dataset
                    or row["dataset_revision"] != run.dataset_revision or row["split_id"] != run.split_id):
                raise ClaimRefused("immutable_run_conflict")
            return UUID(str(row["id"]))

    def schedule(self, slot: Slot) -> None:
        with transaction(self.engine) as connection:
            connection.execute(text(
                "INSERT INTO evaluation.trial_claims (id, evaluation_run_id, study_scope, config_sha256, "
                "task_id, trial_index, seed, scenario_scope, state, created_at) "
                "VALUES (:id, :run, :study, :config, :task, :trial, :seed, :scenario, 'scheduled', :now) "
                "ON CONFLICT (evaluation_run_id, task_id, trial_index) DO NOTHING"),
                {"id": slot.id, "run": slot.run_id, "study": slot.study_id, "config": slot.config_sha256,
                 "task": slot.task_id, "trial": slot.trial_index, "seed": slot.seed, "scenario": slot.scenario_id,
                 "now": datetime.now(UTC)})
            row = connection.execute(text(
                "SELECT * FROM evaluation.trial_claims WHERE evaluation_run_id = :run "
                "AND task_id = :task AND trial_index = :trial"),
                {"run": slot.run_id, "task": slot.task_id, "trial": slot.trial_index}).mappings().one()
            if _slot(row) != Slot(slot.id, slot.run_id, slot.study_id, slot.config_sha256, slot.task_id,
                                  slot.trial_index, slot.seed, slot.scenario_id, row["state"]):
                raise ClaimRefused("immutable_slot_conflict")

    def slots(self, run_id: UUID) -> list[Slot]:
        with transaction(self.engine) as connection:
            rows = connection.execute(text(
                "SELECT * FROM evaluation.trial_claims WHERE evaluation_run_id = :run ORDER BY task_id, trial_index"
            ), {"run": run_id}).mappings().all()
        return [_slot(row) for row in rows]

    def run_configuration(self, run_id: UUID) -> dict[str, Any] | None:
        with transaction(self.engine) as connection:
            value = connection.execute(text("SELECT config FROM evaluation.evaluation_runs WHERE id = :id"),
                                       {"id": run_id}).scalar_one_or_none()
        return None if value is None else dict(value)

    def claim(self, slot: Slot, invocation_id: UUID, lease: StudyLock) -> EvaluationClaimToken | None:
        if lease.study_id != slot.study_id:
            raise ClaimRefused("study_binding_changed")
        owner = uuid4()
        with transaction(self.engine) as connection:
            lease.check(connection)
            row = connection.execute(text(
                "UPDATE evaluation.trial_claims SET state = 'running', owner_token = :owner, "
                "invocation_scope = :invocation, started_at = clock_timestamp() "
                "WHERE id = :id AND state = 'scheduled' RETURNING id"),
                {"id": slot.id, "owner": owner, "invocation": invocation_id}).first()
            lease.check(connection)  # after a competing claim's row-lock wait
        return None if row is None else EvaluationClaimToken(
            slot.id, owner, EvalBinding(slot.study_id, invocation_id, slot.scenario_id), lease.pid)

    def result_hash(self, slot_id: UUID) -> str | None:
        with transaction(self.engine) as connection:
            value = connection.execute(text(
                "SELECT result_sha256 FROM evaluation.evaluation_trials WHERE id = :id"),
                {"id": slot_id}).scalar_one_or_none()
        return None if value is None else str(value)

    def finalize(self, result: EvaluationTrial, token: EvaluationClaimToken | None, lease: StudyLock) -> None:
        digest = result_digest(result)
        try:
            with transaction(self.engine) as connection:
                row = connection.execute(text(
                    "SELECT * FROM evaluation.trial_claims WHERE id = :id FOR UPDATE"),
                    {"id": result.id}).mappings().one()
                lease.check(connection)
                if row["study_scope"] != lease.study_id:
                    raise ClaimRefused("study_binding_changed")
                if token is not None:
                    lock_claim(connection, token)
                    if token.slot_id != result.id:
                        raise ClaimRefused("claim_binding_changed")
                stored = connection.execute(text(
                    "SELECT result_sha256 FROM evaluation.evaluation_trials WHERE id = :id"),
                    {"id": result.id}).scalar_one_or_none()
                if stored is not None:
                    if stored != digest:
                        raise ClaimRefused("terminal_result_conflict")
                    return
                if token is not None:
                    locked = lock_claim(connection, token)
                    if token.slot_id != result.id or locked["state"] != "running":
                        raise ClaimRefused("claim_not_running")
                elif row["state"] != "scheduled" or result.outcome != "aborted":
                    raise ClaimRefused("claim_owner_required")
                from policyops.persistence.repositories import add_trial

                add_trial(connection, result)
                connection.execute(text(
                    "UPDATE evaluation.trial_claims SET state = 'finalized', finished_at = clock_timestamp(), "
                    "result_id = id WHERE id = :id"), {"id": result.id})
        except TransactionOutcomeUnknown:
            # Read once with the same identity and hash. Unavailable/absent DB
            # stops the caller; it never reruns inference to resolve uncertainty.
            observed = self.result_hash(result.id)
            if observed is not None and observed != digest:
                raise ClaimRefused("terminal_result_conflict") from None
            if observed != digest:
                raise

    def abort(self, slot: Slot, lease: StudyLock, *, reason: str = "abandoned_claim") -> None:
        with transaction(self.engine) as connection:
            lease.check(connection)
            row = connection.execute(text(
                "SELECT owner_token, invocation_scope, state FROM evaluation.trial_claims WHERE id = :id"
            ), {"id": slot.id}).mappings().one()
        if row["state"] == "finalized":
            return
        token = None if row["state"] == "scheduled" else EvaluationClaimToken(
            slot.id, row["owner_token"], EvalBinding(slot.study_id, row["invocation_scope"], slot.scenario_id),
            lease.pid)
        self.finalize(EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id, task_id=slot.task_id,
            trial_index=slot.trial_index, seed=slot.seed, outcome="aborted", reward=None,
            components_json='{"usage_status":"unconfirmed"}', error_class=reason,
            cost_status="unknown", cost_usd=None, created_at=datetime.now(UTC)), token, lease)

    def finish_run(self, run_id: UUID, lease: StudyLock) -> None:
        with transaction(self.engine) as connection:
            lease.check(connection)
            connection.execute(text(
                "UPDATE evaluation.evaluation_runs r SET status = CASE WHEN EXISTS "
                "(SELECT 1 FROM evaluation.evaluation_trials t WHERE t.evaluation_run_id = r.id "
                "AND t.outcome = 'aborted') THEN 'aborted' ELSE 'completed' END, "
                "started_at = coalesce(started_at, created_at), finished_at = clock_timestamp(), version = version + 1 "
                "WHERE r.id = :run AND study_scope = :study AND NOT EXISTS "
                "(SELECT 1 FROM evaluation.trial_claims c WHERE c.evaluation_run_id = r.id AND state <> 'finalized')"
            ), {"run": run_id, "study": lease.study_id})

    def results(self, run_id: UUID) -> list[dict[str, Any]]:
        with transaction(self.engine) as connection:
            return [dict(row) for row in connection.execute(text(
                "SELECT id, task_id, trial_index, seed, outcome, reward, components, error_class, result_sha256, "
                "artifact_sha256, cost_status, cost_usd "
                "FROM evaluation.evaluation_trials WHERE evaluation_run_id = :run ORDER BY task_id, trial_index"
            ), {"run": run_id}).mappings()]

    def usage(self, scenario_id: UUID) -> dict[str, Any]:
        with transaction(self.engine) as connection:
            row = connection.execute(text(
                "SELECT spent_usd, held_usd, calls_consumed, calls_held, counts_used, overrun, contract_block "
                "FROM evaluation.budget_scopes WHERE id = :id"), {"id": scenario_id}).mappings().one()
        return dict(row)

    def actor_attempts(self, scenario_id: UUID) -> list[dict[str, Any]]:
        with transaction(self.engine) as connection:
            rows = connection.execute(text(
                "SELECT id, actor, model, state, count_state, actual_usd, reserved_usd, usage, diagnostic, "
                "price_revision, config_sha256, request_sha256 FROM evaluation.usage_attempts "
                "WHERE scenario_scope_id = :id ORDER BY created_at, id LIMIT 1001"
            ), {"id": scenario_id}).mappings().all()
        if len(rows) > 1000:
            raise ClaimRefused("attempt_inventory_bounds")
        return [{key: str(value) if isinstance(value, (UUID, Decimal)) else value for key, value in row.items()}
                for row in rows]


__all__ = ["EvaluationClaimToken", "EvaluationRepository", "EvaluationRun", "EvaluationTrial", "Slot", "StudyLock"]


def environment_repository() -> EvaluationRepository | None:
    """libpq DSN is server-only; never echo it, including in CLI exceptions."""
    dsn = os.environ.get("POLICYOPS_EVAL_DATABASE_DSN")
    if dsn is None:
        return None
    engine = make_engine(lambda: psycopg.connect(dsn, connect_timeout=5, options=RUNTIME_CONNECT_OPTIONS))
    try:
        return EvaluationRepository(engine)
    except BaseException:
        engine.dispose()
        raise
