"""The PostgreSQL ledger stores (T10; schema from revision 0006). Static SQL only: no table name, column or clause
comes from a caller.

Both stores verify at construction that their engine really authenticates as the restricted runtime role (not
the migrator, a superuser or a `SET ROLE` impostor) and refuse a test clock outside the test environment.

- `AppLedgerStore`: the app runtime, inside `workspace_transaction`, so forced RLS confines every row to one
  workspace. It accepts run and operation bindings. A run's scope is created on first use with the server's run
  caps; recreating it with the same caps is a replay, and different caps are a conflict. A new attempt UUID or a
  restarted process therefore cannot reset a run's budget. Settlement also writes one `app.usage_events` row per
  attempt. A provider request ID already recorded (by another attempt, or by the legacy path) is a conflict that
  rolls the settlement back and keeps the hold.
- `EvalLedgerStore`: the eval runtime, in the trusted offline `evaluation` schema (no RLS, no app grants). Studies,
  invocations and scenarios are ensured explicitly (`ensure_*`, with the same replay-or-conflict rule) and an
  attempt binds all three. Usage stays on the attempt row.

Lock order and clock rules are those of `policyops.budget.ledger`: the run and claim job rows, then scopes one by
one in (kind rank, ID) order, then the attempt. Admission rechecks the claim after every scope/attempt wait;
settlement and legal release do not require dispatch authority. Times are read after the locks.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
import json
import re
from typing import Any
from uuid import UUID, uuid4

from psycopg import errors as pg_errors
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError

from policyops.budget.config import Caps, Configuration
from policyops.budget.ledger import (
    Attempt,
    Binding,
    BudgetExhausted,
    Diagnostic,
    EvalBinding,
    Intent,
    Ledger,
    LedgerConflict,
    NotFound,
    OperationBinding,
    RunBinding,
    Scope,
    ScopeKind,
    ScopeRef,
    Settlement,
)
from policyops.budget.prices import PriceSnapshot
from policyops.persistence import runs
from policyops.persistence.database import transaction, verify_runtime_role, workspace_transaction
from policyops.persistence.evaluation import EvaluationClaimToken, check_claim_admission, lock_claim
from policyops.persistence.records import exact_usd
from policyops.persistence.roles import APP_RUNTIME, EVAL_RUNTIME
from policyops.persistence.runs import ClaimToken
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, require_test_environment


SHA256 = re.compile(r"[0-9a-f]{64}")
COUNTERS = ("id, kind, cap_usd, cap_calls, spent_usd, held_usd, calls_consumed, calls_held, overrun, cap_counts, "
            "counts_used, contract_block")
INTENT = ("actor, provider, model, price_revision, config_sha256, cache_mode, max_input, max_output, operation_id, "
          "intent_sha256, reserved_usd, state, provider_request_id, usage_sha256, actual_tier, actual_usd, overrun, "
          "intent_version, request_sha256, count_state, counted_input_tokens, count_source, contract_block, diagnostic")
# Fixed column lists only (no input): S608 does not apply.
APP_SCOPE = f"SELECT {COUNTERS} FROM app.budget_scopes WHERE id = :id FOR UPDATE"  # noqa: S608
EVAL_SCOPE = f"SELECT {COUNTERS} FROM evaluation.budget_scopes WHERE id = :id FOR UPDATE"  # noqa: S608
APP_ATTEMPT = f"SELECT id, scope_id, {INTENT} FROM app.usage_attempts WHERE id = :id FOR UPDATE"  # noqa: S608
EVAL_ATTEMPT = (f"SELECT id, study_scope_id, invocation_scope_id, scenario_scope_id, {INTENT} "  # noqa: S608
                "FROM evaluation.usage_attempts WHERE id = :id FOR UPDATE")
SET_SCOPE = ("SET spent_usd = :spent_usd, held_usd = :held_usd, calls_consumed = :calls_consumed, "
             "calls_held = :calls_held, overrun = :overrun, counts_used = :counts_used, "
             "contract_block = :contract_block, updated_at = greatest(updated_at, :now), "
             "version = version + 1 WHERE id = :id")
SET_ATTEMPT = ("SET state = :state, provider_request_id = :provider_request_id, usage = CAST(:usage AS jsonb), "
               "usage_sha256 = :usage_sha256, actual_tier = :actual_tier, actual_usd = :actual_usd, "
               "overrun = :overrun, count_state = :count_state, counted_input_tokens = :counted_input_tokens, "
               "count_source = :count_source, contract_block = :contract_block, "
               "diagnostic = CAST(:diagnostic AS jsonb), updated_at = greatest(updated_at, :now), "
               "version = version + 1 WHERE id = :id")
INSERT_COLUMNS = ("actor, provider, model, price_revision, config_sha256, cache_mode, max_input, max_output, "
                  "operation_id, intent_sha256, reserved_usd, state, intent_version, request_sha256, created_at, "
                  "updated_at")
INSERT_VALUES = (":actor, :provider, :model, :price_revision, :config_sha256, :cache_mode, :max_input, :max_output, "
                 ":operation_id, :intent_sha256, :reserved_usd, 'reserved', 2, :request_sha256, :now, :now")
APP_INSERT_ATTEMPT = (f"INSERT INTO app.usage_attempts (id, workspace_id, scope_id, {INSERT_COLUMNS}) "  # noqa: S608
                      f"VALUES (:id, app.current_workspace(), :scope_id, {INSERT_VALUES})")
EVAL_INSERT_ATTEMPT = ("INSERT INTO evaluation.usage_attempts (id, study_scope_id, invocation_scope_id, "  # noqa: S608
                       f"scenario_scope_id, {INSERT_COLUMNS}) VALUES (:id, :study, :invocation, :scenario, "
                       f"{INSERT_VALUES})")
INSERT_SCOPE = ("INSERT INTO app.budget_scopes (id, workspace_id, kind, run_id, operation_kind, operation_key, "
                "cap_usd, cap_calls, cap_counts, created_at, updated_at) VALUES (:id, app.current_workspace(), "
                ":kind, :run_id, :operation_kind, :operation_key, :cap_usd, :cap_calls, :cap_calls, :now, :now) ")
INSERT_RUN_SCOPE = INSERT_SCOPE + "ON CONFLICT (workspace_id, run_id) DO NOTHING"
INSERT_OPERATION_SCOPE = INSERT_SCOPE + "ON CONFLICT (workspace_id, operation_kind, operation_key) DO NOTHING"
FIND_RUN_SCOPE = "SELECT id, cap_usd, cap_calls, cap_counts FROM app.budget_scopes WHERE run_id = :run_id"
FIND_OPERATION_SCOPE = ("SELECT id, cap_usd, cap_calls, cap_counts FROM app.budget_scopes "
                        "WHERE operation_kind = :operation_kind AND operation_key = :operation_key")


def _one(connection: Connection, sql: str, params: Mapping[str, Any]) -> dict[str, Any] | None:
    row = connection.execute(text(sql), dict(params)).mappings().first()
    return dict(row) if row is not None else None


@contextmanager
def _unique_is_conflict(message: str) -> Iterator[None]:
    try:
        yield
    except IntegrityError as error:
        if isinstance(error.orig, pg_errors.UniqueViolation):
            raise LedgerConflict(message) from None
        if isinstance(error.orig, pg_errors.ForeignKeyViolation):
            raise NotFound(message) from None
        raise


KINDS: dict[object, ScopeKind] = {"run": "run", "operation": "operation", "study": "study",
                                  "invocation": "invocation", "scenario": "scenario"}


def _kind(value: object) -> ScopeKind:
    kind = KINDS.get(value)
    if kind is None:
        raise ValueError(f"unknown scope kind {value!r}")
    return kind


def _scope(row: Mapping[str, Any]) -> Scope:
    return Scope(row["id"], _kind(row["kind"]), row["cap_usd"], row["cap_calls"], row["spent_usd"], row["held_usd"],
                 row["calls_consumed"], row["calls_held"], row["overrun"], row["cap_counts"], row["counts_used"],
                 row["contract_block"])


def _diagnostic(value: Any) -> Diagnostic | None:
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("v") != "policyops.usage-diagnostic/v1":
        raise ValueError("an unrecognised stored diagnostic")
    return Diagnostic(tuple(value["codes"]), value["counts"])


def _attempt(row: Mapping[str, Any], scope_ids: tuple[UUID, ...]) -> Attempt:
    intent = Intent(row["actor"], row["provider"], row["model"], row["price_revision"], row["config_sha256"],
                    row["cache_mode"], row["max_input"], row["max_output"], row["operation_id"], row["reserved_usd"],
                    scope_ids, row["request_sha256"], row["intent_version"])
    return Attempt(row["id"], intent, row["intent_sha256"], row["state"], row["provider_request_id"],
                   row["usage_sha256"], row["actual_tier"], row["actual_usd"], row["overrun"], row["count_state"],
                   row["counted_input_tokens"], row["count_source"], row["contract_block"],
                   _diagnostic(row["diagnostic"]))


def _intent_params(attempt: Attempt, now: datetime) -> dict[str, Any]:
    intent = attempt.intent
    return {"id": attempt.id, "actor": intent.actor, "provider": intent.provider, "model": intent.model,
            "price_revision": intent.price_revision, "config_sha256": intent.config_sha256,
            "cache_mode": intent.cache_mode, "max_input": intent.max_input,
            "max_output": intent.max_output, "operation_id": intent.operation_id,
            "intent_sha256": attempt.intent_sha256, "reserved_usd": intent.reserved_usd,
            "request_sha256": intent.request_sha256, "now": now}


def _settlement_params(attempt: Attempt, now: datetime, settlement: Settlement | None) -> dict[str, Any]:
    return {"id": attempt.id, "state": attempt.state, "provider_request_id": attempt.provider_request_id,
            "usage": None if settlement is None else json.dumps(settlement.canonical(), sort_keys=True),
            "usage_sha256": attempt.usage_sha256, "actual_tier": attempt.actual_tier,
            "actual_usd": attempt.actual_usd, "overrun": attempt.overrun, "count_state": attempt.count_state,
            "counted_input_tokens": attempt.counted_input_tokens, "count_source": attempt.count_source,
            "contract_block": attempt.contract_block,
            "diagnostic": None if attempt.diagnostic is None else json.dumps(attempt.diagnostic.canonical(),
                                                                              sort_keys=True),
            "now": now}


def _scope_params(scope: Scope, now: datetime) -> dict[str, Any]:
    return {"id": scope.id, "spent_usd": scope.spent_usd, "held_usd": scope.held_usd,
            "calls_consumed": scope.calls_consumed, "calls_held": scope.calls_held, "overrun": scope.overrun,
            "counts_used": scope.counts_used, "contract_block": scope.contract_block, "now": now}


def _same_caps(row: Mapping[str, Any], cap_usd: Decimal, cap_calls: int, what: str) -> None:
    # The count resource is one count per possible call (cap_counts = cap_calls), also for backfilled 0006 scopes.
    if row["cap_usd"] != cap_usd or row["cap_calls"] != cap_calls or row["cap_counts"] != cap_calls:
        raise LedgerConflict(f"the {what} budget already exists with different caps")


# -- app ---------------------------------------------------------------------------------------------------------

def workspace_liability(connection: Connection) -> Decimal:
    """Read settled plus held USD under the current workspace's RLS scope."""
    return Decimal(connection.execute(text(
        "SELECT coalesce(sum(spent_usd + held_usd), 0) FROM app.budget_scopes"
    )).scalar_one())


@dataclass
class _AppTransaction:
    connection: Connection
    clock: LeaseClock
    claim_token: ClaimToken | None
    workspace_max_usd: Decimal | None

    def _lock_workspace_budget(self) -> None:
        self.connection.execute(text(
            "SELECT pg_advisory_xact_lock(hashtextextended('policyops:budget:' || app.current_workspace()::text, 0))"
        ))

    def _admit_run(self, run_id: UUID) -> None:
        token = self.claim_token
        if token is None:
            raise runs.Fenced("claim_required")
        if token.run_id != run_id:
            raise runs.Fenced("binding_changed")
        run, job, _ = runs.check_fence(self.connection, token, self.clock, active=True)
        if run.state != "running" or job.kind != runs.EXECUTE_KIND:
            raise runs.Fenced("not_investigation_claim")

    def now(self) -> datetime:
        return self.clock.now(self.connection)

    def bind(self, binding: Binding, caps: Caps) -> tuple[ScopeRef, ...]:
        if isinstance(binding, RunBinding):
            self._admit_run(binding.run_id)
            params: dict[str, Any] = {"run_id": binding.run_id, "operation_kind": None, "operation_key": None}
            kind: ScopeKind = "run"
            insert, find, cap_usd, cap_calls = INSERT_RUN_SCOPE, FIND_RUN_SCOPE, caps.run_usd, caps.run_calls
        elif isinstance(binding, OperationBinding):
            params = {"run_id": None, "operation_kind": binding.kind, "operation_key": binding.key}
            kind, insert, find = "operation", INSERT_OPERATION_SCOPE, FIND_OPERATION_SCOPE
            cap_usd, cap_calls = caps.operation_usd, caps.operation_calls
        else:
            raise TypeError("the app ledger accepts run and operation bindings only")
        params |= {"id": uuid4(), "kind": kind, "cap_usd": cap_usd, "cap_calls": cap_calls, "now": self.now()}
        self.connection.execute(text(insert), params)
        row = _one(self.connection, find, params)
        if row is None:
            raise NotFound(f"no {kind} budget")
        _same_caps(row, cap_usd, cap_calls, kind)
        return (ScopeRef.of(kind, row["id"]),)

    def attempt_refs(self, attempt_id: UUID) -> tuple[ScopeRef, ...] | None:
        row = _one(self.connection, "SELECT a.scope_id, s.kind FROM app.usage_attempts a JOIN app.budget_scopes s "
                   "ON s.workspace_id = a.workspace_id AND s.id = a.scope_id WHERE a.id = :id", {"id": attempt_id})
        return None if row is None else (ScopeRef.of(_kind(row["kind"]), row["scope_id"]),)

    def run_active(self, refs: Sequence[ScopeRef]) -> bool:
        self.check_admission(refs)
        return True

    def check_admission(self, refs: Sequence[ScopeRef]) -> None:
        for ref in refs:
            if ref.kind == "run":
                row = _one(self.connection, "SELECT run_id FROM app.budget_scopes WHERE id = :id",
                           {"id": ref.id})
                if row is None:
                    raise NotFound("no run budget scope")
                self._admit_run(row["run_id"])

    def lock_scopes(self, refs: Sequence[ScopeRef]) -> list[Scope]:
        scopes = []
        for ref in refs:
            row = _one(self.connection, APP_SCOPE, {"id": ref.id})
            if row is None:
                raise NotFound(f"no budget scope {ref.id}")
            scopes.append(_scope(row))
        return scopes

    def lock_attempt(self, attempt_id: UUID) -> Attempt | None:
        row = _one(self.connection, APP_ATTEMPT, {"id": attempt_id})
        return None if row is None else _attempt(row, (row["scope_id"],))

    def insert_attempt(self, attempt: Attempt, now: datetime) -> None:
        if self.workspace_max_usd is not None:
            self._lock_workspace_budget()
            if workspace_liability(self.connection) + attempt.intent.reserved_usd > self.workspace_max_usd:
                raise BudgetExhausted("workspace", "usd_cap")
        (scope_id,) = attempt.intent.scope_ids
        with _unique_is_conflict(f"attempt {attempt.id} already exists"):
            self.connection.execute(text(APP_INSERT_ATTEMPT), _intent_params(attempt, now) | {"scope_id": scope_id})

    def update_attempt(self, attempt: Attempt, now: datetime, settlement: Settlement | None = None) -> None:
        with _unique_is_conflict(f"provider request {attempt.provider_request_id!r} belongs to another attempt"):
            self.connection.execute(text("UPDATE app.usage_attempts " + SET_ATTEMPT),
                                    _settlement_params(attempt, now, settlement))

    def update_scope(self, scope: Scope, now: datetime) -> None:
        if self.workspace_max_usd is not None:
            self._lock_workspace_budget()
        self.connection.execute(text("UPDATE app.budget_scopes " + SET_SCOPE), _scope_params(scope, now))

    def record_usage(self, attempt: Attempt, settlement: Settlement, now: datetime) -> None:
        (scope_id,) = attempt.intent.scope_ids
        usage = settlement.usage
        params = {"id": uuid4(), "scope_id": scope_id, "attempt_id": attempt.id, "actor": attempt.intent.actor,
                  "provider": attempt.intent.provider, "model": attempt.intent.model,
                  "provider_request_id": settlement.provider_request_id, "uncached": usage.ordinary_input,
                  "cache_read": usage.cache_read, "cache_write": sum(usage.cache_writes.values()),
                  # usage_events.reasoning_tokens is NOT NULL (0002): an unreported count is stored as 0 there,
                  # while the attempt's canonical usage (v2) keeps it as null.
                  "output": usage.output, "reasoning": usage.reasoning or 0,
                  "price_revision": attempt.intent.price_revision, "cost_usd": attempt.actual_usd, "now": now}
        with _unique_is_conflict(f"provider request {settlement.provider_request_id!r} was already recorded"):
            self.connection.execute(text(
                "INSERT INTO app.usage_events (id, workspace_id, attempt_id, run_id, actor, provider, model, "
                "provider_request_id, uncached_input_tokens, cache_read_tokens, cache_write_tokens, output_tokens, "
                "reasoning_tokens, price_revision, cost_status, cost_usd, created_at) SELECT :id, s.workspace_id, "
                ":attempt_id, s.run_id, :actor, :provider, :model, :provider_request_id, :uncached, :cache_read, "
                ":cache_write, :output, :reasoning, :price_revision, 'known', :cost_usd, :now "
                "FROM app.budget_scopes s WHERE s.id = :scope_id"), params)


def _checked_clock(env: str, clock: LeaseClock | None) -> LeaseClock:
    lease_clock = clock or DatabaseLeaseClock()
    require_test_environment(lease_clock, env)  # before any database access
    return lease_clock


class AppLedgerStore:
    def __init__(self, engine: Engine, workspace_id: UUID, *, env: str, clock: LeaseClock | None = None,
                 claim_token: ClaimToken | None = None, workspace_max_usd: Decimal | None = None) -> None:
        self.clock = _checked_clock(env, clock)
        if not isinstance(workspace_id, UUID):
            raise TypeError("workspace_id must be a UUID")
        verify_runtime_role(engine, APP_RUNTIME)
        self.engine = engine
        self.workspace_id = workspace_id
        if claim_token is not None and claim_token.workspace_id != workspace_id:
            raise runs.Fenced("binding_changed")
        self.claim_token = claim_token
        self.workspace_max_usd = workspace_max_usd

    @contextmanager
    def transaction(self) -> Iterator[_AppTransaction]:
        with workspace_transaction(self.engine, self.workspace_id) as connection:
            yield _AppTransaction(connection, self.clock, self.claim_token, self.workspace_max_usd)

    def run_scope(self, run_id: UUID) -> Scope | None:
        with workspace_transaction(self.engine, self.workspace_id) as connection:
            row = _one(connection, f"SELECT {COUNTERS} FROM app.budget_scopes WHERE run_id = :run_id",  # noqa: S608
                       {"run_id": run_id})
        return None if row is None else _scope(row)


# -- evaluation --------------------------------------------------------------------------------------------------

@dataclass
class _EvalTransaction:
    connection: Connection
    clock: LeaseClock
    claim_token: EvaluationClaimToken | None = None

    def check_admission(self, refs: Sequence[ScopeRef]) -> None:
        if self.claim_token is not None:
            check_claim_admission(self.connection, self.claim_token, refs)
        else:
            for ref in refs:
                if ref.kind == "scenario" and self.connection.execute(text(
                    "SELECT EXISTS (SELECT 1 FROM evaluation.trial_claims WHERE scenario_scope = :id)"
                ), {"id": ref.id}).scalar_one():
                    raise LedgerConflict("evaluation_claim_required")

    def now(self) -> datetime:
        return self.clock.now(self.connection)

    def bind(self, binding: Binding, caps: Caps) -> tuple[ScopeRef, ...]:
        del caps  # evaluation scopes are ensured explicitly, with their caps, before any reservation
        if not isinstance(binding, EvalBinding):
            raise TypeError("the evaluation ledger accepts evaluation bindings only")
        rows = self.connection.execute(text(
            "SELECT id, kind, parent_id FROM evaluation.budget_scopes WHERE id IN (:study, :invocation, :scenario)"),
            {"study": binding.study_id, "invocation": binding.invocation_id,
             "scenario": binding.scenario_id}).mappings().all()
        found = {row["id"]: row for row in rows}
        expected = ((binding.study_id, "study", None), (binding.invocation_id, "invocation", binding.study_id),
                    (binding.scenario_id, "scenario", binding.study_id))
        for scope_id, kind, parent in expected:
            row = found.get(scope_id)
            if row is None or row["kind"] != kind or row["parent_id"] != parent:
                raise NotFound(f"no {kind} {scope_id} in study {binding.study_id}")
        return (ScopeRef.of("study", binding.study_id), ScopeRef.of("invocation", binding.invocation_id),
                ScopeRef.of("scenario", binding.scenario_id))

    def attempt_refs(self, attempt_id: UUID) -> tuple[ScopeRef, ...] | None:
        row = _one(self.connection, "SELECT study_scope_id, invocation_scope_id, scenario_scope_id FROM "
                   "evaluation.usage_attempts WHERE id = :id", {"id": attempt_id})
        if row is None:
            return None
        return (ScopeRef.of("study", row["study_scope_id"]), ScopeRef.of("invocation", row["invocation_scope_id"]),
                ScopeRef.of("scenario", row["scenario_scope_id"]))

    def run_active(self, refs: Sequence[ScopeRef]) -> bool:
        self.check_admission(refs)
        return True

    def lock_scopes(self, refs: Sequence[ScopeRef]) -> list[Scope]:
        if self.claim_token is not None:
            expected = self.claim_token.binding
            if {ref.id for ref in refs} != {expected.study_id, expected.invocation_id, expected.scenario_id}:
                raise LedgerConflict("evaluation_claim_binding_changed")
        else:
            for ref in refs:
                if ref.kind == "scenario" and self.connection.execute(text(
                    "SELECT id FROM evaluation.trial_claims WHERE scenario_scope = :id FOR UPDATE"
                ), {"id": ref.id}).first() is not None:
                    raise LedgerConflict("evaluation_claim_required")
        scopes = []
        for ref in refs:
            row = _one(self.connection, EVAL_SCOPE, {"id": ref.id})
            if row is None or row["kind"] != ref.kind:
                raise NotFound(f"no budget scope {ref.id}")
            scopes.append(_scope(row))
        return scopes

    def lock_attempt(self, attempt_id: UUID) -> Attempt | None:
        row = _one(self.connection, EVAL_ATTEMPT, {"id": attempt_id})
        if row is None:
            return None
        return _attempt(row, (row["study_scope_id"], row["invocation_scope_id"], row["scenario_scope_id"]))

    def insert_attempt(self, attempt: Attempt, now: datetime) -> None:
        study, invocation, scenario = attempt.intent.scope_ids  # lock order: study < invocation < scenario
        with _unique_is_conflict(f"attempt {attempt.id} already exists"):
            self.connection.execute(text(EVAL_INSERT_ATTEMPT), _intent_params(attempt, now)
                                    | {"study": study, "invocation": invocation, "scenario": scenario})

    def update_attempt(self, attempt: Attempt, now: datetime, settlement: Settlement | None = None) -> None:
        with _unique_is_conflict(f"provider request {attempt.provider_request_id!r} belongs to another attempt"):
            self.connection.execute(text("UPDATE evaluation.usage_attempts " + SET_ATTEMPT),
                                    _settlement_params(attempt, now, settlement))

    def update_scope(self, scope: Scope, now: datetime) -> None:
        self.connection.execute(text("UPDATE evaluation.budget_scopes " + SET_SCOPE), _scope_params(scope, now))

    def record_usage(self, attempt: Attempt, settlement: Settlement, now: datetime) -> None:
        del attempt, settlement, now  # evaluation usage is kept on the attempt row


def _eval_scope_row(connection: Connection, scope_id: UUID) -> dict[str, Any] | None:
    return _one(connection, "SELECT id, kind, parent_id, study_key, manifest_sha256, task_id, trial_index, "
                "config_sha256, cap_usd, cap_calls, cap_counts FROM evaluation.budget_scopes WHERE id = :id",
                {"id": scope_id})


class EvalLedgerStore:
    def __init__(self, engine: Engine, *, env: str, clock: LeaseClock | None = None,
                 claim_token: EvaluationClaimToken | None = None) -> None:
        self.clock = _checked_clock(env, clock)
        verify_runtime_role(engine, EVAL_RUNTIME)
        self.engine = engine
        self.claim_token = claim_token

    @contextmanager
    def transaction(self) -> Iterator[_EvalTransaction]:
        with transaction(self.engine) as connection:
            if self.claim_token is not None:
                lock_claim(connection, self.claim_token)  # always before scope/attempt, including settlement
            yield _EvalTransaction(connection, self.clock, self.claim_token)

    def ensure_study(self, study_key: str, manifest_sha256: str, *, cap_usd: Decimal, cap_calls: int) -> UUID:
        """The study's one scope. The same key with the same manifest and caps is a replay; anything else conflicts,
        so a new invocation or process cannot reset the study's spend."""
        if not isinstance(study_key, str) or not 1 <= len(study_key) <= 200:
            raise ValueError("a study key has 1-200 characters")
        if not isinstance(manifest_sha256, str) or not SHA256.fullmatch(manifest_sha256):
            raise ValueError("a manifest digest is 64 lowercase hex characters")
        _check_caps(cap_usd, cap_calls)
        with transaction(self.engine) as connection:
            connection.execute(text(
                "INSERT INTO evaluation.budget_scopes (id, kind, study_key, manifest_sha256, cap_usd, cap_calls, "
                "cap_counts, created_at, updated_at) VALUES (:id, 'study', :key, :manifest, :cap_usd, :cap_calls, "
                ":cap_calls, :now, :now) "
                "ON CONFLICT (study_key) DO NOTHING"),
                {"id": uuid4(), "key": study_key, "manifest": manifest_sha256, "cap_usd": cap_usd,
                 "cap_calls": cap_calls, "now": self.clock.now(connection)})
            row = _one(connection, "SELECT id, manifest_sha256, cap_usd, cap_calls, cap_counts FROM "
                       "evaluation.budget_scopes "
                       "WHERE study_key = :key", {"key": study_key})
        if row is None:
            raise NotFound(f"no study {study_key!r}")
        if row["manifest_sha256"] != manifest_sha256:
            raise LedgerConflict(f"study {study_key!r} exists for a different manifest")
        _same_caps(row, cap_usd, cap_calls, "study")
        study_id: UUID = row["id"]
        return study_id

    def ensure_invocation(self, study_id: UUID, invocation_id: UUID, caps: Caps) -> UUID:
        with transaction(self.engine) as connection, _unique_is_conflict(f"no study {study_id}"):
            connection.execute(text(
                "INSERT INTO evaluation.budget_scopes (id, kind, parent_id, parent_kind, cap_usd, cap_calls, "
                "cap_counts, created_at, updated_at) VALUES (:id, 'invocation', :study, 'study', :cap_usd, :cap_calls, "
                ":cap_calls, :now, :now) "
                "ON CONFLICT (id) DO NOTHING"),
                {"id": invocation_id, "study": study_id, "cap_usd": caps.invocation_usd,
                 "cap_calls": caps.invocation_calls, "now": self.clock.now(connection)})
            row = _eval_scope_row(connection, invocation_id)
        if row is None or row["kind"] != "invocation" or row["parent_id"] != study_id:
            raise LedgerConflict(f"scope {invocation_id} is not an invocation of study {study_id}")
        _same_caps(row, caps.invocation_usd, caps.invocation_calls, "invocation")
        return invocation_id

    def ensure_scenario(self, study_id: UUID, task_id: str, trial_index: int, config_sha256: str, caps: Caps) -> UUID:
        if not isinstance(task_id, str) or not 1 <= len(task_id) <= 100:
            raise ValueError("a task ID has 1-100 characters")
        if isinstance(trial_index, bool) or not isinstance(trial_index, int) or not 0 <= trial_index <= 1000:
            raise ValueError("a trial index is 0-1000")
        if not isinstance(config_sha256, str) or not SHA256.fullmatch(config_sha256):
            raise ValueError("a configuration digest is 64 lowercase hex characters")
        params = {"id": uuid4(), "study": study_id, "task": task_id, "trial": trial_index, "config": config_sha256,
                  "cap_usd": caps.scenario_usd, "cap_calls": caps.scenario_calls}
        with transaction(self.engine) as connection, _unique_is_conflict(f"no study {study_id}"):
            connection.execute(text(
                "INSERT INTO evaluation.budget_scopes (id, kind, parent_id, parent_kind, task_id, trial_index, "
                "config_sha256, cap_usd, cap_calls, cap_counts, created_at, updated_at) VALUES (:id, 'scenario', "
                ":study, 'study', :task, :trial, :config, :cap_usd, :cap_calls, :cap_calls, :now, :now) "
                "ON CONFLICT (parent_id, task_id, trial_index, config_sha256) DO NOTHING"),
                params | {"now": self.clock.now(connection)})
            row = _one(connection, "SELECT id, cap_usd, cap_calls, cap_counts FROM evaluation.budget_scopes WHERE "
                       "parent_id = "
                       ":study AND task_id = :task AND trial_index = :trial AND config_sha256 = :config", params)
        if row is None:
            raise NotFound(f"no study {study_id}")
        _same_caps(row, caps.scenario_usd, caps.scenario_calls, "scenario")
        scenario_id: UUID = row["id"]
        return scenario_id

    def scope(self, scope_id: UUID) -> Scope | None:
        """An unlocked snapshot (for preflight availability); reservations remain the authority."""
        with transaction(self.engine) as connection:
            row = _one(connection, f"SELECT {COUNTERS} FROM evaluation.budget_scopes WHERE id = :id",  # noqa: S608
                       {"id": scope_id})
        return None if row is None else _scope(row)

    def study_by_key(self, study_key: str) -> Scope | None:
        with transaction(self.engine) as connection:
            row = _one(connection, f"SELECT {COUNTERS} FROM evaluation.budget_scopes "  # noqa: S608
                       "WHERE study_key = :key", {"key": study_key})
        return None if row is None else _scope(row)


def _check_caps(cap_usd: Decimal, cap_calls: int) -> None:
    if not isinstance(cap_usd, Decimal) or cap_usd <= 0:
        raise ValueError("a cap is a positive Decimal")
    exact_usd(cap_usd, "cap_usd")
    if isinstance(cap_calls, bool) or not isinstance(cap_calls, int) or cap_calls < 1:
        raise ValueError("a call cap is a positive integer")


# -- composition -------------------------------------------------------------------------------------------------

def build_app_ledger(*, env: str, engine: Engine, workspace_id: UUID, configuration: Configuration,
                     clock: LeaseClock | None = None, earlier_snapshots: Sequence[PriceSnapshot] = (),
                     claim_token: ClaimToken | None = None, workspace_max_usd: Decimal | None = None) -> Ledger:
    return Ledger(AppLedgerStore(engine, workspace_id, env=env, clock=clock, claim_token=claim_token,
                                 workspace_max_usd=workspace_max_usd),
                  configuration, earlier_snapshots)


def build_eval_ledger(*, env: str, engine: Engine, configuration: Configuration, clock: LeaseClock | None = None,
                      earlier_snapshots: Sequence[PriceSnapshot] = ()) -> tuple[Ledger, EvalLedgerStore]:
    store = EvalLedgerStore(engine, env=env, clock=clock)
    return Ledger(store, configuration, earlier_snapshots), store
