"""Offline study doubles; PostgreSQL races/grants are verified separately."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from policyops.budget.config import Caps
from policyops.budget.ledger import Binding, EvalBinding, LedgerConflict, Scope, ScopeRef
from policyops.persistence.evaluation import (
    EvaluationClaimToken,
    EvaluationRun,
    EvaluationTrial,
    Slot,
    StudyLock,
    result_digest,
)

from .t29_support import MemoryStore


class StudyStore(MemoryStore):
    def __init__(self) -> None:
        super().__init__(EvalBinding(uuid4(), uuid4(), uuid4()))
        self.scopes.clear()
        self.study: tuple[str, str, Decimal, int, UUID] | None = None
        self.scenarios: dict[tuple[UUID, str, int, str], UUID] = {}

    def ensure_study(self, key: str, digest: str, *, cap_usd: Decimal, cap_calls: int) -> UUID:
        if self.study is not None:
            if self.study[:4] != (key, digest, cap_usd, cap_calls):
                raise LedgerConflict("immutable_study_conflict")
            return self.study[4]
        identity = uuid4()
        self.study = key, digest, cap_usd, cap_calls, identity
        self.scopes[identity] = Scope(identity, "study", cap_usd, cap_calls, Decimal(0), Decimal(0), 0, 0, False,
                                      cap_counts=cap_calls)
        return identity

    def ensure_invocation(self, study_id: UUID, invocation_id: UUID, caps: Caps) -> UUID:
        self.scopes[invocation_id] = Scope(invocation_id, "invocation", caps.invocation_usd, caps.invocation_calls,
            Decimal(0), Decimal(0), 0, 0, False, cap_counts=caps.invocation_calls)
        return invocation_id

    def ensure_scenario(self, study_id: UUID, task_id: str, trial_index: int, digest: str, caps: Caps) -> UUID:
        key = study_id, task_id, trial_index, digest
        if key not in self.scenarios:
            identity = uuid4()
            self.scenarios[key] = identity
            self.scopes[identity] = Scope(identity, "scenario", caps.scenario_usd, caps.scenario_calls,
                Decimal(0), Decimal(0), 0, 0, False, cap_counts=caps.scenario_calls)
        return self.scenarios[key]

    def bind(self, binding: Binding, caps: Caps) -> tuple[ScopeRef, ...]:
        assert isinstance(binding, EvalBinding)
        return (ScopeRef.of("study", binding.study_id), ScopeRef.of("invocation", binding.invocation_id),
                ScopeRef.of("scenario", binding.scenario_id))

    def attempt_refs(self, attempt_id: UUID) -> tuple[ScopeRef, ...] | None:
        attempt = self.attempts.get(attempt_id)
        return None if attempt is None else tuple(ScopeRef.of(self.scopes[i].kind, i) for i in attempt.intent.scope_ids)

    def scope(self, identity: UUID) -> Scope:
        return self.scopes[identity]


class Repository:
    def __init__(self, store: StudyStore) -> None:
        self.store = store
        self.runs: dict[UUID, EvaluationRun] = {}
        self.schedule_rows: dict[UUID, Slot] = {}
        self.tokens: dict[UUID, EvaluationClaimToken] = {}
        self.terminals: dict[UUID, EvaluationTrial] = {}
        self.claims = 0
        self.lease = False

    @contextmanager
    def study_lock(self, study_id: UUID) -> Iterator[StudyLock]:
        assert not self.lease
        self.lease = True
        try:
            yield StudyLock(study_id, 100)
        finally:
            self.lease = False

    def ensure_run(self, run: EvaluationRun) -> UUID:
        if run.id in self.runs:
            assert self.runs[run.id].config_json == run.config_json
        else:
            self.runs[run.id] = run
        return run.id

    def schedule(self, slot: Slot) -> None:
        if slot.id not in self.schedule_rows:
            self.schedule_rows[slot.id] = slot
        else:
            assert replace(self.schedule_rows[slot.id], state=slot.state) == slot

    def slots(self, run_id: UUID) -> list[Slot]:
        return [s for s in self.schedule_rows.values() if s.run_id == run_id]

    def claim(self, slot: Slot, invocation: UUID, lease: StudyLock) -> EvaluationClaimToken | None:
        if self.schedule_rows[slot.id].state != "scheduled":
            return None
        self.claims += 1
        token = EvaluationClaimToken(slot.id, uuid4(), EvalBinding(slot.study_id, invocation, slot.scenario_id),
                                     lease.pid)
        self.tokens[slot.id] = token
        self.schedule_rows[slot.id] = replace(slot, state="running")
        return token

    def finalize(self, result: EvaluationTrial, token: EvaluationClaimToken | None, lease: StudyLock) -> None:
        assert self.lease
        if result.id in self.terminals:
            if result_digest(self.terminals[result.id]) != result_digest(result):
                raise LedgerConflict("terminal_result_conflict")
            return
        assert self.tokens.get(result.id) == token
        self.terminals[result.id] = result
        self.schedule_rows[result.id] = replace(self.schedule_rows[result.id], state="finalized")

    def abort(self, slot: Slot, lease: StudyLock, *, reason: str = "abandoned_claim") -> None:
        if slot.id in self.terminals:
            return
        self.finalize(EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id, task_id=slot.task_id,
            trial_index=slot.trial_index, seed=slot.seed, outcome="aborted", reward=None, components_json="{}",
            error_class=reason, cost_status="unknown", cost_usd=None, created_at=self.store.now()),
            self.tokens.get(slot.id), lease)

    def finish_run(self, run_id: UUID, lease: StudyLock) -> None:
        assert all(s.state == "finalized" for s in self.slots(run_id))

    def results(self, run_id: UUID) -> list[dict[str, Any]]:
        return [r.model_dump() for r in self.terminals.values() if r.evaluation_run_id == run_id]

    def usage(self, scenario_id: UUID) -> dict[str, Any]:
        scope = self.store.scopes[scenario_id]
        return {k: getattr(scope, k) for k in ("spent_usd", "held_usd", "calls_consumed", "calls_held", "counts_used",
                                               "overrun", "contract_block")}

    def actor_attempts(self, scenario_id: UUID) -> list[dict[str, Any]]:
        return [{"id": str(a.id), "actor": a.intent.actor, "actual_usd": str(a.actual_usd), "state": a.state}
                for a in self.store.attempts.values() if a.intent.scope_ids[-1] == scenario_id]

    def unresolved_attempts(self, study_id: UUID) -> int:
        return sum(a.state in {"dispatching", "unresolved"} and study_id in a.intent.scope_ids
                   for a in self.store.attempts.values())
