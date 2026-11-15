"""Offline runner invariants; the memory repository simulates durable claims across invocations."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
import json
from pathlib import Path
import time
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine

from policyops.budget.ledger import EvalBinding, Ledger
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import (
    EvaluationClaimToken,
    EvaluationRepository,
    EvaluationRun,
    EvaluationTrial,
    Slot,
    StudyLock,
)
from policyops.persistence.retrieval import RetrievalStore, Snapshot, StepRefused
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies.config import QAStudy, RetrievalOnly, load_study
from policyops_evals.qa_studies.registration import run_id
from policyops_testing.retrieval_fixtures import TOKENIZER

from .test_qa_study_config import parse
from .test_qa_study_registration import SOURCE


ADMIT = r.admit


@pytest.mark.parametrize("lexical_mode", ["all_terms", "any_terms", "bm25"])
def test_executor_passes_lexical_mode_and_records_cap_refusal(monkeypatch: pytest.MonkeyPatch,
                                                           lexical_mode: str) -> None:
    study, inputs = fixture_study()
    value = study.arms[0].model_dump(mode="json")
    value["retrieval"]["lexical_mode"] = lexical_mode
    arm = RetrievalOnly.model_validate_json(json.dumps(value))
    executor = object.__new__(r.RetrieverExecutor)
    monkeypatch.setattr(executor, "retrieval", object.__new__(RetrievalStore), raising=False)
    monkeypatch.setattr(executor, "tokenizer", TOKENIZER, raising=False)
    monkeypatch.setattr(executor, "corpus", "fictional-corpus", raising=False)
    generation = uuid4()
    monkeypatch.setattr(executor, "generation", generation, raising=False)
    calls: list[dict[str, Any]] = []

    def snapshot(self: RetrievalStore, **kwargs: Any) -> Snapshot:
        calls.append(kwargs)
        return Snapshot(generation, "banking_knowledge", "text-embedding-3-small", 1536, None)

    monkeypatch.setattr(RetrievalStore, "snapshot", snapshot)
    item = r.schedule(study, inputs)[0]
    assert executor.execute(arm, inputs.queries[item.question], item, cast(Ledger, object()),
                            time.monotonic() + 60) == ()
    assert calls[0]["lexical_mode"] == lexical_mode

    def too_many(self: RetrievalStore, **kwargs: Any) -> Snapshot:
        raise StepRefused("lexical_query_too_many_lexemes")

    monkeypatch.setattr(RetrievalStore, "snapshot", too_many)
    with pytest.raises(r.Refused, match=r"^lexical_query_too_many_lexemes$"):
        executor.execute(arm, inputs.queries[item.question], item, cast(Ledger, object()), time.monotonic() + 60)


def fixture_study(*, sealed: bool = False) -> tuple[QAStudy, r.Inputs]:
    value = json.loads((Path(__file__).parents[1] / "qa_studies/g1-dev-retrieval-v1.json").read_bytes())
    value["study_id"] = str(uuid4())
    value["provenance"]["locks"] = [{"path": k, "sha256": v} for k, v in SOURCE["lock_sha256"].items()]
    cohort = value["schedule"]["cohorts"][0]
    cohort.update(question_count=2, dialogue_count=1)
    for comparison in value["analysis"]["comparisons"]:
        comparison["required_questions"] = 2
    split = "validation" if sealed else "train"
    cohort["split"] = split
    value["purpose"] = "sealed_test" if sealed else "dev"
    ids = tuple("md2d.q/" + split + "/fictional/" + str(i) for i in range(2))
    inputs = r.Inputs({q: r.QueryInput(q, "fictional/dialogue", "user: earlier [SEP] user: refunds", "user: refunds")
                       for q in ids}, {q: r.Gold(("md2d.p/" + "a" * 64,), "responding") for q in ids}, {"dev": ids})
    return parse(value), inputs


class Memory:
    def __init__(self) -> None:
        self.engine = cast(Engine, object())
        self.scope = uuid4()
        self.configs: dict[UUID, dict[str, Any]] = {}
        self.claims: dict[UUID, Slot] = {}
        self.rows: dict[UUID, dict[str, Any]] = {}
        self.dispatches: set[UUID] = set()
        self.unknown = False

    def repository(self) -> EvaluationRepository:
        return cast(EvaluationRepository, self)

    def store(self) -> EvalLedgerStore:
        return cast(EvalLedgerStore, self)

    def ensure_study(self, *args: Any, **kwargs: Any) -> UUID:
        return self.scope

    @contextmanager
    def study_lock(self, study: UUID) -> Iterator[StudyLock]:
        yield StudyLock(study, 7)

    def run_configuration(self, identity: UUID) -> dict[str, Any] | None:
        return self.configs.get(identity)

    def ensure_run(self, run: EvaluationRun) -> UUID:
        config = json.loads(run.config_json)
        assert run.id not in self.configs or self.configs[run.id] == config
        self.configs[run.id] = config
        return run.id

    def slots(self, run: UUID) -> list[Slot]:
        return [s for s in self.claims.values() if s.run_id == run]

    def ensure_invocation(self, study: UUID, identity: UUID, caps: Any) -> UUID:
        return identity

    def ensure_scenario(self, study: UUID, task: str, repetition: int, config: str, caps: Any) -> UUID:
        return uuid4()

    def schedule(self, slot: Slot) -> None:
        self.claims.setdefault(slot.id, slot)

    def claim(self, slot: Slot, invocation: UUID, lease: StudyLock) -> EvaluationClaimToken:
        assert self.claims[slot.id].state == "scheduled"
        self.claims[slot.id] = replace(slot, state="running")
        return EvaluationClaimToken(slot.id, uuid4(), EvalBinding(slot.study_id, invocation, slot.scenario_id),
                                    lease.pid)

    def unresolved_attempts(self, scope: UUID) -> int:
        return int(self.unknown)

    def usage(self, scope: UUID) -> dict[str, Any]:
        return {"spent_usd": Decimal(0), "held_usd": Decimal("0.01") if self.unknown else Decimal(0),
                "calls_held": int(self.unknown), "overrun": False, "contract_block": None}

    def finalize(self, result: EvaluationTrial, token: EvaluationClaimToken | None, lease: StudyLock) -> None:
        assert result.id not in self.rows
        self.rows[result.id] = {"id": result.id, "components": json.loads(result.components_json),
            "cost_usd": result.cost_usd, "cost_status": result.cost_status, "latency_ms": result.latency_ms,
            "outcome": result.outcome, "error_class": result.error_class}
        self.claims[result.id] = replace(self.claims[result.id], state="finalized")

    def abort(self, slot: Slot, lease: StudyLock) -> None:
        self.finalize(EvaluationTrial(id=slot.id, evaluation_run_id=slot.run_id, task_id=slot.task_id,
            trial_index=slot.trial_index, seed=slot.seed, outcome="aborted", reward=None, components_json="{}",
            error_class="abandoned_claim", cost_status="unknown", cost_usd=None, created_at=datetime.now(UTC)),
            None, lease)

    def results(self, run: UUID) -> list[dict[str, Any]]:
        return [row for identity, row in self.rows.items() if self.claims[identity].run_id == run]

    def finish_run(self, run: UUID, lease: StudyLock) -> None:
        pass


class Executor:
    def __init__(self, memory: Memory) -> None:
        self.memory = memory
        self.crash = False

    def needs_embedding(self, arm: RetrievalOnly, query: r.QueryInput) -> bool:
        return False

    def binding(self) -> dict[str, str]:
        return {"fictional": "offline"}

    def preprocessing(self) -> r.SharedUsage:
        return r.SharedUsage()

    def execute(self, arm: RetrievalOnly, query: r.QueryInput, identity: r.Scheduled,
                ledger: Ledger, deadline: float) -> tuple[str, ...]:
        assert identity.id not in self.memory.dispatches
        assert not hasattr(query, "gold") and not hasattr(query, "passage_ids")
        self.memory.dispatches.add(identity.id)
        if self.crash:
            self.crash = False
            self.memory.unknown = True
            raise SystemExit("simulated process loss after dispatch")
        return ("md2d.p/" + "a" * 64,)


@pytest.fixture
def memory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Memory:
    value = Memory()
    monkeypatch.setattr(QAStudy, "validate_data", lambda _: None)  # synthetic Inputs; byte binding tested separately
    directory = tmp_path / "qa-studies" / "fictional"
    directory.mkdir(parents=True)
    monkeypatch.setattr(r, "directory_for", lambda _: directory)
    monkeypatch.setattr(r, "admit", lambda *args, **kwargs: True)
    monkeypatch.setattr(r, "Ledger", lambda *args: None)
    monkeypatch.setattr(r, "EvalLedgerStore", lambda *args, **kwargs: None)

    class Connection:
        def execute(self, *args: Any) -> Connection:
            return self

        def scalar_one(self) -> Decimal:
            return Decimal(0)

    @contextmanager
    def tx(*args: Any) -> Iterator[Connection]:
        yield Connection()
    monkeypatch.setattr(r, "transaction", tx)
    return value


def execute(study: QAStudy, inputs: r.Inputs, memory: Memory, executor: Executor, *, resume: bool = False,
            boundary: Any = lambda _: None) -> dict[str, Any]:
    return r.run(study, inputs, memory.repository(), memory.store(), executor, allow_paid=True,
                 resume=resume, source=SOURCE, boundary=boundary)


def test_schedule_determinism_bijection_and_rotation() -> None:
    study, inputs = fixture_study()
    order = r.schedule(study, inputs)
    assert order == r.schedule(study, inputs)
    expected = {(q, a.name, 0) for q in inputs.queries for a in study.arms}
    assert {(s.question, s.arm, s.repetition) for s in order} == expected
    assert len({s.id for s in order}) == len(expected)
    assert [s.arm for s in order[:6]] != [s.arm for s in order[6:]]
    assert all(s.id == study.slot_id(s.cohort, s.question, s.arm, s.repetition) for s in order)


@pytest.mark.parametrize("stage", ["frozen", "scheduled", "claimed", "before_execute", "executed", "artifact",
                                   "finalized"])
def test_resume_each_boundary_never_second_execution(stage: str, memory: Memory) -> None:
    study, inputs = fixture_study()
    executor = Executor(memory)

    def crash(at: str) -> None:
        if at == stage:
            raise SystemExit("simulated crash")

    with pytest.raises(SystemExit):
        execute(study, inputs, memory, executor, boundary=crash)
    previous = set(memory.dispatches)
    result = execute(study, inputs, memory, executor, resume=True)
    assert result["execution_complete"]
    assert previous <= memory.dispatches
    assert len(memory.rows) == 12
    if stage in {"claimed", "before_execute", "executed", "artifact"}:
        assert sum(row["outcome"] == "aborted" for row in memory.rows.values()) == 1


def test_unknown_dispatch_holds_and_resume_does_not_reissue(memory: Memory) -> None:
    study, inputs = fixture_study()
    executor = Executor(memory)
    executor.crash = True
    with pytest.raises(SystemExit):
        execute(study, inputs, memory, executor)
    assert len(memory.dispatches) == 1
    result = execute(study, inputs, memory, executor, resume=True)
    assert len(memory.dispatches) > 1 and not result["execution_complete"]
    assert next(iter(memory.rows.values()))["outcome"] == "aborted"


def test_sealed_refuses_prior_to_any_claim(memory: Memory) -> None:
    study, inputs = fixture_study(sealed=True)
    with pytest.raises(r.Refused, match="prior_registration"):
        execute(study, inputs, memory, Executor(memory))
    assert not memory.claims and not memory.dispatches


def test_export_report_arithmetic_and_no_text(memory: Memory) -> None:
    study, inputs = fixture_study()
    execute(study, inputs, memory, Executor(memory))
    runs = {a.name: run_id(study, memory.scope, a.name) for a in study.arms}
    public = r.export(study, r.schedule(study, inputs), memory.repository(), runs)
    raw = json.dumps(public)
    assert "refunds" not in raw and "earlier" not in raw
    assert not {"text", "query", "passage", "answer", "ranking", "prompt"} & {
        key for slot in public["slots"] for key in slot}
    first = public["slots"][0]
    first.update(outcome="error", failure_code="fictional_failure")
    result = r.report(study, inputs, public, memory.repository(), memory.scope, SOURCE)
    affected = next(row for row in result["aggregates"] if row["arm"] == first["arm"])
    assert affected["metrics"]["recall_at_5"] == "1/2"
    assert all(c["status"] == "descriptive" for c in result["comparisons"])


@pytest.mark.parametrize("field,value", [("usd", Decimal("0.02")), ("calls", 1), ("counts", 1),
                                       ("inputs", 1024), ("outputs", 1), ("seconds", Decimal(31))])
def test_runtime_envelope_rejects_every_exhausted_resource(field: str, value: Any) -> None:
    study, _ = fixture_study()
    cap = study.execution.stages[1].caps.model_copy(update={"usd": Decimal("0.02"), "calls": 1,
        "counts": 1, "input_tokens": 1024, "output_tokens": 0, "seconds": 60})
    usage: dict[str, Any] = dict(usd=Decimal(0), calls=0, counts=0, inputs=0, outputs=0, seconds=Decimal(0))
    usage[field] = value
    assert not r.envelope_fits(cap, **usage, next_usd=Decimal("0.01"), next_inputs=1,
                               next_seconds=30, paid=True)


def test_real_config_validates_and_is_descriptive() -> None:
    study = load_study(Path(__file__).parents[1] / "qa_studies/g1-dev-retrieval-v1.json")
    study.validate_data()
    assert not study.example and study.purpose == "dev" and study.registration_sha256 is None
    assert len(study.arms) == 6


def test_runtime_cap_stops_before_claim_even_after_preflight(memory: Memory,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    study, inputs = fixture_study()

    class Result:
        def __init__(self, statement: str) -> None:
            self.statement = statement

        def mappings(self) -> Result:
            return self

        def all(self) -> list[dict[str, Any]]:
            return ([{"invocation_scope_id": uuid4(), "reserved_usd": Decimal("5.01"), "actual_usd": None,
                      "state": "dispatching", "max_input": 1024, "max_output": 0, "count_state": "admitted"}]
                    if "usage_attempts" in self.statement else [])

    class Connection:
        def execute(self, statement: Any, params: Any) -> Result:
            return Result(str(statement))

    @contextmanager
    def tx(*args: Any) -> Iterator[Connection]:
        yield Connection()

    monkeypatch.setattr(r, "transaction", tx)
    monkeypatch.setattr(r, "admit", ADMIT)
    result = execute(study, inputs, memory, Executor(memory))
    assert not result["execution_complete"] and result["recorded"] == 0
    assert not memory.dispatches and all(s.state == "scheduled" for s in memory.claims.values())
