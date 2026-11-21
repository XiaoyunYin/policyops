"""Serial dev admission, app-ledger reconciliation and restart-safe private results."""

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
import time
from typing import Annotated, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, text

from policyops.persistence import runs
from policyops.persistence.checkpoints import thread_id_for
from policyops.persistence.database import workspace_transaction
from policyops.persistence.evaluation import study_lock_key
from policyops.persistence.records import exact_usd
from policyops_contracts.scalars import Sha256Hex, UtcDatetime
from policyops_contracts.stops import StopReason
from policyops_evals.scenarios import Refused, read_bounded
from policyops_evals.scenarios.cases import Scenario
from policyops_evals.scenarios.grading import Grade, _tool_outputs, grade_slot
from policyops_evals.scenarios.recording import Tape, first_consequential_call, object_from
from policyops_evals.scenarios.runtime import Slot, Summary, configuration, terminal_outcome
from policyops_evals.scenarios.study import (
    MAX_FAILURE_STREAK,
    WALL_SECONDS,
    atomic_write,
    private_child,
)


FailureKind = Literal["provider", "infrastructure", "recorder"]
Money = Annotated[Decimal, Field(ge=0, allow_inf_nan=False)]
Latency = Annotated[int, Field(ge=0)]
RESULT_LIMIT = 16 * 1024


class Ledger(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    settled: Money = Decimal(0)
    held: Money = Decimal(0)
    consumed_calls: Annotated[int, Field(ge=0)] = 0
    count_grants: Annotated[int, Field(ge=0)] = 0
    attempts: Annotated[int, Field(ge=0)] = 0
    price_revision: str | None = None
    overrun: bool = False
    contract_block: bool = False

    @property
    def upper(self) -> Decimal:
        return self.settled + self.held


class Result(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    slot_id: UUID
    run_id: UUID
    registration_sha256: Sha256Hex
    recorded_at: UtcDatetime
    status: Literal["finalized", "held", "interrupted"]
    ledger: Ledger | None
    grade: Grade
    stop_reason: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,99}$")]
    failure_kind: FailureKind | None = None
    decision_ms: Latency | None = None
    terminal_ms: Latency | None = None
    tape_sha256: Sha256Hex | None = None


@dataclass(frozen=True)
class RunState:
    ledger: Ledger | None
    active: bool = False


@dataclass(frozen=True)
class Terminal:
    reason: str
    latency_ms: int
    retrieval_error: bool = False


class Backend(Protocol):
    def accounts(self, slots: Sequence[Slot]) -> Mapping[UUID, RunState]: ...
    def terminal(self, slot: Slot) -> Terminal | None: ...
    def execute(self, scenario: Scenario, slot: Slot, tape: Tape) -> Summary: ...


@dataclass(frozen=True)
class AppBackend:
    engine: Engine
    workspace: UUID
    graph_sha256: str
    prompt_sha256: str
    execute_slot: Callable[[Scenario, Slot, Tape], Summary]

    def execute(self, scenario: Scenario, slot: Slot, tape: Tape) -> Summary:
        return self.execute_slot(scenario, slot, tape)

    def terminal(self, slot: Slot) -> Terminal | None:
        with workspace_transaction(self.engine, self.workspace) as connection:
            run = runs.get_run(connection, slot.run)
            finished = terminal_outcome(connection, run) if run is not None else None
            if finished is None:
                return None
            # The Responses request cannot express is_error on a tool result. Read the bounded
            # checkpoint counters so a failed retrieval is visible even if its text reached the model.
            retrieval_error = connection.execute(text("""
                SELECT CAST(payload #>> '{channel_values,state,retrieval_index}' AS integer)
                    > jsonb_array_length(payload #> '{channel_values,state,retrieved_steps}')
                FROM checkpoints.snapshots
                WHERE workspace_id = :workspace AND thread_id = :thread AND checkpoint_ns = ''
                ORDER BY checkpoint_id DESC LIMIT 1
            """), {"workspace": self.workspace, "thread": thread_id_for(self.workspace, slot.run)}).scalar_one_or_none()
            return Terminal(*finished, retrieval_error=retrieval_error is True)

    def accounts(self, slots: Sequence[Slot]) -> dict[UUID, RunState]:
        by_run = {slot.run: slot for slot in slots}
        config = configuration()
        reservation = config.reservation("agent")
        with workspace_transaction(self.engine, self.workspace) as connection:
            rows = connection.execute(text("""
                SELECT r.id, r.case_id, r.graph_sha256, r.prompt_sha256, r.state, s.id AS scope,
                    s.spent_usd, s.held_usd, s.calls_consumed, s.calls_held, s.counts_used,
                    s.cap_usd, s.cap_calls, s.cap_counts, s.overrun, s.contract_block, a.*
                FROM app.runs r
                LEFT JOIN app.budget_scopes s ON s.workspace_id = r.workspace_id AND s.run_id = r.id
                CROSS JOIN LATERAL (
                    SELECT count(*) AS attempts,
                        count(*) FILTER (WHERE state IN ('dispatching', 'unresolved', 'settled')) AS consumed,
                        count(*) FILTER (WHERE state = 'reserved') AS reserved,
                        count(*) FILTER (WHERE count_state <> 'none') AS counts,
                        COALESCE(sum(actual_usd) FILTER (WHERE state = 'settled'), 0) AS settled,
                        COALESCE(sum(reserved_usd) FILTER
                            (WHERE state IN ('reserved', 'dispatching', 'unresolved')), 0) AS held,
                        bool_and(actor = 'agent' AND model = :model AND price_revision = :price
                            AND config_sha256 = :config AND reserved_usd = :request_usd) AS bound
                    FROM app.usage_attempts WHERE workspace_id = s.workspace_id AND scope_id = s.id
                ) a
                WHERE r.workspace_id = :workspace AND r.id = ANY(:ids)
            """), {"ids": list(by_run), "workspace": self.workspace, "model": reservation.model,
                   "price": reservation.price_revision, "config": reservation.config_sha256,
                   "request_usd": reservation.worst_usd}).mappings().all()

        result = {}
        for row in rows:
            slot = by_run[row["id"]]
            if (row["case_id"], row["graph_sha256"], row["prompt_sha256"]) != (
                slot.case, self.graph_sha256, self.prompt_sha256,
            ):
                raise Refused("app run identity or runtime digest mismatch")
            ledger = None
            if row["scope"] is not None:
                if (
                    (row["settled"], row["held"], row["consumed"], row["reserved"], row["counts"])
                    != (row["spent_usd"], row["held_usd"], row["calls_consumed"], row["calls_held"], row["counts_used"])
                    or (row["cap_usd"], row["cap_calls"], row["cap_counts"])
                    != (config.caps.run_usd, config.caps.run_calls, config.caps.run_calls)
                    or (row["attempts"] and row["bound"] is not True)
                ):
                    raise Refused("app ledger does not reconcile to the registered model and caps")
                ledger = Ledger(
                    settled=row["settled"], held=row["held"], consumed_calls=row["consumed"],
                    count_grants=row["counts"],
                    attempts=row["attempts"], price_revision=reservation.price_revision,
                    overrun=row["overrun"], contract_block=row["contract_block"] is not None,
                )
            active = row["state"] not in runs.TERMINAL_STATES and row["state"] != "waiting_approval"
            result[slot.id] = RunState(ledger, active=active)
        return result


@contextmanager
def serial_lock(engine: Engine, study_id: UUID) -> Iterator[Callable[[], None]]:
    with engine.connect() as connection:
        connection = connection.execution_options(isolation_level="AUTOCOMMIT")
        try:
            if not connection.execute(text("SELECT pg_try_advisory_lock(:key)"),
                                      {"key": study_lock_key(study_id)}).scalar_one():
                raise Refused("another scenario batch is running")
            pid = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()

            def check() -> None:
                if connection.execute(text("SELECT pg_backend_pid()")).scalar_one() != pid:
                    raise Refused("scenario batch lock was lost")

            yield check
        finally:
            connection.invalidate()


def slot_directory(out: Path, slot: Slot) -> Path:
    return private_child(out, str(slot.id))


def read_result(out: Path, slot: Slot, digest: str) -> Result | None:
    path = private_child(slot_directory(out, slot), "result.json")
    if not path.exists():
        return None
    result = Result.model_validate_json(read_bounded(path, RESULT_LIMIT))
    if (result.slot_id, result.run_id, result.registration_sha256) != (slot.id, slot.run, digest):
        raise Refused("private result binding mismatch")
    return result


def _saw_retrieval_error(tape: Tape) -> bool:
    # The graph sends these fixed adapter errors as function outputs. A lexical miss is a normal delivery.
    return any(
        body in {"Policy retrieval unavailable.", "Policy evidence exceeds the delivery limit."}
        for item in tape.records if item.phase == "create"
        for _, body in _tool_outputs(object_from(item.request))
    )


def _failure_kind(tape: Tape, ledger: Ledger | None, stop: str, infrastructure_error: bool) -> FailureKind | None:
    creates = [item for item in tape.records if item.phase == "create"]
    if (tape.write_failed or any(
        item.request is None or (item.status is None and item.elapsed_ms is None)
        or (item.status is not None and 200 <= item.status < 300 and (not item.complete or item.response is None))
        for item in tape.records
    ) or (ledger is not None and ledger.consumed_calls > len(creates))):
        return "recorder"
    if infrastructure_error or _saw_retrieval_error(tape):
        return "infrastructure"
    if (stop.startswith("investigation.provider") or stop == StopReason.USAGE_UNCONFIRMED or any(
        (item.status is not None and item.status >= 400)
        or (item.status is None and not item.complete and item.elapsed_ms is not None)
        or object_from(item.response).get("status") in ("failed", "cancelled")
        for item in tape.records
    )):
        return "provider"
    if stop not in {"succeeded", "waiting_approval", "investigation.loop_ceiling", *StopReason}:
        return "infrastructure"
    return None


def _result(scenario: Scenario, slot: Slot, digest: str, tape: Tape, state: RunState | None,
            terminal: Terminal | None, *, interrupted: bool) -> Result:
    ledger = state.ledger if state is not None else (None if tape.records else Ledger())
    stop = terminal.reason if terminal is not None else "interrupted"
    failure = _failure_kind(tape, ledger, stop, interrupted or (terminal is not None and terminal.retrieval_error))
    # Keep independently captured first-decision evidence even when later accounting or teardown failed.
    grade = grade_slot(scenario.gold, tape.records if tape.records or failure == "provider" else None, stop=stop)
    first = first_consequential_call(tape.records)
    decision = tape.records[first.exchange_index].slot_elapsed_ms if first is not None else None
    tape_digest = sha256(b"\n".join(item.model_dump_json().encode() for item in tape.records)).hexdigest()
    return Result(
        slot_id=slot.id, run_id=slot.run, registration_sha256=digest, recorded_at=datetime.now(UTC),
        status="held" if state is not None and (terminal is None or (ledger is not None and ledger.held))
        else "finalized" if terminal is not None else "interrupted",
        ledger=ledger, grade=grade, stop_reason=stop, failure_kind=failure, decision_ms=decision,
        terminal_ms=terminal.latency_ms if terminal is not None else None, tape_sha256=tape_digest,
    )


def preflight(max_usd: Decimal, ledger: Sequence[Ledger], remaining: int,
              *, active: Sequence[Ledger] = ()) -> Decimal:
    exact_usd(max_usd, "aggregate cap")
    if max_usd <= 0:
        raise Refused("aggregate cap must be positive")
    if any(item.overrun or item.contract_block for item in ledger):
        raise Refused("app ledger overrun or accounting contract block")
    slot_usd = configuration().caps.run_usd
    if any(item.upper > slot_usd for item in ledger):
        raise Refused("app ledger exceeds the registered slot budget")
    worst = sum((item.upper for item in ledger), Decimal(0)) + remaining * slot_usd
    worst += sum((slot_usd - item.upper for item in active), Decimal(0))
    if worst > max_usd:
        raise Refused(f"aggregate preflight requires USD {worst} for this run")
    return worst


def _check_budget(backend: Backend, slots: Sequence[Slot], results: Mapping[UUID, Result],
                  max_usd: Decimal) -> None:
    live = backend.accounts(slots)
    if live.keys() - results.keys():
        raise Refused("unexpected app run during batch admission")
    if any(state.ledger is None for state in live.values()) or any(item.ledger is None for item in results.values()):
        raise Refused("app ledger provenance is missing")
    if any(slot_id not in live and item.ledger is not None and item.ledger != Ledger()
           for slot_id, item in results.items()):
        raise Refused("recorded app ledger is missing")
    preflight(max_usd, [state.ledger for state in live.values() if state.ledger is not None],
              len(slots) - len(results),
              active=[state.ledger for state in live.values() if state.active and state.ledger is not None])


def run_batch(backend: Backend, schedule: Sequence[tuple[Scenario, Slot]], out: Path, digest: str,
              max_usd: Decimal, *, check_lock: Callable[[], None] | None = None) -> dict[UUID, Result]:
    deadline = time.monotonic() + WALL_SECONDS
    slots = [slot for _, slot in schedule]
    live = backend.accounts(slots)
    results: dict[UUID, Result] = {}
    for scenario, slot in schedule:
        directory = slot_directory(out, slot)
        found = read_result(out, slot, digest)
        if found is None and (slot.id in live or directory.exists()):
            directory.mkdir(exist_ok=True)
            tape = Tape(private_child(directory, "tape"))
            terminal = backend.terminal(slot)
            found = _result(scenario, slot, digest, tape, live.get(slot.id), terminal, interrupted=terminal is None)
            atomic_write(private_child(directory, "result.json"), found.model_dump_json().encode())
        if found is not None:
            results[slot.id] = found
    _check_budget(backend, slots, results, max_usd)

    streak = 0
    for scenario, slot in schedule:
        result = results.get(slot.id)
        if result is None:
            if time.monotonic() + configuration().caps.active_seconds >= deadline:
                raise Refused("batch wall deadline")
            _check_budget(backend, slots, results, max_usd)
            if check_lock is not None:
                check_lock()
            directory = slot_directory(out, slot)
            directory.mkdir()  # durable admission marker before creating the run or touching the provider
            tape = Tape(private_child(directory, "tape"))
            try:
                backend.execute(scenario, slot, tape)
                interrupted = False
            except Exception:
                interrupted = True
            terminal = backend.terminal(slot)
            state = backend.accounts([slot]).get(slot.id)
            result = _result(scenario, slot, digest, tape, state, terminal, interrupted=interrupted)
            atomic_write(private_child(directory, "result.json"), result.model_dump_json().encode())
            results[slot.id] = result
            _check_budget(backend, slots, results, max_usd)
        streak = streak + 1 if result.failure_kind is not None else 0
        if streak >= MAX_FAILURE_STREAK:
            raise Refused("three consecutive provider, infrastructure or recorder failures")
    return results
