"""Serial N3 blocks, exact v2 liability and restart reconciliation."""

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
import re
import time
from typing import Protocol
from uuid import UUID

from policyops.persistence.records import exact_usd
from policyops.runtime.spec import RuntimeSpec
from policyops_evals.scenarios import Refused, read_bounded
from policyops_evals.scenarios.arms import Arm, Identity
from policyops_evals.scenarios.batch import (
    AppBackend,
    Ledger,
    Result,
    RunState,
    Terminal,
    _result,
    read_result,
    slot_directory,
)
from policyops_evals.scenarios.n3 import ALL_IN_CAP, BLOCK_PAIRS, DEV_CAP, Assignment, Split
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.runtime import Slot, configuration
from policyops_evals.scenarios.study import MAX_FAILURE_STREAK, WALL_SECONDS, atomic_write, private_child


class Backend(Protocol):
    def accounts(self, frame: Sequence[Assignment]) -> Mapping[UUID, RunState]: ...
    def terminal(self, item: Assignment) -> Terminal | None: ...
    def execute(self, item: Assignment, tape: Tape) -> None: ...


Execute = Callable[[Assignment, Tape, Callable[[RuntimeSpec], RuntimeSpec]], object]


@dataclass(frozen=True)
class ArmBackend:
    backends: Mapping[Arm, AppBackend]
    identities: Mapping[Arm, Identity]
    out: Path
    dispatch: Execute

    def accounts(self, frame: Sequence[Assignment]) -> dict[UUID, RunState]:
        arms: dict[Arm, list[Slot]] = defaultdict(list)
        for item in frame:
            arms[item.arm].append(item.slot)
        return {key: state for arm, slots in arms.items() for key, state in self.backends[arm].accounts(slots).items()}

    def terminal(self, item: Assignment) -> Terminal | None:
        return self.backends[item.arm].terminal(item.slot)

    def execute(self, item: Assignment, tape: Tape) -> None:
        expected = self.identities[item.arm]

        def bind(spec: RuntimeSpec) -> RuntimeSpec:
            spec = item.arm.bind(spec)
            if (spec.graph_sha256, spec.prompt_sha256) != (expected.graph_sha256, expected.prompt_sha256):
                raise Refused("N3 arm graph or prompt digest changed")
            path = _runtime_path(self.out, item.slot)
            existing = config_digest(self.out, item.slot)
            if existing is not None and existing != spec.config_sha256:
                raise Refused("N3 slot config digest changed")
            atomic_write(path, spec.config_sha256.encode())
            return spec

        with item.arm.compose():
            self.dispatch(item, tape, bind)


def _runtime_path(out: Path, slot: Slot) -> Path:
    return private_child(slot_directory(out, slot), "runtime-config.sha256")


def config_digest(out: Path, slot: Slot) -> str | None:
    path = _runtime_path(out, slot)
    if not path.exists():
        return None
    digest = read_bounded(path, 64).decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise Refused("invalid N3 slot config digest")
    return digest


def validate_cap(split: Split, maximum: Decimal) -> None:
    exact_usd(maximum, "N3 aggregate cap")
    if not 0 < maximum <= (DEV_CAP if split == "dev" else ALL_IN_CAP):
        raise Refused("N3 aggregate cap is outside the split limit")


def liability(states: Mapping[UUID, RunState]) -> Decimal:
    slot_cap = configuration().caps.run_usd
    total = Decimal(0)
    for state in states.values():
        ledger = state.ledger
        if ledger is None or ledger.overrun or ledger.contract_block or ledger.upper > slot_cap:
            raise Refused("N3 app ledger cannot be admitted")
        # Active runs retain their full slot ceiling, including amounts already in v2 liability.
        total += slot_cap if state.active else ledger.upper
    return total


def rolling_worst(states: Mapping[UUID, RunState], next_slots: int, *, prior_settled: Decimal = Decimal(0)
                  ) -> Decimal:
    if not 0 <= next_slots <= 2 * BLOCK_PAIRS:
        raise Refused("N3 block exceeds its registered size")
    return prior_settled + liability(states) + next_slots * configuration().caps.run_usd


def _record(out: Path, item: Assignment, digest: str, tape: Tape, state: RunState | None,
            terminal: Terminal | None, *, interrupted: bool) -> Result:
    result = _result(item.case, item.slot, digest, tape, state, terminal, interrupted=interrupted)
    atomic_write(private_child(slot_directory(out, item.slot), "result.json"), result.model_dump_json().encode())
    return result


def _restore(backend: Backend, frame: Sequence[Assignment], out: Path, digest: str,
             live: Mapping[UUID, RunState]) -> dict[UUID, Result]:
    results = {}
    for item in frame:
        slot = item.slot
        result = read_result(out, slot, digest)
        if result is None:
            directory = slot_directory(out, slot)
            state = live.get(slot.id)
            if state is None and not directory.exists():
                continue
            directory.mkdir(exist_ok=True)
            tape = Tape(private_child(directory, "tape"))
            terminal = backend.terminal(item) if state is not None else None
            # A tape starts before the first provider request (including token counting). A
            # consumed count grant also forbids replay if the tape failed or went missing.
            if terminal is None and not tape.records and (
                state is None or (state.ledger is not None and not state.ledger.count_grants
                                  and not state.ledger.consumed_calls)
            ):
                continue
            result = _record(out, item, digest, tape, state, terminal, interrupted=terminal is None)
        results[slot.id] = result
    return results


def reconciles(results: Mapping[UUID, Result], live: Mapping[UUID, RunState]) -> bool:
    for key, result in results.items():
        original = result.ledger
        current = live[key].ledger if key in live else Ledger()
        if original is None or current is None:
            return False
        # A later settlement may convert a hold into spend while preserving the dispatch counters.
        if (current.settled < original.settled or current.held > original.held or current.upper > original.upper
                or original.model_copy(update={"settled": current.settled, "held": current.held}) != current):
            return False
    return True


def refuse_existing(backend: Backend, frame: Sequence[Assignment], out: Path) -> None:
    if backend.accounts(frame) or any(slot_directory(out, item.slot).exists() for item in frame):
        raise Refused("a held-out slot already exists")


def run_blocks(backend: Backend, blocks: Sequence[Sequence[Assignment]], out: Path, digest: str,
               maximum: Decimal, *, prior: Sequence[Assignment] = (),
               prior_settled: Decimal = Decimal(0),
               check_lock: Callable[[], None], close: Callable[[str], None]) -> str:
    """Use fixed case groups and close permanently at the first budget stop."""
    frame = [item for block in blocks for item in block]
    all_slots = [*prior, *frame]
    deadline = time.monotonic() + WALL_SECONDS
    check_lock()
    live = backend.accounts(all_slots)
    results = _restore(backend, frame, out, digest, live)
    if not reconciles(results, live):
        raise Refused("N3 recorded liability differs from the app ledger")
    streak = 0
    for block in blocks:
        pending = [item for item in block if item.slot.id not in results]
        if pending:
            check_lock()
            live = backend.accounts(all_slots)
            # Pending pre-dispatch app runs already occupy a full active reservation.
            fresh = sum(item.slot.id not in live or not live[item.slot.id].active for item in pending)
            if rolling_worst(live, fresh, prior_settled=prior_settled) > maximum:
                close("budget_stop")
                return "budget_stop"
        for item in block:
            slot = item.slot
            result = results.get(slot.id)
            if result is None:
                check_lock()
                if time.monotonic() + configuration().caps.active_seconds >= deadline:
                    close("wall_deadline")
                    return "wall_deadline"
                directory = slot_directory(out, slot)
                directory.mkdir(exist_ok=True)
                tape = Tape(private_child(directory, "tape"))
                try:
                    backend.execute(item, tape)
                    interrupted = False
                except Refused:
                    raise
                except Exception:
                    interrupted = True
                terminal = backend.terminal(item)
                state = backend.accounts([item]).get(slot.id)
                result = _record(out, item, digest, tape, state, terminal, interrupted=interrupted)
                results[slot.id] = result
                liability({slot.id: state} if state is not None else {})
            streak = streak + 1 if result.failure_kind is not None else 0
            if streak >= MAX_FAILURE_STREAK:
                close("failure_streak")
                return "failure_streak"
    if any(result.status != "finalized" and result.terminal_ms is None for result in results.values()):
        close("incomplete_slots")
        return "incomplete_slots"
    return "complete"
