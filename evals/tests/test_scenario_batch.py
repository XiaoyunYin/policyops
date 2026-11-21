"""Offline N2 registration, admission, recovery, and reporting checks."""

import argparse
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest

from policyops.persistence.evaluation import EvaluationRepository, StudyLock
from policyops_evals.scenarios import Refused, study
from policyops_evals.scenarios.batch import Ledger, Result, RunState, Terminal, preflight, read_result, run_batch
from policyops_evals.scenarios.cases import SCENARIOS, STRATA, Scenario, Stratum
from policyops_evals.scenarios.cli import add_parser
from policyops_evals.scenarios.grading import Grade, grade_slot
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.reporting import gate, markdown, report
from policyops_evals.scenarios.runtime import Slot, Summary
from policyops_evals.scenarios.study import assigned_slot


DIGEST = "a" * 64
AT = datetime(2026, 11, 21, 12, tzinfo=UTC)
ZERO_LEDGER = Ledger()


def make_case(key: str, stratum: Stratum = "cancel") -> Scenario:
    base = SCENARIOS[1 if stratum == "delivered_refusal" else 0]
    return replace(base, key=key, gold=replace(base.gold, key=key, stratum=stratum, customer_world=key))


def test_registration_checks_pins_and_uses_db_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    files = {name: name.encode() for name in study.MANIFEST_SHA256}
    pins = {name: sha256(raw).hexdigest() for name, raw in files.items()}
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    workspace, generation, study_id = uuid4(), uuid4(), uuid4()
    manifests = study.checked_manifests(tmp_path, pins)
    inputs = study.Inputs((make_case("one"),), {"manifests": manifests, "source": {"revision": "b" * 40}})
    payload = study.registration_payload(inputs, workspace, generation, DIGEST, tmp_path)
    repository = Mock(spec=EvaluationRepository)
    repository.engine = Mock()
    store = Mock()
    store.ensure_study.return_value = study_id
    monkeypatch.setattr(study, "EvalLedgerStore", Mock(return_value=store))

    @contextmanager
    def locked(identity: UUID) -> Iterator[StudyLock]:
        assert identity == study_id
        yield StudyLock(identity, 1)

    def receipt(runs: Sequence[Any], bound: dict[str, Any], digest: str, lock: StudyLock) -> dict[str, Any]:
        assert lock.study_id == runs[0].study_scope == study_id
        assert len(runs) == 1 and runs[0].id == study.registration_id(study_id)
        assert bound == payload and digest == runs[0].config_sha256
        return {"payload": bound, "sha256": digest, "created_at": AT.isoformat()}

    repository.study_lock.side_effect = locked
    repository.register.side_effect = receipt
    registered = study.register(repository, payload, len(inputs.dev))
    study.write_registration(tmp_path, registered)
    assert study.read_registration(tmp_path, inputs) == (study_id, registered["receipt"])
    assert registered["receipt"]["created_at"] == AT.isoformat()
    changed = replace(inputs, binding=inputs.binding | {"source": {"revision": "c" * 40}})
    with pytest.raises(Refused, match="registered scenario inputs changed"):
        study.read_registration(tmp_path, changed)
    (tmp_path / "held-out.gold.jsonl").write_bytes(b"modified")
    with pytest.raises(Refused, match=r"held-out\.gold\.jsonl"):
        study.checked_manifests(tmp_path, pins)


def test_pilot_order_and_slot_derivation() -> None:
    cases = [make_case(f"{stratum}-{index}", stratum) for stratum in STRATA for index in range(3)]
    frozen = study.interleave(cases)
    assert tuple(case.gold.stratum for case in frozen[:study.PILOT_SLOTS]) == STRATA * 2
    assert [case.key for case in frozen if case.gold.stratum == "cancel"] == ["cancel-0", "cancel-1", "cancel-2"]
    workspace, study_id = uuid4(), uuid4()
    slot = assigned_slot(study_id, workspace, "dev", 1, "case")
    assert slot.run == assigned_slot(study_id, workspace, "dev", 1, "case").run
    neighbors = (
        assigned_slot(study_id, workspace, "dev", 2, "case"),
        assigned_slot(study_id, workspace, "dev", 1, "other"),
        assigned_slot(uuid4(), workspace, "dev", 1, "case"),
    )
    assert len({slot.run, *(item.run for item in neighbors)}) == 4


class ScriptedBackend:
    def __init__(self, ledger: Ledger | None = ZERO_LEDGER, stop: str = "succeeded") -> None:
        self.ledger = ledger
        self.stop = stop
        self.states: dict[UUID, RunState] = {}
        self.called: list[UUID] = []
        self.crash = False
        self.mismatch = False

    def accounts(self, slots: Sequence[Slot]) -> dict[UUID, RunState]:
        if self.called and self.mismatch:
            raise Refused("app ledger does not reconcile")
        return {slot.id: self.states[slot.id] for slot in slots if slot.id in self.states}

    def terminal(self, slot: Slot) -> Terminal | None:
        return Terminal(self.stop, 12) if slot.id in self.states and not self.crash else None

    def execute(self, scenario: Scenario, slot: Slot, tape: Tape) -> Summary:
        assert slot.id not in self.called
        self.called.append(slot.id)
        self.states[slot.id] = RunState(self.ledger)
        if self.crash:
            raise KeyboardInterrupt
        return Summary("none", False, 0, Decimal(0), Decimal(0), 12, self.stop)


def slots(count: int) -> list[tuple[Scenario, Slot]]:
    workspace, study_id = uuid4(), uuid4()
    cases = [make_case(f"case-{index}") for index in range(count)]
    return [(case, assigned_slot(study_id, workspace, "dev", 1, case.key)) for case in cases]


def test_preflight_includes_all_remaining_and_refuses_before_dispatch(tmp_path: Path) -> None:
    backend = ScriptedBackend()
    with pytest.raises(Refused, match=r"0\.024192"):
        run_batch(backend, slots(2), tmp_path, DIGEST, Decimal("0.02"))
    assert backend.called == [] and list(tmp_path.iterdir()) == []
    active = Ledger(held=Decimal("0.001512"))
    with pytest.raises(Refused, match=r"0\.024192"):
        preflight(Decimal("0.02"), [active], 1, active=[active])


def test_finalized_and_held_slot_resume_without_second_attempt(tmp_path: Path) -> None:
    schedule = slots(3)
    backend = ScriptedBackend()
    run_batch(backend, schedule[:1], tmp_path, DIGEST, Decimal("0.02"))
    first = read_result(tmp_path, schedule[0][1], DIGEST)
    backend.crash = True
    backend.ledger = Ledger(held=Decimal("0.001512"))
    with pytest.raises(KeyboardInterrupt):
        run_batch(backend, schedule, tmp_path, DIGEST, Decimal("0.03"))
    assert len(backend.called) == 2
    # The original hold remains live. Recovery may move on to an untouched slot.
    backend.crash = False
    backend.ledger = Ledger()
    batch = run_batch(backend, schedule, tmp_path, DIGEST, Decimal("0.02"))
    assert batch[schedule[0][1].id] == first
    assert batch[schedule[1][1].id].status == "held"
    assert batch[schedule[1][1].id].ledger == Ledger(held=Decimal("0.001512"))
    assert backend.called == [slot.id for _, slot in schedule]


@pytest.mark.parametrize(("ledger", "mismatch", "stop", "calls", "reason"), [
    (Ledger(overrun=True), False, "overrun", 1, "overrun"),
    (Ledger(contract_block=True), False, "contract_block", 1, "accounting contract"),
    (Ledger(), True, "succeeded", 1, "reconcile"),
    (None, False, "succeeded", 1, "provenance"),
    (Ledger(), False, "investigation.provider_error", 3, "three consecutive"),
    (Ledger(), False, "investigation.tool_error", 3, "three consecutive"),
])
def test_batch_halts_and_restart_cannot_clear_streak(tmp_path: Path, ledger: Ledger | None, mismatch: bool,
                                                      stop: str, calls: int, reason: str) -> None:
    backend = ScriptedBackend(ledger, stop)
    backend.mismatch = mismatch
    schedule = slots(4)
    for _ in range(2):
        with pytest.raises(Refused, match=reason):
            run_batch(backend, schedule, tmp_path, DIGEST, Decimal("0.05"))
        assert len(backend.called) == calls


def result(case: Scenario, slot: Slot, *, primary: bool = False, unsafe: bool = False,
           stop: str = "invalid_cap", decision: int | None = None, terminal: int | None = 20,
           ledger: Ledger | None = ZERO_LEDGER) -> Result:
    if case.gold.stratum == "delivered_refusal":
        grade = Grade(None, unsafe, False, False)
    else:
        grade = Grade(primary, None, primary, False, failure=None if primary else "invalid-reply stop")
    return Result(slot_id=slot.id, run_id=slot.run, registration_sha256=DIGEST, recorded_at=AT, status="finalized",
                  grade=grade, ledger=ledger, stop_reason=stop, decision_ms=decision, terminal_ms=terminal)


def test_report_strict_denominators_and_repeat_disagreement() -> None:
    bare, hashed = make_case("bare"), make_case("hash")
    bare = replace(bare, gold=replace(bare.gold, order_id_form="bare"))
    negative = make_case("negative", "delivered_refusal")
    workspace, study_id = uuid4(), uuid4()
    frame = [(rep, case, assigned_slot(study_id, workspace, "dev", rep, case.key))
             for rep in (1, 2) for case in (bare, hashed, negative)]
    results = {}
    for index, (_, case, slot) in enumerate(frame):
        if index in (4, 5):
            continue
        results[slot.id] = result(
            case, slot, primary=index in (0, 1), unsafe=index == 2, decision=10 if index == 0 else None,
            terminal=20 + index * 10,
            ledger=Ledger(settled=Decimal("0.001"), held=Decimal("0.002") if index == 0 else Decimal(0)),
        )
    summary = report(frame, results, set(), digest=DIGEST, draws=20)
    assert summary["overall"]["primary"] == {"numerator": 2, "scheduled": 4, "value": 0.5}
    assert summary["overall"]["unsafe_attempt"] == {"numerator": 1, "scheduled": 2, "value": 0.5}
    assert summary["primary_interval"]["clusters"] == 2
    assert summary["test_retest"]["strict_rate"]["value"] == 1
    assert summary["test_retest"]["observed_rate"] == {"numerator": 1, "scheduled": 1, "value": 1}
    assert summary["test_retest"]["per_case_disagreement_count"] == {"bare": 1, "hash": 1}
    assert summary["test_retest"]["repeat_2_minus_repeat_1"]["point"] == -1
    assert summary["primary_by_id_form"]["bare"]["scheduled"] == 2
    assert summary["decision_latency"] == {"scheduled": 6, "measured": 1, "unmeasured": 5,
                                           "p50_ms": 10, "p95_ms": 10}
    assert summary["terminal_latency"]["measured"] == 4 and summary["terminal_latency"]["p95_ms"] == 48.5
    assert summary["cost"]["upper_usd"] == "0.006"
    assert summary["cost"]["held_usd_per_scheduled_case"] == str(Decimal("0.002") / 6)
    assert summary["gate"]["verdict"] == "incomplete"
    assert summary["gate"]["harness_stops_above_maximum"]["rate"]["numerator"] == 0
    assert "Test-retest" in markdown(summary)
    pending = report(frame, results, {frame[4][2].id}, digest=DIGEST, draws=20)
    assert pending["cost"]["upper_usd"] is None and pending["cost"]["unverifiable_slots"] == 1


def test_d6_counts_only_stricter_stops_and_applies_named_exception() -> None:
    frame = [(1, case, slot) for case, slot in slots(10)]
    results = {slot.id: result(case, slot) for _, case, slot in frame}
    assert gate(frame, results)["verdict"] == "proceed"
    assert gate(frame, results)["named_failure_exception"]["applied"]
    case, slot = frame[0][1:]
    results[slot.id] = result(case, slot, stop="tool_cap")
    assert gate(frame, results)["verdict"] == "proceed"  # Exactly 10%.
    results[slot.id] = results[slot.id].model_copy(update={"stop_reason": "invalid_cap"})
    for _, case, slot in frame[1:3]:
        results[slot.id] = result(case, slot, stop="succeeded").model_copy(update={"failure_kind": "recorder"})
    assert gate(frame, results)["verdict"] == "return_to_design"
    results = {slot.id: result(case, slot) for _, case, slot in frame}
    for _, case, slot in frame[:2]:
        results[slot.id] = results[slot.id].model_copy(update={"grade": grade_slot(case.gold, None)})
    assert gate(frame, results)["named_failure_exception"]["rate"]["value"] == 0.8
    assert gate(frame, results)["verdict"] == "proceed"
    _, case, slot = frame[2]
    results[slot.id] = results[slot.id].model_copy(update={"grade": grade_slot(case.gold, None)})
    assert gate(frame, results)["verdict"] == "return_to_design"
    assert gate(frame, {slot.id: result(case, slot, primary=True)
                        for _, case, slot in frame})["verdict"] == "return_to_design"


@pytest.mark.parametrize(("split", "allow", "error"), [
    ("held-out", True, "sealed until N3"),
    ("dev", False, "--allow-paid"),
    ("dev", True, "outside tests"),
])
def test_cli_refuses_heldout_unpaid_or_test_before_touching_files(split: str, allow: bool, error: str,
                                                                        capsys: pytest.CaptureFixture[str]) -> None:
    parser = argparse.ArgumentParser()
    add_parser(parser)
    flags = ["run", "--split", split, "--repeat", "1", "--max-usd", "2",
             "--manifests", "missing", "--fixture-root", "missing", "--policy-file", "missing",
             "--out", "missing", "--dsn-file", "missing"]
    args = parser.parse_args(flags + (["--allow-paid"] if allow else []))
    assert args.handler(args) == 1
    assert error in capsys.readouterr().err
