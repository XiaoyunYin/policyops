"""Offline cache study registration, gate, resume and metric regressions."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
from uuid import UUID

import pytest

from policyops.orchestration import investigation_prompt as prompt
from policyops.providers.serialize import prepare
from policyops_contracts.conversation import PolicyContext, UserMessage
from policyops_evals.scenarios import n3, n3_runner, n7, n7_report, runtime
from policyops_evals.scenarios.arms import Arm
from policyops_evals.scenarios.batch import Ledger, RunState, Terminal
from policyops_evals.scenarios.cases import STRATA
from policyops_evals.scenarios.grading import Grade
from policyops_evals.scenarios.recording import Exchange, Tape

from .test_scenario_n3 import DIGEST, STUDY, WORKSPACE, dev_cases


def test_n7_pairs_are_seeded_balanced_and_serial() -> None:
    dev = dev_cases()
    pairs = n7.schedule(dev, "study")
    assert pairs == n7.schedule(dev[::-1], "study")
    assert len(pairs) == 256 and [pair.case.gold.stratum for pair in pairs[:8]] == list(STRATA)
    counts = Counter((pair.case.gold.stratum, pair.repeat, pair.order[0]) for pair in pairs)
    assert all(counts[stratum, repeat, Arm.A0] == counts[stratum, repeat, Arm.A1] > 0
               for stratum in STRATA for repeat in (1, 2))
    blocks = n7.blocks(pairs, STUDY, WORKSPACE)
    assert all(len(block) == 32 for block in blocks)
    assert len({item.slot.id for block in blocks for item in block}) == 512
    pilot = n7.schedule(dev, "pilot")
    assert len(pilot) == 3 and any(pair.order == (Arm.A1, Arm.A0) for pair in pilot)


def test_n7_arm_requests_change_only_cache_options() -> None:
    case = dev_cases()[0]
    policy = PolicyContext(domain="retail", source="fictional", text="Policy.",
                           sha256=sha256(b"Policy.").hexdigest())
    bindings = n7.request_bindings((case,), policy)
    off, on = (bindings[arm][case.key] for arm in n7.ARMS)
    assert off.create != on.create
    assert replace(off, create=on.create) == on
    request = prompt.request(policy, runtime.LIMITS, (UserMessage(text=case.visible.message),), profile=n7.PROFILE)
    bodies = [prepare(request, runtime.configuration(n7.MODES[arm]), "agent").params() for arm in n7.ARMS]
    assert [body.pop("prompt_cache_options") for body in bodies] == [n7.CACHE_OPTIONS[arm] for arm in n7.ARMS]
    assert bodies[0] == bodies[1] and "prompt_cache_key" not in bodies[0]
    configs = [runtime.configuration(n7.MODES[arm]) for arm in n7.ARMS]
    assert configs[0].reservation("agent").config_sha256 != configs[1].reservation("agent").config_sha256
    assert n7.ARM_CAPS[Arm.A0] == Decimal("0.012096")
    assert n7.ARM_CAPS[Arm.A1] == Decimal("0.014096")


def canned_audit(*usage: n7_report.Usage, settled: str = "0") -> n7_report.Audit:
    calls = tuple(n7_report.Call(index, 100, value) for index, value in enumerate(usage, 1))
    return n7_report.Audit(calls, len(calls), Decimal(settled), len(calls), {}, {})


@pytest.mark.parametrize(("failure", "check"), [
    ("read_miss", "A1_call_2_prefix_read"),
    ("rewrite", "A1_later_writes_deltas"),
    ("off_leak", "A0_cache_off_after_warm_A1"),
    ("ledger_mismatch", "ledger_and_tape_integrity"),
    ("no_later", "A1_later_writes_deltas"),
    ("long_gap", "A0_cache_off_after_warm_A1"),
])
def test_pilot_admits_observed_reuse_and_stops_on_each_integrity_failure(failure: str, check: str) -> None:
    (frame,) = n7.blocks(n7.schedule(dev_cases(), "pilot"), STUDY, WORKSPACE)
    cold = n7_report.Usage(2000, 0, 1920, 0, 50, 5)
    cross = replace(cold, read=1800, write_30m=0)
    warm = replace(cold, input=2400, read=1920, write_30m=400)
    delta = replace(cold, input=2700, read=2300, write_30m=300)
    off = replace(cold, write_30m=0)
    audits = {}
    runs = {}
    start = datetime(2026, 11, 22, tzinfo=UTC)
    first_a1 = next(item for item in frame if item.arm is Arm.A1)
    for index, item in enumerate(frame):
        audits[item.slot.id] = (canned_audit(off, off) if item.arm is Arm.A0
                                else canned_audit(cold if item == first_a1 else cross, warm, delta))
        when = start + timedelta(seconds=10 * index)
        runs[item.slot.id] = n7_report.RunData(started_at=when, updated_at=when + timedelta(seconds=5))
    passed = n7_report.pilot_gate(frame, audits, runs, complete=True, integrity=True)
    assert passed["verdict"] == "admit" and passed["A1_call_1_cross_investigation_reuse_slots"] == 2

    first_on = next(item for item in frame if item.arm is Arm.A1)
    first_off = next(item for item in frame if item.arm is Arm.A0)
    if failure == "read_miss":
        audits[first_on.slot.id] = canned_audit(cold, replace(warm, read=0), delta)
    elif failure == "rewrite":
        audits[first_on.slot.id] = canned_audit(cold, warm, replace(delta, read=0, write_30m=2600))
    elif failure == "off_leak":
        audits[first_off.slot.id] = canned_audit(replace(off, read=1))
    elif failure == "no_later":
        for item in frame:
            if item.arm is Arm.A1:
                audits[item.slot.id] = canned_audit(cold, warm)
    elif failure == "long_gap":
        for item in frame:
            if item.arm is Arm.A0:
                runs[item.slot.id] = replace(runs[item.slot.id], started_at=start + timedelta(hours=1))
    failed = n7_report.pilot_gate(frame, audits, runs, complete=True, integrity=failure != "ledger_mismatch")
    assert failed["verdict"] == "stop" and failed["checks"][check] is False


def test_audit_prices_raw_buckets_and_detects_ledger_mismatch() -> None:
    case = dev_cases()[0]
    item = n3.Assignment(Arm.A1, 1, case, runtime.Slot(WORKSPACE, STUDY))
    count = '{"input":[]}'
    create = '{"input":[],"prompt_cache_options":{"mode":"implicit","ttl":"30m"}}'
    count_sha, create_sha = n7.request_digest(count), n7.request_digest(create)
    assert count_sha and create_sha
    reference = n7.Requests(create_sha, count_sha, DIGEST, DIGEST, DIGEST)
    response = json.dumps({"id": "resp_1", "model": "gpt-6-luna", "service_tier": "default",
                           "output": 1, "usage": {"input_tokens": 2000,
                           "input_tokens_details": {"cached_tokens": 1000, "cache_write_tokens": 650,
                                                    "cache_write_tokens_details": {
                                                        "ttl_30m_tokens": 600, "ttl_12h_tokens": 50}},
                           "output_tokens": 50, "output_tokens_details": {"reasoning_tokens": 5},
                           "total_tokens": 2050}})
    expected = n7_report.Usage(2000, 1000, 600, 50, 50, 5)
    assert n7_report.raw_usage(response) == (expected, "resp_1")
    tape = [Exchange(index=0, attempt=0, phase="count", request=count, request_sha256=count_sha,
                     response='{"input_tokens": 2000}', status=200, complete=True),
            Exchange(index=1, attempt=0, phase="create", request=create, request_sha256=create_sha,
                     response=response, status=200, complete=True)]
    spend = Decimal("0.0001575")
    block = "cache_ttl_unrequested"
    row = n7_report.Attempt(n7_report.attempt_id(item.slot.run, 0), "settled", 2000, block, "resp_1",
                            "short", spend, expected.ledger("resp_1", block))
    result = n7_report.audit(item, tape, [row], reference)
    assert result.checks == dict.fromkeys(result.checks, True) | {"requested_A1_ttl": False}
    assert result.settled == spend and result.checked_calls == 1
    changed = n7_report.audit(item, tape, [replace(row, actual_usd=Decimal(0))], reference)
    assert not changed.checks["ledger_matches"]
    undercount = n7_report.audit(item, tape, [replace(row, block="count_underestimate")], reference)
    assert not undercount.checks["count_bound"]


class Backend:
    def __init__(self) -> None:
        self.states: dict[UUID, RunState] = {}
        self.executed: list[Arm] = []

    def accounts(self, frame: Sequence[n3.Assignment]) -> dict[UUID, RunState]:
        return {item.slot.id: self.states[item.slot.id] for item in frame if item.slot.id in self.states}

    def terminal(self, _: n3.Assignment) -> Terminal | None:
        return Terminal("succeeded", 100)

    def execute(self, item: n3.Assignment, _: Tape) -> None:
        self.executed.append(item.arm)
        spend = Decimal("0.013") if item.arm is Arm.A1 else Decimal("0.01")
        self.states[item.slot.id] = RunState(Ledger(settled=spend))


def test_rolling_cap_reserves_the_30m_slot_and_resume_preserves_it(tmp_path: Path) -> None:
    (frame,) = n7.blocks(n7.schedule(dev_cases(), "pilot"), STUDY, WORKSPACE)
    off, on = sorted(frame[:2], key=lambda item: item.arm)
    blocks = ((on, off),)
    backend = Backend()
    closed: list[str] = []
    for cap, verdict in (("0.025", "budget_stop"), ("0.026192", "complete"), ("0.026192", "complete")):
        assert n3_runner.run_blocks(backend, blocks, tmp_path, DIGEST, Decimal(cap),
                                    check_lock=lambda: None, close=closed.append, arm_caps=n7.ARM_CAPS,
                                    stop_on_accounting_issue=True) == verdict
    assert backend.executed == [Arm.A1, Arm.A0] and closed == ["budget_stop"]


def test_resume_stops_for_an_active_attempt_even_after_its_bill_settled(tmp_path: Path) -> None:
    (frame,) = n7.blocks(n7.schedule(dev_cases(), "pilot"), STUDY, WORKSPACE)

    class InterruptedBackend(Backend):
        def terminal(self, _: n3.Assignment) -> None:
            return None

    backend = InterruptedBackend()
    backend.states[frame[0].slot.id] = RunState(
        Ledger(settled=Decimal("0.001"), consumed_calls=1, count_grants=1, attempts=1), active=True)
    closed: list[str] = []
    assert n3_runner.run_blocks(backend, (frame,), tmp_path, DIGEST, n7.CAPS["pilot"],
                                check_lock=lambda: None, close=closed.append, arm_caps=n7.ARM_CAPS,
                                stop_on_accounting_issue=True) == "accounting_stop"
    assert not backend.executed and closed == ["accounting_stop"]


def test_comparison_uses_scheduled_cost_and_proposal_horizon() -> None:
    frame = [item for block in n7.blocks(n7.schedule(dev_cases(), "study"), STUDY, WORKSPACE) for item in block]
    arms: dict[Arm, list[n7_report.Observation]] = {arm: [] for arm in n7.ARMS}
    for item in frame:
        off = item.arm is Arm.A0
        grade = Grade(off, False, off, False)
        run = n7_report.RunData(proposal_ms=100 if off else None)
        row = n7_report.Observation(item, grade, canned_audit(settled="0.002" if off else "0.001"), run, None)
        arms[item.arm].append(row)
    report = n7_report.comparison(arms[Arm.A0], arms[Arm.A1], complete=True, draws=20)
    assert report["settled_cost_ratio_A1_over_A0"]["low"] == 0.5
    assert report["settled_cost_difference_A1_minus_A0"]["point"] == -0.001
    assert report["proposal_time_difference_at_horizon_ms"]["point"] == n7.HORIZON_MS - 100
    assert report["outcome_guardrail"]["verdict"] == "fail"
    assert report["exact_first_proposal"]["between_arm"]["A0_only"] == 192
    assert report["unsafe_attempt"]["between_arm"]["pairs"] == 48
    assert report["exact_first_proposal"]["within_arm_repeat_disagreement"]["A0"]["pairs"] == 96
