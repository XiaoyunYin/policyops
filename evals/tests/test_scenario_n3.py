"""Offline protocol and failure-path checks with synthetic cases and billing."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import create_engine

from policyops.orchestration import investigation_prompt as prompt
from policyops.providers.tokenizer import load
from policyops_contracts.conversation import PolicyContext, UserMessage
from policyops_evals.scenarios import Refused, n3, n3_report, n3_runner
from policyops_evals.scenarios.arms import ABLATIONS, COMPARISON, Arm, identities
from policyops_evals.scenarios.batch import Ledger, Result, RunState, Terminal, read_result, slot_directory
from policyops_evals.scenarios.cases import POSITIVES, SCENARIOS, STRATA, Scenario
from policyops_evals.scenarios.grading import Grade
from policyops_evals.scenarios.n3_cli import require_unstarted
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.runtime import LIMITS, configuration


STUDY, WORKSPACE = UUID(int=1), UUID(int=2)
DIGEST = "a" * 64


def cases(*, per_stratum: int = 4) -> tuple[Scenario, ...]:
    case = SCENARIOS[0]
    result = []
    for stratum in STRATA:
        for index in range(per_stratum):
            key = f"{stratum}-{index}"
            gold = replace(case.gold, key=key, stratum=stratum, family=f"{stratum}-f{index % 2}", customer_world=key)
            result.append(replace(case, key=key, gold=gold))
    return tuple(result)


def dev_cases() -> tuple[Scenario, ...]:
    return tuple(case for case in cases(per_stratum=24)
                 if case.gold.stratum in POSITIVES or int(case.key.rsplit("-", 1)[1]) < 8)


def test_seeded_order_shared_half_and_slot_identity() -> None:
    dev = cases()
    groups = n3.case_groups(dev, "dev")
    assert groups == n3.case_groups(tuple(reversed(dev)), "dev")
    assert [g.case.gold.stratum for g in groups[:len(STRATA)]] == list(STRATA)
    assert {g.arms[0][0] for g in groups} == set(COMPARISON)
    assert all({arm for arm, repeat in g.arms[:2] if repeat == 1} == set(COMPARISON) for g in groups)
    assert Counter(g.case.gold.stratum for g in groups if len(g.arms) == 5) == dict.fromkeys(STRATA, 2)
    assert all({arm for arm, _ in g.arms[2:4]} == set(ABLATIONS) for g in groups if len(g.arms) == 5)
    blocks = n3.blocks(groups, "dev", STUDY, WORKSPACE)
    frame = [item for block in blocks for item in block]
    assert all(len(block) <= 32 for block in blocks)
    assert len({item.slot.id for item in frame}) == len(frame) == len({item.slot.run for item in frame})
    first = frame[0]
    assert first.slot == n3.assigned_slot(STUDY, WORKSPACE, "dev", first.arm, 1, first.case.key)
    assert first.slot != n3.assigned_slot(STUDY, WORKSPACE, "held-out", first.arm, 1, first.case.key)
    holdout = n3.case_groups(dev, "held-out")
    assert all(len(group.arms) == 2 for group in holdout)
    with pytest.raises(Refused, match="slot binding"):
        n3.assigned_slot(STUDY, WORKSPACE, "held-out", Arm.WITHOUT_PROMPT, 1, first.case.key)


def test_revision_schedule_has_seeded_pairs_and_only_dev_ambiguous_extras() -> None:
    dev = dev_cases()
    groups = n3.case_groups(dev, "dev", candidate=Arm.REVISION)
    assert groups == n3.case_groups(tuple(reversed(dev)), "dev", candidate=Arm.REVISION)
    assert [g.case.gold.stratum for g in groups[:len(STRATA)]] == list(STRATA)
    assert {g.arms[0][0] for g in groups} == {Arm.BASELINE, Arm.REVISION}
    assert all(set(g.arms[:2]) == {(Arm.BASELINE, 1), (Arm.REVISION, 1)} for g in groups)
    blocks = n3.blocks(groups, "dev", STUDY, WORKSPACE)
    frame = [item for block in blocks for item in block]
    assert [item.case.key for item in frame] == [g.case.key for g in groups for _ in g.arms]
    assert all(len(block) <= 32 for block in blocks)
    assert len({item.slot.id for item in frame}) == len(frame) == 408
    assert Counter((item.arm, item.repeat) for item in frame) == {
        (Arm.BASELINE, 1): 128, (Arm.REVISION, 1): 128, (Arm.REVISION, 2): 128,
        **{(Arm.REVISION, repeat): 8 for repeat in n3.EXTRA_REPEATS},
    }
    assert {item.case.gold.stratum for item in frame if item.repeat > 2} == {"multi_ambiguous"}
    held_out = n3.case_groups(dev, "held-out", candidate=Arm.REVISION)
    assert all(set(g.arms) == {(Arm.BASELINE, 1), (Arm.REVISION, 1)} for g in held_out)
    with pytest.raises(Refused, match="slot binding"):
        n3.assigned_slot(STUDY, WORKSPACE, "held-out", Arm.REVISION, 3, dev[0].key)


def test_profile_and_ablations_change_the_active_runtime_configuration() -> None:
    policy = PolicyContext(domain="retail", source="fictional", text="Policy text.",
                           sha256=sha256(b"Policy text.").hexdigest())
    engine = create_engine("postgresql+psycopg://")
    try:
        identity = identities(engine, policy, load(), env="test")
    finally:
        engine.dispose()
    b, c, f, d = (identity[arm] for arm in (*COMPARISON, *ABLATIONS))
    assert b.prompt_sha256 == "3f4e1c679f32b1f655bcb7d213ab6a3a5c09951745dd8d69aa63bacb768d208c"
    assert c.prompt_sha256 == "17c96f02332972ab349cb001518165ec51abdb2dfa9e163fc8627ee21ce8e7ca"
    assert c.catalog_sha256 == f.catalog_sha256 == d.catalog_sha256 != b.catalog_sha256
    assert c.graph_sha256 == f.graph_sha256 == d.graph_sha256 != b.graph_sha256
    assert c.notice_table_sha256 == f.notice_table_sha256 == d.notice_table_sha256
    assert b.instruction_sha256 == f.instruction_sha256 != c.instruction_sha256 == d.instruction_sha256
    assert b.lexical_mode == d.lexical_mode == "all_terms"
    assert c.lexical_mode == f.lexical_mode == "bm25"
    assert len({arm.config_sha256 for arm in identity.values()}) == 4
    assert len({arm.profile_sha256 for arm in identity.values()}) == 4
    requests = {}
    for arm in identity:
        with arm.compose():
            requests[arm] = prompt.request(policy, LIMITS, (UserMessage(text="Hello"),), profile=arm.profile)
            assert prompt.digest(arm.profile) == identity[arm].prompt_sha256
            assert arm.profile.lexical_mode == identity[arm].lexical_mode
    assert requests[Arm.WITHOUT_PROMPT].instructions == requests[Arm.BASELINE].instructions
    assert requests[Arm.WITHOUT_PROMPT].tools == requests[Arm.CANDIDATE].tools
    assert requests[Arm.WITHOUT_BM25] == requests[Arm.CANDIDATE]
    assert Arm.CANDIDATE.profile.lexical_mode == "bm25"


class Scripted:
    def __init__(self, *, crash: bool = False, unresolved: bool = False) -> None:
        self.calls: list[UUID] = []
        self.live: dict[UUID, RunState] = {}
        self.crash = crash
        self.unresolved = unresolved

    def accounts(self, frame: Sequence[n3.Assignment]) -> dict[UUID, RunState]:
        return {item.slot.id: self.live[item.slot.id] for item in frame if item.slot.id in self.live}

    def terminal(self, item: n3.Assignment) -> Terminal | None:
        state = self.live.get(item.slot.id)
        return Terminal("succeeded", 9) if state is not None and not state.active else None

    def execute(self, item: n3.Assignment, tape: Tape) -> None:
        key = item.slot.id
        self.calls.append(key)
        self.live[key] = RunState(
            Ledger(held=Decimal("0.009"), count_grants=1, consumed_calls=1)
            if self.unresolved else Ledger(settled=Decimal("0.001"), count_grants=1))
        if self.crash:
            self.crash = False
            raise KeyboardInterrupt


def _two_pairs() -> tuple[tuple[n3.Assignment, ...], ...]:
    frame = n3.blocks(n3.case_groups(cases(per_stratum=1)[:2], "held-out"), "held-out", STUDY, WORKSPACE)[0]
    return frame[:2], frame[2:]


def test_rolling_budget_charges_unresolved_v2_hold_and_active_headroom(tmp_path: Path) -> None:
    blocks = _two_pairs()
    closure: list[str] = []
    backend = Scripted(unresolved=True)
    slot_cap = configuration().caps.run_usd
    assert n3_runner.rolling_worst({STUDY: RunState(Ledger(held=slot_cap / 2), active=True)}, 2) == 3 * slot_cap
    status = n3_runner.run_blocks(backend, blocks, tmp_path, DIGEST, 2 * slot_cap + Decimal("0.017"),
                                  check_lock=lambda: None, close=closure.append)
    assert status == "budget_stop" and closure == ["budget_stop"]
    assert backend.calls == [item.slot.id for item in blocks[0]]
    first = read_result(tmp_path, blocks[0][0].slot, DIGEST)
    assert first is not None and first.status == "held"
    assert not any(slot_directory(tmp_path, item.slot).exists() for item in blocks[1])


@pytest.mark.parametrize("headroom, expected", [(Decimal("0"), "complete"), (Decimal("-0.00000001"), "budget_stop")])
def test_revision_admission_charges_e1_spend(tmp_path: Path, headroom: Decimal, expected: str) -> None:
    groups = n3.case_groups(dev_cases()[:1], "dev", candidate=Arm.REVISION)
    blocks = n3.blocks(groups, "dev", STUDY, WORKSPACE)
    maximum = n3.E1_SETTLED_USD + 3 * configuration().caps.run_usd + headroom
    n3_runner.validate_cap("dev", maximum)
    closure: list[str] = []
    backend = Scripted()
    assert n3_runner.run_blocks(backend, blocks, tmp_path, DIGEST, maximum, prior_settled=n3.E1_SETTLED_USD,
                                check_lock=lambda: None, close=closure.append) == expected
    assert closure == ([] if expected == "complete" else ["budget_stop"])
    assert len(backend.calls) == (3 if expected == "complete" else 0)


def test_resume_preserves_dispatched_slot_and_reuses_predispatch_marker(tmp_path: Path) -> None:
    blocks = _two_pairs()
    closure: list[str] = []
    first, second = blocks[0]
    slot_directory(tmp_path, second.slot).mkdir()  # crash after making a marker but before dispatch
    scripted = Scripted(crash=True)
    with pytest.raises(KeyboardInterrupt):
        n3_runner.run_blocks(scripted, blocks, tmp_path, DIGEST, n3.DEV_CAP,
                             check_lock=lambda: None, close=closure.append)
    assert read_result(tmp_path, first.slot, DIGEST) is None
    for _ in range(2):
        assert n3_runner.run_blocks(scripted, blocks, tmp_path, DIGEST, n3.DEV_CAP,
                                    check_lock=lambda: None, close=closure.append) == "complete"
    assert scripted.calls == [item.slot.id for block in blocks for item in block]
    assert closure == []
    with pytest.raises(Refused, match="slot already exists"):
        n3_runner.refuse_existing(scripted, [item for block in blocks for item in block], tmp_path)


@pytest.mark.parametrize("fail", ["lower_bound", "point_delta", "safety_guard", "harness", "integrity", "complete"])
def test_each_gate_condition_is_required(fail: str) -> None:
    point = Fraction(19, 100) if fail == "point_delta" else Fraction(1, 5)
    low = Fraction(0) if fail == "lower_bound" else Fraction(1, 10)
    safety = Fraction(6, 100) if fail == "safety_guard" else Fraction(1, 20)
    report = n3_report.verdict(point, low, safety, complete=fail != "complete",
                               harness=fail != "harness", integrity=fail != "integrity")
    assert report["verdict"] == ("incomplete" if fail == "complete" else "reject")
    assert [name for name, passed in report["checks"].items() if not passed] == [fail]


def test_admission_and_historical_grader_identity() -> None:
    gate = n3_report.verdict(Fraction(1, 5), Fraction(1, 10), Fraction(1, 20),
                             complete=True, harness=True, integrity=True)
    assert gate["verdict"] == "admit"
    for refused in (None, {"verdict": "reject"}, {"verdict": "incomplete"}):
        with pytest.raises(Refused, match="admitted dev gate"):
            require_unstarted(refused, None)
    require_unstarted(gate, None)
    with pytest.raises(Refused, match="already unsealed"):
        require_unstarted(gate, {"registration_sha256": DIGEST})
    assert n3.grader_digest() == "739f01531de207845e532c1ff9126a6ee1ddd7f5febfeffa6d1b3d4169c8fe15"
    assert n3_report.mcnemar({"candidate_only": 4, "baseline_only": 0})["p_two_sided"] == 0.125


@pytest.mark.parametrize(("unsafe", "expected"), [(1, "admit"), (2, "reject")])
def test_revision_gate_counts_unsafe_extras_beyond_the_paired_safety_guard(unsafe: int, expected: str) -> None:
    groups = n3.case_groups(dev_cases(), "dev", candidate=Arm.REVISION)
    frame = [item for block in n3.blocks(groups, "dev", STUDY, WORKSPACE) for item in block]
    unsafe_ids = [item.slot.id for item in frame if item.repeat in n3.EXTRA_REPEATS][:unsafe]
    results, live = {}, {}
    for item in frame:
        primary = item.arm is Arm.REVISION and item.case.gold.stratum in POSITIVES
        grade = Grade(primary, item.slot.id in unsafe_ids, primary, False)
        result = Result(slot_id=item.slot.id, run_id=item.slot.run, registration_sha256=DIGEST,
                        recorded_at=datetime.now(UTC), status="finalized", ledger=Ledger(), grade=grade,
                        stop_reason="succeeded")
        results[item.slot.id] = result
        live[item.slot.id] = RunState(result.ledger)
    evidence = n3_report.Evidence(results, live, {}, set(), DIGEST)
    report = n3_report.comparison(frame, evidence, "dev", candidate=Arm.REVISION, detail=False, draws=40)
    assert report["safety"]["delta"]["scheduled"] == 24
    assert report["primary"]["scheduled"] == 96
    assert report["ambiguous_slots"] == {
        "scheduled": 40, "recorded": 40, "unsafe": unsafe, "unsafe_max": 1, "pass": unsafe == 1,
    }
    assert report["cumulative_dev_v2_ledger"]["settled_usd"] == str(n3.E1_SETTLED_USD)
    assert report["gate"]["verdict"] == expected
    assert [name for name, passed in report["gate"]["checks"].items() if not passed] == (
        [] if unsafe == 1 else ["ambiguous_guard"])


def test_held_out_requires_admission_for_the_current_revision_digest() -> None:
    admitted = {"verdict": "admit", "candidate_sha256": DIGEST}
    require_unstarted(admitted, None, candidate_sha256=DIGEST)
    with pytest.raises(Refused, match="candidate digest"):
        require_unstarted(admitted, None, candidate_sha256="b" * 64)
    with pytest.raises(Refused, match="candidate digest"):
        require_unstarted({"verdict": "admit"}, None, candidate_sha256=DIGEST)
    with pytest.raises(Refused, match="admitted dev gate"):
        require_unstarted(admitted | {"verdict": "reject"}, None, candidate_sha256=DIGEST)


def test_held_out_claim_uses_scheduled_pairs_and_independent_proposal_check() -> None:
    blocks = n3.blocks(n3.case_groups(cases(per_stratum=2), "held-out"), "held-out", STUDY, WORKSPACE)
    frame = [item for block in blocks for item in block]
    results = {}
    live = {}
    for item in frame:
        primary = item.arm is Arm.CANDIDATE and item.case.gold.stratum in POSITIVES
        result = Result(slot_id=item.slot.id, run_id=item.slot.run, registration_sha256=DIGEST,
                        recorded_at=datetime.now(UTC), status="finalized", ledger=Ledger(),
                        grade=Grade(primary, False, primary, False), stop_reason="succeeded")
        results[item.slot.id] = result
        live[item.slot.id] = RunState(result.ledger)
    evidence = n3_report.Evidence(results, live, {}, set(), DIGEST)
    paid = frame[0].slot.id
    hold = Ledger(held=Decimal("0.009"), count_grants=1, consumed_calls=1, attempts=1)
    results[paid] = results[paid].model_copy(update={"status": "held", "ledger": hold, "terminal_ms": 9})
    live[paid] = RunState(hold.model_copy(update={"held": Decimal(0), "settled": Decimal("0.001")}))
    report = n3_report.comparison(frame, evidence, "held-out", draws=40)
    assert report["primary_claim"]
    assert report["primary"]["point"] == 1 and report["primary"]["scheduled"] == 8
    assert report["discordant_counts"]["candidate_only"] == 8
    assert report["exact_mcnemar"]["p_two_sided"] == 2 / 256
    assert report["informative_improvement_descriptive"]

    delivered = next(item.slot.id for item in frame if item.case.gold.stratum == "delivered_refusal")
    live[delivered] = replace(live[delivered], proposed=True)
    report = n3_report.comparison(frame, evidence, "held-out", draws=40)
    assert not report["primary_claim"] and not report["delivered_cancellation"]["pass"]

    missing = next(item.slot.id for item in frame if item.arm is Arm.CANDIDATE and item.case.gold.stratum in POSITIVES)
    del results[missing]
    report = n3_report.comparison(frame, evidence, "held-out", draws=40)
    assert not report["primary_claim"] and report["primary"]["scheduled"] == 8
    assert report["primary"]["point"] == 7 / 8
