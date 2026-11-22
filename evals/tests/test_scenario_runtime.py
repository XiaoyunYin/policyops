"""Real PostgreSQL, retail ASGI, workbench, and provider adapters. Every model reply is scripted."""

from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from policyops.orchestration import investigation_prompt
from policyops.persistence.evaluation import EvaluationRepository
from policyops.persistence.roles import EVAL_RUNTIME
from policyops.runtime.investigation import graph_digest
from policyops.runtime.spec import RuntimeSpec
from policyops_evals.scenarios import n3, n3_runner
from policyops_evals.scenarios.arms import identities
from policyops_evals.scenarios.batch import AppBackend, read_result, run_batch, serial_lock
from policyops_evals.scenarios.cases import SCENARIOS, Scenario, Stratum
from policyops_evals.scenarios.recording import Replay, ReplayMismatch, Tape
from policyops_evals.scenarios.runtime import Profile, Slot, Summary
from policyops_evals.scenarios.study import assigned_slot, register
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import World

from .scenario_support import ABSTAIN, Script, call, no_authority_or_execution
from .scenario_support import database as database
from .scenario_support import profile as profile


pytestmark = pytest.mark.postgres
POSITIVE, NEGATIVE = SCENARIOS



def reference(scenario: Scenario) -> list[dict[str, object]]:
    return [
        call("find_user_id_by_email", {"email": scenario.visible.lookup_email}, 1),
        call("get_order_details", {"order_id": scenario.world.order_id}, 2),
        call("search_policy", {"query": "cancel"}, 3),
        (call("finish_answer", ABSTAIN, 4) if scenario.gold.action is None
         else call("cancel_pending_order", scenario.gold.action.model_dump(exclude={"tool"}), 4)),
    ]


@pytest.mark.parametrize("mode", ["proposal", "delivered", "malformed", "confirmation",
                                  "tool_cap", "call_cap", "retrieval_cap", "invalid_cap"])
def test_scripted_workbench(profile: tuple[Profile, World], mode: str) -> None:
    runtime, world = profile
    scenario = NEGATIVE if mode == "delivered" else POSITIVE
    replies: list[dict[str, object] | str] = list(reference(scenario))
    label, stop, passed = "exact proposal", "waiting_approval", True
    retrieval_traces = 1
    if mode == "delivered":
        label, stop = "retrieval miss leading to an abstention", "succeeded"
    elif mode == "malformed":
        replies.insert(3, call("cancel_pending_order", "{", 5))
        label, passed = "malformed write", False
    elif mode == "confirmation":
        replies[-1] = "Please confirm that you want to cancel the order."
        label, stop, passed = "asked for confirmation", "succeeded", False
    elif mode in {"tool_cap", "call_cap", "retrieval_cap", "invalid_cap"}:
        label, stop, passed = "cap stop", mode, False
        replies = [call("calculate", {"expression": "2 + 2"}, i) for i in range(8)]
        retrieval_traces = 0
        if mode == "call_cap":
            replies[6] = call("calculate", "{", 6)  # Leave room for another tool when the eighth call completes.
        elif mode == "retrieval_cap":
            replies = [call("search_policy", {"query": "cancel"}, i) for i in range(3)]
            retrieval_traces = 2
        elif mode == "invalid_cap":
            replies = [call("calculate", "{", i) for i in range(2)]
    slot, tape = Slot(world.ws, uuid4()), Tape()
    script = Script(runtime.tokenizer, replies)
    result = runtime.run_scripted(scenario, slot, tape, script)
    assert (result.first_decision, result.stop_reason, result.gold_match) == (label, stop, passed)
    assert result.calls == script.created == len(replies)
    assert result.settled_usd > 0 and result.held_usd == 0
    assert max(script.counts) + max(256, (max(script.counts) + 9) // 10) <= 10_000
    assert world.count("app.action_proposals") == int(stop == "waiting_approval")
    assert world.count("app.retrieval_traces") == retrieval_traces
    no_authority_or_execution(world)
    assert runtime.run_scripted(scenario, slot, tape, script).stop_reason == stop
    assert world.count("app.runs") == 1 and script.created == len(replies)


def test_scripted_replay_and_request_divergence(profile: tuple[Profile, World]) -> None:
    runtime, world = profile
    tape, original = Tape(), Slot(world.ws, uuid4())
    first = runtime.run_scripted(POSITIVE, original, tape, Script(runtime.tokenizer, reference(POSITIVE)))
    assert first.gold_match
    recorded = tuple(tape.records)
    replay_slot = Slot(world.ws, uuid4())
    replay = Replay(recorded, replay_slot.redactor(), replay_slot.run)
    replay_tape = Tape()
    other = runtime.run_scripted(POSITIVE, replay_slot, replay_tape, replay)
    replay.verify()
    assert [(item.attempt, item.phase, item.request_sha256) for item in replay_tape.records] == [
        (item.attempt, item.phase, item.request_sha256) for item in recorded]
    assert (other.first_decision, other.gold_match, other.stop_reason, other.calls) == (
        first.first_decision, first.gold_match, first.stop_reason, first.calls)
    assert other.settled_usd == first.settled_usd and other.held_usd == first.held_usd == 0
    changed = replace(POSITIVE, visible=replace(POSITIVE.visible, message=POSITIVE.visible.message + " Thanks."))
    different = Slot(world.ws, uuid4())
    mismatch = Replay(recorded, different.redactor(), different.run)
    runtime.run_scripted(changed, different, Tape(), mismatch)
    with pytest.raises(ReplayMismatch, match="request digest mismatch"):
        mismatch.verify()
    no_authority_or_execution(world)


def test_two_slot_dev_batch_recovers_after_app_completion(profile: tuple[Profile, World],
                                                       database: tuple[AppDatabase, Path, Path],
                                                       tmp_path: Path) -> None:
    runtime, world = profile
    graph, prompt = graph_digest(), investigation_prompt.digest()
    repository = EvaluationRepository(database[0].engine(EVAL_RUNTIME))
    document = register(repository, {"scripted": True}, 2)
    identity, digest = UUID(document["study_id"]), document["receipt"]["sha256"]
    cases = [
        replace(POSITIVE, gold=replace(POSITIVE.gold, stratum="cancel", customer_world=POSITIVE.world.customer_id)),
        replace(NEGATIVE, gold=replace(NEGATIVE.gold, stratum="delivered_refusal",
                                       customer_world=NEGATIVE.world.customer_id)),
    ]
    schedule = [(case, assigned_slot(identity, world.ws, "dev", 1, case.key)) for case in cases]
    scripts = {slot.id: Script(runtime.tokenizer, reference(case), str(index))
               for index, (case, slot) in enumerate(schedule)}
    started = []

    def execute(case: Scenario, slot: Slot, tape: Tape) -> Summary:
        started.append(slot.id)
        result = runtime.run_scripted(case, slot, tape, scripts[slot.id])
        if slot == schedule[0][1]:
            raise KeyboardInterrupt  # Workbench committed; result JSON has not been written.
        return result

    backend = AppBackend(runtime.app, world.ws, graph, prompt, execute)
    out = tmp_path / "dev"
    out.mkdir()
    max_usd = Decimal("0.024192")
    with serial_lock(runtime.app, identity) as check_lock, pytest.raises(KeyboardInterrupt):
        run_batch(backend, schedule, out, digest, max_usd, check_lock=check_lock)
    before = backend.accounts([schedule[0][1]])
    assert world.count("app.runs") == 1 and read_result(out, schedule[0][1], digest) is None
    with serial_lock(runtime.app, identity) as check_lock:
        recovered = run_batch(backend, schedule, out, digest, max_usd, check_lock=check_lock)
        assert run_batch(backend, schedule, out, digest, max_usd, check_lock=check_lock) == recovered
    assert started == [slot.id for _, slot in schedule]
    assert world.count("app.runs") == 2 and world.count("app.action_proposals") == 1
    assert backend.accounts([schedule[0][1]]) == before
    first, second = (recovered[slot.id] for _, slot in schedule)
    assert first.grade.primary and first.decision_ms is not None
    assert second.grade.unsafe_attempt is False and second.terminal_ms is not None
    assert all(item.ledger is not None and item.ledger.consumed_calls == 4 for item in recovered.values())
    no_authority_or_execution(world)


def test_n3_two_arm_paired_dev_resumes_mid_pair(profile: tuple[Profile, World],
                                           database: tuple[AppDatabase, Path, Path], tmp_path: Path) -> None:
    runtime, world = profile
    repo = EvaluationRepository(database[0].engine(EVAL_RUNTIME))
    document = n3.register(repo, {"scripted_n3": True})
    study_id, digest = UUID(document["study_id"]), document["receipt"]["sha256"]
    n3.verify_registration(repo, study_id, document["receipt"])
    cases_and_strata: tuple[tuple[Scenario, Stratum], ...] = ((POSITIVE, "cancel"), (NEGATIVE, "delivered_refusal"))
    cases = [
        replace(case, gold=replace(case.gold, stratum=stratum, customer_world=case.world.customer_id))
        for case, stratum in cases_and_strata
    ]
    paired = tuple(n3.CaseGroup(group.case, group.arms[:2]) for group in n3.case_groups(cases, "dev"))
    blocks = n3.blocks(paired, "dev", study_id, world.ws)
    frame = [item for block in blocks for item in block]
    scripts = {item.slot.id: Script(runtime.tokenizer, reference(item.case), f"n3_{index}")
               for index, item in enumerate(frame)}
    started = []
    out = tmp_path / "n3"
    out.mkdir()
    arms = identities(runtime.app, runtime.policy, runtime.tokenizer)

    def execute(item: n3.Assignment, tape: Tape, bind: Callable[[RuntimeSpec], RuntimeSpec]) -> None:
        started.append(item.slot.id)
        runtime.run_scripted(item.case, item.slot, tape, scripts[item.slot.id], profile=item.arm.profile,
                             bind_spec=bind)
        if len(started) == 1:
            raise KeyboardInterrupt

    def unused(*_: object) -> Summary:
        raise AssertionError("dispatch must carry an arm")

    backends = {arm: AppBackend(runtime.app, world.ws, identity.graph_sha256, identity.prompt_sha256,
                               unused, config_for=lambda slot: n3_runner.config_digest(out, slot))
                for arm, identity in arms.items()}
    backend = n3_runner.ArmBackend(backends, arms, out, execute)
    closed: list[str] = []
    with serial_lock(runtime.app, study_id) as check_lock, pytest.raises(KeyboardInterrupt):
        n3_runner.run_blocks(backend, blocks, out, digest, n3.DEV_CAP, check_lock=check_lock, close=closed.append)
    assert read_result(out, frame[0].slot, digest) is None
    assert world.count("app.runs") == 1
    live = backend.accounts(frame)
    with serial_lock(runtime.app, study_id) as check_lock:
        assert n3_runner.run_blocks(backend, blocks, out, digest, n3.DEV_CAP, check_lock=check_lock,
                                    close=closed.append) == "complete"
    assert started == [item.slot.id for item in frame] and not closed
    assert backend.accounts(frame[:1]) == live
    assert world.count("app.runs") == 4 and world.count("app.action_proposals") == 2
    for item in frame:
        result = read_result(out, item.slot, digest)
        assert result is not None and result.ledger is not None and result.ledger.consumed_calls == 4
        assert bool(result.grade.primary) == (item.case.gold.stratum == "cancel")
    no_authority_or_execution(world)
