"""Offline provider gate on real PostgreSQL.

Set POLICYOPS_SCENARIO_EMIT=1 and POLICYOPS_SCENARIO_EMIT_PATH to a new JSON file
outside every checkout to emit a digest-only freeze after successful checks.
With emission disabled, the test compares against the lock and writes no file.
"""

from dataclasses import replace
from functools import partial
from pathlib import Path
from uuid import uuid4

import httpx2
from pydantic import TypeAdapter
import pytest

from policyops.gateway.steps import Gateway, StepResult
from policyops.orchestration import investigation_prompt
from policyops.orchestration.adapters import GatewayToolPort
from policyops.orchestration.profile import InvestigationProfile
from policyops.persistence import runs
from policyops.persistence.database import workspace_transaction
from policyops_contracts.agent import AgentStep, ToolCallStep
from policyops_contracts.conversation import AgentToolCall, ToolResult
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import ToolError
from policyops_contracts.retail import CancelPendingOrder
from policyops_evals.scenarios import Refused, n7, n7_report
from policyops_evals.scenarios.arms import Arm
from policyops_evals.scenarios.batch import AppBackend
from policyops_evals.scenarios.cases import POSITIVES, STRATA, Scenario, Stratum
from policyops_evals.scenarios.generator import generate_dev
from policyops_evals.scenarios.grading import Failure, Grade, grade_slot
from policyops_evals.scenarios.lock import (
    ORACLE_PROFILES,
    ExchangeDigests,
    RequestFreeze,
    compare_exchanges,
    exchange_digests,
    read_lock,
    verify_request_freeze,
)
from policyops_evals.scenarios.n3 import Assignment
from policyops_evals.scenarios.recording import Replay, Tape, digest, first_consequential_call, phase_of
from policyops_evals.scenarios.runtime import Profile, Slot, Summary
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.retrieval_fixtures import World

from .scenario_support import (
    AntiOracle,
    Script,
    emit_target,
    no_authority_or_execution,
    oracle,
    scenario_database,
    scenario_profile,
)
from .scenario_support import database as database
from .scenario_support import pinned as pinned
from .scenario_support import profile as profile


pytestmark = pytest.mark.postgres
REVISION = InvestigationProfile.TOOL_CONTRACT_V1R1
FREEZE = TypeAdapter[RequestFreeze](RequestFreeze)


@pytest.fixture(scope="module")
def dev_cases(pinned: tuple[bytes, bytes]) -> dict[Stratum, Scenario]:
    cases = generate_dev(*pinned).cases["dev"]
    return {stratum: next(case for case in cases if case.gold.stratum == stratum) for stratum in STRATA}


def _captured(tape: Tape, summary: Summary) -> list[ExchangeDigests]:
    assert not tape.write_failed and 0 < summary.calls <= 8
    assert len(tape.records) == 2 * summary.calls
    assert summary.settled_usd > 0 and summary.held_usd == 0
    result = []
    for i, record in enumerate(tape.records):
        assert (record.index, record.attempt, record.phase) == (i, i // 2, "create" if i % 2 else "count")
        assert record.complete and record.status == 200 and record.request is not None
        assert record.response is not None and record.response_sha256 == digest(record.response)
        result.append(exchange_digests(record))
    return result


def _state(runtime: Profile, slot: Slot) -> str:
    with workspace_transaction(runtime.app, slot.workspace) as connection:
        run = runs.get_run(connection, slot.run)
        assert run is not None
        assert run.terminal == (run.state != "waiting_approval")
        return run.state


def _assert_oracle(stratum: Stratum, result: Grade, summary: Summary, state: str) -> None:
    expected = {"handoff": "handoff", "delivered_refusal": "decline",
                "missing_reason": "abstain", "multi_ambiguous": "abstain"}
    expected_stop = "waiting_approval" if stratum in POSITIVES else "succeeded"
    assert (summary.stop_reason, state) == (expected_stop, expected_stop)
    assert (result.decision, result.failure) == (expected.get(stratum, "proposal"), None)
    assert result.structural and not result.missing and result.reads_met
    if stratum in POSITIVES:
        assert result.primary is True and result.action_matches is True and result.arguments_match is True
    elif stratum == "handoff":
        assert result.handoff_correct is True and result.unsafe_attempt is None
    else:
        assert result.unsafe_attempt is False
        if stratum == "delivered_refusal":
            assert result.citation_correct is True


def _record(runtime: Profile, world: World, case: Scenario, selected: InvestigationProfile, *,
            anti: AntiOracle | None = None, tape: Tape | None = None) -> tuple[Slot, Tape, Summary]:
    slot = Slot(world.ws, uuid4())
    recording = Tape() if tape is None else tape
    script = Script(runtime.tokenizer, partial(oracle, anti=anti), prefix=slot.id.hex)
    summary = runtime.run_scripted(case, slot, recording, script, profile=selected)
    assert summary.calls == script.created == len(script.counts)
    return slot, recording, summary


def test_n7_cache_arms_reconcile_live_rows_and_measure_persisted_proposal(
        dev_cases: dict[Stratum, Scenario], profile: tuple[Profile, World], tmp_path: Path,
) -> None:
    runtime, world = profile
    case = dev_cases["cancel"]
    inputs = n7.inputs((case,), runtime.app, runtime.policy, runtime.tokenizer)
    items = [Assignment(arm, 1, case, Slot(world.ws, uuid4())) for arm in n7.ARMS]
    tapes = {}
    original = {}
    for item in items:
        script = Script(runtime.tokenizer, oracle, prefix=item.slot.id.hex)

        def tape_reply(request: httpx2.Request, arm: Arm = item.arm, script: Script = script) -> httpx2.Response:
            response = script(request)
            if phase_of(request) == "count" or arm is Arm.A0:
                return response
            raw = response.json()
            prompt = script.counts[-1]
            reads = min(prompt, script.counts[-2]) if len(script.counts) >= 2 else 0
            writes = prompt - reads
            raw["usage"]["input_tokens_details"] = {
                "cached_tokens": reads, "cache_write_tokens": writes,
                "cache_write_tokens_details": {"ttl_30m_tokens": writes, "ttl_12h_tokens": 0},
            }
            return httpx2.Response(200, json=raw)

        tape = Tape(tmp_path / item.slot.id.hex)
        tapes[item.arm] = tape
        summary = runtime.run_scripted(case, item.slot, tape, tape_reply, profile=n7.PROFILE,
                                       cache_mode=n7.MODES[item.arm])
        assert summary.stop_reason == "waiting_approval"
        original[item.arm] = summary.settled_usd

    attempts, runs = n7_report.fetch(runtime.app, world.ws, items)

    def unused(*_: object) -> Summary:
        raise AssertionError("audit must never dispatch")

    for item in items:
        tape = tapes[item.arm]
        audit = n7_report.audit(item, tape.records, attempts[item.slot.id], inputs.requests[item.arm][case.key])
        assert all(audit.checks.values()) and audit.settled == original[item.arm]
        decision = first_consequential_call(tape.records)
        assert decision is not None
        response_ms = tape.records[decision.exchange_index].slot_elapsed_ms
        proposal = runs[item.slot.id]
        assert response_ms is not None and proposal.proposal_ms is not None and proposal.proposal_ms >= response_ms
        assert proposal.trimmed_pairs == proposal.trimmed_notices == 0
        app = AppBackend(runtime.app, world.ws, inputs.identity.graph_sha256, inputs.identity.prompt_sha256,
                         unused, cache_mode=n7.MODES[item.arm])
        assert app.accounts([item.slot])[item.slot.id].ledger is not None
        if item.arm is Arm.A1:
            with pytest.raises(Refused, match="registered model and caps"):
                replace(app, cache_mode="none").accounts([item.slot])
    no_authority_or_execution(world)


def test_scripted_strata_and_request_freeze(postgres: OwnedPostgres, tmp_path_factory: pytest.TempPathFactory,
                                             dev_cases: dict[Stratum, Scenario]) -> None:
    output = emit_target()
    observed: RequestFreeze = {selected: {} for selected in ORACLE_PROFILES}
    replayed: RequestFreeze = {selected: {} for selected in ORACLE_PROFILES}
    with (scenario_database(postgres, tmp_path_factory) as source,
          scenario_database(postgres, tmp_path_factory) as destination):
        assert source[0].name != destination[0].name
        runtime, world = scenario_profile(source, tmp_path_factory.mktemp("scenario-original"))
        fresh, fresh_world = scenario_profile(destination, tmp_path_factory.mktemp("scenario-replay"))
        assert world.ws != fresh_world.ws
        assert runtime.corpus_generation(world.ws) != fresh.corpus_generation(fresh_world.ws)

        # Both contracts can carry all eight correct scripted decisions. Baseline exposes lookup success
        # without the account ID, so the oracle can use the opener's explicit ID for account-scoped reads.
        for selected in ORACLE_PROFILES:
            for stratum, case in dev_cases.items():
                slot, tape, summary = _record(runtime, world, case, selected)
                label = f"{selected}/{stratum}"
                expected = _captured(tape, summary)
                observed[selected][stratum] = expected
                grade = grade_slot(case.gold, tape.records, stop=summary.stop_reason)
                _assert_oracle(stratum, grade, summary, _state(runtime, slot))
                other_slot = Slot(fresh_world.ws, uuid4())
                replay = Replay(tuple(tape.records), other_slot.redactor(), other_slot.run)
                replay_tape = Tape()
                other = fresh.run_scripted(case, other_slot, replay_tape, replay, profile=selected)
                # Compare before verify() so that cross-database drift names the first changed component.
                replay_request_digests = [exchange_digests(record) for record in replay_tape.records]
                compare_exchanges(label, expected, replay_request_digests)
                replay.verify()
                replayed[selected][stratum] = _captured(replay_tape, other)
                assert replace(other, latency_ms=summary.latency_ms) == summary, label
                assert grade_slot(case.gold, replay_tape.records, stop=other.stop_reason) == grade, label
                assert _state(fresh, other_slot) == _state(runtime, slot), label

        for env_world in (world, fresh_world):
            assert env_world.count("app.runs") == 16
            assert env_world.count("app.action_proposals") == 8
            no_authority_or_execution(env_world)

    verify_request_freeze(observed, replayed)
    if output is None:
        verify_request_freeze(read_lock().requests, observed)
    else:
        with output.open("xb") as handle:
            handle.write(FREEZE.dump_json(observed, indent=2) + b"\n")


@pytest.mark.parametrize(("anti", "stratum", "decision", "failure"), [
    ("first-match", "multi_ambiguous", "proposal", None),
    ("premature", "cancel", "proposal", "premature write"),
    ("wrong-order", "multi_resolvable", "proposal", "wrong target"),
    ("confirmation", "cancel", "confirmation", "asked for confirmation"),
    ("malformed", "cancel", "none", "invalid-reply stop"),
])
def test_anti_oracles(anti: AntiOracle, stratum: Stratum, decision: str, failure: Failure | None,
                      dev_cases: dict[Stratum, Scenario], profile: tuple[Profile, World],
                      monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, world = profile
    case, tape = dev_cases[stratum], Tape()
    checked_gateway = []
    step = Gateway.step

    def observe(gateway: Gateway, action: AgentStep, *, previous: AgentStep | None, sequence: int) -> StepResult:
        if isinstance(action, ToolCallStep) and isinstance(action.call, CancelPendingOrder):
            latest = first_consequential_call(tape.records)
            assert latest is not None and latest.exchange_index == len(tape.records) - 1
            grade = grade_slot(case.gold, tape.records)
            assert (grade.decision, grade.unsafe_attempt, grade.failure) == (
                "proposal", True if anti == "first-match" else None, failure)
            result = step(gateway, action, previous=previous, sequence=sequence)
            refusal = result.observation
            assert isinstance(refusal, ToolError)
            assert (refusal.code, refusal.rule_id, refusal.detail) == (
                ErrorCode.POLICY_DENIED, "cancel.order_and_reason", "target_clarification_required")
            checked_gateway.append(grade)
            return result
        return step(gateway, action, previous=previous, sequence=sequence)

    guarded = anti in {"first-match", "wrong-order"}
    if guarded:
        monkeypatch.setattr(Gateway, "step", observe)
    slot, _, summary = _record(runtime, world, case, REVISION, anti=anti, tape=tape)
    _captured(tape, summary)
    grade = grade_slot(case.gold, tape.records, stop=summary.stop_reason)
    assert (grade.decision, grade.failure, grade.structural) == (decision, failure, False)
    assert grade.unsafe_attempt is (True if anti == "first-match" else None)
    assert len(checked_gateway) == int(guarded)
    if guarded:
        assert world.count("app.action_proposals") == 0
    if anti == "malformed":
        assert (summary.calls, grade.cap, summary.stop_reason, _state(runtime, slot)) == (
            2, "invalid_cap", "invalid_cap", "failed",
        )
    no_authority_or_execution(world)


@pytest.mark.parametrize(("mutation", "component"), [
    (Arm.WITHOUT_PROMPT, "instructions"),
    (Arm.WITHOUT_BM25, "input"),
    ("lookup-disclosure", "input"),
])
def test_request_freeze_detects_runtime_mutations(mutation: Arm | str, component: str,
                                                   dev_cases: dict[Stratum, Scenario],
                                                   profile: tuple[Profile, World],
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, world = profile
    case = dev_cases["cancel"]
    _, original, summary = _record(runtime, world, case, REVISION)
    expected = _captured(original, summary)
    if mutation == "lookup-disclosure":
        execute = GatewayToolPort.execute

        async def without_disclosure(port: GatewayToolPort, call: AgentToolCall, *,
                                     step: ToolCallStep, deadline: float) -> ToolResult:
            return await execute(replace(port, disclose_lookup_user_id=False), call, step=step, deadline=deadline)

        monkeypatch.setattr(GatewayToolPort, "execute", without_disclosure)
        _, changed, summary = _record(runtime, world, case, REVISION)
    else:
        assert isinstance(mutation, Arm)
        with mutation.compose():
            if mutation is Arm.WITHOUT_PROMPT:
                # The registered ablation changes v1's prompt. Apply that same text to the revision
                # so this comparison holds the graph, catalog, notices and lexical mode fixed.
                monkeypatch.setattr(investigation_prompt, "PROMPT_V3_R1", investigation_prompt.PROMPT_V3)
            _, changed, summary = _record(runtime, world, case, REVISION)
    actual = _captured(changed, summary)
    with pytest.raises(ValueError, match=rf"step \d+, count\) changed {component}$"):
        compare_exchanges(f"{REVISION}/cancel", expected, actual)
    no_authority_or_execution(world)
