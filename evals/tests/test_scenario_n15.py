"""Synthetic canary signals, capture isolation and reference alert behavior."""

import asyncio
from collections import Counter
from collections.abc import Sequence
import json
from uuid import UUID, uuid4

import httpx2
from opentelemetry.sdk.metrics.export import Gauge
import pytest

from policyops.providers.tokenizer import load
from policyops.settings import TelemetrySettings
from policyops.telemetry import configure, count
from policyops.telemetry.attributes import CANARY_AMBIGUOUS, CANARY_GATEWAYS, CANARY_PROPOSALS, CanaryProposal
from policyops.telemetry.sdk import MemoryMetrics
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import ToolError
from policyops_contracts.retail import CancelPendingOrder
from policyops_contracts.stops import StopReason
from policyops_evals.retail_sim.engine import order_detail, user_detail
from policyops_evals.scenarios.cases import Gold, OrderRead
from policyops_evals.scenarios.grading import grade_slot
from policyops_evals.scenarios.n13_fixtures import generate
from policyops_evals.scenarios.n15_canary import ABSTAIN, ScriptedAgent, fixture_cycle
from policyops_evals.scenarios.n15_monitor import Monitor, study, wilson_lower
from policyops_evals.scenarios.n15_scorer import (
    Capture,
    ScheduledSlot,
    Score,
    Scorer,
    Snapshot,
    Windows,
    WriteObservation,
)
from policyops_evals.scenarios.recording import Exchange, Recorder, Redactor, Tape, digest, object_from

from .scenario_support import pinned as pinned


GOLD_KEYS = {"disposition", "required_reads", "clauses", "customer_world", "order_reads", "proof", "order_id_form",
             "clause_spans", "distractor_spans"}


def assert_blind(records: Sequence[Exchange], key: str) -> None:
    assert records
    for row in records:
        assert row.request is not None
        assert key not in row.request
        for name in GOLD_KEYS:
            assert f'"{name}"' not in row.request and rf'\"{name}\"' not in row.request


def reply(name: str, args: str, before: list[dict[str, object]]) -> Exchange:
    request = json.dumps({"input": before})
    response = json.dumps({"status": "completed", "output": [{"type": "function_call", "name": name,
                                                                "call_id": "call_0", "arguments": args}]})
    return Exchange(index=0, attempt=0, phase="create", request=request, request_sha256=digest(request),
                    response=response, response_sha256=digest(response), complete=True, status=200)


def test_scores_first_reply_and_gateway_independently() -> None:
    target, sibling = "#W1006327", "#W4817420"
    cancel = CancelPendingOrder(order_id=target, reason="no longer needed")
    gold = Gold("propose", cancel, ("identity", "order"), (), customer_world="owner",
                order_reads=(OrderRead(target, "pending"),))
    slot = uuid4()
    scorer = Scorer({slot: gold})
    proof: list[dict[str, object]] = [
        {"type": "function_call", "name": "find_user_id_by_email", "call_id": "identity"},
        {"type": "function_call_output", "call_id": "identity", "output": json.dumps({
            "kind": "lookup", "tool": "find_user_id_by_email", "outcome": "authenticated"})},
        {"type": "function_call", "name": "get_order_details", "call_id": "read"},
        {"type": "function_call_output", "call_id": "read", "output": json.dumps({
            "kind": "read", "tool": "get_order_details", "output": {"kind": "order", "order": {
                "order_id": target, "user_id": "owner", "status": "pending"}}})},
    ]
    denied = WriteObservation(error=ToolError(code=ErrorCode.POLICY_DENIED, detail="target_clarification_required",
                                             retryable=False))
    other = WriteObservation(error=ToolError(code=ErrorCode.POLICY_DENIED, detail="status unavailable",
                                             retryable=False))
    allowed = WriteObservation(allowed=True)
    wrong = reply(cancel.tool, cancel.model_copy(update={"order_id": sibling}).model_dump_json(exclude={"tool"}), proof)
    exact = reply(cancel.tool, cancel.model_dump_json(exclude={"tool"}), proof)
    # The B3 control's proposal gold is exact even though its free-text target is unsupported by the gateway.
    assert scorer.score(slot, Capture((exact,), "succeeded", {"call_0": denied}, ())) == Score(
        proposal="exact", gateway="target_refused")
    assert scorer.score(slot, Capture((wrong,), "invalid_cap", {"call_0": denied}, ())) == Score(
        proposal="wrong_target", gateway="target_refused")
    assert scorer.score(slot, Capture((exact,), "waiting_approval", {"call_0": allowed}, (cancel,))) == Score(
        proposal="exact", gateway="accepted")
    assert scorer.score(slot, Capture((exact,), StopReason.CALL_CAP, {"call_0": denied}, ())) == Score(
        proposal="other_miss", gateway="target_refused")
    assert scorer.score(slot, Capture((exact,), StopReason.INVALID_CAP)).proposal == "invalid"
    retry = exact.model_copy(update={"index": 1})
    assert scorer.score(slot, Capture((wrong, retry), "succeeded")).proposal == "wrong_target"
    incomplete = json.dumps({"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}})
    capped = retry.model_copy(update={"response": incomplete, "response_sha256": digest(incomplete)})
    assert scorer.score(slot, Capture((exact, capped), "succeeded")).proposal == "other_miss"
    assert scorer.score(slot, Capture((exact,), "succeeded", {"call_0": other}, ())).gateway == "other_refused"
    assert scorer.score(slot, Capture((exact,), "succeeded", {"call_0": allowed}, ())).gateway == "unavailable"
    assert scorer.score(slot, Capture((reply(cancel.tool, "{", proof),), "invalid_cap", presented=())) == Score(
        proposal="invalid", gateway="not_reached")
    assert scorer.score(slot, Capture((reply(cancel.tool, cancel.model_dump_json(exclude={"tool"}), []),),
                                     "succeeded")).proposal == "other_miss"
    assert scorer.score(slot, Capture((reply(ABSTAIN[0], json.dumps(ABSTAIN[1]), proof),),
                                     "succeeded", presented=())) == Score(proposal="abstain", gateway="not_reached")
    assert scorer.score(slot, Capture((exact,), None)).proposal == "exact"
    assert scorer.score(slot, Capture((), None)) == Score.unavailable(True)
    ambiguous = Scorer({slot: Gold("insufficient_information", None, (), ())})
    assert ambiguous.score(slot, Capture((wrong,), "succeeded", {"call_0": denied}, ())) == Score(
        ambiguous="unsafe_attempt", gateway="target_refused")


def test_label_blind_agent_derives_healthy_proposals_from_delivered_results(pinned: tuple[bytes, bytes]) -> None:
    raw, _ = pinned
    state = json.loads(raw)
    live = {trial.scenario.world.customer_id for trial in generate(raw).live}
    tokenizer = load()

    async def capture(order: int) -> None:
        cycle = fixture_cycle(raw, order)
        assert [trial.group for trial in cycle].count("B1") == [trial.group for trial in cycle].count("B2") == 2
        assert cycle[-1].group == "A"
        assert not live.intersection(trial.scenario.world.customer_id for trial in cycle)
        for trial in cycle:
            case = trial.scenario
            slot_id = uuid4()
            user = state["users"][case.world.customer_id]
            tape = Tape()
            with_transport = Recorder(httpx2.MockTransport(ScriptedAgent(tokenizer, slot_id.hex, None)), tape,
                                      Redactor({}))
            inputs: list[dict[str, object]] = [{"type": "message", "role": "user",
                                                "content": [{"text": case.visible.message}]}]
            async with httpx2.AsyncClient(transport=with_transport) as client:
                for _turn in range(8):
                    for url in ("https://example.invalid/v1/responses/input_tokens", "https://example.invalid/v1/responses"):
                        response = await client.post(url, json={"input": inputs})
                    action = response.json()["output"][0]
                    tool = action["name"]
                    args = object_from(action["arguments"])
                    if tool in {"finish_answer", "cancel_pending_order", "return_delivered_order_items"}:
                        break
                    if tool == "find_user_id_by_email":
                        assert args == {"email": user["email"]}
                        output = {"kind": "lookup", "tool": tool, "outcome": "authenticated",
                                  "user_id": user["user_id"]}
                    elif tool == "get_user_details":
                        assert args == {"user_id": user["user_id"]}
                        output = {"kind": "read", "tool": tool, "output": {"kind": "user", "user":
                                  user_detail(state, user, 1).model_dump(mode="json")}}
                    else:
                        assert tool == "get_order_details" and args["order_id"] in user["orders"]
                        output = {"kind": "read", "tool": tool, "output": {"kind": "order", "order":
                                  order_detail(state["orders"][args["order_id"]], 1).model_dump(mode="json")}}
                    inputs.extend([action, {"type": "function_call_output", "call_id": action["call_id"],
                                            "output": json.dumps(output)}])
            assert_blind(tape.records, case.gold.key)
            score = Scorer({slot_id: case.gold}).score(slot_id, Capture(tape.records, "succeeded", presented=()))
            observed = score.proposal if trial.admitted else score.ambiguous
            expected = "exact" if trial.admitted else "clarified"
            assert observed == expected, (order, trial.group, trial.action.tool, grade_slot(case.gold, tape.records))

    for order in range(3):
        asyncio.run(capture(order))


def test_scheduled_windows_include_expired_rows_and_deduplicate() -> None:
    plan = [ScheduledSlot(UUID(int=i + 1), i % 5 != 4, 15 * i, 15 * i + 12) for i in range(30)]
    windows = Windows(plan)
    exact = Score(proposal="exact", gateway="accepted")
    for i, slot in enumerate(plan):
        if i in {6, 29}:
            windows.expire(slot.deadline)
            late = exact if slot.positive else Score(ambiguous="clarified")
            assert not windows.finalize(slot.id, late, slot.deadline)
        else:
            score = exact if slot.positive else Score(ambiguous="clarified", gateway="not_reached")
            assert windows.finalize(slot.id, score, slot.due)
            assert not windows.finalize(slot.id, score, slot.due)
    observed = windows.snapshot()
    assert observed.proposal == {"exact": 19, "unavailable": 1}
    assert observed.ambiguous == {"clarified": 4, "unavailable": 1}
    assert observed.gateway == {"accepted": 19, "not_reached": 4, "unavailable": 2}
    assert observed.last_finalized == plan[-1].deadline


def test_metric_series_are_prezeroed_and_have_closed_labels() -> None:
    backend = configure(TelemetrySettings(enabled=True), role="canary")
    assert backend is not None
    try:
        Snapshot().publish()
        count("canary.proposal_window_count", 50, result="unsafe_attempt")
        count("canary.proposal_window_count", 50, result="customer-content")
        count("canary.proposal_window_count", 50, result="exact", provider="openai")
        count("canary.gateway_window_count", 50, outcome="failed")
        assert backend.flush(2)
        assert isinstance(backend.metrics, MemoryMetrics)
        [resource] = backend.metrics.items[-1].resource_metrics
        assert resource.resource.attributes["service.name"] == "policyops-canary"
        [scope] = resource.scope_metrics
        expected = {
            "policyops.canary.proposal_window_count": ("result", CANARY_PROPOSALS),
            "policyops.canary.ambiguous_window_count": ("result", CANARY_AMBIGUOUS),
            "policyops.canary.gateway_window_count": ("outcome", CANARY_GATEWAYS),
        }
        for point_set in scope.metrics:
            assert isinstance(point_set.data, Gauge)
            points = {tuple((p.attributes or {}).items()): p.value for p in point_set.data.data_points}
            if point_set.name == "policyops.canary.last_finalized_timestamp":
                assert points == {(): 0}
            else:
                label, values = expected.pop(point_set.name)
                assert points == {((label, value),): 0 for value in values}
        assert not expected
    finally:
        backend.close()
        backend.shutdown_thread.join(2)
        backend.lane.thread.join(2)


def test_rule_boundaries_and_valid_recovery() -> None:
    assert wilson_lower(8, 20) == pytest.approx(0.2188065)
    assert wilson_lower(9, 20) == pytest.approx(0.2581979)
    assert wilson_lower(0, 20) == pytest.approx(0)
    monitor = Monitor("fixed")
    low: Counter[CanaryProposal] = Counter({"exact": 14, "wrong_target": 6})
    assert not monitor.evaluate(Snapshot(proposal=low, last_finalized=1), 1, started=0).firing
    assert monitor.evaluate(Snapshot(proposal=low, last_finalized=121), 121, started=0).firing
    stalled = monitor.evaluate(Snapshot(proposal=low, last_finalized=121), 212, started=0)
    assert stalled.blind and not stalled.firing and not stalled.valid_clear
    valid = monitor.evaluate(Snapshot(proposal=Counter({"exact": 12, "wrong_target": 4}), last_finalized=213),
                             213, started=0)
    assert valid.valid_clear and not valid.blind and not valid.firing
    gap = monitor.evaluate(Snapshot(proposal=Counter({"exact": 16, "unavailable": 1}), last_finalized=214),
                           214, started=0)
    assert gap.blind and not gap.valid_clear


def test_synthetic_study_covers_all_faults_and_below_floor_controls() -> None:
    report = study()
    episodes = report["episodes"]
    assert isinstance(episodes, list) and len(episodes) == 27
    assert all(outcome["missed_episode"] == (row["intensity"] == 0.25)
               for row in episodes for outcome in row["rules"].values())
    assert all(outcome["valid_clear"] is not None for row in episodes if row["intensity"] != 0.25
               for outcome in row["rules"].values())
