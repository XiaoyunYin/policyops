"""Run the N13 scripted panel and model-to-receipt driver on disposable PostgreSQL."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text

from policyops.adapters.retail_client import Unknown
from policyops.domain.retail_rules import ORDER_TARGETS, Allowed, evaluate_write
from policyops.domain.session import CustomerSession
from policyops.gateway.facts import Collected, collect
from policyops.gateway.ports import GatewayScope, PgSessionStore
from policyops.gateway.steps import Gateway, StepResult
from policyops.persistence.database import transaction, workspace_transaction
from policyops.runtime.clock import DatabaseLeaseClock
from policyops_contracts.agent import AgentStep, ToolCallStep
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import ReviewOutcome
from policyops_contracts.gateway import ToolError
from policyops_contracts.retail import OrderOperationHistory, ToolName
from policyops_contracts.retail_service import FIXTURE_SHA256, MutationRequest
from policyops_contracts.scalars import RunScope
from policyops_evals.retail_sim import codec
from policyops_evals.retail_sim.store import Store
from policyops_evals.scenarios import n13_acceptance as acceptance
from policyops_evals.scenarios.n13_fixtures import Trial, generate
from policyops_evals.scenarios.n13_panel import Observation, metrics
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.runtime import Profile, Slot
from policyops_testing import network
from policyops_testing.retrieval_fixtures import World

from .scenario_support import database as database
from .scenario_support import profile as profile


pytestmark = pytest.mark.postgres


class ExternalHistory:
    def history(self, order_id: str, *, case_version: int) -> OrderOperationHistory:
        # The external actors operate on a fresh case / previously untouched sibling.
        return OrderOperationHistory(order_id=order_id, complete=True, successful_tools=())


def _external_change(runtime: Profile, endpoint: acceptance.Endpoint, trial: Trial, slot: Slot) -> None:
    call = trial.action if trial.group == "C1" else trial.unrelated_change
    assert call is not None
    binding = runtime._seed(trial.scenario, slot, DatabaseLeaseClock())
    scope = GatewayScope(run=RunScope(workspace_id=slot.workspace, case_id=slot.case, run_id=slot.run),
                         binding=binding, fixture_sha256=FIXTURE_SHA256)
    authentication = PgSessionStore(runtime.app).load(scope.run)
    session = CustomerSession(binding=binding, run=scope.run, authentication=authentication)
    with endpoint.client(runtime.retail, slot, trial.scenario) as client:
        facts = collect(client, scope, call, ExternalHistory())
        assert isinstance(facts, Collected)
        decision = evaluate_write(call, session, facts.facts)
        assert isinstance(decision, Allowed)
        request = MutationRequest(call=call, expected_effect=decision.effect,
                                  expected_versions=decision.resource_versions,
                                  intent_sha256=sha256(b"N13 external fixture change").hexdigest())
        result = client.mutate(uuid4(), request)
        assert not isinstance(result, Unknown) and result.outcome == "committed"


def _inject_competitor(runtime: Profile, trial: Trial, slot: Slot) -> None:
    """C2 only. Introduce eligibility directly in disposable simulator state, without a business operation."""
    assert trial.sibling is not None
    status, _ = ORDER_TARGETS[ToolName(trial.action.tool)]
    with transaction(runtime.retail.engine) as connection:
        connection.execute(text("SELECT set_config('retail.tenant_id', :tenant, true), "
                                "set_config('retail.case_id', :case, true)"),
                           {"tenant": str(slot.workspace), "case": str(slot.case)})
        raw = connection.execute(text("SELECT state FROM retail.case_states FOR UPDATE")).scalar_one()
        state = json.loads(raw)
        assert state["orders"][trial.sibling]["status"] != status
        state["orders"][trial.sibling]["status"] = status
        updated = codec.encode(runtime.retail.upstream.retail_db.model_validate(state))
        connection.execute(text("UPDATE retail.case_states SET state = :state, state_sha256 = :sha, "
                                "version = version + 1, updated_at = now()"),
                           {"state": updated, "sha": codec.digest(updated)})
        changed = connection.execute(text("UPDATE retail.case_resources SET version = version + 1 "
                                          "WHERE kind = 'order' AND resource_id = :order RETURNING version"),
                                     {"order": trial.sibling}).scalar_one()
        assert changed == 2


def _attempt(runtime: Profile, endpoint: acceptance.Endpoint, trial: Trial, slot: Slot,
             observed: list[ToolError]) -> Observation:
    tape = Tape()
    summary = runtime.run_scripted(trial.scenario, slot, tape, acceptance.scripted(runtime.tokenizer, trial, slot),
                                   profile=acceptance.PROFILE, retail_session=endpoint.client)
    assert 0 < summary.calls <= 8 and not tape.write_failed
    proposal = acceptance.presented(runtime, slot)
    state, _ = acceptance.run_events(runtime.app, slot)
    effects_before = 0
    refused = False
    verified = False
    if proposal is None:
        with workspace_transaction(runtime.app, slot.workspace) as connection:
            count = connection.execute(text("SELECT count(*) FROM app.action_proposals WHERE run_id = :run"),
                                       {"run": slot.run}).scalar_one()
        _, rule_id = ORDER_TARGETS[ToolName(trial.action.tool)]
        refused = (count == 0 and state == "succeeded" and len(observed) == 1 and
                   (observed[0].code, observed[0].rule_id, observed[0].detail) ==
                   (ErrorCode.POLICY_DENIED, rule_id, "target_clarification_required"))
    else:
        assert proposal.action == trial.action and state == "waiting_approval"
        acceptance.assent_and_approve(runtime, slot, proposal)
        if trial.group == "C1":
            _external_change(runtime, endpoint, trial, slot)
            effects_before = 1

        def before_dispatch() -> None:
            nonlocal effects_before
            if trial.group == "C2":
                _inject_competitor(runtime, trial, slot)
            if trial.group == "C3":
                _external_change(runtime, endpoint, trial, slot)
                effects_before = 1

        execution = acceptance.advance(runtime, endpoint, trial, slot, before_dispatch=before_dispatch)
        if execution is None:
            state, events = acceptance.run_events(runtime.app, slot)
            refused = state == "failed" and any(isinstance(event.payload, ReviewOutcome)
                                                 and event.payload.reason == "precheck_refused" for event in events)
        elif execution.state == "succeeded":
            acceptance.verify_receipt(runtime, endpoint, trial, slot, proposal, execution, effects=effects_before + 1)
            verified = True
        else:
            refused = (execution.state, execution.outcome, execution.last_code, execution.attempts) == (
                "failed", "precheck_refused", "target_clarification_required", 0)
    effects = acceptance.case_effects(runtime, slot) - effects_before
    assert effects >= 0
    return Observation(trial.group, trial.action.tool, effects, refused, verified)


@contextmanager
def _server(store: Store) -> Iterator[acceptance.Endpoint]:
    with acceptance.loopback(store) as endpoint, network.allow("127.0.0.1", int(endpoint.origin.rsplit(":", 1)[1])):
        yield endpoint


def test_target_guard_panel(profile: tuple[Profile, World], monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, world = profile
    registered = generate(runtime.retail.fixture.raw)
    print(json.dumps({"census": registered.census}, sort_keys=True), flush=True)
    errors: list[ToolError] = []
    observations = []
    step = Gateway.step

    def observe(gateway: Gateway, action: AgentStep, *, previous: AgentStep | None, sequence: int) -> StepResult:
        result = step(gateway, action, previous=previous, sequence=sequence)
        if isinstance(action, ToolCallStep) and ToolName(action.call.tool) in ORDER_TARGETS and isinstance(
                result.observation, ToolError):
            errors.append(result.observation)
        return result

    monkeypatch.setattr(Gateway, "step", observe)
    with _server(runtime.retail) as endpoint:
        for trial in registered.trials:
            errors.clear()
            row = _attempt(runtime, endpoint, trial, Slot(world.ws, uuid4()), errors)
            print(json.dumps(asdict(row), sort_keys=True), flush=True)
            observations.append(row)
    report = metrics(observations)
    by_tool = {tool: metrics([row for row in observations if row.tool == tool])
               for tool in sorted({row.tool for row in observations})}
    print(json.dumps({"metrics": report, "by_tool": by_tool}, sort_keys=True), flush=True)
    assert report["wrong_target_effects_A_Aprime"][0] == report["false_blocks_B1_B2"][0] == 0
    for row in observations:
        if row.group in {"B1", "B2", "C3"}:
            assert row.receipt_verified and row.effects == 1 and not row.refused, row
        else:
            assert row.refused and row.effects == 0 and not row.receipt_verified, row


def test_scripted_acceptance_verifies_every_receipt(profile: tuple[Profile, World], tmp_path: Path) -> None:
    runtime, world = profile
    trials = generate(runtime.retail.fixture.raw).live
    output = tmp_path / "n13-scripted"
    with _server(runtime.retail) as endpoint:
        verified = acceptance.run(runtime, endpoint, world.ws, trials, maximum=acceptance.MAX_USD, output=output)
    attempts = [f"attempt-{index}.json" for index in range(1, 17)]
    assert {path.name for path in output.iterdir()} == {"preflight.json", "summary.json", *attempts}
    for trial, filename in zip(trials, attempts, strict=True):
        report = json.loads((output / filename).read_text(encoding="utf-8"))
        context = (report["attempt"], report["case"], report["failure"], report["state"], report["investigation"])
        assert report["case"] == trial.scenario.key, context
        assert report["failure"] is None and len(report["receipt_sha256"] or "") == 64, context
        assert not report["paid"] and report["scripted_assent"] and report["usage"]["settled_events"] > 0, context
        assert {span["name"] for span in report["spans"]} >= {"gateway.step", "review.job", "execution.step"}, context
        assert "review.outcome" in {event["type"] for event in report["events"]}, context
    assert verified == len(trials) == 16
    assert json.loads((output / "summary.json").read_text(encoding="utf-8")) == {
        "verified_receipts": 16, "registered_slots": 16, "failures": {
            "gateway_refusal": 0, "model_wrong_or_abstained": 0, "cap_stop": 0, "infrastructure": 0,
        },
    }
