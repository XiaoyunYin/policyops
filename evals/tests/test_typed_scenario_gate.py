"""A separate scripted CI gate for v2 terminal outcomes on the real graph."""

import json
from typing import Literal
from uuid import uuid4

import httpx2
import pytest

from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration import state
from policyops.orchestration.adapters import InvestigationAdapters
from policyops.orchestration.profile import InvestigationProfileV2
from policyops.persistence import runs
from policyops.persistence.database import workspace_transaction
from policyops_contracts.events import EventEnvelope, InvestigationOutcome, InvestigationReason
from policyops_contracts.grounding import CitationBundle, RecordOutcome
from policyops_evals.run_latency import run_scripted
from policyops_evals.scenarios.cases import Scenario, Stratum
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.runtime import Profile, Slot
from policyops_testing.retrieval_fixtures import World

from .scenario_support import Reply, Script, no_authority_or_execution, oracle
from .scenario_support import database as database
from .scenario_support import pinned as pinned
from .scenario_support import profile as profile
from .test_scenario_gate import dev_cases as dev_cases


pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("reason", list(InvestigationReason))
def test_v2_scripted_outcomes(reason: InvestigationReason, dev_cases: dict[Stratum, Scenario],
                             profile: tuple[Profile, World], monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, world = profile
    tape, slot = Tape(), Slot(world.ws, uuid4())
    recording_refusals = 0

    if reason is InvestigationReason.SYSTEM_ERROR:
        def fail(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("synthetic finalizer failure")

        monkeypatch.setattr(InvestigationAdapters, "finalize", fail)
    elif reason is InvestigationReason.CITATION_RECORDING_FAILED:
        finalize = InvestigationAdapters.finalize

        def refuse(bundle: CitationBundle, **_options: object) -> RecordOutcome:
            nonlocal recording_refusals
            assert bundle.run_id == slot.run and len(bundle.claims) == 1
            recording_refusals += 1
            return RecordOutcome(status="refused", code="citation_integrity", committed="none",
                                 claims=1, distinct=1, missing=1)

        def finalize_with_recording_refusal(adapters: InvestigationAdapters, checkpoint: state.InvestigationState,
                                           *, deadline: float) -> tuple[Literal["answered", "abstained"], str]:
            # Keep retrieval and citation validation real. Refuse only the final answer's verified bundle.
            with monkeypatch.context() as finalization:
                finalization.setattr(adapters.recorder, "record", refuse)
                return finalize(adapters, checkpoint, deadline=deadline)

        monkeypatch.setattr(InvestigationAdapters, "finalize", finalize_with_recording_refusal)

    def reply(request: httpx2.Request, index: int) -> Reply:
        step = oracle(request, index)
        if not isinstance(step, dict) or step.get("name") != prompt.FINISH:
            return step
        raw = step["arguments"]
        assert isinstance(raw, str)
        answer = json.loads(raw)
        if reason is InvestigationReason.MODEL_ABSTAINED:
            answer.update(outcome="abstain", assertions=[], abstention={
                "reason": "insufficient_evidence", "detail": "untrusted model detail"})
        if reason is InvestigationReason.CITED_DECLINE:
            step["name"] = prompt.DECLINE
        elif reason is InvestigationReason.RENDERED_ANSWER_INVALID:
            answer["assertions"] = [answer["assertions"][0] | {"text": "x" * 1800}] * 3
        # Replacing the quote while keeping incompatible offsets produces invalid_arguments in v2.
        # Repeating that reply ends with invalid_cap. The app's v2 PostgreSQL test covers a forged
        # quote with omitted offsets, which reaches citation verification and emits citation_recording_failed.
        return step | {"arguments": json.dumps(answer)}

    summary, latency = run_scripted(runtime, dev_cases["delivered_refusal"], slot, tape,
                                    Script(runtime.tokenizer, reply, prefix=slot.id.hex),
                                    selected=InvestigationProfileV2.TOOL_CONTRACT_V2)
    assert summary.calls > 0 and len(tape.records) == 2 * summary.calls
    assert latency.inference["samples"] == latency.count["samples"] == summary.calls
    assert latency.tools_ms and latency.timestamps.first_model_call_at is not None
    assert latency.timestamps.investigation_ended_at is not None
    assert latency.timestamps.proposal_persisted_at is None
    assert recording_refusals == int(reason is InvestigationReason.CITATION_RECORDING_FAILED)
    with workspace_transaction(runtime.app, slot.workspace) as connection:
        run = runs.get_run(connection, slot.run)
        assert run is not None
        assert run.state == ("failed" if reason is InvestigationReason.SYSTEM_ERROR else "succeeded")
        outcomes = [item.payload for item in runs.events_after(connection, run, 0, 100)
                    if isinstance(item, EventEnvelope) and isinstance(item.payload, InvestigationOutcome)]
    assert outcomes == [InvestigationOutcome(reason=reason)]
    assert world.count("app.action_proposals") == 0
    no_authority_or_execution(world)
