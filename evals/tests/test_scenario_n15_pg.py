"""Exercise healthy, faulted and recovered N15 slots with real worker and runtime-role reads."""

from uuid import uuid4

import pytest
from sqlalchemy import text

from policyops.persistence.database import workspace_transaction
from policyops.persistence.roles import APP_RUNTIME
from policyops.runtime.worker import Worker
from policyops_evals.scenarios.n13_acceptance import case_effects
from policyops_evals.scenarios.n15_canary import FAULTS, Fault, fixture_cycle, run_slot
from policyops_evals.scenarios.n15_monitor import CADENCE, FAULT_SCORES, SLOT_DEADLINE, healthy
from policyops_evals.scenarios.n15_scorer import ScheduledSlot, Scorer, Windows
from policyops_evals.scenarios.runtime import CaseInput, Profile, Slot
from policyops_testing.retrieval_fixtures import World

from .scenario_support import database as database
from .scenario_support import no_authority_or_execution
from .scenario_support import profile as profile
from .test_scenario_n15 import assert_blind


pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("fault", FAULTS)
def test_canary_worker_healthy_fault_recovered(profile: tuple[Profile, World], monkeypatch: pytest.MonkeyPatch,
                                               fault: Fault) -> None:
    runtime, world = profile
    monkeypatch.setenv("POLICYOPS_ENV", "local")

    def forbid_discovery(_worker: Worker) -> None:
        pytest.fail("canary process must not use discovery")

    monkeypatch.setattr(Worker, "discover", forbid_discovery)
    with workspace_transaction(runtime.app, world.ws) as connection:
        assert connection.execute(text("SELECT current_user")).scalar_one() == APP_RUNTIME

    cycle = fixture_cycle(runtime.retail.fixture.raw, FAULTS.index(fault))
    cases = cycle * 3
    slots = [Slot(world.ws, uuid4()) for _ in cases]
    plan = [ScheduledSlot(slot.id, trial.admitted, index * CADENCE, index * CADENCE + SLOT_DEADLINE)
            for index, (slot, trial) in enumerate(zip(slots, cases, strict=True))]
    scorer = Scorer({slot.id: trial.scenario.gold for slot, trial in zip(slots, cases, strict=True)})
    windows = Windows(plan)
    for index, (scheduled, slot, trial) in enumerate(zip(plan, slots, cases, strict=True)):
        injected = fault if len(cycle) <= index < 2 * len(cycle) else None
        visible = CaseInput(trial.scenario.world.customer_id, trial.scenario.visible.message)
        capture = run_slot(runtime, slot, visible, injected)
        assert_blind(capture.records, trial.scenario.gold.key)
        observed = scorer.score(slot.id, capture)
        expected = FAULT_SCORES[fault] if injected is not None and trial.admitted else healthy(trial.admitted)
        assert observed == expected, (index, trial.group, capture.stop, observed)
        assert len(capture.presented or ()) == int(expected.gateway == "accepted")
        assert case_effects(runtime, slot) == 0
        assert windows.finalize(slot.id, observed, scheduled.due)
        assert not windows.finalize(slot.id, observed, scheduled.due)

    snapshot = windows.snapshot()
    assert snapshot.proposal["exact"] == 8 and snapshot.ambiguous == {"clarified": 3}
    assert snapshot.gateway["accepted"] == 8
    no_authority_or_execution(world)
