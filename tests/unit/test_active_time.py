"""Exact active-clock arithmetic: no floating-point microseconds or real-clock fixtures."""

from datetime import timedelta

import pytest

from policyops.persistence import runs
from tests.unit.test_runs_unit import NOW, run_record


def test_active_time_is_exact_clamped_and_waiting_allowance_is_frozen() -> None:
    run = run_record().model_copy(update={"active_remaining_us": 2_000_001, "active_started_at": NOW,
                                        "deadline_at": NOW + timedelta(microseconds=2_000_001)})
    assert runs.remaining_us(run, NOW - timedelta(days=1)) == 2_000_001
    assert runs.remaining_us(run, NOW + timedelta(seconds=1)) == 1_000_001
    assert runs.remaining_us(run, run.deadline_at) == 0  # type: ignore[arg-type]
    with pytest.raises(runs.Fenced, match="active_time_exceeded"):
        runs.require_active(run, NOW + timedelta(microseconds=2_000_001))
    paused = run.model_copy(update={"state": "waiting_approval", "active_started_at": None, "deadline_at": None})
    assert runs.remaining_us(paused, NOW + timedelta(days=10)) == 2_000_001
    with pytest.raises(runs.Fenced, match="run_not_active"):
        runs.require_active(paused, NOW)
