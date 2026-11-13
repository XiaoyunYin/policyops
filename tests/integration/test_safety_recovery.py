"""Small regression sample; the standalone CLI executes all 100 preregistered pairs."""

from __future__ import annotations

from pathlib import Path

import pytest

from policyops_testing.safety import process_restart, sensitivity, supplements
from policyops_testing.safety.config import ARMS, FAULTS, load_config
from policyops_testing.safety.e04 import pair_env, run_trial
from policyops_testing.safety.environment import Env
from policyops_testing.safety.fixtures import recovery_test_pairs
from policyops_testing.safety.fixtures import safety_env as safety_env
from policyops_testing.safety.fixtures import safety_live as safety_live
from policyops_testing.safety.reports import assert_ledger, completeness, score, settlement


pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("fault", FAULTS)
def test_each_fault_has_real_paired_observations(safety_env: Env, fault: str) -> None:
    config = load_config()
    pair = recovery_test_pairs(config)[fault][0]
    rows = [run_trial(pair_env(safety_env, pair, arm), pair, arm, config) for arm in ARMS]
    assert rows[0].error is None, rows[0].error
    assert rows[1].error is None, rows[1].error
    assert_ledger(rows[0])
    assert not score(rows[1]).errors
    assert completeness(config, [], rows, ("e04",), (pair.pair_id,)) == []
    if settlement(rows[0]) == "completed_once":
        assert all(control.detected for control in sensitivity.report_controls(config, rows[0]))


@pytest.mark.parametrize("fault", ["crash_before_send", "fail_503_before", "duplicate_delivery"])
def test_once_per_order_recovery_can_fence_without_an_effect(safety_env: Env, fault: str) -> None:
    config = load_config()
    pair = recovery_test_pairs(config)[fault][1]
    assert pair is not None
    row = run_trial(pair_env(safety_env, pair, "ledger"), pair, "ledger", config)
    assert_ledger(row)
    assert settlement(row) == "fenced_no_effect"
    if fault == "duplicate_delivery":
        assert any(e.startswith("old_claimant_action_") for e in row.fault_evidence)
        assert any(e.startswith("old_claimant_http_mutations_") for e in row.fault_evidence)


def test_one_real_owned_subprocess_is_killed_and_restarted(safety_env: Env, tmp_path: Path) -> None:
    assert process_restart.check(safety_env, tmp_path / "kill-restart").detected


def test_supplemental_lost_receipts_and_capped_unknown(safety_env: Env) -> None:
    rows = supplements.run(safety_env)
    for fault in ("commit_then_503", "crash_after_response"):
        assert rows[fault]["state"] == "succeeded" and rows[fault]["effects"] == 1
        assert rows[fault]["receipt_retained"]
    assert rows["capped_unknown"]["state"] == "unknown" and rows["capped_unknown"]["effects"] == 0
