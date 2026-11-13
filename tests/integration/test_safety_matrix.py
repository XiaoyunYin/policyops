"""T30 executed matrix and guard-removal sensitivities on actual runtime LOGIN roles."""

from __future__ import annotations

import pytest

from policyops_testing.app_database import AppCluster
from policyops_testing.safety import matrix, rls, sensitivity
from policyops_testing.safety.config import load_config
from policyops_testing.safety.environment import Env
from policyops_testing.safety.fixtures import safety_env as safety_env
from policyops_testing.safety.fixtures import safety_live as safety_live
from policyops_testing.safety.reports import completeness


pytestmark = pytest.mark.postgres


def test_frozen_matrix_is_fully_executed(safety_env: Env) -> None:
    rows = []
    for runner in (matrix.action_matrix, matrix.rule_matrix, matrix.authority_matrix, matrix.tool_matrix, rls.run):
        rows.extend(runner(safety_env))
    failures = [(r.cell_id, r.observed, r.code, r.observed_rule, r.error) for r in rows if not r.passed]
    assert not failures, failures
    assert completeness(load_config(), rows, [], ("matrix",)) == []


def test_reviewer_guard_removal_is_detected(safety_env: Env) -> None:
    assert sensitivity.reviewer_guard(safety_env).detected


def test_disabled_rls_foreign_read_is_detected(safety_env: Env, app_cluster: AppCluster) -> None:
    assert sensitivity.rls_guard(safety_env, app_cluster).detected


@pytest.mark.parametrize("family", ["customer_authentications", "consents", "decisions", "messages"])
def test_insert_probe_uses_valid_fresh_rows_without_deleting_fixture(safety_env: Env, family: str) -> None:
    from policyops_testing.safety.environment import make_env, study_case
    env = study_case(safety_env)
    foreign = make_env((env.service, env.origin), env.db)
    row = rls.probe(env, family, foreign.run.workspace_id)
    assert row.passed, row.database_evidence
    assert row.database_evidence["foreign_sqlstate"] == "42501"
    assert row.database_evidence["owner_rows"] == row.database_evidence["original_owner_rows"] == 1
    assert row.database_evidence["inserted_owner_rows"] == 1
    assert row.database_evidence["inserted_foreign_rows"] == 0
