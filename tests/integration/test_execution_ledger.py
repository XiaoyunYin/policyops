"""T19 migration 0012 on a populated legacy ledger: refused explicitly, nothing rewritten or discarded."""

from __future__ import annotations

from uuid import uuid4

import pytest

from policyops.domain.examples import build_examples
from policyops.persistence.importer import import_synthetic_world
from policyops.persistence.migrate import MigrationPreconditionError
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops_contracts.consent import ApprovalDecision
from policyops_testing.app_database import NewDatabase


pytestmark = pytest.mark.postgres


def test_a_populated_legacy_execution_ledger_refuses_the_upgrade(new_app_database: NewDatabase) -> None:
    database = new_app_database("t19_legacy", revision="0011")
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    decision = ApprovalDecision.model_validate_json(build_examples()["approval-decision.json"])
    legacy = uuid4()
    with database.superuser() as conn:  # a row of the 0001 shape: no case, run, request or fingerprint binding
        conn.execute("INSERT INTO app.tool_executions (id, workspace_id, operation_id, proposal_id, proposal_version, "
                     "action_digest, approval_id, argument_digest, state, attempts, created_at, updated_at) VALUES "
                     "(%s, %s, %s, %s, %s, %s, %s, %s, 'unknown', 1, now(), now())",
                     (legacy, decision.scope.workspace_id, uuid4(), decision.proposal_id, decision.proposal_version,
                      decision.action_digest, decision.approval_id, "a" * 64))
    with pytest.raises(MigrationPreconditionError, match="predate the execution ledger"):
        database.upgrade()
    assert database.current() == "0011"
    with database.superuser() as conn:
        row = conn.execute("SELECT state, attempts FROM app.tool_executions WHERE id = %s", (legacy,)).fetchone()
        forced = conn.execute("SELECT relforcerowsecurity FROM pg_class "
                              "WHERE oid = 'app.tool_executions'::regclass").fetchone()
    assert row == ("unknown", 1) and forced == (True,)  # kept as it was, still forced


def test_an_empty_ledger_downgrades_and_upgrades_again(new_app_database: NewDatabase) -> None:
    database = new_app_database("t19_roundtrip")
    database.downgrade("0011")
    assert database.current() == "0011"
    database.upgrade()
    assert database.current() == "0012"
