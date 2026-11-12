"""0015 backfills conservatively and guards clocks as the runtime role, with FORCE RLS retained."""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text

from policyops.domain.examples import World
from policyops.persistence import migrate, runs
from policyops.persistence.database import workspace_transaction
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.roles import APP_RUNTIME
from policyops_testing.app_database import NewDatabase
from policyops_testing.migration_fixtures import seed_world


pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("expired", [False, True])
def test_0015_backfill_preserves_active_projection_freezes_waits_and_terminal_zero(
        new_app_database: NewDatabase, expired: bool) -> None:
    db = new_app_database("t23_backfill", revision="0014")
    seed_world(db)
    active = ("queued", "running", "reconciling")
    terminal = ("succeeded", "failed", "cancelled", "budget_exceeded")
    identities = {state: uuid4() for state in (*active, "waiting_approval", "waiting_input", *terminal)}
    with db.superuser() as connection:
        now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
        deadline = now + timedelta(hours=-1 if expired else 1)
        created = now - timedelta(hours=2)
        for state, identity in identities.items():
            # Historical schema fixture: no current repository code runs against 0014.
            connection.execute("INSERT INTO app.runs (id, workspace_id, case_id, case_version, mode, graph_sha256, "
                "prompt_sha256, config_sha256, state, deadline_at, created_at, updated_at) VALUES "
                "(%s, %s, %s, 1, 'evaluation', repeat('a', 64), repeat('b', 64), repeat('c', 64), %s, %s, %s, %s)",
                (identity, World.workspace, World.case, state, deadline, created, now))
    db.upgrade(migrate.head())
    with workspace_transaction(db.engine(APP_RUNTIME), World.workspace) as connection:
        for state, identity in identities.items():
            run = runs.get_run(connection, identity)
            assert run is not None
            if state in active:
                assert run.deadline_at == deadline and run.active_started_at is not None
                assert (run.active_remaining_us == 0 if expired else 0 < run.active_remaining_us <= 3_600_000_000)
                assert run.deadline_at == run.active_started_at + timedelta(microseconds=run.active_remaining_us)
            else:
                assert run.deadline_at is None and run.active_started_at is None
                assert (run.active_remaining_us == 0 if expired or state in terminal else run.active_remaining_us > 0)
    with db.superuser() as connection:
        assert connection.execute("SELECT relforcerowsecurity FROM pg_class WHERE oid = 'app.runs'::regclass"
                                  ).fetchone() == (True,)
    with pytest.raises(DataLossRefused):
        db.downgrade("0014")
    assert db.current() == migrate.head()
    # Exercise the allowed lossy conversion, including terminal/waiting rows that need a
    # non-null historical deadline, then prove that those same populated rows can re-upgrade.
    db.downgrade("0014", allow_data_loss=True)
    assert db.current() == "0014"
    db.upgrade(migrate.head())
    with workspace_transaction(db.engine(APP_RUNTIME), World.workspace) as connection:
        for state, identity in identities.items():
            run = runs.get_run(connection, identity)
            assert run is not None and run.state == state
            if state in active:
                assert run.deadline_at == deadline and run.active_started_at is not None
                assert run.deadline_at == run.active_started_at + timedelta(microseconds=run.active_remaining_us)
            else:
                assert run.deadline_at is None and run.active_started_at is None and run.active_remaining_us == 0


@pytest.mark.parametrize("change", ["active_remaining_us = active_remaining_us + 1",
                                   "active_started_at = active_started_at + interval '1 second'",
                                   "deadline_at = deadline_at + interval '1 second'"])
def test_runtime_cannot_replenish_or_restart_active_segment(new_app_database: NewDatabase, change: str) -> None:
    db = new_app_database("t23_guard")
    seed_world(db)
    with pytest.raises(Exception, match=r"allowance|segment"), workspace_transaction(
            db.engine(APP_RUNTIME), World.workspace) as connection:
        connection.execute(text(f"UPDATE app.runs SET {change} WHERE id = :id"), {"id": World.run})  # noqa: S608
