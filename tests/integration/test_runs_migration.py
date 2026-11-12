"""Revision 0005 (T09) on the pinned PostgreSQL: populated upgrade and backfill, refusal of incompatible legacy
data, the run ledger rules, the discovery role's exact reach, the guarded downgrade, and the data-loss check's
restoration of each table's previous FORCE ROW LEVEL SECURITY state."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from policyops.domain.examples import World
from policyops.persistence import migrate
from policyops.persistence.database import make_engine
from policyops.persistence.importer import import_synthetic_world
from policyops.persistence.migration_guard import DataLossRefused, check_tables_empty
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops_testing.app_database import AppDatabase, NewDatabase


pytestmark = pytest.mark.postgres
APP_TABLES = ("SELECT bool_and(relforcerowsecurity) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
              "WHERE n.nspname = 'app' AND relkind = 'r'")


def counts(database: AppDatabase) -> dict[str, int]:
    with database.superuser() as conn:
        tables = [row[0] for row in conn.execute("SELECT schemaname || '.' || tablename FROM pg_tables WHERE "
                                                 "schemaname IN ('identity', 'app') ORDER BY 1")]
        # Table names come from this owned test database's catalog, not from input.
        return {t: conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in tables}  # noqa: S608


def populated(new_app_database: NewDatabase, label: str) -> tuple[AppDatabase, World]:
    database = new_app_database(label, revision="0004")
    import_synthetic_world(auth=database.engine(AUTH_RUNTIME), app=database.engine(APP_RUNTIME))
    return database, World()


def test_0005_upgrades_populated_data_backfills_and_guards(new_app_database: NewDatabase) -> None:
    database, world = populated(new_app_database, "runs_upgrade")
    with database.superuser() as conn:  # events stored the 0004 way (sequences chosen by the writer)
        for sequence in (1, 2, 3):
            conn.execute("INSERT INTO app.run_events (id, workspace_id, run_id, sequence, event_type, schema_version, "
                         "payload, occurred_at) VALUES (gen_random_uuid(), %s, %s, %s, 'run.state_changed', "
                         "'policyops.run-event/v1', %s, %s)",
                         (world.workspace, world.run, sequence, '{"current": "running"}', world.now))
    before = counts(database)
    database.upgrade("0005")
    assert database.current() == "0005" and counts(database) == before
    with database.superuser() as conn:
        assert conn.execute("SELECT event_highwater, event_retention_floor, generation, initiated_by FROM app.runs "
                            "WHERE id = %s", (world.run,)).fetchone() == (3, 0, 0, None)
        assert conn.execute(APP_TABLES).fetchone() == (True,)  # the backfill's temporary NO FORCE was restored
        with pytest.raises(psycopg.errors.CheckViolation):  # a floor beyond the high-water mark
            conn.execute("UPDATE app.runs SET event_retention_floor = 4 WHERE id = %s", (world.run,))
        with pytest.raises(psycopg.errors.CheckViolation):  # a run operation must name its run
            conn.execute("INSERT INTO app.request_idempotency (workspace_id, principal_id, operation, "
                         "idempotency_key, request_sha256, case_id, response_status, response_body, created_at) VALUES "
                         "(%s, %s, 'run.start', 'key-00000001', %s, %s, 202, '{}', %s)",
                         (world.workspace, world.analyst, "0" * 64, world.case, world.now))
        with pytest.raises(psycopg.errors.CheckViolation):  # and only run operations do
            conn.execute("INSERT INTO app.request_idempotency (workspace_id, principal_id, operation, "
                         "idempotency_key, request_sha256, case_id, run_id, response_status, response_body, "
                         "created_at) VALUES (%s, %s, 'case.status', 'key-00000003', %s, %s, %s, 200, '{}', %s)",
                         (world.workspace, world.analyst, "0" * 64, world.case, world.run, world.now))
        other_case = uuid4()
        conn.execute("INSERT INTO app.cases (id, workspace_id, scenario, status, created_at, updated_at) VALUES "
                     "(%s, %s, 'retail', 'open', %s, %s)", (other_case, world.workspace, world.now, world.now))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):  # the run must belong to the named case
            conn.execute("INSERT INTO app.request_idempotency (workspace_id, principal_id, operation, "
                         "idempotency_key, request_sha256, case_id, run_id, response_status, response_body, "
                         "created_at) VALUES (%s, %s, 'run.cancel', 'key-00000002', %s, %s, %s, 200, '{}', %s)",
                         (world.workspace, world.analyst, "0" * 64, other_case, world.run, world.now))
    with database.server.connect(WORKER_DISCOVERY, database.name) as conn:  # scheduling metadata only, no writes
        assert conn.execute("SELECT id, workspace_id, state, available_at, lease_expires_at, deadline_at FROM app.jobs"
                            ).fetchall() is not None
        assert conn.execute("SELECT id, workspace_id, topic, created_at, delivered_at FROM app.outbox_events"
                            ).fetchall() is not None
        conn.rollback()
        for statement in ("SELECT request_sha256 FROM app.jobs", "SELECT run_id FROM app.jobs",
                          "SELECT payload FROM app.outbox_events", "SELECT id FROM app.runs",
                          "SELECT id FROM app.run_events", "SELECT id FROM identity.sessions",
                          "SELECT id FROM identity.memberships", "SELECT id FROM app.cases",
                          "UPDATE app.jobs SET state = 'dead'", "DELETE FROM app.outbox_events",
                          "INSERT INTO app.jobs (id) VALUES (gen_random_uuid())"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
            conn.rollback()
    with pytest.raises(DataLossRefused, match=r"app\.runs"):
        database.downgrade("0004")
    assert database.current() == "0005"
    database.downgrade("0004", allow_data_loss=True)
    with database.superuser() as conn:
        def columns(table: str) -> set[str]:
            return {row[0] for row in conn.execute("SELECT column_name FROM information_schema.columns WHERE "
                                                   "table_schema = 'app' AND table_name = %s", (table,))}

        assert not {"generation", "event_highwater", "event_retention_floor", "initiated_by"} & columns("runs")
        assert not {"claim_id", "last_error_code"} & columns("jobs")
        assert "run_id" not in columns("request_idempotency")
        assert conn.execute(APP_TABLES).fetchone() == (True,)
        assert conn.execute("SELECT count(*) FROM pg_policy WHERE polname LIKE %s",
                            ("%worker_discovery",)).fetchone() == (0,)
    assert counts(database)["app.runs"] == before["app.runs"]  # the explicitly accepted loss drops columns only
    database.upgrade("0005")
    assert database.current() == "0005"


def test_an_empty_0005_downgrade_keeps_forced_rls(new_app_database: NewDatabase) -> None:
    """The passing data-loss check (no runs or jobs) must not leave the checked tables unforced (the guard fix)."""
    database = new_app_database("runs_empty")  # at head, no rows
    database.downgrade("0004")
    with database.superuser() as conn:
        assert conn.execute(APP_TABLES).fetchone() == (True,)
    database.downgrade("0002")  # also through 0003 and 0004, whose checks pass on empty tables
    with database.superuser() as conn:
        assert conn.execute("SELECT relforcerowsecurity FROM pg_class WHERE oid = 'identity.sessions'::regclass"
                            ).fetchone() == (True,)
        assert conn.execute(APP_TABLES).fetchone() == (True,)


@pytest.mark.parametrize("problem", ["two active workbench runs", "a leased job"])
def test_0005_refuses_incompatible_legacy_data_without_rewriting_it(new_app_database: NewDatabase,
                                                                    problem: str) -> None:
    database, world = populated(new_app_database, "runs_legacy")
    with database.superuser() as conn:
        if problem == "a leased job":
            conn.execute("INSERT INTO app.jobs (id, workspace_id, run_id, dedupe_key, request_sha256, kind, "
                         "run_generation, state, lease_owner, lease_expires_at, max_attempts, available_at, "
                         "deadline_at, created_at, updated_at) VALUES (gen_random_uuid(), %s, %s, 'legacy', %s, "
                         "'run.execute', 0, 'leased', gen_random_uuid(), %s, 3, %s, %s, %s, %s)",
                         (world.workspace, world.run, "a" * 64, world.now, world.now, world.now + timedelta(hours=1),
                          world.now, world.now))
        else:
            conn.execute("UPDATE app.runs SET state = 'running', mode = 'workbench' WHERE id = %s", (world.run,))
            conn.execute("INSERT INTO app.runs (id, workspace_id, case_id, case_version, mode, graph_sha256, "
                         "prompt_sha256, config_sha256, state, deadline_at, created_at, updated_at) SELECT "
                         "gen_random_uuid(), workspace_id, case_id, case_version, 'workbench', graph_sha256, "
                         "prompt_sha256, config_sha256, 'queued', deadline_at, created_at, updated_at "
                         "FROM app.runs WHERE id = %s", (world.run,))
    before = counts(database)
    with pytest.raises(migrate.MigrationPreconditionError):
        database.upgrade("0005")
    assert database.current() == "0004" and counts(database) == before  # nothing rewritten
    with database.superuser() as conn:
        assert conn.execute(APP_TABLES).fetchone() == (True,)


@pytest.mark.parametrize("forced", [True, False])
def test_the_data_loss_check_restores_the_previous_force_state(new_app_database: NewDatabase, forced: bool) -> None:
    database = new_app_database("guard", revision=None)
    with database.server.connect("postgres", database.name) as conn:
        conn.execute("CREATE TABLE guarded (id int)")
        conn.execute("ALTER TABLE guarded ENABLE ROW LEVEL SECURITY")
        if forced:
            conn.execute("ALTER TABLE guarded FORCE ROW LEVEL SECURITY")
        conn.commit()
    engine = make_engine(lambda: database.server.connect("postgres", database.name), pool_size=1)

    def force_state() -> Any:
        with database.superuser() as conn:
            return conn.execute("SELECT relforcerowsecurity FROM pg_class WHERE relname = 'guarded'").fetchone()

    try:
        with engine.begin() as connection:
            check_tables_empty(connection, ("guarded",))  # empty: passes and commits
        assert force_state() == (forced,)
        with database.superuser() as conn:
            conn.execute("INSERT INTO guarded VALUES (1)")
        with pytest.raises(DataLossRefused), engine.begin() as connection:
            check_tables_empty(connection, ("guarded",))
        assert force_state() == (forced,)
    finally:
        engine.dispose()


def served_start_and_cancel(database: AppDatabase) -> tuple[Any, str]:
    """Create run-operation ledger rows the ordinary way: start and cancel a run through the served API."""
    from policyops.runtime.spec import RuntimeCatalog
    from policyops_testing import case_api
    from policyops_testing.scripted import ScriptedExecutor, scripted_spec

    built = scripted_spec(ScriptedExecutor())
    api = case_api.build(database, catalog=RuntimeCatalog.of([built], default=built.spec_id))
    workspace = api.workspace("downgrade")
    browser = api.member(f"subject-{uuid4().hex[:10]}", workspace, "analyst")
    case = api.create(browser).json()["case_id"]
    run = api.start_run(browser, case, '"1"').json()["run_id"]
    assert api.cancel_run(browser, run).status_code == 200
    return api, run


def ledger(database: AppDatabase) -> dict[str, int]:
    with database.superuser() as conn:
        rows = conn.execute("SELECT operation, count(*) FROM app.request_idempotency GROUP BY operation").fetchall()
    return dict(rows)


def test_a_lossy_0005_downgrade_with_run_ledger_rows(new_app_database: NewDatabase) -> None:
    database = new_app_database("runs_ledger_downgrade")
    _api, run = served_start_and_cancel(database)
    # Current API code requires head. Only the migration under test runs against the historical schema.
    database.downgrade("0005")
    assert ledger(database) == {"case.create": 1, "run.start": 1, "run.cancel": 1}
    before = counts(database)
    with pytest.raises(DataLossRefused, match=r"app\.runs"):  # the default refuses, atomically
        database.downgrade("0004")
    assert database.current() == "0005" and counts(database) == before
    database.downgrade("0004", allow_data_loss=True)
    assert database.current() == "0004"
    assert ledger(database) == {"case.create": 1}  # exactly the run-operation rows are gone
    after = counts(database)
    assert after["app.runs"] == before["app.runs"] and after["app.run_events"] == before["app.run_events"]
    with database.superuser() as conn:
        assert conn.execute(APP_TABLES).fetchone() == (True,)
        assert conn.execute("SELECT count(*) FROM pg_policy WHERE polname LIKE %s",
                            ("%worker_discovery",)).fetchone() == (0,)
        assert conn.execute("SELECT has_table_privilege(%s, 'app.jobs', 'SELECT') OR has_column_privilege(%s, "
                            "'app.jobs', 'id', 'SELECT')", (WORKER_DISCOVERY, WORKER_DISCOVERY)).fetchone() == (False,)
    database.upgrade("0005")  # re-upgrade: backfill only; generation, initiator and deleted replays are not restored
    with database.superuser() as conn:
        assert conn.execute("SELECT generation, initiated_by, event_highwater FROM app.runs WHERE id = %s",
                            (UUID(run),)).fetchone() == (0, None, 2)
    assert ledger(database) == {"case.create": 1}
