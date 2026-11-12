"""Application bootstrap and migration chain on the pinned PostgreSQL: empty and populated previous-revision
upgrades, failed-revision rollback, refused/allowed lossy downgrade and restore into a separate database."""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text

from policyops.domain.examples import World
from policyops.persistence import bootstrap, migrate
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.persistence.importer import AlreadyImported
from policyops.persistence.migrate import DataLossRefused
from policyops.persistence.records import UsageEvent
from policyops.persistence.roles import (
    ALL_ROLES,
    APP_MIGRATOR,
    APP_RUNTIME,
    RUNTIME_ROLES,
    RolePassword,
    scram_sha256_verifier,
)
from policyops_testing.app_database import AppCluster, AppDatabase, NewDatabase
from policyops_testing.migration_fixtures import seed_world


pytestmark = pytest.mark.postgres

APP_SCHEMAS = ("identity", "app", "evaluation", "checkpoints")


def _tables(database: AppDatabase) -> list[str]:
    with database.superuser() as conn:
        rows = conn.execute("SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname = ANY(%s) "
                            "ORDER BY 1", (list(APP_SCHEMAS),)).fetchall()
    return [row[0] for row in rows]


def _counts(database: AppDatabase) -> dict[str, int]:
    with database.superuser() as conn:  # the superuser bypasses RLS: true row counts
        # Table names come from pg_tables of this owned test database, not from input.
        return {table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
                for table in _tables(database)}


def test_roles_have_exactly_the_bootstrap_attributes(app_cluster: AppCluster) -> None:
    with app_cluster.server.connect("postgres", "postgres") as conn:
        rows = conn.execute("SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, "
                            "rolreplication, rolbypassrls, left(rolpassword, 19) FROM pg_authid "
                            "WHERE rolname = ANY(%s) ORDER BY rolname", (list(ALL_ROLES),)).fetchall()
        memberships = conn.execute("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member "
                                   "WHERE r.rolname = ANY(%s)", (list(ALL_ROLES),)).fetchone()
    assert {row[0] for row in rows} == set(ALL_ROLES)
    for name, superuser, inherit, createrole, createdb, login, replication, bypassrls, verifier in rows:
        assert (superuser, createrole, createdb, login, replication, bypassrls) == (False, False, False, True,
                                                                                     False, False), name
        assert inherit is (name == APP_MIGRATOR), name  # every runtime role is NOINHERIT
        assert verifier == "SCRAM-SHA-256$4096:", name  # stored as a SCRAM verifier
    assert memberships == (0,)


def test_bootstrap_installs_vector_and_reports_actual_trust(new_app_database: NewDatabase) -> None:
    database = new_app_database("vector", revision=None)
    assert database.report is not None and database.report.version == "0.8.7"
    with database.superuser() as conn:
        owner, trusted = conn.execute(
            "SELECT pg_get_userbyid(e.extowner), v.trusted FROM pg_extension e JOIN pg_available_extension_versions v "
            "ON v.name = e.extname AND v.version = e.extversion WHERE e.extname = 'vector'").fetchone()
        public_create = conn.execute("SELECT has_schema_privilege('public', 'public', 'CREATE')").fetchone()
        datdba = conn.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()"
                              ).fetchone()
    assert owner == "postgres" and trusted is database.report.trusted  # recorded, not assumed
    assert public_create == (False,) and datdba == (APP_MIGRATOR,)
    with database.server.connect(APP_MIGRATOR, database.name) as conn, pytest.raises(Exception, match="must be owner"):
        conn.execute("DROP EXTENSION vector")


def test_empty_database_upgrades_to_head_idempotently(new_app_database: NewDatabase) -> None:
    database = new_app_database("empty")
    assert database.current() == migrate.head() == migrate.revisions()[-1]
    tables = _tables(database)
    assert "app.cases" in tables and "evaluation.evaluation_trials" in tables and "app.chunks" in tables
    database.upgrade()  # a second upgrade is a no-op
    assert _tables(database) == tables
    with database.superuser() as conn:
        schemas = dict(conn.execute("SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace "
                                    "WHERE nspname = ANY(%s)", (list(APP_SCHEMAS),)).fetchall())
        checkpoint_tables = conn.execute("SELECT count(*) FROM pg_tables WHERE schemaname = 'checkpoints'").fetchone()
        retail = conn.execute("SELECT count(*) FROM pg_namespace WHERE nspname = 'retail'").fetchone()
    assert schemas == dict.fromkeys(APP_SCHEMAS, APP_MIGRATOR)
    assert checkpoint_tables == (3,) and retail == (0,)  # T21 owns checkpoint DDL; T16 owns retail


def test_populated_previous_revision_upgrades_with_data_intact(new_app_database: NewDatabase) -> None:
    first, *_ = migrate.revisions()
    database = new_app_database("previous", revision=first)
    assert database.current() == first and "app.chunks" not in _tables(database)
    report = seed_world(database)
    before = _counts(database)
    assert before["app.case_messages"] == report.messages == 11 and before["app.approval_decisions"] == 1
    database.upgrade()
    after = _counts(database)
    assert database.current() == migrate.head()
    assert {table: after[table] for table in before} == before  # nothing changed in pre-existing tables
    assert after["app.chunks"] == after["evaluation.evaluation_runs"] == 0
    with pytest.raises(AlreadyImported):
        seed_world(database)


def test_failed_revision_rolls_back_alone(new_app_database: NewDatabase) -> None:
    first, *_ = migrate.revisions()
    database = new_app_database("failing", revision=first)
    with database.superuser() as conn:
        conn.execute("CREATE SCHEMA evaluation")  # makes the second revision fail midway (after its first tables)
    with pytest.raises(Exception, match="evaluation"):
        database.upgrade()
    assert database.current() == first
    assert "app.chunks" not in _tables(database) and "app.usage_events" not in _tables(database)
    with database.superuser() as conn:
        conn.execute("DROP SCHEMA evaluation")
    database.upgrade()
    assert database.current() == migrate.head()


def test_lossy_downgrade_is_refused_unless_explicitly_allowed(new_app_database: NewDatabase) -> None:
    first, second, *_ = migrate.revisions()
    database = new_app_database("downgrade")
    seed_world(database)
    world = World()
    with workspace_transaction(database.engine(APP_RUNTIME), world.workspace) as conn:
        repo.record_usage(conn, UsageEvent(
            id=uuid4(), workspace_id=world.workspace, actor="agent", provider="fake", model="fake-small",
            provider_request_id="req-1", uncached_input_tokens=10, cache_read_tokens=0, cache_write_tokens=0,
            output_tokens=5, reasoning_tokens=0, price_revision="synthetic-1", cost_status="known",
            cost_usd=Decimal("0.000000000000000001"), created_at=world.now))
    # The synthetic world's run carries 0005's fencing/high-water fields, so leaving 0005 is an explicit, accepted loss.
    database.downgrade("0004", allow_data_loss=True)
    database.downgrade(second)  # later revisions hold no rows here; each downgrade step commits on its own
    with pytest.raises(DataLossRefused, match=r"app\.usage_events"):
        database.downgrade(first)
    assert database.current() == second
    with database.superuser() as conn:
        forced = conn.execute("SELECT bool_and(relforcerowsecurity) FROM pg_class c JOIN pg_namespace n "
                              "ON n.oid = c.relnamespace WHERE n.nspname = 'app' AND c.relkind = 'r'").fetchone()
    assert forced == (True,)  # the refusal rolled back the temporary NO FORCE
    kept = _counts(database)["app.case_messages"]
    database.downgrade(first, allow_data_loss=True)
    assert database.current() == first and "app.usage_events" not in _tables(database)
    assert _counts(database)["app.case_messages"] == kept  # only the dropped revision's tables lost rows


def _security_snapshot(database: AppDatabase) -> dict[str, object]:
    with database.superuser() as conn:
        return {
            "constraints": conn.execute(
                "SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE connamespace::regnamespace::text = ANY(%s) ORDER BY 1, 2", (list(APP_SCHEMAS),)).fetchall(),
            "policies": conn.execute("SELECT schemaname, tablename, policyname, roles::text, cmd, qual, with_check "
                                     "FROM pg_policies ORDER BY 1, 2, 3").fetchall(),
            "rls": conn.execute("SELECT c.oid::regclass::text, relrowsecurity, relforcerowsecurity FROM pg_class c "
                                "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ANY(%s) "
                                "AND relkind = 'r' ORDER BY 1", (list(APP_SCHEMAS),)).fetchall(),
            "grants": conn.execute("SELECT table_schema, table_name, grantee, privilege_type FROM "
                                   "information_schema.role_table_grants WHERE table_schema = ANY(%s) "
                                   "ORDER BY 1, 2, 3, 4", (list(APP_SCHEMAS),)).fetchall(),
            "column_grants": conn.execute("SELECT table_schema, table_name, column_name, grantee, privilege_type "
                                          "FROM information_schema.column_privileges WHERE table_schema = ANY(%s) "
                                          "AND grantee = ANY(%s) ORDER BY 1, 2, 3, 4, 5",
                                          (list(APP_SCHEMAS), list(RUNTIME_ROLES))).fetchall(),
            "triggers": conn.execute("SELECT tgrelid::regclass::text, tgname FROM pg_trigger WHERE NOT tgisinternal "
                                     "ORDER BY 1, 2").fetchall(),
            "schema_acl": conn.execute("SELECT nspname, nspacl::text FROM pg_namespace WHERE nspname = ANY(%s) "
                                       "ORDER BY 1", (list(APP_SCHEMAS),)).fetchall(),
        }


def test_restore_into_a_separate_database_preserves_rows_and_security(app_cluster: AppCluster,
                                                                      new_app_database: NewDatabase) -> None:
    source = new_app_database("restore_src")
    seed_world(source)
    target = new_app_database("restore_dst", extensions=False, revision=None)  # empty database, grants only
    dump = app_cluster.server.dump_and_restore(source.name, target.name)
    assert dump.is_file() and dump.stat().st_size > 0
    target.report = target.provision_extensions()  # idempotent after the restore created the extension
    assert _counts(target) == _counts(source)
    assert _security_snapshot(target) == _security_snapshot(source)
    assert target.current() == source.current() == migrate.head()
    world = World()
    with workspace_transaction(target.engine(APP_RUNTIME), world.workspace) as conn:
        assert repo.get_case(conn, world.case) is not None
    with workspace_transaction(target.engine(APP_RUNTIME), uuid4()) as conn:  # other workspace: nothing visible
        assert repo.get_case(conn, world.case) is None
    assert not list((app_cluster.server.root / "secrets").glob("pgpass-*"))  # transient credential removed


def test_bootstrap_is_idempotent_and_refuses_unsafe_preconditions(app_cluster: AppCluster) -> None:
    server = app_cluster.server
    name = app_cluster.new_name("bootstrap")
    server.register_database(name)
    passwords = [RolePassword(role, server.passwords[role]) for role in ALL_ROLES]
    for _ in range(2):  # the second run re-asserts roles (ALTER) and finds the database already correct
        with server.connect("postgres", "postgres", autocommit=True) as conn:
            report = bootstrap.bootstrap(conn, database=name, passwords=passwords,
                                         connect_database=lambda db: server.connect("postgres", db, autocommit=True))
        assert report.version == "0.8.7"
    for role in ALL_ROLES:  # the re-asserted verifiers still match the registered passwords
        with server.connect(role, name) as conn:
            assert conn.execute("SELECT current_user").fetchone() == (role,)
    with server.connect("postgres", "postgres", autocommit=True) as conn:
        conn.execute(f"CREATE DATABASE {name}_foreign")  # owned by postgres, not the migrator
        try:
            with pytest.raises(bootstrap.BootstrapError, match="owned by postgres"):
                bootstrap.provision_database(conn, f"{name}_foreign")
        finally:
            conn.execute(f"DROP DATABASE {name}_foreign")
        for bad in ("postgres", "pg_app", "app-db", "app;drop", "App"):
            with pytest.raises(bootstrap.BootstrapError, match="not an allowed"):
                bootstrap.provision_database(conn, bad)
        with pytest.raises(bootstrap.BootstrapError, match="exactly one password"):
            bootstrap.provision_roles(conn, passwords[:-1])
    with server.connect(APP_MIGRATOR, name, autocommit=True) as conn, \
            pytest.raises(bootstrap.BootstrapError, match="superuser"):
        bootstrap.provision_database(conn, name)
    with server.connect("postgres", "postgres") as conn, pytest.raises(bootstrap.BootstrapError, match="autocommit"):
        bootstrap.provision_roles(conn, passwords)


def test_client_side_scram_verifier_matches_postgresql(app_cluster: AppCluster) -> None:
    """Independent check: PostgreSQL computes a verifier (random salt) for a synthetic password; ours, given that
    salt and iteration count, must be byte-identical. Done inside a rolled-back transaction."""
    import base64

    synthetic = "synthetic-scram-check-" + "Q7" * 8
    with app_cluster.server.connect("postgres", "postgres") as conn:
        conn.execute(f"CREATE ROLE policyops_test_scram NOLOGIN PASSWORD '{synthetic}'")
        stored = conn.execute("SELECT rolpassword FROM pg_authid WHERE rolname = 'policyops_test_scram'").fetchone()
        conn.rollback()
    assert stored is not None
    verifier = stored[0]
    iterations, salt = verifier.split("$")[1].split(":")
    assert scram_sha256_verifier(synthetic, salt=base64.b64decode(salt), iterations=int(iterations)) == verifier


def test_migrations_refuse_a_connection_with_an_open_transaction(new_app_database: NewDatabase) -> None:
    """C1 finding F1: a caller transaction would make Alembic run every revision inside it (a later failure then
    loses earlier revisions, and the caller's work could be committed). Refused before any work instead."""
    first, *_ = migrate.revisions()
    database = new_app_database("precondition", revision=first)
    with database.superuser() as conn:
        conn.execute("CREATE SCHEMA evaluation")  # would make 0002 fail midway, as in the reviewer's probe
    engine = database.engine(APP_MIGRATOR)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))  # ordinary prior use: an implicit transaction is now open
        assert conn.in_transaction()
        with pytest.raises(migrate.MigrationPreconditionError):
            migrate.upgrade(conn)
        with pytest.raises(migrate.MigrationPreconditionError):
            migrate.downgrade(conn, "base", allow_data_loss=True)
        assert conn.in_transaction()  # the caller's transaction is left exactly as it was
        conn.rollback()
    with engine.connect() as conn:  # uncommitted caller work is neither committed nor rolled back by us
        conn.execute(text("CREATE TABLE public.caller_work (x int)"))
        with pytest.raises(migrate.MigrationPreconditionError):
            migrate.upgrade(conn)
        assert conn.execute(text("SELECT to_regclass('public.caller_work') IS NOT NULL")).scalar_one() is True
        conn.rollback()
    with database.superuser() as conn:
        assert conn.execute("SELECT to_regclass('public.caller_work')").fetchone() == (None,)
    assert database.current() == first and "app.chunks" not in _tables(database)
    with engine.connect() as conn:  # current() leaves no transaction behind, so a migration may follow
        assert migrate.current(conn) == first and not conn.in_transaction()
        with pytest.raises(Exception, match="evaluation"):
            migrate.upgrade(conn)  # the clean-connection failure keeps 0001 (per-revision boundary)
        assert not conn.in_transaction()
    assert database.current() == first
    with database.superuser() as conn:
        conn.execute("DROP SCHEMA evaluation")
    database.upgrade()
    assert database.current() == migrate.head()


def test_0003_upgrades_populated_data_and_refuses_lossy_downgrade(new_app_database: NewDatabase) -> None:
    """T07 forward migration: a 0002 database with identity rows and a pre-0003 session upgrades in place; such a
    session has no CSRF digest or last-seen time, so the application treats it as invalid. Downgrading 0003 is
    refused while login or session rows exist."""
    from datetime import timedelta

    from policyops.auth.tokens import digest

    _, second, third, *_ = migrate.revisions()
    database = new_app_database("auth_upgrade", revision=second)
    seed_world(database)
    world = World()
    with database.superuser() as conn:
        conn.execute("INSERT INTO identity.sessions (id, principal_id, cookie_sha256, created_at, expires_at) "
                     "VALUES (gen_random_uuid(), %s, %s, %s, %s)",
                     (world.analyst, digest("pre-0003-cookie"), world.now, world.now + timedelta(hours=1)))
    before = _counts(database)
    database.upgrade(third)
    assert database.current() == third
    after = _counts(database)
    assert {table: after[table] for table in before} == before and after["identity.login_requests"] == 0
    with database.superuser() as conn:
        assert conn.execute("SELECT csrf_sha256, last_seen_at FROM identity.sessions").fetchone() == (None, None)
    with pytest.raises(DataLossRefused, match=r"identity\.sessions"):
        database.downgrade(second)
    assert database.current() == third
    database.downgrade(second, allow_data_loss=True)
    with database.superuser() as conn:
        columns = {row[0] for row in conn.execute("SELECT column_name FROM information_schema.columns "
                                                  "WHERE table_schema = 'identity' AND table_name = 'sessions'")}
    assert database.current() == second and not {"csrf_sha256", "last_seen_at"} & columns
    assert _counts(database)["identity.sessions"] == 1  # the session row itself survives a column drop


def test_0004_upgrades_populated_data_and_guards_the_response_ledger(new_app_database: NewDatabase) -> None:
    """T08 forward migration: a populated 0003 database upgrades in place, gaining the request-idempotency ledger
    (case/message composite foreign keys, operation/message rule, forced RLS) and the immutable queue index.
    Downgrading is refused while ledger rows exist; without them it removes exactly what 0004 added."""
    import psycopg

    _, _, third, fourth, *_ = migrate.revisions()
    database = new_app_database("idempotency_upgrade", revision=third)
    seed_world(database)
    world = World()
    before = _counts(database)
    database.upgrade(fourth)
    after = _counts(database)
    assert {table: after[table] for table in before} == before and after["app.request_idempotency"] == 0
    other_workspace, other_case, second_case = uuid4(), uuid4(), uuid4()
    with database.superuser() as conn:  # constraints apply to the superuser too (RLS does not)
        assert conn.execute("SELECT indexdef FROM pg_indexes WHERE indexname = 'cases_queue_created'").fetchone() \
            == ("CREATE INDEX cases_queue_created ON app.cases USING btree (workspace_id, created_at DESC, id DESC)",)
        message = conn.execute("SELECT id FROM app.case_messages WHERE case_id = %s", (world.case,)).fetchone()[0]
        conn.execute("INSERT INTO identity.workspaces (id, slug, name, created_at) VALUES (%s, 'other-ws', 'Other', "
                     "%s)", (other_workspace, world.now))
        for case_id, workspace_id in ((other_case, other_workspace), (second_case, world.workspace)):
            conn.execute("INSERT INTO app.cases (id, workspace_id, scenario, status, created_at, updated_at) "
                         "VALUES (%s, %s, 'retail', 'open', %s, %s)", (case_id, workspace_id, world.now, world.now))

        def ledger(operation: str, workspace_id: Any, case_id: Any, message_id: Any, *, key: str = "key-0001",
                   status: int = 201) -> None:
            conn.execute("INSERT INTO app.request_idempotency (workspace_id, principal_id, operation, "
                         "idempotency_key, request_sha256, case_id, message_id, response_status, response_body, "
                         "response_etag, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '{}', '\"1\"', %s)",
                         (workspace_id, world.analyst, operation, key, "0" * 64, case_id, message_id, status,
                          world.now))

        refused = [
            (psycopg.errors.ForeignKeyViolation, ("case.message", world.workspace, second_case, message)),  # wrong case
            (psycopg.errors.ForeignKeyViolation, ("case.status", other_workspace, world.case, None)),  # foreign case
            (psycopg.errors.CheckViolation, ("case.create", world.workspace, world.case, message)),
            (psycopg.errors.CheckViolation, ("case.message", world.workspace, world.case, None)),
            (psycopg.errors.CheckViolation, ("case.delete", world.workspace, world.case, None)),
        ]
        for error, args in refused:
            with pytest.raises(error):
                ledger(*args)
        with pytest.raises(psycopg.errors.CheckViolation):
            ledger("case.status", world.workspace, world.case, None, status=409)
        with pytest.raises(psycopg.errors.CheckViolation):
            ledger("case.status", world.workspace, world.case, None, key="short")
        ledger("case.message", world.workspace, world.case, message)
        ledger("case.status", other_workspace, other_case, None)
        with pytest.raises(psycopg.errors.UniqueViolation):
            ledger("case.message", world.workspace, world.case, message)
    with workspace_transaction(database.engine(APP_RUNTIME), world.workspace) as conn:  # forced RLS
        visible = conn.execute(text("SELECT workspace_id FROM app.request_idempotency")).all()
    assert visible == [(world.workspace,)]
    with pytest.raises(DataLossRefused, match=r"app\.request_idempotency"):
        database.downgrade(third)
    assert database.current() == fourth
    with database.superuser() as conn:
        conn.execute("DELETE FROM app.request_idempotency")
    database.downgrade(third)
    with database.superuser() as conn:
        assert conn.execute("SELECT to_regclass('app.request_idempotency'), to_regclass('app.cases_queue_created')"
                            ).fetchone() == (None, None)
        assert conn.execute("SELECT count(*) FROM pg_constraint WHERE conname = 'case_messages_case_unique'"
                            ).fetchone() == (0,)
    assert database.current() == third and _counts(database)["app.case_messages"] == before["app.case_messages"]
    database.upgrade(fourth)
    assert database.current() == fourth
