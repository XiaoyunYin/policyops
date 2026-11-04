"""Owned PostgreSQL fixture: identity, containment, roles, harness RLS, vectors, restart and failure cleanup.

These prove properties of the test fixture only. The harness table's RLS policy is a fixture self-test, not the
application's tenant isolation (T06/T07).
"""

import os
from pathlib import Path
import subprocess
import time

import psycopg
from psycopg import errors
import pytest

from policyops_testing import network
from policyops_testing.postgres import DATABASE, MIGRATOR, RUNTIME, VOLUME, OwnedPostgres, PostgresUnavailable


pytestmark = pytest.mark.postgres


def test_server_identity_and_containment(postgres: OwnedPostgres) -> None:
    with postgres.connect(MIGRATOR) as conn:
        assert conn.execute("show server_version").fetchone()[0].startswith("17.11")  # type: ignore[index]
        assert conn.execute("select extversion from pg_extension where extname = 'vector'").fetchone() == ("0.8.7",)
    # PGDATA is private to the server's user on Linux, so its settings are read over SQL, not from the host.
    with postgres.connect("postgres", "postgres") as conn:
        assert conn.execute("show data_directory").fetchone() == (f"{VOLUME}/pgdata",)
        assert conn.execute("show unix_socket_directories").fetchone() == ("",)  # TCP only
    info = postgres._inspect()
    assert [(m["Type"], m["Destination"]) for m in info["Mounts"]] == [("bind", VOLUME)]
    assert info["HostConfig"]["ReadonlyRootfs"] is True and info["HostConfig"]["LogConfig"]["Type"] == "none"
    assert info["Config"]["Labels"]["policyops.owner"] == "policyops-tests"
    assert postgres.port != 5432 and ("127.0.0.1", postgres.port) in network.registered()
    temp_root = Path(os.environ["POLICYOPS_TEMP_DIR"]).resolve()
    assert temp_root in postgres.root.resolve().parents
    assert (postgres.root / "pgdata").is_dir() and (postgres.root / "log" / "postgresql.log").is_file()
    assert not (postgres.root / "secrets" / "superuser").exists()


def test_roles_are_distinct_and_runtime_is_unprivileged(postgres: OwnedPostgres) -> None:
    with postgres.connect(MIGRATOR) as conn:
        rows = conn.execute("select rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolinherit "
                            "from pg_roles where rolname = any(%s) order by rolname",
                            ([MIGRATOR, RUNTIME],)).fetchall()
    assert rows == [(MIGRATOR, False, False, False, False, True), (RUNTIME, False, False, False, False, False)]
    with postgres.connect(RUNTIME) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute("create table runtime_ddl(x int)")
    with postgres.connect(RUNTIME) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute("create schema runtime_schema")


def test_harness_rls_is_enforced_for_the_actual_runtime_role(postgres: OwnedPostgres) -> None:
    with postgres.connect(MIGRATOR) as conn:
        conn.execute("create table harness_items(workspace text not null, item text not null)")
        conn.execute("alter table harness_items enable row level security")
        conn.execute("alter table harness_items force row level security")
        conn.execute("create policy by_workspace on harness_items using "
                     "(workspace = current_setting('policyops.workspace', true)) "
                     "with check (workspace = current_setting('policyops.workspace', true))")
        conn.execute(f"grant select, insert on harness_items to {RUNTIME}")
        conn.execute("set policyops.workspace = 'w1'")
        conn.execute("insert into harness_items values ('w1', 'a'), ('w1', 'b')")
        conn.execute("set policyops.workspace = 'w2'")
        conn.execute("insert into harness_items values ('w2', 'c')")
        conn.commit()
    with postgres.connect(RUNTIME) as conn:
        assert conn.execute("select count(*) from harness_items").fetchone() == (0,)  # no workspace set
        conn.execute("select set_config('policyops.workspace', 'w1', false)")
        assert conn.execute("select item from harness_items order by item").fetchall() == [("a",), ("b",)]
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("insert into harness_items values ('w2', 'forged')")
        conn.rollback()
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("delete from harness_items")


def test_exact_vector_distance(postgres: OwnedPostgres) -> None:
    with postgres.connect(MIGRATOR) as conn:
        conn.execute("create table harness_vectors(id int primary key, v vector(3))")
        conn.execute("insert into harness_vectors values (1, '[1,0,0]'), (2, '[0,1,0]'), (3, '[1,1,0]')")
        rows = conn.execute("select id, v <-> '[1,0,0]' from harness_vectors order by v <-> '[1,0,0]', id").fetchall()
    assert [row[0] for row in rows] == [1, 3, 2] and rows[0][1] == 0.0


def test_restart_keeps_data_and_moves_the_registered_endpoint(postgres: OwnedPostgres) -> None:
    with postgres.connect(MIGRATOR) as conn:
        conn.execute("create table harness_durable(x int)")
        conn.execute("insert into harness_durable select generate_series(1, 1000)")
        conn.commit()
    old_port = postgres.port
    postgres.restart()
    assert ("127.0.0.1", postgres.port) in network.registered()
    if postgres.port != old_port:
        assert ("127.0.0.1", old_port) not in network.registered()
    with postgres.connect(MIGRATOR) as conn:
        assert conn.execute("select count(*) from harness_durable").fetchone() == (1000,)


def test_connections_outside_the_registered_endpoint_are_refused(postgres: OwnedPostgres) -> None:
    with pytest.raises(network.NetworkBlocked):
        network.require_registered("127.0.0.1", 5432)
    with pytest.raises(psycopg.OperationalError):
        postgres.try_password(RUNTIME, "wrong-SYNTHETIC")


def _server_log(postgres: OwnedPostgres) -> str:
    return (postgres.root / "log" / "postgresql.log").read_text(encoding="utf-8", errors="replace")


def _wait_for_log(postgres: OwnedPostgres, text: str, seconds: float = 10) -> str:
    deadline = time.monotonic() + seconds
    while text not in (log := _server_log(postgres)) and time.monotonic() < deadline:
        time.sleep(0.2)
    return log


def test_client_error_text_is_not_persisted_in_the_server_log(postgres: OwnedPostgres) -> None:
    # Synthetic canaries, not credentials. The invalid cast and the duplicate key echo the literal in the primary
    # ERROR message / DETAIL; division by zero carries it only in the statement text.
    with postgres.connect(MIGRATOR) as conn:
        with pytest.raises(errors.InvalidTextRepresentation) as cast:
            conn.execute("select 'canary-cast-K7Q4'::int")
        assert "canary-cast-K7Q4" in str(cast.value)  # the client does receive it; only persistence is prevented
        conn.rollback()
        conn.execute("create table harness_unique(v text primary key)")
        conn.execute("insert into harness_unique values ('canary-detail-M2P8')")
        with pytest.raises(errors.UniqueViolation):
            conn.execute("insert into harness_unique values ('canary-detail-M2P8')")
        conn.rollback()
        with pytest.raises(errors.DivisionByZero):
            conn.execute("select 'canary-statement-R5T1' || (1 / 0)::text")
        conn.rollback()
        assert conn.execute("show log_min_messages").fetchone() == ("log",)
        assert conn.execute("show log_min_error_statement").fetchone() == ("panic",)
    # A later FATAL proves the collector has flushed past the errors above.
    with pytest.raises(psycopg.OperationalError):
        postgres.try_password(RUNTIME, "canary-password-W9X3")
    log = _wait_for_log(postgres, f'password authentication failed for user "{RUNTIME}"')
    assert f'password authentication failed for user "{RUNTIME}"' in log  # FATAL diagnostics are kept
    assert "database system is ready to accept connections" in log  # startup LOG lines are kept
    for canary in ("canary-cast-K7Q4", "canary-detail-M2P8", "canary-statement-R5T1", "canary-password-W9X3"):
        assert canary not in log, canary


def _container_exists(container_id: str) -> bool:
    return subprocess.run(["docker", "inspect", container_id], capture_output=True, check=False).returncode == 0


def test_ambient_pg_session_variables_cannot_change_helper_connections(postgres: OwnedPostgres,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    # Set only after the session server's clean bootstrap; the statements are harmless synthetic markers, no
    # credentials are involved.
    monkeypatch.setenv("PGOPTIONS", "-c log_statement=all -c log_min_error_statement=debug5 -c timezone=Asia/Tokyo")
    monkeypatch.setenv("PGCLIENTENCODING", "LATIN1")
    with postgres.connect("postgres", "postgres") as conn:
        assert conn.execute("show log_statement").fetchone() == ("none",)
        assert conn.execute("show log_min_error_statement").fetchone() == ("panic",)
        assert conn.execute("show timezone").fetchone() == ("UTC",)
        assert conn.execute("show client_encoding").fetchone() == ("UTF8",)
        conn.execute("select 'ambient-options-marker-Q8Z2'")
    for role in (MIGRATOR, RUNTIME):  # a superuser-only option in PGOPTIONS would make these fail if it got through
        with postgres.connect(role) as conn:
            assert conn.execute("show timezone").fetchone() == ("UTC",)
            assert conn.execute("select current_user").fetchone() == (role,)
    needle = f'password authentication failed for user "{RUNTIME}"'
    before = _server_log(postgres).count(needle)
    with pytest.raises(psycopg.OperationalError):
        postgres.try_password(RUNTIME, "wrong-SYNTHETIC")
    deadline = time.monotonic() + 10
    while (log := _server_log(postgres)).count(needle) <= before and time.monotonic() < deadline:
        time.sleep(0.2)
    assert log.count(needle) > before  # the collector has flushed past the marker statement
    assert "ambient-options-marker-Q8Z2" not in log


def test_failed_startup_removes_only_its_container_and_keeps_logs(postgres: OwnedPostgres) -> None:
    # A second, owned server that is given no time to become ready: it must be torn down, with its logs kept.
    run_id = f"{postgres.run_id}-fail"
    server = OwnedPostgres(root=postgres.root.parent / run_id, run_id=run_id)
    server.root.mkdir()
    started = time.monotonic()
    with pytest.raises(PostgresUnavailable) as raised:
        server.start(deadline_seconds=0)
    assert time.monotonic() - started < 60
    assert "initdb.log" in str(raised.value)
    assert server.container_id == "" and not _container_exists(f"policyops-test-pg-{run_id}")
    assert (server.root / "log").is_dir()
    assert _container_exists(postgres.container_id)  # the session server is untouched
    with postgres.connect(MIGRATOR, DATABASE) as conn:
        assert conn.execute("select 1").fetchone() == (1,)
