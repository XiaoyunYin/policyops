"""An owned, contained PostgreSQL server for integration tests (pinned pgvector image).

Containment, by construction, verified with `docker inspect` after start:
- The only writable location is one bind mount, from a unique directory under POLICYOPS_TEMP_DIR to the image's
  declared volume path, so Docker creates no anonymous volume. PGDATA, server logs and the one-time bootstrap
  password file live below it.
- The container root filesystem is read-only, Docker log storage is disabled (`--log-driver none`) and there is
  no Unix socket (TCP only).
- The port is published only on 127.0.0.1, on an ephemeral host port; 5432 and other projects' servers are never
  used.

Ownership: unique container name plus `policyops.owner` and `policyops.run` labels. Teardown removes only the
recorded container ID after re-checking those labels (`docker rm -f -v` also drops that container's own anonymous
volumes, of which there should be none). The data directory and logs are kept for diagnosis; a startup failure
raises with the log tails.

libpq (psycopg) bypasses the Python socket guard, so connections go through `connect()` (or `try_password()` for
negative tests). Both fix host, hostaddr, port, user and startup options to this server and check the endpoint
registered with policyops_testing.network for the server's lifetime; no other libpq parameter can be passed through.
Ambient PG* session variables (PGOPTIONS in particular) therefore cannot change logging on the bootstrap connection.
"""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from typing import Any

import psycopg
from psycopg import sql

from policyops_testing import network, redaction


REPO = Path(__file__).resolve().parents[3]
VOLUME = "/var/lib/postgresql/data"
DATABASE = "policyops_harness"
MIGRATOR, RUNTIME = "policyops_migrator", "policyops_runtime"
OWNER_LABEL = "policyops.owner=policyops-tests"
LOOPBACK = "127.0.0.1"
CONNECT_ROLES = ("postgres", MIGRATOR, RUNTIME)
CONNECT_DATABASES = ("postgres", DATABASE)
# Pinned libpq startup options for every helper connection (replaces any ambient PGOPTIONS). Only a user-settable
# parameter: pinning a superuser-only one such as log_statement would make runtime-role connections fail.
SESSION_OPTIONS = "-c timezone=UTC"
SERVER_SCRIPT = (
    "set -eu; "
    f"if [ ! -s {VOLUME}/pgdata/PG_VERSION ]; then "
    f"initdb -D {VOLUME}/pgdata --username=postgres --auth=scram-sha-256 --pwfile={VOLUME}/secrets/superuser "
    f"--encoding=UTF8 --locale=C.UTF-8 >{VOLUME}/log/initdb.log 2>&1; "
    # Docker forwards the 127.0.0.1-only published port from the bridge address; require SCRAM for it.
    f"echo 'host all all all scram-sha-256' >> {VOLUME}/pgdata/pg_hba.conf; fi; "
    f"exec postgres -D {VOLUME}/pgdata -c listen_addresses='*' -c unix_socket_directories='' "
    f"-c logging_collector=on -c log_directory={VOLUME}/log -c log_filename=postgresql.log "
    # The log file is persisted under the temporary root. Client-statement ERROR/WARNING messages (which can echo
    # literal input, e.g. an invalid cast or a duplicate key) and failed statement text (e.g. CREATE ROLE ...
    # PASSWORD) are not written to it; LOG (startup, shutdown, checkpoints) and FATAL/PANIC (authentication and
    # startup failures) are kept for diagnosis. Those can still carry client-chosen text (RAISE LOG, startup
    # option values), so tests must not put secrets there; registered secrets are redacted from log tails.
    "-c log_min_messages=log -c log_min_error_statement=panic "
    # On Linux the server runs as the image's postgres user; the host test user must be able to read the log.
    "-c log_file_mode=0644"
)


class PostgresUnavailable(RuntimeError):
    """Docker or the pinned image is missing, or the server did not become ready (log tails attached)."""


class CleanupUncertain(PostgresUnavailable):
    """Teardown could not confirm that the owned container is gone (Docker unreachable, denied or timed out).

    The container ID is kept on the server object; nothing else is removed.
    """


def _observe(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return _docker(*args, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CleanupUncertain(f"docker {args[0]} could not run: {type(exc).__name__}") from exc


def _container_exists(container_id: str) -> bool:
    """True if Docker lists the exact container, False if a successful listing does not; otherwise raise."""
    listed = _observe("ps", "-a", "-q", "--no-trunc", "--filter", f"id={container_id}")
    if listed.returncode != 0:
        raise CleanupUncertain(f"cannot observe container {container_id}: {listed.stderr.strip()[:300]}")
    return container_id in listed.stdout.split()


def pinned_image() -> str:
    pins = json.loads((REPO / "infra" / "images.json").read_text(encoding="utf-8"))["images"]["postgres"]
    return f"{pins['image']}@{pins['digest']}"


def _docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


def _tail(path: Path, lines: int = 20) -> str:
    if not path.is_file():
        return f"<{path.name} missing>"
    return redaction.redact_text("\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]))


@dataclass
class OwnedPostgres:
    root: Path
    run_id: str
    image: str = field(default_factory=pinned_image)
    container_id: str = ""
    port: int = 0
    passwords: dict[str, str] = field(default_factory=dict)
    _allowance: contextlib.ExitStack = field(default_factory=contextlib.ExitStack)

    @property
    def name(self) -> str:
        return f"policyops-test-pg-{self.run_id}"

    # -- lifecycle ---------------------------------------------------------------------------------------

    def start(self, *, deadline_seconds: float = 120) -> None:
        if _docker("image", "inspect", self.image).returncode != 0:
            raise PostgresUnavailable(f"pinned image {self.image} is not installed; pull it by digest first")
        for sub in ("log", "secrets", "client"):
            (self.root / sub).mkdir(parents=True, exist_ok=False)
        if os.name != "nt":  # the container's postgres user must create PGDATA inside the bind mount
            for path in (self.root, self.root / "log", self.root / "secrets"):
                path.chmod(0o777)
        self.passwords = {role: secrets.token_urlsafe(24) for role in CONNECT_ROLES}
        redaction.register(*self.passwords.values())
        (self.root / "secrets" / "superuser").write_text(self.passwords["postgres"] + "\n", encoding="utf-8")
        run = _docker("run", "-d", "--name", self.name, "--label", OWNER_LABEL,
                      "--label", f"policyops.run={self.run_id}", "--read-only", "--log-driver", "none",
                      "--user", "postgres", "-p", "127.0.0.1::5432",
                      "--mount", f"type=bind,source={self.root},target={VOLUME}",
                      "--entrypoint", "sh", self.image, "-c", SERVER_SCRIPT)
        if run.returncode != 0:
            raise PostgresUnavailable(f"docker run failed: {redaction.redact_text(run.stderr.strip())[-500:]}")
        self.container_id = run.stdout.strip()
        try:
            self._verify_containment()
            self._bind_port()
            self._wait_ready(deadline_seconds)
            self._bootstrap()
        except BaseException:
            self.stop()
            raise
        finally:
            (self.root / "secrets" / "superuser").unlink(missing_ok=True)

    def _inspect(self) -> dict[str, Any]:
        result = _docker("inspect", self.container_id)
        if result.returncode != 0:
            raise PostgresUnavailable("container disappeared")
        inspected: dict[str, Any] = json.loads(result.stdout)[0]
        return inspected

    def _verify_containment(self) -> None:
        info = self._inspect()
        mounts = [(m.get("Type"), m.get("Destination")) for m in info.get("Mounts", [])]
        problems = []
        if mounts != [("bind", VOLUME)]:
            problems.append(f"mounts are {mounts}, expected exactly one bind at {VOLUME}")
        if not info["HostConfig"].get("ReadonlyRootfs"):
            problems.append("root filesystem is writable")
        if info["HostConfig"]["LogConfig"]["Type"] != "none":
            problems.append("Docker log storage is enabled")
        bindings = info["HostConfig"]["PortBindings"].get("5432/tcp") or []
        if [b.get("HostIp") for b in bindings] != ["127.0.0.1"]:
            problems.append(f"port bindings {bindings} are not 127.0.0.1-only")
        if problems:
            raise PostgresUnavailable("; ".join(problems))

    def _bind_port(self) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            mapping = _docker("port", self.container_id, "5432/tcp").stdout.strip().splitlines()
            if mapping:
                port = int(mapping[0].rsplit(":", 1)[1])
                if port == 5432:
                    raise PostgresUnavailable("Docker assigned host port 5432; refusing the shared default port")
                self._allowance.close()
                self._allowance = contextlib.ExitStack()
                self._allowance.enter_context(network.allow("127.0.0.1", port))
                self.port = port
                return
            if _docker("inspect", "-f", "{{.State.Running}}", self.container_id).stdout.strip() != "true":
                break
            time.sleep(0.25)
        raise self._startup_error("the container published no port")

    def _wait_ready(self, deadline_seconds: float) -> None:
        deadline, last = time.monotonic() + deadline_seconds, "not attempted"
        while time.monotonic() < deadline:
            if _docker("inspect", "-f", "{{.State.Running}}", self.container_id).stdout.strip() != "true":
                raise self._startup_error("the server process exited")
            try:
                with self.connect("postgres", "postgres", connect_timeout=3) as conn:
                    conn.execute("select 1")
                    return
            except psycopg.OperationalError as exc:
                last = type(exc).__name__
                time.sleep(0.5)
        raise self._startup_error(f"not ready within {deadline_seconds} s ({last})")

    def _startup_error(self, reason: str) -> PostgresUnavailable:
        return PostgresUnavailable(redaction.redact_text(
            f"{reason}\n--- initdb.log ---\n{_tail(self.root / 'log' / 'initdb.log')}"
            f"\n--- postgresql.log ---\n{_tail(self.root / 'log' / 'postgresql.log')}"))

    def _bootstrap(self) -> None:
        with self.connect("postgres", "postgres", autocommit=True) as conn:
            for role, inherit in ((MIGRATOR, "INHERIT"), (RUNTIME, "NOINHERIT")):
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                                     "NOREPLICATION NOBYPASSRLS " + inherit).format(
                    sql.Identifier(role), sql.Literal(self.passwords[role])))
            conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(DATABASE),
                                                                       sql.Identifier(MIGRATOR)))
            conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(DATABASE)))
            conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(DATABASE),
                                                                            sql.Identifier(RUNTIME)))
        with self.connect("postgres", DATABASE, autocommit=True) as conn:
            conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            conn.execute(sql.SQL("ALTER SCHEMA public OWNER TO {}").format(sql.Identifier(MIGRATOR)))
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(RUNTIME)))

    def restart(self, *, deadline_seconds: float = 120) -> None:
        if _docker("restart", self.container_id).returncode != 0:
            raise self._startup_error("docker restart failed")
        self._bind_port()  # Docker assigns a new ephemeral host port on restart
        self._wait_ready(deadline_seconds)

    def stop(self) -> None:
        self._allowance.close()
        try:
            if self.container_id:
                self._remove_owned_container()
        finally:
            redaction.forget(*self.passwords.values())

    def _remove_owned_container(self) -> None:
        """Remove exactly this run's container (by ID, after checking its labels and name) and verify it is gone.

        Absence counts only when a successful Docker listing confirms it; if Docker cannot be observed the ID is
        kept and CleanupUncertain is raised.
        """
        if not _container_exists(self.container_id):  # confirmed already gone
            self.container_id = ""
            return
        found = _observe("inspect", "-f", '{{index .Config.Labels "policyops.owner"}} '
                         '{{index .Config.Labels "policyops.run"}} {{.Name}}', self.container_id)
        if found.returncode != 0:
            raise CleanupUncertain(f"cannot inspect container {self.container_id}: {found.stderr.strip()[:300]}")
        if found.stdout.split() != ["policyops-tests", self.run_id, f"/{self.name}"]:
            raise PostgresUnavailable(f"refusing to remove {self.container_id}: not this run's container")
        removed = _observe("rm", "-f", "-v", self.container_id)
        if _container_exists(self.container_id):
            raise PostgresUnavailable(f"container {self.container_id} was not removed: {removed.stderr.strip()[:300]}")
        self.container_id = ""

    # -- clients -----------------------------------------------------------------------------------------

    def connect(self, role: str, dbname: str = DATABASE, *, autocommit: bool = False,
                connect_timeout: int = 5) -> psycopg.Connection[Any]:
        """Connect as one of this server's roles to its registered endpoint.

        There is deliberately no pass-through of libpq parameters: host, hostaddr, port, service, user and password
        are fixed here, because libpq would otherwise connect to a target the socket guard never sees.
        """
        if role not in self.passwords:
            raise ValueError(f"{role!r} is not a role of this server")
        return self._connect(role, dbname, self.passwords[role], autocommit=autocommit,
                             connect_timeout=connect_timeout)

    def try_password(self, role: str, password: str) -> None:
        """Negative-test helper: one connection attempt with a caller-chosen password, same fixed target."""
        if role not in CONNECT_ROLES:
            raise ValueError(f"{role!r} is not a role of this server")
        self._connect(role, DATABASE, password, autocommit=False, connect_timeout=5).close()

    def _connect(self, role: str, dbname: str, password: str, *, autocommit: bool,
                 connect_timeout: int) -> psycopg.Connection[Any]:
        # A dbname containing "=" or a URI is expanded by libpq into a full connection string, so only the two
        # known database names are accepted.
        if dbname not in CONNECT_DATABASES:
            raise ValueError(f"{dbname!r} is not a database of this server")
        if not isinstance(autocommit, bool):
            raise TypeError("autocommit must be a bool")
        if isinstance(connect_timeout, bool) or not isinstance(connect_timeout, int) or not 1 <= connect_timeout <= 60:
            raise ValueError("connect_timeout must be an int between 1 and 60 seconds")
        if not isinstance(password, str):
            raise TypeError("password must be a str")
        network.require_registered(LOOPBACK, self.port)
        # libpq fills every parameter not given here from PG* environment variables. hostaddr is pinned so PGHOSTADDR
        # cannot choose the address; `options` is pinned to a harmless value so an ambient PGOPTIONS (for example
        # "-c log_statement=all" on the superuser bootstrap connection) never reaches the server.
        return psycopg.connect(host=LOOPBACK, hostaddr=LOOPBACK, port=self.port, user=role, dbname=dbname,
                               password=password, sslmode="disable", gssencmode="disable",
                               passfile=str(self.root / "client" / "no-passfile"), connect_timeout=connect_timeout,
                               options=SESSION_OPTIONS, client_encoding="UTF8",
                               application_name="policyops-tests", autocommit=autocommit)


@contextlib.contextmanager
def owned_postgres(base: Path, run_id: str) -> Iterator[OwnedPostgres]:
    server = OwnedPostgres(root=base / run_id, run_id=run_id)
    server.root.mkdir(parents=True, exist_ok=False)
    previous = {name: os.environ.get(name) for name in ("PGSERVICEFILE", "PGSYSCONFDIR")}
    os.environ["PGSERVICEFILE"] = str(server.root / "client" / "no-service-file")
    os.environ["PGSYSCONFDIR"] = str(server.root / "client")
    try:
        server.start()
        yield server
    finally:
        server.stop()
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
