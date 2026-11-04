"""Controlled superuser bootstrap of the application roles and an application database.

This is the only step that needs a superuser. It is idempotent and has three parts, usable separately (a restore
target needs only the database part before `pg_restore`):

1. `provision_roles`: create or re-assert the four application roles with their attributes and passwords
   (sent as SCRAM verifiers, never plaintext).
2. `provision_database`: create the database owned by the migrator, revoke PUBLIC access and grant CONNECT to the
   runtime roles.
3. `provision_extensions`: in that database, install `vector` (pgvector), revoke CREATE on schema public from
   PUBLIC and report the extension's actual version and `trusted` metadata (PLAN D6: the migrator is not assumed
   able to install it).

Schemas, tables, grants and policies are created afterwards by the migrator through Alembic (`migrate.py`).
Retail roles/schema are T16's and are never touched.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import re
from typing import Any

import psycopg
from psycopg import sql

from policyops.persistence.roles import (
    ALL_ROLES,
    APP_MIGRATOR,
    RUNTIME_ROLES,
    RolePassword,
    scram_sha256_verifier,
)


DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
ROLE_ATTRIBUTES = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"


class BootstrapError(RuntimeError):
    """A bootstrap precondition failed (wrong connection, invalid name, missing password or extension)."""


@dataclass(frozen=True)
class ExtensionReport:
    name: str
    version: str
    trusted: bool  # pg_available_extension_versions.trusted for the installed version


def _require_superuser(conn: psycopg.Connection[Any]) -> None:
    if not conn.autocommit:
        raise BootstrapError("bootstrap needs an autocommit connection (CREATE DATABASE cannot run in a transaction)")
    row = conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()
    if row is None or row[0] is not True:
        raise BootstrapError("bootstrap must run as a superuser")


def _database_name(name: str) -> str:
    if not DATABASE_NAME.match(name) or name.startswith("pg_") or name in ("postgres", "template0", "template1"):
        raise BootstrapError(f"{name!r} is not an allowed application database name")
    return name


def provision_roles(conn: psycopg.Connection[Any], passwords: Sequence[RolePassword]) -> None:
    _require_superuser(conn)
    given = {password.role: password for password in passwords}
    if set(given) != set(ALL_ROLES) or len(given) != len(passwords):
        raise BootstrapError(f"exactly one password is required for each of {', '.join(ALL_ROLES)}")
    for role in ALL_ROLES:
        inherit = "INHERIT" if role == APP_MIGRATOR else "NOINHERIT"
        verifier = sql.Literal(scram_sha256_verifier(given[role].value))
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone() is not None
        verb = "ALTER" if exists else "CREATE"
        conn.execute(sql.SQL(f"{verb} ROLE {{}} {ROLE_ATTRIBUTES} {inherit} PASSWORD {{}}").format(
            sql.Identifier(role), verifier))
        # Re-asserting attributes is not enough if someone granted the role membership in another role.
        granted = conn.execute("SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
                               "JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = %s", (role,)).fetchall()
        if granted:
            raise BootstrapError(f"{role} is a member of other roles; refusing to continue")


def provision_database(conn: psycopg.Connection[Any], database: str) -> None:
    _require_superuser(conn)
    name = sql.Identifier(_database_name(database))
    row = conn.execute("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = %s", (database,)).fetchone()
    if row is None:
        conn.execute(sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8'").format(
            name, sql.Identifier(APP_MIGRATOR)))
    elif row[0] != APP_MIGRATOR:
        raise BootstrapError(f"database {database} exists but is owned by {row[0]}, not {APP_MIGRATOR}")
    conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(name))
    conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
        name, sql.SQL(", ").join(sql.Identifier(role) for role in RUNTIME_ROLES)))


def provision_extensions(conn: psycopg.Connection[Any], database: str) -> ExtensionReport:
    """Run on a superuser connection to `database` itself."""
    _require_superuser(conn)
    current = conn.execute("SELECT current_database()").fetchone()
    if current is None or current[0] != _database_name(database):
        raise BootstrapError(f"provision_extensions must be connected to {database}")
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public")
    conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    row = conn.execute("SELECT e.extversion, v.trusted FROM pg_extension e JOIN pg_available_extension_versions v "
                       "ON v.name = e.extname AND v.version = e.extversion WHERE e.extname = 'vector'").fetchone()
    if row is None:
        raise BootstrapError("the vector extension is not installed")
    return ExtensionReport(name="vector", version=str(row[0]), trusted=bool(row[1]))


def bootstrap(server: psycopg.Connection[Any], *, database: str, passwords: Sequence[RolePassword],
              connect_database: Callable[[str], psycopg.Connection[Any]]) -> ExtensionReport:
    """All three steps. `server` is an autocommit superuser connection; `connect_database(name)` opens an autocommit
    superuser connection to the named database (connection details are the caller's, never built here)."""
    provision_roles(server, passwords)
    provision_database(server, database)
    with connect_database(database) as conn:
        return provision_extensions(conn, database)
