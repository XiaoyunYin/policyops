"""Provision the retail roles and schema on a superuser connection (coordinated bootstrap; T16 owns these).

* `retail_migrator` owns schema `retail` and runs the retail chain; `retail_runtime` has only the DML the revisions
  grant. Both are LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, and members of nothing.
* `PUBLIC` has no access to `retail`; only `retail_runtime` gets USAGE. Application roles receive nothing here.
`check_isolation` verifies the cross-denials in both directions from the catalog (no application import).
Passwords are sent as SQL literals on the bootstrap connection only (the owned test server does not log statement
text) and are never returned or logged.
"""

from __future__ import annotations

from typing import Any

from psycopg import sql


MIGRATOR, RUNTIME = "retail_migrator", "retail_runtime"
ROLES = (MIGRATOR, RUNTIME)


class BootstrapError(RuntimeError):
    pass


def provision(conn: Any, database: str, passwords: dict[str, str]) -> None:
    if set(passwords) != set(ROLES) or any(len(value) < 24 for value in passwords.values()):
        raise BootstrapError("a password of at least 24 characters is required for each retail role")
    if not conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0]:
        raise BootstrapError("retail bootstrap needs a superuser connection")
    for role in ROLES:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
        verb = "ALTER" if exists else "CREATE"
        conn.execute(sql.SQL(verb + " ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
                             "NOBYPASSRLS").format(sql.Identifier(role), sql.Literal(passwords[role])))
    conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}").format(
        sql.Identifier(database), sql.Identifier(MIGRATOR), sql.Identifier(RUNTIME)))
    conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS retail AUTHORIZATION {}").format(sql.Identifier(MIGRATOR)))
    conn.execute(sql.SQL("ALTER SCHEMA retail OWNER TO {}").format(sql.Identifier(MIGRATOR)))
    conn.execute("REVOKE ALL ON SCHEMA retail FROM PUBLIC")
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA retail TO {}").format(sql.Identifier(RUNTIME)))
    check_isolation(conn)


def check_isolation(conn: Any) -> None:
    """Refuse if a retail role is privileged or a member of anything, if any other non-superuser role can use
    schema `retail`, or if a retail role can use any other non-system schema."""
    for role in ROLES:
        row = conn.execute("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles "
                           "WHERE rolname = %s", (role,)).fetchone()
        if row is None or any(row):
            raise BootstrapError(f"{role} must exist without superuser, BYPASSRLS, CREATEROLE or CREATEDB")
        if conn.execute("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member "
                        "WHERE r.rolname = %s", (role,)).fetchone()[0]:
            raise BootstrapError(f"{role} must not be a member of another role")
    others = conn.execute("SELECT rolname FROM pg_roles WHERE NOT rolsuper AND rolname NOT LIKE 'pg\\_%%' "
                          "AND rolname NOT IN (%s, %s) AND has_schema_privilege(oid, 'retail', 'USAGE')",
                          ROLES).fetchall()
    if others:
        raise BootstrapError("non-retail roles can use schema retail: " + ", ".join(r[0] for r in others))
    # `public` may keep PostgreSQL's default PUBLIC USAGE (the application bootstrap decides that); what must not
    # exist is retail access to any other schema, or to any table outside `retail`.
    leaks = conn.execute(
        "SELECT r.rolname, n.nspname FROM pg_roles r CROSS JOIN pg_namespace n WHERE r.rolname IN (%s, %s) "
        "AND n.nspname NOT IN ('retail', 'public', 'pg_catalog', 'information_schema') "
        "AND n.nspname NOT LIKE 'pg\\_%%' AND has_schema_privilege(r.oid, n.oid, 'USAGE')", ROLES).fetchall()
    leaks += conn.execute(
        "SELECT r.rolname, n.nspname || '.' || c.relname FROM pg_roles r CROSS JOIN pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE r.rolname IN (%s, %s) "
        "AND c.relkind IN ('r', 'v', 'm', 'p') "
        "AND n.nspname NOT IN ('retail', 'pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_%%' "
        "AND has_table_privilege(r.oid, c.oid, 'SELECT, INSERT, UPDATE, DELETE')", ROLES).fetchall()
    if leaks:
        raise BootstrapError("retail roles reach other schemas or tables: " + ", ".join(f"{a}:{b}" for a, b in leaks))
