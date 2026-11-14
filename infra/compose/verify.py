"""In-container assertions used by the manual smoke driver; stdout is safe JSON only."""

from __future__ import annotations

import json
import socket
import sys
from typing import Any

import psycopg
from runtime import connect


def require(value: bool, label: str) -> None:
    if not value:
        raise RuntimeError(label)


def runtime(service: str) -> dict[str, Any]:
    roles = {"api": ("policyops_app_runtime", "policyops_auth_runtime"),
             "worker": ("policyops_app_runtime", "policyops_worker_discovery"), "retail": ("retail_runtime",)}
    result = {}
    for role in roles[service]:
        with connect(role) as conn:
            current = conn.execute("SELECT current_user, session_user").fetchone()
            require(current == (role, role), "runtime identity mismatch")
            attributes = conn.execute("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles "
                                      "WHERE rolname=current_user").fetchone()
            require(attributes is not None and not any(attributes), "privileged runtime login")
            own = conn.execute("SELECT count(*) FROM pg_namespace WHERE nspowner=(SELECT oid FROM pg_roles "
                               "WHERE rolname=current_user) AND nspname NOT LIKE 'pg_%'").fetchone()
            require(own == (0,), "runtime owns a schema")
            query = "SELECT 1 FROM app.cases LIMIT 1" if role == "retail_runtime" else \
                "SELECT 1 FROM retail.case_states LIMIT 1"
            conn.rollback()
            try:
                conn.execute(query)
            except psycopg.errors.InsufficientPrivilege:
                conn.rollback()
            else:
                raise RuntimeError("cross-schema SELECT was not denied")
            result[role] = {"current_user": role, "session_user": role, "owns_schema": False,
                            "cross_schema_denied": True}
    return result


def migrations() -> dict[str, Any]:
    from policyops.persistence import migrate

    with connect("postgres") as conn:
        app = conn.execute("SELECT version_num FROM public.policyops_app_alembic_version").fetchone()
        retail = conn.execute("SELECT version_num FROM retail.alembic_version").fetchone()
        if app is None or retail is None:
            raise RuntimeError("migration version row missing")
        require(app == (migrate.head(),), "application revision mismatch")
        require(retail == ("r0002",), "retail revision mismatch")
        owners = conn.execute("SELECT nspname, pg_get_userbyid(nspowner) FROM pg_namespace "
                             "WHERE nspname IN ('app','identity','evaluation','checkpoints','retail') "
                             "ORDER BY nspname").fetchall()
        expected = {name: "policyops_app_migrator" for name in ("app", "identity", "evaluation", "checkpoints")}
        expected["retail"] = "retail_migrator"
        require(dict(owners) == expected, "schema owner mismatch")
        bad = conn.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE c.relkind IN ('r','p','S','v','m') AND ((n.nspname IN ('app','identity','evaluation','checkpoints') "
            "AND pg_get_userbyid(c.relowner)<>'policyops_app_migrator') OR (n.nspname='retail' "
            "AND pg_get_userbyid(c.relowner)<>'retail_migrator'))").fetchone()
        require(bad == (0,), "table owner mismatch")
        version_owner = conn.execute("SELECT pg_get_userbyid(relowner) FROM pg_class "
            "WHERE oid='public.policyops_app_alembic_version'::regclass").fetchone()
        require(version_owner == ("policyops_app_migrator",), "app version table owner mismatch")
        return {"app_revision": app[0], "retail_revision": retail[0], "schema_owners": dict(owners),
                "table_owners_match": True}


def no_egress() -> dict[str, bool]:
    # Test both external DNS and direct TCP, so a DNS failure cannot hide a route.
    try:
        socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        pass
    else:
        raise RuntimeError("internal-only service resolved an external host")
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=5):
            pass
    except OSError:
        pass
    else:
        raise RuntimeError("internal-only service connected to external address")
    return {"external_dns_denied": True, "external_tcp_denied": True}


def main() -> int:
    try:
        mode = sys.argv[1]
        result = migrations() if mode == "migrations" else no_egress() if mode == "no-egress" else runtime(mode)
        print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"error_type": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
