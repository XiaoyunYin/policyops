"""Read-only backup/restore comparisons and RLS probes; stdout contains only hashes/counts/booleans."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any
from uuid import UUID, uuid4

from runtime import connect, demo


TABLES = (
    "app.runs",
    "app.jobs",
    "app.action_proposals",
    "app.proposal_presentations",
    "app.customer_consents",
    "app.approval_decisions",
    "app.tool_executions",
    "retail.case_states",
    "retail.case_resources",
    "retail.operations",
)


class RecoveryError(RuntimeError):
    """Allowlisted probe failure, safe for the private command receipt."""


def require(value: bool, label: str) -> None:
    if not value:
        raise RecoveryError(label)


def snapshot() -> dict[str, Any]:
    result: dict[str, Any] = {}
    with connect("postgres") as conn:
        for table in TABLES:
            rows = conn.execute(f"SELECT row_to_json(t)::text FROM {table} t ORDER BY row_to_json(t)::text").fetchall()  # noqa: S608 - fixed allowlist
            raw = "\n".join(row[0] for row in rows).encode()
            result[table] = {"count": len(rows), "sha256": hashlib.sha256(raw).hexdigest()}
        # Catalog rows are independent of database OIDs: compare owners, grants, forced RLS and actual policies.
        catalog = conn.execute(
            "SELECT n.nspname,c.relname,pg_get_userbyid(c.relowner),c.relrowsecurity,"
            "c.relforcerowsecurity,ARRAY(SELECT a::text FROM unnest(c.relacl) a ORDER BY a::text) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname IN ('app','identity','evaluation','checkpoints','retail') AND c.relkind IN ('r','p','S') "
            "ORDER BY 1,2"
        ).fetchall()
        policies = conn.execute(
            "SELECT schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check "
            "FROM pg_policies WHERE schemaname IN ('app','identity','evaluation','checkpoints','retail') "
            "ORDER BY 1,2,3"
        ).fetchall()
        schemas = conn.execute(
            "SELECT nspname,pg_get_userbyid(nspowner),"
            "ARRAY(SELECT a::text FROM unnest(nspacl) a ORDER BY a::text) FROM pg_namespace "
            "WHERE nspname IN ('app','identity','evaluation','checkpoints','retail') ORDER BY 1"
        ).fetchall()
        columns = conn.execute(
            "SELECT n.nspname,c.relname,a.attname,"
            "ARRAY(SELECT v::text FROM unnest(a.attacl) v ORDER BY v::text) "
            "FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname IN ('app','identity','evaluation','checkpoints','retail') AND a.attnum>0 "
            "AND NOT a.attisdropped ORDER BY 1,2,3"
        ).fetchall()
        raw_catalog = json.dumps([catalog, policies, schemas, columns], default=str).encode()
        result["catalog_sha256"] = hashlib.sha256(raw_catalog).hexdigest()
    return result


def rls(service: str, case_id: UUID) -> dict[str, bool]:
    config = demo()
    role = "retail_runtime" if service == "retail" else "policyops_app_runtime"
    with connect(role) as conn:
        require(conn.execute("SELECT current_user,session_user").fetchone() == (role, role), "RLS identity mismatch")
        table = "retail.case_states" if service == "retail" else "app.cases"
        settings: tuple[tuple[str, str], ...]
        if service == "retail":
            settings = (("retail.tenant_id", config["workspace_id"]), ("retail.case_id", str(case_id)))
        else:
            settings = (("policyops.workspace_id", config["workspace_id"]),)
        require(conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), "unscoped RLS leaked")  # noqa: S608
        for name, value in settings:
            conn.execute("SELECT set_config(%s,%s,true)", (name, value))
        own = conn.execute(f"SELECT count(*) FROM {table}").fetchone()  # noqa: S608
        require(own is not None and own[0] >= 1, "own scoped row absent")
        if service == "retail":
            conn.execute("SELECT set_config('retail.case_id',%s,true)", (str(uuid4()),))
            require(conn.execute("SELECT count(*) FROM retail.case_states").fetchone() == (0,), "foreign case leaked")
            conn.execute("SELECT set_config('retail.case_id',%s,true)", (str(case_id),))
        conn.execute("SELECT set_config(%s,%s,true)", (settings[0][0], str(uuid4())))
        require(conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), "foreign RLS leaked")  # noqa: S608
        if service == "retail":
            require(
                conn.execute(
                    "SELECT has_table_privilege(current_user,'retail.operations','UPDATE'),"
                    "has_table_privilege(current_user,'retail.operations','DELETE')"
                ).fetchone()
                == (False, False),
                "receipt ledger mutable",
            )
    return {"unscoped_hidden": True, "own_scope_visible": True, "foreign_scope_hidden": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("snapshot", "worker", "retail"))
    parser.add_argument("--case-id", type=UUID)
    args = parser.parse_args()
    try:
        if args.mode != "snapshot":
            require(args.case_id is not None, "RLS probe requires an explicit scenario case")
        print(json.dumps(snapshot() if args.mode == "snapshot" else rls(args.mode, args.case_id)))
    except Exception as error:
        print(
            json.dumps(
                {
                    "error_type": type(error).__name__,
                    "detail": str(error) if isinstance(error, RecoveryError) else "details omitted",
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from None
