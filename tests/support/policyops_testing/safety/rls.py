"""Runtime-login and direct foreign RLS probes with identical owning controls."""

from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops_testing.safety.config import REPO, Config, digest, load_config
from policyops_testing.safety.environment import Env, study_case
from policyops_testing.safety.reports import MatrixRow, sha_file


FAMILIES = {
    "customer_authentications": ("app.customer_authentications", "run_id", None),
    "cases": ("app.cases", "id", "version"),
    "runs": ("app.runs", "id", "version"),
    "proposals": ("app.action_proposals", "id", "presented_at"),
    "consents": ("app.customer_consents", "id", None),
    "decisions": ("app.approval_decisions", "id", None),
    "executions": ("app.tool_executions", "id", "version"),
    "messages": ("app.case_messages", "id", None),
    "memberships": ("identity.memberships", "id", "version"),
}


def identities(env: Env) -> MatrixRow:
    observed = {}
    for role in (APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY):
        with transaction(env.db.engine(role)) as conn:
            row = conn.exec_driver_sql("SELECT session_user, current_user, rolcanlogin, rolsuper, rolbypassrls "
                                       "FROM pg_roles WHERE rolname = current_user").one()
            observed[role] = tuple(row)
    with env.db.superuser() as conn:
        tables = conn.execute("SELECT c.oid::regclass::text, relrowsecurity, relforcerowsecurity "
                             "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                             "WHERE n.nspname IN ('identity','app','checkpoints') AND relkind = 'r'").fetchall()
    passed = all(value == (role, role, True, False, False) for role, value in observed.items()) \
        and bool(tables) and all(enabled and forced for _, enabled, forced in tables)
    marker = digest(tables)
    return MatrixRow(cell_id="runtime/identities", relationship="database_login", expected="restricted_forced_rls",
        observed="restricted_forced_rls" if passed else "incorrect", layer="database", identities=observed,
        database_evidence={"forced_tables": tables}, before_sha256=marker, after_sha256=marker, passed=passed)


def foreign_read(env: Env, table: str, key: str, value: UUID, workspace: UUID) -> int:
    if (table, key) not in {(t, k) for t, k, _ in FAMILIES.values()}:
        raise ValueError("not a frozen matrix resource")
    with workspace_transaction(env.app, workspace) as conn:
        return len(conn.execute(text(f"SELECT {key} FROM {table} WHERE {key} = :id"),  # noqa: S608
                                {"id": value}).fetchall())


def assert_foreign_hidden(count: int) -> None:
    if count != 0:
        raise ValueError("foreign row is visible")


def grants(env: Env, config: Config) -> MatrixRow:
    observed: dict[str, dict[str, dict[str, list[str]]]] = {}
    problems = []
    roles = (APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY)
    retail_grants = {}
    with env.db.superuser() as conn:  # catalog observation only, never the actor of a denial
        tables = conn.execute("SELECT schemaname || '.' || tablename FROM pg_tables "
                             "WHERE schemaname IN ('identity','app','evaluation','checkpoints','public') "
                             "ORDER BY 1").fetchall()
        for role in roles:
            observed[role] = {}
            for (table,) in tables:
                columns = [r[0] for r in conn.execute("SELECT attname FROM pg_attribute WHERE attrelid = "
                    "%s::regclass AND attnum > 0 AND NOT attisdropped", (table,))]
                table_grants = sorted(p for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE",
                    "REFERENCES", "TRIGGER") if conn.execute("SELECT has_table_privilege(%s,%s,%s)",
                                                             (role, table, p)).fetchone()[0])
                updates = sorted(c for c in columns if conn.execute(
                    "SELECT has_column_privilege(%s,%s,%s,'UPDATE')", (role, table, c)).fetchone()[0])
                selects = [] if "SELECT" in table_grants else sorted(c for c in columns if conn.execute(
                    "SELECT has_column_privilege(%s,%s,%s,'SELECT')", (role, table, c)).fetchone()[0])
                actual = {"table": table_grants, "update_columns": updates, "select_columns": selects}
                observed[role][table] = actual
                expected = config.role_grants.get(role, {}).get(table)
                expected_raw = {"table": [], "update_columns": [], "select_columns": []} if expected is None \
                    else expected.model_dump(mode="json")
                if actual != expected_raw:
                    problems.append([role, table])
            usage, readable = conn.execute("SELECT has_schema_privilege(%s,'retail','USAGE'), "
                "has_table_privilege(%s,'retail.case_states','SELECT')", (role, role)).fetchone()
            retail_grants[role] = [usage, readable]
            if usage or readable:
                problems.append([role, "retail"])
    passed = not problems and set(config.role_grants) == set(roles) and config.grants_source_sha256 == sha_file(
        REPO / "tests/integration/test_app_privileges.py")
    marker = digest(observed)
    return MatrixRow(cell_id="runtime/grants", relationship="runtime_catalog_permissions",
        expected="exact_table_and_column_grants", observed="exact_table_and_column_grants" if passed else "incorrect",
        layer="database_catalog", database_evidence={"observed": observed, "mismatches": problems,
                                                     "retail_access": retail_grants},
        before_sha256=marker, after_sha256=marker, passed=passed)


def insert_sql(table: str, record: dict[str, Any]) -> tuple[str, tuple[Any, ...]]:
    allowed = {t for t, _, _ in FAMILIES.values()} | {"app.proposal_presentations"}
    if table not in allowed or any(not name.replace("_", "").isalnum() for name in record):
        raise ValueError("not a frozen probe table/column")
    columns = ", ".join(f'"{name}"' for name in record)
    placeholders = ", ".join("%s" for _ in record)
    return (f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",  # noqa: S608
            tuple(Jsonb(v) if isinstance(v, (dict, list)) else v for v in record.values()))


def fresh_insert_record(env: Env, family: str, original: dict[str, Any]) -> dict[str, Any]:
    """Fresh target keys and valid parents, without deleting any immutable fixture row.

    Only parent setup uses the superuser. The target insert is always performed by
    the actual runtime login, with the identical payload in the foreign/owner contexts.
    """
    record = deepcopy(original)
    record["id" if family != "customer_authentications" else "run_id"] = uuid4()
    with env.db.superuser() as conn:
        def copy_row(table: str, key: str, value: Any) -> dict[str, Any]:
            cursor = conn.execute(f"SELECT * FROM {table} WHERE {key} = %s", (value,))  # noqa: S608
            return dict(zip((c.name for c in cursor.description), cursor.fetchone(), strict=True))

        if family == "customer_authentications":
            # A terminal synthetic run avoids the one-active-workbench-run constraint;
            # authentication's FKs require the same workspace/case, not an active run.
            run = copy_row("app.runs", "id", original["run_id"])
            run.update(id=record["run_id"], state="cancelled", active_remaining_us=0,
                       active_started_at=None, deadline_at=None)
            conn.execute(*insert_sql("app.runs", run))
        elif family == "messages":
            record["sequence"] = conn.execute(
                "SELECT coalesce(max(sequence), 0) + 1 FROM app.case_messages "
                "WHERE workspace_id = %s AND case_id = %s", (record["workspace_id"], record["case_id"])
            ).fetchone()[0]
        elif family in ("consents", "decisions"):
            # Both tables have one-per-proposal uniqueness. Clone a coherent proposal
            # and presentation; a decision additionally needs a fresh consent parent.
            proposal = copy_row("app.action_proposals", "proposal_id", original["proposal_id"])
            new_proposal = uuid4()
            proposal.update(id=uuid4(), proposal_id=new_proposal)
            proposal["body"]["proposal_id"] = str(new_proposal)
            conn.execute(*insert_sql("app.action_proposals", proposal))
            presentation = copy_row("app.proposal_presentations", "proposal_id", original["proposal_id"])
            presentation["proposal_id"] = new_proposal
            conn.execute(*insert_sql("app.proposal_presentations", presentation))
            record["proposal_id"] = new_proposal
            if family == "decisions":
                consent = copy_row("app.customer_consents", "id", original["consent_id"])
                consent.update(id=uuid4(), proposal_id=new_proposal)
                conn.execute(*insert_sql("app.customer_consents", consent))
                record["consent_id"] = consent["id"]
        else:
            raise ValueError("not an insert probe family")
    return record


def probe(env: Env, family: str, foreign: UUID) -> MatrixRow:
    table, key, update_column = FAMILIES[family]
    # Each probe owns its fresh fixture. Authority parents exist before direct probes.
    refs = env.approve()
    if family == "executions":
        env.reserve(refs)
    scope_key = "case_id" if family == "messages" else "id" if family in (
        "cases", "runs", "memberships") else "run_id"
    scope_value = env.run.case_id if family == "cases" else env.membership if family == "memberships" \
        else env.run.case_id if family == "messages" else env.run.run_id
    with env.db.superuser() as conn:
        raw = conn.execute(f"SELECT * FROM {table} WHERE {scope_key} = %s LIMIT 1",  # noqa: S608
                           (scope_value,))
        names = [c.name for c in raw.description]
        values = list(raw.fetchone())
    record = dict(zip(names, values, strict=True))
    value = record[key]
    hidden = foreign_read(env, table, key, value, foreign)
    visible = foreign_read(env, table, key, value, env.run.workspace_id)
    evidence: dict[str, Any] = {"select_foreign_rows": hidden, "select_owner_rows": visible,
                              "table": table, "actor": APP_RUNTIME}
    passed = hidden == 0 and visible == 1
    if update_column is not None:
        assignment = f"{update_column} + 1" if update_column == "version" else update_column
        statement = text(f"UPDATE {table} SET {update_column} = {assignment} WHERE {key} = :id")  # noqa: S608
        with workspace_transaction(env.app, foreign) as conn:
            denied = conn.execute(statement, {"id": value}).rowcount
        with workspace_transaction(env.app, env.run.workspace_id) as conn:
            owner = conn.execute(statement, {"id": value}).rowcount
        evidence.update(write="update", foreign_rows=denied, owner_rows=owner)
        passed = passed and denied == 0 and owner == 1
    else:
        fresh = fresh_insert_record(env, family, record)
        statement_sql, params = insert_sql(table, fresh)
        sqlstate = None
        try:
            with workspace_transaction(env.app, foreign) as app:
                app.exec_driver_sql(statement_sql, params)
        except DBAPIError as exc:
            sqlstate = getattr(exc.orig, "sqlstate", None)
        with workspace_transaction(env.app, env.run.workspace_id) as app:
            owner = app.exec_driver_sql(statement_sql, params).rowcount
        original_rows = foreign_read(env, table, key, value, env.run.workspace_id)
        fresh_owner = foreign_read(env, table, key, fresh[key], env.run.workspace_id)
        fresh_foreign = foreign_read(env, table, key, fresh[key], foreign)
        evidence.update(write="insert", foreign_sqlstate=sqlstate, owner_rows=owner,
                        identical_payload=True, fresh_primary_key=True, original_owner_rows=original_rows,
                        inserted_owner_rows=fresh_owner, inserted_foreign_rows=fresh_foreign)
        passed = passed and sqlstate == "42501" and owner == 1 and original_rows == fresh_owner == 1 \
            and fresh_foreign == 0
    marker = digest(evidence)
    return MatrixRow(cell_id=f"rls/{family}", relationship="foreign_workspace", expected="hidden_and_write_refused",
        observed="hidden_and_write_refused" if passed else "incorrect", layer="APP_RUNTIME_RLS",
        database_evidence=evidence, before_sha256=marker, after_sha256=marker, passed=passed)


def run(base: Env, rows: list[MatrixRow] | None = None, config: Config | None = None) -> list[MatrixRow]:
    rows = [] if rows is None else rows
    rows.append(identities(base))
    rows.append(grants(base, config or load_config()))
    for family in FAMILIES:
        env = study_case(base)
        # Foreign workspace need not have data, but must be an existing workspace for a valid context.
        from policyops_testing.safety.environment import make_env
        foreign = make_env((env.service, env.origin), env.db)
        try:
            rows.append(probe(env, family, foreign.run.workspace_id))
        except Exception as exc:
            marker = digest({"family": family})
            rows.append(MatrixRow(cell_id=f"rls/{family}", relationship="foreign_workspace",
                expected="hidden_and_write_refused", observed="aborted", layer="APP_RUNTIME_RLS",
                before_sha256=marker, after_sha256=marker, passed=False, error=type(exc).__name__))
    return rows
