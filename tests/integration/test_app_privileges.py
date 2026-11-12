"""The complete role/privilege matrix of a migrated application database, checked on the server itself.

The expectation below is the specification (written out, not derived from the migration code): any extra grant,
missing grant, PUBLIC privilege, default privilege, unforced RLS table or retail access fails.
"""

from __future__ import annotations

from typing import Any

import pytest

from policyops.persistence.roles import (
    ALL_ROLES,
    APP_MIGRATOR,
    APP_RUNTIME,
    AUTH_RUNTIME,
    EVAL_RUNTIME,
    RUNTIME_ROLES,
    WORKER_DISCOVERY,
)
from policyops_testing.app_database import AppDatabase


pytestmark = pytest.mark.postgres

TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
SI = {"SELECT", "INSERT"}
SCOPE_COUNTERS = {"spent_usd", "held_usd", "calls_consumed", "calls_held", "overrun", "updated_at", "version",
                  "counts_used", "contract_block"}  # the last two from 0007
ATTEMPT_SETTLEMENT = {"state", "provider_request_id", "usage", "usage_sha256", "actual_tier", "actual_usd", "overrun",
                      "updated_at", "version",
                      "count_state", "counted_input_tokens", "count_source", "contract_block", "diagnostic"}  # 0007

# role -> table -> (table-level privileges, columns updatable through column grants)
EXPECTED: dict[str, dict[str, tuple[set[str], set[str]]]] = {
    APP_RUNTIME: {
        "identity.workspaces": ({"SELECT"}, set()),
        "identity.memberships": (SI, {"revoked_at", "version"}),
        "app.cases": (SI, {"status", "updated_at", "version"}),
        "app.case_messages": (SI, set()),
        "app.documents": (SI, set()),
        "app.document_versions": (SI, {"status", "effective_to"}),
        "app.runs": (SI, {"state", "model_calls", "tool_calls", "updated_at", "version", "generation",
                          "event_highwater"}),
        "app.run_events": (SI, set()),
        "app.action_proposals": (SI, {"status", "presented_at"}),
        "app.proposal_presentations": (SI, set()),
        "app.customer_consents": (SI, set()),
        "app.approval_decisions": (SI, set()),
        "app.tool_executions": (SI, {"state", "attempts", "receipt", "updated_at", "version", "claim_id", "lease_owner",
                                     "lease_expires_at", "outcome", "resolved_by", "last_code", "dispatched_at",
                                     "next_attempt_at", "reconcile_attempts"}),
        "app.jobs": (SI, {"state", "lease_owner", "lease_expires_at", "attempts", "available_at", "updated_at",
                          "version", "claim_id", "last_error_code"}),
        "app.outbox_events": (SI, {"delivered_at"}),
        "app.audit_events": (SI, set()),
        "app.index_generations": (SI, {"status", "ready_at"}),
        "app.chunks": (SI, set()),
        "app.retrieval_traces": (SI, set()),
        "app.citations": (SI, set()),
        "app.customer_authentications": (SI, set()),  # 0008: first write wins, never rewritten at runtime
        "app.usage_reservations": (SI, {"actual_usd", "state", "updated_at", "version"}),
        "app.usage_events": (SI, set()),
        "app.request_idempotency": (SI, set()),  # append-only successful-response ledger (0004)
        # The T10 usage ledger (0006): counters and settlement are updatable; caps, bindings and intent are not.
        "app.budget_scopes": (SI, SCOPE_COUNTERS),
        "app.usage_attempts": (SI, ATTEMPT_SETTLEMENT),
        # The T12 embedding foundation (0009): only job state, batch advancement and lease columns are updatable;
        # inputs, plans, evidence and cached vectors are immutable at runtime.
        "app.embedding_jobs": (SI, {"state", "version", "updated_at"}),
        "app.embedding_job_inputs": (SI, set()),
        "app.embedding_batches": (SI, {"state", "lease_owner", "lease_until", "fence", "updated_at"}),
        "app.embedding_attempt_evidence": (SI, set()),
        "app.embedding_cache": (SI, set()),
        # T12 ingestion (0010): only the corpus pointer moves; generation membership is immutable at runtime.
        "app.corpora": (SI, {"active_generation_id", "version", "updated_at"}),
        "app.generation_documents": (SI, set()),
        # T13 retrieval step intents (0011): append-only request identities.
        "app.retrieval_steps": (SI, set()),
    },
    AUTH_RUNTIME: {
        "identity.workspaces": (SI, set()),
        "identity.principals": (SI, set()),
        "identity.memberships": (SI, {"revoked_at", "version"}),
        "identity.sessions": (SI, {"revoked_at", "workspace_id", "last_seen_at"}),
        "identity.login_requests": (SI, {"consumed_at"}),
    },
    EVAL_RUNTIME: {
        "evaluation.evaluation_runs": (SI, {"status", "started_at", "finished_at", "total_cost_usd", "version"}),
        "evaluation.evaluation_trials": (SI, set()),
        "evaluation.budget_scopes": (SI, SCOPE_COUNTERS),
        "evaluation.usage_attempts": (SI, ATTEMPT_SETTLEMENT),
    },
    WORKER_DISCOVERY: {},  # no table-level privilege at all; column SELECT only (below)
}
# role -> table -> columns readable through column-level SELECT grants without a table-level SELECT (T09).
COLUMN_SELECT: dict[str, dict[str, set[str]]] = {
    WORKER_DISCOVERY: {
        "app.jobs": {"id", "workspace_id", "state", "available_at", "lease_expires_at", "deadline_at"},
        "app.outbox_events": {"id", "workspace_id", "topic", "created_at", "delivered_at"},
        "app.tool_executions": {"id", "workspace_id", "state", "next_attempt_at", "lease_expires_at"},  # T19
    },
}
SCHEMA_USAGE = {APP_RUNTIME: {"identity", "app", "checkpoints", "public"}, AUTH_RUNTIME: {"identity", "public"},
                EVAL_RUNTIME: {"evaluation", "public"}, WORKER_DISCOVERY: {"app", "public"}}
SCHEMAS = ("identity", "app", "evaluation", "checkpoints", "public")


def _rows(database: AppDatabase, query: str, params: Any = None) -> list[tuple[Any, ...]]:
    with database.superuser() as conn:
        return list(conn.execute(query, params).fetchall())


def _all_tables(database: AppDatabase) -> list[str]:
    return [row[0] for row in _rows(database, "SELECT schemaname || '.' || tablename FROM pg_tables "
                                    "WHERE schemaname = ANY(%s) ORDER BY 1", (list(SCHEMAS),))]


def test_table_and_column_privileges_match_the_matrix_exactly(shared_db: AppDatabase) -> None:
    tables = _all_tables(shared_db)
    assert "public.policyops_app_alembic_version" in tables
    problems = []
    with shared_db.superuser() as conn:  # one catalog connection for the whole matrix
        def check(query: str, params: tuple[str, ...]) -> bool:
            row = conn.execute(query, params).fetchone()
            return bool(row and row[0])

        for table in tables:
            columns = [row[0] for row in conn.execute("SELECT attname FROM pg_attribute WHERE attrelid = "
                                                      "%s::regclass AND attnum > 0 AND NOT attisdropped", (table,))]
            for role in RUNTIME_ROLES:
                granted = {privilege for privilege in TABLE_PRIVILEGES
                           if check("SELECT has_table_privilege(%s, %s, %s)", (role, table, privilege))}
                updatable = {column for column in columns
                             if check("SELECT has_column_privilege(%s, %s, %s, 'UPDATE')", (role, table, column))}
                selectable = set() if "SELECT" in granted else {
                    column for column in columns
                    if check("SELECT has_column_privilege(%s, %s, %s, 'SELECT')", (role, table, column))}
                expected_table, expected_columns = EXPECTED[role].get(table, (set(), set()))
                expected_select = COLUMN_SELECT.get(role, {}).get(table, set())
                if (granted, updatable, selectable) != (expected_table, expected_columns, expected_select):
                    problems.append((role, table, sorted(granted), sorted(updatable), sorted(selectable)))
    assert problems == []


def test_no_public_or_default_privileges_and_owner_is_the_migrator(shared_db: AppDatabase) -> None:
    public = _rows(shared_db, "SELECT table_schema, table_name, privilege_type FROM information_schema.table_privileges"
                   " WHERE grantee = 'PUBLIC' AND table_schema = ANY(%s)", (list(SCHEMAS),))
    assert public == []
    assert _rows(shared_db, "SELECT count(*) FROM pg_default_acl") == [(0,)]
    owners = _rows(shared_db, "SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = ANY(%s)",
                   (list(SCHEMAS),))
    assert owners == [(APP_MIGRATOR,)]
    functions = _rows(shared_db, "SELECT p.oid::regprocedure::text, p.proacl::text FROM pg_proc p "
                      "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'app' ORDER BY 1")
    acl = dict(functions)
    guards = {"app.guard_generation_member()", "app.guard_generation_insert()", "app.guard_generation_transition()",
              "app.check_generation_publication()", "app.guard_citation_insert()",  # 0010 trigger functions
              "app.tool_executions_guard()", "app.tool_executions_refuse_delete()"}  # 0012
    assert set(acl) == {"app.current_workspace()", "app.guard_action_proposal_update()",
                        "app.refuse_legacy_usage_attempt()"} | guards
    # Owner plus the app runtime only; a PUBLIC entry would appear as "=X/...".
    assert acl["app.current_workspace()"] == f"{{{APP_MIGRATOR}=X/{APP_MIGRATOR},{APP_RUNTIME}=X/{APP_MIGRATOR}}}"
    assert acl["app.guard_action_proposal_update()"] == f"{{{APP_MIGRATOR}=X/{APP_MIGRATOR}}}"
    assert acl["app.refuse_legacy_usage_attempt()"] == f"{{{APP_MIGRATOR}=X/{APP_MIGRATOR}}}"
    for guard in guards:
        assert acl[guard] == f"{{{APP_MIGRATOR}=X/{APP_MIGRATOR}}}", guard


def test_schema_usage_and_no_runtime_create_anywhere(shared_db: AppDatabase) -> None:
    for role in RUNTIME_ROLES:
        for schema in SCHEMAS:
            usage, create = _rows(shared_db, "SELECT has_schema_privilege(%s, %s, 'USAGE'), "
                                  "has_schema_privilege(%s, %s, 'CREATE')", (role, schema, role, schema))[0]
            assert usage is (schema in SCHEMA_USAGE[role]), (role, schema)
            assert create is False, (role, schema)
        assert _rows(shared_db, "SELECT has_database_privilege(%s, current_database(), 'CREATE'), "
                     "has_database_privilege(%s, current_database(), 'TEMP')", (role, role)) == [(False, False)]
    for role in ALL_ROLES:
        connect = _rows(shared_db, "SELECT has_database_privilege(%s, current_database(), 'CONNECT')", (role,))
        assert connect == [(True,)], role


def test_every_application_table_has_forced_row_level_security(shared_db: AppDatabase) -> None:
    rows = _rows(shared_db, "SELECT c.oid::regclass::text, relrowsecurity, relforcerowsecurity FROM pg_class c "
                 "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN ('identity', 'app') "
                 "AND relkind = 'r'")
    assert rows and all(enabled and forced for _, enabled, forced in rows), [r for r in rows if not (r[1] and r[2])]
    # Evaluation tables are not tenant data; isolation there is by schema/role (the app runtime has no access).
    assert _rows(shared_db, "SELECT bool_or(relrowsecurity) FROM pg_class c JOIN pg_namespace n "
                 "ON n.oid = c.relnamespace WHERE n.nspname = 'evaluation' AND relkind = 'r'") == [(False,)]


def test_application_roles_cannot_reach_a_retail_schema(shared_db: AppDatabase) -> None:
    # A stand-in for the T16-owned schema; created and dropped by the test superuser inside one transaction.
    with shared_db.server.connect("postgres", shared_db.name) as conn:
        conn.execute("CREATE SCHEMA retail")
        conn.execute("CREATE TABLE retail.snapshots (id int)")
        for role in ALL_ROLES:
            usage = conn.execute("SELECT has_schema_privilege(%s, 'retail', 'USAGE'), "
                                 "has_table_privilege(%s, 'retail.snapshots', 'SELECT')", (role, role)).fetchone()
            assert usage == (False, False), role
        conn.rollback()
    for role in RUNTIME_ROLES:
        with shared_db.server.connect(role, shared_db.name) as conn:
            for statement in ("CREATE SCHEMA retail", "CREATE TABLE app.extra (id int)",
                              "CREATE TABLE public.extra (id int)", "CREATE TABLE checkpoints.extra (id int)"):
                with pytest.raises(Exception, match="permission denied"):
                    conn.execute(statement)
                conn.rollback()


def test_no_floating_point_or_rounding_numeric_columns(shared_db: AppDatabase) -> None:
    columns = _rows(shared_db, "SELECT table_schema, table_name, column_name, data_type, numeric_precision, "
                    "numeric_scale FROM information_schema.columns WHERE table_schema = ANY(%s)", (list(SCHEMAS),))
    assert not [c for c in columns if c[3] in ("real", "double precision", "money")]
    numerics = [c for c in columns if c[3] == "numeric"]
    assert numerics and all(c[4] is None and c[5] is None for c in numerics), numerics  # unconstrained + CHECKs
