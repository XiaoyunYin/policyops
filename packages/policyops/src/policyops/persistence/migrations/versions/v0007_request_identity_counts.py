"""Request identity, counting and contract blocks for the usage ledger (T11). Additive and forward-only.

Usage attempts (`app` and `evaluation`):
- `intent_version`: existing rows become version 1. They keep their v1 intent digest and have no request
  fingerprint. New rows must be version 2, which a `BEFORE INSERT` trigger enforces on every role path, raw SQL
  included.
- `request_sha256`: the fingerprint of the exact prepared provider request, required for v2.
- `count_state`, `counted_input_tokens`, `count_source`: at most one supported token count per attempt.
  - The count moves `none → claimed → admitted | rejected | failed`.
  - A v2 attempt can only have been dispatched from `admitted`.
- `contract_block`: a reason code set when the provider's response broke the request contract, or its pricing
  evidence was missing.
- `diagnostic`: small, allowlisted token counts and codes kept for an attempt left unresolved by such evidence.

Budget scopes (`app` and `evaluation`):
- `cap_counts` / `counts_used`: a finite count resource that is never returned (backfilled `cap_counts = cap_calls`).
- `contract_block`: sticky; it stops new holds and dispatches in that scope.

Neither the runtime roles nor any API can update `intent_version`, `request_sha256` or `cap_counts`.

The downgrade is refused whenever version 2, count or block data exists, **even with `allow_data_loss`**. Removing
attempts while keeping the scopes' spent amounts and call totals would leave balances that no longer match their
records, so recovery from such a state is a restore from a consistent backup. An empty downgrade keeps every
version 1 row and restores each table's exact previous FORCE flag.

Revision ID: 0007
"""

from alembic import op
from sqlalchemy import Connection

from policyops.persistence.migration_guard import DataLossRefused


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

APP, EVAL = "policyops_app_runtime", "policyops_eval_runtime"
SHA = "~ '^[0-9a-f]{64}$'"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"
ATTEMPT_TABLES = ("app.usage_attempts", "evaluation.usage_attempts")
SCOPE_TABLES = ("app.budget_scopes", "evaluation.budget_scopes")
ATTEMPT_UPDATE = "count_state, counted_input_tokens, count_source, contract_block, diagnostic"
SCOPE_UPDATE = "counts_used, contract_block"


def attempt_sql(table: str, prefix: str, schema: str) -> str:
    return f"""
ALTER TABLE {table}
    ADD COLUMN intent_version smallint NOT NULL DEFAULT 1,
    ADD COLUMN request_sha256 text CONSTRAINT {prefix}_request_digest CHECK (request_sha256 {SHA}),
    ADD COLUMN count_state text NOT NULL DEFAULT 'none' CONSTRAINT {prefix}_count_state_values
        CHECK (count_state IN ('none', 'claimed', 'admitted', 'rejected', 'failed')),
    ADD COLUMN counted_input_tokens integer CONSTRAINT {prefix}_counted_nonnegative CHECK (counted_input_tokens >= 0),
    ADD COLUMN count_source text CONSTRAINT {prefix}_count_source_format CHECK (count_source {SLUG}),
    ADD COLUMN contract_block text CONSTRAINT {prefix}_contract_block_format CHECK (contract_block {SLUG}),
    ADD COLUMN diagnostic jsonb CONSTRAINT {prefix}_diagnostic_size CHECK (octet_length(diagnostic::text) <= 2048),
    ADD CONSTRAINT {prefix}_intent_version_values CHECK (intent_version IN (1, 2)),
    ADD CONSTRAINT {prefix}_request_by_version CHECK ((intent_version = 2) = (request_sha256 IS NOT NULL)),
    ADD CONSTRAINT {prefix}_count_only_v2 CHECK (intent_version = 2 OR count_state = 'none'),
    ADD CONSTRAINT {prefix}_counted_has_tokens CHECK ((count_state IN ('admitted', 'rejected'))
        = (counted_input_tokens IS NOT NULL AND count_source IS NOT NULL)),
    ADD CONSTRAINT {prefix}_dispatched_was_admitted CHECK (intent_version = 1 OR state IN ('reserved', 'released')
        OR count_state = 'admitted');
ALTER TABLE {table} ALTER COLUMN intent_version SET DEFAULT 2;
CREATE FUNCTION {schema}.refuse_legacy_usage_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.intent_version IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'new usage attempts must use intent version 2' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION {schema}.refuse_legacy_usage_attempt() FROM PUBLIC;
CREATE TRIGGER {prefix}_v2_only BEFORE INSERT ON {table} FOR EACH ROW
    EXECUTE FUNCTION {schema}.refuse_legacy_usage_attempt();
"""


def scope_sql(table: str, prefix: str) -> str:
    return f"""
ALTER TABLE {table}
    ADD COLUMN cap_counts integer,
    ADD COLUMN counts_used integer NOT NULL DEFAULT 0,
    ADD COLUMN contract_block text CONSTRAINT {prefix}_contract_block_format CHECK (contract_block {SLUG});
"""


def scope_constraints(table: str, prefix: str) -> str:
    return f"""
ALTER TABLE {table}
    ALTER COLUMN cap_counts SET NOT NULL,
    ADD CONSTRAINT {prefix}_cap_counts_positive CHECK (cap_counts >= 1),
    ADD CONSTRAINT {prefix}_counts_within_cap CHECK (counts_used >= 0 AND counts_used <= cap_counts);
"""


def _forced(connection: Connection, table: str) -> bool:
    return bool(connection.exec_driver_sql(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid = %s::regclass", (table,)).scalar())


def _with_rows_visible(connection: Connection, table: str, statement: str) -> object:
    """Run one statement as the owner with FORCE lifted (the migrator sees no tenant rows otherwise), then restore
    exactly the previous FORCE state. `table` and `statement` are fixed text from this revision."""
    forced = _forced(connection, table)
    if forced:
        connection.exec_driver_sql(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    result = connection.exec_driver_sql(statement)
    value = result.scalar() if result.returns_rows else None  # an UPDATE returns no rows
    if forced:
        connection.exec_driver_sql(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    return value


def upgrade() -> None:
    connection = op.get_bind()
    op.execute(attempt_sql("app.usage_attempts", "usage_attempts", "app"))
    op.execute(attempt_sql("evaluation.usage_attempts", "eval_usage_attempts", "evaluation"))
    op.execute(scope_sql("app.budget_scopes", "budget_scopes"))
    op.execute(scope_sql("evaluation.budget_scopes", "eval_budget_scopes"))
    for table in SCOPE_TABLES:
        _with_rows_visible(connection, table, f"UPDATE {table} SET cap_counts = cap_calls")  # noqa: S608 (fixed)
    op.execute(scope_constraints("app.budget_scopes", "budget_scopes"))
    op.execute(scope_constraints("evaluation.budget_scopes", "eval_budget_scopes"))
    op.execute(f"GRANT UPDATE ({ATTEMPT_UPDATE}) ON app.usage_attempts TO {APP}; "
               f"GRANT UPDATE ({SCOPE_UPDATE}) ON app.budget_scopes TO {APP}; "
               f"GRANT UPDATE ({ATTEMPT_UPDATE}) ON evaluation.usage_attempts TO {EVAL}; "
               f"GRANT UPDATE ({SCOPE_UPDATE}) ON evaluation.budget_scopes TO {EVAL};")


POPULATED = {
    "app.usage_attempts": "SELECT EXISTS (SELECT 1 FROM app.usage_attempts WHERE intent_version = 2 "
                          "OR count_state <> 'none' OR contract_block IS NOT NULL OR diagnostic IS NOT NULL)",
    "evaluation.usage_attempts": "SELECT EXISTS (SELECT 1 FROM evaluation.usage_attempts WHERE intent_version = 2 "
                                 "OR count_state <> 'none' OR contract_block IS NOT NULL OR diagnostic IS NOT NULL)",
    "app.budget_scopes": "SELECT EXISTS (SELECT 1 FROM app.budget_scopes WHERE counts_used > 0 "
                         "OR contract_block IS NOT NULL)",
    "evaluation.budget_scopes": "SELECT EXISTS (SELECT 1 FROM evaluation.budget_scopes WHERE counts_used > 0 "
                                "OR contract_block IS NOT NULL)",
}


def downgrade() -> None:
    # Refused whenever 0007 data exists, whatever allow_data_loss says. Unlike refuse_data_loss, there is no opt-out:
    # dropping this data would leave scope totals that no longer match their attempts. A refusal raises before
    # anything is dropped, so the transaction rolls back.
    connection = op.get_bind()
    for table, query in POPULATED.items():
        if _with_rows_visible(connection, table, query):
            raise DataLossRefused(f"{table} holds request-identity, count or contract-block data; a 0007 downgrade "
                                  "is not supported once it exists (restore a consistent backup instead)")
    for table, prefix, schema in (("app.usage_attempts", "usage_attempts", "app"),
                                  ("evaluation.usage_attempts", "eval_usage_attempts", "evaluation")):
        op.execute(f"DROP TRIGGER {prefix}_v2_only ON {table}; DROP FUNCTION {schema}.refuse_legacy_usage_attempt(); "
                   f"ALTER TABLE {table} DROP CONSTRAINT {prefix}_dispatched_was_admitted, "
                   f"DROP CONSTRAINT {prefix}_counted_has_tokens, DROP CONSTRAINT {prefix}_count_only_v2, "
                   f"DROP CONSTRAINT {prefix}_request_by_version, DROP CONSTRAINT {prefix}_intent_version_values, "
                   "DROP COLUMN diagnostic, DROP COLUMN contract_block, DROP COLUMN count_source, "
                   "DROP COLUMN counted_input_tokens, DROP COLUMN count_state, DROP COLUMN request_sha256, "
                   "DROP COLUMN intent_version")
    for table, prefix in (("app.budget_scopes", "budget_scopes"), ("evaluation.budget_scopes", "eval_budget_scopes")):
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT {prefix}_counts_within_cap, "
                   f"DROP CONSTRAINT {prefix}_cap_counts_positive, DROP COLUMN contract_block, "
                   "DROP COLUMN counts_used, DROP COLUMN cap_counts")
