"""The execution ledger (T19): one durable, fenced execution per approval on `app.tool_executions`. Forward-only.

* Immutable binding: case, run, consent, tool, target (order or user), the stored `MutationRequest` (canonical
  JSON), its operation fingerprint and the authorization's `not_after`. A composite foreign key binds the execution
  to the exact approval decision (case, run, consent, proposal version and digest).
* One execution per approval (`UNIQUE (workspace_id, approval_id)`), and at most one unresolved execution
  (`pending`, `dispatched`, `unknown`) per case target: a second approval for the same order waits.
* A claim (`claim_id`, owner, lease), the dispatch and reconciliation counters, backoff (`next_attempt_at`), and the
  typed outcome. One NULL-safe CHECK ties state to outcome, resolver, receipt and dispatch; a trigger keeps the
  binding immutable, terminal rows final, the counters monotonic and the transitions to the T19 state machine.
* `policyops_worker_discovery` may read only scheduling metadata of executions (IDs, state, times).

Existing execution rows predate the binding and cannot be backfilled without guessing: the upgrade is refused while
the table holds any row. The downgrade is refused while it holds rows, even with `allow_data_loss`, because dropping
the binding would forget unresolved remote operations.

Revision ID: 0012
"""

from alembic import op
from sqlalchemy import text

from policyops.persistence.migrate import MigrationPreconditionError
from policyops.persistence.migration_guard import check_tables_empty, refuse_data_loss


revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

APP = "policyops_app_runtime"
DISCOVERY = "policyops_worker_discovery"
TABLE = "app.tool_executions"
SHA = "~ '^[0-9a-f]{64}$'"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"
MUTABLE = ("state", "attempts", "receipt", "updated_at", "version", "claim_id", "lease_owner", "lease_expires_at",
           "outcome", "resolved_by", "last_code", "dispatched_at", "next_attempt_at", "reconcile_attempts")
IMMUTABLE = ("id", "workspace_id", "operation_id", "proposal_id", "proposal_version", "action_digest", "approval_id",
             "argument_digest", "created_at", "case_id", "run_id", "consent_id", "tool", "target_kind", "target_id",
             "operation_sha256", "request", "authorization_not_after")
REMOTE_FAILED = "('upstream_rejected', 'effect_mismatch', 'money_unrepresentable', 'version_conflict')"
REMOTE_RESOLVERS = "('response', 'lookup', 'fence')"

SCHEMA = rf"""
ALTER TABLE app.approval_decisions ADD CONSTRAINT approval_decisions_execution_binding
    UNIQUE (workspace_id, id, case_id, run_id, consent_id, proposal_id, proposal_version, action_digest);

ALTER TABLE {TABLE}
    ADD COLUMN case_id uuid NOT NULL,
    ADD COLUMN run_id uuid NOT NULL,
    ADD COLUMN consent_id uuid NOT NULL,
    ADD COLUMN tool text NOT NULL CONSTRAINT tool_executions_tool_values CHECK (tool IN ('cancel_pending_order',
        'modify_pending_order_address', 'modify_pending_order_payment', 'modify_pending_order_items',
        'return_delivered_order_items', 'exchange_delivered_order_items', 'modify_user_address')),
    ADD COLUMN target_kind text NOT NULL
        CONSTRAINT tool_executions_target_kind CHECK (target_kind IN ('order', 'user')),
    ADD COLUMN target_id text NOT NULL
        CONSTRAINT tool_executions_target_id CHECK (char_length(target_id) BETWEEN 1 AND 64),
    ADD COLUMN operation_sha256 text NOT NULL
        CONSTRAINT tool_executions_operation_digest CHECK (operation_sha256 {SHA}),
    ADD COLUMN request jsonb NOT NULL CONSTRAINT tool_executions_request_size CHECK (pg_column_size(request) <= 16384),
    ADD COLUMN authorization_not_after timestamptz NOT NULL,
    ADD COLUMN claim_id uuid,
    ADD COLUMN lease_owner uuid,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN outcome text CONSTRAINT tool_executions_outcome_values CHECK (outcome IN ('committed',
        'upstream_rejected', 'effect_mismatch', 'money_unrepresentable', 'version_conflict', 'fenced',
        'precheck_refused', 'cancelled_before_dispatch')),
    ADD COLUMN resolved_by text CONSTRAINT tool_executions_resolved_by_values
        CHECK (resolved_by IN ('response', 'lookup', 'fence', 'precheck', 'cancel')),
    ADD COLUMN last_code text CONSTRAINT tool_executions_last_code_format CHECK (last_code {SLUG}),
    ADD COLUMN dispatched_at timestamptz,
    ADD COLUMN next_attempt_at timestamptz,
    ADD COLUMN reconcile_attempts integer NOT NULL DEFAULT 0
        CONSTRAINT tool_executions_reconcile_bounds CHECK (reconcile_attempts BETWEEN 0 AND 100),
    ADD CONSTRAINT tool_executions_one_per_approval UNIQUE (workspace_id, approval_id),
    ADD CONSTRAINT tool_executions_binding
        FOREIGN KEY (workspace_id, approval_id, case_id, run_id, consent_id, proposal_id, proposal_version,
        action_digest) REFERENCES app.approval_decisions (workspace_id, id, case_id, run_id, consent_id, proposal_id,
        proposal_version, action_digest),
    ADD CONSTRAINT tool_executions_lease_all_or_none CHECK ((claim_id IS NULL) = (lease_owner IS NULL)
        AND (claim_id IS NULL) = (lease_expires_at IS NULL)),
    -- One explicit, NULL-safe table of state/outcome/resolver combinations: COALESCE(..., false) makes an UNKNOWN
    -- comparison (a NULL outcome or resolver) a violation instead of a pass. Open rows carry no outcome; a terminal
    -- row carries exactly its outcome and resolver; a remote outcome needs a dispatch, a local refusal needs none.
    ADD CONSTRAINT tool_executions_outcome_rule CHECK ((receipt IS NOT NULL) = (state = 'succeeded') AND COALESCE(
        CASE
            WHEN state IN ('pending', 'dispatched', 'unknown') THEN outcome IS NULL AND resolved_by IS NULL
            WHEN state = 'succeeded' THEN outcome = 'committed' AND resolved_by IN {REMOTE_RESOLVERS} AND attempts > 0
            WHEN state = 'reconciled' THEN outcome = 'fenced' AND resolved_by IN {REMOTE_RESOLVERS} AND attempts > 0
            WHEN state = 'failed' THEN
                (outcome IN {REMOTE_FAILED} AND resolved_by IN {REMOTE_RESOLVERS} AND attempts > 0)
                OR (outcome = 'precheck_refused' AND resolved_by = 'precheck' AND attempts = 0)
                OR (outcome = 'cancelled_before_dispatch' AND resolved_by = 'cancel' AND attempts = 0)
            ELSE false
        END, false)),
    ADD CONSTRAINT tool_executions_terminal_rule CHECK (state IN ('pending', 'dispatched', 'unknown') OR
        (resolved_by IS NOT NULL AND claim_id IS NULL AND next_attempt_at IS NULL)),
    ADD CONSTRAINT tool_executions_unsent_rule CHECK (attempts > 0 OR state IN ('pending', 'failed')),
    ADD CONSTRAINT tool_executions_sent_rule CHECK ((attempts > 0) = (dispatched_at IS NOT NULL));
CREATE UNIQUE INDEX tool_executions_one_open_per_target ON {TABLE} (workspace_id, case_id, target_kind, target_id)
    WHERE state IN ('pending', 'dispatched', 'unknown');
CREATE INDEX tool_executions_due ON {TABLE} (next_attempt_at) WHERE state IN ('pending', 'dispatched', 'unknown');
CREATE INDEX tool_executions_case ON {TABLE} (workspace_id, case_id);

CREATE FUNCTION app.tool_executions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ({', '.join('NEW.' + c for c in IMMUTABLE)}) IS DISTINCT FROM ({', '.join('OLD.' + c for c in IMMUTABLE)}) THEN
        RAISE EXCEPTION 'tool execution binding is immutable';
    END IF;
    IF OLD.state IN ('succeeded', 'failed', 'reconciled') THEN
        RAISE EXCEPTION 'tool execution % is terminal', OLD.state;
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'tool execution version must advance by one';
    END IF;
    IF NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts + 1
            OR (NEW.attempts > OLD.attempts AND NEW.state <> 'dispatched')
            OR (NEW.state = 'dispatched' AND OLD.state <> 'dispatched' AND NEW.attempts = OLD.attempts)
            OR NEW.reconcile_attempts < OLD.reconcile_attempts THEN
        RAISE EXCEPTION 'tool execution counters only advance, one dispatch at a time';
    END IF;
    IF NOT ((OLD.state = 'pending' AND NEW.state IN ('pending', 'dispatched', 'failed'))
            OR (OLD.state IN ('dispatched', 'unknown')
                AND NEW.state IN ('dispatched', 'unknown', 'succeeded', 'failed', 'reconciled'))) THEN
        RAISE EXCEPTION 'tool execution transition % -> % is not allowed', OLD.state, NEW.state;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER tool_executions_guard BEFORE UPDATE ON {TABLE} FOR EACH ROW
    EXECUTE FUNCTION app.tool_executions_guard();
CREATE TRIGGER tool_executions_no_delete BEFORE DELETE ON {TABLE} FOR EACH ROW
    EXECUTE FUNCTION app.tool_executions_refuse_delete();

REVOKE ALL ON FUNCTION app.tool_executions_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.tool_executions_refuse_delete() FROM PUBLIC;
REVOKE UPDATE ON {TABLE} FROM {APP};
GRANT UPDATE ({', '.join(MUTABLE)}) ON {TABLE} TO {APP};
GRANT SELECT (id, workspace_id, state, next_attempt_at, lease_expires_at) ON {TABLE} TO {DISCOVERY};
CREATE POLICY tool_executions_worker_discovery ON {TABLE} FOR SELECT TO {DISCOVERY} USING (true);
"""

REFUSE_DELETE = """
CREATE FUNCTION app.tool_executions_refuse_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tool executions are retained';
END $$;
"""


def upgrade() -> None:
    connection = op.get_bind()
    if connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": DISCOVERY}).first() is None:
        raise MigrationPreconditionError(f"role {DISCOVERY} does not exist; run the bootstrap's provision_roles first")
    op.execute(f"ALTER TABLE {TABLE} NO FORCE ROW LEVEL SECURITY")
    rows = connection.execute(text(f"SELECT count(*) FROM {TABLE}")).scalar_one()  # noqa: S608 - fixed name
    op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY")
    if rows:
        raise MigrationPreconditionError(
            f"{rows} tool execution(s) predate the execution ledger and have no case, run, consent, request or "
            "fingerprint binding; they are not backfilled by guessing. Resolve and archive them before upgrading")
    op.execute(REFUSE_DELETE)
    op.execute(SCHEMA)


def downgrade() -> None:
    # The usual guard, then the same check unconditionally (allow_data_loss does not apply): an execution row may be
    # the only record of a remote operation whose outcome is still unknown, and the 0011 shape cannot hold it.
    refuse_data_loss((TABLE,))
    check_tables_empty(op.get_bind(), (TABLE,))
    op.execute(f"DROP POLICY tool_executions_worker_discovery ON {TABLE}; REVOKE ALL ON {TABLE} FROM {DISCOVERY}; "
               f"REVOKE UPDATE ON {TABLE} FROM {APP}; "
               f"GRANT UPDATE (state, attempts, receipt, updated_at, version) ON {TABLE} TO {APP}; "
               f"DROP TRIGGER tool_executions_no_delete ON {TABLE}; DROP TRIGGER tool_executions_guard ON {TABLE}; "
               "DROP FUNCTION app.tool_executions_guard(); DROP FUNCTION app.tool_executions_refuse_delete(); "
               "DROP INDEX app.tool_executions_case; DROP INDEX app.tool_executions_due; "
               "DROP INDEX app.tool_executions_one_open_per_target")
    op.execute(f"ALTER TABLE {TABLE} " + ", ".join(
        ["DROP CONSTRAINT tool_executions_binding", "DROP CONSTRAINT tool_executions_one_per_approval",
         "DROP CONSTRAINT tool_executions_unsent_rule"]
        + [f"DROP COLUMN {column}" for column in reversed(IMMUTABLE[9:] + MUTABLE[5:])]))
    op.execute("ALTER TABLE app.approval_decisions DROP CONSTRAINT approval_decisions_execution_binding")
