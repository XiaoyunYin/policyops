"""Retrieval step intents (T13): the durable, immutable request identity of one retrieval step. Forward-only.

* `app.retrieval_steps`: one row per `(workspace, run, step)`, committed before any provider work for a new step.
  It holds the step's deterministic trace ID and the SHA-256 request fingerprint with its three components (query,
  scope, configuration digests); never the query text. A later request for the same step with any other fingerprint
  is a conflict, even when the earlier step's trace was never written. The run is a composite workspace foreign key.
  Select and insert only: the row is never updated or deleted.

There is no foreign key from `app.retrieval_traces` to this table: traces written before this revision stay valid
historical records, and a trace without an intent is reported as unsupported for replay, not reinterpreted.

Forced workspace RLS for the app runtime, no function or trigger, flat CHECKs (identical after a dump and restore).
The downgrade is refused while the table holds rows (by default).

Revision ID: 0011
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

APP = "policyops_app_runtime"
SHA = "~ '^[0-9a-f]{64}$'"
TABLE = "app.retrieval_steps"

SQL = rf"""
CREATE TABLE app.retrieval_steps (
    workspace_id uuid NOT NULL,
    run_id uuid NOT NULL,
    step integer NOT NULL CONSTRAINT retrieval_steps_step CHECK (step >= 0 AND step <= 9999),
    trace_id uuid NOT NULL,
    request_sha256 text NOT NULL CONSTRAINT retrieval_steps_request_digest CHECK (request_sha256 {SHA}),
    query_sha256 text NOT NULL CONSTRAINT retrieval_steps_query_digest CHECK (query_sha256 {SHA}),
    scope_sha256 text NOT NULL CONSTRAINT retrieval_steps_scope_digest CHECK (scope_sha256 {SHA}),
    config_sha256 text NOT NULL CONSTRAINT retrieval_steps_config_digest CHECK (config_sha256 {SHA}),
    created_at timestamptz NOT NULL,
    CONSTRAINT retrieval_steps_pkey PRIMARY KEY (workspace_id, run_id, step),
    CONSTRAINT retrieval_steps_trace_unique UNIQUE (workspace_id, trace_id),
    CONSTRAINT retrieval_steps_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id)
);
ALTER TABLE app.retrieval_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.retrieval_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_steps_app_workspace ON app.retrieval_steps TO {APP}
    USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());
GRANT SELECT, INSERT ON app.retrieval_steps TO {APP};
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    refuse_data_loss((TABLE,))
    op.execute(f"DROP TABLE {TABLE}")
