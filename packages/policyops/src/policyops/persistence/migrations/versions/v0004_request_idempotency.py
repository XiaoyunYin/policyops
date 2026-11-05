"""Durable request idempotency for case writes, and the immutable case-queue order (T08). Forward-only.

* `app.request_idempotency`: one row per successful write, keyed by workspace, principal, operation and the
  client's Idempotency-Key. It stores the SHA-256 of the canonical request intent and the ORIGINAL successful
  response (status, JSON body, ETag), so a retry returns exactly what the first attempt returned, even after the
  resource changed later. Each row links to its case (and, for message writes, to the message of that case)
  through composite workspace foreign keys. Append-only for the app runtime (INSERT/SELECT; no UPDATE/DELETE),
  forced RLS on the workspace scope. No expiry or cleanup: any future retention policy must keep the replay guarantee.
* `cases_queue_created`: the queue's immutable keyset order (workspace, created_at DESC, id DESC).

Revision ID: 0004
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

UPGRADE = r"""
-- Composite key for links that must name a message of a specific case.
ALTER TABLE app.case_messages ADD CONSTRAINT case_messages_case_unique UNIQUE (workspace_id, case_id, id);

CREATE TABLE app.request_idempotency (
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    principal_id uuid NOT NULL REFERENCES identity.principals (id),
    operation text NOT NULL CONSTRAINT request_idempotency_operation_values
        CHECK (operation IN ('case.create', 'case.status', 'case.message')),
    idempotency_key text NOT NULL CONSTRAINT request_idempotency_key_format
        CHECK (idempotency_key ~ '^[A-Za-z0-9._~-]{8,128}$'),
    request_sha256 text NOT NULL CONSTRAINT request_idempotency_request_digest
        CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    case_id uuid NOT NULL,
    message_id uuid,
    response_status integer NOT NULL CONSTRAINT request_idempotency_status_success
        CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb NOT NULL
        CONSTRAINT request_idempotency_body_size CHECK (pg_column_size(response_body) <= 65536),
    response_etag text CONSTRAINT request_idempotency_etag_format CHECK (response_etag ~ '^"[0-9]{1,19}"$'),
    created_at timestamptz NOT NULL,
    CONSTRAINT request_idempotency_pkey PRIMARY KEY (workspace_id, principal_id, operation, idempotency_key),
    -- Message writes, and only they, name the message; a named message must belong to the named case.
    CONSTRAINT request_idempotency_message_rule CHECK ((operation = 'case.message') = (message_id IS NOT NULL)),
    CONSTRAINT request_idempotency_case FOREIGN KEY (workspace_id, case_id) REFERENCES app.cases (workspace_id, id),
    CONSTRAINT request_idempotency_message FOREIGN KEY (workspace_id, case_id, message_id)
        REFERENCES app.case_messages (workspace_id, case_id, id)
);
ALTER TABLE app.request_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.request_idempotency FORCE ROW LEVEL SECURITY;
CREATE POLICY request_idempotency_app_workspace ON app.request_idempotency TO policyops_app_runtime
    USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());
GRANT SELECT, INSERT ON app.request_idempotency TO policyops_app_runtime;

CREATE INDEX cases_queue_created ON app.cases (workspace_id, created_at DESC, id DESC);
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    refuse_data_loss(("app.request_idempotency",))
    op.execute("DROP INDEX app.cases_queue_created")
    op.execute("DROP TABLE app.request_idempotency")
    op.execute("ALTER TABLE app.case_messages DROP CONSTRAINT case_messages_case_unique")
