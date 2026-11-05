"""Durable customer authentication per run (T17). Forward-only addition.

* `app.customer_authentications`: one row per run, the successful identity lookup that authenticated the case's
  bound customer (`CustomerAuthentication`). Composite foreign keys tie it to the run of that case and to the case's
  own bound customer, so a row can only name the customer the case is bound to. The application runtime may only
  select and insert (first write wins; a row is never updated or deleted at runtime). Workspace RLS is forced.
* `app.cases` gains `UNIQUE (workspace_id, id, customer_user_id)` as the referenced key of that binding (it was
  already unique per `(workspace_id, id)`, so the new constraint adds no restriction on existing rows). Changing a
  case's customer while one of its runs is authenticated is refused by the foreign key.

The downgrade is refused while the table holds rows (by default).

Revision ID: 0008
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

APP = "policyops_app_runtime"


def upgrade() -> None:
    op.execute(f"""
ALTER TABLE app.cases ADD CONSTRAINT cases_customer_binding_unique UNIQUE (workspace_id, id, customer_user_id);
CREATE TABLE app.customer_authentications (
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    run_id uuid NOT NULL,
    user_id text NOT NULL,
    lookup_tool text NOT NULL CONSTRAINT customer_authentications_tool
        CHECK (lookup_tool IN ('find_user_id_by_email', 'find_user_id_by_name_zip')),
    lookup_call_sha256 text NOT NULL CONSTRAINT customer_authentications_call_digest
        CHECK (lookup_call_sha256 ~ '^[0-9a-f]{{64}}$'),
    step_sequence bigint NOT NULL CONSTRAINT customer_authentications_sequence_positive CHECK (step_sequence >= 1),
    authenticated_at timestamptz NOT NULL,
    CONSTRAINT customer_authentications_pkey PRIMARY KEY (workspace_id, run_id),
    CONSTRAINT customer_authentications_run FOREIGN KEY (workspace_id, case_id, run_id)
        REFERENCES app.runs (workspace_id, case_id, id),
    CONSTRAINT customer_authentications_bound_customer FOREIGN KEY (workspace_id, case_id, user_id)
        REFERENCES app.cases (workspace_id, id, customer_user_id)
);
ALTER TABLE app.customer_authentications ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.customer_authentications FORCE ROW LEVEL SECURITY;
CREATE POLICY customer_authentications_app_workspace ON app.customer_authentications TO {APP}
    USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());
GRANT SELECT, INSERT ON app.customer_authentications TO {APP};
""")


def downgrade() -> None:
    refuse_data_loss(("app.customer_authentications",))
    op.execute("DROP TABLE app.customer_authentications; "
               "ALTER TABLE app.cases DROP CONSTRAINT cases_customer_binding_unique;")
