"""Tenant-scoped Zammad inbox, immutable bindings and internal-note delivery ledger."""

from alembic import op

from policyops.persistence.migration_guard import DataLossRefused, refuse_data_loss
from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY


revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

ENDPOINT = "connection_id text NOT NULL CHECK (connection_id ~ '^[a-z][a-z0-9_-]{0,63}$')"
SHA = "CHECK ({} ~ '^[0-9a-f]{{64}}$')"
MAX_ID = 2**53 - 1
EXTERNAL = f"bigint NOT NULL CHECK ({{}} BETWEEN 1 AND {MAX_ID})"
CUSTOMER = "customer_user_id text NOT NULL CHECK (customer_user_id ~ '^[a-z]+(_[a-z]+)*_[0-9]{1,6}$'"
CUSTOMER += " AND char_length(customer_user_id) <= 64)"
SCHEDULE = """
    next_attempt_at timestamptz NOT NULL,
    lease_owner uuid,
    lease_expires_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
"""


def _message_source(*, helpdesk: bool) -> None:
    extra = ", 'helpdesk_ticket'" if helpdesk else ""
    op.execute(f"""
ALTER TABLE app.case_messages DROP CONSTRAINT case_messages_source_values,
    ADD CONSTRAINT case_messages_source_values CHECK (
        source IN ('seeded', 'simulated_customer', 'operator_entered_customer', 'staff_note', 'agent'{extra}));
""")


def upgrade() -> None:
    _message_source(helpdesk=True)
    op.execute(f"""
ALTER TABLE app.case_messages ADD CONSTRAINT case_messages_helpdesk_case_id_unique UNIQUE (workspace_id, case_id, id);

CREATE TABLE app.helpdesk_customer_bindings (
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    {ENDPOINT},
    requester_id {EXTERNAL.format("requester_id")},
    {CUSTOMER},
    seed_id text NOT NULL CHECK (seed_id ~ '^retail-demo-[0-9]{{1,4}}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, connection_id, requester_id),
    UNIQUE (workspace_id, connection_id, requester_id, customer_user_id)
);

CREATE TABLE app.helpdesk_ticket_links (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    {ENDPOINT},
    ticket_id {EXTERNAL.format("ticket_id")},
    requester_id {EXTERNAL.format("requester_id")},
    {CUSTOMER},
    destination_sha256 text NOT NULL {SHA.format("destination_sha256")},
    case_id uuid NOT NULL,
    group_id {EXTERNAL.format("group_id")},
    state_id {EXTERNAL.format("state_id")},
    ticket_updated_at timestamptz NOT NULL,
    max_article_id bigint NOT NULL CHECK (max_article_id BETWEEN 0 AND {MAX_ID}),
    created_at timestamptz NOT NULL,
    UNIQUE (workspace_id, id),
    UNIQUE (workspace_id, connection_id, ticket_id),
    UNIQUE (workspace_id, case_id),
    UNIQUE (workspace_id, case_id, id),
    FOREIGN KEY (workspace_id, case_id) REFERENCES app.cases (workspace_id, id),
    FOREIGN KEY (workspace_id, connection_id, requester_id, customer_user_id)
        REFERENCES app.helpdesk_customer_bindings (workspace_id, connection_id, requester_id, customer_user_id)
);

CREATE TABLE app.helpdesk_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    {ENDPOINT},
    destination_sha256 text NOT NULL {SHA.format("destination_sha256")},
    ticket_id {EXTERNAL.format("ticket_id")},
    event_updated_at timestamptz NOT NULL,
    delivery_id text CHECK (delivery_id ~ '^[!-~]{{1,128}}$'),
    body_sha256 text NOT NULL {SHA.format("body_sha256")},
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 65536),
    created_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN
        ('pending', 'applied', 'stale', 'rejected_mapping', 'incomplete_scan', 'failed')),
    reason text CHECK (reason ~ '^[a-z][a-z0-9_]{{0,63}}$'),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    revivals integer NOT NULL DEFAULT 0 CHECK (revivals BETWEEN 0 AND 3),
    {SCHEDULE}
    CHECK (state = 'pending' OR lease_owner IS NULL),
    UNIQUE (workspace_id, id),
    UNIQUE (workspace_id, connection_id, body_sha256)
);

CREATE TABLE app.helpdesk_writebacks (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    link_id uuid NOT NULL,
    outcome_message_id uuid NOT NULL,
    template_version integer NOT NULL CHECK (template_version = 1),
    body_sha256 text NOT NULL {SHA.format("body_sha256")},
    created_at timestamptz NOT NULL,
    deadline_at timestamptz NOT NULL CHECK (deadline_at > created_at),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN
        ('pending', 'dispatching', 'succeeded', 'unconfirmed', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 12),
    reconciles integer NOT NULL DEFAULT 0 CHECK (reconciles BETWEEN 0 AND 3),
    dispatch_started_at timestamptz,
    reason text CHECK (reason ~ '^[a-z][a-z0-9_]{{0,63}}$'),
    article_id bigint CHECK (article_id BETWEEN 1 AND {MAX_ID}),
    article_created_at timestamptz,
    duplicate_article_ids bigint[],
    {SCHEDULE}
    CHECK (state IN ('pending', 'dispatching') OR lease_owner IS NULL),
    CHECK (state <> 'dispatching' OR dispatch_started_at IS NOT NULL),
    CHECK (state <> 'pending' OR dispatch_started_at IS NULL),
    CHECK ((state = 'succeeded') = (article_id IS NOT NULL)),
    CHECK ((article_id IS NULL) = (article_created_at IS NULL)),
    CHECK (duplicate_article_ids IS NULL OR (state = 'succeeded'
        AND array_ndims(duplicate_article_ids) = 1 AND cardinality(duplicate_article_ids) BETWEEN 2 AND 200
        AND array_position(duplicate_article_ids, NULL) IS NULL
        AND 1 <= ALL(duplicate_article_ids) AND {MAX_ID} >= ALL(duplicate_article_ids)
        AND article_id = ANY(duplicate_article_ids) AND reason IS NOT DISTINCT FROM 'duplicate_detected')),
    UNIQUE (workspace_id, id),
    UNIQUE (workspace_id, outcome_message_id),
    FOREIGN KEY (workspace_id, case_id, link_id) REFERENCES app.helpdesk_ticket_links (workspace_id, case_id, id),
    FOREIGN KEY (workspace_id, case_id, outcome_message_id) REFERENCES app.case_messages (workspace_id, case_id, id)
);

CREATE INDEX helpdesk_events_due ON app.helpdesk_events (next_attempt_at, id) WHERE state = 'pending';
CREATE INDEX helpdesk_writebacks_due ON app.helpdesk_writebacks (next_attempt_at, id)
    WHERE state IN ('pending', 'dispatching');
""")
    for name, grant in (
        ("helpdesk_customer_bindings", ""),
        ("helpdesk_ticket_links", ", UPDATE (group_id, state_id, ticket_updated_at, max_article_id)"),
        ("helpdesk_events", ", UPDATE (state, reason, attempts, revivals, next_attempt_at, lease_owner, "
         "lease_expires_at, version)"),
        ("helpdesk_writebacks", ", UPDATE (state, reason, attempts, reconciles, dispatch_started_at, next_attempt_at, "
         "lease_owner, lease_expires_at, version, article_id, article_created_at, duplicate_article_ids)"),
    ):
        table = f"app.{name}"
        op.execute(f"""
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
CREATE POLICY {name}_workspace ON {table} TO {APP_RUNTIME}
    USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());
GRANT SELECT, INSERT{grant} ON {table} TO {APP_RUNTIME};
""")
        if name in {"helpdesk_events", "helpdesk_writebacks"}:
            op.execute(f"""
CREATE POLICY {name}_discovery ON {table} FOR SELECT TO {WORKER_DISCOVERY} USING (true);
GRANT SELECT (id, workspace_id, state, lease_expires_at, next_attempt_at) ON {table} TO {WORKER_DISCOVERY};
""")


def downgrade() -> None:
    connection = op.get_bind()
    connection.exec_driver_sql("LOCK TABLE app.case_messages IN ACCESS EXCLUSIVE MODE")
    connection.exec_driver_sql("ALTER TABLE app.case_messages NO FORCE ROW LEVEL SECURITY")
    exists = connection.exec_driver_sql(
        "SELECT EXISTS (SELECT 1 FROM app.case_messages WHERE source = 'helpdesk_ticket')").scalar_one()
    connection.exec_driver_sql("ALTER TABLE app.case_messages FORCE ROW LEVEL SECURITY")
    if exists:
        raise DataLossRefused("0018 downgrade refused while imported help desk messages exist")
    refuse_data_loss(("app.helpdesk_writebacks", "app.helpdesk_events", "app.helpdesk_ticket_links",
                      "app.helpdesk_customer_bindings"))
    op.execute("""
DROP TABLE app.helpdesk_writebacks, app.helpdesk_events, app.helpdesk_ticket_links, app.helpdesk_customer_bindings;
ALTER TABLE app.case_messages DROP CONSTRAINT case_messages_helpdesk_case_id_unique;
""")
    _message_source(helpdesk=False)
