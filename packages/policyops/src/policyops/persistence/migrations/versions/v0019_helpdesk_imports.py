"""Resumable, tenant-scoped historical help desk imports and their redacted row ledger."""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss
from policyops.persistence.roles import APP_RUNTIME


revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE app.helpdesk_imports (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    connection_id text NOT NULL CHECK (connection_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
    format_version integer NOT NULL CHECK (format_version = 1),
    file_sha256 text NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
    destination_sha256 text NOT NULL CHECK (destination_sha256 ~ '^[0-9a-f]{64}$'),
    mapping_sha256 text NOT NULL CHECK (mapping_sha256 ~ '^[0-9a-f]{64}$'),
    exported_at timestamptz NOT NULL CHECK (isfinite(exported_at)),
    records_total integer NOT NULL CHECK (records_total BETWEEN 0 AND 50000),
    next_record integer NOT NULL DEFAULT 0 CHECK (next_record BETWEEN 0 AND records_total),
    accepted integer NOT NULL DEFAULT 0 CHECK (accepted BETWEEN 0 AND next_record),
    updated integer NOT NULL DEFAULT 0 CHECK (updated BETWEEN 0 AND next_record),
    duplicate integer NOT NULL DEFAULT 0 CHECK (duplicate BETWEEN 0 AND next_record),
    skipped_stale integer NOT NULL DEFAULT 0 CHECK (skipped_stale BETWEEN 0 AND next_record),
    quarantined integer NOT NULL DEFAULT 0 CHECK (quarantined BETWEEN 0 AND next_record),
    rejected integer NOT NULL DEFAULT 0 CHECK (rejected BETWEEN 0 AND next_record),
    state text NOT NULL CHECK (state IN ('running', 'completed')),
    version integer NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND records_total + 1),
    PRIMARY KEY (workspace_id, id),
    UNIQUE (workspace_id, connection_id, format_version, file_sha256),
    CHECK (accepted + updated + duplicate + skipped_stale + quarantined + rejected = next_record),
    CHECK ((state = 'completed') = (next_record = records_total))
);

CREATE TABLE app.helpdesk_import_records (
    workspace_id uuid NOT NULL,
    import_id uuid NOT NULL,
    record_no integer NOT NULL CHECK (record_no BETWEEN 1 AND 50000),
    ticket_id bigint CHECK (ticket_id BETWEEN 1 AND 9007199254740991),
    record_sha256 text NOT NULL CHECK (record_sha256 ~ '^[0-9a-f]{64}$'),
    disposition text NOT NULL,
    reason text NOT NULL,
    PRIMARY KEY (workspace_id, import_id, record_no),
    FOREIGN KEY (workspace_id, import_id) REFERENCES app.helpdesk_imports (workspace_id, id),
    CHECK (ticket_id IS NOT NULL OR disposition = 'rejected'),
    CHECK (CASE disposition
        WHEN 'accepted' THEN reason = 'case_created'
        WHEN 'updated' THEN reason = 'snapshot_advanced'
        WHEN 'duplicate' THEN reason = 'same_snapshot'
        WHEN 'skipped_stale' THEN reason = 'older_snapshot'
        WHEN 'quarantined' THEN reason IN ('snapshot_conflict', 'incompatible_history', 'disallowed_group',
            'destination_changed', 'requester_changed', 'unmapped_requester')
        WHEN 'rejected' THEN reason IN ('record_too_large', 'invalid_csv', 'invalid_ticket', 'future_ticket',
            'articles_too_large', 'too_many_articles', 'invalid_articles', 'duplicate_article_id',
            'article_ticket_mismatch')
        ELSE false END)
);
""")
    for name, updates in (
        ("helpdesk_imports", ", UPDATE (next_record, accepted, updated, duplicate, skipped_stale, quarantined, "
         "rejected, state, version)"),
        ("helpdesk_import_records", ""),
    ):
        table = f"app.{name}"
        op.execute(f"""
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
CREATE POLICY {name}_workspace ON {table} TO {APP_RUNTIME}
    USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());
GRANT SELECT, INSERT{updates} ON {table} TO {APP_RUNTIME};
""")


def downgrade() -> None:
    refuse_data_loss(("app.helpdesk_import_records", "app.helpdesk_imports"))
    op.execute("DROP TABLE app.helpdesk_import_records, app.helpdesk_imports")
