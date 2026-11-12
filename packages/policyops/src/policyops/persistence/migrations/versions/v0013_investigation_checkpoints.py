"""Tenant-scoped, JSON-only investigation checkpoints and proposal preparation replay (T21).

Downgrade never forgets checkpoint/replay intent: unconditional checks are stricter
than refuse_data_loss (even allow_data_loss cannot bypass them).
The existing proposal trigger compares all fields except status/presented_at via
to_jsonb, so it automatically protects both new immutable creation columns.
"""

from alembic import op
from sqlalchemy import text

from policyops.persistence.migration_guard import DataLossRefused, check_tables_empty


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None
APP = "policyops_app_runtime"
TABLES = ("checkpoints.writes", "checkpoints.snapshots", "checkpoints.threads")

SCHEMA = """
CREATE TABLE checkpoints.threads (
    workspace_id uuid NOT NULL, thread_id uuid NOT NULL, case_id uuid NOT NULL, run_id uuid NOT NULL,
    graph_sha256 text NOT NULL, prompt_sha256 text NOT NULL, config_sha256 text NOT NULL,
    CONSTRAINT checkpoint_threads_pkey PRIMARY KEY (workspace_id, thread_id),
    CONSTRAINT checkpoint_threads_run_unique UNIQUE (workspace_id, run_id),
    CONSTRAINT checkpoint_threads_run FOREIGN KEY (workspace_id, case_id, run_id)
        REFERENCES app.runs (workspace_id, case_id, id),
    CONSTRAINT checkpoint_threads_digests CHECK (graph_sha256 ~ '^[0-9a-f]{64}$'
        AND prompt_sha256 ~ '^[0-9a-f]{64}$' AND config_sha256 ~ '^[0-9a-f]{64}$')
);
CREATE TABLE checkpoints.snapshots (
    workspace_id uuid NOT NULL, thread_id uuid NOT NULL,
    checkpoint_ns text NOT NULL DEFAULT '', checkpoint_id text NOT NULL, parent_checkpoint_id text,
    generation bigint NOT NULL, codec_version integer NOT NULL, state_version integer NOT NULL,
    payload jsonb NOT NULL, metadata jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT checkpoint_snapshots_pkey PRIMARY KEY (workspace_id, thread_id, checkpoint_ns, checkpoint_id),
    CONSTRAINT checkpoint_snapshots_root CHECK (checkpoint_ns = ''),
    CONSTRAINT checkpoint_snapshots_id CHECK (char_length(checkpoint_id) BETWEEN 1 AND 128),
    CONSTRAINT checkpoint_snapshots_generation CHECK (generation >= 0),
    CONSTRAINT checkpoint_snapshots_codec CHECK (codec_version = 1),
    CONSTRAINT checkpoint_snapshots_state_version CHECK (state_version >= 0),
    CONSTRAINT checkpoint_snapshots_payload CHECK (jsonb_typeof(payload) = 'object'
        AND octet_length(payload::text) <= 524288),
    CONSTRAINT checkpoint_snapshots_metadata CHECK (jsonb_typeof(metadata) = 'object'
        AND octet_length(metadata::text) <= 8192),
    CONSTRAINT checkpoint_snapshots_thread FOREIGN KEY (workspace_id, thread_id)
        REFERENCES checkpoints.threads (workspace_id, thread_id),
    CONSTRAINT checkpoint_snapshots_parent FOREIGN KEY (workspace_id, thread_id, checkpoint_ns, parent_checkpoint_id)
        REFERENCES checkpoints.snapshots (workspace_id, thread_id, checkpoint_ns, checkpoint_id)
);
CREATE TABLE checkpoints.writes (
    workspace_id uuid NOT NULL, thread_id uuid NOT NULL, checkpoint_ns text NOT NULL,
    checkpoint_id text NOT NULL, task_id text NOT NULL, idx integer NOT NULL,
    task_path text NOT NULL, channel text NOT NULL, value jsonb NOT NULL,
    CONSTRAINT checkpoint_writes_pkey PRIMARY KEY
        (workspace_id, thread_id, checkpoint_ns, checkpoint_id, task_id, idx),
    CONSTRAINT checkpoint_writes_task CHECK (char_length(task_id) BETWEEN 1 AND 128),
    CONSTRAINT checkpoint_writes_idx CHECK (idx BETWEEN -4 AND 255),
    CONSTRAINT checkpoint_writes_path CHECK (char_length(task_path) <= 1024),
    CONSTRAINT checkpoint_writes_channel CHECK (char_length(channel) BETWEEN 1 AND 128),
    CONSTRAINT checkpoint_writes_value CHECK (octet_length(value::text) <= 524288),
    CONSTRAINT checkpoint_writes_snapshot FOREIGN KEY (workspace_id, thread_id, checkpoint_ns, checkpoint_id)
        REFERENCES checkpoints.snapshots (workspace_id, thread_id, checkpoint_ns, checkpoint_id)
);
CREATE FUNCTION checkpoints.guard_write_update() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF OLD.idx <> -1 OR OLD.channel <> '__error__'
            OR (to_jsonb(NEW) - 'value') IS DISTINCT FROM (to_jsonb(OLD) - 'value') THEN
        RAISE EXCEPTION 'only reserved error write values may be replaced';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION checkpoints.guard_write_update() FROM PUBLIC;
CREATE TRIGGER checkpoint_writes_guard BEFORE UPDATE ON checkpoints.writes FOR EACH ROW
    EXECUTE FUNCTION checkpoints.guard_write_update();

ALTER TABLE app.action_proposals
    ADD COLUMN creation_step integer,
    ADD COLUMN creation_request_sha256 text,
    ADD CONSTRAINT action_proposals_creation_pair CHECK ((creation_step IS NULL) = (creation_request_sha256 IS NULL)),
    ADD CONSTRAINT action_proposals_creation_step CHECK (creation_step BETWEEN 0 AND 64),
    ADD CONSTRAINT action_proposals_creation_digest CHECK (creation_request_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT action_proposals_creation_unique UNIQUE (workspace_id, run_id, creation_step);
"""


def upgrade() -> None:
    op.execute(SCHEMA)
    for table in TABLES:
        name = table.split(".")[1]
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; "
                   f"CREATE POLICY {name}_workspace ON {table} TO {APP} "
                   "USING (workspace_id = app.current_workspace()) "
                   "WITH CHECK (workspace_id = app.current_workspace()); "
                   f"REVOKE ALL ON {table} FROM PUBLIC; GRANT SELECT, INSERT ON {table} TO {APP}")
    op.execute(f"GRANT UPDATE (value) ON checkpoints.writes TO {APP}")


def downgrade() -> None:
    connection = op.get_bind()
    try:
        check_tables_empty(connection, TABLES)
    except DataLossRefused:
        raise DataLossRefused(
            "checkpoints contain restart intent; downgrade is refused even with allow_data_loss") from None
    op.execute("ALTER TABLE app.action_proposals NO FORCE ROW LEVEL SECURITY")
    holds_replay = connection.execute(text(
        "SELECT EXISTS (SELECT 1 FROM app.action_proposals WHERE creation_step IS NOT NULL)")).scalar_one()
    op.execute("ALTER TABLE app.action_proposals FORCE ROW LEVEL SECURITY")
    if holds_replay:
        raise DataLossRefused("downgrade would forget proposal creation replay intent")
    op.execute("DROP TABLE checkpoints.writes; DROP FUNCTION checkpoints.guard_write_update(); "
               "DROP TABLE checkpoints.snapshots; DROP TABLE checkpoints.threads; "
               "ALTER TABLE app.action_proposals DROP CONSTRAINT action_proposals_creation_unique, "
               "DROP CONSTRAINT action_proposals_creation_pair, DROP CONSTRAINT action_proposals_creation_step, "
               "DROP CONSTRAINT action_proposals_creation_digest, DROP COLUMN creation_step, "
               "DROP COLUMN creation_request_sha256")
