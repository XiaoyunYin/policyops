"""Run lifecycle, leased jobs and durable event replay (T09). Forward-only.

* `app.runs`: the initiating principal (NULL for runs created before this revision), a fencing `generation`,
  the durable event high-water mark (sequences are allocated from it, never from MAX + 1, so purged rows cannot
  make a sequence reappear) and an explicit retention floor (no purge exists yet; the runtime cannot move it).
  At most one active workbench run per case.
* `app.jobs`: a stable per-claim `claim_id` (heartbeats never change it) and a typed `last_error_code`.
* `app.request_idempotency`: `run.start` / `run.cancel` operations linked to their run by a composite key.
* `policyops_worker_discovery`: column SELECT on job and outbox scheduling metadata through read-only policies.

Existing rows are backfilled (the event high-water from stored events). Data that violates the new rules (two
active workbench runs on one case, or a leased job, which predates claim IDs) refuses the upgrade instead of
being rewritten. The migrator has no data policy, so the backfill and checks lift FORCE ROW LEVEL SECURITY inside
this revision's transaction and restore it before commit.

Revision ID: 0005
"""

from alembic import op
from sqlalchemy import text

from policyops.persistence.migrate import MigrationPreconditionError
from policyops.persistence.migration_guard import refuse_data_loss


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

APP = "policyops_app_runtime"
DISCOVERY = "policyops_worker_discovery"
ACTIVE = "('queued', 'running', 'waiting_input', 'waiting_approval', 'reconciling')"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"
SEEN = ("app.runs", "app.run_events", "app.jobs")

SCHEMA = rf"""
ALTER TABLE app.runs
    ADD COLUMN initiated_by uuid REFERENCES identity.principals (id),
    ADD COLUMN generation bigint NOT NULL DEFAULT 0 CONSTRAINT runs_generation_nonnegative CHECK (generation >= 0),
    ADD COLUMN event_highwater bigint NOT NULL DEFAULT 0
        CONSTRAINT runs_event_highwater_nonnegative CHECK (event_highwater >= 0),
    ADD COLUMN event_retention_floor bigint NOT NULL DEFAULT 0
        CONSTRAINT runs_event_floor_nonnegative CHECK (event_retention_floor >= 0),
    ADD CONSTRAINT runs_event_floor_within_highwater CHECK (event_retention_floor <= event_highwater);
GRANT UPDATE (generation, event_highwater) ON app.runs TO {APP};
CREATE UNIQUE INDEX runs_one_active_workbench ON app.runs (workspace_id, case_id)
    WHERE mode = 'workbench' AND state IN {ACTIVE};

ALTER TABLE app.jobs
    ADD COLUMN claim_id uuid,
    ADD COLUMN last_error_code text CONSTRAINT jobs_last_error_code_format CHECK (last_error_code {SLUG}),
    ADD CONSTRAINT jobs_claim_state CHECK ((state = 'leased') = (claim_id IS NOT NULL));
GRANT UPDATE (claim_id, last_error_code) ON app.jobs TO {APP};
CREATE INDEX jobs_expired_leases ON app.jobs (lease_expires_at) WHERE state = 'leased';

ALTER TABLE app.request_idempotency
    ADD COLUMN run_id uuid,
    DROP CONSTRAINT request_idempotency_operation_values,
    ADD CONSTRAINT request_idempotency_operation_values
        CHECK (operation IN ('case.create', 'case.status', 'case.message', 'run.start', 'run.cancel')),
    -- Run operations, and only they, name the run; the run must belong to the named case.
    ADD CONSTRAINT request_idempotency_run_rule
        CHECK ((operation IN ('run.start', 'run.cancel')) = (run_id IS NOT NULL)),
    ADD CONSTRAINT request_idempotency_run FOREIGN KEY (workspace_id, case_id, run_id)
        REFERENCES app.runs (workspace_id, case_id, id);

GRANT USAGE ON SCHEMA app TO {DISCOVERY};
GRANT SELECT (id, workspace_id, state, available_at, lease_expires_at, deadline_at) ON app.jobs TO {DISCOVERY};
GRANT SELECT (id, workspace_id, topic, created_at, delivered_at) ON app.outbox_events TO {DISCOVERY};
CREATE POLICY jobs_worker_discovery ON app.jobs FOR SELECT TO {DISCOVERY} USING (true);
CREATE POLICY outbox_worker_discovery ON app.outbox_events FOR SELECT TO {DISCOVERY} USING (true);
"""


def upgrade() -> None:
    connection = op.get_bind()
    if connection.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": DISCOVERY}).first() is None:
        raise MigrationPreconditionError(f"role {DISCOVERY} does not exist; run the bootstrap's provision_roles first")
    for table in SEEN:  # the migrator must see every tenant's rows for the checks and the backfill
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    duplicates = connection.execute(text(
        f"SELECT count(*) FROM (SELECT 1 FROM app.runs WHERE mode = 'workbench' AND state IN {ACTIVE} "  # noqa: S608
        "GROUP BY workspace_id, case_id HAVING count(*) > 1) d")).scalar_one()
    if duplicates:
        raise MigrationPreconditionError(f"{duplicates} case(s) have more than one active workbench run; resolve "
                                         "them before upgrading (no run is changed automatically)")
    leased = connection.execute(text("SELECT count(*) FROM app.jobs WHERE state = 'leased'")).scalar_one()
    if leased:
        raise MigrationPreconditionError(f"{leased} job(s) are leased without a claim ID; stop the workers and let "
                                         "the leases end before upgrading")
    op.execute(SCHEMA)
    op.execute("UPDATE app.runs r SET event_highwater = e.top FROM (SELECT workspace_id, run_id, max(sequence) AS top "
               "FROM app.run_events GROUP BY workspace_id, run_id) e "
               "WHERE e.workspace_id = r.workspace_id AND e.run_id = r.id")
    for table in SEEN:
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Dropping the new run/job columns loses fencing, initiator and high-water state: refuse while runs or jobs exist
    # (by default). Run-operation ledger rows reference runs, so none can exist on that path.
    refuse_data_loss(("app.runs", "app.jobs"))
    # With allow_data_loss=True they may exist, and the restored 0004 operation CHECK cannot hold them: delete exactly
    # the `run.start` / `run.cancel` rows (their replays are lost), and keep every case-ledger row. The migrator sees
    # no tenant rows under FORCE, so FORCE is lifted for the delete and restored in this transaction.
    op.execute("ALTER TABLE app.request_idempotency NO FORCE ROW LEVEL SECURITY")
    op.execute("DELETE FROM app.request_idempotency WHERE operation IN ('run.start', 'run.cancel')")
    op.execute("ALTER TABLE app.request_idempotency FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY outbox_worker_discovery ON app.outbox_events; "
               f"DROP POLICY jobs_worker_discovery ON app.jobs; "
               f"REVOKE ALL ON app.outbox_events FROM {DISCOVERY}; REVOKE ALL ON app.jobs FROM {DISCOVERY}; "
               f"REVOKE USAGE ON SCHEMA app FROM {DISCOVERY}")
    op.execute("ALTER TABLE app.request_idempotency DROP CONSTRAINT request_idempotency_run, "
               "DROP CONSTRAINT request_idempotency_run_rule, DROP CONSTRAINT request_idempotency_operation_values, "
               "ADD CONSTRAINT request_idempotency_operation_values "
               "CHECK (operation IN ('case.create', 'case.status', 'case.message')), DROP COLUMN run_id")
    op.execute(f"DROP INDEX app.jobs_expired_leases; REVOKE UPDATE (claim_id, last_error_code) ON app.jobs FROM {APP}; "
               "ALTER TABLE app.jobs DROP CONSTRAINT jobs_claim_state, DROP COLUMN last_error_code, "
               "DROP COLUMN claim_id")
    op.execute(f"DROP INDEX app.runs_one_active_workbench; "
               f"REVOKE UPDATE (generation, event_highwater) ON app.runs FROM {APP}; "
               "ALTER TABLE app.runs DROP CONSTRAINT runs_event_floor_within_highwater, "
               "DROP COLUMN event_retention_floor, DROP COLUMN event_highwater, DROP COLUMN generation, "
               "DROP COLUMN initiated_by")
