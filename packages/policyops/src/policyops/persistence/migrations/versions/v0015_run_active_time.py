"""Persist active run allowance; human waits suspend it without extending business authority.

Backfill cannot refund historical waits. Upgrade quiescent workers; existing execute-job delivery deadlines
remain unchanged. Nonempty downgrade requires the explicit lossy-downgrade mechanism.
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

SQL = """
ALTER TABLE app.runs NO FORCE ROW LEVEL SECURITY;
ALTER TABLE app.runs DROP CONSTRAINT runs_deadline_after_creation,
    ALTER COLUMN deadline_at DROP NOT NULL,
    ADD COLUMN active_remaining_us bigint,
    ADD COLUMN active_started_at timestamptz;
WITH observed AS (SELECT clock_timestamp() AS at)
UPDATE app.runs r SET
    active_remaining_us = CASE WHEN state IN ('succeeded', 'failed', 'cancelled', 'budget_exceeded') THEN 0
        ELSE greatest(0, floor(extract(epoch FROM (deadline_at - observed.at)) * 1000000))::bigint END,
    active_started_at = CASE WHEN state IN ('queued', 'running', 'reconciling')
        THEN least(deadline_at, observed.at) ELSE NULL END,
    deadline_at = CASE WHEN state IN ('queued', 'running', 'reconciling') THEN deadline_at ELSE NULL END
FROM observed;
ALTER TABLE app.runs ALTER COLUMN active_remaining_us SET NOT NULL,
    ADD CONSTRAINT runs_active_nonnegative CHECK (active_remaining_us >= 0),
    ADD CONSTRAINT runs_active_shape CHECK (CASE WHEN state IN ('queued', 'running', 'reconciling') THEN
        active_started_at IS NOT NULL AND deadline_at IS NOT NULL
        AND deadline_at = active_started_at + active_remaining_us * interval '1 microsecond'
        ELSE active_started_at IS NULL AND deadline_at IS NULL END);
ALTER TABLE app.runs FORCE ROW LEVEL SECURITY;
GRANT UPDATE (active_remaining_us, active_started_at, deadline_at) ON app.runs TO policyops_app_runtime;
CREATE FUNCTION app.runs_active_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    old_active boolean := OLD.state IN ('queued', 'running', 'reconciling');
    new_active boolean := NEW.state IN ('queued', 'running', 'reconciling');
    ceiling_us bigint;
BEGIN
    IF NEW.active_remaining_us > OLD.active_remaining_us THEN
        RAISE EXCEPTION 'run active allowance cannot increase';
    END IF;
    IF OLD.state IN ('succeeded', 'failed', 'cancelled', 'budget_exceeded') AND NEW.state <> OLD.state THEN
        RAISE EXCEPTION 'terminal run cannot resume';
    END IF;
    IF old_active AND new_active OR NEW.state = OLD.state THEN
        IF (NEW.active_remaining_us, NEW.active_started_at, NEW.deadline_at) IS DISTINCT FROM
           (OLD.active_remaining_us, OLD.active_started_at, OLD.deadline_at) THEN
            RAISE EXCEPTION 'run active segment cannot restart';
        END IF;
    ELSIF old_active THEN
        ceiling_us := greatest(0, OLD.active_remaining_us - greatest(0,
            floor(extract(epoch FROM (NEW.updated_at - OLD.active_started_at)) * 1000000))::bigint);
        IF NEW.active_remaining_us > ceiling_us THEN
            RAISE EXCEPTION 'elapsed active time must be deducted';
        END IF;
    ELSIF new_active THEN
        IF NEW.active_remaining_us <> OLD.active_remaining_us OR NEW.active_started_at <> NEW.updated_at THEN
            RAISE EXCEPTION 'resuming preserves allowance at transition time';
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION app.runs_active_guard() FROM PUBLIC;
CREATE TRIGGER runs_active_guard BEFORE UPDATE ON app.runs FOR EACH ROW EXECUTE FUNCTION app.runs_active_guard();
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    refuse_data_loss(("app.runs",))
    op.execute("DROP TRIGGER runs_active_guard ON app.runs; DROP FUNCTION app.runs_active_guard()")
    # Remove the new shape before restoring the historical non-null deadline: paused/terminal
    # rows cannot satisfy both shapes at once. DDL and conversion share this migration transaction.
    op.execute("ALTER TABLE app.runs DROP CONSTRAINT runs_active_shape")
    op.execute("ALTER TABLE app.runs NO FORCE ROW LEVEL SECURITY")
    # Lossy downgrade cannot represent paused/terminal clocks; keep a legal historical timestamp.
    op.execute("UPDATE app.runs SET deadline_at = coalesce(deadline_at, created_at + interval '1 microsecond')")
    op.execute("ALTER TABLE app.runs FORCE ROW LEVEL SECURITY")
    op.execute("REVOKE UPDATE (active_remaining_us, active_started_at, deadline_at) ON app.runs "
               "FROM policyops_app_runtime")
    op.execute("ALTER TABLE app.runs DROP CONSTRAINT runs_active_nonnegative, "
               "DROP COLUMN active_started_at, DROP COLUMN active_remaining_us, ALTER COLUMN deadline_at SET NOT NULL, "
               "ADD CONSTRAINT runs_deadline_after_creation CHECK (deadline_at > created_at)")
