"""Immutable, scoped review continuations; completed jobs remain replay tombstones.

Unlike whole-table refuse_data_loss, downgrade preserves ordinary jobs and
unconditionally refuses the loss of review rows, even with allow_data_loss.
"""

from alembic import op
from sqlalchemy import text

from policyops.persistence.migration_guard import DataLossRefused


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

COLUMNS = ("review_trigger", "proposal_id", "proposal_version", "decision_id", "execution_id", "execution_version")
SQL = """
ALTER TABLE app.action_proposals ADD CONSTRAINT action_proposals_review_binding
    UNIQUE (workspace_id, run_id, proposal_id, proposal_version);
ALTER TABLE app.approval_decisions ADD CONSTRAINT approval_decisions_review_binding
    UNIQUE (workspace_id, run_id, id, proposal_id, proposal_version);
ALTER TABLE app.tool_executions ADD CONSTRAINT tool_executions_review_binding
    UNIQUE (workspace_id, run_id, id, approval_id, proposal_id, proposal_version);
ALTER TABLE app.jobs
    ADD COLUMN review_trigger text,
    ADD COLUMN proposal_id uuid,
    ADD COLUMN proposal_version bigint,
    ADD COLUMN decision_id uuid,
    ADD COLUMN execution_id uuid,
    ADD COLUMN execution_version bigint,
    ADD CONSTRAINT jobs_review_shape CHECK (COALESCE(
        CASE WHEN kind = 'run.review' THEN
            proposal_id IS NOT NULL AND proposal_version > 0 AND
            CASE review_trigger
                WHEN 'decision' THEN decision_id IS NOT NULL AND execution_id IS NULL AND execution_version IS NULL
                WHEN 'expiry' THEN decision_id IS NULL AND execution_id IS NULL AND execution_version IS NULL
                WHEN 'outcome' THEN decision_id IS NOT NULL AND execution_id IS NOT NULL AND execution_version > 0
                ELSE false
            END
        ELSE review_trigger IS NULL AND proposal_id IS NULL AND proposal_version IS NULL
            AND decision_id IS NULL AND execution_id IS NULL AND execution_version IS NULL END, false)),
    ADD CONSTRAINT jobs_review_proposal FOREIGN KEY (workspace_id, run_id, proposal_id, proposal_version)
        REFERENCES app.action_proposals (workspace_id, run_id, proposal_id, proposal_version),
    ADD CONSTRAINT jobs_review_decision FOREIGN KEY (workspace_id, run_id, decision_id, proposal_id, proposal_version)
        REFERENCES app.approval_decisions (workspace_id, run_id, id, proposal_id, proposal_version),
    ADD CONSTRAINT jobs_review_execution FOREIGN KEY
        (workspace_id, run_id, execution_id, decision_id, proposal_id, proposal_version)
        REFERENCES app.tool_executions (workspace_id, run_id, id, approval_id, proposal_id, proposal_version);
CREATE UNIQUE INDEX jobs_review_decision_unique ON app.jobs
    (workspace_id, proposal_id, proposal_version, decision_id) WHERE review_trigger = 'decision';
CREATE UNIQUE INDEX jobs_review_expiry_unique ON app.jobs
    (workspace_id, proposal_id, proposal_version) WHERE review_trigger = 'expiry';
CREATE UNIQUE INDEX jobs_review_outcome_unique ON app.jobs
    (workspace_id, execution_id, execution_version) WHERE review_trigger = 'outcome';
GRANT SELECT (kind) ON app.jobs TO policyops_worker_discovery;
CREATE FUNCTION app.jobs_review_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.kind = 'run.review' THEN
            RAISE EXCEPTION 'review jobs are retained';
        END IF;
        RETURN OLD;
    END IF;
    IF (NEW.review_trigger, NEW.proposal_id, NEW.proposal_version, NEW.decision_id,
            NEW.execution_id, NEW.execution_version) IS DISTINCT FROM
       (OLD.review_trigger, OLD.proposal_id, OLD.proposal_version, OLD.decision_id,
            OLD.execution_id, OLD.execution_version) THEN
        RAISE EXCEPTION 'review job binding is immutable';
    END IF;
    IF OLD.kind = 'run.review' AND (
            (NEW.id, NEW.workspace_id, NEW.run_id, NEW.kind, NEW.dedupe_key, NEW.request_sha256,
             NEW.run_generation, NEW.max_attempts, NEW.deadline_at, NEW.created_at) IS DISTINCT FROM
            (OLD.id, OLD.workspace_id, OLD.run_id, OLD.kind, OLD.dedupe_key, OLD.request_sha256,
             OLD.run_generation, OLD.max_attempts, OLD.deadline_at, OLD.created_at)) THEN
        RAISE EXCEPTION 'review jobs are retained with immutable identities';
    END IF;
    IF OLD.kind = 'run.review' AND OLD.state IN ('done', 'dead') THEN
        RAISE EXCEPTION 'review job tombstones are immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER jobs_review_guard BEFORE UPDATE OR DELETE ON app.jobs
    FOR EACH ROW EXECUTE FUNCTION app.jobs_review_guard();
REVOKE ALL ON FUNCTION app.jobs_review_guard() FROM PUBLIC;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    connection = op.get_bind()
    op.execute("ALTER TABLE app.jobs NO FORCE ROW LEVEL SECURITY")
    exists = connection.execute(text("SELECT EXISTS (SELECT 1 FROM app.jobs WHERE kind = 'run.review')")).scalar_one()
    op.execute("ALTER TABLE app.jobs FORCE ROW LEVEL SECURITY")
    if exists:
        raise DataLossRefused("review jobs, including completed tombstones, cannot be discarded")
    op.execute("REVOKE SELECT (kind) ON app.jobs FROM policyops_worker_discovery")
    op.execute("DROP TRIGGER jobs_review_guard ON app.jobs; DROP FUNCTION app.jobs_review_guard(); "
               "DROP INDEX app.jobs_review_decision_unique; DROP INDEX app.jobs_review_expiry_unique; "
               "DROP INDEX app.jobs_review_outcome_unique")
    op.execute("ALTER TABLE app.jobs DROP CONSTRAINT jobs_review_shape, DROP CONSTRAINT jobs_review_execution, "
               "DROP CONSTRAINT jobs_review_decision, DROP CONSTRAINT jobs_review_proposal, "
               + ", ".join(f"DROP COLUMN {column}" for column in reversed(COLUMNS)))
    op.execute("ALTER TABLE app.tool_executions DROP CONSTRAINT tool_executions_review_binding; "
               "ALTER TABLE app.approval_decisions DROP CONSTRAINT approval_decisions_review_binding; "
               "ALTER TABLE app.action_proposals DROP CONSTRAINT action_proposals_review_binding")
