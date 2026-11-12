"""Durable evaluation slots and one-to-one terminal results (T29)."""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
ALTER TABLE evaluation.evaluation_runs ADD COLUMN study_scope uuid;
UPDATE evaluation.evaluation_runs SET study_scope = gen_random_uuid();
-- Historical runs have no shared-study identity. Preserve each in its own
-- explicitly labelled legacy scope, rather than merging unrelated spending.
INSERT INTO evaluation.budget_scopes
    (id, kind, study_key, manifest_sha256, cap_usd, cap_calls, cap_counts, created_at, updated_at)
SELECT study_scope, 'study', 'legacy-run:' || id, config_sha256,
       greatest(coalesce(total_cost_usd, 0), 5), 20000, 20000, created_at, created_at
FROM evaluation.evaluation_runs;
ALTER TABLE evaluation.evaluation_runs
    ALTER COLUMN study_scope SET NOT NULL,
    ADD COLUMN study_kind text NOT NULL DEFAULT 'study' CHECK (study_kind = 'study'),
    ADD CONSTRAINT evaluation_runs_study FOREIGN KEY (study_scope, study_kind)
        REFERENCES evaluation.budget_scopes (id, kind),
    ADD CONSTRAINT evaluation_runs_study_config UNIQUE (study_scope, config_sha256),
    ADD CONSTRAINT evaluation_runs_binding UNIQUE (id, study_scope, config_sha256);
ALTER TABLE evaluation.budget_scopes ADD CONSTRAINT eval_budget_scopes_slot_binding
    UNIQUE (id, parent_id, task_id, trial_index, config_sha256);
ALTER TABLE evaluation.evaluation_trials ADD COLUMN result_sha256 text;
UPDATE evaluation.evaluation_trials t SET result_sha256 =
    encode(sha256(convert_to(to_jsonb(t)::text, 'UTF8')), 'hex');
ALTER TABLE evaluation.evaluation_trials
    ALTER COLUMN result_sha256 SET NOT NULL,
    ADD CONSTRAINT evaluation_trials_result_digest CHECK (result_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT evaluation_trials_identity UNIQUE (id, evaluation_run_id, task_id, trial_index, seed),
    ADD CONSTRAINT evaluation_trials_error_reward CHECK
        (outcome IN ('success', 'failure') OR reward IS NULL) NOT VALID,
    ADD COLUMN claim_state text NOT NULL DEFAULT 'finalized' CHECK (claim_state = 'finalized');
-- Old diagnostics may have used rewards on errors; retain their historical
-- bytes. NOT VALID still enforces the invariant on every new row.
CREATE TABLE evaluation.trial_claims (
    id uuid PRIMARY KEY,
    evaluation_run_id uuid NOT NULL,
    study_scope uuid NOT NULL,
    config_sha256 text NOT NULL CHECK (config_sha256 ~ '^[0-9a-f]{64}$'),
    task_id text NOT NULL CHECK (char_length(task_id) BETWEEN 1 AND 100),
    trial_index integer NOT NULL CHECK (trial_index BETWEEN 0 AND 1000),
    seed bigint NOT NULL,
    scenario_scope uuid NOT NULL UNIQUE,
    scenario_kind text NOT NULL DEFAULT 'scenario' CHECK (scenario_kind = 'scenario'),
    invocation_scope uuid,
    invocation_kind text NOT NULL DEFAULT 'invocation' CHECK (invocation_kind = 'invocation'),
    state text NOT NULL CHECK (state IN ('scheduled', 'running', 'finalized')),
    owner_token uuid,
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    result_id uuid UNIQUE,
    UNIQUE (evaluation_run_id, task_id, trial_index),
    UNIQUE (id, evaluation_run_id, task_id, trial_index, seed, state),
    FOREIGN KEY (evaluation_run_id, study_scope, config_sha256)
        REFERENCES evaluation.evaluation_runs (id, study_scope, config_sha256),
    FOREIGN KEY (scenario_scope, scenario_kind, study_scope)
        REFERENCES evaluation.budget_scopes (id, kind, parent_id),
    FOREIGN KEY (scenario_scope, study_scope, task_id, trial_index, config_sha256)
        REFERENCES evaluation.budget_scopes (id, parent_id, task_id, trial_index, config_sha256),
    FOREIGN KEY (invocation_scope, invocation_kind, study_scope)
        REFERENCES evaluation.budget_scopes (id, kind, parent_id),
    CHECK (started_at >= created_at AND finished_at >= coalesce(started_at, created_at)),
    CHECK ((state = 'scheduled' AND owner_token IS NULL AND invocation_scope IS NULL
            AND started_at IS NULL AND finished_at IS NULL AND result_id IS NULL)
        OR (state = 'running' AND owner_token IS NOT NULL AND invocation_scope IS NOT NULL
            AND started_at IS NOT NULL AND finished_at IS NULL AND result_id IS NULL)
        OR (state = 'finalized' AND finished_at IS NOT NULL AND result_id IS NOT NULL AND result_id = id
            AND ((owner_token IS NULL AND invocation_scope IS NULL AND started_at IS NULL)
              OR (owner_token IS NOT NULL AND invocation_scope IS NOT NULL AND started_at IS NOT NULL)))),
    FOREIGN KEY (result_id) REFERENCES evaluation.evaluation_trials (id) DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO evaluation.budget_scopes
    (id, kind, parent_id, parent_kind, task_id, trial_index, config_sha256,
     cap_usd, cap_calls, cap_counts, created_at, updated_at)
SELECT gen_random_uuid(), 'scenario', r.study_scope, 'study', t.task_id, t.trial_index, r.config_sha256,
       greatest(coalesce(t.cost_usd, 0), 1), 200, 200, t.created_at, t.created_at
FROM evaluation.evaluation_trials t JOIN evaluation.evaluation_runs r ON r.id = t.evaluation_run_id;
INSERT INTO evaluation.trial_claims
    (id, evaluation_run_id, study_scope, config_sha256, task_id, trial_index, seed,
     scenario_scope, state, created_at, finished_at, result_id)
SELECT t.id, r.id, r.study_scope, r.config_sha256, t.task_id, t.trial_index, t.seed,
       s.id, 'finalized', t.created_at, t.created_at, t.id
FROM evaluation.evaluation_trials t JOIN evaluation.evaluation_runs r ON r.id = t.evaluation_run_id
JOIN evaluation.budget_scopes s ON s.parent_id = r.study_scope AND s.task_id = t.task_id
    AND s.trial_index = t.trial_index AND s.config_sha256 = r.config_sha256;
ALTER TABLE evaluation.evaluation_trials ADD CONSTRAINT evaluation_trials_claim
    FOREIGN KEY (id, evaluation_run_id, task_id, trial_index, seed, claim_state)
    REFERENCES evaluation.trial_claims (id, evaluation_run_id, task_id, trial_index, seed, state)
    DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION evaluation.guard_trial_claim() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, evaluation AS $$
BEGIN
    IF OLD.state = 'finalized' OR NEW.state = 'scheduled'
       OR (OLD.state = 'running' AND NEW.state <> 'finalized')
       OR (OLD.owner_token IS NOT NULL AND
           (NEW.owner_token, NEW.invocation_scope, NEW.started_at) IS DISTINCT FROM
           (OLD.owner_token, OLD.invocation_scope, OLD.started_at)) THEN
        RAISE EXCEPTION 'illegal evaluation claim transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION evaluation.guard_trial_claim() FROM PUBLIC;
CREATE TRIGGER trial_claim_transition BEFORE UPDATE ON evaluation.trial_claims
    FOR EACH ROW EXECUTE FUNCTION evaluation.guard_trial_claim();
GRANT SELECT, INSERT ON evaluation.trial_claims TO policyops_eval_runtime;
GRANT UPDATE (state, owner_token, invocation_scope, started_at, finished_at, result_id)
    ON evaluation.trial_claims TO policyops_eval_runtime;
""")


def downgrade() -> None:
    refuse_data_loss(("evaluation.trial_claims", "evaluation.evaluation_runs"))
    op.execute("""
ALTER TABLE evaluation.evaluation_trials DROP CONSTRAINT evaluation_trials_claim;
DROP TABLE evaluation.trial_claims;
DROP FUNCTION evaluation.guard_trial_claim();
ALTER TABLE evaluation.budget_scopes DROP CONSTRAINT eval_budget_scopes_slot_binding;
ALTER TABLE evaluation.evaluation_trials DROP CONSTRAINT evaluation_trials_identity,
    DROP CONSTRAINT evaluation_trials_error_reward, DROP COLUMN result_sha256, DROP COLUMN claim_state;
ALTER TABLE evaluation.evaluation_runs DROP CONSTRAINT evaluation_runs_study,
    DROP CONSTRAINT evaluation_runs_study_config, DROP CONSTRAINT evaluation_runs_binding,
    DROP COLUMN study_kind, DROP COLUMN study_scope;
""")
