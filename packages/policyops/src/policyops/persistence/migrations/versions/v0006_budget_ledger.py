"""Budget scopes and the per-attempt usage ledger (T10). Forward-only.

* `app.budget_scopes`: one aggregate budget per workbench run (kind `run`) or per non-run operation (kind
  `operation`, such as a future ingestion job; no fake run). It holds server-set caps and the exact counters:
  spent, held, consumed calls and held calls. `overrun` records a truthful settlement above the cap and blocks new
  holds. Workspace RLS is forced.
* `app.usage_attempts`: one row per accounted provider request (a retry is a new row). It holds the internal attempt
  ID, the optional real provider request ID, the immutable intent (with the digest of the full server-owned actor
  configuration) and its digest, the reservation, and the state
  (`reserved | dispatching | released | settled | unresolved`). Settled usage and cost are kept with the original
  price revision and tier. A provider request ID belongs to at most one attempt. Workspace RLS is forced.
* `app.usage_events`: the provider request ID becomes optional and a new event may name its attempt instead (unique
  per workspace). Legacy rows, which have a provider request ID, keep their exact replay key.
* `evaluation.budget_scopes`: study, invocation and scenario scopes, written by the eval runtime only. A scenario and
  an invocation must belong to a study (composite keys). The eval schema stays a trusted offline schema without RLS.
* `evaluation.usage_attempts`: the eval ledger. Each attempt names its study, invocation and scenario, and the
  composite keys require both the scenario and the invocation to belong to that study.

The legacy `app.usage_reservations` is left as it is; nothing writes it. The downgrade is refused while the new
tables hold rows.

Revision ID: 0006
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

APP, EVAL = "policyops_app_runtime", "policyops_eval_runtime"
SHA = "~ '^[0-9a-f]{64}$'"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"
STATES = "('reserved', 'dispatching', 'released', 'settled', 'unresolved')"
ACTORS = "('agent', 'simulator', 'judge', 'reranker', 'embedding')"
CACHE_MODES = "('none', '30m', '12h', '5m', '1h')"


def usd(column: str, constraint: str) -> str:
    return (f"CONSTRAINT {constraint} CHECK ({column} <> 'NaN'::numeric AND {column} >= 0 AND {column} < 1000000 "
            f"AND scale({column}) <= 18)")


def counters(prefix: str) -> str:
    return f"""
    cap_usd numeric NOT NULL {usd("cap_usd", prefix + "_cap_usd_exact")},
    cap_calls integer NOT NULL CONSTRAINT {prefix}_cap_calls_positive CHECK (cap_calls >= 1),
    spent_usd numeric NOT NULL DEFAULT 0 {usd("spent_usd", prefix + "_spent_usd_exact")},
    held_usd numeric NOT NULL DEFAULT 0 {usd("held_usd", prefix + "_held_usd_exact")},
    calls_consumed integer NOT NULL DEFAULT 0
        CONSTRAINT {prefix}_calls_consumed_nonnegative CHECK (calls_consumed >= 0),
    calls_held integer NOT NULL DEFAULT 0 CONSTRAINT {prefix}_calls_held_nonnegative CHECK (calls_held >= 0),
    overrun boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CONSTRAINT {prefix}_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT {prefix}_version_positive CHECK (version >= 1),
    CONSTRAINT {prefix}_calls_within_cap CHECK (calls_consumed + calls_held <= cap_calls)"""


def attempt_columns(prefix: str) -> str:
    return f"""
    actor text NOT NULL CONSTRAINT {prefix}_actor_values CHECK (actor IN {ACTORS}),
    provider text NOT NULL CONSTRAINT {prefix}_provider_format CHECK (provider {SLUG}),
    model text NOT NULL CONSTRAINT {prefix}_model_length CHECK (char_length(model) BETWEEN 1 AND 200),
    price_revision text NOT NULL CONSTRAINT {prefix}_price_revision_length
        CHECK (char_length(price_revision) BETWEEN 1 AND 100),
    config_sha256 text NOT NULL CONSTRAINT {prefix}_config_digest CHECK (config_sha256 {SHA}),
    cache_mode text NOT NULL CONSTRAINT {prefix}_cache_mode_values CHECK (cache_mode IN {CACHE_MODES}),
    max_input integer NOT NULL CONSTRAINT {prefix}_max_input_positive CHECK (max_input >= 1),
    max_output integer NOT NULL CONSTRAINT {prefix}_max_output_nonnegative CHECK (max_output >= 0),
    operation_id text NOT NULL CONSTRAINT {prefix}_operation_length CHECK (char_length(operation_id) BETWEEN 1 AND 200),
    intent_sha256 text NOT NULL CONSTRAINT {prefix}_intent_digest CHECK (intent_sha256 {SHA}),
    reserved_usd numeric NOT NULL {usd("reserved_usd", prefix + "_reserved_usd_exact")},
    state text NOT NULL CONSTRAINT {prefix}_state_values CHECK (state IN {STATES}),
    provider_request_id text CONSTRAINT {prefix}_provider_request_length
        CHECK (char_length(provider_request_id) BETWEEN 1 AND 200),
    usage jsonb CONSTRAINT {prefix}_usage_size CHECK (pg_column_size(usage) <= 4096),
    usage_sha256 text CONSTRAINT {prefix}_usage_digest CHECK (usage_sha256 {SHA}),
    actual_tier text CONSTRAINT {prefix}_actual_tier_format CHECK (actual_tier {SLUG}),
    actual_usd numeric {usd("actual_usd", prefix + "_actual_usd_exact")},
    overrun boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CONSTRAINT {prefix}_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT {prefix}_version_positive CHECK (version >= 1),
    CONSTRAINT {prefix}_settled_has_usage CHECK ((state = 'settled') = (usage IS NOT NULL AND usage_sha256 IS NOT NULL
        AND actual_tier IS NOT NULL AND actual_usd IS NOT NULL)),
    CONSTRAINT {prefix}_overrun_only_settled CHECK (NOT overrun OR state = 'settled')"""


ATTEMPT_UPDATE = ("state, provider_request_id, usage, usage_sha256, actual_tier, actual_usd, overrun, updated_at, "
                  "version")
SCOPE_UPDATE = "spent_usd, held_usd, calls_consumed, calls_held, overrun, updated_at, version"

APP_SQL = rf"""
CREATE TABLE app.budget_scopes (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    kind text NOT NULL CONSTRAINT budget_scopes_kind_values CHECK (kind IN ('run', 'operation')),
    run_id uuid,
    operation_kind text CONSTRAINT budget_scopes_operation_kind_format CHECK (operation_kind {SLUG}),
    operation_key text CONSTRAINT budget_scopes_operation_key_length
        CHECK (char_length(operation_key) BETWEEN 1 AND 200),
    {counters("budget_scopes")},
    CONSTRAINT budget_scopes_kind_binding CHECK (((kind = 'run') = (run_id IS NOT NULL))
        AND ((kind = 'operation') = (operation_kind IS NOT NULL AND operation_key IS NOT NULL))),
    CONSTRAINT budget_scopes_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT budget_scopes_run_unique UNIQUE (workspace_id, run_id),
    CONSTRAINT budget_scopes_operation_unique UNIQUE (workspace_id, operation_kind, operation_key),
    CONSTRAINT budget_scopes_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id)
);
CREATE TABLE app.usage_attempts (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    {attempt_columns("usage_attempts")},
    CONSTRAINT usage_attempts_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT usage_attempts_scope FOREIGN KEY (workspace_id, scope_id) REFERENCES app.budget_scopes (workspace_id, id)
);
CREATE INDEX usage_attempts_scope_state ON app.usage_attempts (workspace_id, scope_id, state);
-- One provider request ID belongs to one attempt (a reused ID is a conflict, never a second settlement).
CREATE UNIQUE INDEX usage_attempts_provider_request ON app.usage_attempts
    (workspace_id, provider, provider_request_id);
ALTER TABLE app.usage_events
    ALTER COLUMN provider_request_id DROP NOT NULL,
    ADD COLUMN attempt_id uuid,
    ADD CONSTRAINT usage_events_attempt_unique UNIQUE (workspace_id, attempt_id),
    ADD CONSTRAINT usage_events_attempt FOREIGN KEY (workspace_id, attempt_id)
        REFERENCES app.usage_attempts (workspace_id, id),
    ADD CONSTRAINT usage_events_identity CHECK (attempt_id IS NOT NULL OR provider_request_id IS NOT NULL);
"""

EVAL_SQL = rf"""
CREATE TABLE evaluation.budget_scopes (
    id uuid PRIMARY KEY,
    kind text NOT NULL CONSTRAINT eval_budget_scopes_kind_values CHECK (kind IN ('study', 'invocation', 'scenario')),
    parent_id uuid,
    parent_kind text CONSTRAINT eval_budget_scopes_parent_is_study CHECK (parent_kind = 'study'),
    study_key text CONSTRAINT eval_budget_scopes_study_key_length CHECK (char_length(study_key) BETWEEN 1 AND 200),
    manifest_sha256 text CONSTRAINT eval_budget_scopes_manifest_digest CHECK (manifest_sha256 {SHA}),
    task_id text CONSTRAINT eval_budget_scopes_task_length CHECK (char_length(task_id) BETWEEN 1 AND 100),
    trial_index integer CONSTRAINT eval_budget_scopes_trial_bounds CHECK (trial_index BETWEEN 0 AND 1000),
    config_sha256 text CONSTRAINT eval_budget_scopes_config_digest CHECK (config_sha256 {SHA}),
    {counters("eval_budget_scopes")},
    CONSTRAINT eval_budget_scopes_kind_binding CHECK (
        (kind = 'study' AND parent_id IS NULL AND parent_kind IS NULL AND study_key IS NOT NULL
         AND manifest_sha256 IS NOT NULL AND task_id IS NULL)
        OR (kind = 'invocation' AND parent_id IS NOT NULL AND parent_kind = 'study' AND study_key IS NULL
            AND task_id IS NULL)
        OR (kind = 'scenario' AND parent_id IS NOT NULL AND parent_kind = 'study' AND study_key IS NULL
            AND task_id IS NOT NULL AND trial_index IS NOT NULL AND config_sha256 IS NOT NULL)),
    CONSTRAINT eval_budget_scopes_id_kind_unique UNIQUE (id, kind),
    CONSTRAINT eval_budget_scopes_child_unique UNIQUE (id, kind, parent_id),
    CONSTRAINT eval_budget_scopes_study_unique UNIQUE (study_key),
    CONSTRAINT eval_budget_scopes_scenario_unique UNIQUE (parent_id, task_id, trial_index, config_sha256),
    CONSTRAINT eval_budget_scopes_parent FOREIGN KEY (parent_id, parent_kind)
        REFERENCES evaluation.budget_scopes (id, kind)
);
CREATE TABLE evaluation.usage_attempts (
    id uuid PRIMARY KEY,
    study_scope_id uuid NOT NULL,
    study_kind text NOT NULL DEFAULT 'study' CONSTRAINT eval_usage_attempts_study_kind CHECK (study_kind = 'study'),
    invocation_scope_id uuid NOT NULL,
    invocation_kind text NOT NULL DEFAULT 'invocation'
        CONSTRAINT eval_usage_attempts_invocation_kind CHECK (invocation_kind = 'invocation'),
    scenario_scope_id uuid NOT NULL,
    scenario_kind text NOT NULL DEFAULT 'scenario'
        CONSTRAINT eval_usage_attempts_scenario_kind CHECK (scenario_kind = 'scenario'),
    {attempt_columns("eval_usage_attempts")},
    -- The invocation and the scenario both belong to the attempt's study.
    CONSTRAINT eval_usage_attempts_study FOREIGN KEY (study_scope_id, study_kind)
        REFERENCES evaluation.budget_scopes (id, kind),
    CONSTRAINT eval_usage_attempts_invocation FOREIGN KEY (invocation_scope_id, invocation_kind, study_scope_id)
        REFERENCES evaluation.budget_scopes (id, kind, parent_id),
    CONSTRAINT eval_usage_attempts_scenario FOREIGN KEY (scenario_scope_id, scenario_kind, study_scope_id)
        REFERENCES evaluation.budget_scopes (id, kind, parent_id)
);
CREATE UNIQUE INDEX eval_usage_attempts_provider_request ON evaluation.usage_attempts
    (provider, provider_request_id);
CREATE INDEX eval_usage_attempts_study_state ON evaluation.usage_attempts (study_scope_id, state);
GRANT SELECT, INSERT ON evaluation.budget_scopes, evaluation.usage_attempts TO {EVAL};
GRANT UPDATE ({SCOPE_UPDATE}) ON evaluation.budget_scopes TO {EVAL};
GRANT UPDATE ({ATTEMPT_UPDATE}) ON evaluation.usage_attempts TO {EVAL};
"""


def app_rls(table: str, name: str) -> str:
    return (f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; "
            f"CREATE POLICY {name}_app_workspace ON {table} TO {APP} "
            "USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());")


def upgrade() -> None:
    op.execute(APP_SQL)
    op.execute(app_rls("app.budget_scopes", "budget_scopes"))
    op.execute(app_rls("app.usage_attempts", "usage_attempts"))
    op.execute(f"GRANT SELECT, INSERT ON app.budget_scopes, app.usage_attempts TO {APP}; "
               f"GRANT UPDATE ({SCOPE_UPDATE}) ON app.budget_scopes TO {APP}; "
               f"GRANT UPDATE ({ATTEMPT_UPDATE}) ON app.usage_attempts TO {APP};")
    op.execute(EVAL_SQL)


def downgrade() -> None:
    # Dropping the ledger loses holds, consumed calls and settled costs: refuse while it holds rows (by default).
    # Every attempt-linked event references an attempt, so on that path no such event exists.
    refuse_data_loss(("app.budget_scopes", "app.usage_attempts", "evaluation.budget_scopes",
                      "evaluation.usage_attempts"))
    # With allow_data_loss=True they may exist. An event that names only its attempt cannot satisfy the restored
    # NOT NULL provider request ID: delete exactly those (an event with a provider request ID is kept as a legacy
    # row). The migrator sees no tenant rows under FORCE, so a forced table is unforced for the delete and forced again
    # in this transaction; an unforced one stays unforced (its previous state is restored exactly).
    forced = op.get_bind().exec_driver_sql(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid = 'app.usage_events'::regclass").scalar()
    if forced:
        op.execute("ALTER TABLE app.usage_events NO FORCE ROW LEVEL SECURITY")
    op.execute("DELETE FROM app.usage_events WHERE provider_request_id IS NULL")
    if forced:
        op.execute("ALTER TABLE app.usage_events FORCE ROW LEVEL SECURITY")
    op.execute("DROP TABLE evaluation.usage_attempts; DROP TABLE evaluation.budget_scopes")
    op.execute("ALTER TABLE app.usage_events DROP CONSTRAINT usage_events_identity, "
               "DROP CONSTRAINT usage_events_attempt, DROP CONSTRAINT usage_events_attempt_unique, "
               "DROP COLUMN attempt_id, ALTER COLUMN provider_request_id SET NOT NULL")
    op.execute("DROP TABLE app.usage_attempts; DROP TABLE app.budget_scopes")
