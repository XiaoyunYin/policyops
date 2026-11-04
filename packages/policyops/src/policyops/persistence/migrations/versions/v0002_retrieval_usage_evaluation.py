"""Retrieval (index generations, chunks, traces, citations), usage ledger, evaluation schema, checkpoint schema.

USD amounts (PLAN D2) are unconstrained NUMERIC with explicit CHECKs: finite (no NaN; the range check excludes
infinities), non-negative, below 10^6 and at most 18 fractional digits. A fixed NUMERIC(p, s) is deliberately not
used: PostgreSQL rounds a value to the column's scale before any CHECK runs, so excess precision would be silently
rounded instead of rejected. Unknown costs are NULL with an explicit cost_status, never zero.

Evaluation tables (PLAN D5) live in their own schema, written by policyops_eval_runtime only; the app runtime has
no grant there. The checkpoint schema (PLAN D4) is created empty: ownership and USAGE only. T21 owns its DDL.

Revision ID: 0002
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

APP, EVAL = "policyops_app_runtime", "policyops_eval_runtime"
SHA = "~ '^[0-9a-f]{64}$'"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"


def usd(column: str, constraint: str) -> str:
    return (f"CONSTRAINT {constraint} CHECK ({column} <> 'NaN'::numeric AND {column} >= 0 AND {column} < 1000000 "
            f"AND scale({column}) <= 18)")


RETRIEVAL = rf"""
CREATE TABLE app.index_generations (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    policy_sha256 text NOT NULL CONSTRAINT index_generations_policy_digest CHECK (policy_sha256 {SHA}),
    parser_version text NOT NULL CONSTRAINT index_generations_parser_length
        CHECK (char_length(parser_version) BETWEEN 1 AND 100),
    embedding_model text NOT NULL CONSTRAINT index_generations_model_length
        CHECK (char_length(embedding_model) BETWEEN 1 AND 200),
    dimension integer NOT NULL CONSTRAINT index_generations_dimension CHECK (dimension = 1536),
    status text NOT NULL CONSTRAINT index_generations_status_values
        CHECK (status IN ('building', 'ready', 'failed', 'retired')),
    created_at timestamptz NOT NULL,
    ready_at timestamptz CONSTRAINT index_generations_ready_after_created CHECK (ready_at >= created_at),
    CONSTRAINT index_generations_ready_time CHECK (status NOT IN ('ready', 'retired') OR ready_at IS NOT NULL),
    CONSTRAINT index_generations_workspace_id_unique UNIQUE (workspace_id, id)
);
CREATE TABLE app.chunks (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    parent_id uuid,
    heading text NOT NULL CONSTRAINT chunks_heading_length CHECK (char_length(heading) <= 500),
    start_offset integer NOT NULL CONSTRAINT chunks_start_nonnegative CHECK (start_offset >= 0),
    end_offset integer NOT NULL,
    text text NOT NULL CONSTRAINT chunks_text_length CHECK (char_length(text) BETWEEN 1 AND 20000),
    sha256 text NOT NULL CONSTRAINT chunks_digest CHECK (sha256 {SHA}),
    tsv tsvector GENERATED ALWAYS AS (to_tsvector('english'::regconfig, text)) STORED,
    embedding public.vector(1536),
    created_at timestamptz NOT NULL,
    CONSTRAINT chunks_offsets CHECK (end_offset > start_offset),
    CONSTRAINT chunks_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT chunks_generation FOREIGN KEY (workspace_id, generation_id)
        REFERENCES app.index_generations (workspace_id, id),
    CONSTRAINT chunks_document_version FOREIGN KEY (workspace_id, document_version_id)
        REFERENCES app.document_versions (workspace_id, id),
    CONSTRAINT chunks_parent FOREIGN KEY (workspace_id, parent_id) REFERENCES app.chunks (workspace_id, id)
);
CREATE INDEX chunks_generation_idx ON app.chunks (workspace_id, generation_id);
CREATE INDEX chunks_tsv ON app.chunks USING gin (tsv);
CREATE TABLE app.retrieval_traces (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    run_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    query_sha256 text NOT NULL CONSTRAINT retrieval_traces_query_digest CHECK (query_sha256 {SHA}),
    authorized_scope jsonb NOT NULL CONSTRAINT retrieval_traces_scope_size
        CHECK (pg_column_size(authorized_scope) <= 8192),
    candidates jsonb NOT NULL CONSTRAINT retrieval_traces_candidates_size CHECK (pg_column_size(candidates) <= 65536),
    final_chunk_ids uuid[] NOT NULL CONSTRAINT retrieval_traces_final_bounds
        CHECK (cardinality(final_chunk_ids) <= 64 AND array_position(final_chunk_ids, NULL) IS NULL),
    created_at timestamptz NOT NULL,
    CONSTRAINT retrieval_traces_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT retrieval_traces_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id),
    CONSTRAINT retrieval_traces_generation FOREIGN KEY (workspace_id, generation_id)
        REFERENCES app.index_generations (workspace_id, id)
);
CREATE TABLE app.citations (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    trace_id uuid NOT NULL,
    chunk_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    span_start integer NOT NULL CONSTRAINT citations_span_start_nonnegative CHECK (span_start >= 0),
    span_end integer NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT citations_span CHECK (span_end > span_start),
    CONSTRAINT citations_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT citations_trace FOREIGN KEY (workspace_id, trace_id) REFERENCES app.retrieval_traces (workspace_id, id),
    CONSTRAINT citations_chunk FOREIGN KEY (workspace_id, chunk_id) REFERENCES app.chunks (workspace_id, id),
    CONSTRAINT citations_document_version FOREIGN KEY (workspace_id, document_version_id)
        REFERENCES app.document_versions (workspace_id, id)
);
"""

USAGE = rf"""
CREATE TABLE app.usage_reservations (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    run_id uuid,
    actor text NOT NULL CONSTRAINT usage_reservations_actor_values
        CHECK (actor IN ('agent', 'simulator', 'judge', 'reranker', 'embedding')),
    price_revision text NOT NULL CONSTRAINT usage_reservations_price_revision_length
        CHECK (char_length(price_revision) BETWEEN 1 AND 100),
    reserved_usd numeric NOT NULL {usd("reserved_usd", "usage_reservations_reserved_usd_exact")},
    actual_usd numeric {usd("actual_usd", "usage_reservations_actual_usd_exact")},
    state text NOT NULL CONSTRAINT usage_reservations_state_values
        CHECK (state IN ('reserved', 'reconciled', 'released')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
        CONSTRAINT usage_reservations_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT usage_reservations_version_positive CHECK (version >= 1),
    CONSTRAINT usage_reservations_reconciled_actual CHECK (state <> 'reconciled' OR actual_usd IS NOT NULL),
    CONSTRAINT usage_reservations_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT usage_reservations_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id)
);
CREATE TABLE app.usage_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    reservation_id uuid,
    run_id uuid,
    actor text NOT NULL CONSTRAINT usage_events_actor_values
        CHECK (actor IN ('agent', 'simulator', 'judge', 'reranker', 'embedding')),
    provider text NOT NULL CONSTRAINT usage_events_provider_format CHECK (provider {SLUG}),
    model text NOT NULL CONSTRAINT usage_events_model_length CHECK (char_length(model) BETWEEN 1 AND 200),
    provider_request_id text NOT NULL CONSTRAINT usage_events_request_id_length
        CHECK (char_length(provider_request_id) BETWEEN 1 AND 200),
    uncached_input_tokens bigint NOT NULL CONSTRAINT usage_events_uncached_nonnegative
        CHECK (uncached_input_tokens >= 0),
    cache_read_tokens bigint NOT NULL CONSTRAINT usage_events_cache_read_nonnegative CHECK (cache_read_tokens >= 0),
    cache_write_tokens bigint NOT NULL CONSTRAINT usage_events_cache_write_nonnegative CHECK (cache_write_tokens >= 0),
    output_tokens bigint NOT NULL CONSTRAINT usage_events_output_nonnegative CHECK (output_tokens >= 0),
    reasoning_tokens bigint NOT NULL CONSTRAINT usage_events_reasoning_within_output
        CHECK (reasoning_tokens BETWEEN 0 AND output_tokens),
    price_revision text NOT NULL CONSTRAINT usage_events_price_revision_length
        CHECK (char_length(price_revision) BETWEEN 1 AND 100),
    cost_status text NOT NULL CONSTRAINT usage_events_cost_status_values
        CHECK (cost_status IN ('known', 'estimated', 'unknown')),
    cost_usd numeric {usd("cost_usd", "usage_events_cost_usd_exact")},
    created_at timestamptz NOT NULL,
    CONSTRAINT usage_events_unknown_cost_is_null CHECK ((cost_status = 'unknown') = (cost_usd IS NULL)),
    CONSTRAINT usage_events_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT usage_events_request_unique UNIQUE (workspace_id, provider, provider_request_id),
    CONSTRAINT usage_events_reservation FOREIGN KEY (workspace_id, reservation_id)
        REFERENCES app.usage_reservations (workspace_id, id),
    CONSTRAINT usage_events_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id)
);
"""

EVALUATION = rf"""
CREATE SCHEMA evaluation AUTHORIZATION policyops_app_migrator;
REVOKE ALL ON SCHEMA evaluation FROM PUBLIC;
GRANT USAGE ON SCHEMA evaluation TO {EVAL};
CREATE TABLE evaluation.evaluation_runs (
    id uuid PRIMARY KEY,
    dataset text NOT NULL CONSTRAINT evaluation_runs_dataset_format CHECK (dataset {SLUG}),
    dataset_revision text NOT NULL CONSTRAINT evaluation_runs_revision_format
        CHECK (dataset_revision ~ '^[0-9a-f]{{40}}$'),
    split_id text NOT NULL CONSTRAINT evaluation_runs_split_format CHECK (split_id {SLUG}),
    config_sha256 text NOT NULL CONSTRAINT evaluation_runs_config_digest CHECK (config_sha256 {SHA}),
    config jsonb NOT NULL CONSTRAINT evaluation_runs_config_size CHECK (pg_column_size(config) <= 65536),
    status text NOT NULL CONSTRAINT evaluation_runs_status_values
        CHECK (status IN ('planned', 'running', 'completed', 'aborted')),
    total_cost_usd numeric {usd("total_cost_usd", "evaluation_runs_total_cost_exact")},
    created_at timestamptz NOT NULL,
    started_at timestamptz CONSTRAINT evaluation_runs_started_after_created CHECK (started_at >= created_at),
    finished_at timestamptz CONSTRAINT evaluation_runs_finished_after_started CHECK (finished_at >= started_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT evaluation_runs_version_positive CHECK (version >= 1),
    CONSTRAINT evaluation_runs_finished_state CHECK ((status IN ('completed', 'aborted')) = (finished_at IS NOT NULL))
);
CREATE TABLE evaluation.evaluation_trials (
    id uuid PRIMARY KEY,
    evaluation_run_id uuid NOT NULL REFERENCES evaluation.evaluation_runs (id),
    task_id text NOT NULL CONSTRAINT evaluation_trials_task_length CHECK (char_length(task_id) BETWEEN 1 AND 100),
    trial_index integer NOT NULL CONSTRAINT evaluation_trials_index_bounds CHECK (trial_index BETWEEN 0 AND 1000),
    seed bigint NOT NULL,
    outcome text NOT NULL CONSTRAINT evaluation_trials_outcome_values
        CHECK (outcome IN ('success', 'failure', 'error', 'budget_exceeded', 'aborted')),
    reward numeric CONSTRAINT evaluation_trials_reward_exact
        CHECK (reward <> 'NaN'::numeric AND reward BETWEEN 0 AND 1 AND scale(reward) <= 18),
    components jsonb NOT NULL CONSTRAINT evaluation_trials_components_size CHECK (pg_column_size(components) <= 65536),
    error_class text CONSTRAINT evaluation_trials_error_class_format CHECK (error_class {SLUG}),
    cost_status text NOT NULL CONSTRAINT evaluation_trials_cost_status_values
        CHECK (cost_status IN ('known', 'estimated', 'unknown')),
    cost_usd numeric {usd("cost_usd", "evaluation_trials_cost_usd_exact")},
    latency_ms bigint CONSTRAINT evaluation_trials_latency_nonnegative CHECK (latency_ms >= 0),
    artifact_sha256 text CONSTRAINT evaluation_trials_artifact_digest CHECK (artifact_sha256 {SHA}),
    created_at timestamptz NOT NULL,
    CONSTRAINT evaluation_trials_unknown_cost_is_null CHECK ((cost_status = 'unknown') = (cost_usd IS NULL)),
    CONSTRAINT evaluation_trials_unique UNIQUE (evaluation_run_id, task_id, trial_index)
);
GRANT SELECT, INSERT ON evaluation.evaluation_runs, evaluation.evaluation_trials TO {EVAL};
GRANT UPDATE (status, started_at, finished_at, total_cost_usd, version) ON evaluation.evaluation_runs TO {EVAL};
"""

CHECKPOINTS = rf"""
CREATE SCHEMA checkpoints AUTHORIZATION policyops_app_migrator;
REVOKE ALL ON SCHEMA checkpoints FROM PUBLIC;
GRANT USAGE ON SCHEMA checkpoints TO {APP};
"""

TENANT_TABLES = ("app.index_generations", "app.chunks", "app.retrieval_traces", "app.citations",
                 "app.usage_reservations", "app.usage_events")
APP_GRANTS = {
    "app.index_generations": "SELECT, INSERT, UPDATE (status, ready_at)",
    "app.chunks": "SELECT, INSERT",
    "app.retrieval_traces": "SELECT, INSERT",
    "app.citations": "SELECT, INSERT",
    "app.usage_reservations": "SELECT, INSERT, UPDATE (actual_usd, state, updated_at, version)",
    "app.usage_events": "SELECT, INSERT",
}


def upgrade() -> None:
    for block in (RETRIEVAL, USAGE, EVALUATION, CHECKPOINTS):
        op.execute(block)
    for table in TENANT_TABLES:
        name = table.split(".")[1]
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        if table == "app.chunks":
            # Only chunks of ready generations are retrievable; writing (during a build) is scoped to the workspace.
            op.execute("""
                CREATE POLICY chunks_app_ready ON app.chunks FOR SELECT TO policyops_app_runtime USING (
                    workspace_id = app.current_workspace() AND EXISTS (
                        SELECT 1 FROM app.index_generations g WHERE g.workspace_id = chunks.workspace_id
                        AND g.id = chunks.generation_id AND g.status = 'ready'));
                CREATE POLICY chunks_app_insert ON app.chunks FOR INSERT TO policyops_app_runtime
                    WITH CHECK (workspace_id = app.current_workspace())""")
        else:
            op.execute(f"CREATE POLICY {name}_app_workspace ON {table} TO {APP} "
                       "USING (workspace_id = app.current_workspace()) "
                       "WITH CHECK (workspace_id = app.current_workspace())")
    for table, privileges in APP_GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {APP}")


DROP_ORDER = ("evaluation.evaluation_trials", "evaluation.evaluation_runs", "app.usage_events",
              "app.usage_reservations", "app.citations", "app.retrieval_traces", "app.chunks", "app.index_generations")


def downgrade() -> None:
    refuse_data_loss(DROP_ORDER)
    for table in DROP_ORDER:
        op.execute(f"DROP TABLE {table}")
    op.execute("DROP SCHEMA evaluation")
    op.execute("DROP SCHEMA checkpoints")
