"""Embedding foundation (T12): jobs, their exact inputs, frozen batches, per-attempt evidence and the vector cache.
Forward-only.

* `app.embedding_jobs`: one job per `(workspace, purpose, subject_key)`. It records the identity of the full intended
  ordered input set, the request configuration and the tokenizer, and an immutable execution deadline fixed when the
  job is created (a restart never extends it). The same subject with any other identity is a conflict, never a silent
  reuse. The runtime may update only `state`, `version` and `updated_at`.
* `app.embedding_job_inputs`: every intended input by position, with its exact text and local token count. A CHECK
  ties `input_sha256` to the text bytes. Select and insert only.
* `app.embedding_batches`: the frozen dispatch plan (the ordered input positions of each physical request, its
  request fingerprint, local token total, operation ID and ledger attempt ID). The runtime may update only the
  advancement and lease columns (`state`, `lease_owner`, `lease_until`, `fence`, `updated_at`); the plan itself is
  immutable.
* `app.embedding_attempt_evidence`: at most one row per accounted physical request that returned parseable billing
  (model and usage), with the ordered input digests, the request fingerprint, the raw response digest, the outcome and
  each vector's norm (a diagnostic; exact decimals, never a floating-point column). It references both the batch and
  the ledger attempt. Select and insert only.
* `app.embedding_cache`: the first validated vector per `(workspace, exact input digest, request configuration)`,
  referencing the evidence row that published it. Select and insert only (first write wins); never updated, deleted
  or shared across workspaces.

All five tables use composite workspace keys and forced workspace RLS for the app runtime. No function is added.
Multi-part CHECKs are written as flat ANDs (no BETWEEN inside an AND), so their stored definitions are identical after
a dump and restore.
The downgrade is refused while any of them holds rows (by default).

Revision ID: 0009
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

APP = "policyops_app_runtime"
SHA = "~ '^[0-9a-f]{64}$'"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"
BATCH_STATES = ("('planned', 'satisfied_by_cache', 'published', 'vectors_invalid', 'blocked', 'unresolved', "
                "'orphaned')")
OUTCOMES = "('published', 'vectors_invalid', 'count_mismatch', 'usage_contradiction', 'model_mismatch')"

TABLES = ("app.embedding_jobs", "app.embedding_job_inputs", "app.embedding_batches",
          "app.embedding_attempt_evidence", "app.embedding_cache")
GRANTS = {
    "app.embedding_jobs": "SELECT, INSERT, UPDATE (state, version, updated_at)",
    "app.embedding_job_inputs": "SELECT, INSERT",
    "app.embedding_batches": "SELECT, INSERT, UPDATE (state, lease_owner, lease_until, fence, updated_at)",
    "app.embedding_attempt_evidence": "SELECT, INSERT",
    "app.embedding_cache": "SELECT, INSERT",
}

SQL = rf"""
CREATE TABLE app.embedding_jobs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    purpose text NOT NULL CONSTRAINT embedding_jobs_purpose_format CHECK (purpose {SLUG}),
    subject_key text NOT NULL CONSTRAINT embedding_jobs_subject_length
        CHECK (char_length(subject_key) BETWEEN 1 AND 200),
    input_set_sha256 text NOT NULL CONSTRAINT embedding_jobs_input_set_digest CHECK (input_set_sha256 {SHA}),
    input_count integer NOT NULL CONSTRAINT embedding_jobs_input_count CHECK (input_count BETWEEN 0 AND 10000),
    request_config_sha256 text NOT NULL CONSTRAINT embedding_jobs_config_digest CHECK (request_config_sha256 {SHA}),
    tokenizer_sha256 text NOT NULL CONSTRAINT embedding_jobs_tokenizer_digest CHECK (tokenizer_sha256 {SHA}),
    state text NOT NULL CONSTRAINT embedding_jobs_state_values
        CHECK (state IN ('running', 'complete', 'blocked', 'incomplete')),
    created_at timestamptz NOT NULL,
    deadline_at timestamptz NOT NULL CONSTRAINT embedding_jobs_deadline_after_created CHECK (deadline_at > created_at),
    updated_at timestamptz NOT NULL CONSTRAINT embedding_jobs_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT embedding_jobs_version_positive CHECK (version >= 1),
    CONSTRAINT embedding_jobs_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT embedding_jobs_subject_unique UNIQUE (workspace_id, purpose, subject_key)
);
CREATE TABLE app.embedding_job_inputs (
    workspace_id uuid NOT NULL,
    job_id uuid NOT NULL,
    position integer NOT NULL CONSTRAINT embedding_job_inputs_position CHECK (position BETWEEN 0 AND 9999),
    input_sha256 text NOT NULL CONSTRAINT embedding_job_inputs_digest CHECK (input_sha256 {SHA}),
    text text NOT NULL CONSTRAINT embedding_job_inputs_text_size
        CHECK (char_length(text) >= 1 AND char_length(text) <= 32768 AND octet_length(text) <= 65536),
    local_tokens integer NOT NULL CONSTRAINT embedding_job_inputs_tokens CHECK (local_tokens BETWEEN 1 AND 8192),
    CONSTRAINT embedding_job_inputs_text_digest
        CHECK (input_sha256 = encode(sha256(convert_to(text, 'UTF8')), 'hex')),
    CONSTRAINT embedding_job_inputs_pkey PRIMARY KEY (workspace_id, job_id, position),
    CONSTRAINT embedding_job_inputs_job FOREIGN KEY (workspace_id, job_id)
        REFERENCES app.embedding_jobs (workspace_id, id)
);
CREATE INDEX embedding_job_inputs_digest_idx ON app.embedding_job_inputs (workspace_id, job_id, input_sha256);
CREATE TABLE app.embedding_batches (
    workspace_id uuid NOT NULL,
    job_id uuid NOT NULL,
    ordinal integer NOT NULL CONSTRAINT embedding_batches_ordinal CHECK (ordinal BETWEEN 0 AND 9999),
    positions integer[] NOT NULL CONSTRAINT embedding_batches_positions
        CHECK (array_ndims(positions) = 1 AND cardinality(positions) >= 1 AND cardinality(positions) <= 64
               AND array_position(positions, NULL) IS NULL),
    batch_sha256 text NOT NULL CONSTRAINT embedding_batches_batch_digest CHECK (batch_sha256 {SHA}),
    request_sha256 text NOT NULL CONSTRAINT embedding_batches_request_digest CHECK (request_sha256 {SHA}),
    local_tokens integer NOT NULL CONSTRAINT embedding_batches_tokens CHECK (local_tokens BETWEEN 1 AND 8192),
    operation_id text NOT NULL CONSTRAINT embedding_batches_operation_length
        CHECK (char_length(operation_id) BETWEEN 1 AND 200),
    attempt_id uuid NOT NULL,
    state text NOT NULL CONSTRAINT embedding_batches_state_values CHECK (state IN {BATCH_STATES}),
    lease_owner uuid,
    lease_until timestamptz,
    fence bigint NOT NULL DEFAULT 0 CONSTRAINT embedding_batches_fence_nonnegative CHECK (fence >= 0),
    updated_at timestamptz NOT NULL,
    CONSTRAINT embedding_batches_lease_pair CHECK ((lease_owner IS NULL) = (lease_until IS NULL)),
    CONSTRAINT embedding_batches_pkey PRIMARY KEY (workspace_id, job_id, ordinal),
    CONSTRAINT embedding_batches_batch_unique UNIQUE (workspace_id, job_id, batch_sha256),
    CONSTRAINT embedding_batches_attempt_unique UNIQUE (workspace_id, attempt_id),
    CONSTRAINT embedding_batches_identity_unique UNIQUE (workspace_id, job_id, ordinal, attempt_id),
    CONSTRAINT embedding_batches_job FOREIGN KEY (workspace_id, job_id) REFERENCES app.embedding_jobs (workspace_id, id)
);
CREATE TABLE app.embedding_attempt_evidence (
    workspace_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    job_id uuid NOT NULL,
    ordinal integer NOT NULL,
    request_sha256 text NOT NULL CONSTRAINT embedding_evidence_request_digest CHECK (request_sha256 {SHA}),
    input_digests text[] NOT NULL CONSTRAINT embedding_evidence_inputs
        CHECK (array_ndims(input_digests) = 1 AND cardinality(input_digests) >= 1 AND cardinality(input_digests) <= 64
               AND array_position(input_digests, NULL) IS NULL),
    returned_model text NOT NULL CONSTRAINT embedding_evidence_model_length
        CHECK (char_length(returned_model) BETWEEN 1 AND 100),
    prompt_tokens integer NOT NULL CONSTRAINT embedding_evidence_prompt_nonnegative CHECK (prompt_tokens >= 0),
    total_tokens integer NOT NULL CONSTRAINT embedding_evidence_total_nonnegative CHECK (total_tokens >= 0),
    provider_request_id text CONSTRAINT embedding_evidence_request_id_length
        CHECK (char_length(provider_request_id) BETWEEN 1 AND 200),
    response_sha256 text NOT NULL CONSTRAINT embedding_evidence_response_digest CHECK (response_sha256 {SHA}),
    norms numeric[] CONSTRAINT embedding_evidence_norms
        CHECK (norms IS NULL OR (array_ndims(norms) = 1 AND cardinality(norms) = cardinality(input_digests))),
    outcome text NOT NULL CONSTRAINT embedding_evidence_outcome_values CHECK (outcome IN {OUTCOMES}),
    created_at timestamptz NOT NULL,
    CONSTRAINT embedding_evidence_consistent_usage
        CHECK ((outcome = 'usage_contradiction') = (prompt_tokens <> total_tokens)),
    CONSTRAINT embedding_evidence_published_norms CHECK (outcome <> 'published' OR norms IS NOT NULL),
    CONSTRAINT embedding_evidence_pkey PRIMARY KEY (workspace_id, attempt_id),
    CONSTRAINT embedding_evidence_batch FOREIGN KEY (workspace_id, job_id, ordinal, attempt_id)
        REFERENCES app.embedding_batches (workspace_id, job_id, ordinal, attempt_id),
    CONSTRAINT embedding_evidence_attempt FOREIGN KEY (workspace_id, attempt_id)
        REFERENCES app.usage_attempts (workspace_id, id)
);
CREATE TABLE app.embedding_cache (
    workspace_id uuid NOT NULL,
    input_sha256 text NOT NULL CONSTRAINT embedding_cache_input_digest CHECK (input_sha256 {SHA}),
    request_config_sha256 text NOT NULL CONSTRAINT embedding_cache_config_digest CHECK (request_config_sha256 {SHA}),
    attempt_id uuid NOT NULL,
    vector vector(1536) NOT NULL CONSTRAINT embedding_cache_dimensions CHECK (vector_dims(vector) = 1536),
    created_at timestamptz NOT NULL,
    CONSTRAINT embedding_cache_pkey PRIMARY KEY (workspace_id, input_sha256, request_config_sha256),
    CONSTRAINT embedding_cache_evidence FOREIGN KEY (workspace_id, attempt_id)
        REFERENCES app.embedding_attempt_evidence (workspace_id, attempt_id)
);
"""


def upgrade() -> None:
    op.execute(SQL)
    for table in TABLES:
        name = table.split(".")[1]
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; "
                   f"CREATE POLICY {name}_app_workspace ON {table} TO {APP} "
                   "USING (workspace_id = app.current_workspace()) "
                   "WITH CHECK (workspace_id = app.current_workspace()); "
                   f"GRANT {GRANTS[table]} ON {table} TO {APP}")


def downgrade() -> None:
    refuse_data_loss(TABLES)
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE {table}")
