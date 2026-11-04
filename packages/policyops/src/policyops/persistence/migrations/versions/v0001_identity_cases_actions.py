"""Identity, cases/messages, documents, runs/events, proposals/consents/decisions/executions, jobs/outbox, audit.

Conventions (all tables):
* Tenant-owned rows carry `workspace_id NOT NULL` and `UNIQUE (workspace_id, id)`; every tenant relationship is a
  composite foreign key `(workspace_id, x_id)`, so a reference to another workspace's row fails in the database even
  with a valid UUID. Optional links use the default MATCH SIMPLE: a NULL link is no link, and because workspace_id is
  never NULL a non-NULL link is always checked. No cascades; no SET NULL (it would null workspace_id too).
* Global identity (principals) is the explicit exception: referenced by a single-column key.
* Forced row-level security on every tenant table, with role-specific policies on the transaction-local scope
  `app.current_workspace()`. The owning migrator has no data policy, so it sees no tenant rows.
* Append-only tables get INSERT/SELECT only; updatable tables get column-level UPDATE grants. No DELETE grants.
* Bounded text/JSON sizes, explicit CHECKs for every state/role/source value (PLAN D3), integer versions >= 1.

Revision ID: 0001
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

MIGRATOR, APP, AUTH = "policyops_app_migrator", "policyops_app_runtime", "policyops_auth_runtime"
SHA = "~ '^[0-9a-f]{64}$'"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"

TENANT_TABLES = ("app.cases", "app.case_messages", "app.documents", "app.document_versions", "app.runs",
                 "app.run_events", "app.action_proposals", "app.proposal_presentations", "app.customer_consents",
                 "app.approval_decisions", "app.tool_executions", "app.jobs", "app.outbox_events", "app.audit_events")

SCHEMAS = r"""
CREATE SCHEMA identity AUTHORIZATION policyops_app_migrator;
CREATE SCHEMA app AUTHORIZATION policyops_app_migrator;
REVOKE ALL ON SCHEMA identity, app FROM PUBLIC;
GRANT USAGE ON SCHEMA app TO policyops_app_runtime;
GRANT USAGE ON SCHEMA identity TO policyops_app_runtime, policyops_auth_runtime;

-- Transaction-local tenant scope. Unset or empty means no workspace: every policy comparison is NULL (denied).
CREATE FUNCTION app.current_workspace() RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE
    SET search_path = pg_catalog
    AS $$ SELECT nullif(current_setting('policyops.workspace_id', true), '')::uuid $$;
REVOKE ALL ON FUNCTION app.current_workspace() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.current_workspace() TO policyops_app_runtime;
"""

IDENTITY = rf"""
CREATE TABLE identity.workspaces (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE CONSTRAINT workspaces_slug_format CHECK (slug {SLUG}),
    name text NOT NULL CONSTRAINT workspaces_name_length CHECK (char_length(name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 1 CONSTRAINT workspaces_version_positive CHECK (version >= 1)
);
CREATE TABLE identity.principals (
    id uuid PRIMARY KEY,
    issuer text NOT NULL CONSTRAINT principals_issuer_length CHECK (char_length(issuer) BETWEEN 1 AND 500),
    subject text NOT NULL CONSTRAINT principals_subject_length CHECK (char_length(subject) BETWEEN 1 AND 255),
    display_name text NOT NULL
        CONSTRAINT principals_display_name_length CHECK (char_length(display_name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL,
    CONSTRAINT principals_issuer_subject_unique UNIQUE (issuer, subject)
);
CREATE TABLE identity.memberships (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    principal_id uuid NOT NULL REFERENCES identity.principals (id),
    role text NOT NULL CONSTRAINT memberships_role_values CHECK (role IN ('analyst', 'reviewer', 'admin', 'auditor')),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz CONSTRAINT memberships_revoked_after_created CHECK (revoked_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT memberships_version_positive CHECK (version >= 1),
    CONSTRAINT memberships_workspace_id_unique UNIQUE (workspace_id, id)
);
CREATE UNIQUE INDEX memberships_active_unique ON identity.memberships (workspace_id, principal_id, role)
    WHERE revoked_at IS NULL;
CREATE INDEX memberships_principal ON identity.memberships (principal_id) WHERE revoked_at IS NULL;
CREATE TABLE identity.sessions (
    id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES identity.principals (id),
    workspace_id uuid REFERENCES identity.workspaces (id),
    cookie_sha256 text NOT NULL UNIQUE CONSTRAINT sessions_cookie_digest CHECK (cookie_sha256 {SHA}),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CONSTRAINT sessions_expiry_after_creation CHECK (expires_at > created_at),
    rotated_from uuid REFERENCES identity.sessions (id),
    revoked_at timestamptz CONSTRAINT sessions_revoked_after_created CHECK (revoked_at >= created_at)
);
CREATE INDEX sessions_principal ON identity.sessions (principal_id);
"""

CASES = rf"""
CREATE TABLE app.cases (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    scenario text NOT NULL CONSTRAINT cases_scenario_format CHECK (scenario {SLUG}),
    customer_user_id text CONSTRAINT cases_customer_format CHECK (customer_user_id ~ '^[a-z]+(_[a-z]+)*_[0-9]{{1,6}}$'),
    status text NOT NULL CONSTRAINT cases_status_values CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
    created_by uuid REFERENCES identity.principals (id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CONSTRAINT cases_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT cases_version_positive CHECK (version >= 1),
    CONSTRAINT cases_workspace_id_unique UNIQUE (workspace_id, id)
);
CREATE INDEX cases_queue ON app.cases (workspace_id, status, updated_at DESC);
CREATE TABLE app.case_messages (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    sequence bigint NOT NULL CONSTRAINT case_messages_sequence_positive CHECK (sequence >= 1),
    source text NOT NULL CONSTRAINT case_messages_source_values
        CHECK (source IN ('seeded', 'simulated_customer', 'operator_entered_customer', 'staff_note', 'agent')),
    entered_by uuid REFERENCES identity.principals (id),
    text text NOT NULL CONSTRAINT case_messages_text_length CHECK (char_length(text) BETWEEN 1 AND 4000),
    text_sha256 text NOT NULL CONSTRAINT case_messages_text_digest CHECK (text_sha256 {SHA}),
    created_at timestamptz NOT NULL,
    CONSTRAINT case_messages_author_rule
        CHECK ((source IN ('operator_entered_customer', 'staff_note')) = (entered_by IS NOT NULL)),
    CONSTRAINT case_messages_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT case_messages_sequence_unique UNIQUE (workspace_id, case_id, sequence),
    -- Binding keys for presentations and consents (they must name the message's real case/sequence/digest).
    CONSTRAINT case_messages_binding_unique UNIQUE (workspace_id, case_id, id, sequence, text_sha256, source),
    CONSTRAINT case_messages_presented_unique UNIQUE (workspace_id, case_id, id, sequence, text_sha256),
    CONSTRAINT case_messages_author_unique UNIQUE (workspace_id, case_id, id, entered_by),
    CONSTRAINT case_messages_case FOREIGN KEY (workspace_id, case_id) REFERENCES app.cases (workspace_id, id)
);
"""

DOCUMENTS = rf"""
CREATE TABLE app.documents (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    domain text NOT NULL CONSTRAINT documents_domain_format CHECK (domain {SLUG}),
    publisher text NOT NULL CONSTRAINT documents_publisher_length CHECK (char_length(publisher) BETWEEN 1 AND 200),
    source_uri text NOT NULL CONSTRAINT documents_source_uri_length CHECK (char_length(source_uri) BETWEEN 1 AND 2000),
    license text NOT NULL CONSTRAINT documents_license_length CHECK (char_length(license) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL,
    CONSTRAINT documents_workspace_id_unique UNIQUE (workspace_id, id)
);
CREATE TABLE app.document_versions (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    document_id uuid NOT NULL,
    version bigint NOT NULL CONSTRAINT document_versions_version_positive CHECK (version >= 1),
    sha256 text NOT NULL CONSTRAINT document_versions_digest CHECK (sha256 {SHA}),
    body text NOT NULL CONSTRAINT document_versions_body_size CHECK (octet_length(body) BETWEEN 1 AND 4194304),
    status text NOT NULL CONSTRAINT document_versions_status_values CHECK (status IN ('draft', 'active', 'retired')),
    effective_from timestamptz NOT NULL,
    effective_to timestamptz CONSTRAINT document_versions_interval CHECK (effective_to > effective_from),
    created_at timestamptz NOT NULL,
    CONSTRAINT document_versions_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT document_versions_number_unique UNIQUE (workspace_id, document_id, version),
    CONSTRAINT document_versions_content_unique UNIQUE (workspace_id, document_id, sha256),
    CONSTRAINT document_versions_document FOREIGN KEY (workspace_id, document_id)
        REFERENCES app.documents (workspace_id, id)
);
"""

RUNS = rf"""
CREATE TABLE app.runs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    case_version bigint NOT NULL CONSTRAINT runs_case_version_positive CHECK (case_version >= 1),
    mode text NOT NULL CONSTRAINT runs_mode_values CHECK (mode IN ('workbench', 'evaluation')),
    graph_sha256 text NOT NULL CONSTRAINT runs_graph_digest CHECK (graph_sha256 {SHA}),
    prompt_sha256 text NOT NULL CONSTRAINT runs_prompt_digest CHECK (prompt_sha256 {SHA}),
    config_sha256 text NOT NULL CONSTRAINT runs_config_digest CHECK (config_sha256 {SHA}),
    state text NOT NULL CONSTRAINT runs_state_values CHECK (state IN ('queued', 'running', 'waiting_input',
        'waiting_approval', 'reconciling', 'succeeded', 'failed', 'cancelled', 'budget_exceeded')),
    model_calls integer NOT NULL DEFAULT 0 CONSTRAINT runs_model_calls_bounds CHECK (model_calls BETWEEN 0 AND 1000),
    tool_calls integer NOT NULL DEFAULT 0 CONSTRAINT runs_tool_calls_bounds CHECK (tool_calls BETWEEN 0 AND 1000),
    deadline_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CONSTRAINT runs_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT runs_version_positive CHECK (version >= 1),
    CONSTRAINT runs_deadline_after_creation CHECK (deadline_at > created_at),
    CONSTRAINT runs_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT runs_case_unique UNIQUE (workspace_id, case_id, id),
    CONSTRAINT runs_case FOREIGN KEY (workspace_id, case_id) REFERENCES app.cases (workspace_id, id)
);
CREATE INDEX runs_case_time ON app.runs (workspace_id, case_id, created_at);
CREATE TABLE app.run_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    run_id uuid NOT NULL,
    sequence bigint NOT NULL CONSTRAINT run_events_sequence_positive CHECK (sequence >= 1),
    event_type text NOT NULL CONSTRAINT run_events_type_format CHECK (event_type {SLUG}),
    schema_version text NOT NULL CONSTRAINT run_events_schema_format
        CHECK (schema_version ~ '^policyops\.[a-z0-9-]+/v[0-9]+$'),
    payload jsonb NOT NULL CONSTRAINT run_events_payload_size CHECK (pg_column_size(payload) <= 65536),
    occurred_at timestamptz NOT NULL,
    CONSTRAINT run_events_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT run_events_sequence_unique UNIQUE (workspace_id, run_id, sequence),
    CONSTRAINT run_events_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id)
);
"""

ACTIONS = r"""
CREATE TABLE app.action_proposals (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    run_id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    proposal_version bigint NOT NULL CONSTRAINT action_proposals_version_positive CHECK (proposal_version >= 1),
    tool_name text NOT NULL CONSTRAINT action_proposals_tool_format CHECK (tool_name ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    arguments jsonb NOT NULL CONSTRAINT action_proposals_arguments_size CHECK (pg_column_size(arguments) <= 16384),
    action_digest text NOT NULL CONSTRAINT action_proposals_action_digest CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    intent_digest text NOT NULL CONSTRAINT action_proposals_intent_digest CHECK (intent_digest ~ '^[0-9a-f]{64}$'),
    presentation_sha256 text NOT NULL CONSTRAINT action_proposals_presentation_digest
        CHECK (presentation_sha256 ~ '^[0-9a-f]{64}$'),
    -- The complete validated contract (policyops.action-proposal/v1); the columns above are its indexed keys.
    body jsonb NOT NULL CONSTRAINT action_proposals_body_size CHECK (pg_column_size(body) <= 65536),
    policy_sha256 text NOT NULL CONSTRAINT action_proposals_policy_digest CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CONSTRAINT action_proposals_status_values
        CHECK (status IN ('created', 'presented', 'superseded', 'expired')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    presented_at timestamptz,
    CONSTRAINT action_proposals_expiry_ttl
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
    CONSTRAINT action_proposals_presented_window CHECK (presented_at >= created_at AND presented_at < expires_at),
    CONSTRAINT action_proposals_presentation_state CHECK (
        (status <> 'presented' OR presented_at IS NOT NULL) AND (status <> 'created' OR presented_at IS NULL)),
    CONSTRAINT action_proposals_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT action_proposals_identity_unique UNIQUE (workspace_id, proposal_id, proposal_version),
    -- Referenced by presentations (and through them consents and decisions): every later record must name this
    -- proposal's exact case, run, digest and presentation text digest.
    CONSTRAINT action_proposals_scope_binding_unique UNIQUE
        (workspace_id, case_id, run_id, proposal_id, proposal_version, action_digest, presentation_sha256),
    -- The run must belong to this proposal's case (not just to the workspace).
    CONSTRAINT action_proposals_run FOREIGN KEY (workspace_id, case_id, run_id)
        REFERENCES app.runs (workspace_id, case_id, id)
);
CREATE INDEX action_proposals_intent ON app.action_proposals (workspace_id, intent_digest);

-- Bound content never changes; only the presentation time (once) and the forward status move.
CREATE FUNCTION app.guard_action_proposal_update() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (to_jsonb(NEW) - 'status' - 'presented_at') IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'presented_at') THEN
        RAISE EXCEPTION 'action proposal content is immutable' USING ERRCODE = 'P0001';
    END IF;
    IF OLD.presented_at IS NOT NULL AND NEW.presented_at IS DISTINCT FROM OLD.presented_at THEN
        RAISE EXCEPTION 'action proposal presentation time is immutable' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND (OLD.status, NEW.status) NOT IN (
            ('created', 'presented'), ('created', 'superseded'), ('created', 'expired'),
            ('presented', 'superseded'), ('presented', 'expired')) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001',
            MESSAGE = 'action proposal status cannot move from ' || OLD.status || ' to ' || NEW.status;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION app.guard_action_proposal_update() FROM PUBLIC;
CREATE TRIGGER action_proposals_guard BEFORE UPDATE ON app.action_proposals
    FOR EACH ROW EXECUTE FUNCTION app.guard_action_proposal_update();

-- ProposalPresentationRecord: the agent message (case, sequence, text digest) that displayed one proposal version.
CREATE TABLE app.proposal_presentations (
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    run_id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    proposal_version bigint NOT NULL,
    action_digest text NOT NULL,
    presentation_sha256 text NOT NULL,
    message_id uuid NOT NULL,
    message_sequence bigint NOT NULL,
    presented_at timestamptz NOT NULL,
    CONSTRAINT proposal_presentations_pkey PRIMARY KEY (workspace_id, proposal_id, proposal_version),
    CONSTRAINT proposal_presentations_binding_unique UNIQUE (workspace_id, case_id, run_id, proposal_id,
        proposal_version, action_digest, presentation_sha256, message_sequence),
    CONSTRAINT proposal_presentations_proposal FOREIGN KEY (workspace_id, case_id, run_id, proposal_id,
        proposal_version, action_digest, presentation_sha256) REFERENCES app.action_proposals (workspace_id, case_id,
        run_id, proposal_id, proposal_version, action_digest, presentation_sha256),
    -- The displayed message is in the same case, at the recorded sequence, and carries exactly the presentation text.
    CONSTRAINT proposal_presentations_message FOREIGN KEY (workspace_id, case_id, message_id, message_sequence,
        presentation_sha256) REFERENCES app.case_messages (workspace_id, case_id, id, sequence, text_sha256)
);

CREATE TABLE app.customer_consents (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    run_id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    proposal_version bigint NOT NULL,
    action_digest text NOT NULL,
    presentation_sha256 text NOT NULL,
    presented_message_sequence bigint NOT NULL,
    customer_message_id uuid NOT NULL,
    customer_message_sequence bigint NOT NULL,
    customer_message_sha256 text NOT NULL,
    message_source text NOT NULL CONSTRAINT customer_consents_source_values
        CHECK (message_source IN ('simulated_customer', 'operator_entered_customer')),
    entered_by uuid,
    basis text NOT NULL CONSTRAINT customer_consents_basis_values
        CHECK (basis IN ('explicit_affirmation', 'simulator_confirmation_event')),
    confirmed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT customer_consents_expiry_ttl
        CHECK (expires_at > confirmed_at AND expires_at <= confirmed_at + interval '15 minutes'),
    CONSTRAINT customer_consents_after_presentation CHECK (customer_message_sequence > presented_message_sequence),
    CONSTRAINT customer_consents_author_rule
        CHECK ((message_source = 'operator_entered_customer') = (entered_by IS NOT NULL)),
    CONSTRAINT customer_consents_simulator_basis
        CHECK (basis <> 'simulator_confirmation_event' OR message_source = 'simulated_customer'),
    CONSTRAINT customer_consents_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT customer_consents_one_per_proposal UNIQUE (workspace_id, proposal_id, proposal_version),
    CONSTRAINT customer_consents_binding_unique
        UNIQUE (workspace_id, case_id, run_id, id, proposal_id, proposal_version, action_digest),
    -- The presentation this consent answers: same case, run, proposal version, digests and presented sequence.
    CONSTRAINT customer_consents_presentation FOREIGN KEY (workspace_id, case_id, run_id, proposal_id,
        proposal_version, action_digest, presentation_sha256, presented_message_sequence)
        REFERENCES app.proposal_presentations (workspace_id, case_id, run_id, proposal_id, proposal_version,
        action_digest, presentation_sha256, message_sequence),
    -- The customer message: same case, recorded sequence, text digest and source.
    CONSTRAINT customer_consents_message FOREIGN KEY (workspace_id, case_id, customer_message_id,
        customer_message_sequence, customer_message_sha256, message_source)
        REFERENCES app.case_messages (workspace_id, case_id, id, sequence, text_sha256, source),
    -- Checked whenever entered_by is set (MATCH SIMPLE): the recorded author is the message's author.
    CONSTRAINT customer_consents_message_author FOREIGN KEY (workspace_id, case_id, customer_message_id, entered_by)
        REFERENCES app.case_messages (workspace_id, case_id, id, entered_by)
);
CREATE TABLE app.approval_decisions (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    case_id uuid NOT NULL,
    run_id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    proposal_version bigint NOT NULL,
    action_digest text NOT NULL,
    consent_id uuid NOT NULL,
    principal_id uuid NOT NULL REFERENCES identity.principals (id),
    role text NOT NULL CONSTRAINT approval_decisions_role_values CHECK (role = 'reviewer'),
    decision text NOT NULL CONSTRAINT approval_decisions_decision_values CHECK (decision IN ('approve', 'reject')),
    reason text NOT NULL CONSTRAINT approval_decisions_reason_length CHECK (char_length(reason) BETWEEN 1 AND 500),
    decided_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT approval_decisions_expiry_ttl
        CHECK (expires_at > decided_at AND expires_at <= decided_at + interval '15 minutes'),
    CONSTRAINT approval_decisions_workspace_id_unique UNIQUE (workspace_id, id),
    -- A single terminal decision per proposal version.
    CONSTRAINT approval_decisions_one_per_proposal UNIQUE (workspace_id, proposal_id, proposal_version),
    CONSTRAINT approval_decisions_binding_unique
        UNIQUE (workspace_id, id, proposal_id, proposal_version, action_digest),
    -- The consent (and through it the presentation and proposal) of the same case, run, version and digest.
    CONSTRAINT approval_decisions_consent
        FOREIGN KEY (workspace_id, case_id, run_id, consent_id, proposal_id, proposal_version, action_digest)
        REFERENCES app.customer_consents (workspace_id, case_id, run_id, id, proposal_id, proposal_version,
        action_digest)
);
CREATE TABLE app.tool_executions (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    proposal_version bigint NOT NULL,
    action_digest text NOT NULL,
    approval_id uuid NOT NULL,
    argument_digest text NOT NULL CONSTRAINT tool_executions_argument_digest CHECK (argument_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CONSTRAINT tool_executions_state_values
        CHECK (state IN ('pending', 'dispatched', 'succeeded', 'failed', 'unknown', 'reconciled')),
    attempts integer NOT NULL DEFAULT 0 CONSTRAINT tool_executions_attempts_bounds CHECK (attempts BETWEEN 0 AND 100),
    receipt jsonb CONSTRAINT tool_executions_receipt_size CHECK (pg_column_size(receipt) <= 16384),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CONSTRAINT tool_executions_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT tool_executions_version_positive CHECK (version >= 1),
    CONSTRAINT tool_executions_workspace_id_unique UNIQUE (workspace_id, id),
    -- One execution per operation ID; reuse with a different payload is a conflict, never last-writer-wins.
    CONSTRAINT tool_executions_operation_unique UNIQUE (workspace_id, operation_id),
    CONSTRAINT tool_executions_approval
        FOREIGN KEY (workspace_id, approval_id, proposal_id, proposal_version, action_digest)
        REFERENCES app.approval_decisions (workspace_id, id, proposal_id, proposal_version, action_digest)
);
"""

JOBS = rf"""
CREATE TABLE app.jobs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    run_id uuid NOT NULL,
    dedupe_key text NOT NULL CONSTRAINT jobs_dedupe_key_length CHECK (char_length(dedupe_key) BETWEEN 1 AND 200),
    -- Immutable fingerprint of the original enqueue request (no runtime UPDATE grant); replays compare it, so
    -- later worker changes to state/schedule/attempts never change the request identity.
    request_sha256 text NOT NULL CONSTRAINT jobs_request_digest CHECK (request_sha256 {SHA}),
    kind text NOT NULL CONSTRAINT jobs_kind_format CHECK (kind {SLUG}),
    run_generation bigint NOT NULL CONSTRAINT jobs_generation_nonnegative CHECK (run_generation >= 0),
    state text NOT NULL CONSTRAINT jobs_state_values CHECK (state IN ('queued', 'leased', 'done', 'dead')),
    lease_owner uuid,
    lease_expires_at timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL CONSTRAINT jobs_max_attempts_bounds CHECK (max_attempts BETWEEN 1 AND 100),
    available_at timestamptz NOT NULL,
    deadline_at timestamptz NOT NULL CONSTRAINT jobs_deadline_after_available CHECK (deadline_at > available_at),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CONSTRAINT jobs_updated_after_created CHECK (updated_at >= created_at),
    version bigint NOT NULL DEFAULT 1 CONSTRAINT jobs_version_positive CHECK (version >= 1),
    CONSTRAINT jobs_attempts_bounds CHECK (attempts BETWEEN 0 AND max_attempts),
    CONSTRAINT jobs_lease_state CHECK ((state = 'leased') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CONSTRAINT jobs_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT jobs_dedupe_unique UNIQUE (workspace_id, dedupe_key),
    CONSTRAINT jobs_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id)
);
CREATE INDEX jobs_claimable ON app.jobs (available_at) WHERE state = 'queued';
CREATE TABLE app.outbox_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    run_id uuid,
    dedupe_key text NOT NULL CONSTRAINT outbox_dedupe_key_length CHECK (char_length(dedupe_key) BETWEEN 1 AND 200),
    topic text NOT NULL CONSTRAINT outbox_topic_format CHECK (topic {SLUG}),
    payload jsonb NOT NULL CONSTRAINT outbox_payload_size CHECK (pg_column_size(payload) <= 65536),
    created_at timestamptz NOT NULL,
    delivered_at timestamptz CONSTRAINT outbox_delivered_after_created CHECK (delivered_at >= created_at),
    CONSTRAINT outbox_events_workspace_id_unique UNIQUE (workspace_id, id),
    CONSTRAINT outbox_events_dedupe_unique UNIQUE (workspace_id, dedupe_key),
    CONSTRAINT outbox_events_run FOREIGN KEY (workspace_id, run_id) REFERENCES app.runs (workspace_id, id)
);
CREATE INDEX outbox_undelivered ON app.outbox_events (created_at) WHERE delivered_at IS NULL;
"""

AUDIT = rf"""
CREATE TABLE app.audit_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    actor_kind text NOT NULL CONSTRAINT audit_events_actor_kind_values
        CHECK (actor_kind IN ('principal', 'system', 'worker')),
    actor_principal_id uuid REFERENCES identity.principals (id),
    action text NOT NULL CONSTRAINT audit_events_action_format CHECK (action {SLUG}),
    target_type text NOT NULL CONSTRAINT audit_events_target_type_format CHECK (target_type {SLUG}),
    target_id uuid NOT NULL,
    before_sha256 text CONSTRAINT audit_events_before_digest CHECK (before_sha256 {SHA}),
    after_sha256 text CONSTRAINT audit_events_after_digest CHECK (after_sha256 {SHA}),
    reason text CONSTRAINT audit_events_reason_length CHECK (char_length(reason) BETWEEN 1 AND 500),
    correlation_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT audit_events_actor_rule CHECK ((actor_kind = 'principal') = (actor_principal_id IS NOT NULL)),
    CONSTRAINT audit_events_workspace_id_unique UNIQUE (workspace_id, id)
);
CREATE INDEX audit_events_target ON app.audit_events (workspace_id, target_type, target_id, occurred_at);
"""

# (table, privileges for the app runtime). Absent tables get nothing. Column lists are the only updatable columns.
APP_GRANTS = {
    "app.cases": "SELECT, INSERT, UPDATE (status, updated_at, version)",
    "app.case_messages": "SELECT, INSERT",
    "app.documents": "SELECT, INSERT",
    "app.document_versions": "SELECT, INSERT, UPDATE (status, effective_to)",
    "app.runs": "SELECT, INSERT, UPDATE (state, model_calls, tool_calls, updated_at, version)",
    "app.run_events": "SELECT, INSERT",
    "app.action_proposals": "SELECT, INSERT, UPDATE (status, presented_at)",
    "app.proposal_presentations": "SELECT, INSERT",
    "app.customer_consents": "SELECT, INSERT",
    "app.approval_decisions": "SELECT, INSERT",
    "app.tool_executions": "SELECT, INSERT, UPDATE (state, attempts, receipt, updated_at, version)",
    "app.jobs": "SELECT, INSERT, UPDATE (state, lease_owner, lease_expires_at, attempts, available_at, updated_at, "
                "version)",
    "app.outbox_events": "SELECT, INSERT, UPDATE (delivered_at)",
    "app.audit_events": "SELECT, INSERT",
}


def _tenant_rls(table: str) -> str:
    name = table.split(".")[1]
    return (f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; "
            f"CREATE POLICY {name}_app_workspace ON {table} TO {APP} "
            "USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());")


IDENTITY_SECURITY = rf"""
ALTER TABLE identity.workspaces ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.principals ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.sessions ENABLE ROW LEVEL SECURITY; ALTER TABLE identity.sessions FORCE ROW LEVEL SECURITY;
-- The auth service is the trusted pre-workspace boundary (PLAN D1): unrestricted rows, but only these tables and
-- only these commands.
CREATE POLICY workspaces_auth ON identity.workspaces TO {AUTH} USING (true) WITH CHECK (true);
CREATE POLICY principals_auth ON identity.principals TO {AUTH} USING (true) WITH CHECK (true);
CREATE POLICY memberships_auth ON identity.memberships TO {AUTH} USING (true) WITH CHECK (true);
CREATE POLICY sessions_auth ON identity.sessions TO {AUTH} USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON identity.workspaces, identity.principals, identity.memberships TO {AUTH};
GRANT UPDATE (revoked_at, version) ON identity.memberships TO {AUTH};
GRANT SELECT, INSERT, UPDATE (revoked_at, workspace_id) ON identity.sessions TO {AUTH};
-- The app runtime sees only its current workspace and that workspace's memberships (revocation is checked on use).
CREATE POLICY workspaces_app_current ON identity.workspaces FOR SELECT TO {APP} USING (id = app.current_workspace());
CREATE POLICY memberships_app_workspace ON identity.memberships TO {APP}
    USING (workspace_id = app.current_workspace()) WITH CHECK (workspace_id = app.current_workspace());
GRANT SELECT ON identity.workspaces TO {APP};
GRANT SELECT, INSERT, UPDATE (revoked_at, version) ON identity.memberships TO {APP};
"""


def upgrade() -> None:
    for block in (SCHEMAS, IDENTITY, CASES, DOCUMENTS, RUNS, ACTIONS, JOBS, AUDIT, IDENTITY_SECURITY):
        op.execute(block)
    for table in TENANT_TABLES:
        op.execute(_tenant_rls(table))
    for table, privileges in APP_GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {APP}")


DROP_ORDER = ("app.audit_events", "app.outbox_events", "app.jobs", "app.tool_executions", "app.approval_decisions",
              "app.customer_consents", "app.proposal_presentations", "app.action_proposals", "app.run_events",
              "app.runs", "app.document_versions", "app.documents", "app.case_messages", "app.cases",
              "identity.sessions", "identity.memberships", "identity.principals", "identity.workspaces")


def downgrade() -> None:
    refuse_data_loss(DROP_ORDER)
    for table in DROP_ORDER:
        op.execute(f"DROP TABLE {table}")
    op.execute("DROP FUNCTION app.guard_action_proposal_update()")
    op.execute("DROP FUNCTION app.current_workspace()")
    op.execute("DROP SCHEMA app")
    op.execute("DROP SCHEMA identity")
