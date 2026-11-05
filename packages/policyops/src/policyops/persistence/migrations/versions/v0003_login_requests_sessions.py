"""Durable OIDC login state and session idle/CSRF columns (T07). Forward-only addition; 0001/0002 unchanged.

* `identity.login_requests`: one row per started login. It stores only digests of the browser-binding cookie,
  `state` and `nonce`, plus the PKCE verifier (needed server-side for the code exchange; never sent to the
  browser), a fixed same-origin return path, a TTL of at most 10 minutes and a single-use `consumed_at`.
* `identity.sessions`: `last_seen_at` (idle expiry) and `csrf_sha256` (synchronizer token digest). Sessions
  created before this revision have neither and are treated as invalid by the application.

Only the auth runtime role can read or write these rows (forced RLS, auth-role policy, narrow grants).

Revision ID: 0003
"""

from alembic import op

from policyops.persistence.migration_guard import refuse_data_loss


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE identity.login_requests (
    id uuid PRIMARY KEY,
    binding_sha256 text NOT NULL CONSTRAINT login_requests_binding_digest CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    state_sha256 text NOT NULL CONSTRAINT login_requests_state_digest CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
    nonce_sha256 text NOT NULL CONSTRAINT login_requests_nonce_digest CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
    code_verifier text NOT NULL CONSTRAINT login_requests_verifier_format
        CHECK (code_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),
    return_to text NOT NULL CONSTRAINT login_requests_return_path
        CHECK (return_to ~ '^/([A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*)?$' AND return_to !~ '(^|/)[.][.]?(/|$)'
               AND char_length(return_to) <= 200),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz CONSTRAINT login_requests_consumed_after_created CHECK (consumed_at >= created_at),
    CONSTRAINT login_requests_ttl CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CONSTRAINT login_requests_state_unique UNIQUE (state_sha256),
    CONSTRAINT login_requests_binding_unique UNIQUE (binding_sha256)
);
CREATE INDEX login_requests_expiry ON identity.login_requests (expires_at) WHERE consumed_at IS NULL;
ALTER TABLE identity.login_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.login_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY login_requests_auth ON identity.login_requests TO policyops_auth_runtime USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON identity.login_requests TO policyops_auth_runtime;
GRANT UPDATE (consumed_at) ON identity.login_requests TO policyops_auth_runtime;

ALTER TABLE identity.sessions
    ADD COLUMN last_seen_at timestamptz,
    ADD COLUMN csrf_sha256 text CONSTRAINT sessions_csrf_digest CHECK (csrf_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT sessions_last_seen_window CHECK (last_seen_at >= created_at AND last_seen_at <= expires_at);
GRANT UPDATE (last_seen_at) ON identity.sessions TO policyops_auth_runtime;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    # Dropping the session columns loses login state as well; refuse while either table holds rows.
    refuse_data_loss(("identity.login_requests", "identity.sessions"))
    op.execute("REVOKE UPDATE (last_seen_at) ON identity.sessions FROM policyops_auth_runtime")
    op.execute("ALTER TABLE identity.sessions DROP CONSTRAINT sessions_last_seen_window, DROP COLUMN csrf_sha256, "
               "DROP COLUMN last_seen_at")
    op.execute("DROP TABLE identity.login_requests")
