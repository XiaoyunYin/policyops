"""Retail operation outcomes and receipts, single-use service nonces and test fault plans (T16, second revision).

* `retail.operations`: one immutable row per accepted operation ID in a case: its stable fingerprint and its
  terminal outcome (`committed` with a receipt; `upstream_rejected`, `effect_mismatch`, `money_unrepresentable`,
  `version_conflict` or `fenced` without one, and with the case version unchanged). The runtime may only insert and
  select: there is no update or delete grant.
* `retail.token_uses`: single-use service nonces per (tenant, case, jti) with their expiry. There is no foreign key
  to `case_states`, so the initialization request's own nonce can be recorded before its case exists. The runtime
  may delete only expired rows (policy).
* `retail.fault_plans`: one-shot, bounded fault injections for tests and demos (default off at the service).
All three force tenant/case row-level security. The downgrade is refused while any of them holds rows.

Revision ID: r0002
"""

from alembic import op

from policyops_evals.retail_sim.schema import refuse_populated, scoped_policy


revision = "r0002"
down_revision = "r0001"
branch_labels = None
depends_on = None

TABLES = ("retail.operations", "retail.token_uses", "retail.fault_plans")


def upgrade() -> None:
    op.execute("""
CREATE TABLE retail.operations (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    operation_sha256 char(64) NOT NULL CHECK (operation_sha256 ~ '^[0-9a-f]{64}$'),
    tool text CHECK (tool IS NULL OR tool IN ('cancel_pending_order', 'modify_pending_order_address',
        'modify_pending_order_payment', 'modify_pending_order_items', 'return_delivered_order_items',
        'exchange_delivered_order_items', 'modify_user_address')),
    outcome text NOT NULL CHECK (outcome IN ('committed', 'upstream_rejected', 'effect_mismatch',
        'money_unrepresentable', 'version_conflict', 'fenced')),
    code text CHECK (code IS NULL OR code ~ '^[a-z][a-z0-9_]{0,63}$'),
    case_version_before bigint NOT NULL CHECK (case_version_before >= 1),
    case_version_after bigint NOT NULL,
    receipt jsonb,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, case_id, operation_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES retail.case_states (tenant_id, case_id),
    CONSTRAINT operations_receipt_iff_committed CHECK ((outcome = 'committed') = (receipt IS NOT NULL)),
    CONSTRAINT operations_version_step CHECK (
        (outcome = 'committed' AND case_version_after = case_version_before + 1)
        OR (outcome <> 'committed' AND case_version_after = case_version_before)),
    CONSTRAINT operations_tool_unless_fenced CHECK ((outcome = 'fenced') OR tool IS NOT NULL)
);
CREATE TABLE retail.token_uses (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    jti uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, case_id, jti)
);
CREATE TABLE retail.fault_plans (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    fault text NOT NULL CHECK (fault IN ('reject_429_before', 'fail_503_before', 'delay_before', 'commit_then_503')),
    remaining integer NOT NULL CHECK (remaining BETWEEN 0 AND 3),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, case_id, fault),
    FOREIGN KEY (tenant_id, case_id) REFERENCES retail.case_states (tenant_id, case_id)
);
""")
    for table in ("operations", "fault_plans"):
        op.execute(scoped_policy(table))
    op.execute(scoped_policy("token_uses", select_insert_only=True))
    op.execute("""
CREATE POLICY token_uses_expired_only ON retail.token_uses FOR DELETE TO retail_runtime
    USING (tenant_id = nullif(current_setting('retail.tenant_id', true), '')::uuid
           AND case_id = nullif(current_setting('retail.case_id', true), '')::uuid AND expires_at < now());
GRANT SELECT, INSERT ON retail.operations TO retail_runtime;
GRANT SELECT, INSERT, DELETE ON retail.token_uses TO retail_runtime;
GRANT SELECT, INSERT, DELETE ON retail.fault_plans TO retail_runtime;
GRANT UPDATE (remaining) ON retail.fault_plans TO retail_runtime;
""")


def downgrade() -> None:
    refuse_populated(op.get_bind(), TABLES)
    op.execute("DROP TABLE retail.fault_plans; DROP TABLE retail.token_uses; DROP TABLE retail.operations;")
