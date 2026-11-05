"""Retail per-case state and resource versions (T16, first of two dependency-separated initial revisions).

* `retail.case_states`: one isolated upstream state per (tenant, case), bound once to its fixture identity and the
  case's customer. The runtime may only update `version`, `state`, `state_sha256` and `updated_at` (column grants):
  the tenant, case, customer and fixture identity are immutable. `version` is the case serial.
* `retail.case_resources`: per-resource positive integer versions for the customer's user and orders. The catalog is
  not stored: it is immutable within the fixture identity and has version 1.
Both tables force tenant/case row-level security from transaction-local settings (`retail.tenant_id`,
`retail.case_id`); without them nothing is visible. The downgrade is refused while either table holds rows.

Revision ID: r0001
"""

from alembic import op

from policyops_evals.retail_sim.schema import refuse_populated, scoped_policy


revision = "r0001"
down_revision = None
branch_labels = None
depends_on = None

TABLES = ("retail.case_resources", "retail.case_states")


def upgrade() -> None:
    op.execute("""
CREATE TABLE retail.case_states (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    customer_id text NOT NULL CHECK (customer_id ~ '^[a-z]+(_[a-z]+)*_[0-9]{1,6}$' AND length(customer_id) <= 64),
    fixture_id text NOT NULL CHECK (fixture_id = 'tau2-retail-19f13ea3'),
    fixture_sha256 char(64) NOT NULL CHECK (fixture_sha256 ~ '^[0-9a-f]{64}$'),
    codec text NOT NULL CHECK (codec = 'retail-state/v1'),
    version bigint NOT NULL CHECK (version >= 1),
    state bytea NOT NULL CHECK (octet_length(state) <= 8388608),
    state_sha256 char(64) NOT NULL CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, case_id)
);
CREATE TABLE retail.case_resources (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('user', 'order')),
    resource_id text NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 64),
    version bigint NOT NULL CHECK (version >= 1),
    PRIMARY KEY (tenant_id, case_id, kind, resource_id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES retail.case_states (tenant_id, case_id)
);
""")
    for table in ("case_states", "case_resources"):
        op.execute(scoped_policy(table))
    op.execute("""
GRANT SELECT ON retail.alembic_version TO retail_runtime;
GRANT SELECT, INSERT ON retail.case_states TO retail_runtime;
GRANT UPDATE (version, state, state_sha256, updated_at) ON retail.case_states TO retail_runtime;
GRANT SELECT, INSERT ON retail.case_resources TO retail_runtime;
GRANT UPDATE (version) ON retail.case_resources TO retail_runtime;
""")


def downgrade() -> None:
    refuse_populated(op.get_bind(), TABLES)
    op.execute("DROP TABLE retail.case_resources; DROP TABLE retail.case_states;")
