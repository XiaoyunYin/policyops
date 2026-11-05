"""Alembic environment for the retail chain. Run only through policyops_evals.retail_sim.migrate, which supplies an
open connection authenticated as retail_migrator (no URL, credentials or ini file here)."""

from alembic import context


connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("run retail migrations through policyops_evals.retail_sim.migrate")

context.configure(
    connection=connection,
    target_metadata=None,
    version_table="alembic_version",
    version_table_schema="retail",
    transaction_per_migration=True,
)
with context.begin_transaction():
    context.run_migrations()
