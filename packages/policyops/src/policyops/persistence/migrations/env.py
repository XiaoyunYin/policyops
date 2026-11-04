"""Alembic environment for the application chain. Run only through policyops.persistence.migrate, which supplies an
open SQLAlchemy connection authenticated as the migrator (no URL, credentials or ini file here)."""

from alembic import context

from policyops.persistence.migrate import VERSION_TABLE, VERSION_TABLE_SCHEMA


connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("run application migrations through policyops.persistence.migrate")

context.configure(
    connection=connection,
    target_metadata=None,
    version_table=VERSION_TABLE,
    version_table_schema=VERSION_TABLE_SCHEMA,
    transaction_per_migration=True,  # a failed revision rolls back alone; earlier revisions stay applied
)
with context.begin_transaction():
    context.run_migrations()
