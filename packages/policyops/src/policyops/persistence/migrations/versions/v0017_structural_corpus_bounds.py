"""Allow one 4,110-passage structural corpus without widening Markdown's manifest limit."""

from alembic import op

from policyops.persistence.migration_guard import DataLossRefused


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def _bounds(documents: int, ordinal: int) -> None:
    op.execute(f"""
ALTER TABLE app.index_generations DROP CONSTRAINT index_generations_document_count,
    ADD CONSTRAINT index_generations_document_count CHECK (document_count BETWEEN 0 AND {documents});
ALTER TABLE app.generation_documents DROP CONSTRAINT generation_documents_ordinal,
    ADD CONSTRAINT generation_documents_ordinal CHECK (ordinal BETWEEN 0 AND {ordinal});
""")


def upgrade() -> None:
    _bounds(5000, 4999)


def downgrade() -> None:
    # The owner has no policy under FORCE RLS. Lock both tables before temporarily
    # lifting FORCE, inspect all workspaces, then restore it in the same transaction.
    # Refusal never honors the lossy override and never mutates tenant data.
    connection = op.get_bind()
    connection.exec_driver_sql(
        "LOCK TABLE app.index_generations, app.generation_documents IN ACCESS EXCLUSIVE MODE")
    for table, predicate in (("app.index_generations", "document_count > 2000"),
                             ("app.generation_documents", "ordinal > 1999")):
        forced = connection.exec_driver_sql(
            "SELECT relforcerowsecurity FROM pg_class WHERE oid = %s::regclass", (table,)).scalar_one()
        connection.exec_driver_sql(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        exceeds = connection.exec_driver_sql(f"SELECT EXISTS (SELECT 1 FROM {table} WHERE {predicate})").scalar_one()  # noqa: S608
        if forced:
            connection.exec_driver_sql(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        if exceeds:
            raise DataLossRefused(f"0017 downgrade refused: {table} exceeds the 0016 bounds; data is unchanged")
    _bounds(2000, 1999)
