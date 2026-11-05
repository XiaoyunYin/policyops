"""Helpers used inside application migrations (Alembic context required)."""

from __future__ import annotations

from alembic import context, op
from sqlalchemy import Connection


class DataLossRefused(RuntimeError):
    """A downgrade would drop tables that still hold rows and allow_data_loss was not given."""


def refuse_data_loss(tables: tuple[str, ...]) -> None:
    """Refuse a lossy downgrade unless the caller passed allow_data_loss=True.

    The owning migrator has no data policy under FORCE ROW LEVEL SECURITY, so it would see zero rows; the check lifts
    FORCE inside the migration transaction first and restores it before returning (a refusal rolls the whole
    transaction back). Without the restore, a downgrade that only drops columns would commit the table unforced.
    """
    if context.config.attributes.get("allow_data_loss"):
        return
    check_tables_empty(op.get_bind(), tables)


def check_tables_empty(connection: Connection, tables: tuple[str, ...]) -> None:
    """The check itself, on the caller's open transaction: each table's FORCE ROW LEVEL SECURITY state is lifted
    for the count and then restored exactly (forced tables are forced again, unforced ones stay unforced)."""
    for table in tables:
        # `tables` are fixed identifiers from the revision files, never input.
        forced = connection.exec_driver_sql(
            "SELECT relforcerowsecurity FROM pg_class WHERE oid = %s::regclass", (table,)).scalar()
        connection.exec_driver_sql(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        holds_rows = connection.exec_driver_sql(f"SELECT EXISTS (SELECT 1 FROM {table})").scalar()  # noqa: S608
        if forced:  # restore exactly the previous state
            connection.exec_driver_sql(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        if holds_rows:
            raise DataLossRefused(f"downgrade would drop rows in {table}; pass allow_data_loss=True to accept that")
