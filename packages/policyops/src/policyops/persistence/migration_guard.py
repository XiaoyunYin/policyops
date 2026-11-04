"""Helpers used inside application migrations (Alembic context required)."""

from __future__ import annotations

from alembic import context, op


class DataLossRefused(RuntimeError):
    """A downgrade would drop tables that still hold rows and allow_data_loss was not given."""


def refuse_data_loss(tables: tuple[str, ...]) -> None:
    """Refuse a lossy downgrade unless the caller passed allow_data_loss=True.

    The owning migrator has no data policy under FORCE ROW LEVEL SECURITY, so it would see zero rows; the check lifts
    FORCE inside the migration transaction first (a refusal rolls that back as well).
    """
    if context.config.attributes.get("allow_data_loss"):
        return
    connection = op.get_bind()
    for table in tables:
        connection.exec_driver_sql(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        # `tables` are fixed identifiers from the revision files, never input.
        if connection.exec_driver_sql(f"SELECT EXISTS (SELECT 1 FROM {table})").scalar():  # noqa: S608
            raise DataLossRefused(f"downgrade would drop rows in {table}; pass allow_data_loss=True to accept that")
