"""Run the application Alembic chain on a connection the caller opened as the migrator.

Semantics (PLAN D7), stated precisely:

* Upgrade: each revision runs in its own transaction (PostgreSQL DDL is transactional). A failing revision rolls
  back completely and the version table stays at the previous revision; earlier revisions are not undone.
* Downgrade: dropping a revision's tables destroys their rows. It is refused when any of them holds rows unless
  `allow_data_loss=True` is passed explicitly; even then it is lossy, never "lossless".
* Restore: a separate operation (pg_dump/pg_restore into another database), not a downgrade.

Precondition: `upgrade` and `downgrade` need a connection with no open transaction (a fresh connection, or one
whose previous work was committed or rolled back). Otherwise Alembic would run every revision inside the caller's
transaction, losing the per-revision boundaries, so they raise MigrationPreconditionError before doing anything
and never commit or roll back caller work. `current` does not leave a transaction open.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection

from policyops.persistence.migration_guard import DataLossRefused


VERSION_TABLE = "policyops_app_alembic_version"
VERSION_TABLE_SCHEMA = "public"
MIGRATIONS = Path(__file__).resolve().parent / "migrations"
__all__ = ["DataLossRefused", "MigrationPreconditionError", "current", "downgrade", "head", "revisions", "upgrade"]


class MigrationPreconditionError(RuntimeError):
    """The connection already has an open transaction; migrations need a clean connection."""


def _config(connection: Connection, *, allow_data_loss: bool = False) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.attributes["connection"] = connection
    config.attributes["allow_data_loss"] = allow_data_loss
    return config


def head() -> str:
    revision = ScriptDirectory(str(MIGRATIONS)).get_current_head()
    if revision is None:
        raise RuntimeError("the application migration chain has no head")
    return revision


def revisions() -> list[str]:
    """All revisions, oldest first."""
    script = ScriptDirectory(str(MIGRATIONS))
    return [entry.revision for entry in reversed(list(script.walk_revisions()))]


def current(connection: Connection) -> str | None:
    started_clean = not connection.in_transaction()
    context = MigrationContext.configure(connection, opts={"version_table": VERSION_TABLE,
                                                            "version_table_schema": VERSION_TABLE_SCHEMA})
    revision = context.get_current_revision()
    if started_clean and connection.in_transaction():
        connection.rollback()  # end only the read transaction this function itself began
    return revision


def _require_clean(connection: Connection) -> None:
    if connection.in_transaction():
        raise MigrationPreconditionError("migrations need a connection without an open transaction; commit or roll "
                                         "back the caller's work (or use a fresh connection) first")


def _run(connection: Connection, config: Config, step: str, revision: str) -> None:
    _require_clean(connection)
    try:
        getattr(command, step)(config, revision)
    except BaseException:
        if connection.in_transaction():  # Alembic's own leftover state; the caller had none
            connection.rollback()
        raise
    if connection.in_transaction():  # Alembic's own trailing work (e.g. version-table bookkeeping)
        connection.commit()


def upgrade(connection: Connection, revision: str = "head") -> None:
    _run(connection, _config(connection), "upgrade", revision)


def downgrade(connection: Connection, revision: str, *, allow_data_loss: bool = False) -> None:
    _run(connection, _config(connection, allow_data_loss=allow_data_loss), "downgrade", revision)
