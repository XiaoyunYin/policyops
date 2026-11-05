"""Run the retail Alembic chain (`evals/migrations/retail`) on a connection opened as `retail_migrator`.

Separate from the application chain: its own environment, its own version table (`retail.alembic_version`) and its
own roles. Each revision runs in its own transaction. Downgrading a revision that holds rows is refused: receipts
and operation outcomes are evidence, and dropping them while keeping state would be inconsistent; recovery uses a
consistent backup (state, resources and operations together). The runtime refuses to serve a schema that is not at
the head revision.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection


VERSION_TABLE = "alembic_version"
VERSION_TABLE_SCHEMA = "retail"
MIGRATIONS = Path(__file__).resolve().parents[3] / "migrations" / "retail"


class MigrationPreconditionError(RuntimeError):
    """The connection already has an open transaction."""


def _config(connection: Connection) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.attributes["connection"] = connection
    return config


def head() -> str:
    revision = ScriptDirectory(str(MIGRATIONS)).get_current_head()
    if revision is None:  # pragma: no cover - the chain has revisions
        raise RuntimeError("the retail migration chain has no head")
    return revision


def current(connection: Connection) -> str | None:
    started_clean = not connection.in_transaction()
    context = MigrationContext.configure(connection, opts={"version_table": VERSION_TABLE,
                                                            "version_table_schema": VERSION_TABLE_SCHEMA})
    revision = context.get_current_revision()
    if started_clean and connection.in_transaction():
        connection.rollback()
    return revision


def _run(connection: Connection, step: str, revision: str) -> None:
    if connection.in_transaction():
        raise MigrationPreconditionError("retail migrations need a connection without an open transaction")
    getattr(command, step)(_config(connection), revision)
    if connection.in_transaction():
        connection.commit()


def upgrade(connection: Connection, revision: str = "head") -> None:
    _run(connection, "upgrade", revision)


def downgrade(connection: Connection, revision: str) -> None:
    _run(connection, "downgrade", revision)
