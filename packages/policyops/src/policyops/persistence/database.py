"""Engines and transaction scopes.

`make_engine` wraps a caller-supplied connection factory (credentials and endpoint come from validated settings or
a test fixture; no URL with a password is built here). `workspace_transaction` is the only way to reach tenant
tables as the app runtime: it opens a transaction and sets `policyops.workspace_id` with `set_config(..., true)`,
which PostgreSQL discards at commit or rollback, so a pooled connection never carries a scope into its next use.
Transactions are short: never hold one across a provider/HTTP call or a human wait.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

import psycopg
from sqlalchemy import Connection, Engine, create_engine, event, text


SCOPE_SETTING = "policyops.workspace_id"


class PersistenceError(RuntimeError):
    """Base class for typed persistence failures."""


class NotFound(PersistenceError):
    """The row does not exist or is outside the current workspace (indistinguishable by design)."""


class StaleVersion(PersistenceError):
    """The expected version did not match: someone else changed the row first."""


class IdempotencyConflict(PersistenceError):
    """A key was reused with a different payload; the original is kept."""


class DecisionConflict(PersistenceError):
    """A terminal decision (or consent) already exists for this proposal version."""


class ImmutableRecord(PersistenceError):
    """A guarded record refused a change (immutable content or an illegal status move)."""


def make_engine(connect: Callable[[], psycopg.Connection[Any]], *, pool_size: int = 5) -> Engine:
    if not 1 <= pool_size <= 50:
        raise ValueError("pool_size must be between 1 and 50")
    engine = create_engine("postgresql+psycopg://", creator=connect, pool_size=pool_size, max_overflow=0,
                           pool_reset_on_return="rollback")

    @event.listens_for(engine, "connect")
    def _utc_session(dbapi_connection: Any, _record: Any) -> None:
        # Timestamps come back as aware UTC datetimes whatever the server or role default time zone is.
        with dbapi_connection.cursor() as cursor:
            cursor.execute("SET TIME ZONE 'UTC'")
        dbapi_connection.commit()

    return engine


@contextmanager
def workspace_transaction(engine: Engine, workspace_id: UUID) -> Iterator[Connection]:
    """A transaction whose RLS scope is exactly `workspace_id`; committed on success, rolled back on error."""
    if not isinstance(workspace_id, UUID):
        raise TypeError("workspace_id must be a UUID")
    with engine.begin() as connection:
        connection.execute(text("SELECT set_config(:name, :value, true)"),
                           {"name": SCOPE_SETTING, "value": str(workspace_id)})
        yield connection


@contextmanager
def transaction(engine: Engine) -> Iterator[Connection]:
    """An unscoped transaction, for the auth and evaluation roles (their tables are not workspace-scoped by RLS)."""
    with engine.begin() as connection:
        yield connection
