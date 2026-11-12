"""Engines and transaction scopes.

`make_engine` wraps a caller-supplied connection factory (credentials and endpoint come from validated settings or
a test fixture; no URL with a password is built here). `workspace_transaction` is the only way to reach tenant
tables as the app runtime: it opens a transaction and sets `policyops.workspace_id` with `set_config(..., true)`,
which PostgreSQL discards at commit or rollback, so a pooled connection never carries a scope into its next use.
Transactions are short: never hold one across a provider/HTTP call or a human wait.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID
import weakref

import psycopg
from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeout

from policyops.telemetry import annotate, count, enabled, span


SCOPE_SETTING = "policyops.workspace_id"
POOL_TIMEOUT_SECONDS = 2
# libpq startup options bound the UTC/role handshake before transaction-local settings exist.
RUNTIME_CONNECT_OPTIONS = "-c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000"


class PersistenceError(RuntimeError):
    """Base class for typed persistence failures."""


class SqlProfile(StrEnum):
    DEFAULT = "default"
    LEASE = "lease"
    RETRIEVAL = "retrieval"


@dataclass(frozen=True)
class SqlTimeouts:
    statement_ms: int
    lock_ms: int
    idle_ms: int

    def __post_init__(self) -> None:
        if any(type(v) is not int or not 1 <= v <= 60_000
               for v in (self.statement_ms, self.lock_ms, self.idle_ms)) or self.lock_ms >= self.statement_ms:
            raise ValueError("SQL timeouts must be positive bounded milliseconds with lock < statement")


SQL_TIMEOUTS = {SqlProfile.DEFAULT: SqlTimeouts(5000, 1000, 5000),
                SqlProfile.LEASE: SqlTimeouts(1000, 250, 2000),
                SqlProfile.RETRIEVAL: SqlTimeouts(15000, 1000, 5000)}
SqlPhase = Literal["acquire", "setup", "body", "commit"]


def observe_sql_failure(error: BaseException, phase: SqlPhase) -> None:
    if not enabled():
        return
    state = sqlstate(error)
    with span("sql.failure", phase=phase, error_code="sql_failure", outcome="error",
              exception_type=type(error).__name__):
        if state is not None:
            annotate(sqlstate_class=state[:2])
        count("errors", error_code="sql_failure")


def sqlstate(error: BaseException) -> str | None:
    original = error.orig if isinstance(error, DBAPIError) else error
    value = getattr(original, "sqlstate", None)
    return value if isinstance(value, str) and len(value) == 5 else None


class DatabaseUnavailable(PersistenceError):
    """A bounded local SQL failure. No SQL, parameters or connection representation in the message."""

    def __init__(self, phase: SqlPhase, state: str | None, *, reconcile: bool = False) -> None:
        self.phase, self.sqlstate, self.reconcile = phase, state, reconcile
        super().__init__(f"database unavailable during {phase} ({state or 'connection/pool'})")


class TransactionOutcomeUnknown(PersistenceError):
    """COMMIT was attempted but not acknowledged. Re-read durable state using the original IDs before work."""

    def __init__(self, state: str | None = None) -> None:
        self.phase, self.sqlstate = "commit", state
        super().__init__("transaction COMMIT outcome is unknown")


class TransactionCommitCancelled(asyncio.CancelledError, TransactionOutcomeUnknown):
    """Cancellation during COMMIT retains both cancellation and unknown-outcome semantics."""

    def __init__(self) -> None:
        TransactionOutcomeUnknown.__init__(self)


def classify_sql_failure(error: Exception, phase: SqlPhase) -> PersistenceError | None:
    if phase == "commit":
        return TransactionOutcomeUnknown(sqlstate(error))
    state = sqlstate(error)
    if state is not None and state[:2] in {"28", "42"}:
        return None  # authentication/authorization/schema/syntax failures are configuration errors
    disconnected = isinstance(error, DBAPIError) and error.connection_invalidated
    # libpq often supplies no SQLSTATE during connection setup, including bad credentials. Only known
    # connectivity failures are transient; never publish the driver text or classify every OperationalError so.
    original = error.orig if isinstance(error, DBAPIError) else error
    connect_failure = (phase == "acquire" and state is None and isinstance(original, psycopg.OperationalError)
                       and any(fragment in str(original).lower() for fragment in (
                           "connection refused", "timeout expired", "connection timed out", "network is unreachable",
                           "no route to host", "could not translate host name", "failed to resolve host",
                           "server closed the connection unexpectedly")))
    if (isinstance(error, PoolTimeout) or state in {"55P03", "57014", "25P03"}
            or (state is not None and state.startswith("08")) or disconnected
            or connect_failure):
        return DatabaseUnavailable(phase, state, reconcile=disconnected or state == "25P03"
                                   or (state is not None and state.startswith("08")))
    return None  # authentication, permission, schema and constraint errors are not transient by default


def initialize_transaction(connection: Connection, workspace_id: UUID | None = None, *,
                           profile: SqlProfile = SqlProfile.DEFAULT) -> None:
    limits = SQL_TIMEOUTS[profile]
    for name, value in (("statement_timeout", limits.statement_ms), ("lock_timeout", limits.lock_ms),
                        ("idle_in_transaction_session_timeout", limits.idle_ms)):
        connection.execute(text("SELECT set_config(:name, :value, true)"), {"name": name, "value": str(value)})
    if workspace_id is not None:
        connection.execute(text("SELECT set_config(:name, :value, true)"),
                           {"name": SCOPE_SETTING, "value": str(workspace_id)})


def connect_runtime(engine: Engine) -> Connection:
    try:
        return engine.connect()
    except Exception as error:
        observe_sql_failure(error, "acquire")
        classified = classify_sql_failure(error, "acquire")
        if classified is not None:
            raise classified from error
        raise


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
                           pool_timeout=POOL_TIMEOUT_SECONDS, pool_reset_on_return="rollback")

    @event.listens_for(engine, "connect")
    def _utc_session(dbapi_connection: Any, _record: Any) -> None:
        # Timestamps come back as aware UTC datetimes whatever the server or role default time zone is.
        with dbapi_connection.cursor() as cursor:
            cursor.execute("SET TIME ZONE 'UTC'")
        dbapi_connection.commit()

    return engine


@contextmanager
def workspace_transaction(engine: Engine, workspace_id: UUID, *, profile: SqlProfile = SqlProfile.DEFAULT
                          ) -> Iterator[Connection]:
    """A transaction whose RLS scope is exactly `workspace_id`; committed on success, rolled back on error."""
    if not isinstance(workspace_id, UUID):
        raise TypeError("workspace_id must be a UUID")
    with transaction(engine, workspace_id=workspace_id, profile=profile) as connection:
        yield connection


@contextmanager
def connection_transaction(connection: Connection, workspace_id: UUID | None = None, *,
                           profile: SqlProfile = SqlProfile.DEFAULT) -> Iterator[Connection]:
    """An owned transaction on an already owned connection, preserving the caller's isolation options."""
    phase: SqlPhase = "setup"
    try:
        tx = connection.begin()
        initialize_transaction(connection, workspace_id, profile=profile)
        phase = "body"
        yield connection
        phase = "commit"
        tx.commit()
    except BaseException as error:
        observe_sql_failure(error, phase)
        try:
            connection.rollback()
        except BaseException as cleanup:
            error.add_note(f"rollback also failed: {type(cleanup).__name__}")
        if isinstance(error, Exception):
            classified = classify_sql_failure(error, phase)
            if classified is not None:
                raise classified from error
        if phase == "commit" and isinstance(error, asyncio.CancelledError):
            raise TransactionCommitCancelled() from error
        # Cancellation remains cancellation; during COMMIT its outcome is still explicitly unknown.
        if phase == "commit":
            error.add_note("transaction COMMIT outcome is unknown; reconcile original IDs")
        raise


@contextmanager
def transaction(engine: Engine, *, workspace_id: UUID | None = None, profile: SqlProfile = SqlProfile.DEFAULT
                ) -> Iterator[Connection]:
    """Own acquisition/setup/body/commit/rollback/close. Auth/eval transactions need no workspace scope."""
    connection = None
    primary: BaseException | None = None
    try:
        connection = connect_runtime(engine)
        with connection_transaction(connection, workspace_id, profile=profile):
            yield connection
    except BaseException as error:
        primary = error
        raise
    finally:
        if connection is not None:
            try:
                connection.close()
            except BaseException as cleanup:
                if primary is None:
                    raise
                primary.add_note(f"connection close also failed: {type(cleanup).__name__}")


class RuntimeRoleError(PersistenceError):
    """A runtime engine authenticates as the wrong role, or as a role with privileges a runtime must not have."""


_VERIFIED: weakref.WeakKeyDictionary[Engine, str] = weakref.WeakKeyDictionary()


def _driver_user(dbapi_connection: Any) -> str:
    """The user psycopg actually authenticated as (not affected by SET ROLE / SET SESSION AUTHORIZATION)."""
    user: str = dbapi_connection.info.user
    return user


def verify_runtime_role(engine: Engine, expected: str) -> None:
    """Refuse runtime wiring unless the engine really authenticates as `expected` (one of the restricted runtime
    roles) with no superuser, BYPASSRLS, CREATEROLE, CREATEDB, replication, inheritance or memberships.

    The authenticated identity is psycopg's `info.user`; `session_user` and `current_user` must equal it too, so a
    privileged login masked by `SET ROLE` or `SET SESSION AUTHORIZATION` is refused. The same driver-identity check
    is then attached to every pool checkout (including connections opened before verification).
    """
    from policyops.persistence.roles import RUNTIME_ROLES

    if expected not in RUNTIME_ROLES:
        raise RuntimeRoleError(f"{expected!r} is not a runtime role")
    with transaction(engine) as connection:
        authenticated = _driver_user(connection.connection.driver_connection)
        row = connection.execute(text(
            "SELECT session_user, current_user, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, "
            "r.rolreplication, r.rolinherit, (SELECT count(*) FROM pg_auth_members m WHERE m.member = r.oid) "
            "FROM pg_roles r WHERE r.rolname = session_user")).one()
    session, current, superuser, bypassrls, createrole, createdb, replication, inherit, memberships = row
    if {authenticated, session, current} != {expected}:
        raise RuntimeRoleError(f"the engine authenticates as {authenticated!r} (session {session!r}, current "
                               f"{current!r}), expected {expected!r}")
    if superuser or bypassrls or createrole or createdb or replication or inherit or memberships:
        raise RuntimeRoleError(f"{expected} has privileges a runtime role must not have")
    known = _VERIFIED.get(engine)
    if known is None:
        _VERIFIED[engine] = expected

        @event.listens_for(engine, "checkout")
        def _same_identity(dbapi_connection: Any, _record: Any, _proxy: Any) -> None:
            # Every checkout, so connections the pool opened before verification are covered too.
            if _driver_user(dbapi_connection) != expected:
                raise RuntimeRoleError("a pooled connection authenticated as a different role")
    elif known != expected:
        raise RuntimeRoleError("this engine was already verified for a different runtime role")
