"""The time authority for leases, deadlines and run/job/event times (T09).

Production uses the database: `DatabaseLeaseClock.now(connection)` reads `clock_timestamp()`, the current time,
not `now()`, which is the transaction's start time: a transaction that began before a lease expired and then waited
for a row lock past the expiry would otherwise still see the lease as current. Callers therefore read the clock
**after** acquiring the locks a decision depends on, never reuse a timestamp taken before a wait, and every process
defers to the one database clock. No timestamp from a browser, a worker payload or a process clock is proof that
a lease is current.
`FixedLeaseClock` adapts a controlled `FixedClock` for deterministic tests; runtime wiring refuses it outside the
test environment (`require_test_environment`).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import Connection, text

from policyops_contracts.clock import FixedClock


class UnsafeTestHook(RuntimeError):
    """A test-only runtime component was wired outside the test environment."""


class LeaseClock(Protocol):
    def now(self, connection: Connection) -> datetime: ...


class DatabaseLeaseClock:
    """PostgreSQL's current time (`clock_timestamp()`), read on the caller's connection."""

    def now(self, connection: Connection) -> datetime:
        value: datetime = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
        return value.astimezone(UTC)


class FixedLeaseClock:
    """Test adapter: the controlled clock's time, whatever the database says."""

    test_only = True

    def __init__(self, clock: FixedClock) -> None:
        self.clock = clock

    def now(self, connection: Connection) -> datetime:
        del connection
        return self.clock.now()


def require_test_environment(component: object, env: str) -> None:
    if getattr(component, "test_only", False) and env != "test":
        raise UnsafeTestHook(f"{type(component).__name__} is only allowed when POLICYOPS_ENV=test")
