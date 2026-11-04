"""Injectable UTC clocks.

Services take a `Clock` instead of reading the wall clock, so tests control time.
Every clock returns timezone-aware `datetime.UTC`. Naive inputs and inputs not at
offset zero are rejected; a zero-offset instant in another tzinfo is normalized to
`datetime.UTC`, because such a zone may change its offset later (e.g. seasonally).
Steps must be positive. Advancing past the largest
representable UTC time raises `OverflowError` explicitly.
"""

from datetime import UTC, datetime, timedelta
from typing import Protocol

from policyops_contracts.timing import MAX_UTC


class Clock(Protocol):
    def now(self) -> datetime: ...


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("clock times must be timezone-aware UTC")
    return value.replace(tzinfo=UTC)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """Returns the same instant until moved explicitly."""

    def __init__(self, at: datetime) -> None:
        self._at = _utc(at)

    def now(self) -> datetime:
        return self._at

    def advance(self, delta: timedelta) -> datetime:
        if delta <= timedelta(0):
            raise ValueError("clocks only move forward")
        if MAX_UTC - self._at < delta:
            raise OverflowError("advancing past the largest representable UTC time")
        self._at = self._at + delta
        return self._at


class SteppingClock(FixedClock):
    """Each `now()` returns the current instant, then moves forward by `step`."""

    def __init__(self, start: datetime, step: timedelta) -> None:
        super().__init__(start)
        if step <= timedelta(0):
            raise ValueError("step must be positive")
        self._step = step

    def now(self) -> datetime:
        current = super().now()
        self.advance(self._step)
        return current
