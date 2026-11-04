"""Overflow-safe binding lifetimes.

Durations are checked by subtraction (end - start), which cannot overflow,
instead of start + TTL, which raises OverflowError near datetime.max. Computed
expiries are capped at the largest representable UTC time.
"""

from datetime import UTC, datetime, timedelta


BINDING_TTL = timedelta(minutes=15)
MAX_UTC = datetime.max.replace(tzinfo=UTC)


def within_ttl(start: datetime, end: datetime, ttl: timedelta = BINDING_TTL) -> bool:
    """start < end and the interval is at most ttl."""
    return start < end and end - start <= ttl


def expiry_after(start: datetime, ttl: timedelta = BINDING_TTL) -> datetime:
    """start + ttl, capped at the largest representable UTC time."""
    if MAX_UTC - start <= ttl:
        return MAX_UTC
    return start + ttl
