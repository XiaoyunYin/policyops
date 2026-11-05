"""Case status transitions (pure; no I/O). The SQL CHECK on app.cases.status is only a storage guard.

open -> in_progress -> resolved -> closed, plus resolved -> in_progress (reopen). closed is terminal. Asking for the
current status is a no-op, not a transition.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


TRANSITIONS: MappingProxyType[CaseStatus, frozenset[CaseStatus]] = MappingProxyType({
    CaseStatus.OPEN: frozenset({CaseStatus.IN_PROGRESS}),
    CaseStatus.IN_PROGRESS: frozenset({CaseStatus.RESOLVED}),
    CaseStatus.RESOLVED: frozenset({CaseStatus.CLOSED, CaseStatus.IN_PROGRESS}),
    CaseStatus.CLOSED: frozenset(),
})


class TransitionRefused(ValueError):
    """The requested status is not reachable from the current one."""


def plan_transition(current: CaseStatus, target: CaseStatus) -> bool:
    """True if `target` is a real transition, False for a no-op (same status); raises TransitionRefused otherwise."""
    if target == current:
        return False
    if target not in TRANSITIONS[current]:
        raise TransitionRefused(f"a case cannot move from {current.value} to {target.value}")
    return True
