"""Workspace role x action matrix.

Reviewers decide proposals. Admins manage memberships but are not implicitly
reviewers; a principal needs the reviewer role itself to approve. Auditors only
read. Membership and revocation are checked on use by the services (T07).
"""

from enum import StrEnum
from types import MappingProxyType


class Role(StrEnum):
    ANALYST = "analyst"
    REVIEWER = "reviewer"
    ADMIN = "admin"
    AUDITOR = "auditor"


class Action(StrEnum):
    VIEW_CASE = "view_case"
    CREATE_CASE = "create_case"
    UPDATE_CASE_STATUS = "update_case_status"
    POST_STAFF_NOTE = "post_staff_note"
    ENTER_CUSTOMER_TURN = "enter_customer_turn"
    START_RUN = "start_run"
    CANCEL_RUN = "cancel_run"
    DECIDE_PROPOSAL = "decide_proposal"
    MANAGE_MEMBERSHIP = "manage_membership"
    READ_AUDIT = "read_audit"
    READ_EVALUATIONS = "read_evaluations"


_OPERATE = frozenset({Action.VIEW_CASE, Action.CREATE_CASE, Action.UPDATE_CASE_STATUS, Action.POST_STAFF_NOTE,
                      Action.ENTER_CUSTOMER_TURN, Action.START_RUN, Action.CANCEL_RUN})

PERMISSIONS: MappingProxyType[Role, frozenset[Action]] = MappingProxyType({
    Role.ANALYST: _OPERATE,
    Role.REVIEWER: _OPERATE | {Action.DECIDE_PROPOSAL, Action.READ_AUDIT, Action.READ_EVALUATIONS},
    Role.ADMIN: _OPERATE | {Action.MANAGE_MEMBERSHIP, Action.READ_AUDIT, Action.READ_EVALUATIONS},
    Role.AUDITOR: frozenset({Action.VIEW_CASE, Action.READ_AUDIT, Action.READ_EVALUATIONS}),
})


def is_allowed(roles: frozenset[Role], action: Action) -> bool:
    """True if any of the principal's current workspace roles grants the action."""
    return any(action in PERMISSIONS[role] for role in roles)
