"""Durable customer authentication per run (T17): first write wins, a conflicting identity is refused.

Only the gateway writes a row, from a lookup it actually performed through the retail client within the run's
scope. There is no API that accepts one. `record` is first write wins: the identical authentication again, or a
later successful lookup of the same customer in the same run (another lookup call or step), returns the first
record unchanged. A different customer for the run is refused (`AuthenticationConflict`), never adopted. The table's
composite foreign keys also refuse a row that names a run of another case or a customer the case is not bound to.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from policyops_contracts.scalars import RunScope
from policyops_contracts.seeds import CustomerAuthentication


class AuthenticationConflict(RuntimeError):
    """The run already has a different authentication, or the record names another case's run or customer."""


COLUMNS = ("workspace_id, case_id, run_id, user_id, lookup_tool, lookup_call_sha256, step_sequence, "
           "authenticated_at")


def _authentication(row: Any) -> CustomerAuthentication:
    return CustomerAuthentication.model_validate({
        "scope": {"workspace_id": row["workspace_id"], "case_id": row["case_id"], "run_id": row["run_id"]},
        "user_id": row["user_id"], "lookup_tool": row["lookup_tool"], "lookup_call_sha256": row["lookup_call_sha256"],
        "step_sequence": row["step_sequence"], "authenticated_at": row["authenticated_at"]})


def load(connection: Connection, scope: RunScope) -> CustomerAuthentication | None:
    """The run's authentication, if any. The caller's transaction sets the workspace scope (RLS)."""
    row = connection.execute(text(f"SELECT {COLUMNS} FROM app.customer_authentications "  # noqa: S608 - fixed
                                  "WHERE workspace_id = :w AND run_id = :r"),
                             {"w": scope.workspace_id, "r": scope.run_id}).mappings().first()
    if row is None:
        return None
    found = _authentication(row)
    if found.scope != scope:
        raise AuthenticationConflict("the stored authentication belongs to another case")
    return found


def record(connection: Connection, authentication: CustomerAuthentication) -> CustomerAuthentication:
    """Insert once (first write wins). The identical authentication again, or a later successful lookup of the same
    customer in the same run, returns the first record unchanged; a different customer, or a row naming another
    case's run or a customer the case is not bound to, raises AuthenticationConflict."""
    scope = authentication.scope
    try:
        with connection.begin_nested():
            inserted = connection.execute(text(
                "INSERT INTO app.customer_authentications (" + COLUMNS + ") VALUES (:w, :c, :r, :u, :tool, :sha, "  # noqa: S608
                ":seq, :at) ON CONFLICT (workspace_id, run_id) DO NOTHING RETURNING run_id"),
                {"w": scope.workspace_id, "c": scope.case_id, "r": scope.run_id, "u": authentication.user_id,
                 "tool": authentication.lookup_tool, "sha": authentication.lookup_call_sha256,
                 "seq": authentication.step_sequence, "at": authentication.authenticated_at}).first()
    except IntegrityError:
        raise AuthenticationConflict("the authentication names another case's run or customer") from None
    if inserted is not None:
        return authentication
    existing = load(connection, scope)
    if existing is None or existing.user_id != authentication.user_id:
        raise AuthenticationConflict("the run is already authenticated as someone else")
    return existing  # first write wins: a repeated successful lookup of the same customer keeps the first record


def run_ids(connection: Connection) -> list[UUID]:
    """Authenticated runs visible in the caller's workspace scope (inspection and tests)."""
    return [row[0] for row in connection.execute(text("SELECT run_id FROM app.customer_authentications"))]
