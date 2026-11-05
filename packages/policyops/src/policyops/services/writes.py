"""The idempotent write path shared by the case (T08) and run (T09) operations.

One short transaction in the authorized workspace's scope:

1. lock the idempotency key's scope. After that (possibly contended) wait, recheck the principal's current role
   for the action and that the target resource is visible in this workspace (404 otherwise), so a revoked member
   gets no replay and a foreign ID stays hidden;
2. look the key up. The same intent replays the ORIGINAL stored response (status, body, ETag), whatever happened
   to the resource since; a different intent for the key conflicts (409). This precedes any version check, so a
   retried, already-committed write with its old precondition replays instead of failing as stale;
3. otherwise run the operation's `mutate` (which takes its own row locks, rechecks the role after waiting for
   them and checks preconditions), then store the response. All of it commits or rolls back together; failures
   store nothing, so the key can be retried.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
import json
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine

from policyops.auth.service import AuthError, Authorized, forbidden
from policyops.domain.roles import Action, Role, is_allowed
from policyops.persistence import idempotency as idem
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.persistence.records import AuditEvent
from policyops_contracts.errors import ErrorCode


def not_found(what: str = "case") -> AuthError:
    return AuthError(404, ErrorCode.NOT_FOUND, f"No such {what}.", f"api.{what}_not_found")


@dataclass(frozen=True)
class WriteResult:
    status: int
    body: dict[str, Any]
    etag: str | None
    case_id: UUID
    message_id: UUID | None
    replayed: bool
    run_id: UUID | None = None


def recheck(connection: Connection, authorized: Authorized, action: Action) -> None:
    """The principal's current roles in the scoped workspace, read in the caller's transaction."""
    roles = frozenset(Role(name) for name in repo.scoped_roles(connection, authorized.session.principal_id))
    if not roles:
        raise forbidden("You are not a member of this workspace.", "auth.membership")
    if not is_allowed(roles, action):
        raise forbidden("Your role does not allow this action.", "auth.role")


def audit(connection: Connection, authorized: Authorized, *, action: str, target_type: str, target_id: UUID,
          before: str | None, after: str | None, occurred_at: datetime) -> None:
    repo.append_audit(connection, AuditEvent(
        id=uuid4(), workspace_id=authorized.workspace_id, actor_kind="principal",
        actor_principal_id=authorized.session.principal_id, action=action, target_type=target_type,
        target_id=target_id, before_sha256=before, after_sha256=after, correlation_id=uuid4(),
        occurred_at=occurred_at))


def idempotent_write(engine: Engine, authorized: Authorized, *, key: str, intent: idem.Intent, action: Action,
                     visible: Callable[[Connection], bool] | None, missing: str,
                     mutate: Callable[[Connection], WriteResult], now: Callable[[Connection], datetime]
                     ) -> WriteResult:
    """`visible` (None when the write names no existing resource) runs after the key lock and role recheck and
    before any replay; it returning False is a 404 for `missing` (for example "case" or "run")."""
    operation, digest = intent.operation, idem.intent_sha256(intent)
    principal = authorized.session.principal_id
    with workspace_transaction(engine, authorized.workspace_id) as connection:
        idem.lock(connection, workspace_id=authorized.workspace_id, principal_id=principal, operation=operation,
                  key=key)
        recheck(connection, authorized, action)  # after waiting for the key lock; before any replay
        if visible is not None and not visible(connection):
            raise not_found(missing)
        stored = idem.find(connection, principal_id=principal, operation=operation, key=key)
        if stored is not None:
            if stored.request_sha256 != digest:
                raise AuthError(409, ErrorCode.CONFLICT, "This Idempotency-Key was used for a different request.",
                                "api.idempotency_mismatch")
            return WriteResult(status=stored.status, body=idem.body(stored), etag=stored.etag,
                               case_id=stored.case_id, message_id=stored.message_id, replayed=True,
                               run_id=stored.run_id)
        result = mutate(connection)
        idem.store(connection, idem.NewRecord(
            workspace_id=authorized.workspace_id, principal_id=principal, operation=operation, idempotency_key=key,
            request_sha256=digest, case_id=result.case_id, message_id=result.message_id, run_id=result.run_id,
            status=result.status, body_json=json.dumps(result.body, sort_keys=True), etag=result.etag,
            created_at=now(connection)))
    return result
