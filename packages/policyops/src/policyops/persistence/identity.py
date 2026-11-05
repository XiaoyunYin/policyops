"""Typed identity repositories for the auth runtime role (`database.transaction(auth_engine)`).

They store and read login requests, principals, sessions and memberships; the decisions (expiry, CSRF, rotation,
which workspace may be selected) are made by `policyops.auth.service`. Only digests of browser tokens are stored.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import AfterValidator, StringConstraints
from sqlalchemy import Connection, text

from policyops.persistence.records import MembershipRole
from policyops_contracts.base import WireModel
from policyops_contracts.scalars import Sha256Hex, ShortText, Slug, UtcDatetime


def _no_dot_segments(value: str) -> str:
    if any(segment in (".", "..") for segment in value.split("/")):
        raise ValueError("return paths must not contain '.' or '..' segments")
    return value


ReturnPath = Annotated[str, StringConstraints(pattern=r"^/([A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*)?$", max_length=200),
                       AfterValidator(_no_dot_segments)]
Verifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._~-]{43,128}$")]


class LoginRequest(WireModel):
    id: UUID
    binding_sha256: Sha256Hex
    state_sha256: Sha256Hex
    nonce_sha256: Sha256Hex
    code_verifier: Verifier
    return_to: ReturnPath
    created_at: UtcDatetime
    expires_at: UtcDatetime


class ConsumedLogin(WireModel):
    id: UUID
    nonce_sha256: Sha256Hex
    code_verifier: Verifier
    return_to: ReturnPath


class SessionRecord(WireModel):
    id: UUID
    principal_id: UUID
    workspace_id: UUID | None
    created_at: UtcDatetime
    expires_at: UtcDatetime
    last_seen_at: UtcDatetime | None
    revoked_at: UtcDatetime | None
    csrf_sha256: Sha256Hex | None


class WorkspaceChoice(WireModel):
    workspace_id: UUID
    slug: Slug
    name: ShortText
    roles: tuple[MembershipRole, ...]


def create_login_request(connection: Connection, request: LoginRequest) -> None:
    connection.execute(text(
        "INSERT INTO identity.login_requests (id, binding_sha256, state_sha256, nonce_sha256, code_verifier, "
        "return_to, created_at, expires_at) VALUES (:id, :binding_sha256, :state_sha256, :nonce_sha256, "
        ":code_verifier, :return_to, :created_at, :expires_at)"), request.model_dump())


def consume_login_request(connection: Connection, *, state_sha256: str, binding_sha256: str,
                          now: datetime) -> ConsumedLogin | None:
    """Atomically mark the matching, unexpired, unused request as used and return it; None otherwise. A request
    is usable at most once whatever happens afterwards (the code exchange runs outside this transaction)."""
    row = connection.execute(text(
        "UPDATE identity.login_requests SET consumed_at = :now WHERE state_sha256 = :state AND binding_sha256 = "
        ":binding AND consumed_at IS NULL AND expires_at > :now "
        "RETURNING id, nonce_sha256, code_verifier, return_to"),
        {"now": now, "state": state_sha256, "binding": binding_sha256}).mappings().first()
    return ConsumedLogin.model_validate(dict(row), strict=False) if row else None


def find_or_create_principal(connection: Connection, *, issuer: str, subject: str, display_name: str,
                             now: datetime) -> UUID:
    """Identity is issuer + subject (never email). A new principal gets no membership."""
    connection.execute(text(
        "INSERT INTO identity.principals (id, issuer, subject, display_name, created_at) VALUES (:id, :issuer, "
        ":subject, :name, :now) ON CONFLICT (issuer, subject) DO NOTHING"),
        {"id": uuid4(), "issuer": issuer, "subject": subject, "name": display_name, "now": now})
    principal_id: UUID = connection.execute(text(
        "SELECT id FROM identity.principals WHERE issuer = :issuer AND subject = :subject"),
        {"issuer": issuer, "subject": subject}).scalar_one()
    return principal_id


def create_session(connection: Connection, *, session_id: UUID, principal_id: UUID, workspace_id: UUID | None,
                   cookie_sha256: str, csrf_sha256: str, now: datetime, expires_at: datetime,
                   rotated_from: UUID | None) -> None:
    connection.execute(text(
        "INSERT INTO identity.sessions (id, principal_id, workspace_id, cookie_sha256, created_at, expires_at, "
        "rotated_from, last_seen_at, csrf_sha256) VALUES (:id, :principal, :workspace, :cookie, :now, :expires, "
        ":rotated_from, :now, :csrf)"),
        {"id": session_id, "principal": principal_id, "workspace": workspace_id, "cookie": cookie_sha256,
         "now": now, "expires": expires_at, "rotated_from": rotated_from, "csrf": csrf_sha256})


def load_session(connection: Connection, cookie_sha256: str) -> SessionRecord | None:
    row = connection.execute(text(
        "SELECT id, principal_id, workspace_id, created_at, expires_at, last_seen_at, revoked_at, csrf_sha256 "
        "FROM identity.sessions WHERE cookie_sha256 = :cookie"), {"cookie": cookie_sha256}).mappings().first()
    return SessionRecord.model_validate(dict(row), strict=False) if row else None


def touch_session(connection: Connection, session_id: UUID, now: datetime) -> None:
    connection.execute(text("UPDATE identity.sessions SET last_seen_at = :now WHERE id = :id AND revoked_at IS NULL "
                            "AND last_seen_at < :now AND expires_at >= :now"), {"id": session_id, "now": now})


def revoke_session(connection: Connection, session_id: UUID, now: datetime) -> bool:
    """Revoke if still active; True if this call revoked it (False if it was already revoked)."""
    revoked = connection.execute(text(
        "UPDATE identity.sessions SET revoked_at = :now WHERE id = :id AND revoked_at IS NULL"),
        {"id": session_id, "now": now}).rowcount
    return bool(revoked)


def active_roles(connection: Connection, principal_id: UUID, workspace_id: UUID) -> frozenset[str]:
    rows = connection.execute(text(
        "SELECT role FROM identity.memberships WHERE principal_id = :p AND workspace_id = :w AND revoked_at IS NULL"),
        {"p": principal_id, "w": workspace_id}).scalars().all()
    return frozenset(rows)


def workspace_choices(connection: Connection, principal_id: UUID) -> list[WorkspaceChoice]:
    rows = connection.execute(text(
        "SELECT w.id, w.slug, w.name, array_agg(m.role ORDER BY m.role) AS roles FROM identity.memberships m "
        "JOIN identity.workspaces w ON w.id = m.workspace_id WHERE m.principal_id = :p AND m.revoked_at IS NULL "
        "GROUP BY w.id, w.slug, w.name ORDER BY w.slug"), {"p": principal_id}).mappings().all()
    return [WorkspaceChoice(workspace_id=row["id"], slug=row["slug"], name=row["name"], roles=tuple(row["roles"]))
            for row in rows]
