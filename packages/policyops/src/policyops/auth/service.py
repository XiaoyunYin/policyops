"""Login, session and authorization decisions (framework-independent).

Login: `begin_login` stores a single-use request (digests of the browser-binding cookie, state and nonce, plus the
PKCE verifier) before redirecting. `complete_login` first consumes that request in its own short transaction, then
exchanges the code over HTTP with no transaction open, validates the ID token, and finally creates the principal
(if new, with no membership) and a fresh session in another short transaction.

Sessions: an opaque random cookie whose SHA-256 is stored, a CSRF token whose SHA-256 is stored, absolute and idle
expiry, revocation, and rotation (a new cookie and CSRF token, the old session revoked) whenever the workspace
changes. Rotation never extends the absolute lifetime.

Authorization: the request's expected context (the principal and workspace the client composed it for) must equal
the resolved session's, so a session rotated or replaced in another window refuses the request (409
`context_changed`) instead of running it under a different identity or workspace. The expected context is only a
refusal precondition: it never selects a workspace or grants anything. The workspace must be selected, and the
principal's roles are read from active memberships on every request, so a revocation takes effect immediately.
Permissions come from `policyops.domain.roles.PERMISSIONS`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import Connection, Engine

from policyops.auth import tokens
from policyops.auth.oidc import IdTokenClaims, OidcClient, OidcError, OidcUnavailable
from policyops.domain.roles import Action, Role, is_allowed
from policyops.persistence import identity
from policyops.persistence.database import transaction
from policyops.settings import AuthSettings
from policyops_contracts.clock import Clock
from policyops_contracts.errors import ErrorCode


TOUCH_INTERVAL = timedelta(seconds=60)  # upper bound; short idle windows refresh more often (touch_interval)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class AuthError(Exception):
    """A request is refused. `detail` is safe to show; it never contains tokens or identity-provider output."""

    def __init__(self, status: int, code: ErrorCode, detail: str, rule_id: str) -> None:
        super().__init__(detail)
        self.status, self.code, self.detail, self.rule_id = status, code, detail, rule_id


def unauthenticated(rule_id: str = "auth.session") -> AuthError:
    return AuthError(401, ErrorCode.UNAUTHENTICATED, "Sign in is required.", rule_id)


def forbidden(detail: str, rule_id: str) -> AuthError:
    return AuthError(403, ErrorCode.FORBIDDEN, detail, rule_id)


def context_changed(rule_id: str) -> AuthError:
    """The session no longer matches the request's expected principal or workspace. Raised before the operation's
    resources, roles or writes are touched, so the requested operation was not applied; resolving the session may
    still have refreshed its own `last_seen_at`."""
    return AuthError(409, ErrorCode.CONTEXT_CHANGED, "Your sign-in or selected workspace changed in another window, "
                     "so this request was not applied. Reload to continue.", rule_id)


def provider_unavailable() -> AuthError:
    return AuthError(503, ErrorCode.UNAVAILABLE, "The identity provider is unavailable. Try again later.",
                     "auth.provider")


@dataclass(frozen=True)
class LoginStart:
    redirect_url: str
    login_cookie: str


@dataclass(frozen=True, repr=False)
class IssuedSession:
    """Raw cookie values for the response; never logged (repr hides them)."""

    session_id: UUID
    cookie: str
    csrf: str
    return_to: str

    def __repr__(self) -> str:
        return f"IssuedSession(session_id={self.session_id}, return_to={self.return_to!r})"


@dataclass(frozen=True)
class SessionContext:
    session_id: UUID
    principal_id: UUID
    workspace_id: UUID | None
    expires_at: datetime
    csrf_sha256: str


@dataclass(frozen=True)
class ExpectedContext:
    """The principal and workspace a request was composed for (from the client's own `/me`). Compared with the
    resolved session before any authorization work; never a selector or a source of authority."""

    principal_id: UUID
    workspace_id: UUID


@dataclass(frozen=True)
class Authorized:
    session: SessionContext
    workspace_id: UUID
    roles: frozenset[Role]


def _display_name(claims: IdTokenClaims) -> str:
    for value in (claims.name, claims.preferred_username, claims.email):
        cleaned = CONTROL.sub("", value or "").strip()
        if cleaned:
            return cleaned[:200]
    return "Signed-in user"


def touch_interval(idle_ttl: timedelta) -> timedelta:
    """How stale `last_seen_at` may get before an authenticated request refreshes it: at most a quarter of the idle
    window, so continuous activity at any accepted idle TTL keeps the session open."""
    return min(TOUCH_INTERVAL, idle_ttl / 4)


@dataclass
class AuthService:
    settings: AuthSettings
    oidc: OidcClient
    auth_engine: Engine
    clock: Clock

    # -- login ---------------------------------------------------------------------------------------------

    def begin_login(self, return_to: str = "/") -> LoginStart:
        now = self.clock.now()
        binding, state, nonce = tokens.new_token(), tokens.new_token(), tokens.new_token()
        verifier, challenge = tokens.pkce_pair()
        try:
            request = identity.LoginRequest(
                id=uuid4(), binding_sha256=tokens.digest(binding), state_sha256=tokens.digest(state),
                nonce_sha256=tokens.digest(nonce), code_verifier=verifier, return_to=return_to, created_at=now,
                expires_at=now + self.settings.login_request_ttl)
        except ValidationError:
            raise AuthError(422, ErrorCode.INVALID_INPUT, "The return path is not allowed.", "auth.return_to") \
                from None
        try:
            url = self.oidc.authorization_url(state=state, nonce=nonce, code_challenge=challenge)  # discovery
        except OidcError:  # nothing stored yet: a provider failure leaves no login request behind
            raise provider_unavailable() from None
        with transaction(self.auth_engine) as connection:
            identity.create_login_request(connection, request)
        return LoginStart(redirect_url=url, login_cookie=binding)

    def complete_login(self, *, binding: str | None, state: str | None, code: str | None,
                       error: str | None) -> IssuedSession:
        if not binding or not state:
            raise unauthenticated("auth.login_state")
        with transaction(self.auth_engine) as connection:  # single use, committed before any HTTP
            consumed = identity.consume_login_request(connection, state_sha256=tokens.digest(state),
                                                      binding_sha256=tokens.digest(binding), now=self.clock.now())
        if consumed is None:
            raise unauthenticated("auth.login_state")
        if error is not None or not code:
            raise unauthenticated("auth.login_denied")
        try:
            id_token = self.oidc.exchange_code(code, consumed.code_verifier)
            claims = self.oidc.validate_id_token(id_token, nonce_sha256=consumed.nonce_sha256)
        except OidcUnavailable:  # the login request stays consumed; the user starts a new login
            raise provider_unavailable() from None
        except OidcError:
            raise unauthenticated("auth.id_token") from None
        now = self.clock.now()
        with transaction(self.auth_engine) as connection:
            principal_id = identity.find_or_create_principal(
                connection, issuer=claims.iss, subject=claims.sub, display_name=_display_name(claims), now=now)
            issued = self._new_session(connection, principal_id=principal_id, workspace_id=None, now=now,
                                       expires_at=now + self.settings.session_absolute_ttl, rotated_from=None,
                                       return_to=consumed.return_to)
        return issued

    def _new_session(self, connection: Connection, *, principal_id: UUID, workspace_id: UUID | None, now: datetime,
                     expires_at: datetime, rotated_from: UUID | None, return_to: str) -> IssuedSession:
        cookie, csrf, session_id = tokens.new_token(), tokens.new_token(), uuid4()
        identity.create_session(connection, session_id=session_id, principal_id=principal_id,
                                workspace_id=workspace_id, cookie_sha256=tokens.digest(cookie),
                                csrf_sha256=tokens.digest(csrf), now=now, expires_at=expires_at,
                                rotated_from=rotated_from)
        return IssuedSession(session_id=session_id, cookie=cookie, csrf=csrf, return_to=return_to)

    # -- sessions ------------------------------------------------------------------------------------------

    def resolve(self, cookie: str | None) -> SessionContext:
        if not cookie or len(cookie) > 200:
            raise unauthenticated()
        now = self.clock.now()
        with transaction(self.auth_engine) as connection:
            record = identity.load_session(connection, tokens.digest(cookie))
            if (record is None or record.revoked_at is not None or record.csrf_sha256 is None
                    or record.last_seen_at is None or now >= record.expires_at
                    or now - record.last_seen_at >= self.settings.session_idle_ttl):
                raise unauthenticated()
            if now - record.last_seen_at >= touch_interval(self.settings.session_idle_ttl):
                identity.touch_session(connection, record.id, now)
        return SessionContext(session_id=record.id, principal_id=record.principal_id,
                              workspace_id=record.workspace_id, expires_at=record.expires_at,
                              csrf_sha256=record.csrf_sha256)

    def check_csrf(self, session: SessionContext, token: str | None) -> None:
        if not tokens.matches(token, session.csrf_sha256):
            raise forbidden("The request could not be verified.", "auth.csrf")

    def logout(self, session: SessionContext) -> None:
        with transaction(self.auth_engine) as connection:
            identity.revoke_session(connection, session.session_id, self.clock.now())

    def select_workspace(self, session: SessionContext, workspace_id: UUID) -> IssuedSession:
        """Rotate to a new session bound to `workspace_id`, which must have an active membership."""
        now = self.clock.now()
        with transaction(self.auth_engine) as connection:
            if not identity.active_roles(connection, session.principal_id, workspace_id):
                raise AuthError(404, ErrorCode.NOT_FOUND, "No such workspace.", "auth.workspace")
            if not identity.revoke_session(connection, session.session_id, now):
                raise unauthenticated()  # a concurrent logout or rotation won
            return self._new_session(connection, principal_id=session.principal_id, workspace_id=workspace_id,
                                     now=now, expires_at=session.expires_at, rotated_from=session.session_id,
                                     return_to="/")

    def workspaces(self, session: SessionContext) -> list[identity.WorkspaceChoice]:
        with transaction(self.auth_engine) as connection:
            return identity.workspace_choices(connection, session.principal_id)

    # -- authorization -------------------------------------------------------------------------------------

    def roles(self, session: SessionContext) -> frozenset[Role]:
        if session.workspace_id is None:
            return frozenset()
        with transaction(self.auth_engine) as connection:
            names = identity.active_roles(connection, session.principal_id, session.workspace_id)
        return frozenset(Role(name) for name in names)

    def authorize(self, session: SessionContext, action: Action, *, expected: ExpectedContext) -> Authorized:
        """Refuse unless `session` is the expected principal in the expected workspace (409, before any membership
        read), then require a selected workspace, a membership and a role allowing `action` (403). `expected` is
        mandatory: there is no unbound path to an `Authorized`."""
        if not isinstance(expected, ExpectedContext):  # typed callers cannot omit it; refuse a None at runtime too
            raise TypeError("an ExpectedContext is required")
        if session.principal_id != expected.principal_id:
            raise context_changed("auth.principal_changed")
        if session.workspace_id != expected.workspace_id:  # including an unselected session
            raise context_changed("auth.workspace_changed")
        if session.workspace_id is None:
            raise forbidden("Select a workspace first.", "auth.workspace_required")
        roles = self.roles(session)
        if not roles:
            raise forbidden("You are not a member of this workspace.", "auth.membership")
        if not is_allowed(roles, action):
            raise forbidden("Your role does not allow this action.", "auth.role")
        return Authorized(session=session, workspace_id=session.workspace_id, roles=roles)
