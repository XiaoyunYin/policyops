"""Authentication routes and reusable authorization dependencies.

Routes (under /api/v1):
* `GET /auth/login?return_to=/path`: store a single-use login request, set the browser-binding cookie, 302 to the
  issuer. `GET /auth/callback`: complete the login, set the session and CSRF cookies, 303 to the stored path.
* `GET /me`: the principal's workspaces (from active memberships), the selected workspace and its roles.
* `POST /auth/workspace`: select a workspace (rotates the session). `POST /auth/logout`: revoke the session.
* `GET /workspace/members`, `POST /workspace/members/{id}/revoke`: the narrow admin membership surface.

Every unsafe method needs an exact `Origin` (or, without it, a `Referer` on the public origin) and the session's
synchronizer token in `X-CSRF-Token`. The CSRF token reaches the browser in its own non-HttpOnly cookie when the
session is created; the server stores only its digest and compares against it, so it is not a bare double-submit
cookie. CORS stays disabled (no CORS middleware). Auth responses are `no-store` and `Referrer-Policy: no-referrer`.

`require_action(Action.X)` is the reusable dependency for later routes: it resolves the session, the selected
workspace and the principal's current roles, and refuses (401/403) before the route runs. Routes that load a
resource must then use `workspace_transaction(app_engine, authorized.workspace_id)`, so another workspace's
resource is simply not found (404).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Engine
from starlette.exceptions import HTTPException as StarletteHTTPException

from policyops.auth.service import AuthError, Authorized, AuthService, IssuedSession, SessionContext, forbidden
from policyops.domain.roles import Action, Role
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.settings import AuthSettings
from policyops_contracts.errors import ErrorCode, ErrorEnvelope


UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CSRF_HEADER = "X-CSRF-Token"
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}


@dataclass(frozen=True)
class AuthRuntime:
    settings: AuthSettings
    service: AuthService
    app_engine: Engine

    @property
    def csrf_cookie(self) -> str:
        return "__Host-policyops_csrf" if self.settings.secure_cookies else "policyops_csrf_local"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkspaceOut(Model):
    workspace_id: UUID
    slug: str
    name: str
    roles: list[Role]


class MeOut(Model):
    principal_id: UUID
    workspace_id: UUID | None
    roles: list[Role]
    workspaces: list[WorkspaceOut]


class SelectWorkspaceIn(Model):
    workspace_id: UUID


class MembershipOut(Model):
    membership_id: UUID
    principal_id: UUID
    role: Role
    active: bool


def runtime(request: Request) -> AuthRuntime:
    value: AuthRuntime = request.app.state.auth
    return value


Runtime = Annotated[AuthRuntime, Depends(runtime)]


def error_response(error: AuthError) -> JSONResponse:
    envelope = ErrorEnvelope(code=error.code, detail=error.detail, rule_id=error.rule_id, correlation_id=uuid4(),
                             retryable=False)
    return JSONResponse(envelope.model_dump(mode="json"), status_code=error.status, headers=NO_STORE)


def _cookie(response: Response, auth: AuthRuntime, name: str, value: str, *, max_age: int, http_only: bool,
            same_site: str) -> None:
    response.set_cookie(name, value, max_age=max_age, path="/", secure=auth.settings.secure_cookies,
                        httponly=http_only, samesite=same_site)  # type: ignore[arg-type]


def _clear(response: Response, auth: AuthRuntime, *names: str) -> None:
    for name in names:
        response.delete_cookie(name, path="/", secure=auth.settings.secure_cookies, httponly=True, samesite="lax")


def _issue(response: Response, auth: AuthRuntime, issued: IssuedSession) -> None:
    max_age = int(auth.settings.session_absolute_ttl.total_seconds())
    _cookie(response, auth, auth.settings.session_cookie, issued.cookie, max_age=max_age, http_only=True,
            same_site="lax")
    _cookie(response, auth, auth.csrf_cookie, issued.csrf, max_age=max_age, http_only=False, same_site="strict")


def current_session(request: Request, auth: Runtime) -> SessionContext:
    session = auth.service.resolve(request.cookies.get(auth.settings.session_cookie))
    if request.method in UNSAFE:
        check_origin(request, auth.settings)
        auth.service.check_csrf(session, request.headers.get(CSRF_HEADER))
    return session


def check_origin(request: Request, settings: AuthSettings) -> None:
    origin = request.headers.get("origin")
    if origin is not None:
        if origin != settings.public_origin:
            raise forbidden("The request origin is not allowed.", "auth.origin")
        return
    referer = request.headers.get("referer")
    if referer is None or not (referer == settings.public_origin or referer.startswith(settings.public_origin + "/")):
        raise forbidden("The request origin is not allowed.", "auth.origin")


Session = Annotated[SessionContext, Depends(current_session)]


def require_action(action: Action) -> Callable[..., Authorized]:
    """Reusable dependency: an authenticated session, a selected workspace and a role allowing `action`."""
    def dependency(session: Session, auth: Runtime) -> Authorized:
        return auth.service.authorize(session, action)

    dependency.__name__ = f"require_{action.value}"
    return dependency


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/auth/login")
    def login(auth: Runtime, return_to: str = "/") -> Response:
        start = auth.service.begin_login(return_to)
        response = RedirectResponse(start.redirect_url, status_code=302, headers=NO_STORE)
        _cookie(response, auth, auth.settings.login_cookie, start.login_cookie,
                max_age=int(auth.settings.login_request_ttl.total_seconds()), http_only=True, same_site="lax")
        return response

    @router.get("/auth/callback")
    def callback(request: Request, auth: Runtime, state: str | None = None, code: str | None = None,
                 error: str | None = None) -> Response:
        try:
            issued = auth.service.complete_login(binding=request.cookies.get(auth.settings.login_cookie),
                                                 state=state, code=code, error=error)
        except AuthError as exc:
            response: Response = error_response(exc)
            _clear(response, auth, auth.settings.login_cookie)
            return response
        response = RedirectResponse(issued.return_to, status_code=303, headers=NO_STORE)
        _clear(response, auth, auth.settings.login_cookie)
        _issue(response, auth, issued)
        return response

    @router.get("/me", response_model=MeOut)
    def me(session: Session, auth: Runtime) -> Response:
        choices = auth.service.workspaces(session)
        roles = sorted(auth.service.roles(session))
        body = MeOut(principal_id=session.principal_id, workspace_id=session.workspace_id, roles=roles,
                     workspaces=[WorkspaceOut(workspace_id=c.workspace_id, slug=c.slug, name=c.name,
                                              roles=[Role(r) for r in c.roles]) for c in choices])
        return JSONResponse(body.model_dump(mode="json"), headers=NO_STORE)

    @router.post("/auth/workspace", status_code=204)
    def select_workspace(body: SelectWorkspaceIn, session: Session, auth: Runtime) -> Response:
        issued = auth.service.select_workspace(session, body.workspace_id)
        response = Response(status_code=204, headers=NO_STORE)
        _issue(response, auth, issued)
        return response

    @router.post("/auth/logout", status_code=204)
    def logout(session: Session, auth: Runtime) -> Response:
        auth.service.logout(session)
        response = Response(status_code=204, headers=NO_STORE)
        _clear(response, auth, auth.settings.session_cookie, auth.csrf_cookie, auth.settings.login_cookie)
        return response

    @router.get("/workspace/members", response_model=list[MembershipOut])
    def members(authorized: Annotated[Authorized, Depends(require_action(Action.MANAGE_MEMBERSHIP))],
                auth: Runtime) -> list[MembershipOut]:
        with workspace_transaction(auth.app_engine, authorized.workspace_id) as connection:
            rows = repo.workspace_memberships(connection)
        return [MembershipOut(membership_id=m.id, principal_id=m.principal_id, role=Role(m.role),
                              active=m.revoked_at is None) for m in rows]

    @router.post("/workspace/members/{membership_id}/revoke", status_code=204)
    def revoke_member(membership_id: UUID,
                      authorized: Annotated[Authorized, Depends(require_action(Action.MANAGE_MEMBERSHIP))],
                      auth: Runtime) -> Response:
        with workspace_transaction(auth.app_engine, authorized.workspace_id) as connection:
            if not repo.revoke_membership(connection, membership_id, auth.service.clock.now()):
                raise AuthError(404, ErrorCode.NOT_FOUND, "No such membership.", "auth.membership")
        return Response(status_code=204, headers=NO_STORE)

    return router


def install(app: FastAPI, auth: AuthRuntime) -> None:
    app.state.auth = auth
    app.include_router(build_router(), prefix="/api/v1")

    @app.exception_handler(AuthError)
    def _auth_error(_request: Request, exc: AuthError) -> JSONResponse:
        return error_response(exc)


HTTP_CODES = {401: ErrorCode.UNAUTHENTICATED, 403: ErrorCode.FORBIDDEN, 404: ErrorCode.NOT_FOUND,
              405: ErrorCode.INVALID_INPUT, 409: ErrorCode.CONFLICT, 429: ErrorCode.RATE_LIMITED,
              503: ErrorCode.UNAVAILABLE}
HTTP_DETAILS = {404: "Not found.", 405: "This method is not allowed here."}


def install_error_boundary(app: FastAPI) -> None:
    """Every /api/v1 response is no-store/no-referrer, and errors use the standard envelope: framework HTTP errors
    (404/405, keeping headers such as Allow), request validation (422, no echo of the input) and unexpected
    failures (500, no internals) included."""
    @app.middleware("http")
    async def _no_store(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        if request.url.path.startswith("/api/v1"):
            for name, value in NO_STORE.items():
                response.headers.setdefault(name, value)
        return response

    @app.exception_handler(StarletteHTTPException)
    def _http(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        fallback = ErrorCode.INTERNAL if exc.status_code >= 500 else ErrorCode.INVALID_INPUT
        code = HTTP_CODES.get(exc.status_code, fallback)
        response = error_response(AuthError(exc.status_code, code, HTTP_DETAILS.get(exc.status_code, "The request "
                                            "could not be completed."), f"api.http_{exc.status_code}"))
        for name, value in (exc.headers or {}).items():  # e.g. Allow on 405
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(RequestValidationError)
    def _invalid(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return error_response(AuthError(422, ErrorCode.INVALID_INPUT, "The request is not valid.", "api.invalid_input"))

    @app.exception_handler(Exception)
    def _unexpected(_request: Request, _exc: Exception) -> JSONResponse:
        return error_response(AuthError(500, ErrorCode.INTERNAL, "Something went wrong.", "api.internal"))
