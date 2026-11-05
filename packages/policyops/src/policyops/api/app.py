"""FastAPI application factory and authentication wiring."""

from typing import Literal

from fastapi import APIRouter, FastAPI
import httpx
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Engine

from policyops import __version__
from policyops.api import auth as auth_api
from policyops.api import cases as cases_api
from policyops.api import docs
from policyops.api.body_limit import BodyLimit
from policyops.auth.oidc import OidcClient
from policyops.auth.service import AuthService
from policyops.persistence.database import verify_runtime_role
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.settings import AuthSettings
from policyops_contracts.clock import Clock


API_PREFIX = "/api/v1"


class Liveness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok"]


class UnsafeTestHook(RuntimeError):
    """A test-only hook (such as an injected OIDC transport) was used outside the test environment."""


def build_auth_runtime(settings: AuthSettings, *, auth_engine: Engine, app_engine: Engine, clock: Clock,
                       oidc_transport: httpx.BaseTransport | None = None) -> auth_api.AuthRuntime:
    """Wire authentication. Refuses runtime engines that authenticate as anything but the restricted auth/app
    runtime roles, and refuses a substituted OIDC transport unless `settings.env == "test"`."""
    if oidc_transport is not None and settings.env != "test":
        raise UnsafeTestHook("a test OIDC transport is only allowed when POLICYOPS_ENV=test")
    verify_runtime_role(auth_engine, AUTH_RUNTIME)
    verify_runtime_role(app_engine, APP_RUNTIME)
    oidc = OidcClient(settings, clock, transport=oidc_transport)
    service = AuthService(settings=settings, oidc=oidc, auth_engine=auth_engine, clock=clock)
    return auth_api.AuthRuntime(settings=settings, service=service, app_engine=app_engine)


def include_api_routes(app: FastAPI) -> None:
    """The authenticated route composition (authentication and case routes): served by `create_app(auth)` and
    exported, without a runtime, by `policyops.api.openapi`."""
    app.include_router(auth_api.build_router(), prefix=API_PREFIX)
    app.include_router(cases_api.build_router(), prefix=API_PREFIX)


def create_app(auth: auth_api.AuthRuntime | None = None) -> FastAPI:
    """Without `auth` only liveness is served (as before); with it, the authentication and case routes are
    installed. Request bodies are bounded to 64 KiB as received (`BodyLimit`)."""
    # Not served (`openapi_url=None`); exported by `policyops.api.openapi`. Operation IDs are the route names.
    app = FastAPI(title="PolicyOps", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                  generate_unique_id_function=lambda route: route.name)
    router = APIRouter(prefix=API_PREFIX)

    @router.get("/health/live", response_model=Liveness, **docs.operation())
    def live() -> Liveness:
        # Process liveness only; readiness (database/config checks) is added with deployment wiring.
        return Liveness(status="ok")

    app.include_router(router)
    auth_api.install_error_boundary(app)
    app.add_middleware(BodyLimit)  # outermost: bounds and pre-reads the body before anything else runs
    if auth is not None:
        auth_api.install(app, auth)
        include_api_routes(app)
    return app
