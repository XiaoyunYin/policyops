"""FastAPI application factory and authentication wiring."""

from typing import Literal

from fastapi import APIRouter, FastAPI
from fastapi.openapi.utils import get_openapi
import httpx
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Engine

from policyops import __version__
from policyops.api import auth as auth_api
from policyops.api import cases as cases_api
from policyops.api import docs, run_reads
from policyops.api import proposals as proposals_api
from policyops.api import runs as runs_api
from policyops.api.body_limit import BodyLimit
from policyops.auth.oidc import OidcClient
from policyops.auth.service import AuthService
from policyops.persistence.database import verify_runtime_role
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.settings import AuthSettings
from policyops.telemetry.attributes import ROUTES
from policyops.telemetry.http import HttpTelemetry
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
    runtime roles, and refuses a substituted OIDC transport unless `settings.env == "test"`. The engines stay
    owned by the caller; the returned runtime owns an OIDC HTTP client (`runtime.service.oidc.close()`), which is
    closed here if wiring fails after it was opened."""
    if oidc_transport is not None and settings.env != "test":
        raise UnsafeTestHook("a test OIDC transport is only allowed when POLICYOPS_ENV=test")
    verify_runtime_role(auth_engine, AUTH_RUNTIME)
    verify_runtime_role(app_engine, APP_RUNTIME)
    oidc = OidcClient(settings, clock, transport=oidc_transport)
    try:  # the HTTP client is owned here until the runtime that closes it is returned
        service = AuthService(settings=settings, oidc=oidc, auth_engine=auth_engine, clock=clock)
        return auth_api.AuthRuntime(settings=settings, service=service, app_engine=app_engine)
    except BaseException as error:
        try:
            oidc.close()
        except BaseException as cleanup:  # the original error propagates; a cleanup failure (or interruption) is noted
            error.add_note(f"closing the OIDC client also failed: {type(cleanup).__name__}")
        raise


def include_api_routes(app: FastAPI) -> None:
    """The authenticated route composition (authentication, case, run and proposal routes): served by
    `create_app(auth)` and exported, without a runtime, by `policyops.api.openapi`."""
    app.include_router(auth_api.build_router(), prefix=API_PREFIX)
    app.include_router(cases_api.build_router(), prefix=API_PREFIX)
    app.include_router(runs_api.build_router(), prefix=API_PREFIX)
    app.include_router(run_reads.build_router(), prefix=API_PREFIX)
    app.include_router(proposals_api.build_router(), prefix=API_PREFIX)


def create_app(auth: auth_api.AuthRuntime | None = None, runs: runs_api.RunsRuntime | None = None) -> FastAPI:
    """Without `auth` only liveness is served (as before); with it, the authentication, case, run and proposal
    routes are installed (`runs` defaults to the database clock with no installed run runtime; the proposal routes
    use its lease clock). Request bodies are bounded to 64 KiB as received (`BodyLimit`)."""
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
    app.add_middleware(BodyLimit)  # bounds and pre-reads the body before anything else runs
    app.add_middleware(runs_api.StreamDeadline)  # outermost: bounds event-stream delivery, stalled sends included
    if auth is not None:
        auth_api.install(app, auth)
        # Without an explicit runs runtime: the database clock and no installed run runtime (start answers 503).
        app.state.runs = runs or runs_api.build_runs_runtime(env=auth.settings.env, app_engine=auth.app_engine,
                                                             ledger_clock=auth.service.clock)
        include_api_routes(app)
    # Included routers are lazy wrappers in the pinned FastAPI, not flattened APIRoutes.
    # OpenAPI resolves their prefixes and yields only registered path templates.
    ROUTES.update(get_openapi(title=app.title, version=app.version, routes=app.routes).get("paths", {}))
    app.add_middleware(HttpTelemetry)
    return app
