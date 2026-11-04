"""FastAPI application factory."""

from typing import Literal

from fastapi import APIRouter, FastAPI
from pydantic import BaseModel, ConfigDict

from policyops import __version__


API_PREFIX = "/api/v1"


class Liveness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok"]


def create_app() -> FastAPI:
    app = FastAPI(title="PolicyOps", version=__version__)
    router = APIRouter(prefix=API_PREFIX)

    @router.get("/health/live", response_model=Liveness)
    def live() -> Liveness:
        # Process liveness only; readiness (database/config checks) is added with persistence.
        return Liveness(status="ok")

    app.include_router(router)
    return app
