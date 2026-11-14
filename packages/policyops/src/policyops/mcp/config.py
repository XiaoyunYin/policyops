"""Trusted subprocess configuration, never accepted as tool arguments or read from .env."""

from __future__ import annotations

from datetime import timedelta
import os
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, SecretStr, model_validator

from policyops.domain.roles import Role
from policyops_contracts.base import WireModel
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.scalars import Sha256Hex, Slug, UtcDatetime
from policyops_contracts.seeds import CaseCustomerBinding


class Configuration(WireModel):
    principal_id: UUID
    workspace_id: UUID
    run_id: UUID
    role: Role
    binding: CaseCustomerBinding
    corpus_key: Slug
    issued_at: UtcDatetime
    expires_at: UtcDatetime
    fixture_sha256: Sha256Hex = FIXTURE_SHA256
    timeout_seconds: Annotated[int, Field(ge=1, le=30)] = 10
    concurrency: Annotated[int, Field(ge=1, le=4)] = 1
    worker_mode: Literal["cold", "warm"] = "warm"
    worker_max_calls: Annotated[int, Field(ge=1, le=1000)] = 100
    worker_max_age_seconds: Annotated[int, Field(ge=1, le=3600)] = 300

    @model_validator(mode="after")
    def consistent(self) -> Configuration:
        if self.binding.scope.workspace_id != self.workspace_id:
            raise ValueError("binding workspace mismatch")
        if not timedelta(0) < self.expires_at - self.issued_at <= timedelta(hours=1):
            raise ValueError("MCP credential window must be at most one hour")
        return self


def load() -> tuple[Configuration, SecretStr]:
    raw = os.environ["POLICYOPS_MCP_CONFIG"]
    cookie = os.environ["POLICYOPS_MCP_SESSION"]
    if len(raw.encode("utf-8")) > 8192 or not 16 <= len(cookie) <= 200:
        raise ValueError("MCP configuration exceeds bounds")
    return Configuration.model_validate_json(raw), SecretStr(cookie)
