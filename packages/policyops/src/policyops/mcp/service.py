"""Transport-independent direct path: existing staff auth, persisted scope and gateway authorization."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any

from pydantic import SecretStr
from sqlalchemy import Engine

from policyops.auth.service import AuthError, AuthService, ExpectedContext
from policyops.domain.roles import Action
from policyops.gateway.policy_search import search
from policyops.gateway.ports import PgSessionStore, RetailPort, ScopeMismatch, load_scope
from policyops.gateway.steps import Gateway
from policyops.mcp.config import Configuration
from policyops.mcp.contracts import Citation, PolicyObservation, Result, SearchPolicy, arguments, bounded, error
from policyops.persistence.database import DatabaseUnavailable
from policyops.persistence.retrieval import StepRefused
from policyops.providers.tokenizer import InputRefused
from policyops.retrieval.counting import EvidenceDeadline
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.clock import Clock
from policyops_contracts.digest import text_sha256
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import LookupObservation, ReadObservation, ToolError


@dataclass
class ReadService:
    configuration: Configuration
    cookie: SecretStr
    auth: AuthService
    engine: Engine
    retail: RetailPort
    clock: Clock

    def call(self, name: str, values: dict[str, Any]) -> Result:
        parsed = arguments(name, values)
        if isinstance(parsed, Result):
            return parsed
        config = self.configuration
        try:
            self.authorize()
            scope = load_scope(self.engine, workspace_id=config.workspace_id, run_id=config.run_id,
                               binding=config.binding, fixture_sha256=config.fixture_sha256)
            if isinstance(parsed, SearchPolicy):
                generation, chunks = search(self.engine, scope.run, config.corpus_key, parsed.query,
                                            deadline=time.monotonic() + config.timeout_seconds)
                result = Result(result=PolicyObservation(generation_id=generation, citations=tuple(Citation(
                    document_version_id=c.document_version_id, chunk_id=c.chunk_id, source_uri=c.source_uri,
                    version=c.version_number, start=c.start, end=c.end, text=c.text, text_sha256=text_sha256(c.text))
                    for c in chunks)))
            else:
                observation = Gateway(scope, retail=self.retail, sessions=PgSessionStore(self.engine),
                                      clock=self.clock).step(ToolCallStep(call=parsed), previous=None,
                                                             sequence=1).observation
                if not isinstance(observation, ReadObservation | LookupObservation | ToolError):
                    return error(ErrorCode.UNAVAILABLE, "result_invalid_or_too_large")
                result = Result(result=observation)
            # A revocation/expiry while the read ran also prevents delivering the result.
            self.authorize()
            return bounded(result)
        except AuthError as refused:
            return error(refused.code, "identity_refused")
        except ScopeMismatch:
            return error(ErrorCode.NOT_FOUND, "scope_not_found")
        except StepRefused as refused:
            if refused.code == "citation_integrity":
                return error(ErrorCode.UNAVAILABLE, "citation_integrity")
            return error(ErrorCode.NOT_FOUND, "policy_not_available")
        except (EvidenceDeadline, TimeoutError):
            return error(ErrorCode.UNAVAILABLE, "call_timeout", retryable=True)
        except InputRefused:
            return error(ErrorCode.INVALID_INPUT, "arguments_invalid")
        except DatabaseUnavailable:
            return error(ErrorCode.UNAVAILABLE, "database_unavailable", retryable=True)

    def authorize(self) -> None:
        config = self.configuration
        now = self.clock.now()
        if now < config.issued_at or now >= config.expires_at:
            raise AuthError(401, ErrorCode.UNAUTHENTICATED, "identity_expired", "auth.session")
        session = self.auth.resolve(self.cookie.get_secret_value())
        authorized = self.auth.authorize(session, Action.VIEW_CASE,
                                         expected=ExpectedContext(config.principal_id, config.workspace_id))
        if config.role not in authorized.roles:
            raise AuthError(403, ErrorCode.FORBIDDEN, "bound_role_revoked", "auth.role")
