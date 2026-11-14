"""MCP uses the actual retail Gateway; malicious strings remain typed data and never become calls."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, cast
from uuid import uuid4

from pydantic import SecretStr
import pytest
from sqlalchemy import Engine

from policyops.auth.service import AuthError, Authorized, AuthService, ExpectedContext, SessionContext
from policyops.domain.roles import Action, Role
from policyops.mcp import service as module
from policyops.mcp.config import Configuration
from policyops.mcp.contracts import PolicyObservation
from policyops.mcp.service import ReadService
from policyops.retrieval.rank import ChunkRow
from policyops_contracts.clock import FixedClock
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import ReadObservation, ToolError
from policyops_testing.gateway_cases import INJECTION, SCOPE, FakeRetail, W, authenticated_sessions, state


class Auth:
    def __init__(self) -> None:
        self.revoked = False
        self.calls = 0

    def resolve(self, cookie: str) -> object:
        assert cookie == "synthetic-mcp-session"
        self.calls += 1
        return object()

    def authorize(self, session: object, action: Action, *, expected: ExpectedContext) -> Authorized:
        assert action == Action.VIEW_CASE and expected.workspace_id == W.run_scope.workspace_id
        if self.revoked:
            raise AuthError(403, ErrorCode.FORBIDDEN, "revoked", "auth.membership")
        context = SessionContext(uuid4(), expected.principal_id, expected.workspace_id,
                                 W.now + timedelta(hours=1), "0" * 64)
        return Authorized(context, expected.workspace_id, frozenset({Role.REVIEWER}))


def setup(monkeypatch: pytest.MonkeyPatch) -> tuple[ReadService, FakeRetail, Auth]:
    retail = FakeRetail(state())
    auth = Auth()
    monkeypatch.setattr(module, "load_scope", lambda *args, **kwargs: SCOPE)
    monkeypatch.setattr(module, "PgSessionStore", lambda *args: authenticated_sessions())
    config = Configuration(principal_id=uuid4(), workspace_id=W.run_scope.workspace_id, run_id=W.run_scope.run_id,
        role=Role.REVIEWER, binding=W.binding(), corpus_key="retail", issued_at=W.now,
        expires_at=W.now + timedelta(minutes=5))
    return (ReadService(config, SecretStr("synthetic-mcp-session"), cast(AuthService, auth), cast(Engine, object()),
                        retail, FixedClock(W.now)), retail, auth)


def test_revocation_between_calls_denies_next_read(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, auth = setup(monkeypatch)
    assert isinstance(service.call("get_order_details", {"order_id": W.order_id}).result, ReadObservation)
    count = len(retail.calls)
    auth.revoked = True
    result = service.call("get_order_details", {"order_id": W.order_id}).result
    assert isinstance(result, ToolError) and result.code == "forbidden"
    assert len(retail.calls) == count


def test_expiry_denies_before_any_port(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, auth = setup(monkeypatch)
    service.clock = FixedClock(service.configuration.expires_at)
    result = service.call("get_order_details", {"order_id": W.order_id}).result
    assert isinstance(result, ToolError) and result.code == "unauthenticated"
    assert auth.calls == 0 and not retail.calls


def test_revocation_during_adapter_read_prevents_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, auth = setup(monkeypatch)
    def revoke(call: Any, result: Any, count: int) -> Any:
        auth.revoked = True
        return result
    retail.tamper = revoke
    result = service.call("get_order_details", {"order_id": W.order_id}).result
    assert isinstance(result, ToolError) and result.code == "forbidden"


def test_foreign_customer_is_denied_by_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, _ = setup(monkeypatch)
    result = service.call("get_user_details", {"user_id": W.other_user}).result
    assert isinstance(result, ToolError) and result.code == "customer_mismatch"
    assert not retail.calls


def test_retail_injection_stays_data(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, _ = setup(monkeypatch)
    retail.state.product_name = INJECTION
    result = service.call("list_all_product_types", {}).result
    assert isinstance(result, ReadObservation) and INJECTION in result.model_dump_json()
    assert [c.tool for c in retail.calls] == ["list_all_product_types"]


def test_retrieved_injection_stays_cited_data(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, _ = setup(monkeypatch)
    chunk = ChunkRow(uuid4(), uuid4(), uuid4(), "policy://synthetic", 1, "Heading", 0, len(INJECTION), INJECTION)
    monkeypatch.setattr(module, "search", lambda *args, **kwargs: (uuid4(), (chunk,)))
    result = service.call("search_policy", {"query": "policy"}).result
    assert isinstance(result, PolicyObservation)
    assert result.citations[0].text == INJECTION and result.claim_support_validated is False
    assert not retail.calls


def test_identity_arguments_denied_before_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, auth = setup(monkeypatch)
    result = service.call("get_order_details", {"order_id": W.order_id, "role": "admin"}).result
    assert isinstance(result, ToolError) and result.code == "invalid_input"
    assert auth.calls == 0 and not retail.calls


def test_another_current_role_cannot_replace_the_pinned_role(monkeypatch: pytest.MonkeyPatch) -> None:
    service, retail, _ = setup(monkeypatch)
    service.configuration = service.configuration.model_copy(update={"role": Role.AUDITOR})
    result = service.call("get_order_details", {"order_id": W.order_id}).result
    assert isinstance(result, ToolError) and result.code == "forbidden"
    assert not retail.calls
