"""Expected-context binding (T25a): the route inventory, the header grammar and the order of checks in `authorize`.

The PostgreSQL behavior (rotation, principal swap, no effects, SSE) is in
`tests/integration/test_context_binding.py`; this module pins what can be checked without a database.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, cast, get_type_hints
from uuid import UUID, uuid4

from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
import pytest
from starlette.datastructures import Headers

from policyops.api.auth import EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER, expected_context
from policyops.api.openapi import schema_app
from policyops.api.runs import StreamViewer
from policyops.auth.service import AuthError, Authorized, AuthService, ExpectedContext, SessionContext
from policyops.domain.roles import Action, Role


ROOT = Path(__file__).resolve().parents[2]
GLOBAL = frozenset({"live", "login", "callback", "me", "select_workspace", "logout"})
BOUND = frozenset({"list_cases", "create_case", "get_case", "change_status", "list_messages", "post_message",
                   "start_run", "get_run", "cancel_run", "run_events", "list_approvals", "list_case_proposals",
                   "get_proposal", "decide", "members", "revoke_member", "list_case_runs", "run_snapshot",
                   "list_run_citations", "historical_evidence"})
P, W = uuid4(), uuid4()


def _produces_authorization(dependant: Dependant) -> bool:
    for dependency in dependant.dependencies:
        call = dependency.call
        returned = get_type_hints(call).get("return") if call is not None else None
        if returned in (Authorized, StreamViewer) or _produces_authorization(dependency):
            return True
    return False


def _api_routes(routes: list[Any]) -> list[APIRoute]:
    """The app's operations; FastAPI 0.162 wraps each included router (its `original_router` holds the routes)."""
    found: list[APIRoute] = []
    for route in routes:
        if isinstance(route, APIRoute):
            found.append(route)
        elif hasattr(route, "original_router"):
            found.extend(_api_routes(route.original_router.routes))
    return found


def test_every_authorized_route_is_bound_and_documents_both_headers() -> None:
    """A route whose dependencies produce an `Authorized` must be in the bound set and document both required
    headers; the routes without one are exactly the global bootstrap, selection and logout routes."""
    routes = _api_routes(schema_app().routes)
    by_name = {r.name: r for r in routes}
    assert set(by_name) == BOUND | GLOBAL
    assert {r.name for r in routes if _produces_authorization(r.dependant)} == BOUND
    document = json.loads((ROOT / "packages/policyops/openapi/v1.json").read_bytes())
    seen: dict[str, set[str]] = {}
    for operations in document["paths"].values():
        for operation in operations.values():
            headers = {p["name"] for p in operation.get("parameters", []) if p["in"] == "header" and p["required"]}
            seen[operation["operationId"]] = headers & {EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER}
            if operation["operationId"] in BOUND:
                assert {"400", "409", "422"} <= set(operation["responses"]), operation["operationId"]
    assert {name for name, found in seen.items() if found} == BOUND
    assert all(found == {EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER} for name, found in seen.items()
               if name in BOUND)


def headers(*pairs: tuple[str, str]) -> Headers:
    return Headers(raw=[(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in pairs])


def refusal(raw: Headers) -> tuple[int, str]:
    with pytest.raises(AuthError) as caught:
        expected_context(raw)
    return caught.value.status, caught.value.rule_id


def test_the_canonical_headers_parse_to_a_frozen_typed_context() -> None:
    parsed = expected_context(headers((EXPECTED_PRINCIPAL_HEADER, str(P)), (EXPECTED_WORKSPACE_HEADER, str(W))))
    assert parsed == ExpectedContext(principal_id=P, workspace_id=W)
    with pytest.raises(AttributeError):
        parsed.workspace_id = uuid4()  # type: ignore[misc]


@pytest.mark.parametrize("value", [
    "", " ", str(W).upper(), "{" + str(W) + "}", "urn:uuid:" + str(W), W.hex, str(W) + "0", str(W)[:-1],
    f" {W}", f"{W} ", f"{W},{W}", "not-a-uuid", "0" * 36, "x" * 4096])
def test_malformed_values_are_refused_without_echo(value: str) -> None:
    for name, label in ((EXPECTED_PRINCIPAL_HEADER, "principal"), (EXPECTED_WORKSPACE_HEADER, "workspace")):
        other = EXPECTED_WORKSPACE_HEADER if name == EXPECTED_PRINCIPAL_HEADER else EXPECTED_PRINCIPAL_HEADER
        with pytest.raises(AuthError) as caught:
            expected_context(headers((name, value), (other, str(uuid4()))))
        assert (caught.value.status, caught.value.rule_id) == (422, f"api.invalid_expected_{label}")
        assert (value.strip() == "" or value not in caught.value.detail) and len(caught.value.detail) < 100


def test_missing_and_repeated_headers() -> None:
    assert refusal(headers()) == (400, "api.expected_principal_required")  # the principal is checked first
    assert refusal(headers((EXPECTED_WORKSPACE_HEADER, str(W)))) == (400, "api.expected_principal_required")
    assert refusal(headers((EXPECTED_PRINCIPAL_HEADER, str(P)))) == (400, "api.expected_workspace_required")
    assert refusal(headers((EXPECTED_PRINCIPAL_HEADER, str(P)), (EXPECTED_PRINCIPAL_HEADER, str(P)),
                           (EXPECTED_WORKSPACE_HEADER, str(W)))) == (422, "api.invalid_expected_principal")
    assert refusal(headers((EXPECTED_PRINCIPAL_HEADER, str(P)), (EXPECTED_WORKSPACE_HEADER, str(W)),
                           (EXPECTED_WORKSPACE_HEADER, str(W)))) == (422, "api.invalid_expected_workspace")


class RecordingService(AuthService):
    """`authorize` with the membership read replaced, to show what runs before it."""

    def __init__(self, roles: frozenset[Role]) -> None:
        super().__init__(settings=cast(Any, None), oidc=cast(Any, None), auth_engine=cast(Any, None),
                         clock=cast(Any, None))
        self.granted, self.reads = roles, 0

    def roles(self, session: SessionContext) -> frozenset[Role]:
        self.reads += 1
        return self.granted


def session(principal: UUID = P, workspace: UUID | None = W) -> SessionContext:
    return SessionContext(session_id=uuid4(), principal_id=principal, workspace_id=workspace,
                          expires_at=datetime(2030, 1, 1, tzinfo=UTC), csrf_sha256="0" * 64)


@pytest.mark.parametrize(("actual", "rule_id"), [
    (session(principal=uuid4()), "auth.principal_changed"),
    (session(workspace=uuid4()), "auth.workspace_changed"),
    (session(workspace=None), "auth.workspace_changed"),
    (session(principal=uuid4(), workspace=uuid4()), "auth.principal_changed"),
])
def test_a_mismatch_is_refused_before_any_membership_read(actual: SessionContext, rule_id: str) -> None:
    service = RecordingService(frozenset())  # no roles at all: a role check would answer 403 instead
    with pytest.raises(AuthError) as caught:
        service.authorize(actual, Action.CREATE_CASE, expected=ExpectedContext(principal_id=P, workspace_id=W))
    assert (caught.value.status, caught.value.code, caught.value.rule_id) == (409, "context_changed", rule_id)
    assert "not applied" in caught.value.detail and service.reads == 0


def test_a_matching_context_still_needs_membership_and_role() -> None:
    expected = ExpectedContext(principal_id=P, workspace_id=W)
    for roles, outcome in ((frozenset(), "auth.membership"), (frozenset({Role.AUDITOR}), "auth.role")):
        with pytest.raises(AuthError) as caught:
            RecordingService(roles).authorize(session(), Action.CREATE_CASE, expected=expected)
        assert (caught.value.status, caught.value.rule_id) == (403, outcome)
    granted = RecordingService(frozenset({Role.ANALYST})).authorize(session(), Action.CREATE_CASE, expected=expected)
    assert (granted.workspace_id, granted.session.principal_id) == (W, P)


def test_the_expected_context_is_mandatory() -> None:
    service = RecordingService(frozenset({Role.ANALYST}))
    with pytest.raises(TypeError):
        service.authorize(session(), Action.VIEW_CASE)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        service.authorize(session(), Action.VIEW_CASE, expected=cast(Any, None))
    with pytest.raises(TypeError):
        service.authorize(session(), Action.VIEW_CASE, expected=cast(Any, (P, W)))
    assert service.reads == 0
