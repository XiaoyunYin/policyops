"""The retail-simulator client against a scripted transport: signed contexts, identity-bound results, unknown
outcomes, no retries and the operation fingerprint. The service itself is tested in evals and end to end."""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime
import hashlib
import hmac
import json
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from policyops.adapters import retail_client
from policyops.adapters.retail_client import AuthorizationExpired, Refused, RetailClient, Unknown
from policyops_contracts.money import Money
from policyops_contracts.retail import ItemChangeLine, ItemsEffect, ModifyPendingOrderItems, ResourceVersion
from policyops_contracts.retail_service import (
    FIXTURE_SHA256,
    MutationRequest,
    OperationResult,
    Receipt,
    ServiceContext,
    operation_fingerprint,
)


KEY = b"k" * 32
TENANT, CASE = UUID(int=1), UUID(int=2)
CUSTOMER = "james_johnson_9321"


def request(intent: str = "a" * 64, version: int = 1) -> MutationRequest:
    call = ModifyPendingOrderItems(order_id="#W1006327", item_ids=("5172162216",), new_item_ids=("4068787148",),
                                   payment_method_id="credit_card_4998749")
    effect = ItemsEffect(kind="modify_pending_order_items", order_id="#W1006327", changes=(ItemChangeLine(
        item_id="5172162216", new_item_id="4068787148", product_id="1808611083",
        price_before=Money(amount_minor=4851), price_after=Money(amount_minor=5201)),),
        price_difference=Money(amount_minor=350), payment_method_id="credit_card_4998749", status_before="pending",
        status_after="pending (item modified)")
    return MutationRequest(call=call, expected_effect=effect, intent_sha256=intent, expected_versions=(
        ResourceVersion(kind="order", resource_id="#W1006327", version=version),
        ResourceVersion(kind="user", resource_id=CUSTOMER, version=1),
        ResourceVersion(kind="product", resource_id="1808611083", version=1)))


def fingerprint(op: UUID, body: MutationRequest, **changes: Any) -> str:
    identity: dict[str, Any] = {"tenant_id": TENANT, "case_id": CASE, "customer_id": CUSTOMER,
                                "fixture_sha256": FIXTURE_SHA256} | changes
    return operation_fingerprint(operation_id=op, request=body, **identity)


def result(op: UUID, sha: str, body: MutationRequest, **receipt_changes: Any) -> dict[str, Any]:
    receipt = Receipt(operation_id=str(op), operation_sha256=sha, tool=body.call.tool,
                      actual_effect=body.expected_effect, case_version_before=1, case_version_after=2,
                      resource_versions_after=body.expected_versions, state_sha256_after="e" * 64,
                      committed_at=datetime(2026, 11, 5, tzinfo=UTC)).model_copy(update=receipt_changes)
    return OperationResult(operation_id=str(op), operation_sha256=sha, outcome="committed", receipt=receipt,
                           replayed=False).model_dump(mode="json")


class Server:
    """Verifies each request's signed context, then answers with `respond(request, claims)`."""

    def __init__(self, respond: Callable[[httpx.Request, dict[str, Any]], httpx.Response]) -> None:
        self.respond, self.calls = respond, 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        token = request.headers["authorization"].removeprefix("Bearer ")
        claims_b64, signature_b64 = token.split(".")
        claims = base64.urlsafe_b64decode(claims_b64 + "=" * (-len(claims_b64) % 4))
        signature = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
        assert hmac.compare_digest(hmac.new(KEY, claims, hashlib.sha256).digest(), signature)
        context = ServiceContext.model_validate_json(claims)
        body = request.read()
        assert (context.method, context.path) == (request.method, request.url.path) and not request.url.query
        assert context.body_sha256 == hashlib.sha256(body).hexdigest()
        assert (context.tenant_id, context.case_id, context.customer_id) == (TENANT, CASE, CUSTOMER)
        assert 0 < context.exp - context.iat <= 60
        return self.respond(request, json.loads(claims))


def client(server: Server) -> RetailClient:
    return RetailClient("http://127.0.0.1:9", KEY, tenant_id=TENANT, case_id=CASE, customer_id=CUSTOMER,
                        transport=httpx.MockTransport(server))


def test_a_committed_result_for_this_operation_is_accepted_with_a_signed_write_context() -> None:
    op, body = uuid4(), request()
    seen: list[dict[str, Any]] = []

    def respond(req: httpx.Request, claims: dict[str, Any]) -> httpx.Response:
        seen.append(claims)
        return httpx.Response(200, json=result(op, fingerprint(op, body), body))
    outcome = client(Server(respond)).mutate(op, body)
    assert isinstance(outcome, OperationResult) and outcome.outcome == "committed"
    assert seen[0]["scope"] == "write" and seen[0]["method"] == "PUT"
    assert seen[0]["path"] == f"/v1/cases/{CASE}/operations/{op}"


@pytest.mark.parametrize("foreign", ["operation_id", "tenant", "case", "customer", "fixture", "intent", "version",
                                     "receipt_operation", "receipt_tool_effect"])
def test_a_structurally_valid_result_for_another_identity_is_unknown(foreign: str) -> None:
    op, body = uuid4(), request()
    sha = {"tenant": fingerprint(op, body, tenant_id=UUID(int=9)), "case": fingerprint(op, body, case_id=UUID(int=9)),
           "customer": fingerprint(op, body, customer_id="raj_sanchez_2970"),
           "fixture": fingerprint(op, body, fixture_sha256="f" * 64),
           "intent": fingerprint(op, request(intent="b" * 64)),
           "version": fingerprint(op, request(version=2))}.get(foreign, fingerprint(op, body))
    payload = result(op, sha, body)
    if foreign == "operation_id":
        other = uuid4()
        payload = result(other, fingerprint(other, body), body)
    elif foreign == "receipt_operation":
        payload["receipt"]["operation_id"] = str(uuid4())
    elif foreign == "receipt_tool_effect":
        other_effect = request().expected_effect.model_copy(update={"order_id": "#W1067251"})
        payload["receipt"]["actual_effect"] = other_effect.model_dump(mode="json")
    outcome = client(Server(lambda req, claims: httpx.Response(200, json=payload))).mutate(op, body)
    assert isinstance(outcome, Unknown) and outcome.reason in ("foreign_result", "foreign_receipt")


@pytest.mark.parametrize(("respond", "reason"), [
    (lambda req, claims: httpx.Response(503, json={"detail": "x"}), "http_503"),
    (lambda req, claims: httpx.Response(429, json={"detail": "x"}), "http_429"),
    (lambda req, claims: httpx.Response(200, content=b"{not json"), "malformed_response"),
    (lambda req, claims: httpx.Response(200, content=b" " * (retail_client.MAX_RESPONSE_BYTES + 1)),
     "response_too_large"),
])
def test_an_ambiguous_response_is_unknown_and_never_retried(respond: Any, reason: str) -> None:
    server = Server(respond)
    outcome = client(server).mutate(uuid4(), request())
    assert outcome == Unknown(reason) and server.calls == 1


@pytest.mark.parametrize(("error", "reason"), [(httpx.ReadTimeout("t"), "timeout"),
                                               (httpx.ConnectError("c"), "transport_error")])
def test_a_timeout_or_transport_error_is_unknown_and_never_retried(error: Exception, reason: str) -> None:
    def respond(req: httpx.Request, claims: dict[str, Any]) -> httpx.Response:
        raise error
    server = Server(respond)
    assert client(server).mutate(uuid4(), request()) == Unknown(reason) and server.calls == 1


def envelope(code: str, detail: str, *, retryable: bool = False) -> dict[str, Any]:
    return {"schema_version": "policyops.error/v1", "code": code, "detail": detail, "rule_id": None,
            "correlation_id": str(uuid4()), "retryable": retryable}


def test_a_definite_refusal_is_typed() -> None:
    server = Server(lambda req, claims: httpx.Response(409, json=envelope("conflict", "operation_conflict")))
    with pytest.raises(Refused) as refused:
        client(server).mutate(uuid4(), request())
    assert (refused.value.status, refused.value.code) == (409, "operation_conflict")


CANARY = "UNTRUSTED-ERROR-DETAIL-CANARY"


def test_untrusted_refusal_detail_is_never_repeated() -> None:
    server = Server(lambda req, claims: httpx.Response(403, json=envelope("forbidden", CANARY)))
    with pytest.raises(Refused) as refused:
        client(server).mutate(uuid4(), request())
    assert (refused.value.status, refused.value.code) == (403, "forbidden")
    assert CANARY not in repr(refused.value) and CANARY not in str(refused.value)


@pytest.mark.parametrize(("status", "body"), [
    (400, b"not json at all"),
    (400, b'{"detail": "operation_conflict"}'),  # not an ErrorEnvelope
    (409, json.dumps(envelope("invalid_input", "operation_conflict")).encode()),  # code does not match status
    (409, json.dumps(envelope("conflict", "operation_conflict", retryable=True)).encode()),  # retryable
    (409, json.dumps(envelope("conflict", "operation_conflict")).replace('"code"', '"code": "conflict", "code"', 1)
     .encode()),  # duplicate key
    (408, json.dumps(envelope("unavailable", "x")).encode()),
    (418, json.dumps(envelope("forbidden", "x")).encode()),
    (204, b""),
])
def test_a_malformed_inconsistent_or_unexpected_status_is_unknown_not_a_refusal(status: int, body: bytes) -> None:
    server = Server(lambda req, claims: httpx.Response(status, content=body))
    outcome = client(server).mutate(uuid4(), request())
    assert isinstance(outcome, Unknown) and server.calls == 1


def test_duplicate_or_non_finite_json_in_a_result_is_unknown() -> None:
    op, body = uuid4(), request()
    good = json.dumps(result(op, fingerprint(op, body), body))
    assert isinstance(client(Server(lambda req, claims: httpx.Response(200, content=good.encode()))).mutate(op, body),
                      OperationResult)  # positive control
    foreign = str(uuid4())
    duplicated = good.replace('"operation_id": ', f'"operation_id": "{foreign}", "operation_id": ', 1)
    nested = good.replace('"receipt": {', f'"receipt": {{"operation_id": "{foreign}", ', 1)
    non_finite = good.replace('"replayed": false', '"replayed": false, "x": NaN')
    for content in (duplicated, nested, non_finite):
        def respond(req: httpx.Request, claims: dict[str, Any], c: str = content) -> httpx.Response:
            return httpx.Response(200, content=c.encode())
        assert client(Server(respond)).mutate(op, body) == Unknown("malformed_response")


def test_an_encoded_response_is_refused_before_decoding() -> None:
    import gzip
    import tracemalloc
    bomb = gzip.compress(b"0" * (8 * 1024 * 1024))
    server = Server(lambda req, claims: httpx.Response(200, content=iter([bomb]),  # streamed, as from a network
                                                       headers={"content-encoding": "gzip"}))
    tracemalloc.start()
    try:
        outcome = client(server).mutate(uuid4(), request())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert outcome == Unknown("encoded_response") and peak < 2 * 1024 * 1024


def test_requests_ask_for_identity_encoding() -> None:
    seen: list[str] = []

    def respond(req: httpx.Request, claims: dict[str, Any]) -> httpx.Response:
        seen.append(req.headers["accept-encoding"])
        return httpx.Response(503)
    client(Server(respond)).mutate(uuid4(), request())
    assert seen == ["identity"]


def test_a_fence_names_the_original_fingerprint_and_signs_its_own_body() -> None:
    op, body = uuid4(), request()
    original = fingerprint(op, body)
    seen: dict[str, Any] = {}

    def respond(req: httpx.Request, claims: dict[str, Any]) -> httpx.Response:
        seen["body"], seen["digest"] = json.loads(req.read()), claims["body_sha256"]
        return httpx.Response(200, json=OperationResult(operation_id=str(op), operation_sha256=original,
                                                        outcome="fenced", replayed=False).model_dump(mode="json"))
    outcome = client(Server(respond)).fence(op, body)
    assert isinstance(outcome, OperationResult) and outcome.outcome == "fenced"
    assert seen["body"] == {"operation_sha256": original} and seen["digest"] != original


def test_the_operation_fingerprint_is_stable_across_transport_and_changes_with_identity() -> None:
    op, body = uuid4(), request()
    same = fingerprint(op, body)
    reordered = body.model_copy(update={"expected_versions": tuple(reversed(body.expected_versions))})
    assert fingerprint(op, reordered) == same  # nonce, time, signature and version order are not identity
    changed = {fingerprint(uuid4(), body), fingerprint(op, request(intent="b" * 64)),
               fingerprint(op, request(version=2)),
               fingerprint(op, body, customer_id="raj_sanchez_2970"), fingerprint(op, body, fixture_sha256="f" * 64)}
    assert same not in changed and len(changed) == 5


def test_the_signed_context_never_outlives_the_callers_authorization() -> None:
    op, body, now = uuid4(), request(), 1_800_000_000
    seen: list[dict[str, Any]] = []

    def respond(req: httpx.Request, claims: dict[str, Any]) -> httpx.Response:
        seen.append(claims)
        return httpx.Response(200, json=result(op, fingerprint(op, body), body))
    server = Server(respond)
    timed = RetailClient("http://127.0.0.1:9", KEY, tenant_id=TENANT, case_id=CASE, customer_id=CUSTOMER,
                         transport=httpx.MockTransport(server), clock=lambda: float(now))
    assert isinstance(timed.mutate(op, body, authorization_not_after=now + 7), OperationResult)
    assert seen[-1]["exp"] == now + 7  # capped by the approval's expiry, not a fresh bearer lifetime
    assert isinstance(timed.mutate(op, body), OperationResult) and seen[-1]["exp"] == now + 30
    for expired in (now, now - 1):
        with pytest.raises(AuthorizationExpired):
            timed.mutate(op, body, authorization_not_after=expired)
        with pytest.raises(AuthorizationExpired):
            timed.fence(op, body, authorization_not_after=expired)
    assert server.calls == 2  # nothing was sent once the authorization had expired
    assert timed.fingerprint(op, body) == fingerprint(op, body)  # expiry is not operation identity


def test_the_network_transport_ignores_ambient_configuration_and_never_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[dict[str, Any]] = []
    real = httpx.HTTPTransport

    def record(**kwargs: Any) -> httpx.HTTPTransport:
        built.append(kwargs)
        return real(**kwargs)
    monkeypatch.setattr(httpx, "HTTPTransport", record)  # the module object the client uses
    made = RetailClient("http://127.0.0.1:9", KEY, tenant_id=TENANT, case_id=CASE, customer_id=CUSTOMER)
    try:
        assert built == [{"trust_env": False, "retries": 0, "proxy": None}]
        assert made._http.trust_env is False and made._http.follow_redirects is False
        assert "redacted" in repr(made) and KEY.decode() not in repr(made)
    finally:
        made.close()
    for origin in ("http://127.0.0.1:9/v1", "127.0.0.1:9", "http://user@127.0.0.1:9"):
        with pytest.raises(ValueError):
            RetailClient(origin, KEY, tenant_id=TENANT, case_id=CASE, customer_id=CUSTOMER)
