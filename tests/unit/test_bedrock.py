"""G7: real CPU signer + static file providers + bounded transport, entirely offline."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
import hashlib
import json
import logging
from pathlib import Path
import runpy
import sys
import time
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.loaders import Loader
from botocore.model import ServiceModel
from botocore.serialize import create_serializer
import httpx2
from pydantic import SecretStr
import pytest

from policyops import telemetry
from policyops.budget.config import Caps
from policyops.budget.ledger import Attempt, Binding, Ledger, OperationBinding, RunBinding, Scope, ScopeRef, Settlement
from policyops.providers import bedrock_auth
from policyops.providers.bedrock import invoke
from policyops.providers.bedrock_auth import BedrockAccess, BedrockSettings
from policyops.providers.calls import CallLimits, Providers, _retryable, call
from policyops.providers.canonical import fresh
from policyops.providers.contract import ENDPOINTS, ContractGap
from policyops.providers.transport import BoundedTransport, Expected, TransportRefused, http_client
from policyops.settings import TelemetrySettings
from policyops.telemetry.sdk import MemorySpans
from tests.unit.test_bedrock_contract import configuration, prepared, request, response
from tests.unit.test_provider_call_grants import Books
from tests.unit.test_providers_transport import Chunks, Script, reply


KEY_ID = "synthetic-key-id"
SECRET = "synthetic-secret-canary"
TOKEN = "synthetic-session-canary"


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    for name in tuple(os.environ):
        if name.startswith(("AWS_", "ANTHROPIC_")):
            monkeypatch.delenv(name)


@pytest.fixture
def settings(tmp_path: Path) -> BedrockSettings:
    shared, config = tmp_path / "credentials", tmp_path / "config"
    shared.write_text(f"[operator]\naws_access_key_id={KEY_ID}\naws_secret_access_key={SECRET}\n"
                      f"aws_session_token={TOKEN}\n", encoding="utf-8")
    config.write_text("[profile operator]\nregion=us-west-2\noutput=json\n", encoding="utf-8")
    return BedrockSettings(profile="operator", credentials_file=shared, config_file=config)


@pytest.fixture
def access(settings: BedrockSettings, monkeypatch: pytest.MonkeyPatch) -> BedrockAccess:
    monkeypatch.setattr(bedrock_auth, "get_current_datetime", lambda: datetime(2026, 11, 15, 12, 0, tzinfo=UTC))
    return BedrockAccess.from_settings(settings)


def test_exact_request_and_golden_signature(access: BedrockAccess, monkeypatch: pytest.MonkeyPatch) -> None:
    p = prepared()
    headers = access.sign(p.body)
    # Independent fixed-input HMAC oracle is retained as a digest, never the signed Authorization header.
    assert hashlib.sha256(p.body).hexdigest() == "16070552cc527eb4c0be608538190fd31ddf8d2b78d3c96a81abd719209e8a12"
    assert headers["Authorization"].split("Signature=")[1] == (
        "c33868914a9760438aec8caa375e76a8b6a95eedf3563ce8c424a557d50818c8")
    script = Script(reply(response(), 200, **{"x-amzn-RequestId": "aws-request-1"}))
    invocation = asyncio.run(invoke(p, script, access))
    (wire,) = script.requests
    assert str(wire.url) == "https://bedrock-runtime.us-west-2.amazonaws.com/model/us.anthropic.claude-haiku-5-5/invoke"
    assert wire.method == "POST" and wire.headers["x-amz-date"] == "20261115T120000Z"
    assert wire.headers["x-amz-security-token"] == TOKEN
    assert script.bodies == [p.body]
    body = fresh(p.body)
    assert body["anthropic_version"] == "bedrock-2023-05-31"
    assert not {"model", "service_tier", "stream"} & body.keys()
    assert body["messages"] == [{"role": "user", "content": [{"type": "text", "text": "Confirm."}]}]
    assert invocation.result is not None and invocation.result.outcome == "structured"
    assert invocation.result.provider_request_id == "aws-request-1"
    assert invocation.result.returned_model == "claude-haiku-5-5"
    assert access.sign(p.body + b" ")["Authorization"] != headers["Authorization"]  # negative control
    # Compare quiet orchestration to the pinned upstream implementation (capture its unsafe logs separately).
    monkeypatch.setattr("botocore.auth.get_current_datetime", lambda: datetime(2026, 11, 15, 12, 0, tzinfo=UTC))
    upstream = AWSRequest(method="POST", url=str(wire.url), data=p.body,
                          headers={k: headers[k] for k in ("Content-Type", "Accept", "Host")})
    logger = logging.getLogger("botocore.auth")
    monkeypatch.setattr(logger, "disabled", True)
    SigV4Auth(access._credentials, "bedrock", "us-west-2").add_auth(upstream)
    assert dict(upstream.headers.items()) == headers
    assert SigV4Auth(access._credentials, "bedrock", "us-west-2").canonical_request(upstream).splitlines()[1] == p.path


@pytest.mark.parametrize(("identifier", "wire_path", "canonical_path"), [
    ("us.anthropic.claude-haiku-5-5", "/model/us.anthropic.claude-haiku-5-5/invoke",
     "/model/us.anthropic.claude-haiku-5-5/invoke"),
    ("us.anthropic.claude-haiku-5-5:0", "/model/us.anthropic.claude-haiku-5-5%3A0/invoke",
     "/model/us.anthropic.claude-haiku-5-5%253A0/invoke"),
])
def test_botocore_path_segment_and_canonical_uri_rules(
    access: BedrockAccess, identifier: str, wire_path: str, canonical_path: str,
) -> None:
    # Local service data + serializer only, no SDK client or credential discovery. The colon case is an oracle
    # for the escaping rule, not an allowed adapter ID (the registry/serializer refusal tests cover that).
    service = ServiceModel(Loader().load_service_model("bedrock-runtime", "service-2"))
    serialized = create_serializer("rest-json").serialize_to_request(
        {"modelId": identifier, "body": prepared().body, "contentType": "application/json"},
        service.operation_model("InvokeModel"))
    assert serialized["url_path"] == wire_path
    request = AWSRequest(method="POST", url=ENDPOINTS["bedrock"].base_url + wire_path, data=prepared().body)
    canonical = SigV4Auth(access._credentials, "bedrock", "us-west-2").canonical_request(request)
    assert canonical.splitlines()[1] == canonical_path


@pytest.mark.parametrize("key", ["sso_session", "sso_start_url", "sso_account_id", "sso_role_name", "sso_region",
                                "role_arn", "source_profile", "credential_process", "web_identity_token_file",
                                "credential_source", "login_session"])
@pytest.mark.parametrize("location", ["credentials", "config"])
def test_unsupported_provider_refused_before_either_provider_runs(
    settings: BedrockSettings, key: str, location: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = settings.credentials_file if location == "credentials" else settings.config_file
    assert path is not None
    with path.open("a", encoding="utf-8") as stream:
        stream.write(f"{key}=PRIVATE_CANARY\n")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("provider ran before static-only validation")

    monkeypatch.setattr(bedrock_auth, "SharedCredentialProvider", forbidden)
    monkeypatch.setattr(bedrock_auth, "ConfigProvider", forbidden)
    with pytest.raises(ContractGap, match=r"^bedrock.credentials_unsupported_provider$"):
        BedrockAccess.from_settings(settings)


def test_missing_profile_config_fallback_and_no_refresh(settings: BedrockSettings) -> None:
    with pytest.raises(ContractGap, match=r"bedrock.credentials_missing"):
        BedrockAccess.from_settings(settings.model_copy(update={"profile": "missing"}))
    access = BedrockAccess.from_settings(settings)
    assert settings.credentials_file is not None and settings.config_file is not None
    settings.credentials_file.write_text("", encoding="utf-8")
    settings.config_file.write_text(f"[profile operator]\naws_access_key_id={KEY_ID}\naws_secret_access_key={SECRET}\n",
                                    encoding="utf-8")
    assert "X-Amz-Security-Token" not in BedrockAccess.from_settings(settings).sign(b"{}")
    assert access.sign(b"{}")["X-Amz-Security-Token"] == TOKEN  # old object uses the frozen token as given
    with pytest.raises(ContractGap, match=r"bedrock.region_unsupported"):
        BedrockAccess.from_settings(settings.model_copy(update={"region": "us-east-1"}))


@pytest.mark.parametrize(("status", "retryable"), [(400, False), (403, False), (404, False), (408, True),
    (424, True), (429, True), (500, True), (503, True)])
def test_errors_are_value_free(access: BedrockAccess, status: int, retryable: bool) -> None:
    script = Script(reply({"message": TOKEN}, status, **{"x-amzn-errortype": "ModelNotReadyException"}))
    invocation = asyncio.run(invoke(prepared(), script, access))
    assert invocation.error == f"http_{status}" and _retryable(invocation) == retryable
    assert TOKEN not in repr(invocation) and len(script.requests) == 1


def test_port_has_one_network_request_and_no_secrets_in_logs_traces_or_records(
    access: BedrockAccess, caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    books = Books()
    books.configuration = configuration()
    script = Script(reply(response(), 200, **{"x-amzn-requestid": "aws-1"}))
    backend = telemetry.configure(TelemetrySettings(enabled=True))
    assert backend is not None
    try:
        providers = Providers({}, lambda _: script, bedrock=access)
        report = asyncio.run(call(cast(Any, books), providers, RunBinding(uuid4()),
            uuid4(), "bedrock", request(), "judge", deadline=time.monotonic() + 5,
            limits=CallLimits(retries_per_request=0, repairs=0)))
        assert len(script.requests) == 1 and report.attempts[0].fate == "settled"
        assert "record_count:bedrock.byte_bound.v1" in books.log
        backend.processor.force_flush(timeout_millis=1000)
        assert isinstance(backend.spans, MemorySpans)
        deadline = time.monotonic() + 1
        while backend.lane.queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        spans = backend.spans.get_finished_spans()
        assert any(span.name == "provider.call" for span in spans)
        serialized = repr(report) + caplog.text + json.dumps([dict(span.attributes or {}) for span in spans])
        for secret in (KEY_ID, SECRET, TOKEN, "20261115T120000Z", "AWS4-HMAC-SHA256", "Authorization"):
            assert secret not in serialized
        assert repr(access) == "BedrockAccess(<hidden>)"
        with pytest.raises(TypeError):
            json.dumps(access)
    finally:
        backend.close()
        backend.shutdown_thread.join(timeout=2)


def test_cancellation_leaves_no_signer_worker_or_late_request(access: BedrockAccess) -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        count = 0
        closed = False

        class Blocking(httpx2.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
                nonlocal count
                count += 1
                entered.set()
                await asyncio.Event().wait()
                pytest.fail("cancelled exchange resumed")

            async def aclose(self) -> None:
                nonlocal closed
                closed = True

        books = Books()
        books.configuration = configuration()
        task = asyncio.create_task(call(cast(Any, books), Providers({}, lambda _: Blocking(), bedrock=access),
            RunBinding(uuid4()), uuid4(), "cancel", request(), "judge", deadline=time.monotonic() + 5,
            limits=CallLimits(retries_per_request=0, repairs=0)))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.03)
        assert count == 1 and closed and "mark_unresolved" in books.log

    asyncio.run(scenario())


def test_transport_refuses_second_request_and_signed_header_tampering(access: BedrockAccess) -> None:
    async def scenario() -> None:
        p = prepared()
        headers = access.sign(p.body)
        inner = Script(reply(response()))
        transport = BoundedTransport(inner, Expected("bedrock", p.path, p.body), SecretStr(""),
                                     signed_headers={k.lower(): SecretStr(v) for k, v in headers.items()})
        http = http_client(transport, httpx2.Timeout(1))
        try:
            url = ENDPOINTS["bedrock"].base_url + p.path
            await http.post(url, headers=headers, content=p.body)
            with pytest.raises(TransportRefused, match="second_request"):
                await http.post(url, headers=headers, content=p.body)
            assert len(inner.requests) == 1
        finally:
            await http.aclose()
        for name in ("Authorization", "X-Amz-Date", "X-Amz-Security-Token"):
            inner = Script()
            transport = BoundedTransport(inner, Expected("bedrock", p.path, p.body), SecretStr(""),
                                         signed_headers={k.lower(): SecretStr(v) for k, v in headers.items()})
            http = http_client(transport, httpx2.Timeout(1))
            try:
                with pytest.raises(TransportRefused, match="credential_mismatch"):
                    await http.post(url, headers=headers | {name: "tampered"}, content=p.body)
                assert not inner.requests
            finally:
                await http.aclose()
        inner = Script()
        transport = BoundedTransport(inner, Expected("bedrock", p.path, p.body), SecretStr(""),
                                     signed_headers={k.lower(): SecretStr(v) for k, v in headers.items()})
        http = http_client(transport, httpx2.Timeout(1))
        try:
            with pytest.raises(TransportRefused, match="body_mismatch"):
                await http.post(url, headers=headers, content=p.body + b" ")
            assert not inner.requests
        finally:
            await http.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize(("data", "fate", "reason"), [
    (response(usage=None), "unresolved", None),
    (response(usage={"input_tokens": 1, "output_tokens": True}), "unresolved", "usage_incomplete"),
    (response(usage={"input_tokens": 1, "output_tokens": 65}), "settled", "output_limit_exceeded"),
    (response(usage={"input_tokens": 3000, "output_tokens": 1}), "settled", "count_underestimate"),
    (response(role="user"), "settled", "response_malformed"),
    (response(content=[{"type": "image", "source": {}}]), "settled", "unexpected_content_block"),
])
def test_port_settles_known_holds_unknown_and_blocks_overruns(access: BedrockAccess, data: dict[str, Any],
                                                            fate: str, reason: str | None) -> None:
    books = Books()
    books.configuration = configuration()
    script = Script(reply(data))
    report = asyncio.run(call(cast(Any, books), Providers({}, lambda _: script, bedrock=access), RunBinding(uuid4()),
        uuid4(), "bedrock", request(), "judge", deadline=time.monotonic() + 5,
        limits=CallLimits(retries_per_request=0, repairs=0)))
    assert report.attempts[0].fate == fate
    assert report.reason == reason
    assert len(script.requests) == 1
    assert ("settle" in books.log) == (fate == "settled")


def test_bedrock_response_bounds_redirect_and_no_env_proxies(access: BedrockAccess,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "https://invalid-proxy.example.invalid")
    redirect = Script(reply({}, 307, location="https://other.example.invalid"))
    assert asyncio.run(invoke(prepared(), redirect, access)).error == "http_307"
    assert len(redirect.requests) == 1
    compressed = Script(reply(response(), 200, **{"content-encoding": "gzip"}))
    assert asyncio.run(invoke(prepared(), compressed, access)).error == "content_encoding"
    oversized = Script(lambda req: httpx2.Response(200, stream=Chunks([b"x" * (65536 + 1)]), request=req))
    assert asyncio.run(invoke(prepared(), oversized, access)).error == "line_too_long"


def test_each_retry_signs_once_and_sends_one_request(access: BedrockAccess, monkeypatch: pytest.MonkeyPatch) -> None:
    signs = 0
    original = BedrockAccess.sign

    def sign(self: BedrockAccess, body: bytes) -> dict[str, str]:
        nonlocal signs
        signs += 1
        return original(self, body)

    monkeypatch.setattr(BedrockAccess, "sign", sign)
    books = Books()
    books.configuration = configuration()
    script = Script(reply({"message": "not ready"}, 429), reply(response()))
    report = asyncio.run(call(cast(Any, books), Providers({}, lambda _: script, bedrock=access), RunBinding(uuid4()),
        uuid4(), "retry", request(), "judge", deadline=time.monotonic() + 5,
        limits=CallLimits(retries_per_request=1, repairs=0, backoff_seconds=0)))
    assert signs == len(script.requests) == len(report.attempts) == 2
    assert [record.fate for record in report.attempts] == ["unresolved", "settled"]


class MemoryStore:
    """Offline store for the real Ledger rules; no claim about PostgreSQL properties."""

    def __init__(self) -> None:
        scope = Scope(uuid4(), "operation", Decimal("0.05"), 4, Decimal(0), Decimal(0), 0, 0, False, cap_counts=4)
        self.scope = scope
        self.ref = ScopeRef.of("operation", scope.id)
        self.attempts: dict[UUID, Attempt] = {}

    @contextmanager
    def transaction(self) -> Iterator[MemoryStore]:
        earlier_scope, earlier_attempts = self.scope, dict(self.attempts)
        try:
            yield self
        except BaseException:
            self.scope, self.attempts = earlier_scope, earlier_attempts
            raise

    def now(self) -> datetime:
        return datetime.now(UTC)

    def bind(self, binding: Binding, caps: Caps) -> tuple[ScopeRef, ...]:
        assert isinstance(binding, OperationBinding)
        return (self.ref,)

    def attempt_refs(self, attempt_id: UUID) -> tuple[ScopeRef, ...] | None:
        return (self.ref,) if attempt_id in self.attempts else None

    def run_active(self, refs: Sequence[ScopeRef]) -> bool:
        return True

    def check_admission(self, refs: Sequence[ScopeRef]) -> None:
        pass

    def lock_scopes(self, refs: Sequence[ScopeRef]) -> list[Scope]:
        return [self.scope]

    def lock_attempt(self, attempt_id: UUID) -> Attempt | None:
        return self.attempts.get(attempt_id)

    def insert_attempt(self, attempt: Attempt, now: datetime) -> None:
        assert attempt.id not in self.attempts
        self.attempts[attempt.id] = attempt

    def update_attempt(self, attempt: Attempt, now: datetime, settlement: Settlement | None = None) -> None:
        self.attempts[attempt.id] = attempt

    def update_scope(self, scope: Scope, now: datetime) -> None:
        self.scope = scope

    def record_usage(self, attempt: Attempt, settlement: Settlement, now: datetime) -> None:
        pass


@pytest.mark.parametrize(("data", "expected"), [(response(), "settled"), (response(usage=None), "unresolved"),
    (response(usage={"input_tokens": 100_001, "output_tokens": 128_000}), "settled")])
def test_real_ledger_settlement_hold_and_cost_overrun(access: BedrockAccess, data: dict[str, Any],
                                                    expected: str) -> None:
    store = MemoryStore()
    ledger = Ledger(store, configuration())
    script = Script(reply(data))
    report = asyncio.run(call(ledger, Providers({}, lambda _: script, bedrock=access),
        OperationBinding("bedrock-smoke", "fixture"), uuid4(), "bedrock", request(), "judge",
        deadline=time.monotonic() + 5, limits=CallLimits(retries_per_request=0, repairs=0)))
    assert report.attempts[0].fate == expected
    assert len(script.requests) == 1
    if expected == "unresolved":
        assert store.scope.held_usd > 0 and store.scope.spent_usd == 0
    else:
        assert store.scope.held_usd == 0 and store.scope.spent_usd > 0
    if data["usage"] and data["usage"]["input_tokens"] > 100_000:
        assert store.scope.overrun and store.scope.contract_block == "input_limit_exceeded"


def test_real_ledger_rejects_byte_bound_before_network(access: BedrockAccess) -> None:
    store = MemoryStore()
    ledger = Ledger(store, configuration(max_input=100))
    script = Script()
    report = asyncio.run(call(ledger, Providers({}, lambda _: script, bedrock=access),
        OperationBinding("bedrock-smoke", "too-large"), uuid4(), "bedrock", request(), "judge",
        deadline=time.monotonic() + 5, limits=CallLimits(retries_per_request=0, repairs=0)))
    assert report.attempts[0].fate == "released" and not script.requests
    assert store.scope.held_usd == store.scope.spent_usd == 0


@pytest.mark.parametrize("operation_key", [None, "retained-smoke-budget"])
def test_smoke_profile_output_and_persisted_budget(
    access: BedrockAccess, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    operation_key: str | None,
) -> None:
    # Execute the actual driver with local database boundaries replaced and the real Ledger/adapter intact.
    # Reusing the same store models persisted scope lookup; PostgreSQL persistence is covered separately.
    driver = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/bedrock_smoke.py"))
    main = driver["main"]
    runtime = main.__globals__
    config = driver["configuration"]()
    assert config.actors["judge"].model == "bedrock:us.anthropic.claude-haiku-5-5"
    assert config.actors["judge"].max_input == 4096 and config.actors["judge"].max_output == 64
    assert config.caps.operation_calls == 4 and config.caps.operation_usd == Decimal("0.05")
    store = MemoryStore()
    bindings: list[OperationBinding] = []

    def bind(binding: Binding, caps: Caps) -> tuple[ScopeRef, ...]:
        assert isinstance(binding, OperationBinding)
        bindings.append(binding)
        return (store.ref,)

    def ledger(**kwargs: Any) -> Ledger:
        return Ledger(store, kwargs["configuration"])

    script = Script(*(reply(response(), 200, **{"x-amzn-RequestId": "offline-smoke"}) for _ in range(4)))
    monkeypatch.setattr(store, "bind", bind)
    monkeypatch.setitem(runtime, "make_engine", lambda _, **kwargs: SimpleNamespace(dispose=lambda: None))
    monkeypatch.setitem(runtime, "build_app_ledger", ledger)
    monkeypatch.setenv("POLICYOPS_BEDROCK_PROFILE", "operator")
    monkeypatch.setattr(BedrockAccess, "from_settings", lambda _: access)
    monkeypatch.setattr(httpx2, "AsyncHTTPTransport", lambda **_: script)
    argv = ["bedrock_smoke.py", "--workspace", str(uuid4())]
    if operation_key is not None:
        argv += ["--operation-key", operation_key]
    monkeypatch.setattr(sys, "argv", argv)
    assert main() == 2 and not bindings and not script.requests
    monkeypatch.setattr(sys, "argv", [*argv, "--execute"])
    for index in range(5):
        assert main() == (0 if index < 4 else 1)
        summary = json.loads(capsys.readouterr().out)
        assert set(summary) == {"effective_model", "usage", "cost_usd", "request_id"}
        assert summary["effective_model"] == "us.anthropic.claude-haiku-5-5"
        if index < 4:
            assert summary["request_id"] == "offline-smoke" and Decimal(summary["cost_usd"]) > 0
    assert bindings and all(b == OperationBinding("bedrock-smoke", operation_key or "bedrock-haiku-smoke-v1")
                            for b in bindings)
    assert len(script.requests) == len(store.attempts) == 4
    assert store.scope.held_usd == 0 and store.scope.spent_usd < Decimal("0.05")
    assert all(fresh(body)["max_tokens"] == 64 for body in script.bodies)
