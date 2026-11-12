"""Settings safety by environment, test-hook refusal outside test mode, and access-log redaction (offline)."""

from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from pydantic import SecretStr, ValidationError
import pytest

from policyops.api.app import UnsafeTestHook, build_auth_runtime
from policyops.api.logging import RedactQueryFilter
from policyops.settings import AuthSettings
from policyops_contracts.clock import SystemClock
from policyops_testing.oidc_fake import FakeIssuer


SECRET = SecretStr("s" * 24)


def settings(**changes: Any) -> AuthSettings:
    values: dict[str, Any] = {"env": "local", "public_origin": "http://127.0.0.1:8000",
                              "oidc_issuer": "http://127.0.0.1:5556/dex", "oidc_client_id": "policyops-local",
                              "oidc_client_secret": SECRET, **changes}
    return AuthSettings(**values)


def test_local_loopback_http_uses_distinct_non_host_cookies() -> None:
    local = settings()
    assert (local.secure_cookies, local.session_cookie, local.login_cookie) == (
        False, "policyops_session_local", "policyops_login_local")
    assert local.redirect_uri == "http://127.0.0.1:8000/api/v1/auth/callback"
    https = settings(public_origin="https://policyops.example.test", oidc_issuer="https://id.example.test/dex")
    assert (https.secure_cookies, https.session_cookie) == (True, "__Host-policyops_session")


@pytest.mark.parametrize("changes", [
    {"env": "deployment"},  # HTTP origin and issuer
    {"env": "deployment", "public_origin": "https://policyops.example.test"},  # HTTP issuer
    {"public_origin": "http://localhost:8000"},  # loopback HTTP must be an explicit loopback IP
    {"oidc_issuer": "http://id.example.test/dex"},  # non-loopback HTTP issuer
    {"public_origin": "http://127.0.0.1:8000/app"}, {"public_origin": "http://127.0.0.1:8000/"},
    {"oidc_issuer": "http://user:" + "pw@127.0.0.1:5556/dex"},  # assembled: no literal credential URL
    {"oidc_issuer": "http://127.0.0.1:5556/dex?x=1"},
    {"oidc_issuer": "ftp://127.0.0.1/dex"}, {"oidc_client_secret": SecretStr("short")},
    {"oidc_client_id": "bad id"}, {"session_idle_ttl": timedelta(hours=9)},
    {"session_absolute_ttl": timedelta(hours=1), "session_idle_ttl": timedelta(hours=2)},
    {"login_request_ttl": timedelta(minutes=11)}, {"clock_skew": timedelta(minutes=6)}, {"env": "production"},
    {"unexpected": "x"},
])
def test_unsafe_or_inconsistent_settings_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        settings(**changes)


def test_a_valid_deployment_configuration() -> None:
    deployed = settings(env="deployment", public_origin="https://policyops.example.test",
                        oidc_issuer="https://id.example.test/dex")
    assert deployed.secure_cookies and deployed.login_cookie == "__Host-policyops_login"


def test_secrets_never_appear_in_reprs_or_errors() -> None:
    assert "s" * 24 not in repr(settings())
    with pytest.raises(ValidationError) as raised:
        settings(env="deployment", oidc_client_secret=SecretStr("t" * 24))
    assert "t" * 24 not in str(raised.value)


def test_settings_are_read_only_from_explicit_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {"POLICYOPS_ENV": "local", "POLICYOPS_PUBLIC_ORIGIN": "http://127.0.0.1:8000",
                        "POLICYOPS_OIDC_ISSUER": "http://127.0.0.1:5556/dex",
                        "POLICYOPS_OIDC_CLIENT_ID": "policyops-local",
                        "POLICYOPS_OIDC_CLIENT_SECRET": "e" * 24}.items():
        monkeypatch.setenv(name, value)
    loaded = AuthSettings()
    assert loaded.oidc_client_secret.get_secret_value() == "e" * 24 and loaded.env == "local"
    assert AuthSettings.model_config.get("env_file") is None


@pytest.mark.parametrize("env", ["local", "deployment"])
def test_a_test_oidc_transport_is_refused_outside_test_mode(env: str) -> None:
    configured = settings() if env == "local" else settings(env="deployment",
                                                            public_origin="https://policyops.example.test",
                                                            oidc_issuer="https://id.example.test/dex")
    fake = FakeIssuer(redirect_uri=configured.redirect_uri)
    with pytest.raises(UnsafeTestHook):  # refused before any database or network use
        build_auth_runtime(configured, auth_engine=None, app_engine=None,  # type: ignore[arg-type]
                           clock=SystemClock(), oidc_transport=fake.transport)


def test_access_log_query_strings_are_redacted() -> None:
    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                               ("127.0.0.1:5000", "GET", "/api/v1/auth/callback?code=c0de&state=st4te", "1.1", 303),
                               None)
    assert RedactQueryFilter().filter(record) is True
    assert record.getMessage() == '127.0.0.1:5000 - "GET /api/v1/auth/callback?[REDACTED] HTTP/1.1" 303'
    plain = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                              ("127.0.0.1:5000", "GET", "/api/v1/me", "1.1", 200), None)
    RedactQueryFilter().filter(plain)
    assert plain.getMessage().endswith('"GET /api/v1/me HTTP/1.1" 200')


def test_the_access_log_configuration_loads_and_redacts(capsys: pytest.CaptureFixture[str]) -> None:
    import logging.config

    from policyops.api.logging import LOG_CONFIG

    root = logging.getLogger()
    saved = root.handlers[:], root.level
    logging.config.dictConfig(LOG_CONFIG)
    access = logging.getLogger("uvicorn.access")
    try:
        access.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:5000", "GET", "/api/v1/auth/callback?code=c0de-1&state=s",
                    "1.1", 303)
        output = capsys.readouterr().out
        assert '"event":"http_access"' in output
        assert "/api/v1/auth/callback" not in output and "c0de-1" not in output
    finally:
        for handler in root.handlers:
            if handler not in saved[0]:
                handler.close()
        root.handlers[:], root.level = saved
        for handler in list(access.handlers):
            access.removeHandler(handler)
        access.propagate = True
