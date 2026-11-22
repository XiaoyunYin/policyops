"""Validated application settings (authentication, HTTP surface and the API server's runtime database logins).

Values come from explicit `POLICYOPS_*` environment variables only (no `.env` file is read). Secrets are
`SecretStr` and never appear in reprs or logs.

Environments:
* `deployment`: HTTPS issuer and public origin, `Secure` `__Host-` cookies; no test hooks (the app factory refuses
  a test OIDC transport, see `policyops.api.app`).
* `local`: the local demo. Plain HTTP is allowed only for an explicit loopback IP origin/issuer (127.0.0.1 or ::1);
  cookies then use distinct non-`__Host-` names without `Secure`, because browsers do not uniformly treat a
  loopback IP over HTTP as a secure context.
* `test`: like `local`, and the only mode in which a test OIDC transport may be injected.
"""

from __future__ import annotations

from datetime import timedelta
import ipaddress
import os
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, StringConstraints, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


Environment = Literal["test", "local", "deployment"]
CALLBACK_PATH = "/api/v1/auth/callback"
ClientId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]


class TelemetrySettings(BaseSettings):
    """Manual telemetry with explicit, local-only OTLP HTTP destinations."""

    model_config = SettingsConfigDict(env_prefix="POLICYOPS_TELEMETRY_", env_file=None, extra="forbid", frozen=True,
                                      hide_input_in_errors=True)
    enabled: bool = False
    exporter: Literal["console", "memory", "otlp"] = "memory"
    traces_url: str | None = None
    metrics_url: str | None = None

    def require_safe_environment(self, *, deployment: bool = False) -> None:
        # The SDK has ambient configuration for exporters, resources, readers and processors.
        if any(name.upper().startswith("OTEL_") for name in os.environ):
            raise SettingsError("OTEL_* variables must be unset")
        if self.exporter == "otlp" and (deployment or os.environ.get("POLICYOPS_ENV") == "deployment"):
            raise SettingsError("OTLP export is local only")

    @model_validator(mode="after")
    def _safe_export(self) -> Self:
        self.require_safe_environment()
        if self.exporter == "otlp":
            for signal, value in (("traces", self.traces_url), ("metrics", self.metrics_url)):
                # Use numeric loopback addresses so name resolution cannot change the destination.
                match = re.fullmatch(rf"http://(127\.0\.0\.1|\[::1\]):([0-9]{{1,5}})/v1/{signal}", value or "")
                if match is None or not 1 <= int(match[2]) <= 65535:
                    raise SettingsError(f"{signal}_url must be an explicit loopback HTTP /v1/{signal} URL with a port")
        return self


class SettingsError(ValueError):
    """Configuration is unsafe or inconsistent for the selected environment."""


def _is_loopback_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_url(value: str, name: str, *, origin_only: bool) -> tuple[str, str]:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SettingsError(f"{name} must be an absolute http(s) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise SettingsError(f"{name} must not contain credentials, a query or a fragment")
    if origin_only and parts.path not in ("", "/"):
        raise SettingsError(f"{name} must be an origin (scheme, host and optional port only)")
    if value.endswith("/"):
        raise SettingsError(f"{name} must not end with '/'")
    return parts.scheme, parts.hostname


class AuthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POLICYOPS_", env_file=None, extra="forbid", frozen=True,
                                      hide_input_in_errors=True)

    env: Environment
    public_origin: str
    oidc_issuer: str
    oidc_client_id: ClientId
    oidc_client_secret: SecretStr
    session_absolute_ttl: Annotated[timedelta, Field(ge=timedelta(minutes=5), le=timedelta(hours=24))] = \
        timedelta(hours=8)
    session_idle_ttl: Annotated[timedelta, Field(ge=timedelta(minutes=1), le=timedelta(hours=8))] = \
        timedelta(minutes=30)
    login_request_ttl: Annotated[timedelta, Field(ge=timedelta(minutes=1), le=timedelta(minutes=10))] = \
        timedelta(minutes=10)
    clock_skew: Annotated[timedelta, Field(ge=timedelta(0), le=timedelta(minutes=5))] = timedelta(seconds=60)
    http_timeout_seconds: Annotated[float, Field(gt=0, le=30)] = 5.0
    max_response_bytes: Annotated[int, Field(ge=4096, le=1_048_576)] = 262_144
    jwks_cache_ttl: Annotated[timedelta, Field(ge=timedelta(minutes=1), le=timedelta(hours=24))] = \
        timedelta(minutes=10)
    jwks_min_refresh_interval: Annotated[timedelta, Field(ge=timedelta(seconds=1), le=timedelta(minutes=10))] = \
        timedelta(seconds=30)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        origin_scheme, origin_host = _check_url(self.public_origin, "public_origin", origin_only=True)
        issuer_scheme, issuer_host = _check_url(self.oidc_issuer, "oidc_issuer", origin_only=False)
        if len(self.oidc_client_secret.get_secret_value()) < 16:
            raise SettingsError("oidc_client_secret must have at least 16 characters")
        if self.session_idle_ttl > self.session_absolute_ttl:
            raise SettingsError("session_idle_ttl must not exceed session_absolute_ttl")
        if self.env == "deployment":
            if origin_scheme != "https" or issuer_scheme != "https":
                raise SettingsError("deployment requires an HTTPS public origin and issuer")
        else:
            for scheme, host, name in ((origin_scheme, origin_host, "public_origin"),
                                       (issuer_scheme, issuer_host, "oidc_issuer")):
                if scheme == "http" and not _is_loopback_ip(host):
                    raise SettingsError(f"plain-HTTP {name} is allowed only on a loopback IP (127.0.0.1 or ::1)")
        return self

    # -- derived values ------------------------------------------------------------------------------------

    @property
    def redirect_uri(self) -> str:
        return self.public_origin + CALLBACK_PATH

    @property
    def secure_cookies(self) -> bool:
        return urlsplit(self.public_origin).scheme == "https"

    @property
    def session_cookie(self) -> str:
        return "__Host-policyops_session" if self.secure_cookies else "policyops_session_local"

    @property
    def login_cookie(self) -> str:
        return "__Host-policyops_login" if self.secure_cookies else "policyops_login_local"


DatabaseName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")]
SslMode = Literal["disable", "require", "verify-ca", "verify-full"]
# Refuse ambient endpoint overrides and every libpq TLS environment option. Even options passed explicitly
# are refused so configuration has one auditable source. See docs/database.md for the per-option rationale.
REFUSED_LIBPQ_ENV = (
    "PGSERVICE", "PGHOSTADDR", "PGSSLMODE", "PGREQUIRESSL", "PGSSLROOTCERT", "PGSSLCRL", "PGSSLCRLDIR",
    "PGSSLCERT", "PGSSLKEY", "PGSSLCERTMODE", "PGSSLNEGOTIATION", "PGSSLCOMPRESSION", "PGSSLSNI",
    "PGSSLMINPROTOCOLVERSION", "PGSSLMAXPROTOCOLVERSION",
)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                       r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def validate_sslrootcert(value: str | None) -> str | None:
    """Validate a path lexically, without file I/O or exposing its value in diagnostics.

    Accept absolute POSIX and Windows paths so container configuration can be checked on either host OS.
    libpq's special `system` trust-store selector is deliberately not a path.
    """
    if value is not None and (not value or any(ord(char) < 32 or ord(char) == 127 for char in value)
                              or not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute())):
        raise SettingsError("sslrootcert must be an absolute path without control characters")
    return value


class DatabaseSettings(BaseSettings):
    """The API server's two runtime logins to one PostgreSQL database (`POLICYOPS_DB_*`).

    The login roles are fixed (`policyops_auth_runtime` and `policyops_app_runtime`); only their separately
    configured passwords are read, so one credential is never assumed to serve both roles. No URL is accepted: a
    libpq URL or `key=value` string could carry its own host, service or options. `host` is one IP literal or DNS
    name (no list), `name` a plain identifier (libpq expands a database name containing `=` or a URI).
    """

    model_config = SettingsConfigDict(env_prefix="POLICYOPS_DB_", env_file=None, extra="forbid", frozen=True,
                                      hide_input_in_errors=True)

    host: str
    port: Annotated[int, Field(ge=1, le=65535)] = 5432
    name: DatabaseName
    sslmode: SslMode = "verify-full"
    sslrootcert: str | None = Field(default=None, repr=False)
    connect_timeout_seconds: Annotated[int, Field(ge=2, le=30)] = 5
    pool_size: Annotated[int, Field(ge=1, le=50)] = 5
    auth_password: SecretStr
    app_password: SecretStr

    _root_path = field_validator("sslrootcert")(validate_sslrootcert)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if not (_is_ip(self.host) or _HOSTNAME.match(self.host)):
            raise SettingsError("host must be one IP address or DNS name")
        if self.sslmode == "disable" and not _is_loopback_ip(self.host):
            raise SettingsError("sslmode=disable is allowed only for a loopback IP host (127.0.0.1 or ::1)")
        if self.sslmode in {"verify-ca", "verify-full"} and self.sslrootcert is None:
            raise SettingsError("sslrootcert is required for verify-ca or verify-full")
        for name in ("auth_password", "app_password"):
            secret: SecretStr = getattr(self, name)
            value = secret.get_secret_value()
            if not 16 <= len(value) <= 1024 or "\x00" in value:
                raise SettingsError(f"{name} must have 16 to 1024 characters and no NUL character")
        return self

    @property
    def host_is_ip(self) -> bool:
        return _is_ip(self.host)
