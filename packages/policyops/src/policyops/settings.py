"""Validated application settings (authentication and HTTP surface).

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
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, StringConstraints, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


Environment = Literal["test", "local", "deployment"]
CALLBACK_PATH = "/api/v1/auth/callback"
ClientId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]


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
