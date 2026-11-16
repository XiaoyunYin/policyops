"""Static-file-only credentials, resolved before a call deadline; CPU-only, quiet SigV4 per attempt."""

from __future__ import annotations

from configparser import ConfigParser
from configparser import Error as ConfigError
from pathlib import Path
from typing import Annotated, Any

from botocore.auth import SIGV4_TIMESTAMP, SigV4Auth, get_current_datetime
from botocore.awsrequest import AWSRequest
from botocore.credentials import ConfigProvider, ReadOnlyCredentials, SharedCredentialProvider
from pydantic import StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict

from policyops.providers.contract import ENDPOINTS, ContractGap, require_clean_environment


MODEL = "us.anthropic.claude-haiku-5-5"
REGISTRY_MODEL = "bedrock:us.anthropic.claude-haiku-5-5"
REGION = "us-west-2"
UNSUPPORTED = frozenset({"role_arn", "source_profile", "credential_process", "web_identity_token_file",
                         "credential_source", "login_session", "aws_security_token"})
MAX_PROFILE_BYTES = 1 << 20


class BedrockSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POLICYOPS_BEDROCK_", env_file=None, extra="forbid", frozen=True,
                                      hide_input_in_errors=True)
    profile: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    region: str = REGION
    credentials_file: Path | None = None
    config_file: Path | None = None


def _profile(path: Path, section: str) -> dict[str, str]:
    """One capped snapshot, no interpolation, includes defaults so provider keys cannot hide there."""
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_PROFILE_BYTES + 1)
        if len(data) > MAX_PROFILE_BYTES:
            raise ContractGap("bedrock.credentials_file_too_large")
        parser = ConfigParser(interpolation=None)
        parser.read_string(data.decode("utf-8"))
        return dict(parser.items(section)) if parser.has_section(section) else {}
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError, ConfigError):
        raise ContractGap("bedrock.credentials_file_invalid") from None


class _QuietSigV4Auth(SigV4Auth):  # type: ignore[misc]
    """Pinned botocore add_auth orchestration with its four DEBUG calls omitted.

    Canonicalization, key derivation, signature and header injection remain botocore's. Upstream logs the
    canonical security-token/date headers. No global logger mutation or worker thread is needed.
    """

    def add_auth(self, request: Any) -> None:
        request.context["timestamp"] = get_current_datetime().strftime(SIGV4_TIMESTAMP)
        self._modify_request_before_signing(request)
        canonical = self.canonical_request(request)
        signature = self.signature(self.string_to_sign(request, canonical), request)
        self._inject_signature_to_request(request, signature)


class BedrockAccess:
    """Opaque process-memory access. Reconstruct to reload keys; session tokens are used as given, never refreshed."""

    __slots__ = ("_credentials",)

    def __init__(self, credentials: Any) -> None:
        if type(credentials) is not ReadOnlyCredentials:
            raise ContractGap("bedrock.credentials_invalid")
        self._credentials = credentials

    def __repr__(self) -> str:
        return "BedrockAccess(<hidden>)"

    @classmethod
    def from_settings(cls, settings: BedrockSettings) -> BedrockAccess:
        require_clean_environment("bedrock")
        if settings.region != REGION:
            raise ContractGap("bedrock.region_unsupported")
        # Path.home is the platform user home, not AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE.
        home = Path.home() / ".aws"
        shared = _profile(settings.credentials_file or home / "credentials", settings.profile)
        config = _profile(settings.config_file or home / "config",
                          "default" if settings.profile == "default" else f"profile {settings.profile}")
        if any(key.startswith("sso_") or key in UNSUPPORTED for values in (shared, config) for key in values):
            raise ContractGap("bedrock.credentials_unsupported_provider")
        # Only these two providers exist. Their parsers read the already validated local snapshots, eliminating
        # a check/load file race; neither can spawn, fetch, assume a role, discover metadata or refresh.
        try:
            credentials = SharedCredentialProvider(
                "unused", profile_name=settings.profile, ini_parser=lambda _: {settings.profile: shared}).load()
            if credentials is None:
                credentials = ConfigProvider(
                    "unused", profile_name=settings.profile,
                    config_parser=lambda _: {"profiles": {settings.profile: config}}).load()
            if credentials is None:
                raise ContractGap("bedrock.credentials_missing")
            frozen = credentials.get_frozen_credentials()
            if not frozen.access_key or not frozen.secret_key:
                raise ContractGap("bedrock.credentials_missing")
            if any(not value.isascii() or not value.isprintable() or len(value) > 8192
                   for value in (frozen.access_key, frozen.secret_key, frozen.token) if value is not None):
                raise ContractGap("bedrock.credentials_invalid")
        except ContractGap:
            raise
        except Exception:
            raise ContractGap("bedrock.credentials_invalid") from None
        return cls(frozen)

    def sign(self, body: bytes) -> dict[str, str]:
        require_clean_environment("bedrock")
        endpoint = ENDPOINTS["bedrock"]
        request = AWSRequest(method="POST", url=endpoint.base_url + endpoint.create_path, data=body,
                             headers={"Content-Type": "application/json", "Accept": "application/json",
                                      "Host": endpoint.host})
        _QuietSigV4Auth(self._credentials, "bedrock", REGION).add_auth(request)
        return dict(request.headers.items())
