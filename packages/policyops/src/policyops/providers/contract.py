"""The server-owned provider contract (T11): endpoints, versions, wire values and what the adapters refuse.

Facts are from the installed SDK sources (`openai` 3.40.0 and `anthropic` 2.3.0, inspected 2026-11-05) and the
reviewer's primary-documentation notes of 2026-11-05. They are a contract for this code, not proof of any account's
access, model behaviour or price.

**Endpoints** are fixed HTTPS hosts and paths: the model never chooses one, and no environment variable or setting
can redirect them.

**Version identity:**
- Anthropic: the `anthropic-version` header is pinned to what the installed SDK sends (`2026-10-21`).
- OpenAI: there is no version header.

Both are part of the request identity.

**OpenAI (Responses, `gpt-6-luna`):**
- `service_tier="default"`, `store=false`, `parallel_tool_calls=false`, `truncation="disabled"`;
- cache `none` is sent as `prompt_cache_options={"mode": "explicit"}` with no breakpoints (implicit caching
  otherwise writes at 30m);
- cache `30m` is sent as `{"mode": "implicit", "ttl": "30m"}`;
- `12h` is refused: the SDK documents `30m` as the only supported TTL.

**Anthropic (Messages, `claude-haiku-5-5`):**
- `thinking={"type": "disabled"}` with `output_config.effort="low"`. Haiku 5.5's adaptive thinking is otherwise on by
  default, and the effort guide's Haiku 5.5 section accepts `disabled` at effort `high` or below.
- `service_tier="standard_only"`, `speed="standard"`;
- no sampling parameters and no `inference_geo`;
- cache `none` means no `cache_control` anywhere, no replayed thinking blocks and no per-message effort change;
- the positive cache modes (`5m`, `1h`) are not implemented and are refused.

**Ambient SDK settings.** The SDKs read many environment variables beyond the key: organization, project and
workspace, admin and webhook keys, custom headers, logging, profiles, identity tokens, telemetry and cloud base URLs.
A client is refused while any `OPENAI_*` / `ANTHROPIC_*` **name** other than the API key's is set (values are never
read). Each request is also checked against a header
allowlist, so nothing such a setting could add reaches the wire.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from types import MappingProxyType
from typing import Literal


Provider = Literal["openai", "anthropic"]


@dataclass(frozen=True)
class Endpoint:
    host: str
    create_path: str
    count_path: str
    base_url: str
    version_headers: Mapping[str, str]
    auth_header: str


ENDPOINTS: Mapping[str, Endpoint] = MappingProxyType({
    "openai": Endpoint("api.openai.com", "/v1/responses", "/v1/responses/input_tokens", "https://api.openai.com/v1",
                       MappingProxyType({}), "authorization"),
    "anthropic": Endpoint("api.anthropic.com", "/v1/messages", "/v1/messages/count_tokens",
                          "https://api.anthropic.com", MappingProxyType({"anthropic-version": "2026-10-21"}),
                          "authorization"),  # anthropic 2.3.0 sends its API key as `Authorization: Bearer`
})
CONTRACT_VERSION = "policyops.provider-request/v1"

# Cache modes the adapters implement. Everything else in the registry is refused before any reservation.
IMPLEMENTED_CACHE_MODES: Mapping[str, frozenset[str]] = MappingProxyType({
    "openai": frozenset({"none", "30m"}), "anthropic": frozenset({"none"})})
NOT_IMPLEMENTED = MappingProxyType({
    ("openai", "12h"): "the installed SDK documents 30m as the only supported prompt-cache TTL",
    ("anthropic", "5m"): "Anthropic positive cache modes are not implemented (cache-none contract only)",
    ("anthropic", "1h"): "Anthropic positive cache modes are not implemented (cache-none contract only)",
})
EXPECTED_SERVICE_TIER = MappingProxyType({"openai": "default", "anthropic": "standard"})
# Returned model IDs priced as the requested model. Versioned and explicit: initially only the exact requested ID.
# No dated snapshot is assumed (none was listed in the verified sources); one is added here only with a recorded
# source, such as a bounded live run that returned it.
CONFIRMED_MODEL_IDS_VERSION = "policyops.confirmed-model-ids/v1"
CONFIRMED_MODEL_IDS: Mapping[str, frozenset[str]] = MappingProxyType({
    "gpt-6-luna": frozenset({"gpt-6-luna"}), "claude-haiku-5-5": frozenset({"claude-haiku-5-5"})})
ALLOWED_INFERENCE_GEO = frozenset({None, "global"})

# Deny by prefix: the installed SDKs read many more of their own variables (organization, project and workspace IDs,
# admin and webhook keys, custom headers, logging, profiles and config directories, identity tokens, telemetry,
# cloud base URLs). Only the API key name is tolerated, because the key is always passed explicitly.
ENV_PREFIX: Mapping[str, str] = MappingProxyType({"openai": "OPENAI_", "anthropic": "ANTHROPIC_"})
ENV_TOLERATED: Mapping[str, frozenset[str]] = MappingProxyType({"openai": frozenset({"OPENAI_API_KEY"}),
                                                               "anthropic": frozenset({"ANTHROPIC_API_KEY"})})

# Header names (lower case) a request may carry. `x-stainless-*` are the SDK's platform and retry-count headers.
ALLOWED_HEADERS = frozenset({"accept", "accept-encoding", "content-type", "content-length", "user-agent", "host",
                             "connection"})
ALLOWED_HEADER_PREFIX = "x-stainless-"


class ContractGap(ValueError):
    """The requested mode, field or setting is outside the implemented provider contract; nothing was sent."""


def ambient_settings(provider: Provider, environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """The disallowed SDK environment variable names that are set. Only the names are read: the mapping is iterated
    for its keys (`name in os.environ` would go through `__getitem__` and decode the value)."""
    names = frozenset(iter(os.environ if environ is None else environ))
    prefix = ENV_PREFIX[provider]
    return tuple(sorted(name for name in names if name.startswith(prefix) and name not in ENV_TOLERATED[provider]))


def require_clean_environment(provider: Provider, environ: Mapping[str, str] | None = None) -> None:
    present = ambient_settings(provider, environ)
    if present:
        raise ContractGap(f"refusing to build a {provider} client while {', '.join(present)} is set")


def require_cache_mode(provider: Provider, cache_mode: str) -> None:
    if cache_mode not in IMPLEMENTED_CACHE_MODES[provider]:
        reason = NOT_IMPLEMENTED.get((provider, cache_mode), "not an implemented cache mode")
        raise ContractGap(f"{provider} cache mode {cache_mode!r}: {reason}")
