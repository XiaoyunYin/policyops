"""OpenID Connect relying party: discovery, JWKS, code exchange and ID token validation.

Transport (httpx, already locked): fixed timeouts, no redirects, no environment proxies or `.netrc`
(`trust_env=False`), bounded response sizes, and every endpoint must be on the configured issuer's own origin.

ID token validation (OIDC Core 1.0 §3.1.3.7), with no algorithm or key choice taken from the token:
* the header `alg` must be RS256 (the only configured algorithm); `jku`, `x5u`, `jwk`, `x5c` and `crit` headers are
  refused, never followed; `kid` must select exactly one RSA signing key from the issuer's JWKS;
* PyJWT verifies the signature, `iss` (exact) and `aud`; required claims are typed explicitly;
* `aud` must be exactly the client ID (no other audiences); `azp`, if present, must be the client ID;
* `exp`, `iat` and `nbf` are checked here against the injected Clock with the configured skew. PyJWT's own time
  checks are switched off for that reason only: it reads the system clock, which deterministic tests cannot
  control. The replacement checks are explicit and tested at their boundaries;
* `nonce` must match the stored digest for this login.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import json
import time
from typing import Annotated, Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from policyops.auth import tokens
from policyops.settings import AuthSettings
from policyops_contracts.clock import Clock


ALGORITHM = "RS256"
REFUSED_HEADERS = ("jku", "x5u", "jwk", "x5c", "crit")
MAX_JWKS_KEYS = 20


class OidcError(RuntimeError):
    """The identity provider or its response failed validation. Messages never contain tokens or secrets."""


class OidcUnavailable(OidcError):
    """The identity provider could not be used: transport failure, timeout, server error or an unusable response
    to a well-formed request (as opposed to a refused grant or an invalid token)."""


Subject = Annotated[str, StringConstraints(min_length=1, max_length=255)]
# NumericDate (RFC 7519) bounded to what a datetime can represent: 0 .. 9999-12-31T23:59:59Z.
NumericDate = Annotated[int, Field(ge=0, le=253_402_300_799)]


class IdTokenClaims(BaseModel):
    """The validated claims the application uses (others are ignored)."""

    model_config = ConfigDict(frozen=True, extra="ignore", strict=True)

    iss: str
    sub: Subject
    aud: str | list[str]
    exp: NumericDate
    iat: NumericDate
    nbf: NumericDate | None = None
    nonce: str
    azp: str | None = None
    name: Annotated[str, StringConstraints(max_length=200)] | None = None
    preferred_username: Annotated[str, StringConstraints(max_length=200)] | None = None
    email: Annotated[str, StringConstraints(max_length=320)] | None = None


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass
class OidcClient:
    settings: AuthSettings
    clock: Clock
    transport: httpx.BaseTransport | None = None
    _http: httpx.Client = field(init=False)
    _metadata: ProviderMetadata | None = field(default=None, init=False)
    _keys: dict[str, Any] = field(default_factory=dict, init=False)
    _keys_loaded_at: datetime | None = field(default=None, init=False)
    _last_refresh_attempt: datetime | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        timeout = httpx.Timeout(self.settings.http_timeout_seconds)
        self._http = httpx.Client(transport=self.transport, timeout=timeout, follow_redirects=False,
                                  trust_env=False, limits=httpx.Limits(max_connections=10))
        self._origin = self._origin_of(self.settings.oidc_issuer)

    def close(self) -> None:
        self._http.close()

    # -- transport -----------------------------------------------------------------------------------------

    @staticmethod
    def _origin_of(url: str) -> tuple[str, str, int | None]:
        parts = urlsplit(url)
        return parts.scheme, (parts.hostname or "").lower(), parts.port

    def _trusted(self, url: object, name: str) -> str:
        """An absolute endpoint URL on the issuer's exact origin, with no credentials, query or fragment."""
        if not isinstance(url, str) or not 1 <= len(url) <= 2000:
            raise OidcUnavailable(f"{name} is missing or malformed")
        try:
            parts = urlsplit(url)
            origin = (parts.scheme, (parts.hostname or "").lower(), parts.port)  # .port raises for a bad port
        except ValueError:
            raise OidcUnavailable(f"{name} is not a valid URL") from None
        if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
            raise OidcUnavailable(f"{name} must not contain credentials, a query or a fragment")
        if origin != self._origin:
            raise OidcUnavailable(f"{name} is not on the issuer's origin")
        return url

    def _request(self, method: str, url: str, what: str, **kwargs: Any) -> dict[str, Any]:
        """One bounded provider call: the body is streamed and refused as soon as it exceeds max_response_bytes
        (a larger declared Content-Length is refused before reading), and the whole call must finish within
        http_timeout_seconds. httpx timeouts apply per network operation, so the overall deadline is checked
        between chunks: the worst case is that deadline plus one read timeout, never an indefinitely trickled body.
        The response is always closed."""
        limit, deadline = self.settings.max_response_bytes, time.monotonic() + self.settings.http_timeout_seconds
        body = bytearray()
        # Identity encoding only: compressed bodies are refused before any byte is decoded, and the limit then
        # bounds the raw bytes actually read (iter_raw), so a small compressed body cannot expand in memory.
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        try:
            with self._http.stream(method, url, headers=headers, **kwargs) as response:
                if response.status_code >= 500 or response.status_code in (408, 429):
                    raise OidcUnavailable(f"{what} returned HTTP {response.status_code}")
                if response.status_code != 200:
                    raise OidcError(f"{what} returned HTTP {response.status_code}")
                if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
                    raise OidcUnavailable(f"{what} response uses an unsupported content encoding")
                if self._declared_length(response.headers.get("content-length")) > limit:
                    raise OidcUnavailable(f"{what} response is too large")
                # A body an in-memory test transport already read is checked as one chunk; a network
                # transport never pre-reads, so its raw bytes are streamed and bounded as they arrive.
                chunks = [response.content] if response.is_stream_consumed else response.iter_raw()
                for chunk in chunks:
                    body += chunk
                    if len(body) > limit:
                        raise OidcUnavailable(f"{what} response is too large")
                    if time.monotonic() > deadline:
                        raise OidcUnavailable(f"{what} response took too long")
        except httpx.HTTPError as exc:
            raise OidcUnavailable(f"{what} request failed ({type(exc).__name__})") from None
        try:
            data = json.loads(bytes(body))
        except (ValueError, RecursionError):  # includes invalid UTF-8 and pathologically nested JSON
            raise OidcUnavailable(f"{what} response is not usable JSON") from None
        if not isinstance(data, dict):
            raise OidcUnavailable(f"{what} response is not a JSON object")
        return data

    def _declared_length(self, header: str | None) -> int:
        """The declared body length, bounded before conversion: only ASCII digits are accepted (leading zeros
        ignored), and anything longer than the limit's own digit count is "too large" without calling int() on it
        (Python refuses to convert very long digit strings). A malformed value is an unusable response."""
        if header is None:
            return 0
        declared = header.strip()
        if not declared or not declared.isascii() or not declared.isdigit():
            raise OidcUnavailable("the provider response has an invalid Content-Length")
        digits = declared.lstrip("0") or "0"
        if len(digits) > len(str(self.settings.max_response_bytes)):
            return self.settings.max_response_bytes + 1
        return int(digits)

    def _get(self, url: str, what: str) -> dict[str, Any]:
        return self._request("GET", url, what)

    # -- discovery and keys --------------------------------------------------------------------------------

    def metadata(self) -> ProviderMetadata:
        if self._metadata is None:
            data = self._get(self.settings.oidc_issuer + "/.well-known/openid-configuration", "discovery")
            if data.get("issuer") != self.settings.oidc_issuer:
                raise OidcUnavailable("discovery issuer does not exactly match the configured issuer")
            for name, required in (("id_token_signing_alg_values_supported", ALGORITHM),
                                   ("code_challenge_methods_supported", "S256")):
                values = data.get(name)
                if (not isinstance(values, list) or len(values) > 50
                        or not all(isinstance(value, str) for value in values) or required not in values):
                    raise OidcUnavailable(f"discovery {name} does not include {required}")
            self._metadata = ProviderMetadata(
                issuer=data["issuer"],
                authorization_endpoint=self._trusted(data.get("authorization_endpoint"), "authorization_endpoint"),
                token_endpoint=self._trusted(data.get("token_endpoint"), "token_endpoint"),
                jwks_uri=self._trusted(data.get("jwks_uri"), "jwks_uri"))
        return self._metadata

    def _load_keys(self) -> None:
        data = self._get(self.metadata().jwks_uri, "jwks")
        keys = data.get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JWKS_KEYS:
            raise OidcUnavailable("jwks must contain between 1 and 20 keys")
        loaded: dict[str, Any] = {}
        duplicates: set[str] = set()
        for entry in keys:
            if not isinstance(entry, dict) or entry.get("kty") != "RSA" or not isinstance(entry.get("kid"), str):
                continue
            if entry.get("use", "sig") != "sig" or entry.get("alg", ALGORITHM) != ALGORITHM:
                continue
            kid = entry["kid"]
            if kid in loaded:
                duplicates.add(kid)
                continue
            try:
                loaded[kid] = RSAAlgorithm.from_jwk(json.dumps(entry))
            except (ValueError, TypeError, KeyError, jwt.InvalidKeyError):
                continue
        for kid in duplicates:  # an ambiguous key ID selects nothing
            loaded.pop(kid, None)
        self._keys, self._keys_loaded_at = loaded, self.clock.now()

    def _key(self, kid: str) -> Any:
        now = self.clock.now()
        stale = self._keys_loaded_at is None or now - self._keys_loaded_at >= self.settings.jwks_cache_ttl
        if stale:
            self._load_keys()
        elif kid not in self._keys and (self._last_refresh_attempt is None or
                                        now - self._last_refresh_attempt >= self.settings.jwks_min_refresh_interval):
            self._last_refresh_attempt = now  # rotation: refresh once for an unknown kid, rate-limited
            self._load_keys()
        if kid not in self._keys:
            raise OidcError("no unique signing key for the token's kid")
        return self._keys[kid]

    # -- authorization request and code exchange -----------------------------------------------------------

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        query = urlencode({"response_type": "code", "client_id": self.settings.oidc_client_id,
                           "redirect_uri": self.settings.redirect_uri, "scope": "openid profile email",
                           "state": state, "nonce": nonce, "code_challenge": code_challenge,
                           "code_challenge_method": "S256"})
        return f"{self.metadata().authorization_endpoint}?{query}"

    def exchange_code(self, code: str, code_verifier: str) -> str:
        """Exchange the code (with the PKCE verifier) and return the raw ID token."""
        data = self._request(
            "POST", self.metadata().token_endpoint, "token",
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": self.settings.redirect_uri,
                  "code_verifier": code_verifier},
            auth=(self.settings.oidc_client_id, self.settings.oidc_client_secret.get_secret_value()))
        id_token = data.get("id_token")
        if not isinstance(id_token, str) or not 1 <= len(id_token) <= 16384:
            raise OidcError("the token response has no usable id_token")
        return id_token

    # -- ID token validation -------------------------------------------------------------------------------

    def validate_id_token(self, id_token: str, *, nonce_sha256: str) -> IdTokenClaims:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            raise OidcError("the ID token is malformed") from None
        if header.get("alg") != ALGORITHM:
            raise OidcError("the ID token algorithm is not allowed")
        if any(name in header for name in REFUSED_HEADERS):
            raise OidcError("the ID token carries a refused header")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OidcError("the ID token has no key ID")
        key = self._key(kid)
        metadata = self.metadata()
        try:
            payload: Mapping[str, Any] = jwt.decode(
                id_token, key=key, algorithms=[ALGORITHM], audience=self.settings.oidc_client_id,
                issuer=metadata.issuer,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"], "verify_signature": True,
                         "verify_aud": True, "verify_iss": True,
                         # Time claims are verified below against the injected Clock (see module docstring).
                         "verify_exp": False, "verify_iat": False, "verify_nbf": False})
        except jwt.PyJWTError as exc:
            raise OidcError(f"the ID token failed validation ({type(exc).__name__})") from None
        try:
            claims = IdTokenClaims.model_validate(dict(payload))
        except ValidationError:
            raise OidcError("the ID token claims have the wrong types") from None
        audiences = [claims.aud] if isinstance(claims.aud, str) else claims.aud
        if audiences != [self.settings.oidc_client_id]:
            raise OidcError("the ID token is also intended for other audiences")
        if claims.azp is not None and claims.azp != self.settings.oidc_client_id:
            raise OidcError("the ID token azp is not this client")
        now = self.clock.now()
        skew = self.settings.clock_skew

        def at(value: int) -> datetime:
            try:
                return datetime.fromtimestamp(value, UTC)
            except (OverflowError, OSError, ValueError):  # defensive: the claim bounds already exclude these
                raise OidcError("the ID token time claims are out of range") from None

        if at(claims.exp) <= now - skew:
            raise OidcError("the ID token has expired")
        if at(claims.iat) > now + skew:
            raise OidcError("the ID token was issued in the future")
        if now - at(claims.iat) > timedelta(hours=24) + skew:
            raise OidcError("the ID token is too old")
        if claims.nbf is not None and at(claims.nbf) > now + skew:
            raise OidcError("the ID token is not yet valid")
        if not tokens.matches(claims.nonce, nonce_sha256):
            raise OidcError("the ID token nonce does not match this login")
        return claims
