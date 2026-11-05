"""A test-only fake OIDC issuer served through httpx.MockTransport (no sockets, no network).

It signs ID tokens with an RSA key generated per test, serves discovery, JWKS and a token endpoint that checks the
client credentials, the redirect URI, the single-use code and the PKCE S256 verifier. Tests choose the claims and
headers of each token, so every negative case is a real signed token rather than a mocked validator.
Application code accepts this transport only when `POLICYOPS_ENV=test` (`policyops.api.app.build_auth_runtime`).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm


ISSUER = "http://127.0.0.1:1/fake"
CLIENT_ID = "policyops-test"
CLIENT_SECRET = "fake-client-secret-" + "0" * 16


def new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(key: rsa.RSAPrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    return {**jwk, "kid": kid, "use": "sig", "alg": "RS256", **extra}


@dataclass
class PendingCode:
    claims: dict[str, Any]
    challenge: str | None
    headers: dict[str, Any]
    key: Any
    algorithm: str


@dataclass
class FakeIssuer:
    redirect_uri: str
    issuer: str = ISSUER
    key: rsa.RSAPrivateKey = field(default_factory=new_key)
    kid: str = "key-1"
    discovery_overrides: dict[str, Any] = field(default_factory=dict)
    jwks_keys: list[dict[str, Any]] | None = None
    codes: dict[str, PendingCode] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)
    status_override: dict[str, int] = field(default_factory=dict)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def discovery(self) -> dict[str, Any]:
        return {"issuer": self.issuer, "authorization_endpoint": f"{self.issuer}/auth",
                "token_endpoint": f"{self.issuer}/token", "jwks_uri": f"{self.issuer}/keys",
                "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"],
                **self.discovery_overrides}

    def keys(self) -> list[dict[str, Any]]:
        return self.jwks_keys if self.jwks_keys is not None else [public_jwk(self.key, self.kid)]

    def claims_for(self, nonce_value: str, now: datetime, **changes: Any) -> dict[str, Any]:
        stamp = int(now.timestamp())
        base = {"iss": self.issuer, "sub": "fake-subject-alice", "aud": CLIENT_ID, "exp": stamp + 600, "iat": stamp,
                "nonce": nonce_value, "name": "Alice Example"}
        base.update(changes)
        return {name: value for name, value in base.items() if value is not _DROP}

    def issue_code(self, authorization_url: str, now: datetime, *, code: str = "code-1",
                   headers: dict[str, Any] | None = None, key: Any = None, algorithm: str = "RS256",
                   **claim_changes: Any) -> tuple[str, str]:
        """Simulate the user's login at the issuer: returns (code, state) for the callback."""
        query = {name: values[0] for name, values in parse_qs(urlsplit(authorization_url).query).items()}
        claims = self.claims_for(query["nonce"], now, **claim_changes)
        self.codes[code] = PendingCode(claims=claims, challenge=query.get("code_challenge"),
                                       headers={"kid": self.kid, **(headers or {})}, key=key or self.key,
                                       algorithm=algorithm)
        return code, query["state"]

    def sign(self, pending: PendingCode) -> str:
        return jwt.encode(pending.claims, pending.key, algorithm=pending.algorithm, headers=pending.headers)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(f"{request.method} {path}")
        name = path.rsplit("/", 1)[-1]
        if name in self.status_override:
            return httpx.Response(self.status_override[name], json={})
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.discovery())
        if path.endswith("/keys"):
            return httpx.Response(200, json={"keys": self.keys()})
        if path.endswith("/token") and request.method == "POST":
            return self._token(request)
        return httpx.Response(404, json={})

    def _token(self, request: httpx.Request) -> httpx.Response:
        expected = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        if request.headers.get("authorization") != f"Basic {expected}":
            return httpx.Response(401, json={"error": "invalid_client"})
        form = {name: values[0] for name, values in parse_qs(request.content.decode()).items()}
        pending = self.codes.pop(form.get("code", ""), None)  # single use
        if pending is None or form.get("redirect_uri") != self.redirect_uri:
            return httpx.Response(400, json={"error": "invalid_grant"})
        verifier = form.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if pending.challenge != challenge:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(200, json={"access_token": "unused", "token_type": "bearer",
                                         "id_token": self.sign(pending)})


class _Drop:
    def __repr__(self) -> str:
        return "DROP"


_DROP: Any = _Drop()
DROP = _DROP  # pass as a claim value to omit that claim
