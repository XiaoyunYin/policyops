"""Random tokens, their stored digests and PKCE values."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


TOKEN_BYTES = 32


def new_token() -> str:
    """An opaque, URL-safe random token (256 bits)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest(token: str) -> str:
    """SHA-256 hex of a token; only digests are stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def matches(token: str | None, stored_digest: str) -> bool:
    """Constant-time comparison of a presented token with a stored digest."""
    return token is not None and hmac.compare_digest(digest(token), stored_digest)


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge) per RFC 7636: 43 characters of URL-safe randomness."""
    verifier = secrets.token_urlsafe(TOKEN_BYTES)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return verifier, challenge
