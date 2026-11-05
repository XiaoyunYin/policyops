"""OIDC relying-party validation against a fake issuer: every negative case is a real signed token (offline)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import httpx
import jwt
from pydantic import SecretStr
import pytest

from policyops.auth import tokens
from policyops.auth.oidc import OidcClient, OidcError, OidcUnavailable
from policyops.settings import AuthSettings
from policyops_contracts.clock import FixedClock
from policyops_testing.oidc_fake import CLIENT_ID, CLIENT_SECRET, DROP, ISSUER, FakeIssuer, new_key, public_jwk


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
NONCE = "nonce-" + "n" * 30
SETTINGS = AuthSettings(env="test", public_origin="http://127.0.0.1:8000", oidc_issuer=ISSUER,
                        oidc_client_id=CLIENT_ID, oidc_client_secret=SecretStr(CLIENT_SECRET))


def client(fake: FakeIssuer, clock: FixedClock | None = None) -> OidcClient:
    return OidcClient(SETTINGS, clock or FixedClock(NOW), transport=fake.transport)


@pytest.fixture
def fake() -> FakeIssuer:
    return FakeIssuer(redirect_uri=SETTINGS.redirect_uri)


def token(fake: FakeIssuer, *, headers: dict[str, Any] | None = None, key: Any = None, algorithm: str = "RS256",
          **claims: Any) -> str:
    return jwt.encode(fake.claims_for(NONCE, NOW, **claims), key or fake.key, algorithm=algorithm,
                      headers={"kid": fake.kid, **(headers or {})})


def validate(rp: OidcClient, raw: str) -> Any:
    return rp.validate_id_token(raw, nonce_sha256=tokens.digest(NONCE))


def test_a_valid_token_is_accepted(fake: FakeIssuer) -> None:
    claims = validate(client(fake), token(fake))
    assert (claims.iss, claims.sub, claims.aud, claims.nonce) == (ISSUER, "fake-subject-alice", CLIENT_ID, NONCE)


@pytest.mark.parametrize("missing", ["iss", "sub", "aud", "exp", "iat", "nonce"])
def test_every_required_claim_is_required(fake: FakeIssuer, missing: str) -> None:
    with pytest.raises(OidcError):
        validate(client(fake), token(fake, **{missing: DROP}))


@pytest.mark.parametrize("claims", [
    {"iss": ISSUER + "/"}, {"iss": "http://127.0.0.1:1/other"}, {"aud": "someone-else"},
    {"aud": [CLIENT_ID, "someone-else"]}, {"aud": [CLIENT_ID], "azp": "someone-else"}, {"sub": ""},
    {"sub": 42}, {"exp": "1767268800"}, {"iat": 1.5}, {"aud": 7}, {"nonce": "other-nonce"}, {"exp": True},
], ids=["iss-slash", "iss-other", "aud-other", "aud-extra", "azp-other", "sub-empty", "sub-int", "exp-string",
        "iat-float", "aud-int", "nonce", "exp-bool"])
def test_wrong_issuer_audience_types_and_nonce_are_refused(fake: FakeIssuer, claims: dict[str, Any]) -> None:
    with pytest.raises(OidcError):
        validate(client(fake), token(fake, **claims))


def test_single_audience_list_and_matching_azp_are_accepted(fake: FakeIssuer) -> None:
    assert validate(client(fake), token(fake, aud=[CLIENT_ID], azp=CLIENT_ID)).azp == CLIENT_ID


def stamp(delta: timedelta) -> int:
    return int((NOW + delta).timestamp())


SKEW = SETTINGS.clock_skew


@pytest.mark.parametrize(("claims", "accepted"), [
    ({"exp": stamp(-SKEW + timedelta(seconds=1))}, True),   # within skew after expiry
    ({"exp": stamp(-SKEW)}, False),                          # exactly expired beyond skew
    ({"iat": stamp(SKEW)}, True), ({"iat": stamp(SKEW + timedelta(seconds=1))}, False),  # issued in the future
    ({"nbf": stamp(SKEW)}, True), ({"nbf": stamp(SKEW + timedelta(seconds=1))}, False),  # not yet valid
    ({"iat": stamp(-timedelta(hours=24) - SKEW), "exp": stamp(timedelta(minutes=5))}, True),
    ({"iat": stamp(-timedelta(hours=24) - SKEW - timedelta(seconds=1)), "exp": stamp(timedelta(minutes=5))}, False),
])
def test_time_claims_use_the_injected_clock_at_their_boundaries(fake: FakeIssuer, claims: dict[str, Any],
                                                                accepted: bool) -> None:
    raw = token(fake, **claims)
    if accepted:
        validate(client(fake), raw)
    else:
        with pytest.raises(OidcError):
            validate(client(fake), raw)


@pytest.mark.parametrize("claim", ["exp", "iat", "nbf"])
@pytest.mark.parametrize("value", [10**50, -(10**50), 253_402_300_800, -1, 2**63])
def test_out_of_range_numeric_dates_are_refused_safely(fake: FakeIssuer, claim: str, value: int) -> None:
    changes: dict[str, Any] = {claim: value}
    raw = token(fake, **changes)  # a genuinely signed token carrying the huge or negative date
    with pytest.raises(OidcError) as raised:
        validate(client(fake), raw)
    assert str(value) not in str(raised.value)


def test_algorithm_confusion_and_unsigned_tokens_are_refused(fake: FakeIssuer) -> None:
    public_pem = fake.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
    # Classic confusion: an HS256 token "signed" with the public key bytes as the HMAC secret (built by hand,
    # since PyJWT refuses to create one).
    signing_input = b".".join(jwt.utils.base64url_encode(json.dumps(part).encode()) for part in (
        {"alg": "HS256", "typ": "JWT", "kid": fake.kid}, fake.claims_for(NONCE, NOW)))
    mac = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    hs256 = (signing_input + b"." + jwt.utils.base64url_encode(mac)).decode()
    unsigned = jwt.encode(fake.claims_for(NONCE, NOW), None, algorithm="none",  # type: ignore[arg-type]
                          headers={"kid": fake.kid})
    es_key = ec.generate_private_key(ec.SECP256R1())
    es256 = jwt.encode(fake.claims_for(NONCE, NOW), es_key, algorithm="ES256", headers={"kid": fake.kid})
    for raw in (hs256, unsigned, es256, "not.a.jwt", ""):
        with pytest.raises(OidcError):
            validate(client(fake), raw)


@pytest.mark.parametrize("header", [{"jku": "http://attacker.invalid/keys"}, {"x5u": "http://attacker.invalid/c"},
                                    {"jwk": {"kty": "RSA"}}, {"x5c": ["MIIB"]}, {"crit": ["exp"]}])
def test_key_location_and_critical_headers_are_refused_not_followed(fake: FakeIssuer,
                                                                    header: dict[str, Any]) -> None:
    rp = client(fake)
    with pytest.raises(OidcError):  # "refused header" (PyJWT itself rejects a crit header as malformed)
        validate(rp, token(fake, headers=header))
    assert not any("attacker" in request for request in fake.requests)


def test_signature_and_key_identity(fake: FakeIssuer) -> None:
    rp = client(fake)
    other = new_key()
    with pytest.raises(OidcError):  # same kid, wrong key
        validate(rp, token(fake, key=other))
    with pytest.raises(OidcError, match="no unique signing key"):
        validate(rp, token(fake, headers={"kid": "unknown"}))
    raw = token(fake)
    tampered = raw[:-4] + ("AAAA" if not raw.endswith("AAAA") else "BBBB")
    with pytest.raises(OidcError):
        validate(rp, tampered)
    without_kid = jwt.encode(fake.claims_for(NONCE, NOW), fake.key, algorithm="RS256")
    with pytest.raises(OidcError, match="no key ID"):
        validate(rp, without_kid)


def test_ambiguous_or_unusable_jwks_keys_select_nothing(fake: FakeIssuer) -> None:
    fake.jwks_keys = [public_jwk(fake.key, fake.kid), public_jwk(new_key(), fake.kid)]  # duplicate kid
    with pytest.raises(OidcError, match="no unique signing key"):
        validate(client(fake), token(fake))
    fake.jwks_keys = [public_jwk(fake.key, fake.kid, use="enc")]
    with pytest.raises(OidcError, match="no unique signing key"):
        validate(client(fake), token(fake))
    fake.jwks_keys = [public_jwk(fake.key, fake.kid, alg="RS512")]
    with pytest.raises(OidcError, match="no unique signing key"):
        validate(client(fake), token(fake))
    fake.jwks_keys = []
    with pytest.raises(OidcError, match="between 1 and 20"):
        validate(client(fake), token(fake))


def test_key_rotation_refreshes_once_and_is_rate_limited(fake: FakeIssuer) -> None:
    clock = FixedClock(NOW)
    rp = client(fake, clock)
    validate(rp, token(fake))
    rotated = new_key()
    fake.jwks_keys = [public_jwk(fake.key, fake.kid), public_jwk(rotated, "key-2")]
    validate(rp, token(fake, key=rotated, headers={"kid": "key-2"}))  # unknown kid: one refresh
    fetches = fake.requests.count("GET /fake/keys")
    for _ in range(3):  # further unknown kids within the interval do not refetch
        with pytest.raises(OidcError):
            validate(rp, token(fake, headers={"kid": "key-3"}))
    assert fake.requests.count("GET /fake/keys") == fetches == 2
    clock.advance(SETTINGS.jwks_min_refresh_interval)
    with pytest.raises(OidcError):
        validate(rp, token(fake, headers={"kid": "key-3"}))
    assert fake.requests.count("GET /fake/keys") == 3


@pytest.mark.parametrize("overrides", [
    {"issuer": ISSUER + "/"}, {"token_endpoint": "http://127.0.0.1:2/fake/token"},
    {"jwks_uri": "https://127.0.0.1:1/fake/keys"}, {"authorization_endpoint": "http://evil.invalid/auth"},
    {"code_challenge_methods_supported": ["plain"]}, {"id_token_signing_alg_values_supported": ["HS256"]},
    {"jwks_uri": f"{ISSUER}/keys?x=1"},
])
def test_discovery_must_match_the_issuer_and_its_origin(fake: FakeIssuer, overrides: dict[str, Any]) -> None:
    fake.discovery_overrides = overrides
    with pytest.raises(OidcError):
        client(fake).metadata()


def test_transport_does_not_follow_redirects_or_accept_oversized_or_non_json(fake: FakeIssuer) -> None:
    def redirecting(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://evil.invalid/"})

    rp = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(redirecting))
    with pytest.raises(OidcError, match="HTTP 302"):
        rp.metadata()
    assert rp._http.trust_env is False and rp._http.follow_redirects is False
    big = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=b'{"a": "' + b"x" * SETTINGS.max_response_bytes + b'"}')))
    with pytest.raises(OidcError, match="too large"):
        big.metadata()
    text = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"<html>")))
    with pytest.raises(OidcError, match="not usable JSON"):
        text.metadata()


def test_authorization_url_and_code_exchange(fake: FakeIssuer) -> None:
    rp = client(fake)
    verifier, challenge = tokens.pkce_pair()
    url = rp.authorization_url(state="state-1", nonce=NONCE, code_challenge=challenge)
    assert url.startswith(f"{ISSUER}/auth?") and "code_challenge_method=S256" in url
    assert "redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2Fapi%2Fv1%2Fauth%2Fcallback" in url
    code, state = fake.issue_code(url, NOW)
    assert state == "state-1"
    with pytest.raises(OidcError, match="HTTP 400"):  # wrong PKCE verifier
        rp.exchange_code(code, tokens.pkce_pair()[0])
    code, _ = fake.issue_code(url, NOW, code="code-2")
    raw = rp.exchange_code(code, verifier)
    assert validate(rp, raw).sub == "fake-subject-alice"
    with pytest.raises(OidcError, match="HTTP 400"):  # the code is single use
        rp.exchange_code(code, verifier)


def test_responses_are_size_bounded_while_streaming(fake: FakeIssuer) -> None:
    consumed: list[int] = []

    def endless() -> Iterator[bytes]:
        while True:
            consumed.append(1)
            yield b" " * 4096

    rp = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=endless())))
    with pytest.raises(OidcError, match="too large"):
        rp.metadata()
    assert len(consumed) == SETTINGS.max_response_bytes // 4096 + 1  # stopped at the cap, not at exhaustion
    declared = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"content-length": str(10**9)}, content=b"{}")))
    with pytest.raises(OidcError, match="too large"):
        declared.metadata()


def test_a_trickled_response_cannot_outlast_the_call_deadline(fake: FakeIssuer,
                                                              monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter(range(10**6))
    monkeypatch.setattr("policyops.auth.oidc.time.monotonic", lambda: float(next(ticks)))  # 1 s per call

    def trickle() -> Iterator[bytes]:
        while True:
            yield b" "

    rp = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=trickle())))
    with pytest.raises(OidcError, match="took too long"):
        rp.metadata()


# -- C2 regressions (review findings F2/F3 on pre1) ------------------------------------------------------------

def test_compressed_responses_are_refused_before_decoding(fake: FakeIssuer) -> None:
    """F2: a 4 KiB gzip body expanding to 4 MiB must not be decoded at all (the cap bounds raw bytes)."""
    import gzip
    import tracemalloc

    bomb = gzip.compress(b" " * (4 * 1024 * 1024))
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        # Streamed content, as from a network: a bytes body would be decoded by httpx inside this handler.
        return httpx.Response(200, headers={"content-encoding": "gzip"}, content=iter([bomb]))

    rp = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(handler))
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        with pytest.raises(OidcUnavailable, match="unsupported content encoding"):
            rp.metadata()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024, peak  # far below the 4 MiB the body would decode to
    assert seen[0].headers["accept-encoding"] == "identity"


@pytest.mark.parametrize("overrides", [
    {"code_challenge_methods_supported": 7}, {"code_challenge_methods_supported": "S256"},
    {"code_challenge_methods_supported": [7, "S256"]}, {"id_token_signing_alg_values_supported": "RS256"},
    {"id_token_signing_alg_values_supported": [None]}, {"jwks_uri": "http://127.0.0.1:abc/fake/keys"},
    {"jwks_uri": "http://127.0.0.1:99999/fake/keys"}, {"authorization_endpoint": f"{ISSUER}/auth#fragment"},
    {"token_endpoint": "http://user@127.0.0.1:1/fake/token"}, {"token_endpoint": 12},
    {"jwks_uri": ISSUER + "/" + "k" * 2000}, {"authorization_endpoint": None},
], ids=["pkce-int", "pkce-str", "pkce-mixed", "alg-str", "alg-null", "port-text", "port-range", "fragment",
        "userinfo", "endpoint-int", "endpoint-long", "endpoint-null"])
def test_malformed_discovery_is_a_safe_unavailable_error(fake: FakeIssuer, overrides: dict[str, Any]) -> None:
    """F3: malformed provider metadata never escapes as TypeError/ValueError or yields an unusable endpoint."""
    fake.discovery_overrides = overrides
    with pytest.raises(OidcUnavailable):
        client(fake).metadata()


@pytest.mark.parametrize("body", [b"[" * 200_000, b"\xff\xfe{}", b"[]", b"null"],
                         ids=["deep-nesting", "invalid-utf8", "array", "null"])
def test_unusable_json_bodies_are_safe_errors(body: bytes) -> None:
    rp = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=body)))
    with pytest.raises(OidcUnavailable):
        rp.metadata()


def test_server_failures_are_unavailable_but_refused_grants_are_not(fake: FakeIssuer) -> None:
    rp = client(fake)
    verifier, challenge = tokens.pkce_pair()
    url = rp.authorization_url(state="s", nonce=NONCE, code_challenge=challenge)
    for status in (500, 503, 429, 408):
        fake.status_override["token"] = status
        with pytest.raises(OidcUnavailable):
            rp.exchange_code("code", verifier)
    del fake.status_override["token"]
    with pytest.raises(OidcError) as refused:  # 400 invalid_grant: a refusal, not an outage
        rp.exchange_code("unknown-code", verifier)
    assert not isinstance(refused.value, OidcUnavailable)
    assert url


@pytest.mark.parametrize(("header", "outcome"), [
    ("9" * 5000, "too large"), ("0" * 5000 + "12", None), ("000123", None), (str(SETTINGS.max_response_bytes), None),
    (str(SETTINGS.max_response_bytes + 1), "too large"), ("12a", "invalid Content-Length"),
    ("²", "invalid Content-Length"), ("-1", "invalid Content-Length"), (" ", "invalid Content-Length"),
], ids=["5000-digits", "leading-zeros-long", "leading-zeros", "at-limit", "over-limit", "letters", "unicode-digit",
        "negative", "blank"])
def test_declared_content_length_is_bounded_before_conversion(fake: FakeIssuer, header: str,
                                                             outcome: str | None) -> None:
    """F3 residual: a huge digit string must not reach int() (Python's integer-string limit would raise
    ValueError past the safe boundary); malformed values are an unusable response."""
    discovery = json.dumps(fake.discovery()).encode()
    rp = OidcClient(SETTINGS, FixedClock(NOW), transport=httpx.MockTransport(
        # Raw header bytes, as a network peer could send them (httpx refuses non-ASCII header text).
        lambda request: httpx.Response(200, headers=[(b"content-length", header.encode("latin-1"))],
                                       content=iter([discovery]))))
    if outcome is None:
        assert rp.metadata().issuer == ISSUER
    else:
        with pytest.raises(OidcUnavailable, match=outcome):
            rp.metadata()
