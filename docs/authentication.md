# Authentication and authorization

This page describes the implementation in `packages/policyops/src/policyops/{settings.py,auth/,api/auth.py}` and its tests. The real-issuer path was exercised only on Windows Docker Desktop: the pinned Dex image together with pinned PostgreSQL, via `pytest -m postgres`. Linux hosts, hosted CI, macOS and real browsers have not been exercised.

## Flow

The application is an OpenID Connect relying party using the authorization code flow with PKCE (S256) through the backend. Tokens never reach the browser; only opaque cookies do.

1. **`GET /api/v1/auth/login?return_to=/path`.**
   - Generates a browser-binding token, `state`, `nonce` and a PKCE verifier.
   - Stores a single-use login request in `identity.login_requests`. The request holds digests of the binding token, state and nonce, the verifier, a plain same-origin return path and an expiry of at most 10 minutes.
   - Sets the binding cookie (`HttpOnly`, `SameSite=Lax`) and redirects to the issuer's discovered authorization endpoint.
2. **`GET /api/v1/auth/callback`.**
   - **Consume.** In one short transaction the login request matching both `state` and the binding cookie is consumed. Missing, expired, reused or foreign state is refused (401) before anything else.
   - **Exchange.** The code is then exchanged over HTTP with no database transaction open, using client authentication and the verifier.
   - **Validate.** The ID token is validated, as described under Validation.
   - **Create the session.** A second short transaction finds or creates the principal and creates a new session. Identity is issuer plus subject, never email, and a new principal gets no membership.
   - **Respond.** The response clears the binding cookie, sets the session and CSRF cookies, and redirects (303) to the stored path.
3. **`GET /api/v1/me`.** Returns the principal, its workspaces (from active memberships), the selected workspace and the current roles.
4. **`POST /api/v1/auth/workspace {"workspace_id": ...}`.** Selects a workspace in which the principal has an active membership; anything else gives 404. Selection rotates the session: a new cookie and CSRF token are issued and the old session is revoked. It never extends the original absolute expiry.
5. **`POST /api/v1/auth/logout`.** Revokes the session and clears the cookies.

**Headers.** Every `/api/v1` response, errors included, is `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

**Error envelope.** Errors use the standard envelope with a safe message and a stable `rule_id`. They never echo codes, tokens, issuer output or request input:
- authentication and authorization: `auth.login_state`, `auth.id_token`, `auth.csrf`, `auth.origin`, `auth.membership`, `auth.role`;
- `auth.provider` (503): the identity provider is unreachable, times out, returns a server error, or serves unusable discovery, JWKS or token responses. A login that cannot start stores nothing; at the callback the login request stays consumed;
- `api.http_404`, `api.http_405` and other framework HTTP errors, keeping framework headers such as `Allow`;
- `api.invalid_input` (422): request validation;
- `api.internal` (500): anything unexpected.

## Validation

**Discovery.**
- The discovered `issuer` must equal the configured issuer exactly.
- The issuer must advertise RS256 ID tokens and PKCE S256.
- The algorithm and PKCE lists must be lists of strings.
- The authorization, token and JWKS endpoints must be absolute URLs on the issuer's exact origin: same scheme, host and a valid port, with no credentials, query or fragment.

**Transport.** Uses httpx with:
- fixed timeouts, no redirects and no environment proxies or `.netrc` (`trust_env=False`);
- `Accept-Encoding: identity`. A compressed response is refused before any byte is decoded, so the size limit bounds the raw bytes actually read;
- streamed bodies, refused as soon as they exceed the configured size. A larger declared `Content-Length` is refused before reading; it is checked by digit count before conversion, and a malformed one is refused as unusable;
- unusable JSON (invalid, non-object, invalid UTF-8 or pathologically nested) refused as a provider error;
- an overall per-call deadline checked between chunks. The worst case is that deadline plus one read timeout.

**ID token.**
- **Algorithm.** The token's `alg` must be RS256. That comes from configuration, not from the token, so `none`, HS256 (including HMAC with the public key) and ES256 are refused.
- **Headers.** `jku`, `x5u`, `jwk`, `x5c` and `crit` are refused and never followed.
- **Key.** `kid` must select exactly one RSA signing key from the JWKS. Duplicate key IDs select nothing. An unknown `kid` triggers one rate-limited JWKS refresh, to handle rotation.
- **Signature, issuer and audience.** PyJWT 2.15.1 checks the signature, `iss` and `aud`.
- **Required claims and types.** `iss`, `sub`, `aud`, `exp`, `iat` and `nonce` are required with strict types. Numeric dates must be in the range 0 to the end of year 9999.
- **Audience.** `aud` must be exactly the client ID, with no extra audiences. `azp`, if present, must be the client ID.
- **Time.** `exp`, `iat` and `nbf` are checked against the injected clock with a bounded skew (default 60 s, at most 5 min). `iat` may not be more than 24 h old. PyJWT's own time checks are disabled for this reason only, because it reads the system clock, and the replacements are tested at their boundaries.
- **Nonce.** It must match the digest stored for this login.

## Sessions and CSRF

**Sessions.**
- The session cookie is an opaque 256-bit random token; only its SHA-256 is stored.
- Sessions expire absolutely (default 8 h, at most 24 h) and after idle time (default 30 min, at least 1 min). Activity refreshes `last_seen_at` once it is older than a quarter of the idle window, capped at 60 s, so continuous use keeps even the shortest window open.
- Every login creates a new session, so a planted cookie never becomes one.
- Logout and rotation revoke sessions in the database.

**CSRF.** Each session has a CSRF token whose digest is stored. The browser receives the raw token in its own non-`HttpOnly`, `SameSite=Strict` cookie. Every unsafe request (POST, PUT, PATCH, DELETE), including logout and workspace selection, must:
- send an `Origin` exactly equal to the configured public origin. Without an `Origin`, a `Referer` on that origin is required;
- send the token in `X-CSRF-Token`. It is compared with the session's stored digest, so this is a synchronizer token, not a bare double-submit cookie.

CORS is not enabled.

**Cookie names and the Secure flag.**

| Public origin | Session / CSRF / login cookies | `Secure` |
|---|---|---|
| `https://…` (always in `deployment`) | `__Host-policyops_session`, `__Host-policyops_csrf`, `__Host-policyops_login` (`Path=/`, no `Domain`) | yes |
| `http://127.0.0.1:…` or `http://[::1]:…` (`local`/`test` only) | `policyops_session_local`, `policyops_csrf_local`, `policyops_login_local` | no |

Plain HTTP is accepted only for an explicit loopback IP, because browsers do not uniformly treat a loopback IP over HTTP as a secure context. Deployment mode requires an HTTPS origin and issuer.

## Authorization

`policyops.api.auth.require_action(Action.X)` is the reusable FastAPI dependency. For every request it:
- resolves the session (401 if missing, expired, idle or revoked) and requires a selected workspace (403 `auth.workspace_required`);
- reads the principal's **current active memberships** in that workspace through the auth role, so a revoked membership is refused at once (403 `auth.membership`);
- checks `PERMISSIONS` (403 `auth.role`).

Admin is not implicitly a reviewer, and roles never come from token claims.

Routes then reach tenant data only through `workspace_transaction(app_engine, workspace_id)`. Another workspace's resource is therefore not found (404) by row-level security, not merely by a check in code.

The narrow admin surface is:
- `GET /api/v1/workspace/members`;
- `POST /api/v1/workspace/members/{id}/revoke` (`MANAGE_MEMBERSHIP`, CSRF).

Case and message APIs belong to T08.

## Database roles and wiring

- **Auth role.** `policyops_auth_runtime` alone reads and writes login requests, principals and sessions (revision `0003` adds `identity.login_requests` and the session `last_seen_at`/`csrf_sha256` columns).
- **App role.** `policyops_app_runtime` reads memberships only within the selected workspace.
- **Startup check.** `policyops.api.app.build_auth_runtime` verifies each engine's actual database user, meaning the user psycopg authenticated as (`info.user`), with `session_user` and `current_user` equal to it. A superuser login masked by `SET ROLE` or `SET SESSION AUTHORIZATION` is therefore refused. So is the migrator, and any role with superuser, BYPASSRLS, CREATEROLE, CREATEDB, replication, inheritance or memberships. Every later pool checkout rechecks the driver identity, including connections opened before verification.
- **Test hooks.** It refuses an injected OIDC transport (the test-only fake issuer) unless `POLICYOPS_ENV=test`.

## Configuration and logging

`policyops.settings.AuthSettings` reads only explicit `POLICYOPS_*` environment variables: `ENV`, `PUBLIC_ORIGIN`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`, plus bounded TTL and limit overrides. No `.env` file is read. The secret is a `SecretStr` and never appears in reprs or validation errors.

uvicorn's access log would record the callback's `code` and `state` in the request target. Run uvicorn with `policyops.api.logging.LOG_CONFIG`, which installs `RedactQueryFilter`, so query strings appear as `?[REDACTED]`.

## Local identity provider

`infra/dex/config.yaml.tmpl` configures the pinned Dex v2.46.1 with:
- memory storage, RS256 signing and the code flow only;
- one static client, `policyops-local`, with an exact redirect URI;
- fictional users `alice`, `bob` and `carol` at `@example.invalid`.

The client secret and passwords are files under `/work/secrets`, generated per run and never committed. The image's own gomplate turns them into the rendered config, with bcrypt for the passwords.

The test fixture (`tests/support/policyops_testing/dex.py`) runs Dex the same way as the PostgreSQL fixture:
- an owned, labelled container with a read-only root filesystem and Docker logging off;
- one bind mount under `$POLICYOPS_TEMP_DIR`, with the log in `log/dex.log`;
- a 127.0.0.1-only port registered with the network guard;
- the secret files and the rendered config deleted as soon as Dex is ready. On any failure, from secret generation onwards, they are deleted and their absence confirmed; otherwise `CleanupUncertain` is raised with the primary error kept.

Memberships for fictional users are provisioned explicitly by trusted code, never derived from tokens.

## Tests

- **Offline** (`tests/unit/test_auth_*.py`):
  - signed negative tokens for every validation rule;
  - JWKS rotation and its rate limit;
  - discovery and transport bounds;
  - settings safety per environment, test-hook refusal and log redaction.
- **Real PostgreSQL with the fake issuer** (`tests/integration/test_auth_flow.py`):
  - login state binding, single use and expiry; failed tokens creating nothing; return-path validation;
  - idle/absolute expiry and rotation; fixation;
  - the CSRF and origin matrix;
  - the full Role × Action matrix through the real dependencies;
  - immediate membership revocation and cross-workspace 404s;
  - digest-only storage and runtime-role refusal.
- **Real PostgreSQL with the owned Dex** (`tests/integration/test_auth_dex.py`):
  - the login form and the code exchange; RS256 validation against Dex's JWKS;
  - Dex rejecting a wrong PKCE verifier and a replayed code;
  - distinct principals per subject;
  - no secrets, codes or state in the Dex log.

## Limits

- **Not exercised.** Real browsers (cookie-prefix and `SameSite` behavior was exercised through the test client's cookie jar), Linux-host Docker, hosted CI and deployment behind HTTPS.
- **Logging.** Access-log redaction applies only when uvicorn uses the provided log configuration. The reverse proxy (T38) must redact too.
- **Trusted auth role.** The auth runtime role is a trusted boundary: it can read all identity rows. A compromised application process with its credentials can choose any workspace scope; row-level security protects against query mistakes, not against that.
- **Out of scope.** There is no rate limiting of login attempts (the issuer handles password attempts), no refresh tokens and no single logout at the issuer.
