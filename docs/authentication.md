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
- resolves the session (401 if missing, expired, idle or revoked) and, on unsafe methods, checks Origin and CSRF (403);
- reads the required expected-context headers and compares them with that session (below): 400/422 for missing or malformed headers, 409 `context_changed` for a mismatch;
- requires a selected workspace (403 `auth.workspace_required`, now reachable only through a forged call path, because an unselected session already fails the comparison);
- reads the principal's **current active memberships** in that workspace through the auth role, so a revoked membership is refused at once (403 `auth.membership`);
- checks `PERMISSIONS` (403 `auth.role`).

Admin is not implicitly a reviewer, and roles never come from token claims.

Routes then reach tenant data only through `workspace_transaction(app_engine, workspace_id)`. Another workspace's resource is therefore not found (404) by row-level security, not merely by a check in code.

### Expected context (cross-tab binding)

The session cookie is shared by every tab of a browser profile. When another tab selects a workspace (which rotates the session) or signs in as someone else, an older tab would otherwise send its next request with the new cookie and see, or change, data it does not show. Every workspace-bound operation (all 16 routes of the case, message, run, event-stream, proposal-review and membership surfaces) therefore requires two headers copied from the tab's own `GET /me`:

- `PolicyOps-Expected-Principal: <principal_id>` and `PolicyOps-Expected-Workspace: <workspace_id>`, each exactly one field holding one canonical lowercase UUID (36 characters). A missing header is 400 `api.expected_principal_required` or `api.expected_workspace_required`; a repeated, uppercase, braced, URN, unhyphenated, padded, comma-joined or otherwise malformed value is 422 `api.invalid_expected_principal` or `api.invalid_expected_workspace`. The principal header is checked first. Values are never echoed.
- `AuthService.authorize(session, action, *, expected: ExpectedContext)` takes the parsed pair as a required, frozen typed value (no default and no `None`), and compares it with the same frozen `SessionContext` that becomes `Authorized`, before any membership, role or resource read. A different principal is 409 `context_changed` with `rule_id` `auth.principal_changed`; a different (or no) selected workspace is 409 `context_changed` with `auth.workspace_changed`. `retryable` is false.
- The headers are refusal preconditions, never selectors or authority: they cannot choose, switch or widen a workspace. A header naming another or a nonexistent workspace gets the same 409 envelope, with no lookup. Once the context matches, a foreign or missing resource is still 404 and a missing role still 403.
- Order: body limit (400/413), malformed JSON or undecodable body (FastAPI reads the body first: 422/400), session (401), Origin and CSRF on unsafe methods (403), the headers (400/422), the comparison (409), workspace/membership/role (403), then route-level headers, body validation and the service. So a 409 for a context change precedes a 403 for a role the principal lacks in the other workspace.
- Meaning of the 409: the requested operation was not applied. No case, message, run, job, outbox, idempotency, audit, decision, membership or budget effect happens. Resolving the session is still authentication work and may refresh the session's own `last_seen_at`.
- `/me`, `POST /auth/workspace`, `POST /auth/logout`, the login flow and liveness are global and take no expected-context headers.
- The event stream (`GET /runs/{id}/events`) has no exemption. Its authorization runs in a worker thread: the session is resolved first, then the headers are parsed and compared, and the parsed context is kept for every later poll (the stream never re-reads a browser cookie jar). A session that no longer matches ends the stream. A native `EventSource` cannot send these headers, so a browser client must read the stream with `fetch` streaming (T26). The existing abandonment limits of cancelled worker queries are unchanged.
- A request whose session resolved before another tab rotated it completes in its original context, which is the context it was composed for. A request that carries the old cookie after the rotation is 401.

The web client sends both headers only from a scope that also holds the session generation and abort signal. It treats only an explicit 409 with code `context_changed` as a context change (other 409s, such as `stale_version` or `conflict`, stay with the resource). It then clears the view, reloads `/me` once, returns to `/cases` and shows a generic notice. A 401 also reloads `/me` once, because the request may have carried a cookie another tab replaced. Automatic recovery is bounded per incident. The reconciliation records the generation it produced and the resource (the `useSessionResource` key) whose refusal started it. While that generation is current, only a success of that same resource closes the incident; a sibling resource that succeeds does not, since the refused resource has not recovered. Any further 401 or `context_changed` in that generation stops instead of reloading again: a 401 ends the session, and a `context_changed` shows the refusal with an explicit **Reload session** action. That action only reloads `/me` under a new generation (which may again recover once); it replays no earlier write, and the refusal's `retryable: false` still keeps the refused request from being offered for retry. Any other transition (boot, a workspace switch, sign-out, a changed context found on refresh) also starts a new generation, so the next refusal is a new incident. With an endpoint that keeps refusing, each view therefore costs at most one automatic `/me` reload; it does not loop. The client never replays an earlier write automatically, least of all in a new context; resource reads are simply loaded again for the regenerated view. A future write whose outcome is unknown (timeout, network loss, cancellation) must keep its original principal, workspace and operation ID for reconciliation, which is different from a definitive `context_changed` refusal. Future drafts must be cleared, not shown in the new context.

The narrow admin surface is:
- `GET /api/v1/workspace/members`;
- `POST /api/v1/workspace/members/{id}/revoke` (`MANAGE_MEMBERSHIP`, CSRF).

The case and message routes use the same dependencies ([architecture](architecture.md#case-and-message-api)). Their writes recheck the principal's current role inside the write transaction after each lock wait, so a membership revoked while a request waited is refused before any change or replay.

## Database roles and wiring

- **Auth role.** `policyops_auth_runtime` alone reads and writes login requests, principals and sessions (revision `0003` adds `identity.login_requests` and the session `last_seen_at`/`csrf_sha256` columns).
- **App role.** `policyops_app_runtime` reads memberships only within the selected workspace.
- **Startup check.** `policyops.api.app.build_auth_runtime` verifies each engine's actual database user, meaning the user psycopg authenticated as (`info.user`), with `session_user` and `current_user` equal to it. A superuser login masked by `SET ROLE` or `SET SESSION AUTHORIZATION` is therefore refused. So is the migrator, and any role with superuser, BYPASSRLS, CREATEROLE, CREATEDB, replication, inheritance or memberships. Every later pool checkout rechecks the driver identity, including connections opened before verification.
- **Test hooks.** It refuses an injected OIDC transport (the test-only fake issuer) unless `POLICYOPS_ENV=test`.

## Configuration and logging

`policyops.settings.AuthSettings` reads only explicit `POLICYOPS_*` environment variables: `ENV`, `PUBLIC_ORIGIN`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`, plus bounded TTL and limit overrides. No `.env` file is read. The secret is a `SecretStr` and never appears in reprs or validation errors.

Run uvicorn with `policyops.api.logging.LOG_CONFIG` to use the allowlisted JSON formatter. It omits raw request targets and query strings, including callback `code` and `state`. The legacy `RedactQueryFilter` also remains installed as defense in depth.

## Serving the API (local)

`python -m policyops.api.serve [--host 127.0.0.1] [--port 8000]` serves the API from explicit environment variables. `--host` must be a loopback IP; public binding and TLS termination are deployment wiring (T38).

- **Configuration.** `AuthSettings` (above) plus `policyops.settings.DatabaseSettings`, which reads `POLICYOPS_DB_HOST` (one IP or DNS name), `POLICYOPS_DB_PORT` (5432), `POLICYOPS_DB_NAME`, `POLICYOPS_DB_SSLMODE` (`verify-full` by default; `disable` only for a loopback IP host; deployment requires `verify-full`), `POLICYOPS_DB_CONNECT_TIMEOUT_SECONDS` (2 to 30, default 5), `POLICYOPS_DB_POOL_SIZE` (1 to 50, default 5) and two separate secrets: `POLICYOPS_DB_AUTH_PASSWORD` for `policyops_auth_runtime` and `POLICYOPS_DB_APP_PASSWORD` for `policyops_app_runtime`. The login roles are fixed. No URL, `POLICYOPS_DATABASE_URL` or migrator/superuser credential is read. `POLICYOPS_ENV=test` is refused.
- **Connections.** Each engine goes through `make_engine` with a connection factory that passes the endpoint, role, password, `sslmode`, `require_auth=scram-sha-256`, connect timeout, session options and application name (`policyops-api-auth`, `policyops-api-app`) explicitly. `hostaddr` is pinned for an IP host. The server refuses to start if `PGSERVICE` or `PGHOSTADDR` is set. Other `PG*` variables are not read for parameters passed explicitly; libpq can still read TLS file locations (`PGSSLROOTCERT` and similar), which are trusted operator configuration.
- **Lifetime.** `create_served_app()` validates configuration and opens nothing. The ASGI lifespan startup opens both engines, runs the startup role check above for each, opens the OIDC HTTP client and builds `create_app(auth)`. If any step fails, the release of everything already opened is attempted, every release even when one fails. A failed release is reported by exception type (a startup note, `lifespan.shutdown.failed` or stderr) and is not a verified release. The original error stays the one raised (startup wraps it as the cause), and a release failure, an interruption included, never replaces it; with no error in flight, a release interruption propagates after the remaining releases. Shutdown releases the same resources. Each engine release closes its connection gate before disposing the pool, refusing connection calls that begin afterwards. An already-started connection attempt or a connection still held by a request that outlived uvicorn's 10-second graceful shutdown is not forcibly stopped. That window bounds in-flight requests only: releases run afterwards, synchronously, and closing pooled connections is unbounded socket I/O. Without lifespan, every request is answered 503 `server.not_started`. Nothing creates or changes schema, roles or data: bootstrap and migrations stay separate, privileged steps.
- **Clocks.** Authentication uses the process UTC `SystemClock`. Leases, runs and events use the database clock (`DatabaseLeaseClock`) through the default runs runtime. The two are not interchangeable. No investigation runtime is installed, so starting a run answers 503 `runtime.unconfigured`.
- **Errors and logging.** Startup/configuration diagnostics name variables, stages and fixed error categories without configured values or driver text. Runtime logs use one JSON formatter for access, uvicorn and library messages. It drops free-form message/argument text, exception messages, traceback frames, raw paths and arbitrary extras, including already formatted library strings. Only fixed event codes, typed allowlisted fields, exception type names and active trace/span IDs are emitted. Other hosts must install the same logging configuration. See the README Observability section for opt-in spans/metrics and the export limits.

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
- **Served API** (`tests/unit/test_serve.py` offline; `tests/integration/test_serve.py` on real PostgreSQL with the owned Dex):
  - import without settings or connections; missing and malformed configuration with synthetic canary values that never appear in messages, tracebacks or logs;
  - the pinned connection parameters; release of everything acquired when startup fails at each stage, including when releases fail;
  - the actual factory and lifespan under uvicorn on an ephemeral loopback port, over real HTTP with an httpx client. The client signs in through Dex, selects a workspace with Origin and CSRF, then lists and creates a case with the expected-context headers. Starting a run gives the real 503, and `pg_stat_activity` shows the two runtime logins. No login remains after shutdown;
  - a privileged app role, a wrong password and a closed port are refused with nothing left open. `python -m policyops.api.serve` exits 3 with a sanitized message.

## Limits

- **Not exercised.** Real browsers (cookie-prefix and `SameSite` behavior was exercised through the test client's cookie jar), Linux-host Docker, hosted CI and deployment behind HTTPS.
- **Logging.** Access-log redaction applies only when uvicorn uses the provided log configuration. The reverse proxy (T38) must redact too.
- **Cross-tab binding evidence.** It comes from the test client against real PostgreSQL as the runtime roles, plus jsdom with a fake API. The SSE cases also use loopback HTTP with uvicorn running in the test process and a fake identity provider. Native `EventSource` cannot supply the required headers.
- **Served API evidence.** The environment-configured app ran under uvicorn inside the test process, with an httpx client standing in for a browser and signing in through the owned Dex. The separately launched command was exercised only on its startup-failure path. No real browser was used.
- **Trusted auth role.** The auth runtime role is a trusted boundary: it can read all identity rows. A compromised application process with its credentials can choose any workspace scope; row-level security protects against query mistakes, not against that.
- **Out of scope.** There is no rate limiting of login attempts (the issuer handles password attempts), no refresh tokens and no single logout at the issuer.
