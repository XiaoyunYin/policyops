# Local Compose operations

For the optional public AWS profile, Terraform commands, public fictional credentials,
TLS, reset and rollback procedures, see [deployment](deployment.md). That profile is
offline preparation pending independent review and live drills; this page describes
the accepted local stack.

This stack is a fictional, loopback-only showcase. It needs Docker Engine with Compose v2.24+, Linux amd64
containers, network access **during builds**, and Python 3.12 with the frozen app dependencies for secret generation
(`cryptography` is already in that lock). PostgreSQL, retail, Dex, worker and one-shots use only an internal Docker
network without internet egress. Caddy also joins a non-internal `edge` network so Docker Desktop can deliver the
published host loopback port; API shares Caddy's network namespace and therefore its potential internet egress.
This is a local reachability trade-off, not egress confinement for Caddy/API. External deployment hardening is required before any
non-loopback exposure; see the [residual risks](security.md#residual-risks-and-explicit-exclusions).
The stack has been built and exercised locally; offline policy tests alone do not verify Docker behavior.
External hosting requires the separate deployment/security work described in [security.md](security.md).

## Start and stop

From the repository root in PowerShell, using the existing external development environment:

```powershell
$env:POLICYOPS_TEMP_DIR = 'D:\path\outside\the\checkout'
$env:TEMP = "$env:POLICYOPS_TEMP_DIR/tmp/t38-compose"
$env:TMP = $env:TEMP
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:POLICYOPS_PYTHON = "$env:POLICYOPS_TEMP_DIR/venvs/app/Scripts/python.exe"
$env:COMPOSE_PROJECT_NAME = 'policyops-demo'
$env:POLICYOPS_RUN_ID = 'demo-choose-a-fresh-unique-id'
$env:POLICYOPS_SECRETS_DIR = "$env:POLICYOPS_TEMP_DIR/compose/$env:POLICYOPS_RUN_ID/secrets"
$env:POLICYOPS_HTTP_PORT = '8080'
New-Item -ItemType Directory -Force $env:TEMP | Out-Null
& $env:POLICYOPS_PYTHON -B scripts/compose_secrets.py
python -B scripts/check_build_context.py --context .
docker compose build
docker compose up -d
docker compose ps --all
```

On Linux, use the equivalent exported variables, `venvs/app/bin/python`, and set `TMPDIR` too. Bootstrap and
migration containers should exit 0; all six runtime services should become healthy. Open
<http://127.0.0.1:8080>. Keep the port consistent for the volume's lifetime: it is part of the seeded identity
issuer. `localhost` is a different origin. Choose another port with `POLICYOPS_HTTP_PORT` **before** seeding.

```powershell
docker compose stop                 # keep database and externally stored secrets
docker compose up -d                # resume with the same configuration and secrets
docker compose down                # remove this project's containers/network, retain its database volume
# Destructive demo reset; only for the explicitly selected disposable project:
docker compose down --volumes --remove-orphans
```

Do not use `down --volumes` on a project whose evidence or data must be retained. Delete the exact external secret
directory only after every container using it is gone; inventory its `owner.json` first. Do not delete the shared
temporary root. Changing password files does not rotate a live database; use a stopped, explicit credential
rotation procedure or create fresh secrets with a fresh disposable project/volume. Secret generation refuses an
existing directory, including a partial run. PostgreSQL's local certificate expires after 30 days; regenerate it
as an explicit stopped maintenance operation, preserving the database role passwords.

## Topology and credentials

| Service | Identity and purpose | Inputs/storage |
|---|---|---|
| `caddy` | UID/GID 10001, static web and same-origin `/api`/`dex` proxy | Only published port: `127.0.0.1:8080`; no secrets |
| `api` | UID/GID 10001, existing ASGI API plus dependency readiness | Auth/app runtime passwords and OIDC client secret |
| `worker` | UID/GID 10001, review jobs, execution reconciliation and event outbox | App runtime/discovery passwords and retail HMAC key |
| `retail` | UID/GID 10001, simulator HTTP on internal port 8001 | Retail runtime password and HMAC key; audited fixture |
| `postgres` | UID/GID 999, pgvector/PostgreSQL 17 | Named `pgdata` volume; superuser password and local TLS pair |
| `dex` | UID/GID 10001, in-memory fictional identity provider on internal port 5556 | OIDC client secret and three fictional passwords |

All root filesystems are read-only; writable temporary paths are tmpfs. Linux capabilities are dropped, and the
web build strips Caddy's file capability and fails if `getcap` reports any remaining capability. PostgreSQL
owns its persistent volume; the other services have none. Caddy and API share a network namespace: API listens
only on its loopback port 8000, and its OIDC HTTP client reaches `http://127.0.0.1:8080/dex` through Caddy exactly
as a browser does. This preserves issuer/origin checks without a custom OIDC transport, extra published Dex port,
host networking or relaxing local HTTP settings. Restart/recreate API after recreating Caddy's namespace.
SSE is forwarded with immediate flushing. Caddy's process health is separate from API dependency readiness.

Secrets come only from explicit Compose file-secret mounts in `POLICYOPS_SECRETS_DIR`, outside the repository
and inside `POLICYOPS_TEMP_DIR`. No credentials are build arguments or Compose environment values. File mounts
are readable to numeric container UIDs; the host parent directory is mode 0700 (Windows: inheritance removed and
current-user ACL). Docker administrators can read container secrets. PostgreSQL copies its TLS key to a mode-0600
tmpfs file because local Compose bind-secret permissions vary. API loads its three files into its own process
environment for the existing settings loader; Docker's configured environment contains no values. Do not inspect
or publish process environments, rendered Dex configuration, database dumps or secrets.

App connections use SCRAM and TLS `require` on this isolated local network (encryption, without certificate name
verification). This is not the `verify-full` deployment profile. Retail uses the same TLS connection settings.
PostgreSQL's Unix socket allows local administrative access inside its container; no database port is published.

## Bootstrap, migrations and demo fixtures

The startup dependency chain is explicit:

1. Healthy PostgreSQL → `bootstrap-app` (superuser only here) provisions the app's five roles, database and vector.
2. `migrate-app` uses **only** `policyops_app_migrator`, runs the existing app Alembic chain to `0016`, and verifies it.
3. `bootstrap-retail` uses the retail image and superuser to provision the two retail roles and schema.
4. `migrate-retail` uses **only** `retail_migrator`, runs the existing retail chain to `r0002`, and verifies it.
5. `seed-demo` uses auth/app runtime logins to create the fictional workspace, users and case. API waits for it,
   healthy retail, and healthy Caddy; worker waits for API readiness.

The existing migration modules own all schema changes; Compose introduces no migration or runtime DDL. App schemas
and the app version table are owned by `policyops_app_migrator`; retail schema/tables/version are owned by
`retail_migrator`. Runtime roles have no migration passwords, DDL, superuser or BYPASSRLS. The smoke checks their
actual login identity and cross-schema SELECT denial, rather than relying on configured role names.

`infra/compose/demo.json` contains stable IDs for the browser scenario: workspace `...3801`, case `...3802`, and the upstream
fictional customer `james_johnson_9321` (retail order `#W1006327` is a deterministic fixture candidate).
Alice (`alice@example.invalid`) is an analyst, Bob is a reviewer and Carol is an auditor; their passwords are the
separate `alice`, `bob`, `carol` files. Read your selected password locally without recording it in logs. Dex's
OIDC subjects encode the configured static password userID and `local` connector ID; the seed uses that same
Dex protobuf/base64url subject rather than the raw UUID historically named `subject` in `demo.json`.
There is no test-auth bypass. **Use a fresh volume for browser acceptance:** an earlier demo volume with raw-UUID
principal subjects is not repaired by idempotent seeding. Do not change an existing seed's IDs/issuer
without a fresh volume or an explicit data migration. Seed creation is idempotent, not a repair/overwrite tool.
The binding ID `retail-demo-9999` denotes this synthetic service fixture, not an upstream benchmark task;
the stack selects or loads no benchmark task, split, hidden criterion or reference action.

Base demo seeding creates no preapproved action, consent or receipt. It does not configure a model-driven investigation:
starting a fresh run returns the existing `runtime.unconfigured` response. The browser scenario creates a
fresh deterministic run/proposal using the real gateway/services, initializes the corresponding simulator case,
and obtains customer consent and staff approval through the UI. The worker's real review/ledger composition then executes and
reconciles that case. No test-only runtime catalog or fake success is used in the deployed services.

The app image uses root `uv.lock`; retail uses the separate evaluator lock and full pinned `tau2[knowledge]`.
Exact uv 0.13.7 is installed in the **build stage only**, from its release archive with SHA-256
`c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83` (the previously acquired amd64 archive).
This avoids adding a registry image pin without verified provenance; builds currently target linux/amd64.
Both Python installs use `--frozen --no-dev`; final images inherit no uv/Git/download cache. Web build tools are
development dependencies confined to the Node stage; runtime contains only scanned static output and notices.
`npm ci --ignore-scripts` uses locked platform packages without package lifecycle execution. The bundle guard
must pass in an intermediate stage before Caddy can copy its output.

Retail stages exactly the hash-verified upstream retail database and LICENSE, reduces the runtime source manifest
to those two entries, and rejects JSON/YAML/data payloads in the installed tau2 package. No task/reference/split
payload or provider key is supplied. The full dependency set includes the accepted pinned litellm advisory risk;
no litellm CLI/proxy/model is launched or port exposed. Image layer/package/license inspection remains a separate redistribution
check; see [third-party notices](../THIRD_PARTY_NOTICES.md).

## Health and shutdown

`/api/v1/health/live` is process liveness. `/api/v1/health/ready` returns 200 only when both actual runtime DB logins
and retail `/healthz` succeed; a stopped simulator gives 503 with `checks.retail=false`. No exception or connection
text is returned. Worker health is a recent completed-loop heartbeat; a failed/stalled batch ages it out.
API/retail use Uvicorn's SIGTERM/lifespan handling with a 10-second request-drain window. Worker SIGTERM stops
discovery after the in-flight bounded batch and releases engines; the Compose grace period is 30 seconds
(PostgreSQL: 60). This is not a universal cancellation guarantee: database socket cleanup and in-flight adapters
have their own limits. If Docker ultimately kills a process, the durable lease/ledger remains the recovery source.
The deployment smoke records normal API/worker stop exit codes; the recovery driver exercises abrupt kills.

## Consistent backup and separate-database restore

Keep both schemas, identity, approvals, jobs, usage, checkpoints, state **and receipts** together. Stop all writers
before taking a demonstration recovery point; leave PostgreSQL running. A single full-database custom dump gives
one PostgreSQL snapshot of all schemas. Store it privately outside the checkout. Example for the selected project:

```powershell
docker compose stop worker api retail
docker compose exec -T postgres pg_dump -U postgres -d policyops -Fc -f /tmp/policyops-backup.dump
$pg = docker compose ps -q postgres
docker cp "${pg}:/tmp/policyops-backup.dump" "$env:POLICYOPS_TEMP_DIR/backups/policyops-backup.dump"
docker compose exec -T postgres rm /tmp/policyops-backup.dump
```

Create the external backup directory first and hash/retain the dump plus source/image/migration versions and
secret-directory identity in your private recovery record. Use the actual database name if changed. Do not use
PowerShell text redirection for binary dumps. `pg_dump` does not include cluster roles/passwords: retain the secret
directory securely and provision the same roles before restoring into a **new cluster**. Preserve a matching
database/retail backup; do not restore only a state table or discard the operation receipts.

Restore into a new database on the same cluster, with the original writers still stopped. For example:

```powershell
'CREATE DATABASE policyops_restore_a OWNER policyops_app_migrator TEMPLATE template0;' | docker compose exec -T postgres psql -X -U postgres -v ON_ERROR_STOP=1 -d postgres
'REVOKE ALL ON DATABASE policyops_restore_a FROM PUBLIC; GRANT CONNECT ON DATABASE policyops_restore_a TO policyops_app_runtime, policyops_auth_runtime, policyops_worker_discovery, policyops_eval_runtime, retail_migrator, retail_runtime;' | docker compose exec -T postgres psql -X -U postgres -v ON_ERROR_STOP=1 -d postgres
docker cp "$env:POLICYOPS_TEMP_DIR/backups/policyops-backup.dump" "${pg}:/tmp/policyops-restore.dump"
docker compose exec -T postgres pg_restore -U postgres --exit-on-error -d policyops_restore_a /tmp/policyops-restore.dump
docker compose exec -T postgres rm /tmp/policyops-restore.dump
docker compose run --rm --no-deps -e POLICYOPS_DB_NAME=policyops_restore_a --entrypoint python bootstrap-app -B infra/compose/verify.py migrations
docker compose run --rm --no-deps -e POLICYOPS_DB_NAME=policyops_restore_a --entrypoint python api -B infra/compose/verify.py api
docker compose run --rm --no-deps -e POLICYOPS_DB_NAME=policyops_restore_a --entrypoint python retail -B infra/compose/verify.py retail
```

Do not use `--no-owner`, `--no-acl`, `--clean` against the source, or a lossy downgrade as restore substitutes.
Compare exact migration versions, table owners, role isolation, app execution operation IDs and matching retail
receipts/case versions before accepting the restored target. Do not run both source and restored workers.
Set `POLICYOPS_DATABASE=policyops_restore_a`, then recreate `retail`, `api`, `worker` with
`docker compose up -d --no-deps --force-recreate retail api worker`. Keep the original database untouched until
the new target has passed the restore assertions. The automated drill exercised this
stopped-writer same-cluster procedure locally; offline static tests alone would not prove it. A restore rolls demo state back in time; it cannot roll back a real external business sink.

## Crash with unresolved writes

Preserve the database, secrets, stable operation IDs and simulator receipts. Restart the simulator before the
worker. Inspect the durable execution state; `unknown`/`dispatched` is not success or proof of noncommit.
The existing dispatcher claims after lease expiry and performs authenticated lookup/reconciliation under the
same operation ID; current policy/consent/approval/resource versions are rechecked before any authorized dispatch.
An absent operation may be fenced; expired or stale authority must not be renewed implicitly. Do not click or
script a new proposal/operation to replace an ambiguous write. A row that exhausts reconciliation stays visibly
unresolved and requires investigation. Restore both sides to a consistent isolated target before recovery tests;
never pair an old app ledger with newer simulator state and then replay writes.

## Deployment smoke

```powershell
# Generates its own unique project, secrets directory and image tags. Always attempts owned down -v cleanup.
python -B scripts/compose_smoke.py --port 8080
```

Set `POLICYOPS_PYTHON` as above when the invoking Python lacks app dependencies. The JSON report is under
`POLICYOPS_TEMP_DIR/compose/<run-id>/report.json`; it includes command exits, migrations/owners, actual runtime
logins, cross-schema denial, effective UIDs, exact loopback bindings, host access to Caddy, network membership,
retail external DNS/TCP denial, simulator outage/recovery and shutdown results. Every failing command retains
up to the last 60 output lines and 16,000 characters, with generated secret values, private keys and DSNs redacted;
successful command output is omitted. Review this bounded diagnostic output before sharing it. Failed startup still enters cleanup, which verifies
project/run/owner labels before `down --volumes`; uncertain ownership fails closed. Secret inputs are removed
after successful container cleanup; run-tagged images remain for layer/package inspection, then an operator
may remove those exact images after retaining evidence. Supply `DOCKER_CONFIG` for the task-scoped Docker context
if needed; the driver otherwise uses the external temporary root's `user-data/docker` location.

## Real-browser workbench acceptance

Use a fresh disposable stack started with the variables in **Start and stop**. Install the exact development
dependencies from `apps/web/package-lock.json` and provision that Playwright version's Chromium separately;
the application image needs neither Playwright nor a browser. The suite is separate from `npm test` (Vitest).

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = "$env:POLICYOPS_TEMP_DIR/tools/playwright-browsers"
$env:POLICYOPS_E2E_ORIGIN = "http://127.0.0.1:$env:POLICYOPS_HTTP_PORT"
$env:POLICYOPS_E2E_RUN = "browser-$env:POLICYOPS_RUN_ID"
# No Docker/browser needed for collection:
Push-Location apps/web
npx --offline playwright test --list
# The stack must now be healthy; retain its existing project/run/secrets variables:
npx --offline playwright test
Pop-Location
```

The first test initializes the real simulator and creates a fresh, authenticated deterministic run plus a
presented address-change proposal through runtime repositories, real lookup/facts and `ProposalService`.
It installs no model, fake provider response, receipt or authorization override. Alice signs in through Dex,
enters `yes` as an explicitly confirmed **staff-entered customer simulation**, and cannot approve it. Bob
signs in in an independent browser context, inspects consent/version/digest, confirms the exact decision,
and the ordinary worker performs the real simulator mutation. The outcome card must contain the operation ID
and SHA-256 of the actual simulator receipt, equal to the app ledger receipt. Carol is read-only; both Alice
and Carol's authenticated decision attempts must return typed `403 forbidden` / `auth.role` errors. All three
must see typed `404 not_found` for an actual case seeded in a foreign workspace.

The test observes `consent.recorded` and `execution.changed` frames in the browser's actual SSE fetch response
through Caddy (no HTTP mocks), checks DOM and console CSP violations, CSP/nosniff/frame/referrer headers, and
refuses actual source maps even if a missing `.map` URL returns the SPA's HTML fallback. A second test races
two independently signed-in Bob contexts with distinct decision reasons: exactly one 201 and one 409, one
execution and one simulator version increment. It is a same-principal race, not a claim about two reviewers.

Results and sanitized post-login traces are under `POLICYOPS_TEMP_DIR/tests/T38b/<POLICYOPS_E2E_RUN>/`.
Tracing starts after login; screenshots, DOM snapshots, sources and video are disabled. The sanitizer omits
all resource bodies, strips headers/cookies/storage/URL queries and known generated secrets, then removes
the raw ZIP even on parse failure. These limited traces support action/network timing, not full visual replay.
They remain private review artifacts. A failed scenario may leave an active proposal; inspect/reset that
disposable stack instead of blindly retrying with a new ambiguous operation.
The private reporter also removes generated credentials, session-header values and authentication URL queries
from console/result diagnostics and automatically generated error-context text.

## Automated kill/restart and separate-database restore drills

```powershell
# Pinned Node must be on PATH; POLICYOPS_PYTHON and browser/temp paths as above.
# This driver creates/builds its OWN unique project; it never uses the existing demo project.
& $env:POLICYOPS_PYTHON -B scripts/compose_drills.py --port 18080
```

Choose an unused loopback port. The driver uses the smoke driver's isolated environment, command exits,
bounded/redacted failure tails, labels/ownership checks and guarded `down --volumes` cleanup. It builds and
starts a fresh `policyops-t38b-<run-id>` project. JSON evidence is in
`POLICYOPS_TEMP_DIR/compose/<run-id>/report.json`; a failure still attempts cleanup and marks the report failed.

1. **Kill/restart:** real-browser Alice/Bob consent and approval run against a separate, explicit local drill
   worker entrypoint. The existing `ExecutionHooks.after_response` seam pauses for at most 120 seconds after
   a validated committed response. A marker identifies the operation. The driver verifies one simulator
   version increment and a remote receipt, kills that exact owned worker ID with SIGKILL, and verifies the
   app row is still `dispatched` with no local receipt. It recreates the **ordinary** worker, waits for the
   real 75-second lease (no clock/ledger edits), and requires `succeeded`, `resolved_by=lookup`, attempts=1,
   the original operation ID and identical retained remote/local receipt hashes, with no new effect.
2. **Restore:** after that completed operation, a second browser-authorized operation is killed at the same
   unresolved point. All app/simulator writers stop. `pg_dump -U postgres -Fc` takes one coherent full-database
   snapshot, preserving both migration-owned schemas, ACLs, RLS, approvals, jobs, state and receipts. The
   existing cluster roles/passwords remain; the driver creates a uniquely named **separate database** owned
   by `policyops_app_migrator`, revokes PUBLIC connect and grants the documented runtime/retail roles.
   `pg_restore -U postgres --exit-on-error` preserves original object owners and grants (no `--no-owner`,
   `--no-acl` or source cleanup). Before starting writers, row counts/hashes and normalized table/column/schema
   ACL, owner and policy hashes must match. Both migration versions/owners and actual runtime logins and
   cross-schema denials are rechecked. Runtime RLS probes require own-scope visibility, unscoped/foreign-tenant
   denial, foreign retail-case denial, and append-only receipt grants. Services are recreated against the
   restored DB only. Its unresolved write must recover by lookup with no resend; the prior completed operation
   must stay identical on another scheduler pass. The stopped source DB's protected rows/catalog must remain
   unchanged. Source and restored workers never run concurrently.

The normal runtime cannot select the pause hook by setting an environment variable: only the separate drill
entrypoint supplies it, and composition requires both explicit drill opt-in and the local environment. No
application migrations, provider calls or alternate auth mode are introduced.

The driver removes owned Compose resources, generated secrets, its override and inventoried nested tool caches.
It retains the private coherent dump and its hash, safe scenario identifiers, JSON report, sanitized browser
traces and run-tagged images for review. The dump includes identity/session and fictional case data: retain
privately, never commit/upload it. Inspect failures before retrying; uncertain cleanup is a failed assertion.
After review, remove only the exact retained run artifacts/images under the project's normal cleanup rules.

These drills cover one host and Docker Desktop/Linux amd64, a same-cluster separate database and a logical
backup with stopped writers. They do not prove PITR/WAL recovery, independent-cluster role bootstrap, physical
backup, host-loss recovery, every crash window, production TLS/egress, real commerce rollback or previous-image/
schema rollback. External deployment hardening remains required for external deployment.

## Verified locally

Local Docker Desktop/Linux amd64 execution verified deployment, migration ownership,
runtime logins, loopback publishing, retail egress denial, outage/recovery and shutdown.
Both Playwright flows passed on the real stack, including OIDC, proxy SSE, consent,
approval, receipt-backed execution and a same-reviewer two-context race. Kill-after-commit
reconciled by lookup without resend; the stopped-writer same-cluster separate-database
restore passed its selected data, grants, ownership, RLS and replay checks.
See [the evidence report](evaluation.md#recovery-and-e07-correctness) for scope and limits.
The default stack does not install model-driven investigation. The Compose stack and browser
flows are not part of hosted CI. External TLS deployment, host-loss recovery and broader
accessibility review remain unverified.

## Development setup

Prerequisites: Git, a Python 3.10+ interpreter to run the helper scripts, [uv](https://docs.astral.sh/uv/) 0.13.x (CI uses 0.13.7) and Node.js 26.13.0 (`.nvmrc`). uv installs the project's CPython 3.12 itself.

### Process-local paths

Every tool run goes through `scripts/devenv.py`. It requires `POLICYOPS_TEMP_DIR`, an absolute directory **outside** the checkout, and points temporary files, uv/npm/ruff/mypy caches, Python installs, both virtual environments, coverage, web build output and the per-user application data directory (`LOCALAPPDATA` on Windows, `XDG_DATA_HOME` on Linux, where Vitest keeps its API token file) beneath it for that command only. It also disables Python bytecode, `.env` auto-loading by upstream libraries (`PYTHON_DOTENV_DISABLED=1`) and litellm's import-time pricing download. No global settings are changed. Test suites refuse to run without this setup. On macOS, Vitest uses `~/Library/Application Support` regardless of these variables, so this containment is unsupported and unverified on macOS; it covers Windows and Linux.

The helper scripts and Git hooks below run without the wrapper, so set the temporary root and the process temp variables in that shell first (current session only):

```powershell
# PowerShell
$env:POLICYOPS_TEMP_DIR = 'D:\path\outside\checkout\policyops-tmp'
$env:TEMP = "$env:POLICYOPS_TEMP_DIR\tmp"; $env:TMP = $env:TEMP; $env:PYTHONDONTWRITEBYTECODE = '1'
New-Item -ItemType Directory -Force $env:TEMP | Out-Null
```

```sh
# POSIX shells
export POLICYOPS_TEMP_DIR=/path/outside/checkout/policyops-tmp
export TEMP="$POLICYOPS_TEMP_DIR/tmp" TMP="$POLICYOPS_TEMP_DIR/tmp" TMPDIR="$POLICYOPS_TEMP_DIR/tmp" PYTHONDONTWRITEBYTECODE=1
mkdir -p "$TMPDIR"
```

Installed web dependencies are the one directory kept in the checkout: `apps/web/node_modules/`, which Node module resolution needs inside the web project (ignored by Git and Docker). It holds only what `npm ci` installs; caches and scratch files that tools generate are routed to `POLICYOPS_TEMP_DIR` like everything else, and new files appearing below `node_modules/` fail the artifact check.

### Publication safeguards (before any commit)

```powershell
git config --local core.hooksPath .githooks
python -B scripts/gitleaks_gate.py install   # checksum-verified gitleaks 8.30.1 into $POLICYOPS_TEMP_DIR/tools
```

The pre-commit hook runs `scripts/check_publication.py` (index path/content guard) and then `scripts/gitleaks_gate.py staged`; the pre-push hook runs the guard over reachable history and then a gitleaks scan of every local ref. The guard runs first and must pass before the scanner runs; a failure of either step blocks the commit or push, and so does a missing or unverified scanner. Scans also require a valid `POLICYOPS_TEMP_DIR`, even when `POLICYOPS_GITLEAKS` names the scanner, and keep their scratch files and the scanner's TEMP/TMP under `$POLICYOPS_TEMP_DIR/tmp`, whatever the shell's TEMP/TMP say. The gate verifies the scanner binary against pinned SHA-256 values, uses the repository `.gitleaks.toml` (built-in rules plus a project rule, no allowlist), ignores inline `gitleaks:allow` comments, refuses to run when a root `.gitleaksignore` exists, and prints only redacted locations. Hooks find the scanner through `POLICYOPS_GITLEAKS`, then `$POLICYOPS_TEMP_DIR/tools/gitleaks-8.30.1/`, then `PATH`; commit and push from a shell set up as in [Process-local paths](#process-local-paths). These are safeguards against accidental publication, not a complete secret-detection system. New clones must enable hooks themselves.

### Python: application and evaluator

Two separate uv projects with separate locks:

| Project | Lock | Contents |
|---|---|---|
| Application (repository root workspace) | `uv.lock` | `packages/policyops` (FastAPI, SQLAlchemy/Alembic, psycopg, LangGraph) and `packages/policyops_contracts` |
| Evaluator / retail-simulator wrapper | `evals/uv.lock` | `tau2[knowledge]` at commit `19f13ea3f5fba8b4c4d272d1353590f29dc53062`, transport/persistence/migration libraries, `policyops_contracts` and local `policyops` for narrow evaluator composition |

`policyops_contracts` depends only on Pydantic. The evaluator also installs the local `policyops` package for composition of its minimal agent/ports, bounded providers, budgets and evaluation persistence; application code never imports tau2. Both locks only admit distributions published before the `exclude-newer` cutoff in their `pyproject.toml`.

```powershell
python -B scripts/devenv.py uv sync --frozen
python -B scripts/fetch_tokenizer_vocab.py    # once: the pinned cl100k_base vocabulary (hash-checked) for the tests
python -B scripts/devenv.py uv run --frozen ruff check .
python -B scripts/devenv.py uv run --frozen mypy
python -B scripts/devenv.py uv run --frozen pytest

python -B scripts/devenv.py uv sync --project evals --frozen
cd evals
python -B ../scripts/devenv.py uv run --frozen mypy
python -B ../scripts/devenv.py uv run --frozen pytest
```

The wrapper resolves the uv project the way uv does (`--directory`/`UV_WORKING_DIR` first, then `--project`/`UV_PROJECT` relative to it, otherwise the working directory), selects the matching application or evaluator virtual environment and pins `UV_PROJECT` to that project for the command and its children, so the two locks never install into the same environment. It refuses, before running anything, forms it cannot read reliably: uv options other than `--directory`/`--project` before the subcommand, `--project`/`--directory` after `run` or `tool` (write `uv --project evals run ...`, and put a child command's own options after `--`), `--active`, repeated options, and other uv projects inside the checkout.

### Web

```powershell
cd apps/web
python -B ../../scripts/devenv.py npm ci
python -B ../../scripts/devenv.py npm run lint
python -B ../../scripts/devenv.py npm run typecheck
python -B ../../scripts/devenv.py npm test
python -B ../../scripts/devenv.py npm run build    # output: $POLICYOPS_TEMP_DIR/build/web
```

There is no `dev` script. For local development, start the Vite dev server with `python -B ../../scripts/devenv.py npm exec -- vite --configLoader native`. It listens on `http://127.0.0.1:5173` (the port is strict, so it fails rather than moving) and forwards `/api/*` to the API at `http://127.0.0.1:8000`, so application API requests stay on the Vite origin. Sign-in redirects to the configured identity provider. `POLICYOPS_API_PROXY_TARGET` overrides the target; it must be an `http` origin on `127.0.0.1` or `[::1]`, and the config refuses anything else. The proxy leaves the browser's `Origin` header untouched and the API compares it exactly, so run the API with `POLICYOPS_PUBLIC_ORIGIN=http://127.0.0.1:5173` (and an identity-provider client registered for that origin). Node HTTP integration tests execute the actual typed client through this proxy to the configured API and real PostgreSQL, covering case creation, messages, replay, context refusal, stale versions and an unconfigured run. They use a minted fixture session and emulate Cookie, Origin and the readable CSRF cookie; this is not browser, SameSite, CORS-preflight or live identity-provider sign-in through the proxy evidence.

**Operator workflow.** In a selected workspace, the case queue filters by status and pages with a server cursor, up to 200 cases. Analysts, reviewers and admins can open cases, post internal notes or staff-entered demo customer replies, and start/cancel investigations; auditors read only. The server checks whether a customer reply confirms the exact presented action. Posting confirmation alone never establishes consent, and customer consent stays separate from staff approval.

The case workbench discovers workbench runs, supports direct run/evidence links and reload, and attaches a validated successful start to its returned run. Starting works with a configured runtime; an unconfigured server answers 503 `runtime.unconfigured`. The activity stream uses expected-context headers, ordered replay/recovery, a 500-entry memory bound and pages of at most 100 activities. Current typed review/stop/execution projections are stored separately from that ring; a truncated historical snapshot explicitly reports when projections are incomplete. Terminal EOF is revalidated; cancelled or uncertain executions continue read observation while visible. No investigation state or prose summary is interpreted as a successful business action.

Sources are recorded per run, without invented sentence attribution. The historical evidence pane verifies the exact UTF-8 quote hash and Unicode code-point offsets, displays bounded excerpts and inert source metadata, and never loads a live source URL. Exact proposal inspection shows its presentation, sealed resource versions and persisted consent. Approval controls and receipt-backed outcome cards are implemented. The real-browser
scenario is documented above; model-generated customer replies remain outside the release.

Writes freeze their identity and payload before sending. Start and messages use the displayed case version; cancellation uses a run-specific key without If-Match. Unconfirmed writes are never resent automatically: **Retry the same request** reuses the original key/body/version and remains bound to the same principal/workspace. A later authorization refusal does not resolve an earlier uncertain attempt. Message text is dropped on session/context changes. Reload reconstructs reads from the server and discards this tab's unresolved-write ledger. Component fault tests use fake APIs/byte streams; real-browser checks above have a separate, narrower scenario scope.

The API contract comes from the backend: `python -B scripts/devenv.py uv run --frozen python -B -m policyops.api.openapi --out packages/policyops/openapi/v1.json` exports the OpenAPI document (a unit test fails when it is stale), and `python -B scripts/devenv.py python -B scripts/api_types.py --write` (or `--check`) regenerates `apps/web/src/api/schema.d.ts` with the isolated, exactly locked generator in `scripts/api-types`. The generator is installed from its lock into a fresh directory under the temporary root on every run, so it needs registry access for that install; the generation itself runs with closed proxies.

From the repository root, `python -B -m unittest discover -s tests/web -v` runs `npm test` with a fresh temporary root and checks that Vitest's token file is created under it, not in the caller's user-data directory or `node_modules/` (existence only; the token is never read). It needs the installed web dependencies, so pytest does not collect it; the web CI job runs it.

### Test harness

Both pytest suites load `tests/support/policyops_testing` as a plugin. It provides:

- **Network guard.** Installed for the whole session, it refuses outbound TCP/UDP connections, DNS lookups (`getaddrinfo` accepts IP literals only) and unregistered loopback endpoints. It raises `NetworkBlocked`, which is not an `OSError`, so retry code cannot treat it as a transient error. A test reaches a local server only by registering its exact loopback IP and port with the `allow_endpoint` fixture; registrations are revoked at teardown.
  - Limitations: the guard patches Python's `socket` module in the test process only. Subprocesses, C extensions (libpq, so psycopg checks its targets with `require_registered`), `ctypes` and socket functions captured before the plugin loads are not intercepted.
  - It is not physical network isolation. Run under a network-less container for that.
- **Web guard.** In the web tests, `src/test/setup.ts` replaces `fetch`, `XMLHttpRequest`, `WebSocket` and `EventSource` with blockers as soon as it is evaluated, before any test file or application module is imported, and again before each test. Every attempt is recorded and fails the test, even if the code under test swallows the error. A test may `installFake()` one global; fakes are reset after each test. Node modules imported directly by a test are not covered.
- **Fake provider.** A scripted, deterministic model stand-in. Each expected request must match exactly; only a matching request advances the script. An unexpected or extra request fails, and teardown fails too, even if the code under test caught the error; so does a leftover script. Timeouts are raised, never retried, and carry the scripted billed usage (or `None` when unknown).
- **Clocks and seeds.** `policyops_contracts.clock` provides UTC-only `FixedClock` and `SteppingClock`. Every test reseeds `random` from `POLICYOPS_TEST_SEED`, default `20261104`, which the report header shows.
- **Evidence recorder.** Artifacts stay inside a root below `POLICYOPS_TEMP_DIR`. The root is checked before anything is created, and its directory chain is re-checked before every later operation, so a root replaced by a link or another directory is refused. Absolute paths, traversal, symlinks and junctions are refused, and files are written through fresh, exclusively created temporary files.
  - Command output is redacted before it is written, including the values of secret-named flags in that command's argv and of secret-named variables in an explicitly supplied `env`.
  - Every non-zero exit, timeout or failure to start adds a failure record.
  - Other artifacts that contain a known secret or credential pattern are refused rather than altered.
  - The manifest may not replace a recorded or existing file.
  - Metrics must be exact values traced to recorded artifacts.
  - Artifacts are re-hashed before the manifest (schema `evidence-manifest`) is written. The recorder refuses to write a manifest that still contains secret-like content.
  - Redaction covers registered values, argv/env-derived values and common key/token/password formats.
  - Explicitly known secrets must be at least 6 characters. Shorter ones are refused before anything runs or is written, because masking them would destroy ordinary output.
  - Unknown formats can pass. Pytest's own terminal output is not redacted.

PostgreSQL tests (and the real-issuer tests, which also need the pinned Dex image) carry the `postgres` marker and are deselected by default. They cover the harness fixture and the application database: bootstrap, migrations (empty, populated previous revision, failed revision, refused/allowed lossy downgrade), dump/restore into a separate database, the full role/privilege matrix, RLS and pool scope reset, tenant-composite keys, immutability, binding records and optimistic/dedupe races. The run tests cover two-worker contention, a killed worker process and its reclaim, lease expiry and expired-but-unreclaimed writes, the claim clock read after a synchronized lock wait, cancellation races, dead letters, outbox rollback/coalescing/starvation, the 0005 upgrade/refusals/downgrade and SSE over a real loopback server (positions, gaps, revocation mid-stream, lifetime). The budget ledger tests hold the contended scope row while competing reservations, dispatch grants, releases and settlements queue on it. They also cover overruns, cancellation, provider request ID reuse, tenancy, the eval study chain, role and grant refusals, and the 0006 upgrade and guarded downgrade. The case API tests drive the served app over HTTP: roles, tenancy and foreign IDs, same-key and separate-key races, original-response replay (also after a lost response), stale versions, revocation while waiting for a lock, rollback, body bounds, cursors, every response checked against the OpenAPI document and real bodies compiled against the generated TypeScript (this one needs Node and `npm ci` in `apps/web`). The restart self-test uses a separate owned server and leaves the shared test server untouched; it verifies a small fixture data set. Representative Compose shutdown and recovery validation is described above. The PostgreSQL tests need Docker with Linux containers and the pinned image, which they never pull themselves:

```powershell
docker pull pgvector/pgvector@sha256:01215e09bd4bd582d20230e025b6c971deeeffee49ceef1aae167e839cb62a7e
docker pull ghcr.io/dexidp/dex@sha256:65b72ca0f4b0bf6d4ada84ec21da8851782563404ac7b8f926923d27ceced9ab
python -B scripts/devenv.py uv run --frozen pytest -m postgres
cd evals
python -B ../scripts/devenv.py uv run --frozen pytest -m postgres   # the evaluator's retail-simulator database tests
```

Both projects' default selection excludes `postgres`; only these explicit runs start the container.

Each session starts its own container: labelled, read-only root filesystem, Docker logging off, TCP only, published on an ephemeral `127.0.0.1` port (never 5432). It does not touch any other container or port. The image's data volume is bind-mounted from a unique directory under `$POLICYOPS_TEMP_DIR/tests/postgres/`, so no anonymous volume is created; PGDATA and the server log live there.

The fixture creates two roles, a migrator and a runtime role, both without superuser, BYPASSRLS, CREATEDB or CREATEROLE. The tests check row-level security as the actual runtime role on a harness table; this is not application tenant isolation.

The persisted server log omits client ERROR/WARNING messages and failed statement text, while keeping startup, shutdown and FATAL lines. Do not put secrets in `RAISE LOG` text or connection startup options.

Tests connect only through `connect()`, which fixes host, hostaddr, port, user and libpq startup options to the owned server and accepts only its two database names. Ambient `PG*` variables such as `PGOPTIONS` therefore cannot change server logging on the bootstrap connection. `try_password()` exists for wrong-password tests. No other libpq parameter can be passed through.

Application-database tests register extra roles and databases explicitly (`register_role`, `register_database`; validated identifiers only, never connection strings) before `connect()` accepts them. `dump_and_restore` runs `pg_dump`/`pg_restore` inside the owned container as the superuser; the password reaches a 0600 pgpass file through stdin (never argv or logs), the file is removed afterwards and the dump stays in the bind mount under `$POLICYOPS_TEMP_DIR`.

Teardown removes the container by ID after checking its labels and fails if it is still there. The data and log directories are kept for diagnosis. On Linux, PGDATA belongs to the image's `postgres` user, so the invoking user may be unable to delete it.

### Continuous integration

`.github/workflows/ci.yml` runs on Ubuntu and Windows without secrets or model API keys: publication guard plus gitleaks over full history, both Python environments (frozen sync, lint, strict type checks, tests) and the web checks. Before the application tests, a setup step provisions the pinned cl100k_base vocabulary with `scripts/fetch_tokenizer_vocab.py` (one fixed URL, hash-checked, at most 2 MiB); the tests themselves never download. An Ubuntu-only job pulls the pinned PostgreSQL and Dex images by digest, runs the application's `pytest -m postgres` (database, authentication and real-issuer tests) and the evaluator's (retail simulator database tests), and then fails if an owned container or a new Docker volume remains; Windows runners have no Linux container engine. That job's timeout is 45 minutes (the local full application PostgreSQL run took about 23 minutes on Windows). Its temporary root is `$RUNNER_TEMP/policyops`, outside the checkout, and each job finishes with `scripts/check_repo_artifacts.py`, which lists every untracked or ignored path individually (including inside ignored directories) and fails on files left in the checkout. The web job records the tree `npm ci` installed (failing if the install wrote anywhere else) and afterwards fails on any new path, including new files under `node_modules/`; it also checks the generated API types against the OpenAPI document. The PostgreSQL job installs the web dependencies the same way, for the TypeScript response check. Actions are pinned to commit SHAs. Container image pins (PostgreSQL 17 with pgvector, Dex, Caddy) are recorded by digest in `infra/images.json`; Compose and Dockerfiles are implemented under `infra/` and at the repository root.

The application has no `policyops eval` command; evaluation is the separate
`policyops-evals preflight|run|report|taxonomy` CLI described in [evaluation](evaluation.md).
The API does not automatically load `.env`; export explicit configuration or use mounted
secrets. Hosted CI covers the workflow above; it does not build or run the Compose stack,
the real-browser flows or any paid evaluation.
