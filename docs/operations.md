# Local Compose operations

This stack is a fictional, loopback-only showcase. It needs Docker Engine with Compose v2.24+, Linux amd64
containers, network access **during builds**, and Python 3.12 with the frozen app dependencies for secret generation
(`cryptography` is already in that lock). PostgreSQL, retail, Dex, worker and one-shots use only an internal Docker
network without internet egress. Caddy also joins a non-internal `edge` network so Docker Desktop can deliver the
published host loopback port; API shares Caddy's network namespace and therefore its potential internet egress.
This is a local reachability trade-off, not egress confinement for Caddy/API. X04 is required before any
non-loopback exposure; see the [residual risks](security.md#residual-risks-and-explicit-exclusions).
The coordinator must build and exercise these definitions; offline policy tests alone do not verify Docker behavior.
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

`infra/compose/demo.json` contains stable IDs for Slice B: workspace `...3801`, case `...3802`, and the upstream
fictional customer `james_johnson_9321` (retail order `#W1006327` is a deterministic fixture candidate).
Alice (`alice@example.invalid`) is an analyst, Bob is a reviewer and Carol is an auditor; their passwords are the
separate `alice`, `bob`, `carol` files. Read your selected password locally without recording it in logs. Dex's
subjects match the seeded principals; there is no test-auth bypass. Do not change an existing seed's IDs/issuer
without a fresh volume or an explicit data migration. Seed creation is idempotent, not a repair/overwrite tool.
The binding ID `retail-demo-9999` denotes this synthetic service fixture, not an upstream benchmark task;
the stack selects or loads no benchmark task, split, hidden criterion or reference action.

Slice A seeds no preapproved action, consent or receipt. It does not configure a model-driven investigation:
starting a fresh run returns the existing `runtime.unconfigured` response. Slice B must create a fresh deterministic
run/proposal using the real gateway/services, initialize the corresponding simulator case, and obtain customer
consent and staff approval through the UI. The worker's real review/ledger composition can then execute and
reconcile that case. No test-only runtime catalog or fake success is used in the deployed services.

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
no litellm CLI/proxy/model is launched or port exposed. Image layer/package/license inspection remains a coordinator
check; see [third-party notices](../THIRD_PARTY_NOTICES.md).

## Health and shutdown

`/api/v1/health/live` is process liveness. `/api/v1/health/ready` returns 200 only when both actual runtime DB logins
and retail `/healthz` succeed; a stopped simulator gives 503 with `checks.retail=false`. No exception or connection
text is returned. Worker health is a recent completed-loop heartbeat; a failed/stalled batch ages it out.
API/retail use Uvicorn's SIGTERM/lifespan handling with a 10-second request-drain window. Worker SIGTERM stops
discovery after the in-flight bounded batch and releases engines; the Compose grace period is 30 seconds
(PostgreSQL: 60). This is not a universal cancellation guarantee: database socket cleanup and in-flight adapters
have their own limits. If Docker ultimately kills a process, the durable lease/ledger remains the recovery source.
The coordinator smoke records normal API/worker stop exit codes; Slice B must exercise actual abrupt kills.

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
the new target has passed Slice B. This procedure is specified for that verification; it has not been exercised
by offline static tests. A restore rolls demo state back in time; it cannot roll back a real external business sink.

## Crash with unresolved writes

Preserve the database, secrets, stable operation IDs and simulator receipts. Restart the simulator before the
worker. Inspect the durable execution state; `unknown`/`dispatched` is not success or proof of noncommit.
The existing dispatcher claims after lease expiry and performs authenticated lookup/reconciliation under the
same operation ID; current policy/consent/approval/resource versions are rechecked before any authorized dispatch.
An absent operation may be fenced; expired or stale authority must not be renewed implicitly. Do not click or
script a new proposal/operation to replace an ambiguous write. A row that exhausts reconciliation stays visibly
unresolved and requires investigation. Restore both sides to a consistent isolated target before recovery tests;
never pair an old app ledger with newer simulator state and then replay writes.

## Coordinator smoke and remaining verification

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
after successful container cleanup; run-tagged images remain for layer/package inspection, then the coordinator
may remove those exact images after retaining evidence. Supply `DOCKER_CONFIG` for the task-scoped Docker context
if needed; the driver otherwise uses the external temporary root's `user-data/docker` location.

Slice B owns real Playwright login through Caddy/Dex, browser CSP/header/SSE verification, customer consent →
staff approval → simulator receipt, two-browser races, coherent separate-database restore and abrupt kill/restart
reconciliation with no duplicate effects. Passing this smoke alone does not complete T38.
