# AWS public fictional demo

**Status.** The demo was verified live on 2026-11-15 at `3609714` and observed
reachable on 2026-11-21. That deploy reported a healthy release after 201 seconds
with zero API, worker and retail restarts. `scripts/deploy_verify.py --allow-admin-ssh`
passed 28/28 checks covering the certificate chain, headers, banners, HTTP redirect,
`__Host-` cookies, Dex login, health and port reachability. From the admin network,
ports 22, 80 and 443 were open among nine tested ports. The same verifier passed
28/28 at each step of the schema-compatible A/B/A rollback drill. The live release
returned to `3609714`. [Rollback scope](#backup-rollback-retention-and-teardown).

The host was 98–99% idle with no CPU steal. The worker container used about 1% CPU,
and every other service used less than 0.4%. Retail used about 237 MiB of its 256 MiB
memory limit.

The first 2026-11-15 Lightsail attempt exposed launch-script handling of user-data and a shared
resource-name namespace; that host was destroyed. The replacement host bootstrapped
successfully. At 19:10Z, deploy A built images but failed after 183 seconds creating API:
Docker rejected the overlay's `extra_hosts` combined with inherited
`network_mode: service:caddy`. Structural overlay tests had missed the merged conflict.
The mapping now belongs to Caddy; a real Compose merge regression covers the failure.
The next deploy, at `a4681dd`, reached API creation but restarted with `ServeConfigError`:
the base profile selected `require` while deployment correctly required `verify-full`.
No client had a mounted trust root. The coordinator's temporary explicit-root override
made API healthy with zero restarts and all dependency checks true; public `/`, `/healthz`
and Dex discovery returned 200 over the ACME certificate. That was diagnostic evidence.
The coordinator subsequently passed local Compose smoke and backup/restore drills at
`ae776c7`, including the runtime roles under verified TLS. Its next public deploy ran with
exhausted CPU burst capacity, as described below. That attempt preceded the verified release above.

## Architecture and cost

One x86_64 Lightsail Ubuntu 24.04 LTS host in `us-west-2`, bundle `small_3_0`, runs the
existing Compose services. Terraform provisions the instance, supplied SSH public key,
attached static IPv4, firewall and an account-wide $20 monthly Budget with 80% actual /
100% forecast email alerts. Credentials use `AWS_PROFILE`; the provider does not receive
keys in configuration. Terraform 1.15.8 and AWS provider 6.25.0 are exact pins. The
coordinator generates and reviews `.terraform.lock.hcl` with network access.
Lightsail resource names share one per-region namespace across resource types: the
instance is `policyops-demo`, key pair `policyops-demo-key`, and static IP `policyops-demo-ip`.

| Item | Monthly USD assumption |
|---|---:|
| Lightsail small_3_0, 2 GB / 2 vCPU / 60 GB, IPv4 | 12.00 |
| One static IPv4 while attached | 0.00 |
| sslip.io hostname, Caddy ACME certificate | 0.00 |
| Docker Engine/CLI 29.7.2, Compose 5.3.1, Buildx 0.36.1, containerd 2.4.2 | 0.00 licence cost |
| Included disk/transfer, no snapshots, no other AWS services | 0.00 incremental |
| Headroom below $20 | 8.00 |

These are coordinator-provided list-price assumptions, not a bill or guaranteed ceiling.
Tax, excess transfer, unattached IP, snapshots, backup destinations and unrelated account
usage can add charges. Budget emails are delayed alerts, not a spending stop. Check the
current regional bundle price/transfer allowance before apply; do not enable snapshots
or paid model calls implicitly. The public host has **no provider API keys**. Public demo
investigations remain `runtime.unconfigured`; the browser starts from a deterministic
presented proposal. Real customer data and commerce are out of scope.

EC2, ECS and EKS were rejected for this slice's cost and operational complexity. A custom
Caddy plugin/build was rejected: stock Caddy handles TLS, redirects, headers and bounded
request bodies; an opt-in API limiter supplies 120 requests/IP per 60-second fixed window,
with at most 4,096 tracked IPs and fail-closed admission for new IPs at capacity. It trusts
only Caddy's overwritten `X-PolicyOps-Client-IP` from a loopback socket. It is per API
process, resets on restart, permits a boundary burst, and does not limit Dex/static files
or establish distributed denial-of-service protection. No extra service is needed.

### Burstable CPU budget and deployment builds

The selected 2-vCPU `small_3_0` host has a baseline of about **20% aggregate CPU**,
equivalent to 0.4 continuously available CPU cores. Budget for credits starting empty;
do not assume a new or depleted host can sustain a build burst. Below-baseline use banks
burst capacity; builds can consume it much faster than it accrues. RAM capacity and two
advertised vCPUs do not establish sustained CPU headroom.

Coordinator evidence from 2026-11-15, host at `ae776c7`: `BurstCapacityPercentage` was
0.0 from 19:40Z, aggregate `CPUUtilization` stayed near 20%, and `vmstat` steal was
39–54%. Deploy exited 1 after 1,129 seconds, roughly seven times the earlier 155-second
attempt. Worker, then retail, failed with `Health check exceeded timeout (8s)` without
app errors or restarts. A single `runtime.py health-worker`, merely checking a file mtime,
used **14.62 CPU-seconds / 19.21 seconds wall**. Worker main-process CPU ticks stayed at
zero over 20 seconds while its container used about 41% CPU: probes dominated that sample.

Each old Python probe imported the full runtime every 10 seconds. On the unthrottled
desktop image, that import cost 1.56–1.66 CPU-seconds from source, or 0.69–0.76 with
precompiled bytecode. At the nominal cadence, three source imports alone would demand
`3 × (1.56–1.66) / 10 = 0.468–0.498 cores`, or **23.4–24.9% of a 2-vCPU host** before
application, database or OS work. Probes longer than their interval cannot actually
maintain that cadence; this is offered demand, not a measured host utilization model.
Precompiling the heavy imports alone would still budget 10.35–11.4% on that desktop
basis, so removing those imports from recurring checks matters as well.

The images now run `compileall -f --invalidation-mode unchecked-hash` after the final
source copies, covering `/opt/venv`, copied application/retail/Compose sources, and the
base Python standard library. The temporary Python stage in the web build compiles its
stdlib and scanner scripts too; the final web image is Caddy. This explicit compile
step replaces the need for `uv sync --compile-bytecode` and also covers editable retail
sources after packaging. Forced unchecked hashes replace any wheel-provided timestamp
caches and avoid source-mtime dependence. This is appropriate because the deployed trees
are immutable, read-only image contents built together with their caches; any source
change requires a rebuild. A writable/source-mounted image would need checked hashes or
a different cache policy. Runtime `-B` and `PYTHONDONTWRITEBYTECODE=1` remain: Python reads
existing caches but creates none. Directly executed script files are still parsed;
their imported modules benefit from the caches.

Policy reconciliation: `.dockerignore` still excludes `__pycache__` from host build
inputs, and `check_build_context.py` still rejects private/generated context paths via
`check_publication.py`. `check_repo_artifacts.py` still rejects newly generated checkout
paths against its baseline. These govern inputs and checkouts, not files generated
inside Docker layers. No existing image audit bans `.pyc`; the Compose image policy
now explicitly requires build-generated caches. No guard exemption or scratch-bytecode
permission was added. Keep development `-B`/bytecode suppression and inspect actual
image layers/packages during the coordinator smoke.

`infra/compose/health.py` imports only the standard library. HTTP probes retain the
2-second socket timeout, no proxies or redirects, exact URLs, HTTP 200 and JSON object
with `status == "ok"`; the worker retains the regular-file `/tmp/worker-heartbeat`
mtime age strictly below 25 seconds. API readiness still performs the same database
role and retail dependency checks. The unused heavy CLI health commands were removed
from `runtime.py`; its internal HTTP helper remains for API readiness itself.

Local checks remain every 10 seconds for prompt development readiness. Their process
timeout is now 5 seconds: a 2-second HTTP socket timeout plus interpreter/scheduling
headroom, with Docker bounding the whole process (including a stalled response body).
The public overlay polls all six services every **30 seconds**, reducing recurring probe
work threefold. The 15-second startup grace, 12 consecutive failures and all startup
dependency gates remain. A successful probe is still necessary for readiness; grace
does not confer success. Public initial readiness can take an extra polling interval,
and persistent failure detection takes roughly six minutes plus probe durations rather
than two. Every worker sample still rejects a heartbeat aged 25 seconds or more, even
though samples are farther apart. Probe failures never trigger automatic restarts by
themselves. Reassess cadence after live CPU and outage-detection measurements.

**Planning estimate for steady-state idle use.** Assume no
build, visitors or runnable jobs, with at most 0.25 CPU-seconds for each of the three
light Python probes and 0.10 CPU-seconds for each of PostgreSQL/Dex/Caddy's probes.
At 30-second intervals, `(3 × 0.25 + 3 × 0.10) / 30 = 0.035 cores`, or **1.75% aggregate
host CPU**. Reserve another 0.20 cores (10 aggregate percentage points) for worker polls,
API/retail, database maintenance, Dex/Caddy, Docker and OS idle work. Total estimated
idle demand is **0.235 cores / 2 = 11.75%**, leaving about 8.25 percentage points below
the 20% baseline. These are planning assumptions, not measured probe costs or a guarantee;
CPU-seconds vary with the host. The equivalent local 10-second probe budget is 5.25%
aggregate before background work. Public traffic, queued work and builds are outside
this idle estimate.

Before deploying, inspect burst capacity, CPU utilization, steal and memory; after
depletion, stop the stack while retaining its volume and let credits accrue before a
build. Wait for observed credit recovery, not a fixed promised delay. Keep **one build
at a time**, as the deploy lock and serial image builds already enforce; do not overlap
manual builds or maintenance. Preserve failed-deploy evidence before retrying. After
deployment, measure per-probe CPU/wall time and whole-host idle CPU over several probe
cycles, including the worker/database background workload, with no build in progress.
Verify credit balance is stable or increasing below baseline, services stay healthy
without restarts, and dependency outages still fail readiness. If idle use exceeds the
baseline, reduce actual work or select a larger sustained budget before acceptance;
longer timeouts alone do not fix CPU demand. Builds still need burst credit even when
the corrected idle stack fits the baseline.

### Public Compose profile

`infra/compose/public.yaml` layers on the root Compose file to keep local behavior and
image definitions authoritative. The host pins Compose **5.3.1**, matching T38's verified
version; `!override` of ports and tmpfs requires at least 2.24.4. Only Caddy publishes
IPv4 80/443. It stays UID 10001 with capabilities dropped;
a namespaced unprivileged-port sysctl allows low ports. API shares that namespace and
resolves the public issuer hostname to loopback, with normal SNI/CA/name verification.
No transport verification is disabled. A root-owned external bind directory persists
Caddy ACME state with UID 10001 access; restarts/resets retain it. HTTP redirects to HTTPS;
HSTS has a one-year max age, without preload or `includeSubDomains` on a shared suffix.
Dex issuer/callback come from the hostname; the existing template already parameterizes
both. API uses deployment-mode settings and Secure `__Host-` cookies. The CSRF cookie is
intentionally readable by JavaScript; login/session cookies are HttpOnly.

### Public issuer networking

The issuer remains exactly `https://<hostname>/dex` for tokens, discovery and stored
principals. `api` uses `network_mode: service:caddy`, which Compose implements as Docker
`container:` networking. Docker reuses the owner's `/etc/hosts` and resolver paths when
initializing that container (see Moby's
[namespace initialization](https://github.com/moby/moby/blob/master/daemon/container_operations.go)
and [networking paths](https://github.com/moby/moby/blob/master/daemon/container_operations_unix.go)).
Thus only **Caddy** declares `<hostname>:127.0.0.1` in `extra_hosts`. API resolves through
that shared hosts file, connects to Caddy on loopback TCP 443 with the public hostname
as SNI, and verifies the normal public certificate. Caddy proxies `/dex/*` to `dex:5556`
on the internal default network. Docker's
[container-network restrictions](https://docs.docker.com/engine/network/#container-networks)
prohibit custom hosts, DNS, hostname, MAC and port options on the joining container;
Compose also forbids specifying its own `networks` alongside `network_mode`.

| Service | Issuer/callback use | Route or reason no issuer route is needed |
|---|---|---|
| `api` | `auth/oidc.py`: discovery GET, JWKS GET, token POST; exact issuer validation | Owner's hosts file -> loopback 443 -> Caddy -> Dex; callback URI is sent as a parameter, not fetched |
| `dex` | `infra/dex/config.yaml.tmpl`: advertises issuer and endpoints; validates registered redirect URI, redirects browser | Serves requests; local health probe uses `127.0.0.1:5556`; local password DB and signer make no outbound issuer/callback requests |
| `seed-demo` | `infra/compose/runtime.py:seed_demo` stores issuer as principal identity | Database writes only; no discovery, keys or token exchange |
| `worker` | Inherits issuer environment; worker entry point never reads it or constructs OIDC client | Database scheduling and retail HTTP only |
| `bootstrap-app`, `migrate-app`, `bootstrap-retail`, `migrate-retail`, `retail` | Inherit local issuer environment but entry points never use it | Provisioning/migrations/database or retail serving only |
| `postgres`, `caddy` | No OIDC issuer setting consumed | Database server / TLS reverse proxy; Caddy uses hostname for routing and ACME |
| External browser | Follows authorization and callback redirects | Public DNS -> host's published Caddy 443 |

The default-network services need no hostname override: none calls the public issuer,
including at startup. Public-IP hairpin routing is **not relied upon or validated**;
the internal network does not promise public egress. If another issuer client is added,
provide and verify its internal route to Caddy rather than assuming public-IP hairpin
works. Do not put loopback mappings on a service with its own network namespace.

`tests/unit/test_public_compose_networking.py` invokes the real `docker compose config`
merge without contacting the daemon (explicit skip if the CLI is unavailable), checks
namespace conflicts and the owner's mapping, and rejects the old overlay as a negative
control. A successful config check alone does not prove daemon creation, hosts-file
sharing or TLS/login. Verify those against the pinned Engine before live acceptance.

PostgreSQL, retail, worker and Dex remain on the internal Docker network. API/Caddy retain
outbound internet reachability (ACME and issuer TLS); this is not destination-allowlisted
egress. Application provider adapters remain unconfigured. Database transport uses
SCRAM-SHA-256 plus TLS `verify-full` and an explicit pinned trust root as described below.
Migration/superuser secrets are mounted only in one-shots, and no admin demo membership exists.

### Database TLS

Both local and public Compose profiles set `POLICYOPS_DB_SSLMODE=verify-full` and
`POLICYOPS_DB_SSLROOTCERT=/run/secrets/postgres_tls_cert`. The base file mounts that
certificate on API, worker, retail, seed, bootstrap and migration services. The public
overlay adds no secrets. The PostgreSQL TCP readiness probe also uses that root and the
hostname `postgres`; verifier, scenario, drill and recovery helpers inherit their owning
service's mounts/environment and use `runtime.connect()`. The smoke driver runs those
helpers inside containers; it does not open a host-side database connection.
The drill's `pg_dump`, `psql` and `pg_restore` commands run through the mounted
`postgres_client.sh` helper in the PostgreSQL container. It requires the same explicit
mode/root, connects over TCP to `postgres`, clears ambient libpq inputs with `env -i`,
and reads the role password only inside the clean child shell (never in argv).

`scripts/compose_secrets.py` creates a self-signed certificate with SAN `DNS:postgres`.
The trust anchor is the server leaf itself (certificate pinning), not a public or private
CA hierarchy. Connect to `postgres`, matching that SAN, and protect the host secret files:
replacing this certificate changes the trusted identity. The coordinator verified that
libpq accepts this certificate as a `verify-full` root. See the
[libpq verification rules](https://www.postgresql.org/docs/17/libpq-ssl.html).

`infra/deploy/renew_db_cert.py` remains compatible: it retains the key and subject,
sets SAN `postgres`, and rewrites the same inode so all file-secret bind mounts see the
renewed leaf. libpq loads `sslrootcert` for each new connection (see its
[connection-specific TLS initialization](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/interfaces/libpq/fe-secure-openssl.c)).
Existing pooled connections retain their established TLS sessions. Renewal runs while
writers are stopped during reset, followed by PostgreSQL recreation and client startup;
the script alone does not reload the server certificate, and an in-flight connection
attempt during a partial rewrite can fail closed. Key/subject/name changes require a
coordinated trust update, not an ambient `PGSSLROOTCERT` override.

Settings require an absolute root path without control characters; file existence and
certificate validity are checked by libpq on connection, keeping startup validation free
of file reads and configured values in errors. Both verification modes fail closed
without the explicit path even outside deployment. Deployment additionally requires
`verify-full`; every Compose role refuses missing/other modes or roots before reading a
password. Ambient TLS variables are refused by API and helpers; the
[database configuration policy](database.md#transport-and-explicit-trust) lists them.

Runtime memory limits are **estimates**, not measured T38 baselines: Caddy 160 MiB, API
320 MiB, worker 320 MiB, retail 256 MiB, PostgreSQL 384 MiB, Dex 128 MiB (1,568 MiB total).
This leaves about 480 MiB for the OS/Docker; serialized one-shots are 256 MiB each and
overlap some services during startup. A 2 GiB swap file supports build/startup pressure;
serial image builds can still OOM or fill 60 GB. Measure `docker stats`, swap and disk in
the live gate; reduce concurrency/limits or stop the deployment if this bundle cannot fit.
Do not claim measured capacity, uptime or load performance from static tests.

## Prerequisites and pins

The user supplies an AWS profile with Lightsail/Budgets permissions (prefer a locally
authenticated short-lived session), an SSH key whose private half stays local, their
current public IPv4 `/32`, and a budget alert email. No values go in chat or committed
files. Terraform state/backup/plan and private tfvars live outside the checkout, protected
by the operator's ACL. State includes user-data, public key and budget email; `sensitive`
only hides display. No TLS private key, SSH private key or application secret enters state.

Before apply the coordinator verifies `ubuntu_24_04` and `small_3_0` in the selected region,
provider schema/lock checksum, current Docker apt candidates, and the SSH public-key type
accepted by Lightsail import (use RSA if the selected region rejects Ed25519). Bootstrap
pins Docker Engine/CLI `5:29.7.2-1~ubuntu.24.04~noble`, containerd
`2.4.2-4~ubuntu.24.04~noble`, Buildx `0.36.1-1~ubuntu.24.04~noble`, Compose
`5.3.1-1~ubuntu.24.04~noble`. Engine/Compose match T38's verified versions and Buildx
matches its 0.36 series; the Ubuntu host combination still needs live verification.
Engine 29.7.2 requires containerd >= 2.1.5 and `nftables`; apt installs the latter dependency.
Installing that package does not select Docker's native nftables firewall backend.
The coordinator fetched Docker's noble amd64 stable `Packages.gz` on 2026-11-14 and
confirmed all five exact versions. Repeat before apply, keeping the fetched index as
private evidence under the configured temporary root. From the checkout in PowerShell:

```powershell
$pinEvidence = "$env:POLICYOPS_TEMP_DIR/deployment/docker-pins"
New-Item -ItemType Directory -Force $pinEvidence | Out-Null
curl.exe --fail --silent --show-error https://download.docker.com/linux/ubuntu/dists/noble/stable/binary-amd64/Packages.gz -o "$pinEvidence/Packages.gz"
if ($LASTEXITCODE -ne 0) { throw 'Docker package index fetch failed' }
@'
import gzip
from pathlib import Path
import re
import sys

index = gzip.decompress(Path(sys.argv[1]).read_bytes()).decode("utf-8")
versions = set()
for stanza in index.split("\n\n"):
    fields = dict(line.split(": ", 1) for line in stanza.splitlines() if ": " in line and not line[0].isspace())
    if "Package" in fields and "Version" in fields:
        versions.add((fields["Package"], fields["Version"]))
template = Path(sys.argv[2]).read_text(encoding="utf-8")
pins = re.findall(r"\b(docker-ce(?:-cli)?|containerd\.io|docker-buildx-plugin|docker-compose-plugin)=([^\s]+)", template)
if len(pins) != 5 or any(pin not in versions for pin in pins):
    raise SystemExit("Missing or incomplete Docker pins; revise and review before apply")
for package, version in pins:
    print(f"Verified {package}={version}")
'@ | python -B - "$pinEvidence/Packages.gz" infra/deploy/bootstrap.sh.tftpl
if ($LASTEXITCODE -ne 0) { throw 'Docker pin verification failed' }
Get-FileHash "$pinEvidence/Packages.gz" -Algorithm SHA256
```

Record fetch time, index hash and successful exact-version checks. Also confirm candidates
with `apt-cache madison` using Docker's signed Ubuntu noble amd64 stable repository;
the index check alone does not authenticate packages or prove bootstrap succeeds. Bootstrap
fails instead of falling back to an unpinned package. Packages are held; security updates
for Ubuntu are unattended, Docker pin updates require operator review. Review the Docker
signing-key fingerprint against official documentation before use. No curl-to-shell.

### Lightsail bootstrap and SSH management

Lightsail appends user-data verbatim to its own `#!/bin/sh` launch script; it does not
deliver this data as a cloud-config YAML part. `infra/deploy/bootstrap.sh.tftpl` therefore
starts with a POSIX dash-compatible stub. A quoted heredoc writes the real bash bootstrap
atomically to `/usr/local/sbin/policyops-bootstrap` (0700). The stub invokes it with bash;
the payload uses `set -euo pipefail`. Only `admin_cidr` is interpolated by Terraform.
Configuration files are written through temporary files and renamed on the same filesystem.
The script preserves package pins/holds, automatic Ubuntu updates, swap, journal limits,
SSH hardening, the Docker forwarding fence, UFW order and private deploy directories.
The Ubuntu blueprint supplies the `ubuntu` user; no extra management user is created.

The stub appends diagnostics to `/var/log/policyops-bootstrap.log` (0600) and records exit
code `0` in `/var/lib/policyops/bootstrap/success`, or the nonzero exit code in `failure`.
The marker directory is 0700 and both markers are root-only. Each launch clears stale
markers; missing bash or a failed bootstrap returns nonzero to cloud-init. To rerun the
entire bootstrap with fresh markers, run the reviewed rendered launch script under
`sudo sh`, rather than invoking the payload alone. Reruns replace managed files, avoid
duplicate swap activation/fstab entries and UFW rules, and rebuild DOCKER-USER in order.

Lightsail's wrapper also installs `/etc/ssh/lightsail_instance_ca.pub` and appends a
`TrustedUserCAKeys` directive. This profile permits no alternate remote-management path.
Bootstrap removes that directive and file idempotently and sets `TrustedUserCAKeys none`
in the hardening drop-in. It creates `/run/sshd` (0755) before `/usr/sbin/sshd -t`,
because socket activation may precede the service's runtime-directory creation, then restarts
`ssh.service`, the Ubuntu 24.04 unit (the wrapper's `sshd.service` restart fails there).
Browser SSH certificate trust is disabled; key-authenticated SSH from the operator `/32`
remains the management path. Verify the effective settings with `sudo sshd -T` live.

`aws lightsail get-instance-access-details` returned no `hostKeys` for this profile:
AWS witnesses host keys only through browser SSH, which the operator `/32` rule blocks.
The coordinator's decision is to record keys with `ssh-keyscan` from that `/32`, minutes
after creation, into a dedicated known_hosts file, then pin that file and require
`StrictHostKeyChecking=yes` thereafter. This is **trust on first use**: an on-path attacker
at first contact could supply substituted keys. Later strict checks detect a changed key;
the initial scan is not independent host authentication. Retain the file and fingerprints
privately and investigate mismatches; never silently overwrite the pinned file.

On Windows, OpenSSH 9.5 `ssh-keyscan` fails with
`unsupported KEX method sntrup761x25519-sha512`; use a newer OpenSSH (Git for Windows
OpenSSH 9.9 worked). The sequence prepends Git's `usr\bin` to the process-local PATH
and checks for OpenSSH 9.9 or later, so SSH, SCP, key scanning and the rollback drill
use the same client build. The coordinator's pinned known_hosts file uses LF line endings.
A `-o UserKnownHostsFile=` path containing spaces must be quoted
**inside the option value**, as the command sequence below does. Use the same dedicated
file for SSH, SCP and the rollback drill; disable global host-key lookup for these commands.

## Coordinator command sequence

From the reviewed checkout in PowerShell (paths below are operator-chosen external paths).
Keep Terraform logging disabled; never publish state, saved plans, tfvars or raw cloud-init
logs. Set temp routing for every local process, as in the development instructions.

```powershell
$gitSshBin = 'C:\Program Files\Git\usr\bin'
$env:PATH = "$gitSshBin;$env:PATH"
$sshVersion = (ssh -V 2>&1 | Out-String).Trim()
$sshVersionMatch = [regex]::Match($sshVersion, '\bOpenSSH_(\d+\.\d+)')
if ($LASTEXITCODE -ne 0 -or -not $sshVersionMatch.Success) { throw 'Cannot verify Git OpenSSH version' }
if ([version]$sshVersionMatch.Groups[1].Value -lt [version]'9.9') { throw 'OpenSSH 9.9 or later is required' }
$env:POLICYOPS_TEMP_DIR = 'D:\path\outside\checkout\policyops'
$env:TEMP = "$env:POLICYOPS_TEMP_DIR/tmp"
$env:TMP = $env:TEMP
$env:PYTHONDONTWRITEBYTECODE = '1'
New-Item -ItemType Directory -Force $env:TEMP | Out-Null
$stateDir = "$env:POLICYOPS_TEMP_DIR/aws-state"
New-Item -ItemType Directory -Force $stateDir | Out-Null
$env:TF_DATA_DIR = "$stateDir/terraform-data"
$env:TF_PLUGIN_CACHE_DIR = "$stateDir/provider-cache"
New-Item -ItemType Directory -Force $env:TF_PLUGIN_CACHE_DIR | Out-Null
$env:AWS_PROFILE = '<locally-authenticated-profile>'
# Create $stateDir/demo.tfvars from the example; replace all placeholders privately.
terraform -chdir=infra/terraform/aws init "-backend-config=path=$stateDir/terraform.tfstate"
terraform -chdir=infra/terraform/aws fmt -check
terraform -chdir=infra/terraform/aws validate
terraform -chdir=infra/terraform/aws plan "-var-file=$stateDir/demo.tfvars" "-out=$stateDir/deploy.plan"
# Inspect the plan locally; verify cost/ports/region. Apply exactly that plan.
terraform -chdir=infra/terraform/aws apply "$stateDir/deploy.plan"
$ip = terraform -chdir=infra/terraform/aws output -raw static_ip
$hostName = terraform -chdir=infra/terraform/aws output -raw hostname
$key = 'D:\path\to\local\ssh-key'
$commitA = '<reviewed-and-published-full-40-character-commit-A>'
$commitB = '<reviewed-and-published-full-40-character-compatible-commit-B>'
$knownHosts = "$stateDir/known_hosts"
if (Test-Path -LiteralPath $knownHosts) { throw 'Pinned known_hosts already exists; investigate before changing it' }
# First contact from the operator /32, minutes after creation: TOFU risk described above.
$scan = ssh-keyscan -T 10 -t ed25519,ecdsa,rsa $ip
if ($LASTEXITCODE -ne 0 -or -not $scan) { throw 'Host-key scan failed' }
$knownHostsText = ([string[]]$scan -join "`n") + "`n"
[System.IO.File]::WriteAllBytes($knownHosts, [System.Text.UTF8Encoding]::new($false).GetBytes($knownHostsText))
ssh-keygen -lf $knownHosts
$sshOptions = @('-o', 'StrictHostKeyChecking=yes', '-o', ('UserKnownHostsFile="{0}"' -f ($knownHosts -replace '\\', '/')), '-o', 'GlobalKnownHostsFile=none')
ssh -i $key @sshOptions "ubuntu@$ip" 'sudo cloud-init status --wait && sudo test ! -e /var/lib/policyops/bootstrap/failure && sudo grep -qx 0 /var/lib/policyops/bootstrap/success'
if ($LASTEXITCODE -ne 0) { throw 'Bootstrap incomplete or failed; inspect the root-only bootstrap log' }
scp -i $key @sshOptions infra/deploy/deploy.sh "ubuntu@${ip}:/home/ubuntu/policyops-deploy"
scp -i $key @sshOptions infra/deploy/cd_agent.py "ubuntu@${ip}:/home/ubuntu/cd_agent.py"
ssh -i $key @sshOptions "ubuntu@$ip" 'sudo install -m 0644 /home/ubuntu/cd_agent.py /usr/local/sbin/cd_agent.py && sudo install -m 0755 /home/ubuntu/policyops-deploy /usr/local/sbin/policyops-deploy'
ssh -i $key @sshOptions "ubuntu@$ip" "sudo bash /usr/local/sbin/policyops-deploy $commitA $hostName"
python -B scripts/devenv.py uv run --offline --frozen python -B scripts/deploy_verify.py $hostName --allow-admin-ssh
# Run again from a non-admin network without --allow-admin-ssh to establish anonymous 22 denial.
python -B scripts/devenv.py uv run --offline --frozen python -B scripts/deploy_rollback_drill.py $hostName --ssh-host "ubuntu@$ip" --identity $key --known-hosts $knownHosts --commit-a $commitA --commit-b $commitB --schema-compatible --allow-admin-ssh
# Teardown, after preserving required private evidence/backups:
ssh -i $key @sshOptions "ubuntu@$ip" 'sudo systemctl disable --now policyops-reset.timer policyops-seed.timer'
terraform -chdir=infra/terraform/aws plan -destroy "-var-file=$stateDir/demo.tfvars" "-out=$stateDir/destroy.plan"
terraform -chdir=infra/terraform/aws apply "$stateDir/destroy.plan"
```

Do not substitute a different backend path during validate/plan/apply/destroy. Backend
metadata is external via `TF_DATA_DIR`; the actual local state path was set at init.
CI/build images must never contain that directory. `*.tfstate*`, `*.tfvars` and
`.terraform/` are already ignored; the committed tfvars example has placeholders only.
Do not override the local backend to use a repository state path.

### Recovering from an admin IPv4 change

Keep a trusted SSH session open while changing networks when possible. Update only
`admin_cidr` in the private `demo.tfvars` to the new public IPv4 `/32`. Use the same
profile, region and external backend. For this exceptional recovery, target **only**
the existing Lightsail public-port resource, inspect the saved plan for a port-22 CIDR
change with no instance replacement, then apply it:

```powershell
terraform -chdir=infra/terraform/aws plan "-var-file=$stateDir/demo.tfvars" -target=aws_lightsail_instance_public_ports.demo "-out=$stateDir/ssh-recovery.plan"
# Apply only after inspection confirms an in-place port-rule update and no other changes.
terraform -chdir=infra/terraform/aws apply "$stateDir/ssh-recovery.plan"
```

`admin_cidr` is also embedded in immutable instance user-data. Terraform targeting
[includes dependencies](https://developer.hashicorp.com/terraform/cli/commands/plan#resource-targeting),
including this instance, so **targeting alone does not prevent its replacement**.
If the recovery plan proposes replacement, do not apply it. The coordinator must first
prepare a reviewed local recovery configuration that temporarily adds
`lifecycle { ignore_changes = [user_data] }` to `aws_lightsail_instance.demo`, regenerate
the plan, and verify that only the existing public-port rule changes. Restore the
configuration after recovery and review the remaining user-data drift at the next full
plan; never apply an instance replacement as an SSH repair. This lifecycle exception
and targeting are confined to the recovery operation, not normal deployment or a
permanent suppression of bootstrap changes.

The host's UFW rule still allows the old `/32`. Through the retained SSH session or
trusted access from the old egress IP, run `sudo ufw allow from <new-ip>/32 to any port
22 proto tcp`, verify a second key-authenticated session from the new IP, then run
`sudo ufw delete allow from <old-ip>/32 to any port 22 proto tcp`. Keep SSH restricted
to the operator; never temporarily use `0.0.0.0/0`. If there is no retained session or
access from the old IP, updating Terraform alone cannot bypass UFW: stop and arrange
coordinator recovery from a verified backup/reprovisioning plan instead of promising
SSH recovery through the cloud firewall alone.

The Lightsail browser SSH console requires port 22 allowed from AWS's browser-SSH IP
ranges, so it is unavailable with this operator-only `/32` restriction. It is not a
back door through the Lightsail firewall or UFW; this profile provisions no alternate
remote-management agent.

Both commits must contain this deployment profile and be publicly cloneable. Deploy
builds detached exact commits on the host, serially, with commit-tagged images. First
deploy reuses `scripts/compose_secrets.py` in the frozen app image: external secrets mode
0700, no host pip dependency. Fictional passwords alone are replaced by public credentials.
There is no private Git token on the host. A root-only lock excludes deploy/reset overlap;
failed deploys retain evidence and images and do not silently attempt a schema downgrade.

## Public credentials and fixture reset

These deliberately public credentials grant only the single **fictional demo tenant**:

| Login | Public password | Role |
|---|---|---|
| `alice@example.invalid` | `PolicyOps-public-demo-alice` | analyst / simulated customer consent |
| `bob@example.invalid` | `PolicyOps-public-demo-bob` | reviewer / separate staff approval |
| `carol@example.invalid` | `PolicyOps-public-demo-carol` | auditor / read-only |

They are not database, migration, AWS or admin credentials. Visitors share these users
and fixtures and can interfere with each other's demo state. Do not enter personal data.
Choose the newest address-change case in the queue, supply simulated consent as
Alice, then sign in as Bob to approve; no model call is needed. Base seeding never supplies
consent, staff approval or execution. A fresh investigation reports `runtime.unconfigured`.

A second timer presents a fresh independent case every five minutes, because proposal
and run expiry must remain enforced. It supplies no consent or approval. Daily reset
bounds this to about 289 fixture cases/day (below the worker's 1,000-binding cap). Visitors
may consume a shared case; choose the newest still-pending proposal. A prolonged reset
failure stops periodic seeding at a hard cap of 300 between successful resets; operator
deploys can add further cases. Repair the timer before the worker's binding cap is reached.
The seed/reset/deploy scripts all take the same lock.

The systemd timer resets at 08:00 UTC nightly (plus up to five minutes jitter). It takes
the same deployment lock, stops writers, verifies the exact Compose volume owner/project/run
labels, deletes **only** `policyops-public_pgdata`, renews the existing DB TLS certificate,
then recreates migrations/fixtures and presents a fresh deterministic proposal. Sessions,
entered text, approvals, receipts and retail mutations are disposable; there is downtime.
It retains secret values and ACME state. Missed timers run at next activation. Inspect
`systemctl list-timers policyops-reset.timer` and `journalctl -u policyops-reset.service`;
a failed reset requires operator intervention. Never run this against retained real data.

### Record the demo walkthrough

From `apps/web`, use Node 26, the locked web dependencies, and the matching Playwright Chromium installation.
Put the public demo passwords listed above in separate files named `alice` and `bob` in an external directory.

```powershell
$env:POLICYOPS_TEMP_DIR = 'D:\path\to\external\scratch'
$env:TEMP = $env:TMP = $env:npm_config_cache = $env:POLICYOPS_TEMP_DIR
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:NODE_DISABLE_COMPILE_CACHE = '1'
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $env:POLICYOPS_TEMP_DIR 'playwright-browsers'
$env:POLICYOPS_DEMO_ORIGIN = 'https://52-11-210-0.sslip.io'
node .\demo\record-demo.ts --password-dir 'D:\path\to\demo-passwords'
```

Create the scratch directory before running and set `PLAYWRIGHT_BROWSERS_PATH` to your prepared Chromium installation.
The recorder prints the WebM and PNG paths under `POLICYOPS_TEMP_DIR/N12/<run>/`. Review both files before copying
them to `docs/assets/policyops-demo.webm` and `docs/assets/policyops-demo.png` for the README.

The run uses one pending fictional fixture. It records staff-entered simulated customer consent, a separate approval,
and the committed receipt from the simulated retail system. There is no model call. If a write or its outcome is
unclear, inspect the same proposal before starting another run.

For a disposable local rehearsal, start the [loopback Compose stack](operations.md#start-and-stop) and present a fresh
fixture from the repository root with `docker compose exec -T worker python -B infra/compose/scenario.py seed`.
Set `POLICYOPS_DEMO_ORIGIN` to `http://127.0.0.1:8080`, add `--local`, and point `--password-dir` at that stack's
`alice` and `bob` password files.

## Local live-agent profile

The opt-in `infra/compose/live-agent.yaml` overlay runs the real investigation graph with GPT-6-Luna at low
reasoning effort. It uses `tool-contract-v1r1`, the pinned fictional retail fixture, and the
`tau2-retail-policy` corpus. The local seed creates a fresh customer cancellation case with a single pending
order. Start the investigation in the workbench to see its activity, then inspect the cited proposal, enter
simulated customer consent, and approve it in a separate reviewer session. The final receipt comes from the
retail simulator.

This overlay is local-only and is not deployable. Use a disposable Compose project with a loopback HTTP origin.
Public deployments use the explicit base and public Compose files. The default stack leaves the investigation
catalog unconfigured.

Use Docker Compose 2.33.1 or later for the worker's egress gateway priority. Set `POLICYOPS_TEMP_DIR` to an
external directory, set `POLICYOPS_RUN_ID` to a unique name, and set `POLICYOPS_SECRETS_DIR` to a fresh
subdirectory of that temp root. Generate the usual demo secret files with `scripts/compose_secrets.py`. Place the
OpenAI key in the file `$POLICYOPS_SECRETS_DIR/openai_api_key`, using host permissions that give the worker's
UID 10001 read access. Compose mounts this file only in the worker. The API can bind and queue the same runtime
without a provider credential. Set `POLICYOPS_LIVE_AGENT_POLICY` to the absolute path of
`data/tau2/domains/retail/policy.md` from the pinned tau2 checkout at
`19f13ea3f5fba8b4c4d272d1353590f29dc53062`, with SHA-256
`2c9652afbce57d6e087768d37cda64d31c53d50b3e3225cfdb791bac66466467`. Provision the tokenizer with
`scripts/fetch_tokenizer_vocab.py --from-file <absolute-pinned-vocabulary>`.

With those inputs prepared, run these commands from the checkout in PowerShell. The ingestion command may send
paid embedding requests. The seed also ensures ingestion has completed, so the two worker commands can be
reduced to the seed alone. A matching active corpus generation is reused without new rows or provider calls.

```powershell
$compose = @('compose', '-p', $env:POLICYOPS_RUN_ID, '-f', 'compose.yaml', '-f', 'infra/compose/live-agent.yaml')
docker @compose config -q
docker @compose up --build --wait --wait-timeout 300
docker @compose logs --tail 20 worker
docker @compose exec -T worker python -B infra/compose/runtime.py ingest-live-agent
$case = docker @compose exec -T worker python -B infra/compose/runtime.py seed-live-agent
```

Set `POLICYOPS_DEMO_ORIGIN` to the stack's loopback HTTP origin and prepare Playwright Chromium with the locked
web dependencies. Create an external recording directory before running the recorder. From `apps/web`:

```powershell
node demo/record-demo.ts --mode live-agent --local --case $case --password-dir $env:POLICYOPS_SECRETS_DIR --output-dir $recordings
```

The worker prints its price-bound preflight at startup. A run reserves at most **USD 0.012096** across eight
model calls, with 10,000 input tokens and 1,024 output tokens per call and 120 seconds of active investigation
time. Ingestion has separate operation caps of USD 0.01, four calls, 16,000 input tokens, and 120 seconds.
`POLICYOPS_LIVE_AGENT_MAX_USD` defaults to **USD 0.50** for the life of the demo workspace. A new run needs enough
room for its full preflight above settled and held liability. Each model and embedding reservation checks the
same workspace limit. Unconfirmed charges remain held, and provider charges above their reservations are
recorded as overruns. The runtime uses the configured model throughout.

### Transport tapes and latency

For a recorded reproduction, create an external directory writable by worker UID 10001. Set
`POLICYOPS_LIVE_AGENT_TAPES` to its absolute path and add `-f infra/compose/live-agent-recording.yaml` to
`$compose`. Run Compose through `python -B scripts/devenv.py -- docker @compose ...` so the host path is
checked before it is passed to Docker. The mount and recorder are worker-only and opt-in. Use
`tool-contract-v1r1` for the original seeded case. Set `POLICYOPS_LIVE_AGENT_PROFILE=tool-contract-v2` to run
the version with typed operator outcomes. Both the API and worker read this setting when they start.

Each run and claim gets its own tape directory. The tape records only bounded JSON bodies for the OpenAI
Responses token-count and inference endpoints. It excludes HTTP headers and redacts the configured key,
sensitive JSON fields and recognizable credential strings. Tapes still contain fictional prompts, tool
results and model output. Keep them private. Missing responses and incomplete exchanges remain visible.
Pass `--investigation-only` to the browser recorder to end at the proposal or another investigation outcome.
That skips consent and approval. Use the worker to export the corresponding transport timing summary.

```powershell
python -B scripts/devenv.py -- docker @compose exec -T worker python -B infra/compose/runtime.py summarize-live-agent --run $runId
```

The case recording summary and the worker summary use the following database times.

- Run creation comes from the persisted run row. First model call is the first agent ledger reservation, before
  the preflight count request. The tape reports the start of each HTTP exchange separately.
- Proposal time comes from the first `proposal.presented` event written in the proposal persistence
  transaction. Investigation end is the first state change to `waiting_approval` or a terminal state.
  Consent, approval and execution time are outside that interval.
- Each tape exchange measures monotonic time from dispatch to complete response body, failed dispatch or
  incomplete close. Count and inference samples are reported separately. Tool time measures the graph's
  retrieval, read and proposal calls, including their own validation and persistence. Queueing, checkpoint
  work and retry waits remain in end-to-end time. An incomplete exchange or non-200 status is a transport
  failure. A 200 response can still fail later model or accounting checks.

For the latency panel, report nearest-rank p50 and p95 among slots reaching a persisted proposal by the
registered horizon. Include that count over all scheduled slots and report terminal durations for the other
slots with an observed end. Report provider duration sample and failure counts separately for count and
inference. Keep profiles, models and turns separate and state that runs are serial along with the workstation
network path. Missing timestamps and unstarted slots remain in the denominator.

PostgreSQL and the simulator stay on the internal default network. The overlay adds a separate outbound bridge
for the worker. The intended external endpoint is `api.openai.com`; Compose does not enforce that destination.
This demonstration covers a fictional cancellation and its independently approved simulator effect. Live model
output can abstain, stop, or omit the required citation. The recorder exits nonzero in those cases and keeps the
captioned recording with a sanitized summary when it completes capture. The summary reports the run's pinned
case version, proposal version, ledger call count and amounts, and the verified receipt digest when available.

When finished, run `docker @compose down --volumes` for this disposable project, retain recordings as needed, and
remove the local copy of the provider key from the secret directory.

**Recorded result (2026-11-27, one Windows workstation, Docker Desktop).** The committed
[recording](assets/policyops-live-agent.webm) shows one run. GPT-6-Luna read the customer and order, retrieved
the cancellation policy and proposed cancelling the single pending order with cited policy evidence. Staff then
entered simulated consent, a separate reviewer approved, and the simulator returned a verified receipt. The run
used 6 model calls and settled an estimated USD 0.0022, with nothing held.

While the profile was brought up, 16 local runs in one workspace settled an estimated USD 0.031 in total across
88 ledgered calls, including the one-time policy embedding. Nothing was held. 11 runs reached a proposal. In the
other 5, the agent ended without one, replying that it could not answer from the verified policy evidence.

Those runs also exposed a workbench defect. A live `case.message_posted` event updated the conversation but not
the case version, so the next customer message was rejected with HTTP 409. The case view now re-reads the case
after such events and blocks posting until the read completes.

## Hardening and live acceptance

- Confirm Lightsail ingress: TCP 80/443 from all IPv4, 22 only from admin `/32`, no IPv6.
  Confirm ufw default-deny INPUT, key-only SSH/no root login, and DOCKER-USER forwarding
  restrictions after bootstrap, reboot and Docker restart. Docker publishing bypasses
  ufw INPUT; Lightsail firewall and DOCKER-USER are essential additional boundaries.
- This host owns the entire `DOCKER-USER` chain. The locked firewall script flushes it
  and appends exactly: ESTABLISHED/RELATED ACCEPT, public-NIC TCP 80/443 ACCEPT,
  public-NIC DROP, then RETURN. Reruns remove an old early RETURN and duplicate rules.
  The systemd unit starts with Docker and is restarted with it; bootstrap enables it
  immediately. Rebuild is not atomic: briefly no fence exists between flush and append,
  so keep the Lightsail ingress restrictions active and perform maintenance before
  public acceptance. A script failure requires repair before exposure.
- Docker's [iptables documentation](https://docs.docker.com/engine/network/firewall-iptables/)
  places `DOCKER-USER` before Docker's forwarding accepts. This profile requires that
  backend; do not enable Docker 29's experimental
  [native nftables backend](https://docs.docker.com/engine/network/firewall-nftables/),
  which has no `DOCKER-USER` chain. Ubuntu's iptables-nft compatibility frontend is
  distinct from Docker's native nftables backend. DNAT precedes `DOCKER-USER`, so the
  80/443 rule matches container ports; this profile publishes the same host/container
  ports. Review the fence if port mappings change.
- Run the following after bootstrap, after reboot, after Docker restart, and after
  manually rerunning `sudo /usr/local/sbin/policyops-firewall` twice. Privately record
  timestamps, Docker/backend version, service status, the FORWARD jump to DOCKER-USER
  before Docker's accepts, and exactly the four ordered rules above (with the real
  public NIC). Verify both 80/443 reachability and denial of unintended ports from
  outside the host. Offline order tests do not prove live packet filtering or restart
  behavior. Do not expose the demo if the unit fails or the backend/jump/rules differ.

  ```powershell
  ssh -i $key @sshOptions "ubuntu@$ip" 'sudo docker info; sudo systemctl status --no-pager policyops-firewall.service; sudo iptables -S FORWARD; sudo iptables -S DOCKER-USER'
  ```

- Confirm `ss -lntup`, `docker compose ... config`, container effective UID/capabilities,
  internal network membership, bounded logs, memory/swap/disk and separate migration roles.
  No service except Caddy may publish; API binds namespace loopback. Keep Docker root-only.
- Verify no provider credentials in the process configuration, mounts, images or user-data.
  Avoid dumping environments/config/secrets into evidence. There is no admin web identity.
- Verify TLS chain, redirect, HSTS/CSP/frame/nosniff/referrer, Dex login and cookie properties
  with `deploy_verify.py`. It signs in with public Alice and writes a sanitized report to
  `POLICYOPS_TEMP_DIR/deployment/`. Port checks cover a fixed small list, not all 65,535
  ports; firewall/config inspection complements the probe. API session and login cookies
  must be Secure/HttpOnly/SameSite=Lax; CSRF must be Secure/Strict and readable.
- Repeat the existing real-browser consent -> Bob approval -> one receipt scenario over
  HTTPS, denial for Carol/foreign tenant, API 429 behavior, reboot, nightly reset and
  backup restore. Run the rollback drill for new release pairs after checking schema
  compatibility. Static tests do not establish these composed behaviors.
- Verify correct auto-renewal state and retain Caddy storage. sslip.io/DNS/ACME availability
  and issuance rate limits are external dependencies. An owned domain is optional; set
  `hostname` before initial seeding and point its A record to the static IP. Changing an
  existing issuer requires a fresh disposable volume and new sessions.

## Continuous deployment

The host timer checks `main` every ten minutes with up to one minute of jitter.
The agent binds the full Git tip to the newest completed, successful GitHub
`ci.yml` push attempt for the pinned repository. It compares the tip with the
last gated release, so an intervening runtime change is eligible even when the
tip only edits documentation. The agent builds on the host, at least three
hours apart and at most four times per UTC day. Low free disk space (under
8 GiB on `/var/lib`) holds the build. CPU steal above 20% over a three-second
sample defers it. Builds leave the current stack serving.

### Install and adopt

From a reviewed release checkout, use a root shell on the existing host. The
baseline must already serve its full SHA at `/release`, with its app, retail,
web, PostgreSQL and Dex images retained locally. For a legacy deployment, use
the manual runbook to deploy the reviewed baseline and seed its fixture first.
For the first install, the reset markers in `/var/lib/policyops/cd`
(`reset-missed`, `reset-pending`, `reset-progress`) must be absent or have
been created only by the current `reset.sh`.
Disable the CD timer and remove `/var/lib/policyops/cd/enabled` before a manual
deploy or tooling reinstall. Allow any running CD invocation to finish, then
hold the deploy lock during installation.

```bash
umask 077
install -d -m 0700 /var/lib/policyops/cd /usr/local/lib/policyops-cd
(
  flock -w 10 9 || exit
  install -m 0755 infra/deploy/cd_agent.py /usr/local/lib/policyops-cd/policyops-cd
  ln -sfn /usr/local/lib/policyops-cd/policyops-cd /usr/local/sbin/policyops-cd
  install -m 0755 infra/deploy/deploy.sh /usr/local/lib/policyops-cd/deploy.sh
  install -m 0644 scripts/deploy_verify.py /usr/local/lib/policyops-cd/deploy_verify.py
  install -m 0755 infra/deploy/reset.sh /usr/local/sbin/policyops-demo-reset
  install -m 0755 infra/deploy/seed.sh /usr/local/sbin/policyops-demo-seed
  install -m 0644 infra/deploy/policyops-cd.{service,timer} /etc/systemd/system/
) 9>>/var/lib/policyops/deploy.lock
```

Create root-owned mode-0600 `/var/lib/policyops/cd/config.json`. Fill in the
immutable numeric GitHub repository ID for `XiaoyunYin/policyops` and the
hostname recorded in `/var/lib/policyops/hostname`. The interval fields below
show the defaults. Stricter build limits can be used without changing the timer.

```json
{
  "repo_id": 0,
  "hostname": "demo.example.invalid",
  "min_build_interval_seconds": 10800,
  "max_builds_per_utc_day": 4,
  "api_backoff_seconds": 600
}
```

On a tooling reinstall, run `policyops-cd cancel` before `adopt` if the
previous agent left a `building` or `built` attempt. The command acquires
the deploy lock, requires the `active` marker to be absent, and leaves the
serving release in place.

```bash
policyops-cd adopt &&
  systemctl daemon-reload &&
  touch /var/lib/policyops/cd/enabled &&
  systemctl enable --now policyops-cd.timer
```

A failed adopt must leave `/var/lib/policyops/cd/enabled` absent.

The installed verifier uses the last healthy app image's Python and validates
HTTPS, the release SHA, Alice's session and the exact seeded proposal in a
read-only GET. It can retry once after 30 seconds. Six readiness and container
probes, spaced 30 seconds apart, require one container per service and verify its
running image ID, restart count, and OOM state. The host gate skips external
port probes. Run the full verifier from outside the admin network for ingress
evidence.

### Review holds and recover

- Use `policyops-cd release <full-sha>` on the specific held green tip after
  review. It prints and approves the recorded HOLD reasons. A later reason for
  the same SHA requires another release. Inspect schema changes in both
  Alembic trees, migration and bootstrap code and the PostgreSQL image pin.
  A released schema change can run
  migrations. Activation or gate failure freezes the host for operator repair.
- For tooling changes, reinstall the reviewed host tools before releasing the
  tip. Review protected branch history before releasing a non-fast-forward tip.
  Before building, the agent checks the resolved service sets, single-replica
  topology, and reserved image tags. Unsupported configs stay held. The command
  output tail change is CD tooling and requires an operator release.
- A failed same-schema activation or gate restores the retained last healthy
  checkout and images locally, reseeds a proposal and gates the restored
  release. Keep those artifacts and both pinned dependency images when pruning.
  The agent quarantines failures by full SHA and freezes after two failed
  rollback attempts or three rollbacks within 24 hours.
- A frozen host also pauses nightly reset and periodic seeding. Inspect
  `/var/lib/policyops/cd/log.jsonl` and `cd/quarantine/<full-sha>.json` under
  `/var/lib/policyops`. Find the failed command in `output_tails` and read its
  referenced file as root. After repairing the serving release, use
  `policyops-cd adopt` if the baseline needs to change and
  `policyops-cd unfreeze` to resume. Preserve a damaged `state.json` for review,
  reconcile any recorded attempt, and adopt a verified baseline before enabling
  the timer again. Keep the enabled switch absent throughout recovery.
- The agent defers builds from 06:57 to 08:30 UTC and cutover, promotion and
  rollback from 07:45 to 08:30 UTC. A blocked nightly reset leaves a durable
  `reset-missed` marker. The agent retries it when the host is unfrozen and
  cutover is idle. An interrupted reset resumes from `reset-progress`, which
  records the reset ID, release, and last completed step. If adoption reports
  `reset_in_progress`, complete or retry the reset with `policyops-demo-reset`
  on the recorded release first, then run `policyops-cd adopt`. The agent gates the
  reset fixture before resuming a built candidate and freezes if verification
  fails.

Failed commands save up to 64 KiB of combined stdout and stderr as UTF-8 in
`/var/lib/policyops/cd/attempts/<attempt-id>/<key>.log`. Commands run outside
an attempt use `no-attempt`. For commands with parsed stdout, the file groups
the retained bytes by stream. The direct child's exit code determines the
result. The agent closes the pipes after EOF or a quarter-second drain period
following exit, so background descendants can contribute only during that
period. On timeout the tail contains output captured before cleanup finished.
An expired budget before launch or a spawn failure can produce a zero-byte file.
A failed post-activation seed copies the head of its output to stderr, so it appears in the command's tail.

`output_tails` records each file's path relative to `cd`, byte length and
SHA-256. `output_tail_errors` lists commands whose diagnostics could not be
fully saved or pruned. A later failure with the same attempt and key replaces
that file, so check its length and digest against the record before relying on
it. Retention keeps up to 20 attempt directories and 1 MiB of tail files,
pruning the oldest directories by modification time. If needed, it prunes
older logs within the current directory while keeping that directory and its
latest write. Older audit and quarantine records can reference expired files.

The agent strips terminal escape sequences and redacts obvious credential
assignments, Authorization values and PEM blocks. It also redacts a leading
partial line when clipping may have removed its credential label. Tails can
still contain host-local diagnostic text. Root owns the mode-0700 directories
and mode-0600 files. Audit and quarantine records contain metadata only, and
tails stay out of the journal and command stdout.

### Rollback drill and trust

Write root-owned mode-0600 `/var/lib/policyops/cd/drill.json` with `candidate`
(the full green runtime SHA), `fail_stage` (`gate` or `rollback`), and
`expires_at` (an ISO 8601 timestamp with a UTC offset). Use a same-schema
candidate. The matching gate runs normally and the audit records its true
result and a forced failure. A `rollback` drill also forces the first rollback
verdict to fail, then lets the real retry decide whether to freeze. The
instruction is consumed once and applies only to that SHA before expiry.
From an off-host network, run `python -B scripts/deploy_probe.py <hostname> --duration 900`
with Python and curl, and redirect stdout to an external JSONL report. The
report records readiness and release samples, observation gaps, and each SHA's
first and last sightings. Use the readiness series (`/api/v1/health/ready`) to
measure the sampled outage. `/release` tracks release identity. Failures there
before the first sighting of a release that serves the route do not count as
downtime.

During the 2026-11-23 manual baseline deploy, the off-host operator workstation
on the admin network collected 5,400 samples over one hour: 1,800 readiness
samples every 2 seconds and 3,600 release samples every second, with no gaps in
either series. The longest readiness failure window spanned 32 seconds across
17 consecutive failed samples (20:11:59–20:12:31 UTC). The legacy release did not
serve `/release`, which accounts for the 271-second release failure window.

Anyone who can push to `main` controls the root-run release on this demo host.
Protect `main`, require review of workflow and host-control changes, and
disable force pushes. Trust extends to GitHub's control plane, the host's TLS
roots, installed tools and retained images. The agent uses anonymous outbound
HTTPS and the existing host firewall and CI permissions. Revisit host builds
in favor of CI-built, digest-pinned and signed images if live drills show CPU
steal during builds or burst capacity failing to recover between deploys.

## Backup, rollback, retention and teardown

For a private recovery artifact, disable both timers and stop API/worker/retail/Dex
as described in [operations](operations.md#consistent-backup-and-separate-database-restore). Use its stopped-writer
logical dump/restore procedure and role/migration/RLS/receipt checks. Stream dumps out of
the container; `docker cp` cannot read tmpfs. Protect dumps, secrets, Caddy storage and
state under root-only directories; export encrypted backups to an operator-controlled
destination with separately reviewed cost. No automatic paid snapshot or external backup
service is provisioned. For the selected public project, stream a coherent dump on the
host in a root shell (binary redirection here is Bash, not PowerShell text redirection):

```bash
sudo -i
umask 077
base=/var/lib/policyops
systemctl stop policyops-reset.timer policyops-seed.timer
exec 9>"$base/deploy.lock"
flock -w 10 9
cd "$(readlink -f "$base/current")"
export COMPOSE_PROJECT_NAME=policyops-public POLICYOPS_RUN_ID=public-demo
export POLICYOPS_IMAGE_TAG="$(git rev-parse HEAD)" POLICYOPS_HOSTNAME="$(cat "$base/hostname")"
export POLICYOPS_SECRETS_DIR="$base/secrets" POLICYOPS_HTTP_PORT=8080
compose=(docker compose -f compose.yaml -f infra/compose/public.yaml)
backup="$base/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 0700 -p "$backup"
"${compose[@]}" stop worker api retail dex
"${compose[@]}" exec -T postgres pg_dump -U postgres -d policyops -Fc > "$backup/database.dump"
sha256sum "$backup/database.dump" > "$backup/SHA256SUMS"
printf '%s\n' "$POLICYOPS_IMAGE_TAG" > "$backup/commit"
"${compose[@]}" start dex retail api worker
flock -u 9
systemctl start policyops-reset.timer policyops-seed.timer
exit
```

On failure preserve stopped writers and repair/verify before resuming; do not silently
restart after a failed dump. Retain secrets/ACME state separately under root-only access.
Restore into a separate database with the existing operations commands, using **both**
Compose files and the same exported public environment for every command. Stream a dump
back with `docker compose ... exec -T postgres pg_restore -U postgres --exit-on-error
-d policyops_restore_a < /absolute/backup/database.dump`; do not depend on `docker cp`
for tmpfs. Verify schema versions/owners, RLS and receipts before switching the selected
database. Keep all source writers stopped until that decision. Restore is a separate
drill; a backup file alone is not evidence.

On 2026-11-15 the schema-compatible drill deployed A (`3609714`), deployed B
(`5325f72`, documentation only), and rolled back to A's retained images without
rerunning migrations. Each step passed 28/28 verifier checks. This covered a
same-schema image rollback on one host. Schema changes and changes to application
behavior were outside the drill's scope.

The rollback driver records A deploy -> B deploy -> A image rollback with health/auth/
header checks and elapsed time per step. Review schema compatibility first and supply
`--schema-compatible`. It uses strict known-host SSH, and stops at the first failed step.
Timeout means remote work may still run; inspect the host/lock before retrying. A failed
B is retained for diagnosis; inspect state and manually invoke the same script with
`<A> <hostname> --rollback` only after compatibility is confirmed. It uses the exact retained
checkout and images locally and reattaches API to Caddy's new namespace. It skips migrations.
Health checks cannot prove all data/authorization behavior survived rollback; run the
browser/receipt and migration-version checks as well. The script does not promise zero
downtime. **Irreversible migrations cannot be rolled back by an image change.** Keep B
running, deploy a forward fix, or restore a verified coherent backup into a separate
environment after explicitly accepting lost demo writes. Never promise schema downgrade.

Keep current and previous images/checkouts until rollback acceptance and evidence are
sealed; never run global `docker system prune`. Then inventory exact task-owned image IDs
and release directories before removing old versions. Container logs rotate at 2 x 5 MiB
per service. Scenario JSON files are overwritten per commit/nightly/latest; retain only current,
previous and drill evidence. Journald is bounded to 64 MiB persistent / 32 MiB runtime and
seven days; verify with `journalctl --disk-usage`. Demo database retention is
one reset interval. DB certificate renewal retains its key/passwords and happens while
stopped at nightly reset; operator must repair prolonged timer failure before certificate expiry.
Private deployment/verification/drill reports and backup hashes stay external; retain raw
evidence necessary for reviewed claims. After destroy, confirm the instance, static IP,
key-pair resource and budget are gone in the same region/account; inspect billing for
orphaned resources. Local state, plans, SSH key and private evidence are not deleted by
Terraform. Clean exact disposable paths only after preserving the required evidence.
