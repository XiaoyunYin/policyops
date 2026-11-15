# AWS public fictional demo

Status: **verified PostgreSQL TLS repair awaiting live verification**. The first
2026-11-15 Lightsail attempt exposed launch-script handling of user-data and a shared
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
The source repair below still needs the PostgreSQL integration suite and local/public
Compose smoke, including renewal. Public login, host sizing and rollback remain live gates.

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
ssh -i $key @sshOptions "ubuntu@$ip" 'sudo install -m 0755 /home/ubuntu/policyops-deploy /usr/local/sbin/policyops-deploy'
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
  HTTPS, denial for Carol/foreign tenant, API 429 behavior, reboot, nightly reset, backup
  restore and the A/B/A drill. Static tests do not establish these composed behaviors.
- Verify correct auto-renewal state and retain Caddy storage. sslip.io/DNS/ACME availability
  and issuance rate limits are external dependencies. An owned domain is optional; set
  `hostname` before initial seeding and point its A record to the static IP. Changing an
  existing issuer requires a fresh disposable volume and new sessions.

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

The rollback driver records A deploy -> B deploy -> A image rollback with health/auth/
header checks and elapsed time per step. Review schema compatibility first and supply
`--schema-compatible`. It uses strict known-host SSH, and stops at the first failed step.
Timeout means remote work may still run; inspect the host/lock before retrying. A failed
B is retained for diagnosis; inspect state and manually invoke the same script with
`<A> <hostname> --rollback` only after compatibility is confirmed. It uses retained images,
does not build or execute older migrations, and reattaches API to Caddy's new namespace.
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
