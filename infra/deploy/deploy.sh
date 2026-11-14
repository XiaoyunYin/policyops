#!/bin/bash
# Run as root over SSH. Values are nonsecret: full commit, DNS hostname, optional --rollback.
set -euo pipefail
umask 077
test "$EUID" -eq 0
commit=${1:?full 40-character commit required}
hostname=${2:?public DNS hostname required}
mode=${3:-deploy}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]
[[ "$hostname" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$ ]]
[[ "$mode" == deploy || "$mode" == --rollback ]]
base=/var/lib/policyops
install -d -m 0700 "$base" "$base/tmp" "$base/releases" "$base/logs"
exec 9>"$base/deploy.lock"
flock -w 10 9
export POLICYOPS_TEMP_DIR="$base" TEMP="$base/tmp" TMP="$base/tmp" TMPDIR="$base/tmp"
export PYTHONDONTWRITEBYTECODE=1
export COMPOSE_PROJECT_NAME=policyops-public POLICYOPS_RUN_ID=public-demo
export POLICYOPS_SECRETS_DIR="$base/secrets" POLICYOPS_HOSTNAME="$hostname"
export POLICYOPS_IMAGE_TAG="$commit" POLICYOPS_HTTP_PORT=8080
# No arbitrary repository URL or mutable ref. Each release is a detached checkout.
release="$base/releases/$commit"
if ! test -d "$release"; then
  git clone https://github.com/XiaoyunYin/policyops.git "$release"
fi
git -C "$release" fetch origin "$commit"
git -C "$release" checkout --detach "$commit"
test "$(git -C "$release" rev-parse HEAD)" = "$commit"
test -z "$(git -C "$release" status --porcelain)"
# Clone runs with private umask; non-root containers must read these public bind-mounted sources.
chmod -R a+rX "$release"
cd "$release"
compose=(docker compose -f compose.yaml -f infra/compose/public.yaml)
if test -f "$base/hostname"; then test "$(cat "$base/hostname")" = "$hostname"; fi
if test "$mode" == --rollback; then
  # Rollback is image/config only. Never rerun migrations from old source or downgrade schema.
  for image in app retail web; do docker image inspect "policyops-$image:$commit" >/dev/null; done
else
  # Build serially; parallel builds can exhaust the 2 GB host. No provider keys forwarded.
  export COMPOSE_PARALLEL_LIMIT=1
  for service in api retail caddy; do "${compose[@]}" build "$service"; done
fi
if ! test -d "$POLICYOPS_SECRETS_DIR"; then
  # Reuse the frozen app image for cryptography; no host Python package installation.
  docker run --rm --user 0:0 --entrypoint python \
    -e POLICYOPS_TEMP_DIR="$base" -e POLICYOPS_SECRETS_DIR="$POLICYOPS_SECRETS_DIR" \
    -e POLICYOPS_RUN_ID -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$base:$base" -v "$release:/source:ro" \
    "policyops-app:$commit" -B /source/scripts/compose_secrets.py
  # Intentional public fictional credentials, never reused as database/client credentials.
  for name in alice bob carol; do
    printf 'PolicyOps-public-demo-%s' "$name" > "$POLICYOPS_SECRETS_DIR/$name"
    chmod 0444 "$POLICYOPS_SECRETS_DIR/$name"
  done
fi
chmod 0700 "$POLICYOPS_SECRETS_DIR"
install -d -o 10001 -g 10001 -m 0700 "$base/caddy-data" "$base/caddy-config"
printf '%s\n' "$hostname" > "$base/hostname"
# Remove API before replacing Caddy's shared namespace; preserve volume and secrets.
"${compose[@]}" stop worker api
"${compose[@]}" rm -f api
if test "$mode" == --rollback; then
  "${compose[@]}" up -d --no-build --no-deps --force-recreate postgres dex retail caddy
  "${compose[@]}" up -d --no-build --no-deps api worker
else
  "${compose[@]}" up -d --no-build --force-recreate --wait --wait-timeout 360
fi
# Valid CA chain/hostname required; retry startup/ACME without printing response bodies or cookies.
ready=0
for ((attempt=0; attempt<90; attempt++)); do
  if curl --fail --silent --show-error --max-time 5 "https://$hostname/api/v1/health/ready" > /dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
test "$ready" -eq 1
if test "$mode" != --rollback; then
  # This creates a presented deterministic proposal, never consent, approval, or a receipt.
  "${compose[@]}" exec -T worker python -B infra/compose/scenario.py seed > "$base/logs/scenario-$commit.json"
fi
if test -L "$base/current"; then readlink "$base/current" > "$base/previous-release"; fi
ln -sfn "$release" "$base/current"
install -m 0755 infra/deploy/reset.sh /usr/local/sbin/policyops-demo-reset
install -m 0755 infra/deploy/seed.sh /usr/local/sbin/policyops-demo-seed
install -m 0644 infra/deploy/policyops-reset.service infra/deploy/policyops-reset.timer \
  infra/deploy/policyops-seed.service infra/deploy/policyops-seed.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now policyops-reset.timer policyops-seed.timer
printf 'Healthy release %s (%s)\n' "$commit" "$mode"
