#!/bin/bash
# Run as root, either manually or under the installed CD agent.
set -euo pipefail
umask 077
test "$EUID" -eq 0
base=/var/lib/policyops
if [[ "${1:-}" = --build-only || "${1:-}" = --checkout-only ]]; then
  mode=$1
  commit=${2:?full 40-character commit required}
  hostname=$(cat "$base/hostname")
else
  commit=${1:?full 40-character commit required}
  hostname=${2:?public DNS hostname required}
  mode=${3:-deploy}
  if [[ "$mode" = --candidate && "${4:-}" = --allow-schema ]]; then mode=--candidate-schema; fi
fi
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]
[[ "$hostname" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$ ]]
case "$mode" in
  deploy|--rollback|--checkout-only|--build-only|--candidate|--candidate-schema|--describe|--soak) ;;
  *) exit 2 ;;
esac
if [[ "$mode" == deploy || "$mode" == --build-only || "$mode" == --checkout-only ]]; then
  install -d -m 0700 "$base" "$base/tmp" "$base/releases" "$base/logs"
fi
inherited=0
if test /proc/self/fd/9 -ef "$base/deploy.lock"; then
  flock -n 9
  inherited=1
else
  exec 9>"$base/deploy.lock"
  flock -w 10 9
fi
case "$mode" in --candidate*|--checkout-only|--describe|--soak) test "$inherited" -eq 1 ;; esac
export POLICYOPS_TEMP_DIR="$base" TEMP="$base/tmp" TMP="$base/tmp" TMPDIR="$base/tmp"
export PYTHONDONTWRITEBYTECODE=1
export COMPOSE_PROJECT_NAME=policyops-public POLICYOPS_RUN_ID=public-demo
export POLICYOPS_SECRETS_DIR="$base/secrets" POLICYOPS_HOSTNAME="$hostname"
export POLICYOPS_IMAGE_TAG="$commit" POLICYOPS_HTTP_PORT=8080
# No arbitrary repository URL or mutable ref. Each release is a detached checkout.
release="$base/releases/$commit"
tool_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ "$mode" = deploy || ( "$mode" = --build-only && "$inherited" -eq 0 ) ]]; then
  if ! test -d "$release"; then
    git clone https://github.com/XiaoyunYin/policyops.git "$release"
  fi
  git -C "$release" fetch origin "$commit"
  git -C "$release" checkout --detach "$commit"
elif [[ "$mode" = --checkout-only || "$mode" = --build-only ]] && ! test -d "$release"; then
  # The agent has already fetched and authenticated this commit in the bare mirror.
  checkout=$(mktemp -d "$base/tmp/release-$commit.XXXXXX")
  trap 'rm -rf -- "$checkout"' EXIT
  git clone --no-local --no-checkout "$base/cd/repo.git" "$checkout"
  git -C "$checkout" checkout --detach "$commit"
  git -C "$checkout" remote set-url origin https://github.com/XiaoyunYin/policyops.git
  mv -T "$checkout" "$release"
  trap - EXIT
fi
test "$(git -C "$release" rev-parse HEAD)" = "$commit"
test -z "$(git -C "$release" status --porcelain)"
if [[ "$mode" = deploy || "$mode" = --build-only || "$mode" = --checkout-only ]]; then chmod -R a+rX "$release"; fi
if test "$mode" = --checkout-only; then exit 0; fi
cd "$release"
compose=(docker compose -f compose.yaml -f infra/compose/public.yaml)
if test -f "$base/hostname"; then test "$(cat "$base/hostname")" = "$hostname"; fi
if [[ "$mode" == deploy || "$mode" == --build-only ]]; then
  checker="$tool_dir/cd_agent.py"
  if ! test -f "$checker"; then checker="$tool_dir/policyops-cd"; fi
  "${compose[@]}" --profile '*' config --format json | python3 -B "$checker" _check-build "$commit"
  # Build serially; parallel builds can exhaust the 2 GB host. No provider keys forwarded.
  export COMPOSE_PARALLEL_LIMIT=1
  for service in api retail caddy; do "${compose[@]}" build "$service" || exit 1; done
fi
if test "$mode" = --build-only; then exit 0; fi
if test "$mode" = --describe; then exec "${compose[@]}" --profile '*' config --format json; fi

core=(postgres dex retail caddy)
app=(api worker)
services=("${core[@]}" "${app[@]}")
public_ready() {
  local status options=()
  if test "$inherited" -eq 1; then options=(--disable --noproxy '*'); fi
  status=$(curl "${options[@]}" "$@" --silent --show-error --max-time 5 --output /dev/null \
    --write-out '%{http_code}' "https://$hostname/api/v1/health/ready") && test "$status" = 200
}
if test "$mode" = --soak; then
  declare -A expected initial
  shift 3
  test "$#" -eq "${#services[@]}"
  for service in "${services[@]}"; do
    [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
    expected[$service]=$1
    shift
  done
  for ((probe=1; probe<=6; probe++)); do
    if public_ready --resolve "$hostname:443:127.0.0.1"; then echo readiness; else echo '!readiness'; fi
    for service in "${services[@]}"; do
      containers=()
      if ids=$(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
        --filter "label=com.docker.compose.service=$service") && test -n "$ids"; then
        mapfile -t containers <<< "$ids"
      fi
      snapshot=''
      if test "${#containers[@]}" -gt 0; then
        snapshot=$(docker inspect -f '{{.State.Status}} {{.RestartCount}} {{.State.OOMKilled}} {{.Image}} {{.Id}}' \
          -- "${containers[@]}") || snapshot=''
      fi
      read -r status count oom running id <<< "$snapshot"
      if test "$probe" -eq 1; then initial[$service]="$id:$count"; fi
      if [[ "${#containers[@]}" -eq 1 && "$status" = running && "$id:$count" = "${initial[$service]}" && "$oom" = false &&
            "$running" = "${expected[$service]}" ]]; then
        echo "$service"
      else
        echo "!$service"
      fi
    done
    if test "$probe" -lt 6; then sleep 30; fi
  done
  exit 0
fi

if test "$mode" = --candidate; then
  # Inspect the revision graph in each built image. Read the installed revision tables
  # in the existing postgres container using its private Unix socket.
  check_head() {
    local head current
    head=$(docker run --rm --pull never --network none --read-only --cap-drop ALL \
      --entrypoint python "policyops-$1:$commit" -B -c "from $2 import head; print(head())")
    current=$("${compose[@]}" exec -T -e PGOPTIONS='-c default_transaction_read_only=on' postgres \
      psql -X -A -t -v ON_ERROR_STOP=1 -U postgres -d "${POLICYOPS_DATABASE:-policyops}" \
      -c "SELECT version_num FROM $3")
    test -n "$head" && test "$head" = "$current"
  }
  check_head app policyops.persistence.migrate public.policyops_app_alembic_version
  check_head retail policyops_evals.retail_sim.migrate retail.alembic_version
fi
if [[ "$mode" == --candidate* ]]; then
  "${compose[@]}" pull --policy missing postgres dex
fi
if [[ "$mode" = --rollback && "$inherited" -eq 1 ]]; then
  # Override the runtime images with the immutable IDs recorded by the passing healthy gate.
  shift 3
  test "$#" -eq "${#services[@]}"
  for image in "$@"; do
    [[ "$image" =~ ^sha256:[0-9a-f]{64}$ ]]
    docker image inspect -- "$image" >/dev/null
  done
  override=$(mktemp "$base/tmp/rollback-images.XXXXXX.json")
  trap 'rm -f -- "$override"' EXIT
  python3 -B -c '
import json
import sys

names = sys.argv[1:]
count = len(names) // 2
print(json.dumps({"services": {name: {"image": image} for name, image in zip(names[:count], names[count:])}}))
' "${services[@]}" "$@" > "$override"
  compose+=(-f "$override")
elif test "$mode" != deploy; then
  images=$("${compose[@]}" config --images)
  while IFS= read -r image; do docker image inspect -- "$image" >/dev/null; done <<< "$images"
fi
if ! test -d "$POLICYOPS_SECRETS_DIR"; then
  test "$mode" = deploy
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
  # Image/config only. Both pinned dependency images must already be local.
  "${compose[@]}" up -d --no-build --pull never --no-deps --force-recreate "${core[@]}"
  "${compose[@]}" up -d --no-build --pull never --no-deps "${app[@]}"
  if test "$inherited" -eq 1; then
    rm -f -- "$override"
    trap - EXIT
    compose=(docker compose -f compose.yaml -f infra/compose/public.yaml)
  fi
elif test "$mode" = --candidate; then
  # The agent owns the deadline and distinguishes a timeout from a Compose failure.
  "${compose[@]}" up -d --no-build --pull never --no-deps --force-recreate --wait "${core[@]}"
  "${compose[@]}" up -d --no-build --pull never --no-deps --wait "${app[@]}"
else
  "${compose[@]}" up -d --no-build --force-recreate --wait --wait-timeout 360
fi
# Valid CA chain/hostname required; retry startup/ACME without printing response bodies or cookies.
ready=0
for ((attempt=0; attempt<90; attempt++)); do
  if test "$inherited" -eq 1; then
    public_ready --resolve "$hostname:443:127.0.0.1" || echo "Loopback readiness probe failed" >&2
  fi
  if public_ready; then
    ready=1; break
  fi
  sleep 2
done
test "$ready" -eq 1
if [[ "$mode" != --rollback || "$inherited" -eq 1 ]]; then
  # This creates a presented deterministic proposal, never consent, approval, or a receipt.
  seed=$(mktemp "$base/logs/.scenario-$commit.XXXXXX")
  trap 'rm -f -- "$seed"' EXIT
  if "${compose[@]}" exec -T worker python -B infra/compose/scenario.py seed > "$seed"; then
    sync -f "$seed"
    mv -f "$seed" "$base/logs/scenario-$commit.json"
    sync -f "$base/logs"
    trap - EXIT
  else
    seed_status=$?
    printf '%s\n' 'Demo seed failed; first 4 KiB of its output:' >&2
    head -c 4096 -- "$seed" >&2
    exit "$seed_status"
  fi
fi
if [[ "$mode" != deploy && "$inherited" -eq 1 ]]; then exit 0; fi
if test -L "$base/current"; then readlink "$base/current" > "$base/previous-release"; fi
ln -sfn "$release" "$base/current"
install -m 0755 infra/deploy/reset.sh /usr/local/sbin/policyops-demo-reset
install -m 0755 infra/deploy/seed.sh /usr/local/sbin/policyops-demo-seed
install -m 0644 infra/deploy/policyops-reset.service infra/deploy/policyops-reset.timer \
  infra/deploy/policyops-seed.service infra/deploy/policyops-seed.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now policyops-reset.timer policyops-seed.timer
printf 'Healthy release %s (%s)\n' "$commit" "$mode"
