#!/bin/bash
# Proposals expire by design; keep a recent fictional case available without granting any consent.
set -euo pipefail
umask 077
base=/var/lib/policyops
exec 9>"$base/deploy.lock"
flock -w 10 -E 75 9 || {
  status=$?
  if test "$status" -eq 75; then
    printf '%s\n' 'Demo seed skipped: a deploy holds the lock.' >&2
    exit 0
  fi
  exit "$status"
}
if test -e "$base/cd/frozen" || test -e "$base/cd/active"; then exit 0; fi
cd "$(readlink -f "$base/current")"
export COMPOSE_PROJECT_NAME=policyops-public POLICYOPS_RUN_ID=public-demo
export POLICYOPS_TEMP_DIR="$base" TEMP="$base/tmp" TMP="$base/tmp" TMPDIR="$base/tmp"
export PYTHONDONTWRITEBYTECODE=1
export POLICYOPS_IMAGE_TAG="$(git rev-parse HEAD)" POLICYOPS_HOSTNAME="$(cat "$base/hostname")"
export POLICYOPS_SECRETS_DIR="$base/secrets" POLICYOPS_HTTP_PORT=8080
count=$(cat "$base/periodic-seed-count" 2>/dev/null || printf 0)
[[ "$count" =~ ^[0-9]{1,3}$ ]] && test "$count" -lt 300
docker compose -f compose.yaml -f infra/compose/public.yaml exec -T worker \
  python -B infra/compose/scenario.py seed > "$base/logs/scenario-latest.json"
printf '%s\n' "$((count + 1))" > "$base/periodic-seed-count"
