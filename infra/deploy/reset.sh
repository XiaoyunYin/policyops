#!/bin/bash
# Destructive reset of this one fictional demo only. No other Docker project or TLS state is removed.
set -euo pipefail
umask 077
base=/var/lib/policyops
exec 9>"$base/deploy.lock"
flock -w 10 9
cd "$(readlink -f "$base/current")"
export COMPOSE_PROJECT_NAME=policyops-public POLICYOPS_RUN_ID=public-demo
export POLICYOPS_TEMP_DIR="$base" TEMP="$base/tmp" TMP="$base/tmp" TMPDIR="$base/tmp"
export PYTHONDONTWRITEBYTECODE=1
export POLICYOPS_IMAGE_TAG="$(git rev-parse HEAD)" POLICYOPS_HOSTNAME="$(cat "$base/hostname")"
export POLICYOPS_SECRETS_DIR="$base/secrets" POLICYOPS_HTTP_PORT=8080
compose=(docker compose -f compose.yaml -f infra/compose/public.yaml)
# Verify ownership before deleting a persistent volume; a name alone is insufficient.
volume=policyops-public_pgdata
test "$(docker volume inspect -f '{{index .Labels "com.docker.compose.project"}}' "$volume")" = policyops-public
test "$(docker volume inspect -f '{{index .Labels "policyops.run"}}' "$volume")" = public-demo
test "$(docker volume inspect -f '{{index .Labels "policyops.owner"}}' "$volume")" = policyops-compose
"${compose[@]}" down --remove-orphans
docker volume rm "$volume"
# compose_secrets.py issues a 30-day self-signed DB certificate; renew with the SAME key/passwords.
docker run --rm --user 0:0 --entrypoint python -v "$base/secrets:/secrets" \
  -v "$PWD/infra/deploy/renew_db_cert.py:/renew.py:ro" "policyops-app:$POLICYOPS_IMAGE_TAG" -B /renew.py
# postgres.sh copies the certificate on startup. No live writer spans the reset.
"${compose[@]}" up -d --no-build --wait --wait-timeout 360
"${compose[@]}" exec -T worker python -B infra/compose/scenario.py seed > "$base/logs/scenario-nightly.json"
printf '0\n' > "$base/periodic-seed-count"
