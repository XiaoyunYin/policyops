#!/bin/bash
# Destructive reset of this one fictional demo only. No other Docker project or TLS state is removed.
set -euo pipefail
umask 077
base=/var/lib/policyops
records="$base/cd"
progress="$records/reset-progress"
pending="$records/reset-pending"
missed_file="$records/reset-missed"
completed="$records/reset-completed"
today=$(date -u +%F)
resume=${1:-}
[[ "$#" -eq 0 || ( "$#" -eq 1 && "$resume" = --resume ) ]]
install -d -m 0700 "$records" "$completed"
exec 8>>"$records/reset-records.lock"
valid_id() { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}(-[0-9a-f]{32})?$ ]]; }
write_record() {
  local path=$1 tmp
  shift
  tmp="${path%/*}/.${path##*/}"
  printf '%s\n' "$*" > "$tmp"
  sync -f "$tmp"
  mv -f "$tmp" "$path"
  sync -f "${path%/*}"
}
read_missed() {
  request=
  if test -f "$missed_file"; then
    if test -s "$missed_file"; then
      read -r request < "$missed_file"
    else
      # Round 2 used an empty marker. Use the UTC date of that request.
      request="$(date -u -r "$missed_file" +%F)-$(python3 -B -c 'import uuid; print(uuid.uuid4().hex)')"
      write_record "$missed_file" "$request"
    fi
    valid_id "$request"
    if test -f "$completed/$request"; then request=; fi
  fi
}
completed_today() { compgen -G "$completed/$today*" >/dev/null; }
mark_missed() {
  read_missed
  local underway=''
  if test -f "$progress"; then read -r underway _ < "$progress"; fi
  if [[ -z "$request" && "${underway:0:10}" != "$today" ]] && ! completed_today; then
    write_record "$missed_file" "$today-$(python3 -B -c 'import uuid; print(uuid.uuid4().hex)')"
  fi
}
missed() {
  if test -z "$resume"; then
    flock -w 10 8
    mark_missed
  fi
  echo "PolicyOps reset deferred: $1" >&2
  exit 1
}
if test /proc/self/fd/9 -ef "$base/deploy.lock"; then
  flock -n 9 || missed lock
else
  test -z "$resume"
  exec 9>>"$base/deploy.lock"
  flock -w 10 9 || missed lock
fi
if test -e "$base/cd/frozen"; then missed frozen; fi
if test -e "$base/cd/active"; then missed active; fi
cd "$(readlink -f "$base/current")"
export COMPOSE_PROJECT_NAME=policyops-public POLICYOPS_RUN_ID=public-demo
export POLICYOPS_TEMP_DIR="$base" TEMP="$base/tmp" TMP="$base/tmp" TMPDIR="$base/tmp"
export PYTHONDONTWRITEBYTECODE=1
export POLICYOPS_IMAGE_TAG="$(git rev-parse HEAD)" POLICYOPS_HOSTNAME="$(cat "$base/hostname")"
export POLICYOPS_SECRETS_DIR="$base/secrets" POLICYOPS_HTTP_PORT=8080
[[ "$POLICYOPS_IMAGE_TAG" =~ ^[0-9a-f]{40}$ ]]
compose=(docker compose -f compose.yaml -f infra/compose/public.yaml)
flock -w 10 8
if test -f "$pending" && ! test -f "$progress"; then
  if test -z "$resume"; then mark_missed; fi
  exit 0
fi
if test -f "$progress"; then
  read -r reset_id release step extra < "$progress"
  valid_id "$reset_id"
  [[ "$release" = "$POLICYOPS_IMAGE_TAG" && -z "$extra" ]]
  case "$step" in
    started|volume_owned|volume_deleted|cert_renewed|stack_started|seeded) ;;
    *) exit 1 ;;
  esac
  if test -f "$completed/$reset_id"; then
    test "$step" = seeded
    test "$(cat "$completed/$reset_id")" = "$reset_id $release"
  fi
else
  read_missed
  if test -z "$request" && { test -n "$resume" || completed_today; }; then exit 0; fi
  reset_id=${request:-$today}
  step=started
  write_record "$progress" "$reset_id" "$POLICYOPS_IMAGE_TAG" "$step"
fi
flock -u 8
advance() {
  step=$1
  write_record "$progress" "$reset_id" "$POLICYOPS_IMAGE_TAG" "$step"
}

volume=policyops-public_pgdata
if [[ "$step" = started || "$step" = volume_owned ]]; then
  volumes=$(docker volume ls -q --filter "name=$volume")
  if grep -Fxq -- "$volume" <<< "$volumes"; then
    # Names can be reused. Check all labels even when resuming with the volume present.
    project=$(docker volume inspect -f '{{index .Labels "com.docker.compose.project"}}' "$volume")
    run=$(docker volume inspect -f '{{index .Labels "policyops.run"}}' "$volume")
    owner=$(docker volume inspect -f '{{index .Labels "policyops.owner"}}' "$volume")
    [[ "$project" = policyops-public && "$run" = public-demo && "$owner" = policyops-compose ]]
    advance volume_owned
    "${compose[@]}" down --remove-orphans
    docker volume rm "$volume"
  else
    # A retry after removal may see the volume already gone.
    test "$step" = volume_owned
  fi
  advance volume_deleted
fi
if test "$step" = volume_deleted; then
  # Renew the 30-day certificate with the same key and passwords.
  docker run --rm --user 0:0 --entrypoint python -v "$base/secrets:/secrets" \
    -v "$PWD/infra/deploy/renew_db_cert.py:/renew.py:ro" "policyops-app:$POLICYOPS_IMAGE_TAG" -B /renew.py
  sync -f "$base/secrets"
  advance cert_renewed
fi
if test "$step" = cert_renewed; then
  "${compose[@]}" up -d --no-build --wait --wait-timeout 360
  advance stack_started
fi
if test "$step" = stack_started; then
  "${compose[@]}" exec -T worker python -B infra/compose/scenario.py seed > "$base/logs/scenario-nightly.json"
  printf '0\n' > "$base/periodic-seed-count"
  sync -f "$base/logs/scenario-nightly.json" "$base/periodic-seed-count"
  advance seeded
fi

# Keep seeded progress until pending is published so an interrupted publication can resume.
flock -w 10 8
write_record "$completed/$reset_id" "$reset_id" "$POLICYOPS_IMAGE_TAG"
if test -f "$missed_file" && test "$(cat "$missed_file")" = "$reset_id"; then
  rm -f "$missed_file"
  sync -f "$records"
fi
write_record "$pending" "$reset_id" "$POLICYOPS_IMAGE_TAG"
rm -f "$progress"
sync -f "$records"
