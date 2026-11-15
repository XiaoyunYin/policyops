#!/bin/sh
# Container-only drill clients: explicit pinned TLS; password never enters argv or output.
set -eu
test "${POLICYOPS_DB_SSLMODE:-}" = verify-full
test "${POLICYOPS_DB_SSLROOTCERT:-}" = /run/secrets/postgres_tls_cert
test "$#" = 2
operation=$1
database=$2
case "$database" in ''|*[!a-zA-Z0-9_]*|[0-9]*) exit 2 ;; esac
test "${#database}" -le 63
# env -i removes every ambient libpq option. Read the password inside the clean child shell, never env's argv.
run() {
  exec env -i PATH="$PATH" sh -ec 'PGPASSWORD=$(cat /run/secrets/postgres); export PGPASSWORD; exec "$@"' \
    postgres-client "$@"
}
conninfo="host=postgres port=5432 user=postgres dbname=$database sslmode=$POLICYOPS_DB_SSLMODE sslrootcert=$POLICYOPS_DB_SSLROOTCERT gssencmode=disable require_auth=scram-sha-256 connect_timeout=3"
case "$operation" in
  dump)
    run pg_dump --no-password --dbname="$conninfo" \
      -Fc -f /tmp/policyops-drill.dump
    ;;
  create)
    # CREATE DATABASE cannot run inside a transaction; psql executes the two -c commands separately.
    conninfo="host=postgres port=5432 user=postgres dbname=postgres sslmode=$POLICYOPS_DB_SSLMODE sslrootcert=$POLICYOPS_DB_SSLROOTCERT gssencmode=disable require_auth=scram-sha-256 connect_timeout=3"
    run psql --no-password --dbname="$conninfo" -X -v ON_ERROR_STOP=1 \
      -c "CREATE DATABASE $database OWNER policyops_app_migrator TEMPLATE template0" \
      -c "REVOKE ALL ON DATABASE $database FROM PUBLIC; GRANT CONNECT ON DATABASE $database TO policyops_app_runtime,policyops_auth_runtime,policyops_eval_runtime,policyops_worker_discovery,retail_migrator,retail_runtime"
    ;;
  restore)
    run pg_restore --no-password --dbname="$conninfo" \
      --exit-on-error /tmp/policyops-drill.dump
    ;;
  *) exit 2 ;;
esac
