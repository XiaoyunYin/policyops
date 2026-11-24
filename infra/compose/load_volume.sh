#!/bin/sh
# The PostgreSQL image runs this hook only during initialization of an empty PGDATA.
(
    set -eu
    marker="n10-volume-v1 $POLICYOPS_N10_RUN_ID $POLICYOPS_N10_TOKEN_SHA256"
    marker="$marker $POLICYOPS_N10_ISSUER $POLICYOPS_N10_DATABASE"
    PGHOST= PGHOSTADDR= psql -Xw --username "$POSTGRES_USER" --dbname postgres \
        --set=ON_ERROR_STOP=1 --set=marker="$marker" <<'SQL'
COMMENT ON DATABASE postgres IS :'marker';
SQL
)
