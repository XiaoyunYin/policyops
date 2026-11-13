#!/bin/sh
set -eu
# The image's postgres UID is 999 on this Debian pin. The service already runs as it.
# Compose file secrets may ignore uid/mode on local bind mounts; copy to private tmpfs.
cp /run/secrets/postgres_tls_key /tmp/server.key
cp /run/secrets/postgres_tls_cert /tmp/server.crt
chmod 600 /tmp/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_key_file=/tmp/server.key -c ssl_cert_file=/tmp/server.crt -c log_statement=none
