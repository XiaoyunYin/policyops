#!/bin/sh
set -eu
gomplate -f /etc/policyops/dex.yaml.tmpl -o /tmp/dex.yaml
exec dex serve /tmp/dex.yaml
