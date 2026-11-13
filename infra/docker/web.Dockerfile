# Pins and reviewed tags/contents: infra/images.json.
FROM node@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS build
ENV npm_config_cache=/tmp/npm POLICYOPS_WEB_BUILD_DIR=/opt/bundle POLICYOPS_WEB_CACHE_DIR=/tmp/vite
WORKDIR /opt/policyops/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
# Vite/esbuild use their platform packages; no lifecycle scripts are required.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY apps/web/ ./
COPY packages/policyops_contracts/ /opt/policyops/packages/policyops_contracts/
RUN npm run build
COPY infra/compose/web_notices.mjs /opt/web_notices.mjs
RUN node /opt/web_notices.mjs

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS scan
WORKDIR /opt/policyops
COPY scripts/check_bundle.py scripts/check_publication.py scripts/
COPY --from=build /opt/bundle /opt/bundle
RUN python -B scripts/check_bundle.py --bundle /opt/bundle

FROM caddy@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5 AS runtime
# High-port listener needs no file capabilities. A file-capability binary cannot
# exec with cap_drop ALL + no-new-privileges; fail the build if any remain.
RUN apk add --no-cache libcap-utils \
    && setcap -r /usr/bin/caddy \
    && capabilities="$(getcap /usr/bin/caddy)" \
    && test -z "$capabilities"
COPY --from=scan /opt/bundle /srv
COPY --from=build /opt/web-notices /usr/share/policyops/web-notices
COPY apps/web/package-lock.json /usr/share/policyops/web-package-lock.json
COPY infra/caddy/Caddyfile /etc/caddy/Caddyfile
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/policyops/
USER 10001:10001
ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
