# Pins and their reviewed tags/contents: infra/images.json. amd64 uv archive, checksum verified.
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
ENV PYTHONDONTWRITEBYTECODE=1 UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv UV_CACHE_DIR=/tmp/uv
ADD --checksum=sha256:c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83 https://github.com/astral-sh/uv/releases/download/0.13.7/uv-x86_64-unknown-linux-gnu.tar.gz /tmp/uv.tar.gz
RUN tar -xzf /tmp/uv.tar.gz -C /tmp && cp /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv
WORKDIR /opt/policyops
COPY pyproject.toml uv.lock ./
COPY packages/ packages/
RUN uv sync --frozen --no-dev --package policyops --no-editable

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 HOME=/tmp
WORKDIR /opt/policyops
COPY --from=build /opt/venv /opt/venv
COPY infra/compose/ infra/compose/
COPY LICENSE THIRD_PARTY_NOTICES.md ./
COPY pyproject.toml uv.lock /usr/share/policyops/
# Immutable source: hash caches avoid mtime dependence; -B still reads these at runtime.
# Include the base stdlib and installed application/dependencies, not just compose helpers.
RUN python -m compileall -q -f --invalidation-mode unchecked-hash /usr/local/lib/python3.12 /opt/venv /opt/policyops
USER 10001:10001
ENTRYPOINT ["python", "-B", "infra/compose/runtime.py"]
CMD ["api"]
