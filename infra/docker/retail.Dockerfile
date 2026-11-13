# Pins and reviewed tags/contents: infra/images.json. No evaluator data enters the runtime layer.
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv UV_CACHE_DIR=/tmp/uv
ADD --checksum=sha256:c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83 https://github.com/astral-sh/uv/releases/download/0.13.7/uv-x86_64-unknown-linux-gnu.tar.gz /tmp/uv.tar.gz
RUN tar -xzf /tmp/uv.tar.gz -C /tmp && cp /tmp/uv-x86_64-unknown-linux-gnu/uv /usr/local/bin/uv
# Git is required only in this stage for the frozen tau2 VCS dependency; never in runtime.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/policyops
COPY packages/ packages/
COPY evals/pyproject.toml evals/uv.lock evals/
COPY evals/src/ evals/src/
COPY evals/migrations/retail/ evals/migrations/retail/
COPY evals/manifests/tau2-19f13ea3/source.json evals/manifests/tau2-19f13ea3/source.json
COPY infra/compose/ infra/compose/
RUN uv sync --project evals --frozen --no-dev && /opt/venv/bin/python -B infra/compose/package_retail.py

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 HOME=/tmp PYTHON_DOTENV_DISABLED=1 LITELLM_LOCAL_MODEL_COST_MAP=True
WORKDIR /opt/policyops
COPY --from=build /opt/venv /opt/venv
# evals lock has editable local paths. Preserve their exact locations, not the uv VCS cache.
COPY --from=build /opt/policyops/packages /opt/policyops/packages
COPY --from=build /opt/policyops/evals/src /opt/policyops/evals/src
COPY --from=build /opt/policyops/evals/migrations /opt/policyops/evals/migrations
COPY --from=build /opt/policyops/evals/manifests /opt/policyops/evals/manifests
COPY --from=build /opt/fixture /opt/fixture
COPY infra/compose/ infra/compose/
COPY LICENSE THIRD_PARTY_NOTICES.md ./
COPY evals/pyproject.toml evals/uv.lock /usr/share/policyops/
USER 10001:10001
ENTRYPOINT ["python", "-B", "infra/compose/runtime.py"]
CMD ["retail"]
