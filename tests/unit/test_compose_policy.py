"""Offline deployment-policy checks against actual Compose and Dockerfile contents."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import sys
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.check_build_context import check_context, included, parse_rules
from scripts.compose_smoke import SmokeError, check_networks, check_ownership, check_ports


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = {"api", "worker", "retail", "dex", "caddy", "postgres"}
CHAIN = {"bootstrap-app": ("postgres", "service_healthy"),
         "migrate-app": ("bootstrap-app", "service_completed_successfully"),
         "bootstrap-retail": ("migrate-app", "service_completed_successfully"),
         "migrate-retail": ("bootstrap-retail", "service_completed_successfully"),
         "seed-demo": ("migrate-retail", "service_completed_successfully")}


def compose() -> dict[str, Any]:
    result: dict[str, Any] = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    return result


def secret_names(service: dict[str, Any]) -> set[str]:
    return {value if isinstance(value, str) else value["source"] for value in service.get("secrets", [])}


def enforce(stack: dict[str, Any]) -> None:
    pins = json.loads((ROOT / "infra/images.json").read_bytes())["images"]
    allowed_images = {f"{value['image']}@{value['digest']}" for value in pins.values()}
    services = stack["services"]
    assert set(services) == RUNTIME | CHAIN.keys()
    published = [(name, port) for name, service in services.items() for port in service.get("ports", [])]
    assert published == [("caddy", "127.0.0.1:${POLICYOPS_HTTP_PORT:-8080}:${POLICYOPS_HTTP_PORT:-8080}")]
    assert stack["networks"]["default"]["internal"] is True
    assert set(stack["networks"]) == {"default", "edge"}
    assert stack["networks"]["edge"]["internal"] is False
    assert services["api"]["network_mode"] == "service:caddy"
    for name, service in services.items():
        if name == "api":
            assert "networks" not in service
        else:
            assert "network_mode" not in service
            assert service.get("networks", ["default"]) == (["default", "edge"] if name == "caddy" else ["default"])
        assert re.fullmatch(r"[1-9]\d*:[1-9]\d*", service["user"]), "non-root numeric UID/GID required"
        assert service["read_only"] is True
        assert service["tmpfs"] and all(mount.startswith("/") and ":uid=" in mount and ",gid=" in mount
                                        and ",mode=" in mount for mount in service["tmpfs"]), "invalid tmpfs mount"
        assert service["cap_drop"] == ["ALL"] and service["security_opt"] == ["no-new-privileges:true"]
        assert service["stop_grace_period"].endswith("s")
        assert service.get("privileged") is None and "pid" not in service and "devices" not in service
        assert service.get("network_mode") in (None, "service:caddy")
        assert "env_file" not in service
        assert not service.get("build", {}).get("args"), "build args are not a secret channel"
        assert all(not re.search(r"PASSWORD|TOKEN|SECRET|KEY|DATABASE_URL", key, re.I) or key.upper().endswith("_FILE")
                   for key in service.get("environment", {})), "secret environment value"
        assert all(str(value).startswith("/run/secrets/") for key, value in service.get("environment", {}).items()
                   if key.upper().endswith("_FILE")), "file-secret setting must be a mounted path"
        assert not any("/var/run/docker.sock" in value for value in service.get("volumes", []))
        if "build" in service:
            assert service["build"]["context"] == "."
            assert service["build"]["dockerfile"] in {
                "infra/docker/app.Dockerfile", "infra/docker/web.Dockerfile", "infra/docker/retail.Dockerfile"}
        else:
            assert service["image"] in allowed_images, "unreviewed base image"
        if name in RUNTIME:
            assert service["healthcheck"]["test"] and service["healthcheck"]["timeout"]
            assert not (secret_names(service) & {"policyops_app_migrator", "retail_migrator"})
            if name != "postgres":
                assert "postgres" not in secret_names(service), "runtime got superuser credential"
        else:
            parent, condition = CHAIN[name]
            assert service["depends_on"] == {parent: {"condition": condition}}
            assert service["restart"] == "no"
    assert secret_names(services["api"]) == {
        "policyops_auth_runtime", "policyops_app_runtime", "client_secret", "postgres_tls_cert"}
    assert secret_names(services["worker"]) == {
        "policyops_app_runtime", "policyops_worker_discovery", "retail_key", "postgres_tls_cert"}
    assert secret_names(services["retail"]) == {"retail_runtime", "retail_key", "postgres_tls_cert"}
    assert secret_names(services["migrate-app"]) == {"policyops_app_migrator", "postgres_tls_cert"}
    assert secret_names(services["migrate-retail"]) == {"retail_migrator", "postgres_tls_cert"}
    assert services["retail"]["depends_on"]["migrate-retail"]["condition"] == "service_completed_successfully"
    assert services["api"]["depends_on"]["retail"]["condition"] == "service_healthy"
    assert services["api"]["depends_on"]["seed-demo"]["condition"] == "service_completed_successfully"
    assert services["worker"]["depends_on"]["api"]["condition"] == "service_healthy"
    for value in stack["secrets"].values():
        assert set(value) == {"file"} and value["file"].startswith("${POLICYOPS_SECRETS_DIR:?")


def test_compose_policy() -> None:
    enforce(compose())


@pytest.mark.parametrize("kind", ["port", "binding", "root", "environment", "migration_secret", "build_arg",
                                  "health", "ordering", "image", "superuser", "network", "edge_internal",
                                  "retail_edge", "oneshot_edge", "worker_host", "api_networks", "caddy_internal_only"])
def test_policy_rejects_unsafe_changes(kind: str) -> None:
    stack = deepcopy(compose())
    service = stack["services"]["api"]
    if kind == "port":
        service["ports"] = ["8000:8000"]
    elif kind == "binding":
        stack["services"]["caddy"]["ports"] = ["0.0.0.0:8080:8080"]
    elif kind == "root":
        service["user"] = "0:0"
    elif kind == "environment":
        service["environment"]["POLICYOPS_DB_APP_PASSWORD"] = "unsafe-literal"
    elif kind == "migration_secret":
        service["secrets"].append("policyops_app_migrator")
    elif kind == "build_arg":
        service["build"]["args"] = {"KEY": "unsafe-literal"}
    elif kind == "health":
        del service["healthcheck"]
    elif kind == "ordering":
        stack["services"]["migrate-retail"]["depends_on"] = {"postgres": {"condition": "service_started"}}
    elif kind == "image":
        stack["services"]["dex"]["image"] = "ghcr.io/dexidp/dex:latest"
    elif kind == "superuser":
        service["secrets"].append("postgres")
    elif kind == "network":
        stack["networks"]["default"]["internal"] = False
    elif kind == "edge_internal":
        stack["networks"]["edge"]["internal"] = True
    elif kind in {"retail_edge", "oneshot_edge"}:
        stack["services"]["retail" if kind == "retail_edge" else "seed-demo"]["networks"] = ["default", "edge"]
    elif kind == "worker_host":
        stack["services"]["worker"]["network_mode"] = "host"
    elif kind == "api_networks":
        service["networks"] = ["edge"]
    else:
        stack["services"]["caddy"]["networks"] = ["default"]
    with pytest.raises((AssertionError, KeyError)):
        enforce(stack)


@pytest.mark.parametrize("name", ["app", "retail", "web"])
def test_real_dockerfile_pins_and_context(name: str) -> None:
    pins = json.loads((ROOT / "infra/images.json").read_bytes())["images"]
    allowed = {f"{value['image']}@{value['digest']}" for value in pins.values()}
    source = (ROOT / f"infra/docker/{name}.Dockerfile").read_text(encoding="utf-8")
    bases = re.findall(r"^FROM (\S+)", source, re.M)
    assert len(bases) >= 2 and all(base in allowed for base in bases)
    assert re.search(r"^USER [1-9]\d*:[1-9]\d*$", source, re.M)
    assert "ARG " not in source and not re.search(r"^COPY \. ", source, re.M)
    assert "infra/images.json" in source
    assert check_context(ROOT) == []
    if name in {"app", "retail"}:
        assert "--frozen --no-dev" in source
        assert "--checksum=sha256:c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83" in source
        assert "uv/releases/download/0.13.7/" in source
    else:
        assert "npm ci --ignore-scripts" in source and "check_bundle.py --bundle" in source
        assert "COPY --from=scan /opt/bundle /srv" in source
        assert "web-notices" in source
        enforce_caddy_build(source)
    if name == "retail":
        assert "COPY --from=build /tmp/uv" not in source
        assert "package_retail.py" in source


def enforce_caddy_build(source: str) -> None:
    commands = source.replace("\\\n", " ")
    check = re.search(r'^RUN apk add --no-cache libcap-utils\s+&& setcap -r /usr/bin/caddy\s+'
                      r'&& capabilities="\$\(getcap /usr/bin/caddy\)"\s+&& test -z "\$capabilities"$',
                      commands, re.M)
    assert check is not None, "Caddy capability removal and fail-closed verification required"
    assert commands.index(" AS runtime") < check.start() < commands.index("\nUSER ")
    assert not re.search(r"^COPY .* /usr/bin(?:/caddy)?$", commands[check.end():], re.M)


@pytest.mark.parametrize("old,new", [("setcap -r", "setcap -v"), ("getcap /usr/bin/caddy", "true"),
                                    ('test -z "$capabilities"', "true")])
def test_caddy_build_rejects_missing_capability_guard(old: str, new: str) -> None:
    source = (ROOT / "infra/docker/web.Dockerfile").read_text(encoding="utf-8")
    with pytest.raises(AssertionError):
        enforce_caddy_build(source.replace(old, new))


def test_smoke_network_policy_rejects_edge_leaks() -> None:
    networks = [{"Labels": {"com.docker.compose.network": name}, "Id": name, "Internal": name == "default"}
                for name in ("default", "edge")]
    items: list[dict[str, Any]] = [{"Config": {"Labels": {"com.docker.compose.service": name}}, "Id": name,
              "HostConfig": {"NetworkMode": "container:caddy" if name == "api" else "default"},
              "NetworkSettings": {"Networks": {network: {"NetworkID": network} for network in attached}}}
             for name, attached in (("caddy", ["default", "edge"]), ("api", []), ("retail", ["default"]))]
    check_networks(items, networks)
    items[-1]["NetworkSettings"]["Networks"]["edge"] = {"NetworkID": "edge"}
    with pytest.raises(SmokeError):
        check_networks(items, networks)
    items[-1]["NetworkSettings"]["Networks"].pop("edge")
    items[1]["HostConfig"]["NetworkMode"] = "host"
    with pytest.raises(SmokeError):
        check_networks(items, networks)


def test_retail_context_excludes_evaluation_payloads() -> None:
    rules = parse_rules((ROOT / ".dockerignore").read_text(encoding="utf-8"))
    for path in ("evals/.env", "evals/data/tasks.json", "evals/results/run.json", "evals/studies/live.json",
                 "evals/manifests/tau2-19f13ea3/retail-split.json", "evals/tests/test_example.py"):
        assert not included(path, rules), path
    for path in ("evals/src/policyops_evals/retail_sim/app.py", "evals/uv.lock",
                 "evals/manifests/tau2-19f13ea3/source.json", "evals/migrations/retail/env.py"):
        assert included(path, rules), path


def test_proxy_security_headers_and_sse() -> None:
    source = (ROOT / "infra/caddy/Caddyfile").read_text(encoding="utf-8")
    for value in ("Content-Security-Policy", "frame-ancestors 'none'", "X-Content-Type-Options nosniff",
                  "Referrer-Policy no-referrer", "flush_interval -1", "reverse_proxy dex:5556"):
        assert value in source


def test_smoke_refuses_foreign_resources_and_ports() -> None:
    labels = {"com.docker.compose.project": "p", "policyops.owner": "policyops-compose", "policyops.run": "r"}
    check_ownership([{"Labels": labels}], "p", "r", container=False)
    with pytest.raises(SmokeError):
        check_ownership([{"Labels": labels}], "other", "r", container=False)
    item: dict[str, Any] = {"Config": {"Labels": {**labels, "com.docker.compose.service": "caddy"}},
            "HostConfig": {"PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}}}
    check_ports([item], 8080)
    item["HostConfig"]["PortBindings"]["8080/tcp"][0]["HostIp"] = "0.0.0.0"  # noqa: S104 - negative fixture
    with pytest.raises(SmokeError):
        check_ports([item], 8080)
