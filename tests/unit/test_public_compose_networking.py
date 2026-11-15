"""Check the real Compose merge, including options rejected by Docker at container creation.

Requires the Compose CLI, but no daemon, images, builds or secret files. Skip explicitly
when that CLI is absent or cannot be launched; a config/merge failure is a test failure.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "infra/compose/public.yaml"
HOST = "demo.example.test"
# https://docs.docker.com/engine/network/#container-networks lists the CLI flags.
# Compose additionally disallows networks with network_mode; domainname and links
# also conflict with Docker's container mode. publish-all has no Compose service key.
CONFLICTING_KEYS = (
    "extra_hosts", "ports", "expose", "dns", "dns_search", "dns_opt", "hostname",
    "domainname", "mac_address", "networks", "links",
)


@pytest.fixture(scope="module")
def compose_cli() -> str:
    binary = shutil.which("docker")
    if binary is None:
        pytest.skip("Docker CLI absent; real public Compose merge cannot run")
    try:
        version = subprocess.run([binary, "compose", "version"], capture_output=True, text=True, timeout=30)
    except OSError as error:
        pytest.skip(f"Docker Compose CLI launch unavailable: {error}")
    if version.returncode:
        pytest.skip(f"Docker Compose plugin unavailable: {version.stderr.strip()}")
    return binary


def merged_profile(binary: str, overlay: Path = PUBLIC) -> dict[str, Any]:
    env = dict(os.environ, POLICYOPS_HOSTNAME=HOST, POLICYOPS_RUN_ID="public-networking-check",
               POLICYOPS_HTTP_PORT="8080", POLICYOPS_IMAGE_TAG="local",
               POLICYOPS_SECRETS_DIR=str(Path(os.environ["POLICYOPS_TEMP_DIR"]) / "unused-secrets"))
    result = subprocess.run(
        [binary, "compose", "--project-directory", str(ROOT), "--project-name", "policyops-networking-check",
         "-f", str(ROOT / "compose.yaml"), "-f", str(overlay), "config", "--format", "json"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    stack: dict[str, Any] = json.loads(result.stdout)
    return stack


def check_namespace_options(stack: dict[str, Any]) -> None:
    for name, service in stack["services"].items():
        if service.get("network_mode", "").startswith(("service:", "container:")):
            conflicts = sorted(set(CONFLICTING_KEYS).intersection(service))
            assert not conflicts, f"{name}: namespace sharing conflicts with {conflicts}"


def check_issuer_route(stack: dict[str, Any]) -> None:
    services = stack["services"]
    assert services["api"]["network_mode"] == "service:caddy"
    # Compose's JSON output canonicalizes host:IP entries to host=IP strings.
    assert services["caddy"]["extra_hosts"] == [f"{HOST}=127.0.0.1"]
    issuer = f"https://{HOST}/dex"
    for name in ("api", "worker", "seed-demo"):
        assert services[name]["environment"]["POLICYOPS_OIDC_ISSUER"] == issuer
    assert services["dex"]["environment"]["DEX_ISSUER"] == issuer
    assert services["dex"]["environment"]["POLICYOPS_REDIRECT_URI"] == f"https://{HOST}/api/v1/auth/callback"
    assert {name for name, service in services.items() if service.get("ports")} == {"caddy"}
    assert {(p["host_ip"], str(p["published"]), p["target"]) for p in services["caddy"]["ports"]} == {
        ("0.0.0.0", "80", 80), ("0.0.0.0", "443", 443),  # noqa: S104 - intended public Caddy only
    }


def test_merged_public_profile_networking(compose_cli: str) -> None:
    stack = merged_profile(compose_cli)
    check_namespace_options(stack)
    check_issuer_route(stack)


@pytest.mark.parametrize("mode", ["service:caddy", "container:namespace-owner"])
@pytest.mark.parametrize("key", CONFLICTING_KEYS)
def test_namespace_options_reject_conflicts(mode: str, key: str) -> None:
    stack = {"services": {"client": {"network_mode": mode, key: ["conflict"]}}}
    with pytest.raises(AssertionError, match=key):
        check_namespace_options(stack)


def test_namespace_owner_requires_hostname_mapping(compose_cli: str) -> None:
    stack = deepcopy(merged_profile(compose_cli))
    stack["services"]["caddy"]["extra_hosts"] = [f"{HOST}=192.0.2.1"]
    with pytest.raises(AssertionError):
        check_issuer_route(stack)


def test_old_public_overlay_is_rejected(compose_cli: str, tmp_path: Path) -> None:
    # Reconstruct the live failure: mapping on API, absent from namespace owner.
    raw = PUBLIC.read_text(encoding="utf-8")
    mapping = '    extra_hosts:\n      - "${POLICYOPS_HOSTNAME:?Set public DNS hostname}:127.0.0.1"\n'
    assert raw.count(mapping) == 1
    old = raw.replace(mapping, "").replace("  api:\n", "  api:\n" + mapping)
    overlay = tmp_path / "old-public.yaml"
    overlay.write_text(old, encoding="utf-8", newline="\n")
    stack = merged_profile(compose_cli, overlay)
    with pytest.raises(AssertionError, match=r"api:.*extra_hosts"):
        check_namespace_options(stack)
