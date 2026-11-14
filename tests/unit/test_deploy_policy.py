"""Offline checks of the actual AWS/profile/bootstrap files, with unsafe mutation controls.

Not a Terraform schema validator, Compose merger or proof of live host firewall behavior.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
import shlex
import sys
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.check_publication import SECRET_PATTERNS


ROOT = Path(__file__).resolve().parents[2]
AWS = ROOT / "infra/terraform/aws"


class ProfileLoader(yaml.SafeLoader):  # type: ignore[misc]  # untyped dependency; inherits only SafeLoader
    pass


ProfileLoader.add_constructor("!override", lambda loader, node: loader.construct_sequence(node))


def profile() -> dict[str, Any]:
    result: dict[str, Any] = yaml.load((ROOT / "infra/compose/public.yaml").read_text(encoding="utf-8"),
                                       Loader=ProfileLoader)  # noqa: S506 - SafeLoader subclass, inert !override only
    return result


def enforce_profile(stack: dict[str, Any]) -> None:
    services = stack["services"]
    assert {name for name, service in services.items() if service.get("ports")} == {"caddy"}
    assert services["caddy"]["ports"] == ["0.0.0.0:80:80", "0.0.0.0:443:443"]
    text = repr(stack)
    assert not re.search(r"OPENAI|ANTHROPIC|BEDROCK|AWS_ACCESS|AWS_SECRET|GEMINI|API_KEY|PROVIDER", text, re.I)
    assert not stack.get("secrets") and not stack.get("networks")
    for service in services.values():
        assert not any(key in service for key in ("env_file", "secrets", "network_mode", "networks", "privileged"))
        assert "mem_limit" in service
        assert not service.get("build", {}).get("args")
    assert services["api"]["environment"]["POLICYOPS_ENV"] == "deployment"
    assert services["api"]["environment"]["POLICYOPS_PUBLIC_RATE_LIMIT"] == "1"
    for name in ("api", "worker", "seed-demo"):
        assert services[name]["environment"]["POLICYOPS_OIDC_ISSUER"].startswith("https://${POLICYOPS_HOSTNAME:?")
    assert services["dex"]["environment"]["DEX_ISSUER"].startswith("https://${POLICYOPS_HOSTNAME:?")
    assert services["dex"]["environment"]["POLICYOPS_REDIRECT_URI"].endswith("/api/v1/auth/callback")


def test_public_overlay_policy() -> None:
    enforce_profile(profile())
    raw = (ROOT / "infra/compose/public.yaml").read_text(encoding="utf-8")
    assert "ports: !override" in raw and "tmpfs: !override" in raw
    caddy = (ROOT / "infra/deploy/Caddyfile").read_text(encoding="utf-8")
    assert "{$POLICYOPS_HOSTNAME}" in caddy and "auto_https off" not in caddy
    assert "Strict-Transport-Security" in caddy and "max-age=31536000" in caddy
    assert "header_up X-PolicyOps-Client-IP {remote_host}" in caddy
    assert "max_size 65536" in caddy and "-Server" in caddy
    assert "/var/lib/policyops/caddy-data:/data" in raw


@pytest.mark.parametrize("mutation", ["api_port", "provider_env", "provider_secret", "http", "unbounded"])
def test_public_profile_rejects_unsafe_mutations(mutation: str) -> None:
    stack = deepcopy(profile())
    api = stack["services"]["api"]
    if mutation == "api_port":
        api["ports"] = ["8000:8000"]
    elif mutation == "provider_env":
        api["environment"]["OPENAI_API_KEY"] = "${OPENAI_API_KEY}"
    elif mutation == "provider_secret":
        api["secrets"] = ["anthropic_key"]
    elif mutation == "http":
        api["environment"]["POLICYOPS_OIDC_ISSUER"] = "http://unsafe.example/dex"
    else:
        del api["mem_limit"]
    with pytest.raises(AssertionError):
        enforce_profile(stack)


def test_terraform_pins_firewall_budget_state_and_secret_policy() -> None:
    versions = (AWS / "versions.tf").read_text(encoding="utf-8")
    assert 'required_version = "= 1.15.8"' in versions
    assert 'version = "= 6.25.0"' in versions
    assert 'source  = "hashicorp/aws"' in versions
    assert 'backend "local" {}' in versions
    main = (AWS / "main.tf").read_text(encoding="utf-8")
    variables = (AWS / "variables.tf").read_text(encoding="utf-8")
    assert 'resource "aws_budgets_budget"' in main and 'limit_amount = "20"' in main
    assert 'notification_type          = "ACTUAL"' in main and 'threshold                  = 80' in main
    assert 'notification_type          = "FORECASTED"' in main and 'threshold                  = 100' in main
    ssh = re.search(r"port_info\s*\{[^}]*from_port\s*=\s*22[^}]*\}", main)
    assert ssh and "[var.admin_cidr]" in ssh[0] and "0.0.0.0/0" not in ssh[0]
    admin = variables.split('variable "admin_cidr"', 1)[1].split('variable "ssh_public_key"', 1)[0]
    assert not re.search(r"\bdefault\s*=", admin) and 'endswith(var.admin_cidr, "/32")' in admin
    assert 'default = "us-west-2"' in variables
    assert 'public_key = var.ssh_public_key' in main
    assert 'profile = var.profile' in versions
    assert not re.search(r"access_key\s*=|secret_key\s*=|private_key\s*=|tls_private_key", main + versions + variables)
    outputs = (AWS / "outputs.tf").read_text(encoding="utf-8")
    assert not re.search(r"email|key|password|secret|user_data", outputs, re.I)
    assert 'output "hostname"' in outputs and ".sslip.io" in outputs
    for path in AWS.glob("*.tf*"):
        assert not any(pattern.search(path.read_bytes()) for pattern in SECRET_PATTERNS.values()), path


def test_cloud_init_security_and_idempotence_markers() -> None:
    raw = (ROOT / "infra/deploy/cloud-init.yaml.tftpl").read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    assert data["package_update"] and "unattended-upgrades" in data["packages"]
    for required in ("fallocate -l 2G", "chmod 0600 /swapfile", "swapon", "ufw default deny incoming",
                     "ufw allow from ${admin_cidr}", "PasswordAuthentication no", "PermitRootLogin no",
                     "docker-ce=", "docker-compose-plugin=", "DOCKER-USER", "ESTABLISHED,RELATED"):
        assert required in raw
    assert 'test -f /swapfile' in raw and "flock -w 10" in raw
    assert not re.search(r"(?i)(access_key|secret_key|password\s*:|PRIVATE KEY|OPENAI_|ANTHROPIC_)", raw)
    assert not any(pattern.search(raw.encode()) for pattern in SECRET_PATTERNS.values())
    # Terraform templatefile must not accidentally interpret Bash parameter expansion.
    assert re.findall(r"\$\{([^}]+)\}", raw) == ["admin_cidr"]


def rendered_host_file(path: str) -> str:
    raw = (ROOT / "infra/deploy/cloud-init.yaml.tftpl").read_text(encoding="utf-8")
    data = yaml.safe_load(raw.replace("${admin_cidr}", "192.0.2.10/32"))
    content: str = next(item["content"] for item in data["write_files"] if item["path"] == path)
    return content


def test_docker_pins_include_complete_ubuntu_release_suffix() -> None:
    script = rendered_host_file("/usr/local/sbin/policyops-bootstrap")
    installs = [shlex.split(line) for line in script.splitlines() if line.startswith("apt-get install ")]
    assert len(installs) == 1
    pins = dict(argument.split("=", 1) for argument in installs[0][3:])
    assert set(pins) == {"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}
    for package, version in pins.items():
        assert re.fullmatch(r"(?:5:)?\d+\.\d+\.\d+-\d+~ubuntu\.24\.04~noble", version), (package, version)
    assert pins == {
        "docker-ce": "5:29.7.2-1~ubuntu.24.04~noble",
        "docker-ce-cli": "5:29.7.2-1~ubuntu.24.04~noble",
        "containerd.io": "2.4.2-4~ubuntu.24.04~noble",
        "docker-buildx-plugin": "0.36.1-1~ubuntu.24.04~noble",
        "docker-compose-plugin": "5.3.1-1~ubuntu.24.04~noble",
    }


def test_rendered_firewall_replaces_stale_rules_in_exact_order() -> None:
    script = rendered_host_file("/usr/local/sbin/policyops-firewall")
    commands = [shlex.split(line) for line in script.splitlines() if line.startswith("iptables ")]
    prefix = ["iptables", "-w", "10"]
    assert commands == [
        [*prefix, "-F", "DOCKER-USER"],
        [*prefix, "-A", "DOCKER-USER", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        [*prefix, "-A", "DOCKER-USER", "-i", "$nic", "-p", "tcp", "-m", "multiport", "--dports", "80,443",
         "-j", "ACCEPT"],
        [*prefix, "-A", "DOCKER-USER", "-i", "$nic", "-j", "DROP"],
        [*prefix, "-A", "DOCKER-USER", "-j", "RETURN"],
    ]
    # A stale early RETURN and foreign rules cannot survive a rerun; no duplicate rules accumulate.
    chain = [["-j", "RETURN"], ["-j", "ACCEPT"]]
    for _ in range(2):
        for command in commands:
            if command[3] == "-F":
                chain.clear()
            else:
                chain.append(command[5:])
        assert chain == [command[5:] for command in commands[1:]]
    unit = rendered_host_file("/etc/systemd/system/policyops-firewall.service")
    assert "After=docker.service" in unit and "PartOf=docker.service" in unit
    assert "WantedBy=docker.service" in unit
    raw = (ROOT / "infra/deploy/cloud-init.yaml.tftpl").read_text(encoding="utf-8")
    assert ["systemctl", "enable", "--now", "policyops-firewall.service"] in yaml.safe_load(raw)["runcmd"]


def test_state_and_tfvars_ignored_and_example_is_placeholder_only() -> None:
    rules = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert {"*.tfstate*", "*.tfvars", ".terraform/", "!*.tfvars.example"} <= set(rules)
    example = (AWS / "terraform.tfvars.example").read_text(encoding="utf-8")
    assert "REPLACE_WITH_OPENSSH_PUBLIC_KEY" in example and "REPLACE_WITH_ALERT_EMAIL" in example
    assert "192.0.2.10/32" in example


def test_host_reset_rollback_and_secret_boundaries() -> None:
    deploy = (ROOT / "infra/deploy/deploy.sh").read_text(encoding="utf-8")
    reset = (ROOT / "infra/deploy/reset.sh").read_text(encoding="utf-8")
    assert "compose_secrets.py" in deploy and 'chmod 0700 "$POLICYOPS_SECRETS_DIR"' in deploy
    assert "--detach" in deploy and "[0-9a-f]{40}" in deploy and "flock -w" in deploy and "flock -w" in reset
    assert 'chmod -R a+rX "$release"' in deploy
    assert "--no-build --no-deps" in deploy and "docker image inspect" in deploy
    assert "downgrade" not in re.sub(r"#[^\n]*", "", deploy)
    assert "docker volume rm" in reset and reset.index("docker volume inspect") < reset.index("docker volume rm")
    assert "policyops.run" in reset and "policyops.owner" in reset
    assert "secrets" not in reset.split("docker volume rm", 1)[0].split("compose=(", 1)[1].split("volume=", 1)[0]
    timer = (ROOT / "infra/deploy/policyops-reset.timer").read_text(encoding="utf-8")
    assert "OnCalendar=" in timer and "Persistent=true" in timer
    seed = (ROOT / "infra/deploy/seed.sh").read_text(encoding="utf-8")
    assert 'test "$count" -lt 300' in seed and "periodic-seed-count" in reset
