"""Offline checks of the actual AWS/profile/bootstrap files, with unsafe mutation controls.

Not a Terraform schema validator, Compose merger or proof of live host firewall behavior.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from infra.deploy.cd_agent import runtime_path
from scripts.check_publication import SECRET_PATTERNS


ROOT = Path(__file__).resolve().parents[2]
AWS = ROOT / "infra/terraform/aws"
BOOTSTRAP = ROOT / "infra/deploy/bootstrap.sh.tftpl"


def rendered_launch_script() -> str:
    raw = BOOTSTRAP.read_text(encoding="utf-8")
    # This template intentionally has just one Terraform interpolation.
    assert re.findall(r"(?<!\$)\$\{([^}]+)\}", raw) == ["admin_cidr"]
    return "#!/bin/sh\n" + raw.replace("${admin_cidr}", "192.0.2.10/32").replace("$${", "${")


def launch_parts(rendered: str) -> tuple[str, str]:
    opening = 'cat > "$bootstrap_tmp" <<\'POLICYOPS_BOOTSTRAP\'\n'
    assert opening in rendered, "Lightsail needs a POSIX stub with a quoted bootstrap heredoc"
    before, body = rendered.split(opening, 1)
    bootstrap, after = body.split("\nPOLICYOPS_BOOTSTRAP\n", 1)
    return before + opening + "POLICYOPS_BOOTSTRAP\n" + after, bootstrap + "\n"


def shell_binary(name: str) -> str:
    # Prefer Git's real shells over Windows' bash.exe WSL launcher.
    git_shell = Path("C:/Program Files/Git/bin") / f"{name}.exe"
    binary = str(git_shell) if sys.platform == "win32" and git_shell.is_file() else shutil.which(name)
    if binary is None:
        pytest.skip(f"{name} binary absent; shell syntax/runtime check unavailable")
    return binary


def check_stub(stub: str) -> None:
    assert not re.search(r"pipefail|\[\[|\]\]|\bfunction\b|\bsource\b|\$'|(?:^|\n|;)\s*(?:local|declare|typeset)\s|"
                         r"\w+=\(|\$\{[^}]*\[|<\(|>\(|&>|==", stub)
    assert "set -eu\n" in stub and "umask 077\n" in stub
    assert 'trap finish EXIT' in stub
    assert 'bash /usr/local/sbin/policyops-bootstrap >> /var/log/policyops-bootstrap.log 2>&1' in stub


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
    assert 'respond "{$POLICYOPS_RELEASE}" 200' in caddy
    assert profile()["services"]["caddy"]["environment"]["POLICYOPS_RELEASE"] == "${POLICYOPS_IMAGE_TAG:-local}"
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


def test_lightsail_resource_names_are_unique_across_resource_types() -> None:
    # Lightsail rejects an instance or static IP whose name a key pair already holds.
    main = (AWS / "main.tf").read_text(encoding="utf-8")
    names = re.findall(r'resource "aws_lightsail_(?:key_pair|instance|static_ip)" "\w+" \{\n\s+name\s+= "([^"]+)"',
                       main)
    assert len(names) == 3 and len(set(names)) == 3


def test_launch_script_security_and_idempotence_markers() -> None:
    raw = BOOTSTRAP.read_text(encoding="utf-8")
    assert "apt-get update" in raw and "unattended-upgrades" in raw
    for required in ("fallocate -l 2G", "chmod 0600 /swapfile", "swapon", "ufw default deny incoming",
                     "ufw allow from ${admin_cidr}", "PasswordAuthentication no", "PermitRootLogin no",
                     "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
                     "docker-ce=", "docker-compose-plugin=", "DOCKER-USER", "ESTABLISHED,RELATED"):
        assert required in raw
    assert 'test -f /swapfile' in raw and "flock -w 10" in raw
    assert "grep -q '^/swapfile ' /etc/fstab" in raw
    assert "write_file 0644 /etc/fstab" in raw and ">> /etc/fstab" not in raw
    assert 'mv -f "$file_tmp" /swapfile' in raw
    assert "APT::Periodic::Unattended-Upgrade \"1\";" in raw
    assert "SystemMaxUse=64M" in raw and "RuntimeMaxUse=32M" in raw and "MaxRetentionSec=7day" in raw
    assert "apt-mark hold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" in raw
    assert "install -d -m 0700 /var/lib/policyops /var/lib/policyops/tmp /var/lib/policyops/releases" in raw
    assert not re.search(r"curl[^\n]*\|\s*(?:sh|bash)", raw)
    assert not re.search(r"(?i)(access_key|secret_key|password\s*:|PRIVATE KEY|OPENAI_|ANTHROPIC_)", raw)
    assert not any(pattern.search(raw.encode()) for pattern in SECRET_PATTERNS.values())
    # Terraform templatefile must not accidentally interpret Bash parameter expansion.
    assert re.findall(r"\$\{([^}]+)\}", raw) == ["admin_cidr"]
    main = (AWS / "main.tf").read_text(encoding="utf-8")
    assert 'templatefile("${path.module}/../../deploy/bootstrap.sh.tftpl"' in main
    assert not (ROOT / "infra/deploy/cloud-init.yaml.tftpl").exists()


def test_lightsail_wrapper_has_posix_stub() -> None:
    stub, bootstrap = launch_parts(rendered_launch_script())
    check_stub(stub)
    assert bootstrap.startswith("#!/bin/bash\nset -euo pipefail\n")


@pytest.mark.parametrize("name", ["sh", "bash"])
def test_lightsail_shell_syntax(name: str) -> None:
    stub, bootstrap = launch_parts(rendered_launch_script())
    # sh parses the whole wrapped launch script, including nested quoted heredocs.
    script = rendered_launch_script() if name == "sh" else bootstrap
    result = subprocess.run([shell_binary(name), "-n"], input=script, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    if name == "sh":
        result = subprocess.run([shell_binary(name), "-n"], input=stub, text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr


def test_launch_contract_rejects_cloud_config_negative_control() -> None:
    with pytest.raises(AssertionError, match="POSIX stub"):
        launch_parts("#!/bin/sh\n#cloud-config\npackages: [curl]\nwrite_files: []\n")


@pytest.mark.parametrize("outcome", ["success", "bootstrap_failure", "missing_bash"])
def test_lightsail_stub_execution_and_markers(tmp_path: Path, outcome: str) -> None:
    rendered = rendered_launch_script()
    _, bootstrap = launch_parts(rendered)
    # Execute only the real stub in a sandbox, replacing the privileged payload.
    payload = "#!/bin/bash\nset -euo pipefail\nprintf '%s\\n' '$unexpanded'\n"
    payload += "false\necho must-not-run\n" if outcome == "bootstrap_failure" else "true\n"
    rendered = rendered.replace(bootstrap, payload)
    for directory in ("/var/lib/policyops", "/var/log", "/usr/local/sbin"):
        target = tmp_path / directory.lstrip("/")
        target.mkdir(parents=True)
        rendered = rendered.replace(directory, directory.lstrip("/"))
    if outcome == "missing_bash":
        rendered = rendered.replace("command -v bash", "command -v policyops-missing-bash")
    if sys.platform == "win32":
        # The Windows sandbox denies MSYS chmod. Check modes statically above;
        # exercise shell control flow here without POSIX permission emulation.
        rendered = rendered.replace("install -d -m 0700", "mkdir -p")
        rendered = re.sub(r"(?m)^chmod (?:0600|0700) ", ": ", rendered)
    state = tmp_path / "var/lib/policyops/bootstrap"
    state.mkdir()
    # A failed rerun must invalidate an earlier success, and vice versa.
    (state / "success").write_text("stale", encoding="utf-8")
    (state / "failure").write_text("stale", encoding="utf-8")
    result = subprocess.run([shell_binary("sh"), "-s"], input=rendered, text=True,
                            capture_output=True, timeout=15, cwd=tmp_path)
    expected = "success" if outcome == "success" else "failure"
    assert (result.returncode == 0) == (outcome == "success"), result.stderr
    assert (state / expected).read_text(encoding="utf-8").strip() == str(result.returncode)
    assert not (state / ("failure" if expected == "success" else "success")).exists()
    log = (tmp_path / "var/log/policyops-bootstrap.log").read_text(encoding="utf-8")
    if outcome != "missing_bash":
        assert "$unexpanded" in log  # The stub must not expand the bootstrap heredoc.
        assert "must-not-run" not in log  # Bash errexit must propagate through the stub.
    assert not list((tmp_path / "usr/local/sbin").glob(".policyops-bootstrap.*"))
    assert not list(state.glob(".result.*"))


def test_ca_removal_and_ssh_restart_order() -> None:
    _, bootstrap = launch_parts(rendered_launch_script())
    config = rendered_host_file("/etc/ssh/sshd_config.d/00-policyops.conf")
    assert "TrustedUserCAKeys none\n" in config
    removal = "rm -f /etc/ssh/lightsail_instance_ca.pub"
    assert "sed -E '/^[[:space:]]*TrustedUserCAKeys" in bootstrap
    assert "| write_file 0644 /etc/ssh/sshd_config" in bootstrap
    assert (bootstrap.index(removal) < bootstrap.index("/usr/sbin/sshd -t")
            < bootstrap.index("systemctl restart ssh.service"))
    assert "sshd.service" not in bootstrap


def test_ssh_runtime_directory_precedes_validation_and_restart() -> None:
    _, bootstrap = launch_parts(rendered_launch_script())
    # Socket activation may leave /run/sshd absent until ssh.service first starts.
    assert ("install -d -m 0755 /run/sshd\n/usr/sbin/sshd -t\n"
            "systemctl restart ssh.service\n") in bootstrap


def test_ca_directive_filter_is_idempotent() -> None:
    _, bootstrap = launch_parts(rendered_launch_script())
    line = next(line for line in bootstrap.splitlines() if line.startswith("sed -E "))
    command = shlex.split(line.split(" | write_file", 1)[0])
    assert command[-1] == "/etc/ssh/sshd_config"
    config = ("Include /etc/ssh/sshd_config.d/*.conf\n"
              "# TrustedUserCAKeys /etc/ssh/lightsail_instance_ca.pub\n"
              "TrustedUserCAKeys /etc/ssh/lightsail_instance_ca.pub\n"
              "  trustedusercakeys   /etc/ssh/lightsail_instance_ca.pub # duplicate\n"
              "Port 22\n")
    expected = ("Include /etc/ssh/sshd_config.d/*.conf\n"
                "# TrustedUserCAKeys /etc/ssh/lightsail_instance_ca.pub\nPort 22\n")
    for _ in range(2):
        result = subprocess.run([shell_binary("sh"), "-c", shlex.join(command[:-1])], input=config,
                                text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert result.stdout == expected
        config = result.stdout


def test_rendered_files_are_atomic_and_have_original_modes() -> None:
    stub, bootstrap = launch_parts(rendered_launch_script())
    assert 'chmod 0700 "$bootstrap_tmp"\nmv -f "$bootstrap_tmp" /usr/local/sbin/policyops-bootstrap' in stub
    assert 'file_tmp=$(mktemp "$target.XXXXXX")' in bootstrap
    assert 'chown root:root "$file_tmp"\n  chmod "$mode" "$file_tmp"\n  mv -f "$file_tmp" "$target"' in bootstrap
    for mode, path in (("0644", "/etc/ssh/sshd_config.d/00-policyops.conf"),
                       ("0644", "/etc/apt/apt.conf.d/20auto-upgrades"),
                       ("0644", "/etc/systemd/journald.conf.d/policyops.conf"),
                       ("0700", "/usr/local/sbin/policyops-firewall"),
                       ("0644", "/etc/systemd/system/policyops-firewall.service")):
        assert f"write_file {mode} {path} <<'" in bootstrap
        assert rendered_host_file(path)


def test_ufw_only_allows_admin_ssh_and_enables_last() -> None:
    _, bootstrap = launch_parts(rendered_launch_script())
    assert [line for line in bootstrap.splitlines() if line.startswith("ufw ")] == [
        "ufw default deny incoming", "ufw default allow outgoing",
        "ufw allow from 192.0.2.10/32 to any port 22 proto tcp", "ufw allow 80/tcp", "ufw allow 443/tcp",
        "ufw --force enable",
    ]


def rendered_host_file(path: str) -> str:
    _, bootstrap = launch_parts(rendered_launch_script())
    if path == "/usr/local/sbin/policyops-bootstrap":
        return bootstrap
    match = re.search(rf"^write_file \d+ {re.escape(path)} <<'([^']+)'\n(.*?)^\1$", bootstrap, re.M | re.S)
    assert match, path
    return match[2]


def test_docker_pins_include_complete_ubuntu_release_suffix() -> None:
    script = rendered_host_file("/usr/local/sbin/policyops-bootstrap")
    installs = [shlex.split(line) for line in script.splitlines()
                if line.startswith("apt-get install ") and "docker-ce=" in line]
    assert len(installs) == 1
    pins = dict(argument.split("=", 1) for argument in installs[0][3:])
    coordinator_pins = re.findall(
        r"\b(docker-ce(?:-cli)?|containerd\.io|docker-buildx-plugin|docker-compose-plugin)=([^\s]+)",
        BOOTSTRAP.read_text(encoding="utf-8"))
    assert len(coordinator_pins) == 5 and dict(coordinator_pins) == pins
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
    _, bootstrap = launch_parts(rendered_launch_script())
    assert "systemctl enable --now policyops-firewall.service" in bootstrap


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
    assert "--no-build --pull never --no-deps" in deploy and "docker image inspect" in deploy
    assert "downgrade" not in re.sub(r"#[^\n]*", "", deploy)
    assert "docker volume rm" in reset and reset.index("docker volume inspect") < reset.index("docker volume rm")
    assert "policyops.run" in reset and "policyops.owner" in reset
    assert "secrets" not in reset.split("docker volume rm", 1)[0].split("compose=(", 1)[1].split("volume=", 1)[0]
    timer = (ROOT / "infra/deploy/policyops-reset.timer").read_text(encoding="utf-8")
    assert "OnCalendar=" in timer and "Persistent=true" in timer
    seed = (ROOT / "infra/deploy/seed.sh").read_text(encoding="utf-8")
    assert 'test "$count" -lt 300' in seed and "periodic-seed-count" in reset
    assert all('"$base/cd/frozen"' in script and '"$base/cd/active"' in script for script in (reset, seed))
    assert "reset-pending" in reset


@pytest.mark.parametrize(("lock_status", "expected_status", "expected_stderr"), [
    (75, 0, "Demo seed skipped: a deploy holds the lock.\n"),
    (1, 1, ""),
])
def test_seed_lock_outcomes(tmp_path: Path, lock_status: int, expected_status: int, expected_stderr: str) -> None:
    seed = (ROOT / "infra/deploy/seed.sh").read_text(encoding="utf-8")
    seed = seed.replace("base=/var/lib/policyops", f"base={shlex.quote(tmp_path.as_posix())}")
    if lock_status == 75 and shutil.which("flock"):
        lock = shlex.quote((tmp_path / "deploy.lock").as_posix())
        harness = f'exec 8>{lock}\nflock -n 8 || exit 99\n'
    else:
        # Git Bash lacks util-linux flock. Model its selected contention status.
        harness = f'''flock() {{
  case "$*" in
    '-w 10 -E 75 9') return {lock_status} ;;
    '-w 10 9') return 1 ;;
    *) exit 99 ;;
  esac
}}
'''
    result = subprocess.run([shell_binary("bash"), "-s"], input=harness + "readlink() { exit 99; }\n" + seed, text=True,
                            capture_output=True, timeout=15)
    assert result.returncode == expected_status, result.stderr
    assert result.stderr == expected_stderr
    assert result.stdout == ""


def test_agent_deploy_modes_keep_mutation_and_installs_separate() -> None:
    deploy = (ROOT / "infra/deploy/deploy.sh").read_text(encoding="utf-8")
    assert deploy.index('if test "$mode" = --build-only; then exit 0; fi') < deploy.index("stop worker api")
    assert deploy.index("public.policyops_app_alembic_version") < deploy.index("stop worker api")
    assert deploy.index("retail.alembic_version") < deploy.index("stop worker api")
    candidate_exit = deploy.index('if [[ "$mode" != deploy && "$inherited" -eq 1 ]]; then exit 0; fi')
    assert candidate_exit < deploy.index('readlink "$base/current"')
    assert candidate_exit < deploy.index("systemctl daemon-reload")
    fetch = deploy.split("git -C", 1)[0][-350:]
    assert 'if [[ "$mode" = deploy || ( "$mode" = --build-only && "$inherited" -eq 0 ) ]]; then' in fetch
    rollback = deploy.split('if test "$mode" == --rollback; then', 1)[1].split("elif", 1)[0]
    assert "--no-deps" in rollback and "--pull never" in rollback
    assert 'test /proc/self/fd/9 -ef "$base/deploy.lock"' in deploy and "flock -n 9" in deploy


def test_real_container_inputs_are_runtime_paths() -> None:
    inputs: set[str] = set()
    for path in (ROOT / "infra/docker").glob("*.Dockerfile"):
        for line in path.read_text(encoding="utf-8").replace("\\\n", " ").splitlines():
            instruction = line.strip().split(maxsplit=1)
            if not instruction or instruction[0].upper() != "COPY":
                continue
            arguments = instruction[1]
            flags = []
            while arguments.startswith("--"):
                flag, arguments = arguments.split(maxsplit=1)
                flags.append(flag)
            if any(flag.startswith("--from=") for flag in flags):
                continue  # stage-to-stage copies have no checkout source
            sources = json.loads(arguments)[:-1] if arguments.startswith("[") else shlex.split(arguments)[:-1]
            inputs.update(sources)
    for path in (ROOT / "compose.yaml", *(ROOT / "infra/compose").glob("*.yaml")):
        stack = yaml.load(path.read_text(encoding="utf-8"), Loader=ProfileLoader)  # noqa: S506
        sections = [*stack.get("services", {}).values(), *(v for k, v in stack.items() if k.startswith("x-"))]
        for section in sections:
            for mount in section.get("volumes", []):
                if isinstance(mount, dict):
                    if mount["type"] == "bind":
                        inputs.add(mount["source"])
                elif mount.startswith((".", "/", "~", "${")):
                    inputs.add(mount.split(":", 1)[0])
    assert {"THIRD_PARTY_NOTICES.md", "./infra/deploy/Caddyfile", "./infra/compose/postgres.sh"} <= inputs
    for source in inputs:
        assert runtime_path(source.removeprefix("./")), source
