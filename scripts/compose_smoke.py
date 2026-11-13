"""Coordinator-only Docker smoke: fresh secrets, build, deploy, inspect, fault, scoped down -v.

Run with Python 3.12 and POLICYOPS_TEMP_DIR. POLICYOPS_PYTHON can name the frozen
application interpreter for secret generation. Docker Compose v2.24+ is required.
No provider variables are forwarded. Failing commands retain bounded, redacted output tails.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ("caddy", "api", "worker", "retail", "postgres", "dex")
ONESHOTS = ("bootstrap-app", "migrate-app", "bootstrap-retail", "migrate-retail", "seed-demo")


class SmokeError(RuntimeError):
    pass


def require(condition: bool, label: str) -> None:
    if not condition:
        raise SmokeError(label)


def safe_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.upper().startswith(
        ("OPENAI_", "ANTHROPIC_", "PG", "COMPOSE_", "POLICYOPS_", "VITE_"))}


def check_ports(containers: list[dict[str, Any]], port: int) -> None:
    actual = []
    for item in containers:
        service = item["Config"]["Labels"]["com.docker.compose.service"]
        for container_port, bindings in (item["HostConfig"].get("PortBindings") or {}).items():
            for binding in bindings or []:
                actual.append((service, container_port, binding["HostIp"], binding["HostPort"]))
    require(actual == [("caddy", f"{port}/tcp", "127.0.0.1", str(port))], "published ports differ from policy")


def check_ownership(items: list[dict[str, Any]], project: str, run_id: str, *, container: bool) -> None:
    for item in items:
        labels = (item["Config"] if container else item).get("Labels") or {}
        require(labels.get("com.docker.compose.project") == project
                and labels.get("policyops.owner") == "policyops-compose"
                and labels.get("policyops.run") == run_id, "foreign resource; cleanup refused")


def check_networks(containers: list[dict[str, Any]], networks: list[dict[str, Any]]) -> None:
    by_name = {item["Labels"]["com.docker.compose.network"]: item for item in networks}
    require(set(by_name) == {"default", "edge"}, "unexpected project networks")
    require(by_name["default"]["Internal"] is True and by_name["edge"]["Internal"] is False,
            "network isolation differs from policy")
    for item in containers:
        service = item["Config"]["Labels"]["com.docker.compose.service"]
        if service == "api":
            caddy = next(row for row in containers
                         if row["Config"]["Labels"]["com.docker.compose.service"] == "caddy")
            require(item["HostConfig"]["NetworkMode"] == "container:" + caddy["Id"],
                    "API does not share Caddy network namespace")
            continue
        actual = {value["NetworkID"] for value in item["NetworkSettings"]["Networks"].values()}
        expected = {by_name["default"]["Id"]}
        if service == "caddy":
            expected.add(by_name["edge"]["Id"])
        require(actual == expected, "service attached to unexpected network")


class Driver:
    def __init__(self, root: Path, port: int) -> None:
        self.run_id = secrets.token_hex(6)
        self.project = "policyops-t38a-" + self.run_id
        self.root, self.port = root / "compose" / self.run_id, port
        require(root.resolve() in self.root.resolve().parents, "run directory escapes temporary root")
        self.root.mkdir(parents=True, exist_ok=False)
        self.secrets = self.root / "secrets"
        self.redactions: set[str] = set()
        self.env = safe_environment() | {
            "POLICYOPS_TEMP_DIR": str(root), "POLICYOPS_SECRETS_DIR": str(self.secrets),
            "POLICYOPS_RUN_ID": self.run_id, "POLICYOPS_HTTP_PORT": str(port),
            "POLICYOPS_IMAGE_TAG": self.run_id, "PYTHONDONTWRITEBYTECODE": "1",
            "TEMP": str(self.root / "tmp"), "TMP": str(self.root / "tmp"), "TMPDIR": str(self.root / "tmp"),
            "DOCKER_CONFIG": os.environ.get("DOCKER_CONFIG", str(root / "user-data/docker")),
        }
        (self.root / "tmp").mkdir()
        self.report: dict[str, Any] = {"run_id": self.run_id, "project": self.project, "commands": [],
                                      "assertions": {}, "passed": False, "cleanup": {}}

    def redact(self, output: str) -> str:
        # Refresh even after partial secret generation, and retain values through cleanup.
        if self.secrets.is_dir() and not self.secrets.is_symlink() and not self.secrets.is_junction():
            for path in self.secrets.iterdir():
                if (path.name != "owner.json" and path.is_file() and not path.is_symlink()
                        and not path.is_junction() and path.stat().st_size <= 65536):
                    value = path.read_text(encoding="utf-8").strip()
                    if value:
                        self.redactions.update((value, json.dumps(value)[1:-1], urllib.parse.quote(value, safe="")))
        for value in sorted(self.redactions, key=len, reverse=True):
            output = output.replace(value, "[REDACTED]")
        output = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                        "[REDACTED PRIVATE KEY]", output, flags=re.S)
        output = re.sub(r"(?i)\b(?:postgres(?:ql)?(?:\+[a-z0-9]+)?://|[a-z][a-z0-9+.-]*://[^\s/@]+:[^\s/@]+@)"
                        r"[^\s\"'<>]+", "[REDACTED DSN]", output)
        return re.sub(r"(?im)^.*\b(?:password|dbname|sslmode)\s*=.*$", "[REDACTED DSN/credential line]", output)

    def failure_tail(self, *outputs: str | bytes | None) -> str:
        raw = "\n".join(value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
                        for value in outputs)
        return "\n".join(self.redact(raw).splitlines()[-60:])[-16000:]

    def command(self, *args: str, timeout: int = 180) -> str:
        receipt: dict[str, Any] = {"argv": [self.redact(arg) for arg in args], "exit_code": None}
        self.report["commands"].append(receipt)
        try:
            done = subprocess.run(list(args), env=self.env, cwd=ROOT, capture_output=True, encoding="utf-8",
                                  errors="replace", timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            receipt["error_type"] = type(error).__name__
            receipt["output_tail"] = (
                self.failure_tail(error.stdout, error.stderr)
                if isinstance(error, subprocess.TimeoutExpired) else self.failure_tail(str(error)))
            receipt["argv"] = [self.redact(arg) for arg in args]
            raise
        receipt["exit_code"] = done.returncode
        if done.returncode != 0:
            receipt["output_tail"] = self.failure_tail(done.stdout, done.stderr)
            # Secret generation may have created values after argv was first recorded.
            receipt["argv"] = [self.redact(arg) for arg in args]
            raise SmokeError("command failed; see redacted output_tail in command receipt")
        return done.stdout.strip()

    def compose(self, *args: str, timeout: int = 180) -> str:
        return self.command("docker", "compose", "--project-name", self.project,
                            "--file", str(ROOT / "compose.yaml"), *args, timeout=timeout)

    def resources(self, kind: str) -> list[dict[str, Any]]:
        listing = self.command("docker", kind, "ls", "--quiet", "--filter",
                               f"label=com.docker.compose.project={self.project}")
        if not listing:
            return []
        result: list[dict[str, Any]] = json.loads(self.command("docker", kind, "inspect", *listing.split()))
        return result

    def containers(self) -> list[dict[str, Any]]:
        # `docker container ls --all` is essential: failed/one-shot containers must also be owned.
        listing = self.command("docker", "container", "ls", "--all", "--quiet", "--filter",
                               f"label=com.docker.compose.project={self.project}")
        if not listing:
            return []
        result: list[dict[str, Any]] = json.loads(self.command("docker", "container", "inspect", *listing.split()))
        return result

    def wait(self, *, seconds: int = 180) -> list[dict[str, Any]]:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            items = self.containers()
            by_service = {item["Config"]["Labels"]["com.docker.compose.service"]: item for item in items}
            if all(name in by_service for name in (*RUNTIME, *ONESHOTS)):
                require(all(by_service[name]["State"]["Status"] != "exited"
                            or by_service[name]["State"]["ExitCode"] == 0 for name in ONESHOTS), "migration failed")
                if (all(by_service[name]["State"].get("Health", {}).get("Status") == "healthy" for name in RUNTIME)
                        and all(by_service[name]["State"]["Status"] == "exited"
                                and by_service[name]["State"]["ExitCode"] == 0 for name in ONESHOTS)):
                    return items
            time.sleep(1)
        raise SmokeError("stack did not reach healthy/completed states")

    def verify(self, service: str, mode: str, *, oneshot: bool = False) -> Any:
        args = ("run", "--rm", "--no-deps", "--entrypoint", "python") if oneshot else ("exec", "-T")
        if oneshot:
            raw = self.compose(*args, service, "-B", "infra/compose/verify.py", mode)
        else:
            raw = self.compose(*args, service, "python", "-B", "infra/compose/verify.py", mode)
        return json.loads(raw)

    def request_ready(self) -> tuple[int, dict[str, Any]]:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f"http://127.0.0.1:{self.port}/api/v1/health/ready"
        try:
            with opener.open(url, timeout=10) as response:
                return response.status, json.loads(response.read(8192))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read(8192))

    def run(self) -> None:
        require(not self.containers() and not self.resources("volume") and not self.resources("network"),
                "project identity already exists")
        interpreter = os.environ.get("POLICYOPS_PYTHON", sys.executable)
        self.command(interpreter, "-B", str(ROOT / "scripts/compose_secrets.py"))
        # The three builds share one reviewed context. Explicit checks apply before any Docker build.
        for _image in ("app", "retail", "web"):
            self.command(sys.executable, "-B", str(ROOT / "scripts/check_build_context.py"), "--context", str(ROOT))
        self.compose("build", timeout=1800)
        self.compose("up", "--detach", timeout=300)
        items = self.wait()
        check_ownership(items, self.project, self.run_id, container=True)
        check_ports(items, self.port)
        check_networks(items, self.resources("network"))
        assertions = self.report["assertions"]
        assertions["published_ports"] = [{"service": "caddy", "host": "127.0.0.1", "port": self.port}]
        assertions["network_policy"] = {"internal_only": "default", "edge_namespace": ["caddy", "api"]}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{self.port}/proxy-health", timeout=10) as response:
            require(response.status == 200, "Caddy loopback port unreachable from host")
        assertions["host_loopback_reachable"] = True
        assertions["retail_no_egress"] = self.verify("retail", "no-egress")
        assertions["migrations"] = self.verify("bootstrap-app", "migrations", oneshot=True)
        assertions["runtime_roles"] = {name: self.verify(name, name) for name in ("api", "worker", "retail")}
        users = {}
        for name in RUNTIME:
            uid = self.compose("exec", "-T", name, "id", "-u")
            require(uid.isdigit() and int(uid) > 0, "effective container UID is root or unknown")
            users[name] = int(uid)
        assertions["effective_uids"] = users
        status, ready = self.request_ready()
        require(status == 200 and ready.get("status") == "ok", "API was not ready before fault")
        self.compose("stop", "retail")
        status, ready = self.request_ready()
        require(status == 503 and ready.get("checks", {}).get("retail") is False,
                "retail failure not visible in API readiness")
        assertions["retail_failure_visible"] = True
        self.compose("start", "retail")
        self.wait()
        require(self.request_ready()[0] == 200, "readiness did not recover")
        assertions["retail_recovered"] = True
        self.compose("stop", "worker", "api")
        stopped = {item["Config"]["Labels"]["com.docker.compose.service"]: item["State"]
                   for item in self.containers()}
        require(stopped["worker"]["Status"] == "exited" and stopped["worker"]["ExitCode"] == 0,
                "worker did not stop gracefully")
        require(stopped["api"]["Status"] == "exited" and stopped["api"]["ExitCode"] in (0, 143),
                "API did not stop gracefully")
        assertions["shutdown_exit_codes"] = {name: stopped[name]["ExitCode"] for name in ("worker", "api")}
        self.report["passed"] = True

    def cleanup(self) -> None:
        items = self.containers()
        check_ownership(items, self.project, self.run_id, container=True)
        for kind in ("volume", "network"):
            check_ownership(self.resources(kind), self.project, self.run_id, container=False)
        self.compose("down", "--volumes", "--remove-orphans", timeout=180)
        require(not self.containers() and not self.resources("volume") and not self.resources("network"),
                "Compose resources remain after cleanup")
        self.report["cleanup"]["compose_removed"] = True
        require(not self.secrets.is_symlink() and not self.secrets.is_junction()
                and self.secrets.resolve().parent == self.root.resolve(), "secret directory escapes run root")
        marker = self.secrets / "owner.json"
        require(not marker.is_symlink() and not marker.is_junction(), "secret ownership marker is linked")
        if marker.exists():
            owner = json.loads(marker.read_bytes())
            require(owner["run_id"] == self.run_id, "secret ownership uncertain")
            # Exact task-owned names; do not recursively delete the temp root or follow replaced links.
            for name in [*owner["files"], "owner.json"]:
                path = self.secrets / name
                require(path.parent.resolve() == self.secrets.resolve()
                        and not path.is_symlink() and not path.is_junction(), "secret path unsafe")
                if path.exists():
                    path.chmod(0o600)
                    path.unlink()
            self.secrets.rmdir()
        require(not self.secrets.exists(), "partial secret generation retained; inspect its private directory")
        self.report["cleanup"]["secrets_removed"] = True
        (self.root / "tmp").rmdir()
        self.report["cleanup"]["images_retained"] = "run-tagged images retained for coordinator layer/package audit"

    def save(self) -> Path:
        path = self.root / "report.json"
        path.write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")
        return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    root = Path(raw).resolve()
    if not raw or not Path(raw).is_absolute() or root == ROOT or ROOT in root.parents or not 1024 <= args.port <= 65535:
        print("Set an absolute external POLICYOPS_TEMP_DIR and a port between 1024 and 65535.", file=sys.stderr)
        return 2
    driver = Driver(root, args.port)
    try:
        driver.run()
    except Exception as error:
        driver.report["failure"] = {"type": type(error).__name__, "detail": str(error) if isinstance(error, SmokeError)
                                   else "details omitted"}
    finally:
        try:
            driver.cleanup()
        except Exception as error:
            driver.report["cleanup"]["error_type"] = type(error).__name__
            driver.report["passed"] = False
        report = driver.save()
    print(json.dumps({"passed": driver.report["passed"], "report": str(report), "project": driver.project}))
    return 0 if driver.report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
