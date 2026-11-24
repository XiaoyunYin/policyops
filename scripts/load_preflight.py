"""Verify the privately recorded disposable host and local Docker daemon before Compose."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


STATE = Path("/var/lib/policyops")
LOCAL_DOCKER = "unix:///var/run/docker.sock"


def preflight(run_id: str, instance: str, hostname: str, deny_file: Path) -> None:
    if not re.fullmatch(r"n10-[a-z0-9-]{1,59}", run_id) or not instance:
        raise ValueError("expected the privately recorded run and instance")
    if os.path.lexists(STATE / "cd"):
        raise ValueError("CD state exists")
    host = (STATE / "hostname").read_text(encoding="ascii").strip().lower().rstrip(".")
    denied = {
        line.strip().lower().rstrip(".")
        for line in deny_file.read_text(encoding="ascii").splitlines() if line.strip()
    }
    if not denied or "" in denied or not host or any(host == name or host.endswith("." + name) for name in denied):
        raise ValueError("hostname check refused")
    if host != hostname.lower().rstrip("."):
        raise ValueError("host does not match the private record")
    marker = json.loads((STATE / "n10-instance.json").read_bytes())
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    if (
        not isinstance(marker, dict) or marker.get("run_id") != run_id or marker.get("instance") != instance
        or not machine_id or marker.get("machine_id") != machine_id or not marker.get("docker_id")
    ):
        raise ValueError("disposable instance marker mismatch")
    if os.environ.get("DOCKER_CONTEXT") or os.environ.get("DOCKER_HOST", LOCAL_DOCKER) != LOCAL_DOCKER:
        raise ValueError("Docker environment must select the local daemon")
    result = subprocess.run(
        ["docker", "--host", LOCAL_DOCKER, "info", "--format", "{{.ID}}"],
        check=True, capture_output=True, text=True, timeout=5,
    )
    if result.stdout.strip() != marker["docker_id"]:
        raise ValueError("Docker daemon does not match the disposable instance")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--deny-host-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        preflight(args.run_id, args.instance, args.hostname, args.deny_host_file)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("N10 preflight refused. Verify the private instance record, hostname, CD state and local daemon.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
