"""Explicit A -> B -> A live drill over SSH; deployment output is discarded, report is sanitized.

Use only after confirming forward schema compatibility of both commits. No schema downgrade is attempted.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.deploy_verify import hostname, report_path, verify


def commit_id(raw: str) -> str:
    if not re.fullmatch("[0-9a-f]{40}", raw):
        raise argparse.ArgumentTypeError("full lowercase commit SHA required")
    return raw


def drill(host: str, ssh_host: str, identity: Path, first: str, second: str,
          *, allow_admin_ssh: bool = False, known_hosts: Path | None = None) -> dict[str, Any]:
    if first == second:
        raise ValueError("A and B must be distinct commits")
    if not re.fullmatch(r"ubuntu@[a-zA-Z0-9.-]+", ssh_host):
        raise ValueError("SSH target must be ubuntu@hostname-or-IPv4")
    ssh_options = ["-o", "StrictHostKeyChecking=yes"]
    if known_hosts is not None:
        # OpenSSH parses the option value again; inner quotes preserve spaces on Windows too.
        known_hosts_value = str(known_hosts.resolve()).replace("\\", "/")
        if any(char in known_hosts_value for char in ('"', "\n", "\r")):
            raise ValueError("known_hosts path contains unsupported SSH option characters")
        ssh_options += ["-o", f'UserKnownHostsFile="{known_hosts_value}"', "-o", "GlobalKnownHostsFile=none"]
    steps: list[dict[str, Any]] = []
    for label, commit, rollback in (("A", first, False), ("B", second, False), ("rollback_A", first, True)):
        started = time.monotonic()
        # The installed script is the reviewed deployment implementation, not downloaded mutable shell text.
        command = f"sudo bash /usr/local/sbin/policyops-deploy {commit} {hostname(host)}"
        if rollback:
            command += " --rollback"
        try:
            result = subprocess.run(["ssh", "-i", str(identity), "-o", "BatchMode=yes",
                                     *ssh_options, ssh_host, command],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800, check=False)
            code = result.returncode
            health = verify(host, allow_admin_ssh=allow_admin_ssh) if code == 0 else None
            step = {"step": label, "commit": commit, "exit_code": code,
                    "seconds": round(time.monotonic() - started, 3), "verification": health,
                    "passed": code == 0 and health is not None and health["passed"]}
        except subprocess.TimeoutExpired:
            step = {"step": label, "commit": commit, "seconds": round(time.monotonic() - started, 3),
                    "passed": False, "outcome": "timeout_remote_process_may_continue"}
        steps.append(step)
        if not step["passed"]:
            break
    return {"schema": "policyops.rollback-drill/v1", "at": datetime.now(UTC).isoformat(),
            "hostname": host, "steps": steps, "passed": len(steps) == 3 and all(s["passed"] for s in steps),
            "schema_downgrade": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", type=hostname)
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, help="dedicated pinned host-key file")
    parser.add_argument("--commit-a", type=commit_id, required=True)
    parser.add_argument("--commit-b", type=commit_id, required=True)
    parser.add_argument("--allow-admin-ssh", action="store_true")
    parser.add_argument("--schema-compatible", action="store_true", required=True,
                        help="operator has reviewed both commits for compatibility with B's schema")
    args = parser.parse_args()
    destination = report_path("rollback")
    result = drill(args.hostname, args.ssh_host, args.identity, args.commit_a, args.commit_b,
                   allow_admin_ssh=args.allow_admin_ssh, known_hosts=args.known_hosts)
    destination.write_bytes((json.dumps(result, indent=2) + "\n").encode("utf-8"))
    print(f"Rollback drill {'passed' if result['passed'] else 'FAILED'}; report: {destination}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
