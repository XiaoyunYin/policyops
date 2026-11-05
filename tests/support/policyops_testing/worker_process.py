"""A real OS worker process for the killed-worker test (T09; test support only).

`start()` launches `python -m policyops_testing.worker_process` and sends it the owned test server's endpoint and
the two role passwords on stdin: not through argv or the environment, which other processes could read. The child
connects as the actual app-runtime and worker-discovery roles, verifies both, and runs one `Worker.run_once()` with
the database clock. Its scripted executor (the same spec definition, so the same digests, as the parent's catalog)
blocks until the process is killed, after printing `CLAIMED <run_id>` once it holds the lease.
"""

from __future__ import annotations

from datetime import timedelta
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
from typing import Any

from policyops_testing.app_database import AppDatabase


def start(db: AppDatabase, *, run_id: str, lease_seconds: int = 2, timeout_minutes: int = 5) -> subprocess.Popen[str]:
    from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY

    server = db.server
    config = {"port": server.port, "database": db.name, "lease": lease_seconds, "timeout_minutes": timeout_minutes,
              "run_id": run_id, "passfile": str(server.root / "client" / "no-passfile"),
              "passwords": {role: server.passwords[role] for role in (APP_RUNTIME, WORKER_DISCOVERY)}}
    support = str(Path(__file__).resolve().parents[1])  # tests/support, which pytest puts on sys.path itself
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, (support, os.environ.get("PYTHONPATH"))))}
    process = subprocess.Popen(
        [sys.executable, "-B", "-m", "policyops_testing.worker_process"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    assert process.stdin is not None
    process.stdin.write(json.dumps(config) + "\n")
    process.stdin.close()
    return process


def stop(process: subprocess.Popen[str]) -> None:
    """Kill (if still running), reap and close the pipes."""
    if process.poll() is None:
        process.kill()
    process.wait(30)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def wait_until_claimed(process: subprocess.Popen[str], *, timeout: float) -> None:
    lines: queue.Queue[str] = queue.Queue()
    assert process.stdout is not None
    stdout = process.stdout

    def pump() -> None:
        for line in stdout:
            lines.put(line)

    threading.Thread(target=pump, daemon=True).start()
    try:
        line = lines.get(timeout=timeout)
    except queue.Empty:
        exited = process.poll()
        detail = ""
        if exited is not None and process.stderr is not None:
            detail = process.stderr.read()[-2000:]  # the child prints no credentials
        raise AssertionError(f"the worker process never claimed the job (exit {exited}) {detail}") from None
    if not line.startswith("CLAIMED "):
        raise AssertionError(f"unexpected worker output {line[:80]!r}")


def main() -> int:
    import psycopg

    from policyops.persistence.database import make_engine
    from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
    from policyops.runtime.clock import DatabaseLeaseClock
    from policyops.runtime.spec import RuntimeCatalog
    from policyops.runtime.worker import build_worker
    from policyops_testing.postgres import SESSION_OPTIONS
    from policyops_testing.scripted import ScriptedExecutor, scripted_spec

    config = json.loads(sys.stdin.readline())

    def connect(role: str) -> Any:
        return lambda: psycopg.connect(
            host="127.0.0.1", hostaddr="127.0.0.1", port=config["port"], user=role, dbname=config["database"],
            password=config["passwords"][role], sslmode="disable", gssencmode="disable", passfile=config["passfile"],
            connect_timeout=5, options=SESSION_OPTIONS, client_encoding="UTF8",
            application_name="policyops-worker-process-test")

    app = make_engine(connect(APP_RUNTIME), pool_size=2)
    discovery = make_engine(connect(WORKER_DISCOVERY), pool_size=1)
    blocked = ScriptedExecutor(release=threading.Event(), wait_timeout=3600)  # released only by the kill
    spec = scripted_spec(blocked, lease=timedelta(seconds=config["lease"]),
                         run_timeout=timedelta(minutes=config["timeout_minutes"]))

    def claimed(token: Any) -> None:
        print(f"CLAIMED {token.run_id}", flush=True)

    # The supported composition verifies both engines' roles; env "test" because the spec is scripted.
    worker = build_worker(env="test", app_engine=app, discovery_engine=discovery, clock=DatabaseLeaseClock(),
                          catalog=RuntimeCatalog.of([spec], default=spec.spec_id), on_claimed=claimed)
    worker.run_once()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
