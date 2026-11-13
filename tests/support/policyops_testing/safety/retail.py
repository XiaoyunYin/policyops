"""Shared owned retail simulator lifecycle, extracted from T16 without behavior changes."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
from typing import Any

import httpx
from pydantic import BaseModel
import pytest

from policyops_testing import network
from policyops_testing.app_database import AppDatabase
from policyops_testing.postgres import OwnedPostgres


REPO = Path(__file__).resolve().parents[4]
RETAIL_ROLES = ("retail_migrator", "retail_runtime")
CUSTOMER, ORDER, CARD = "james_johnson_9321", "#W1006327", "credit_card_4998749"


class Fault(BaseModel):
    fault: str
    count: int


def evals_python() -> Path:
    root = Path(os.environ["POLICYOPS_TEMP_DIR"]) / "venvs" / "evals-raw-v1"
    python = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        pytest.fail("the evals environment is not synced (scripts/devenv.py uv sync --project evals --frozen)")
    return python


def evals_environment() -> dict[str, str]:
    keep = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PG", "OPENAI_", "ANTHROPIC_",
                                                                              "PYTHONPATH", "VIRTUAL_ENV"))}
    return keep | {"PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHON_DOTENV_DISABLED": "1",
                   "LITELLM_LOCAL_MODEL_COST_MAP": "True"}


def cli(*args: str) -> None:
    done = subprocess.run([str(evals_python()), "-B", "-m", "policyops_evals.retail_sim.cli", *args], cwd=REPO,
                          env=evals_environment(), capture_output=True, text=True, timeout=600, check=False)
    assert done.returncode == 0, f"retail cli {args[0]} exited {done.returncode}"  # output is not echoed


def reviewed_tree() -> Path:
    cache = Path(os.environ["POLICYOPS_TEMP_DIR"]) / "cache" / "uv-evals-raw-v1" / "git-v1" / "checkouts"
    for candidate in sorted(cache.glob("*/19f13ea")):
        if (candidate / "data/tau2/domains/retail/db.json").is_file():
            return candidate
    pytest.fail("no verified tau2 checkout in the evals uv cache")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class Service:
    def __init__(self, server: OwnedPostgres, database: AppDatabase, root: Path) -> None:
        self.server, self.database, self.root = server, database, root
        self.process: subprocess.Popen[bytes] | None = None
        self.key = secrets.token_bytes(32)
        for role in RETAIL_ROLES:
            if role not in server.passwords:
                server.register_role(role)
        secrets_dir = root / "secrets"
        secrets_dir.mkdir(parents=True)
        for name, value in (("superuser", server.passwords["postgres"]), *((r, server.passwords[r])
                                                                          for r in RETAIL_ROLES)):
            (secrets_dir / name).write_text(value, encoding="utf-8")
        (secrets_dir / "key").write_bytes(self.key)
        self.db = ["--db-port", str(server.port), "--db-name", database.name]
        cli("stage", "--source-tree", str(reviewed_tree()), "--fixture-root", str(root / "fixture"))
        cli("bootstrap", *self.db, "--db-password-file", str(secrets_dir / "superuser"),
            "--migrator-password-file", str(secrets_dir / "retail_migrator"),
            "--runtime-password-file", str(secrets_dir / "retail_runtime"))
        cli("migrate", *self.db, "--db-password-file", str(secrets_dir / "retail_migrator"))
        self.port = free_port()

    @contextmanager
    def running(self) -> Iterator[str]:
        """Own the log and the process from acquisition through readiness to cleanup. Cleanup always runs (a bounded
        terminate, then kill, with the exit confirmed; then the log is closed), and a cleanup problem never hides the
        original setup or test error."""
        log: Any = None
        process: subprocess.Popen[bytes] | None = None
        original: BaseException | None = None
        try:
            log = (self.root / f"service-{secrets.token_hex(3)}.log").open("wb")
            process = subprocess.Popen(
                [str(evals_python()), "-B", "-m", "policyops_evals.retail_sim.cli", "serve", *self.db,
                 "--db-password-file", str(self.root / "secrets" / "retail_runtime"),
                 "--fixture-root", str(self.root / "fixture"), "--key-file", str(self.root / "secrets" / "key"),
                 "--port", str(self.port), "--faults"], cwd=REPO, env=evals_environment(), stdout=log,
                stderr=subprocess.STDOUT)
            self.process = process
            origin = f"http://127.0.0.1:{self.port}"
            with network.allow("127.0.0.1", self.port):
                deadline = time.monotonic() + 90
                while True:
                    if process.poll() is not None:
                        pytest.fail(f"the retail service exited early ({process.returncode})")
                    try:
                        if httpx.get(origin + "/healthz", timeout=2, trust_env=False).status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        pytest.fail("the retail service did not become ready")
                    time.sleep(0.5)
                yield origin
        except BaseException as error:
            original = error
            raise
        finally:
            problems = stop(process)
            if log is not None:
                try:
                    log.close()
                except OSError:
                    problems.append("the service log did not close")
            if problems and original is None:
                raise AssertionError("; ".join(problems))
            if problems and original is not None:
                # Keep the original error, and keep the cleanup uncertainty visible on it (fixed texts only).
                original.add_note("service cleanup: " + "; ".join(problems))


def stop(process: Any) -> list[str]:
    """Bounded terminate, then kill; returns the problems instead of raising, so the caller decides."""
    if process is None:
        return []
    problems = []
    try:
        process.terminate()
        try:
            process.wait(15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(15)
    except (OSError, subprocess.TimeoutExpired):
        problems.append("the service process did not stop")
    if process.poll() is None:
        problems.append("the service process is still running")
    return problems


