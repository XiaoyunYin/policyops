"""One real owned process kill at the committed dispatch checkpoint (outside E04 N)."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from policyops.gateway.ports import load_scope
from policyops.persistence.roles import APP_RUNTIME
from policyops.services.execution import ExecutionHooks
from policyops_contracts.clock import FixedClock
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.seeds import CaseCustomerBinding
from policyops_testing import network
from policyops_testing.app_database import AppDatabase
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.safety.config import REPO, canonical
from policyops_testing.safety.e04 import expected_state, observe, state_sha
from policyops_testing.safety.environment import CANCEL, Env, due, ledger_record, study_case
from policyops_testing.safety.reports import Sensitivity


def child(path: Path) -> int:
    # Parent-created config contains transient fixture credentials; NEVER echo or report it.
    if path.stat().st_size > 65536:
        raise ValueError("worker config exceeds cap")
    data = json.loads(path.read_bytes())
    server = OwnedPostgres(root=Path(data["server_root"]), run_id=data["server_run"], port=data["port"],
                           passwords=data["passwords"], databases={data["database"]})
    db = AppDatabase(server, data["database"])
    try:
        with network.allow("127.0.0.1", server.port), network.allow("127.0.0.1", data["retail_port"]):
            binding = CaseCustomerBinding.model_validate_json(canonical(data["binding"]))
            scope = load_scope(db.engine(APP_RUNTIME, pool_size=6), workspace_id=UUID(data["workspace"]),
                               run_id=UUID(data["run"]), binding=binding, fixture_sha256=FIXTURE_SHA256)
            env = Env(db, SimpleNamespace(key=bytes.fromhex(data["key"])), data["origin"],
                      FixedClock(datetime.fromisoformat(data["clock"])), scope,
                      UUID(data["reviewer"]), UUID(data["membership"]))

            class Signal(ExecutionHooks):
                test_only = True

                def before_send(self, execution: Any) -> None:
                    Path(data["ready"]).write_bytes(b"checkpoint_committed_before_send\n")
                    # Finite even if the parent dies; the parent kills this process after the signal.
                    time.sleep(30)
                    raise RuntimeError("parent did not kill worker")

            env.dispatcher(hooks=Signal()).executor.step(env.run.workspace_id, UUID(data["execution"]))
        return 0
    finally:
        db.dispose()


def check(base: Env, root: Path) -> Sensitivity:
    env = study_case(base)
    execution_id = env.reserve(env.approve())
    before, full_before, _ = observe(env)
    root.mkdir(parents=True, exist_ok=False)
    config, ready = root / "worker-private.json", root / "ready"
    data = {"server_root": str(env.db.server.root), "server_run": env.db.server.run_id,
            "port": env.db.server.port, "passwords": env.db.server.passwords, "database": env.db.name,
            "binding": env.scope.binding.model_dump(mode="json"), "workspace": str(env.run.workspace_id),
            "run": str(env.run.run_id), "key": env.service.key.hex(), "origin": env.origin,
            "retail_port": env.service.port, "reviewer": str(env.reviewer), "membership": str(env.membership),
            "clock": env.clock.now().isoformat(), "execution": str(execution_id), "ready": str(ready)}
    process: subprocess.Popen[bytes] | None = None
    primary: BaseException | None = None
    try:
        config.write_bytes(canonical(data))
        process = subprocess.Popen([sys.executable, "-B", str(REPO / "scripts/run_safety_study.py"),
                                    "--worker", str(config)], cwd=REPO, env=dict(os.environ),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 20
        while not ready.is_file():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("worker did not reach checkpoint")
            time.sleep(0.05)
        if env.row(execution_id)["state"] != "dispatched" or observe(env)[0].version != before.version:
            raise ValueError("worker signal did not name unsent persisted checkpoint")
        process.kill()
        process.wait(10)
        due(env)
        # A new worker/client reconstructs from persisted application/retail state.
        for _ in range(12):
            env.dispatcher().executor.step(env.run.workspace_id, execution_id)
            if env.row(execution_id)["state"] not in ("pending", "dispatched", "unknown"):
                break
            due(env)
        after, _, receipts = observe(env)
        record = ledger_record(env, execution_id)
        detected = record.state == "succeeded" and after.version - before.version == 1 \
            and len(receipts) == 1 and record.receipt == receipts[0] and process.poll() is not None \
            and after.full_sha256 == state_sha(expected_state(env, CANCEL, full_before))
        return Sensitivity(check_id="real_subprocess_kill_restart", detected=detected,
            evidence={"checkpoint": "persisted_dispatched_before_send", "exit_code": process.returncode,
                      "effects": after.version - before.version, "receipt_retained": record.receipt is not None,
                      "pid": process.pid, "execution_id": str(execution_id),
                      "operation_id": str(record.operation_id), "before_sha256": before.full_sha256,
                      "after_sha256": after.full_sha256,
                      "receipts": [r.model_dump(mode="json") for r in receipts],
                      "outside_paired_denominator": True, "all_faults_are_os_kills": False})
    except BaseException as error:
        primary = error
        raise
    finally:
        problems = []
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(10)
            except (OSError, subprocess.TimeoutExpired):
                problems.append("process stop unconfirmed")
        # Exact task-owned paths, no recursive deletion; config never enters the sealed artifacts.
        if process is None or process.poll() is not None:
            try:
                config.unlink(missing_ok=True)
                ready.unlink(missing_ok=True)
                root.rmdir()
            except OSError:
                problems.append("worker scratch cleanup unconfirmed")
        if problems and primary is not None:
            primary.add_note("; ".join(problems))
        elif problems:
            raise RuntimeError("; ".join(problems))
