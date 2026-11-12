"""OS-kill test worker. Connection secrets arrive only over stdin, never argv/env/output."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from policyops.runtime.investigation import InvestigationExecutor
from policyops_testing.app_database import AppDatabase
from policyops_testing.worker_process import stop


def start(db: AppDatabase, executor: InvestigationExecutor) -> subprocess.Popen[str]:
    from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY

    server = db.server
    config = {"port": server.port, "database": db.name,
              "passfile": str(server.root / "client" / "no-passfile"),
              "passwords": {role: server.passwords[role] for role in (APP_RUNTIME, WORKER_DISCOVERY)},
              "bindings": [b.model_dump(mode="json") for b in executor.bindings]}
    support = str(Path(__file__).resolve().parents[1])
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, (support, os.environ.get("PYTHONPATH"))))}
    process = subprocess.Popen([sys.executable, "-B", "-m", "policyops_testing.investigation_process"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", env=env)
    try:
        if process.stdin is None:
            raise RuntimeError("missing child input")
        process.stdin.write(json.dumps(config) + "\n")
        process.stdin.close()
        return process
    except BaseException:
        stop(process)
        raise


def main() -> int:
    import psycopg

    from policyops.budget.config import Configuration
    from policyops.persistence.database import RUNTIME_CONNECT_OPTIONS, make_engine
    from policyops.persistence.roles import APP_RUNTIME, WORKER_DISCOVERY
    from policyops.runtime.clock import FixedLeaseClock
    from policyops.runtime.investigation import build_investigation_spec
    from policyops.runtime.spec import RuntimeCatalog
    from policyops.runtime.worker import build_worker
    from policyops_contracts.clock import FixedClock
    from policyops_contracts.retail_service import FIXTURE_SHA256
    from policyops_contracts.retrieval import RetrievalConfig, RetrievalScope
    from policyops_contracts.seeds import CaseCustomerBinding
    from policyops_testing.agent_fakes import ScriptedModel, calls, fictional_policy
    from policyops_testing.case_api import START
    from policyops_testing.gateway_cases import FakeRetail, state
    from policyops_testing.postgres import SESSION_OPTIONS
    from policyops_testing.retrieval_fixtures import TOKENIZER, Embeddings

    config = json.loads(sys.stdin.readline())

    def connect(role: str) -> Any:
        return lambda: psycopg.connect(
            host="127.0.0.1", hostaddr="127.0.0.1", port=config["port"], user=role, dbname=config["database"],
            password=config["passwords"][role], sslmode="disable", gssencmode="disable", passfile=config["passfile"],
            connect_timeout=5, options=SESSION_OPTIONS + " " + RUNTIME_CONNECT_OPTIONS, client_encoding="UTF8",
            application_name="policyops-investigation-kill-test")

    app = make_engine(connect(APP_RUNTIME), pool_size=2)
    discovery = make_engine(connect(WORKER_DISCOVERY), pool_size=1)
    clock = FixedClock(START)

    async def block(request: Any) -> Any:
        # The preceding calculate result is now synchronously checkpointed. The parent kills this process here.
        print("CLAIMED checkpoint-ready", flush=True)
        await asyncio.Event().wait()

    model = ScriptedModel([calls("calculate", {"expression": "1+1"}), block])
    spec = build_investigation_spec(
        env="test", engine=app, configuration=Configuration(), policy=fictional_policy(),
        retrieval_scope=RetrievalScope(corpus_key="test-banking"), retrieval_config=RetrievalConfig(mode="lexical"),
        bindings=tuple(CaseCustomerBinding.model_validate_json(json.dumps(b)) for b in config["bindings"]),
        fixture_sha256=FIXTURE_SHA256,
        retail=lambda scope: FakeRetail(state(), tenant_id=scope.run.workspace_id, case_id=scope.run.case_id),
        providers=Embeddings().providers(), tokenizer=TOKENIZER, clock=FixedLeaseClock(clock), wall_clock=clock,
        test_model=lambda ledger, run: model)
    try:
        worker = build_worker(env="test", app_engine=app, discovery_engine=discovery, clock=FixedLeaseClock(clock),
                              catalog=RuntimeCatalog.of([spec], default=spec.spec_id))
        worker.run_once()
    finally:
        app.dispose()
        discovery.dispose()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Third-party DB exceptions can contain connection representations. No raw traceback/locals in stderr.
        print(f"child failure type={type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
