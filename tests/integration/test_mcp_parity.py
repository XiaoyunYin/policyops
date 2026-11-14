"""G4 real MCP subprocess parity; owned PostgreSQL/retail fixtures, no paid calls."""

import asyncio
import json
from pathlib import Path
import sys

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
import pytest

from policyops.mcp.contracts import Result
from policyops_contracts.gateway import ToolError
from policyops_testing.safety.environment import Env
from policyops_testing.safety.fixtures import safety_env as safety_env
from policyops_testing.safety.fixtures import safety_live as safety_live


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.mcp_parity_report import child_environment, credential, expected_ids, run_replay, summary


pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("suite", ["matrix", "e05", "identity"])
def test_real_stdio_parity(safety_env: Env, tmp_path: Path, suite: str) -> None:
    rows = run_replay(safety_env, tmp_path, (suite,))
    report = summary(rows)
    assert {r["case_id"] for r in rows} == expected_ids((suite,))
    assert rows and report["parity"] == report["calls"], rows
    assert report["unauthorized_disclosures"] == report["false_denials_vs_direct"] == report["oracle_failures"] == 0
    assert report["text_preservation_failures"] == 0
    assert report["latency_by_worker_phase"]["cold"]["calls"] > 0
    if suite in ("e05", "identity"):
        assert report["latency_by_worker_phase"]["warm"]["calls"] > 0


def test_bounded_sql_failure_closes_real_database_work(safety_env: Env) -> None:
    """Observe a blocked auth backend release after the SQL/call deadline, as well as the MCP reply."""
    config, cookie = credential(safety_env)
    config = config.model_copy(update={"timeout_seconds": 4})
    async def run() -> None:
        params = StdioServerParameters(command=sys.executable, args=["-B", "-m", "policyops.mcp"],
                                       env=child_environment(safety_env, config, cookie))
        with safety_env.db.superuser() as blocker, blocker.transaction():
            blocker.execute("LOCK TABLE identity.memberships IN ACCESS EXCLUSIVE MODE")
            async with (stdio_client(params) as (read, write),
                        ClientSession(read, write, read_timeout_seconds=15) as session):
                await session.initialize()
                task = asyncio.create_task(session.call_tool("get_order_details", {"order_id": safety_env.order}))
                backend = None
                try:
                    with anyio.fail_after(3.5):
                        while backend is None:
                            with safety_env.db.superuser() as monitor:
                                row = monitor.execute("SELECT pid FROM pg_stat_activity WHERE datname = %s AND "
                                    "usename = 'policyops_auth_runtime' AND wait_event_type = 'Lock' AND "
                                    "query LIKE 'SELECT role FROM identity.memberships%%'", (safety_env.db.name,)) \
                                    .fetchone()
                            backend = None if row is None else row[0]
                            if backend is None:
                                await anyio.sleep(.01)
                    framed = await task
                    result = Result.model_validate_json(json.dumps(framed.structured_content))
                    assert isinstance(result.result, ToolError) and result.result.code == "unavailable"
                    assert result.result.detail in ("call_timeout", "database_unavailable")
                    # PostgreSQL can finish its current statement up to its own SQL deadline after disconnect.
                    with anyio.fail_after(6):
                        while True:
                            with safety_env.db.superuser() as monitor:
                                present = monitor.execute("SELECT 1 FROM pg_stat_activity WHERE pid = %s",
                                                          (backend,)).fetchone()
                            if present is None:
                                break
                            await anyio.sleep(.01)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
    asyncio.run(run())
