"""Real child timeout/cancellation/concurrency and real MCP ClientSession over stdio (no network)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
from typing import Any, cast

import anyio
from anyio.abc import Process
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
import pytest

from policyops.domain.roles import Role
from policyops.mcp.config import Configuration
from policyops.mcp.contracts import TOOLS, PolicyObservation, Result
from policyops.mcp.process import ProcessCaller
from policyops_contracts.gateway import ToolError
from policyops_testing.gateway_cases import W


def environment() -> dict[str, str]:
    now = datetime.now(UTC)
    config = Configuration(principal_id=W.run_scope.run_id, workspace_id=W.run_scope.workspace_id,
        run_id=W.run_scope.run_id, binding=W.binding(), corpus_key="retail", issued_at=now - timedelta(minutes=5),
        expires_at=now - timedelta(minutes=1), timeout_seconds=5, role=Role.REVIEWER)
    return dict(os.environ) | {"POLICYOPS_MCP_CONFIG": config.model_dump_json(),
                               "POLICYOPS_MCP_SESSION": "synthetic-mcp-session", "PYTHONUTF8": "1"}


def active_environment() -> dict[str, str]:
    env = environment()
    config = Configuration.model_validate_json(env["POLICYOPS_MCP_CONFIG"])
    now = datetime.now(UTC)
    env["POLICYOPS_MCP_CONFIG"] = config.model_copy(update={"issued_at": now,
        "expires_at": now + timedelta(minutes=5)}).model_dump_json()
    return env


def test_real_stdio_client_lists_fixed_tools_and_receives_normalized_errors() -> None:
    async def run() -> None:
        env = environment() | {"PYTHONUTF8": "0", "PYTHONIOENCODING": "ascii"}
        params = StdioServerParameters(command=sys.executable, args=["-B", "-m", "policyops.mcp"], env=env)
        async with (stdio_client(params) as (read, write),
                    ClientSession(read, write, read_timeout_seconds=15) as session):
            await session.initialize()
            listing = await session.list_tools()
            assert {t.name for t in listing.tools} == set(TOOLS)
            cases: list[tuple[str, dict[str, Any], str]] = [("unknown", {}, "policy_unsupported"),
                ("get_order_details", {"order_id": 7}, "invalid_input"),
                ("search_policy", {"query": "\u9000\u8d27"}, "unauthenticated"),
                ("get_order_details", {"order_id": W.order_id}, "unauthenticated")]
            for index, (name, args, code) in enumerate(cases):
                result = await session.call_tool(name, args)
                assert isinstance(result, types.CallToolResult) and result.is_error
                payload = Result.model_validate_json(json.dumps(result.structured_content))
                assert isinstance(payload.result, ToolError) and payload.result.code == code
                assert not result.content
                assert result.meta == {"policyops/worker_phase": ("facade", "facade", "cold", "warm")[index]}
    asyncio.run(run())


def test_timeout_kills_and_reaps_blocking_child() -> None:
    async def run() -> None:
        caller = ProcessCaller(timeout=0.2, concurrency=1,
            command=[sys.executable, "-B", "-c", "import time; time.sleep(60)"])
        start = time.monotonic()
        result = await caller.call("search_policy", {"query": "policy"})
        assert isinstance(result.result, ToolError) and result.result.detail == "call_timeout"
        assert time.monotonic() - start < 5 and not caller.active
    asyncio.run(run())


def test_client_cancellation_reaps_child_and_releases_capacity() -> None:
    async def run() -> None:
        caller = ProcessCaller(timeout=10, concurrency=1,
            command=[sys.executable, "-B", "-c", "import time; time.sleep(60)"])
        process = None
        with anyio.move_on_after(0.3):
            async with anyio.create_task_group() as group:
                group.start_soon(caller.call, "search_policy", {"query": "policy"})
                with anyio.fail_after(2):
                    while not caller.active:
                        await anyio.sleep(0.005)
                process = next(iter(caller.active))
                refused = await caller.call("search_policy", {"query": "policy"})
                assert isinstance(refused.result, ToolError) and refused.result.detail == "concurrency_limit"
        assert process is not None and process.returncode is not None
        assert not caller.active and caller.limiter.borrowed_tokens == 0
    asyncio.run(run())


def test_oversized_child_output_is_bounded_and_child_stopped() -> None:
    async def run() -> None:
        caller = ProcessCaller(timeout=5, concurrency=1, command=[sys.executable, "-B", "-c",
            "import sys,time; sys.stdout.write('x'*1000000); sys.stdout.flush(); time.sleep(60)"])
        result = await caller.call("search_policy", {"query": "policy"})
        assert isinstance(result.result, ToolError) and result.result.detail == "result_invalid_or_too_large"
        assert not caller.active
    asyncio.run(run())


@pytest.mark.parametrize("frame", [b"", b"x" * 20000 + b"\n", b"private-canary-not-json\n"])
def test_server_exits_and_is_reaped_on_eof_or_oversize_frame(frame: bytes) -> None:
    with subprocess.Popen([sys.executable, "-B", "-m", "policyops.mcp"], env=environment(),
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        stdout, stderr = process.communicate(frame, timeout=15)
        assert process.returncode in (0, 2)
        assert b"synthetic-mcp-session" not in stdout + stderr
        assert b"private-canary" not in stdout + stderr


def test_worker_exits_when_parent_pipe_closes(tmp_path: Path) -> None:
    # This is the real worker's parent-death watchdog, without any database access.
    source = ("import sys,time; from policyops.mcp.worker import parent_watch; import threading; "
              "threading.Thread(target=parent_watch,daemon=True).start(); "
              "sys.stdout.write('ready\\n'); sys.stdout.flush(); time.sleep(60)")
    with subprocess.Popen([sys.executable, "-B", "-c", source], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        assert process.stdout is not None and process.stdin is not None
        assert process.stdout.readline().strip() == b"ready"
        process.stdin.close()
        assert process.wait(timeout=10) == 1


@pytest.mark.parametrize("client_timeout", [False, True])
def test_real_mcp_timeout_or_cancel_reaps_inflight_worker(tmp_path: Path, client_timeout: bool) -> None:
    marker = tmp_path / "reaped.txt"
    source = textwrap.dedent(f"""\
        from pathlib import Path
        import sys
        from policyops.mcp import server
        from policyops.mcp.process import ProcessCaller
        class Blocking(ProcessCaller):
            def __init__(self, **kwargs):
                super().__init__(**kwargs, command={framed_worker(tmp_path)!r})
            async def stop(self, process):
                await super().stop(process)
                Path({str(marker)!r}).write_bytes(str(process.returncode).encode())
        server.ProcessCaller = Blocking
        server.main()
    """)
    script = tmp_path / "blocking_server.py"
    script.write_bytes(source.encode("utf-8"))
    env = environment()
    config = Configuration.model_validate_json(env["POLICYOPS_MCP_CONFIG"])
    env["POLICYOPS_MCP_CONFIG"] = config.model_copy(update={"timeout_seconds": 10 if client_timeout else 1}) \
        .model_dump_json()
    async def run() -> None:
        params = StdioServerParameters(command=sys.executable, args=["-B", str(script)], env=env)
        async with (stdio_client(params) as (read, write),
                    ClientSession(read, write, read_timeout_seconds=15) as session):
            await session.initialize()
            if client_timeout:
                with pytest.raises((TimeoutError, MCPError)):
                    await session.call_tool("search_policy", {"query": "block"}, read_timeout_seconds=0.3)
            else:
                framed = await session.call_tool("search_policy", {"query": "block"})
                payload = Result.model_validate_json(json.dumps(framed.structured_content))
                assert isinstance(payload.result, ToolError) and payload.result.detail == "call_timeout"
            with anyio.fail_after(3):
                while not marker.exists():
                    await anyio.sleep(.01)
            assert marker.read_text(encoding="utf-8")
            framed = await session.call_tool("search_policy", {"query": "ok"})
            assert isinstance(Result.model_validate_json(json.dumps(framed.structured_content)).result,
                              PolicyObservation)
            assert framed.meta == {"policyops/worker_phase": "cold"}
    asyncio.run(run())


def framed_worker(tmp_path: Path) -> list[str]:
    """Lightweight real process, controllable only through test query data, with PID as generation ID."""
    path = tmp_path / "framed_worker.py"
    path.write_bytes(textwrap.dedent("""\
        import json, os, sys, time, uuid
        def exact(size):
            body = b''
            while len(body) < size:
                chunk = sys.stdin.buffer.read(size - len(body))
                if not chunk:
                    sys.exit(0)
                body += chunk
            return body
        while True:
            raw = exact(int.from_bytes(exact(4), 'big'))
            query = json.loads(raw)['arguments']['query']
            if query == 'block':
                time.sleep(60)
            if query == 'crash':
                sys.exit(1)
            if query == 'oversize':
                sys.stdout.buffer.write((1000000).to_bytes(4, 'big'))
                sys.stdout.buffer.flush()
                time.sleep(60)
            if query == 'failure':
                result = {'kind': 'error', 'code': 'unavailable', 'detail': 'call_failed', 'retryable': False}
            else:
                result = {'kind': 'policy', 'tool': 'search_policy', 'generation_id': str(uuid.UUID(int=os.getpid())),
                          'citations': [], 'claim_support_validated': False}
            body = b'bad-json' if query == 'invalid' else json.dumps({'result': result}).encode()
            if query == 'truncated':
                sys.stdout.buffer.write(len(body).to_bytes(4, 'big') + body[:5])
                sys.stdout.buffer.flush()
                sys.exit(0)
            sys.stdout.buffer.write(len(body).to_bytes(4, 'big') + body)
            sys.stdout.buffer.flush()
    """).encode("utf-8"))
    return [sys.executable, "-B", str(path)]


def worker_pid(result: Result) -> int:
    assert isinstance(result.result, PolicyObservation)
    return result.result.generation_id.int


def test_warm_worker_reuses_process_and_recycles_at_call_and_age_caps(tmp_path: Path) -> None:
    async def run() -> None:
        caller = ProcessCaller(timeout=5, concurrency=1, command=framed_worker(tmp_path), max_calls=2)
        try:
            first = worker_pid(await caller.call("search_policy", {"query": "ok"}))
            process = next(iter(caller.active))
            assert caller.phase.get() == "cold"
            assert worker_pid(await caller.call("search_policy", {"query": "ok"})) == first
            assert caller.phase.get() == "warm"
            assert process.returncode is not None and not caller.active  # second clean call hits cap
            third = worker_pid(await caller.call("search_policy", {"query": "ok"}))
            assert third != first and caller.phase.get() == "cold"
            process = next(iter(caller.active))
            caller.idle[0].created_at -= caller.max_age + 1  # controlled age, no wall-clock sleep
            assert worker_pid(await caller.call("search_policy", {"query": "ok"})) != third
            assert process.returncode is not None and caller.phase.get() == "cold"
        finally:
            await caller.close()
        assert not caller.active and not caller.idle and caller.limiter.borrowed_tokens == 0
    asyncio.run(run())


@pytest.mark.parametrize("query", ["block", "oversize", "failure", "invalid", "truncated", "crash", "cancel"])
def test_unclean_warm_call_kills_worker_and_next_call_uses_fresh_process(tmp_path: Path, query: str) -> None:
    async def run() -> None:
        caller = ProcessCaller(timeout=5, concurrency=1, command=framed_worker(tmp_path))
        try:
            first = worker_pid(await caller.call("search_policy", {"query": "ok"}))
            process = next(iter(caller.active))
            caller.timeout = .25
            if query == "cancel":
                with anyio.move_on_after(.1) as scope:
                    await caller.call("search_policy", {"query": "block"})
                assert scope.cancel_called
            else:
                result = await caller.call("search_policy", {"query": query})
                assert isinstance(result.result, ToolError) and result.result.code == "unavailable"
            assert process.returncode is not None and not caller.active and not caller.idle
            assert caller.limiter.borrowed_tokens == 0
            caller.timeout = 5
            assert worker_pid(await caller.call("search_policy", {"query": "ok"})) != first
            assert caller.phase.get() == "cold"
        finally:
            await caller.close()
        assert not caller.active
    asyncio.run(run())


def test_cold_mode_discards_every_clean_worker(tmp_path: Path) -> None:
    async def run() -> None:
        caller = ProcessCaller(timeout=5, concurrency=1, command=framed_worker(tmp_path), mode="cold")
        first = worker_pid(await caller.call("search_policy", {"query": "ok"}))
        assert not caller.active
        assert worker_pid(await caller.call("search_policy", {"query": "ok"})) != first
        assert not caller.active and caller.phase.get() == "cold"
        await caller.close()
    asyncio.run(run())


def test_client_exit_reaps_idle_warm_worker(tmp_path: Path) -> None:
    marker = tmp_path / "idle-reaped.txt"
    source = textwrap.dedent(f"""\
        from pathlib import Path
        from policyops.mcp import server
        from policyops.mcp.process import ProcessCaller
        class Recorded(ProcessCaller):
            async def stop(self, process):
                await super().stop(process)
                Path({str(marker)!r}).write_bytes(str(process.returncode).encode())
        server.ProcessCaller = Recorded
        server.main()
    """)
    script = tmp_path / "recorded_server.py"
    script.write_bytes(source.encode("utf-8"))
    async def run() -> None:
        params = StdioServerParameters(command=sys.executable, args=["-B", str(script)], env=environment())
        async with (stdio_client(params) as (read, write), ClientSession(read, write) as session):
            await session.initialize()
            for phase in ("cold", "warm"):
                result = await session.call_tool("search_policy", {"query": "policy"})
                assert result.meta == {"policyops/worker_phase": phase}
                assert not marker.exists()
        assert marker.read_text(encoding="utf-8")
    asyncio.run(run())


def test_real_worker_initializes_resources_once_and_health_failure_replaces_it(tmp_path: Path) -> None:
    setup_log, health_log, fail = (tmp_path / name for name in ("setup.log", "health.log", "fail"))
    source = textwrap.dedent(f"""\
        import os
        from pathlib import Path
        from types import SimpleNamespace
        from uuid import UUID
        from policyops.mcp import worker
        from policyops.mcp.contracts import PolicyObservation, Result
        def append(path, value):
            with Path(path).open('a', encoding='utf-8') as output:
                output.write(value + '\\n')
        class Reader:
            auth = SimpleNamespace(auth_engine='auth')
            engine = 'app'
            def call(self, name, values):
                return Result(result=PolicyObservation(generation_id=UUID(int=os.getpid()), citations=()))
        def service(*args):
            append({str(setup_log)!r}, 'setup')
            return Reader()
        def verify(engine, role):
            if Path({str(fail)!r}).exists():
                raise RuntimeError('synthetic failed health check')
            append({str(health_log)!r}, engine)
        worker.service = service
        worker.verify_runtime_role = verify
        worker.main()
    """)
    script = tmp_path / "real_worker.py"
    script.write_bytes(source.encode("utf-8"))
    async def run() -> None:
        caller = ProcessCaller(timeout=10, concurrency=1, environment=active_environment(),
                               command=[sys.executable, "-B", str(script)])
        try:
            first = worker_pid(await caller.call("search_policy", {"query": "ok"}))
            assert worker_pid(await caller.call("search_policy", {"query": "ok"})) == first
            assert setup_log.read_text(encoding="utf-8").splitlines() == ["setup"]
            assert health_log.read_text(encoding="utf-8").splitlines() == ["auth", "app"] * 2
            process = next(iter(caller.active))
            fail.write_bytes(b"fail health check")
            result = await caller.call("search_policy", {"query": "ok"})
            assert isinstance(result.result, ToolError) and result.result.detail == "call_failed"
            assert process.returncode is not None and not caller.active
            fail.unlink()
            assert worker_pid(await caller.call("search_policy", {"query": "ok"})) != first
            assert setup_log.read_text(encoding="utf-8").splitlines() == ["setup"] * 2
            assert health_log.read_text(encoding="utf-8").splitlines() == ["auth", "app"] * 3
        finally:
            await caller.close()
        assert not caller.active
    asyncio.run(run())


@pytest.mark.parametrize("blocked", [False, True])
def test_real_worker_watchdog_detects_eof_after_framed_call(tmp_path: Path, blocked: bool) -> None:
    entered = tmp_path / "entered"
    source = textwrap.dedent(f"""\
        import time
        from pathlib import Path
        from policyops.mcp import worker
        from policyops.mcp.contracts import error
        from policyops_contracts.errors import ErrorCode
        def execute(*args):
            Path({str(entered)!r}).write_bytes(b'entered')
            if {blocked!r}:
                time.sleep(60)
            return error(ErrorCode.UNAUTHENTICATED, 'identity_refused')
        worker.service = lambda *args: object()
        worker.execute = execute
        worker.main()
    """)
    script = tmp_path / "eof_worker.py"
    script.write_bytes(source.encode("utf-8"))
    with subprocess.Popen([sys.executable, "-B", str(script)], env=active_environment(),
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        assert process.stdin is not None and process.stdout is not None
        body = json.dumps({"name": "search_policy", "arguments": {"query": "policy"}}).encode()
        process.stdin.write(len(body).to_bytes(4, "big") + body)
        process.stdin.flush()
        if not blocked:
            size = int.from_bytes(process.stdout.read(4), "big")
            assert isinstance(Result.model_validate_json(process.stdout.read(size)).result, ToolError)
        deadline = time.monotonic() + 10
        while not entered.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert entered.exists()
        process.stdin.close()
        assert process.wait(timeout=5) == 1


def test_failed_kill_preserves_ownership_and_closes_new_worker_admission() -> None:
    class Unkillable:
        returncode = None

        def kill(self) -> None:
            raise PermissionError("synthetic OS kill rejection")

    async def run() -> None:
        caller = ProcessCaller(timeout=1, concurrency=1)
        process = cast(Process, Unkillable())  # no real OS resource is created by this fault injection
        caller.active.add(process)
        with pytest.raises(PermissionError, match="synthetic OS kill rejection"):
            await caller.stop(process)
        assert caller.closed and process in caller.active
        result = await caller.call("search_policy", {"query": "policy"})
        assert isinstance(result.result, ToolError) and result.result.detail == "call_failed"
        assert caller.limiter.borrowed_tokens == 0 and caller.active == {process}
    asyncio.run(run())
