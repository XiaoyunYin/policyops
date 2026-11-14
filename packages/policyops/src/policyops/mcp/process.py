"""Bounded warm process pool: an unclean call always forfeits its worker."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import dataclass
import os
import subprocess
import sys
import time
from typing import Any, Literal

import anyio
from anyio.abc import ByteReceiveStream, Process

from policyops.mcp.contracts import MAX_RESULT_BYTES, Result, arguments, bounded, error
from policyops.providers.canonical import canonical_bytes
from policyops_contracts.errors import ErrorCode
from policyops_contracts.gateway import ToolError


async def receive_exact(stream: ByteReceiveStream, size: int) -> bytes:
    body = bytearray()
    while len(body) < size:
        body.extend(await stream.receive(size - len(body)))
    return bytes(body)


@dataclass
class Worker:
    process: Process
    created_at: float
    calls: int = 0


class ProcessCaller:
    def __init__(self, *, timeout: float, concurrency: int, environment: Mapping[str, str] | None = None,
                 command: Sequence[str] | None = None, mode: Literal["cold", "warm"] = "warm",
                 max_calls: int = 100, max_age: float = 300) -> None:
        if (not 0 < timeout <= 30 or not 1 <= concurrency <= 4 or mode not in ("cold", "warm")
                or not 1 <= max_calls <= 1000 or not 0 < max_age <= 3600):
            raise ValueError("invalid process bounds")
        self.timeout, self.mode, self.max_calls, self.max_age = timeout, mode, max_calls, max_age
        self.limiter = anyio.CapacityLimiter(concurrency)
        self.environment = dict(os.environ if environment is None else environment)
        self.command = list(command or (sys.executable, "-B", "-m", "policyops.mcp.worker"))
        self.active: set[Process] = set()
        self.idle: list[Worker] = []
        self.closed = False
        # Request-local telemetry only; no identity, worker PID or secret enters the MCP metadata.
        self.phase: ContextVar[str] = ContextVar("worker_phase", default="facade")

    def expired(self, worker: Worker) -> bool:
        return worker.calls >= self.max_calls or time.monotonic() - worker.created_at >= self.max_age

    async def call(self, name: str, values: dict[str, Any]) -> Result:
        self.phase.set("facade")
        parsed = arguments(name, values)
        if isinstance(parsed, Result):
            return parsed
        if self.closed:
            return error(ErrorCode.UNAVAILABLE, "call_failed")
        try:
            self.limiter.acquire_nowait()
        except anyio.WouldBlock:
            return error(ErrorCode.UNAVAILABLE, "concurrency_limit", retryable=True)
        worker = None
        clean = False
        try:
            with anyio.fail_after(self.timeout):
                while self.idle:
                    candidate = self.idle.pop()
                    if candidate.process.returncode is not None or self.expired(candidate):
                        with anyio.CancelScope(shield=True):
                            await self.stop(candidate.process)
                    else:
                        worker = candidate
                        break
                self.phase.set("cold" if worker is None else "warm")
                if worker is None:
                    # Record ownership before allowing cancellation, including cancellation during spawning.
                    with anyio.CancelScope(shield=True):
                        process = await anyio.open_process(self.command, env=self.environment,
                                                          stderr=subprocess.DEVNULL)
                        self.active.add(process)
                        worker = Worker(process, time.monotonic())
                if worker is None:  # a cancel scope can suppress its own cancellation
                    raise RuntimeError("child acquisition interrupted")
                await anyio.lowlevel.checkpoint()
                process = worker.process
                if process.stdin is None or process.stdout is None:
                    raise RuntimeError("missing child pipes")
                body = canonical_bytes({"name": name, "arguments": values})
                await process.stdin.send(len(body).to_bytes(4, "big") + body)
                # Length-prefixed frames bound allocation and permit reuse without waiting for stdout EOF.
                size = int.from_bytes(await receive_exact(process.stdout, 4), "big")
                if not 0 < size <= MAX_RESULT_BYTES:
                    return error(ErrorCode.UNAVAILABLE, "result_invalid_or_too_large")
                result = bounded(Result.model_validate_json(await receive_exact(process.stdout, size)))
                worker.calls += 1
                # Expected policy/identity refusals are clean results; infrastructure/validation failures are not.
                clean = not (isinstance(result.result, ToolError) and result.result.code == ErrorCode.UNAVAILABLE)
                return result
        except TimeoutError:
            return error(ErrorCode.UNAVAILABLE, "call_timeout", retryable=True)
        except Exception:
            return error(ErrorCode.UNAVAILABLE, "call_failed")
        finally:
            try:
                if worker is not None:
                    if clean and self.mode == "warm" and not self.closed and not self.expired(worker):
                        self.idle.append(worker)
                    else:
                        with anyio.CancelScope(shield=True):
                            await self.stop(worker.process)
            finally:
                self.limiter.release()

    async def stop(self, process: Process) -> None:
        # Keep the handle for diagnosis if cleanup cannot be confirmed. Never hide a cleanup failure.
        try:
            with anyio.fail_after(2):
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.kill()
                await process.wait()
                await process.aclose()
        except BaseException:
            self.closed = True  # no new worker admission after an unconfirmed cleanup
            raise
        self.active.discard(process)

    async def close(self) -> None:
        self.closed = True
        self.idle.clear()
        with anyio.CancelScope(shield=True):
            for process in tuple(self.active):
                await self.stop(process)
