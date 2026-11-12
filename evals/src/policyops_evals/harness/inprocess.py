"""Visible-DTO-only T20 composition. In-memory wire validation is not an OS sandbox.

One loop owns each invocation's asynchronous work. The synchronous upstream caller
receives one event at a time; only upstream executes tools. Closing cancels the
pending turn, with a finite cleanup grace. Blocking Python/provider work that
ignores cancellation can outlive that grace; such a loop cannot be reused.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from contextlib import suppress
import math
from queue import Empty, Full, Queue
import threading
import time
from typing import Any, TypeVar
from uuid import UUID

from policyops.budget.config import Configuration
from policyops.orchestration.minimal import MinimalAgent, agent_config
from policyops.orchestration.ports import ModelPort
from policyops_contracts import wire
from policyops_contracts.conversation import AgentLimits, AgentToolCall, ToolResult
from policyops_evals.harness.adapter import (
    BridgeEvent,
    OpenSession,
    SessionOpened,
    ToolRequest,
    ToolReturnRequest,
    TurnEnded,
    UserTurnRequest,
)


T = TypeVar("T")


class BridgeRefused(RuntimeError):
    """Fixed diagnostics only: never copy a provider exception or conversation."""


def _seconds(value: float) -> float:
    if isinstance(value, bool) or not math.isfinite(value) or not 0 < value <= 900:
        raise BridgeRefused("budget_invalid")
    return value


class OwnedLoop:
    """An explicitly owned loop/thread, usable by both the agent and other actors."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.closed = False
        self.cleanup_unconfirmed = False
        thread: threading.Thread | None = None
        try:
            self._ready = threading.Event()
            # asyncio's default handler can render task arguments/locals containing
            # untrusted content. Preserve only the fixed cleanup status here.
            self.loop.set_exception_handler(self._loop_error)
            thread = threading.Thread(target=self._run, name="policyops-eval-loop", daemon=True)
            self.thread = thread
            thread.start()
            if not self._ready.wait(2):
                raise BridgeRefused("loop_start_failed")
        except BaseException:
            if thread is not None and thread.is_alive():
                with suppress(BaseException):
                    self.close(seconds=2)
            else:
                self.loop.close()
            raise

    def _loop_error(self, loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        self.cleanup_unconfirmed = True

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self._ready.set()
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()

    def submit(self, work: Coroutine[Any, Any, T]) -> Future[T]:
        if self.closed or self.cleanup_unconfirmed or threading.current_thread() is self.thread:
            work.close()
            raise BridgeRefused("loop_unavailable")
        try:
            return asyncio.run_coroutine_threadsafe(work, self.loop)
        except BaseException:
            work.close()
            raise

    def run(self, work: Coroutine[Any, Any, T], *, seconds: float) -> T:
        try:
            timeout = _seconds(seconds)
        except BaseException:
            work.close()
            raise
        future = self.submit(work)
        try:
            return future.result(timeout)
        except FutureTimeout:
            future.cancel()
            raise BridgeRefused("deadline") from None

    def close(self, *, seconds: float) -> None:
        timeout = _seconds(seconds)
        if self.closed:
            return
        end = time.monotonic() + timeout

        async def cancel() -> bool:
            tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            if tasks:
                _, pending = await asyncio.wait(tasks, timeout=max(0, (end - time.monotonic()) / 2))
                return not pending
            return True

        try:
            future = asyncio.run_coroutine_threadsafe(cancel(), self.loop)
            self.cleanup_unconfirmed |= not future.result(max(0.001, timeout / 2))
        except BaseException:
            self.cleanup_unconfirmed = True
        finally:
            self.closed = True
            if not self.loop.is_closed():
                self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(max(0, end - time.monotonic()))
            self.cleanup_unconfirmed |= self.thread.is_alive()
        if self.cleanup_unconfirmed:
            raise BridgeRefused("cleanup_unconfirmed")


class InProcessAgentBridge:
    """Single-use bridge. Configuration/model are trusted composition inputs only.

    An injected loop is owned by the invocation context; otherwise this bridge owns
    its loop. Provider clients are opened/closed per call by the T11 model port.
    No environment, task, toolkit or tool callback is retained here.
    """

    def __init__(self, configuration: Configuration, model: ModelPort, *, limits: AgentLimits | None = None,
                 loop: OwnedLoop | None = None, env: str | None = None) -> None:
        self.configuration, self.model = configuration, model
        self.limits, self.env = limits, env
        self._owns_loop = loop is None
        self.runtime = loop or OwnedLoop()
        self._connection: wire.WireConnection | None = None
        self._agent: MinimalAgent | None = None
        self._turn: Future[None] | None = None
        self._async_turn: asyncio.Task[None] | None = None
        self._pending: tuple[str, asyncio.Future[ToolResult]] | None = None
        self._events: Queue[wire.ToolRequestBody | wire.TurnEndedBody | BridgeRefused] = Queue(maxsize=1)
        self._busy = threading.Lock()
        self._closed = False
        self.cleanup_unconfirmed = False
        self._end = 0.0
        self._turn_index = 0

    def _timeout(self, seconds: float) -> float:
        left = min(_seconds(seconds), self._end - time.monotonic())
        if self._closed or left <= 0:
            raise BridgeRefused("deadline_or_closed")
        return left

    def _request(self, body: wire.OpenSessionBody | wire.UserTurnBody | wire.ToolReturnBody) -> wire.ToRuntime:
        if self._connection is None:
            raise BridgeRefused("session_unknown")
        emitted = self._connection.request(body)
        return wire.decode_payload(emitted.payload, wire.ToRuntime)

    def _reply(self, request: wire.ToRuntime,
               body: wire.SessionOpenedBody | wire.ToolRequestBody | wire.TurnEndedBody) -> wire.FromRuntime:
        if self._connection is None:
            raise BridgeRefused("session_unknown")
        frame = wire.FromRuntime(session_id=request.session_id, seq=self._connection.next_recv,
                                 reply_to=request.seq, body=body)
        decoded = wire.decode_payload(wire.encode_payload(frame), wire.FromRuntime)
        delivered = self._connection.receive(decoded)
        if not isinstance(delivered, wire.Deliver):
            raise BridgeRefused("wire_not_delivered")
        return delivered.frame

    def open(self, request: OpenSession, *, seconds: float) -> SessionOpened:
        if not self._busy.acquire(blocking=False):
            raise BridgeRefused("busy")
        try:
            if self._closed or self._connection is not None or self.runtime.closed or self.runtime.cleanup_unconfirmed:
                raise BridgeRefused("already_opened")
            self._end = time.monotonic() + _seconds(seconds)
            self._connection = wire.WireConnection(request.session_id)
            frame = self._request(wire.OpenSessionBody(policy=request.policy, catalog=request.catalog,
                opening=request.opening, budget_ms=max(1, int(seconds * 1000))))
            body = frame.body
            if not isinstance(body, wire.OpenSessionBody):
                raise BridgeRefused("wire_body")
            config = agent_config(body.policy, body.catalog, self.configuration, self.limits, opening=True)
            self._agent = MinimalAgent(config, body.policy, body.catalog, conversation_id=frame.session_id,
                model=self.model, tools=self, knowledge=None, configuration=self.configuration,
                opening=body.opening, env=self.env)
            self._reply(frame, wire.SessionOpenedBody(config_sha256=config.digest()))
            return SessionOpened(request.session_id, config.digest())
        except BaseException:
            # Caller owns the ID before open; also release resources for direct bridge users.
            with suppress(BaseException):
                self.close(request.session_id, seconds=1)
            raise
        finally:
            self._busy.release()

    async def execute(self, call: AgentToolCall, *, deadline: float) -> ToolResult:
        if self._pending is not None:
            raise BridgeRefused("tool_pending")
        future: asyncio.Future[ToolResult] = asyncio.get_running_loop().create_future()
        self._pending = (call.call_id, future)
        try:
            self._publish(wire.ToolRequestBody(call=call))
            async with asyncio.timeout_at(deadline):
                return await future
        finally:
            self._pending = None

    def _publish(self, body: wire.ToolRequestBody | wire.TurnEndedBody | BridgeRefused) -> None:
        if self._closed:
            return
        try:
            self._events.put_nowait(body)
        except Full:
            self.cleanup_unconfirmed = True
            self._end = time.monotonic()  # refuse the queued event; never accept dropped handoff work

    async def _drive(self, frame: wire.ToRuntime) -> None:
        if self._agent is None or not isinstance(frame.body, wire.UserTurnBody):
            raise BridgeRefused("wire_body")
        self._async_turn = asyncio.current_task()
        try:
            outcome = await self._agent.turn(frame.body.message, deadline=self._end)
            self._publish(wire.TurnEndedBody(outcome=outcome))
        except asyncio.CancelledError:
            raise
        except Exception:
            self._publish(BridgeRefused("turn_failed"))

    def _event(self, frame: wire.ToRuntime, seconds: float) -> BridgeEvent:
        try:
            body = self._events.get(timeout=self._timeout(seconds))
        except Empty:
            if self._turn is not None:
                self._turn.cancel()
            raise BridgeRefused("deadline") from None
        if isinstance(body, BridgeRefused):
            raise body
        self._timeout(seconds)  # late events are never delivered
        result = self._reply(frame, body)
        seq = wire.to_adapter_seq(result.reply_to)
        if isinstance(result.body, wire.ToolRequestBody):
            return ToolRequest(result.session_id, seq, result.body.call)
        if not isinstance(result.body, wire.TurnEndedBody):
            raise BridgeRefused("wire_body")
        return TurnEnded(result.session_id, seq, result.body.outcome)

    def _check(self, session: UUID, seq: int) -> None:
        if self._connection is None or session != self._connection.session_id:
            raise BridgeRefused("session_mismatch")
        if wire.to_wire_seq(seq) != self._connection.next_send:
            raise BridgeRefused("sequence_mismatch")

    def user_turn(self, request: UserTurnRequest, *, seconds: float) -> BridgeEvent:
        if not self._busy.acquire(blocking=False):
            raise BridgeRefused("busy")
        try:
            self._timeout(seconds)
            self._check(request.session_id, request.seq)
            if request.turn != self._turn_index:
                raise BridgeRefused("turn_mismatch")
            frame = self._request(wire.UserTurnBody(turn=request.turn, message=request.message,
                                                   budget_ms=max(1, int(seconds * 1000))))
            self._turn_index += 1
            self._turn = self.runtime.submit(self._drive(frame))
            return self._event(frame, seconds)
        finally:
            self._busy.release()

    def tool_return(self, request: ToolReturnRequest, *, seconds: float) -> BridgeEvent:
        if not self._busy.acquire(blocking=False):
            raise BridgeRefused("busy")
        try:
            self._timeout(seconds)
            self._check(request.session_id, request.seq)
            if self._pending is None or self._pending[0] != request.result.call_id:
                raise BridgeRefused("call_mismatch")
            frame = self._request(wire.ToolReturnBody(result=request.result,
                                                     budget_ms=max(1, int(seconds * 1000))))
            if not isinstance(frame.body, wire.ToolReturnBody):
                raise BridgeRefused("wire_body")
            future = self._pending[1]

            def deliver() -> None:
                if not future.done():
                    future.set_result(frame.body.result)  # type: ignore[union-attr]

            self.runtime.loop.call_soon_threadsafe(deliver)
            return self._event(frame, seconds)
        finally:
            self._busy.release()

    def close(self, session_id: UUID, *, seconds: float) -> None:
        _seconds(seconds)
        if self._connection is not None and session_id != self._connection.session_id:
            return  # never release somebody else's session
        if self._closed:
            return
        self._closed = True
        # Wake a synchronous caller even when it is waiting on a provider. It
        # receives a refusal, never an event from after close.
        with suppress(Full):
            self._events.put_nowait(BridgeRefused("agent_closed"))
        end = time.monotonic() + seconds

        async def cancel() -> None:
            task = self._async_turn
            if task is not None and not task.done():
                task.cancel()
                _, pending = await asyncio.wait([task], timeout=max(0, (end - time.monotonic()) / 2))
                if pending:
                    raise BridgeRefused("cleanup_unconfirmed")

        cleanup_error = False
        try:
            self.runtime.run(cancel(), seconds=max(0.001, seconds / 2))
        except Exception:
            cleanup_error = True
        try:
            if self._connection is not None:
                emitted = self._connection.close(max(1, int(seconds * 1000)))
                if isinstance(emitted, wire.Emit):
                    frame = wire.decode_payload(emitted.payload, wire.ToRuntime)
                    reply = wire.FromRuntime(session_id=session_id, seq=self._connection.next_recv,
                        reply_to=frame.seq, body=wire.SessionClosedBody())
                    self._connection.receive(wire.decode_payload(wire.encode_payload(reply), wire.FromRuntime))
        finally:
            self.cleanup_unconfirmed |= cleanup_error
            if self._owns_loop:
                self.runtime.close(seconds=max(0.001, end - time.monotonic()))
            # No turn can publish after confirmed cancellation. Keep a single
            # fixed sentinel only while a synchronous caller still needs waking.
            if not self._busy.locked():
                while not self._events.empty():
                    with suppress(Empty):
                        self._events.get_nowait()
        if cleanup_error:
            # Invocation-owned loops must refuse another trial as well.
            self.runtime.cleanup_unconfirmed = True
            raise BridgeRefused("cleanup_unconfirmed")
