"""A task-owned background call for tests that must interleave a request with work on the main thread.

The worker is owned from `start()` until the block exits: whatever the main thread does in between (a failed
readiness wait, a failed query, a failed assertion), leaving the block joins the worker with a bound. Put the
resource the worker is waiting on (a held lock, an event) in an inner block so it is released before the join.
A worker error, a worker that is still alive after the bound, or a failure to join or observe the worker (including
joining a worker whose `Thread.start` itself failed) never masks an error already propagating; it is attached to that
error as a note. With nothing else propagating, any of them fails the block, chained to the cleanup or worker error.
"""

from __future__ import annotations

from collections.abc import Callable
import threading
from types import TracebackType
from typing import Self


class BackgroundCall[T]:
    def __init__(self, call: Callable[[], T], *, join_timeout: float = 30.0) -> None:
        self._call = call
        self._join_timeout = join_timeout
        self._thread: threading.Thread | None = None
        self._result: list[T] = []
        self._error: list[BaseException] = []

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("the background call was already started")
        # Daemon so a worker that never stops cannot hold the interpreter open; it is still reported.
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self._result.append(self._call())
        except BaseException as error:  # captured; result() re-raises it, and leaving the block reports it
            self._error.append(error)

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def result(self) -> T:
        """The call's return value; raises the call's own error, or AssertionError if it has not finished."""
        if self._error:
            raise self._error[0]
        if not self._result:
            raise AssertionError("the background call has not produced a result")
        return self._result[0]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 traceback: TracebackType | None) -> None:
        problems: list[str] = []
        cleanup_error: Exception | None = None
        if self._thread is not None:
            # The worker is owned from before `start()`, so a failed start reaches this join too (CPython refuses to
            # join a thread that never started). A join or observation failure is cleanup context, never the primary.
            # Observation is attempted even if the join failed, so an alive worker is never hidden by a join error.
            try:
                self._thread.join(timeout=self._join_timeout)
            except Exception as error:
                cleanup_error = error
                problems.append(f"the background worker could not be joined: {error!r}")
            try:
                still_alive = self._thread.is_alive()
            except Exception as error:
                cleanup_error = cleanup_error or error
                problems.append(f"the background worker could not be observed: {error!r}")
            else:
                if still_alive:
                    problems.append(
                        f"the background worker was still running {self._join_timeout}s after the block ended")
        if self._error and exc is not self._error[0]:
            problems.append(f"the background call failed: {self._error[0]!r}")
        if exc is not None:
            for problem in problems:
                exc.add_note(problem)
            return
        if problems:
            raise AssertionError("; ".join(problems)) from (
                cleanup_error if cleanup_error is not None else (self._error[0] if self._error else None))
