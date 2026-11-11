"""The task-owned background call used by the in-flight rotation test (T25a R4).

A setup, query or assertion failure on the main thread must still join the worker (after the held resource is
released), the original error must survive a failing or stuck worker, and a stuck worker must be reported without an
unbounded wait. Everything is finite: controlled events, a tiny join bound, and every real worker is released and
joined in `finally`. A failed `Thread.start` (R6) and a failing join or liveness check must neither mask the primary
error nor pass silently; those cases use a fake thread, so no OS thread is created.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from policyops_testing import background
from policyops_testing.background import BackgroundCall


GENEROUS = 10.0


def settle(worker: BackgroundCall[Any]) -> None:
    """Wait (bounded) for a worker this test owns and has just released."""
    deadline = time.monotonic() + GENEROUS
    while worker.alive and time.monotonic() < deadline:
        time.sleep(0.005)


def test_the_result_is_available_after_the_block_and_the_worker_is_joined() -> None:
    with BackgroundCall(lambda: 41 + 1) as worker:
        worker.start()
    assert worker.result() == 42 and not worker.alive


def test_a_failure_after_start_still_joins_the_worker_once_the_lock_is_released() -> None:
    held = threading.Event()  # stands in for the case lock the worker waits on
    ran = threading.Event()

    def call() -> str:
        assert held.wait(GENEROUS)
        time.sleep(0.05)  # work that outlasts the block unless the block joins the worker
        ran.set()
        return "done"

    worker = BackgroundCall(call, join_timeout=GENEROUS)
    with pytest.raises(RuntimeError, match="select failed") as caught, worker:
        try:
            worker.start()
            raise RuntimeError("select failed")  # readiness, query or select error after start
        finally:
            held.set()  # leaving the lock block, before the worker join
    assert ran.is_set() and not worker.alive and worker.result() == "done"
    assert not getattr(caught.value, "__notes__", [])


def test_a_failure_before_start_has_nothing_to_join() -> None:
    with pytest.raises(RuntimeError, match="setup failed"), BackgroundCall(lambda: 1):
        raise RuntimeError("setup failed")


def test_a_worker_error_never_masks_the_original_failure_and_is_attached_to_it() -> None:
    def call() -> None:
        raise ValueError("worker boom")

    with pytest.raises(RuntimeError, match="primary") as caught, BackgroundCall(call, join_timeout=GENEROUS) as worker:
        worker.start()
        settle(worker)
        raise RuntimeError("primary")
    assert any("worker boom" in note for note in caught.value.__notes__)


def test_a_worker_error_without_another_failure_fails_the_block() -> None:
    def call() -> None:
        raise ValueError("worker boom")

    with pytest.raises(AssertionError, match="worker boom") as caught, BackgroundCall(call) as worker:
        worker.start()
    assert isinstance(caught.value.__cause__, ValueError)
    with pytest.raises(ValueError, match="worker boom"):
        worker.result()


def test_a_stuck_worker_is_reported_after_a_bounded_wait_and_the_original_failure_survives() -> None:
    release = threading.Event()
    worker = BackgroundCall(lambda: release.wait(GENEROUS), join_timeout=0.05)
    try:
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="primary") as caught, worker:
            worker.start()
            raise RuntimeError("primary")
        assert time.monotonic() - started < 5.0
        assert worker.alive
        assert any("still running" in note for note in caught.value.__notes__)
    finally:
        release.set()
        settle(worker)
    assert not worker.alive


def test_a_stuck_worker_without_another_failure_fails_the_block() -> None:
    release = threading.Event()
    worker = BackgroundCall(lambda: release.wait(GENEROUS), join_timeout=0.05)
    try:
        with pytest.raises(AssertionError, match="still running"), worker:
            worker.start()
        assert worker.alive
    finally:
        release.set()
        settle(worker)
    assert not worker.alive


UNSTARTED_JOIN = "cannot join thread before it is started"


class FakeThread:
    """A finite stand-in for `threading.Thread`: no OS thread is ever created. `start`, `join` and `is_alive` fail or
    answer as configured; the join of a thread that never started raises CPython's own RuntimeError."""

    def __init__(self, *, start_error: BaseException | None = None, join_error: BaseException | None = None,
                 alive_error: BaseException | None = None, alive: bool = False) -> None:
        self.start_error, self.join_error, self.alive_error, self.alive = start_error, join_error, alive_error, alive
        self.started = False
        self.join_calls: list[float | None] = []

    def __call__(self, *, target: Any, daemon: bool) -> FakeThread:
        assert callable(target) and daemon  # the worker stays a daemon so it can never hold the interpreter open
        return self

    def start(self) -> None:
        if self.start_error is not None:
            raise self.start_error
        self.started = True

    def join(self, timeout: float | None = None) -> None:
        self.join_calls.append(timeout)
        if self.join_error is not None:
            raise self.join_error
        if not self.started:
            raise RuntimeError(UNSTARTED_JOIN)

    def is_alive(self) -> bool:
        if self.alive_error is not None:
            raise self.alive_error
        return self.alive


def fake_worker(monkeypatch: pytest.MonkeyPatch, fake: FakeThread) -> BackgroundCall[int]:
    # Only the helper module's `threading` name is replaced; the real `threading` module is left alone.
    monkeypatch.setattr(background, "threading", SimpleNamespace(Thread=fake))
    return BackgroundCall(lambda: 1, join_timeout=0.25)


def test_a_failed_thread_start_propagates_the_exact_original_error(monkeypatch: pytest.MonkeyPatch) -> None:
    original = OSError("can't start new thread")
    fake = FakeThread(start_error=original)
    worker = fake_worker(monkeypatch, fake)
    with pytest.raises(OSError) as caught, worker:
        worker.start()
    assert caught.value is original
    assert fake.join_calls == [0.25]  # the worker was owned before start, so cleanup still tried the bounded join
    assert any(UNSTARTED_JOIN in note for note in original.__notes__)  # the cleanup failure is context, not the error
    assert not worker.alive


def test_a_partially_started_worker_is_still_reported_when_the_start_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    original = OSError("start failed after the thread existed")
    fake = FakeThread(start_error=original, alive=True)
    worker = fake_worker(monkeypatch, fake)
    with pytest.raises(OSError) as caught, worker:
        worker.start()
    assert caught.value is original
    assert any("could not be joined" in note and UNSTARTED_JOIN in note for note in original.__notes__)
    assert any("still running" in note for note in original.__notes__)  # never treated as joined
    assert worker.alive


def test_a_join_failure_never_masks_the_primary_error(monkeypatch: pytest.MonkeyPatch) -> None:
    primary = RuntimeError("primary")
    fake = FakeThread(join_error=OSError("join broke"))
    worker = fake_worker(monkeypatch, fake)
    with pytest.raises(RuntimeError) as caught, worker:
        worker.start()
        raise primary
    assert caught.value is primary
    assert any("could not be joined" in note and "join broke" in note for note in primary.__notes__)


def test_an_observation_failure_never_masks_the_primary_error(monkeypatch: pytest.MonkeyPatch) -> None:
    primary = RuntimeError("primary")
    fake = FakeThread(alive_error=OSError("observe broke"))
    worker = fake_worker(monkeypatch, fake)
    with pytest.raises(RuntimeError) as caught, worker:
        worker.start()
        raise primary
    assert caught.value is primary
    assert any("could not be observed" in note and "observe broke" in note for note in primary.__notes__)


def test_a_join_failure_without_another_error_fails_the_block_with_its_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    join_error = OSError("join broke")
    fake = FakeThread(join_error=join_error)
    worker = fake_worker(monkeypatch, fake)
    with pytest.raises(AssertionError, match="could not be joined") as caught, worker:
        worker.start()
    assert caught.value.__cause__ is join_error


def test_a_failed_start_with_an_unjoinable_worker_and_no_primary_cannot_pass_silently(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # Only reachable if the start error is swallowed inside the block: the unjoinable worker must still be reported.
    fake = FakeThread(start_error=OSError("start failed"))
    worker = fake_worker(monkeypatch, fake)
    with (pytest.raises(AssertionError, match=UNSTARTED_JOIN) as caught, worker,
          pytest.raises(OSError, match="start failed")):
        worker.start()
    assert isinstance(caught.value.__cause__, RuntimeError)


def test_a_second_start_is_refused() -> None:
    with BackgroundCall(lambda: 1) as worker:
        worker.start()
        with pytest.raises(RuntimeError, match="already started"):
            worker.start()
