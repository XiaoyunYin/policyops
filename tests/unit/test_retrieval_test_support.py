"""Controls for the T13 `run_threads` test helper with scripted actors and cancellation (no real threads, no
database): every started actor is joined, bounded, through start, cancellation and join failures; the primary failure
is re-raised with type-only secondary notes; an unconfirmed stop is reported, never assumed. Offline only."""

from __future__ import annotations

from collections.abc import Callable, Collection
from typing import Any

import pytest

from policyops_testing.retrieval_fixtures import run_threads


class StartupFailure(RuntimeError):
    pass


class CancelFailure(RuntimeError):
    pass


class JoinFailure(RuntimeError):
    pass


class Script:
    """Scripted actors: `fail_start` ordinals raise on start; `fail_join` ordinals raise on their cleanup join; `stuck`
    ordinals never stop; the others stop at their first join after the cancellation, or run their target on start
    when `run_on_start`."""

    def __init__(self, *, fail_start: Collection[int] = (), stuck: Collection[int] = (),
                 fail_join: Collection[int] = (), run_on_start: bool = False,
                 cancel_error: Exception | None = None) -> None:
        self.fail_start, self.stuck, self.fail_join = fail_start, stuck, fail_join
        self.run_on_start, self.cancel_error = run_on_start, cancel_error
        self.actors: list[Actor] = []
        self.cancels = 0
        self.startup = StartupFailure("scripted start failure")

    def factory(self, *, target: Callable[[], None], daemon: bool) -> Actor:
        assert daemon
        actor = Actor(self, len(self.actors), target)
        self.actors.append(actor)
        return actor

    def cancel(self, _db: Any) -> None:
        self.cancels += 1
        if self.cancel_error is not None:
            raise self.cancel_error


class Actor:
    def __init__(self, script: Script, ordinal: int, target: Callable[[], None]) -> None:
        self.script, self.ordinal, self.target = script, ordinal, target
        self.joins: list[float | None] = []
        self.alive = False

    def start(self) -> None:
        if self.ordinal in self.script.fail_start:
            raise self.script.startup
        if self.script.run_on_start:
            self.target()
        else:
            self.alive = True

    def join(self, timeout: float | None = None) -> None:
        self.joins.append(timeout)
        if self.ordinal in self.script.fail_join and self.script.cancels:  # only the cleanup join fails
            raise JoinFailure("scripted join failure")
        if self.script.cancels and self.ordinal not in self.script.stuck:
            self.alive = False

    def is_alive(self) -> bool:
        return self.alive


def call(script: Script, count: int) -> None:
    run_threads(None, [lambda: None] * count, timeout=0.0, join_seconds=0.5,  # type: ignore[arg-type]
                thread_factory=script.factory, cancel=script.cancel)


def test_a_start_failure_and_a_cancellation_failure_keep_the_primary_and_still_join_every_started_actor() -> None:
    script = Script(fail_start={1}, cancel_error=CancelFailure("scripted cancel failure"))
    with pytest.raises(StartupFailure) as raised:
        call(script, 3)
    assert raised.value is script.startup
    assert raised.value.__notes__ == ["statement cancellation failed: CancelFailure"]
    assert len(script.actors) == 2 and script.cancels == 1  # the third was never created
    assert script.actors[0].joins == [0.5] and script.actors[1].joins == []  # never started, never joined
    assert not script.actors[0].alive


def test_an_unconfirmed_stop_is_reported_on_the_primary() -> None:
    script = Script(fail_start={1}, stuck={0}, cancel_error=CancelFailure("scripted cancel failure"))
    with pytest.raises(StartupFailure) as raised:
        call(script, 2)
    assert raised.value.__notes__ == ["statement cancellation failed: CancelFailure",
                                      "1 test thread(s) still alive after cancellation; stop not confirmed"]
    assert script.actors[0].joins == [0.5]


def test_a_failing_cleanup_join_does_not_skip_the_next_actor() -> None:
    script = Script(fail_join={0})
    with pytest.raises(TimeoutError, match="did not stop after cancellation; stop not confirmed") as raised:
        call(script, 2)
    assert raised.value.__notes__ == ["cleanup join failed: JoinFailure"]
    assert script.actors[1].joins == [0.0, 0.5] and not script.actors[1].alive and script.cancels == 1


def test_a_deadline_overrun_is_the_primary_even_when_every_actor_then_stops() -> None:
    script = Script()
    with pytest.raises(TimeoutError, match="exceeded the deadline and were cancelled") as raised:
        call(script, 2)
    assert getattr(raised.value, "__notes__", []) == []
    assert [a.joins for a in script.actors] == [[0.0, 0.5], [0.0, 0.5]]


def test_a_worker_error_is_raised_without_cancellation_when_every_actor_finished() -> None:
    script = Script(run_on_start=True)

    def broken() -> None:
        raise KeyError("worker failure")

    with pytest.raises(KeyError, match="worker failure"):
        run_threads(None, [broken, lambda: None], timeout=0.0, thread_factory=script.factory,  # type: ignore[arg-type]
                    cancel=script.cancel)
    assert script.cancels == 0 and [a.joins for a in script.actors] == [[0.0], [0.0]]


def test_a_clean_run_returns_without_cancellation() -> None:
    script = Script(run_on_start=True)
    run_threads(None, [lambda: None] * 3, timeout=0.0, thread_factory=script.factory,  # type: ignore[arg-type]
                cancel=script.cancel)
    assert script.cancels == 0 and all(a.joins == [0.0] for a in script.actors)
