"""Finite controls for the T25 operator-client host helper: no Node/Vite/PostgreSQL child, no real reader thread
for the lifecycle cases (fake `Popen`/`Thread`), and in-memory streams for the protocol bounds. The Node framing and
trace bounds run the host module's exported functions in one short-lived pinned-Node process."""

from __future__ import annotations

from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any

import pytest

from policyops_testing import operator_client as m
from policyops_testing.operator_client import HostError, OperatorClientHost


REPOSITORY = Path(__file__).resolve().parents[2]


class FakeProcess:
    """A `Popen` stand-in whose first `wait` raises `wait_error` (if given); later waits report exit 0."""

    def __init__(self, wait_error: BaseException | None = None) -> None:
        self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
        self.returncode: int | None = None
        self.wait_error = wait_error
        self.waits = 0

    def wait(self, timeout: float | None = None) -> int:
        assert timeout is not None  # every wait is bounded
        self.waits += 1
        if self.waits == 1 and self.wait_error is not None:
            raise self.wait_error
        self.returncode = 0
        return 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = 0

    def pipes_closed(self) -> list[bool]:
        return [self.stdin.closed, self.stdout.closed, self.stderr.closed]


class FakeThread:
    def __init__(self, start_error: BaseException | None = None, stops: bool = True) -> None:
        self.ident: int | None = None
        self.start_error, self.stops = start_error, stops
        self.joins: list[float | None] = []

    def start(self) -> None:
        if self.start_error is not None:
            raise self.start_error
        self.ident = 1

    def join(self, timeout: float | None = None) -> None:
        assert self.ident is not None, "joined a reader that never started"
        self.joins.append(timeout)

    def is_alive(self) -> bool:
        return self.ident is not None and not (self.stops and self.joins)


def host_with(monkeypatch: pytest.MonkeyPatch, process: FakeProcess, *threads: FakeThread) -> OperatorClientHost:
    made = iter(threads)
    monkeypatch.setattr(threading, "Thread", lambda *a, **k: next(made))
    host = OperatorClientHost(process, ())  # type: ignore[arg-type]
    host._start_readers()
    return host


def test_partial_reader_start_preserves_the_primary_and_releases_what_started(monkeypatch: pytest.MonkeyPatch) -> None:
    primary = OSError("synthetic second reader start failure")
    process = FakeProcess(wait_error=RuntimeError("synthetic wait failure"))
    first, second = FakeThread(), FakeThread(start_error=primary)
    made = iter((first, second))
    monkeypatch.setattr(m, "node_executable", lambda: "synthetic-node")
    monkeypatch.setattr(m, "child_environment", lambda port: {})
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(threading, "Thread", lambda *a, **k: next(made))
    with pytest.raises(OSError) as raised:
        OperatorClientHost.start(web_root=REPOSITORY, proxy_port=9)
    assert raised.value is primary
    assert first.joins == [m.JOIN_READER] and second.joins == []  # only the started reader is joined, bounded
    assert process.pipes_closed() == [True, True, True]
    assert process.waits == 2  # the failed wait did not stop the remaining release steps


def test_cleanup_failure_is_reported_persistently_and_never_masks_an_active_error(
        monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(wait_error=RuntimeError("synthetic close wait failure"))
    readers = (FakeThread(), FakeThread())
    host = host_with(monkeypatch, process, *readers)
    primary = ValueError("the active scenario failure")
    with pytest.raises(ValueError) as raised, ExitStack() as stack:
        stack.enter_context(host)
        raise primary
    assert raised.value is primary
    first = host.issues
    assert first == ["waiting for the host failed: RuntimeError"]  # then terminated and confirmed exited
    assert all(r.joins == [m.JOIN_READER] for r in readers) and process.pipes_closed() == [True, True, True]
    assert host.close() == first and host.close() == first  # repeated close keeps the truthful record
    assert all(len(r.joins) == 1 for r in readers)


def test_interrupt_during_close_is_raised_after_the_remaining_releases(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(wait_error=KeyboardInterrupt())
    readers = (FakeThread(), FakeThread())
    host = host_with(monkeypatch, process, *readers)
    with pytest.raises(KeyboardInterrupt):
        host.close()  # no active error: the interrupt is not swallowed
    assert process.pipes_closed() == [True, True, True] and all(r.joins for r in readers)
    interrupted = ["reaping the host interrupted: KeyboardInterrupt",
                   "uncertain: the Node host process may still be running"]
    assert host.close() == interrupted
    # With an interrupt already propagating, a second interrupt during release does not replace it.
    other = host_with(monkeypatch, FakeProcess(wait_error=KeyboardInterrupt()), FakeThread(), FakeThread())
    assert other._release(SystemExit(5)) == interrupted


@pytest.mark.parametrize("entry", ["start", "context"])
@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
def test_an_interrupted_release_never_replaces_an_active_ordinary_error(
        monkeypatch: pytest.MonkeyPatch, entry: str, interrupt: type[BaseException]) -> None:
    process = FakeProcess(wait_error=interrupt())
    primary = OSError("synthetic setup or scenario failure")
    if entry == "start":
        first, second = FakeThread(), FakeThread(start_error=primary)
        made = iter((first, second))
        monkeypatch.setattr(m, "node_executable", lambda: "synthetic-node")
        monkeypatch.setattr(m, "child_environment", lambda port: {})
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
        monkeypatch.setattr(threading, "Thread", lambda *a, **k: next(made))
        with pytest.raises(OSError) as raised:
            OperatorClientHost.start(web_root=REPOSITORY, proxy_port=9)
        readers: tuple[FakeThread, ...] = (first,)
    else:
        readers = (FakeThread(), FakeThread())
        host = host_with(monkeypatch, process, *readers)
        with pytest.raises(OSError) as raised, host:
            raise primary
        assert host.issues[0] == f"reaping the host interrupted: {interrupt.__name__}"
    assert raised.value is primary  # the exact original, not merely its __context__
    assert raised.value.__notes__ == [f"host release was interrupted by {interrupt.__name__}"]
    assert process.pipes_closed() == [True, True, True] and all(r.joins == [m.JOIN_READER] for r in readers)


def test_a_reader_that_does_not_stop_keeps_its_pipe_and_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess()
    stuck = FakeThread(stops=False)
    host = host_with(monkeypatch, process, stuck, FakeThread())
    issues = host.close()
    assert stuck.joins == [m.JOIN_READER]
    assert process.pipes_closed() == [True, False, True]  # stdout stays open behind the live reader's lock
    assert issues == ["uncertain: a host output reader did not stop; its pipe is left open"]


class CountingStream(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.requests: list[int] = []

    def readline(self, size: int | None = -1) -> bytes:
        assert size is not None and size > 0  # never an unbounded line read
        self.requests.append(size)
        return super().readline(size)


def bare_host() -> OperatorClientHost:
    return OperatorClientHost(FakeProcess(), ())  # type: ignore[arg-type]


def test_stdout_frames_and_backlog_are_bounded_before_materialisation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(m, "MAX_FRAME_BYTES", 64)
    host = bare_host()
    stream = CountingStream(b'{"id": 1}\n' + b"x" * 1000 + b'\n{"id": 2}\n')
    host._pump_stdout(stream)
    assert set(stream.requests) == {65}
    assert host._read(1) == {"id": 1}
    with pytest.raises(HostError, match="a frame exceeded 64 bytes"):
        host._read(1)  # the frame after an oversize one is drained, not delivered
    host = bare_host()
    host._pump_stdout(io.BytesIO(b"".join(b'{"id": %d}\n' % i for i in range(m.MAX_BACKLOG + 3))))
    assert len(host._frames) == m.MAX_BACKLOG
    assert [host._read(1)["id"] for _ in range(m.MAX_BACKLOG)] == list(range(m.MAX_BACKLOG))
    with pytest.raises(HostError, match=f"more than {m.MAX_BACKLOG} unread frames"):
        host._read(1)


def test_stderr_tail_keeps_bounded_lines_and_marks_truncation() -> None:
    host = bare_host()
    lines = [b"y" * 10_000 + b"\n"] + [b"line %d\n" % i for i in range(m.MAX_STDERR_LINES + 5)]
    stream = CountingStream(b"".join(lines))
    host._pump_stderr(stream)
    assert set(stream.requests) == {m.MAX_STDERR_LINE_BYTES}
    assert len(host._stderr) == m.MAX_STDERR_LINES and host._stderr[-1] == f"line {m.MAX_STDERR_LINES + 4}"
    host = bare_host()
    host._pump_stderr(io.BytesIO(b"z" * 2000 + b"\nnext\n"))
    assert list(host._stderr) == ["z" * m.MAX_STDERR_LINE_BYTES + " [truncated]", "next"]


def make_junction(link: Path, target: Path) -> None:
    if sys.platform == "win32":  # mypy narrows platform-only APIs on this check
        import _winapi
        _winapi.CreateJunction(str(target), str(link))  # needs no symlink privilege
    else:
        link.symlink_to(target, target_is_directory=True)


def test_report_path_must_be_a_new_file_inside_the_temp_root(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / "proof").mkdir(parents=True)
    outside.mkdir()
    good = root / "proof" / "wire.json"
    assert m.checked_report_path(str(good), str(root), REPOSITORY) == good.resolve()
    m.write_report(good, b"{}\n")
    refused = {
        "existing": str(good),
        "relative": "proof/wire.json",
        "outside": str(outside / "wire.json"),
        "traversal": str(root / ".." / "outside" / "wire.json"),
        "missing parent": str(root / "absent" / "wire.json"),
        "repository": str(REPOSITORY / "wire.json"),
        "no temp root": None,
    }
    make_junction(root / "escape", outside)
    refused["link escape"] = str(root / "escape" / "wire.json")
    for case, raw in refused.items():
        with pytest.raises(HostError):
            m.checked_report_path(raw or str(good.with_name("other.json")), None if raw is None else str(root),
                                  REPOSITORY)
        assert not (outside / "wire.json").exists() and not (REPOSITORY / "wire.json").exists(), case
    with pytest.raises(FileExistsError):
        m.write_report(good, b"again\n")  # exclusive creation: a file appearing after validation is refused


NODE_CHECK = r"""
const host = await import(process.argv[1]);
const framer = host.createFramer(8);
const frames = [...framer.push(Buffer.from('{"a":1}\n123456789')), ...framer.push(Buffer.from('xyz\n{"b":2}\npart'))];
const held = framer.held();
const tail = framer.end();
const body = (text) => new Response(text).body;
const full = await host.traceBody(body("abc"), 3);
const over = await host.traceBody(body("abcd"), 3);
const reply = host.encodeReply({ id: 7, ok: true, value: "x".repeat(100) }, 64);
process.stdout.write(JSON.stringify({ frames, held, tail, full, over, reply }));
"""


def test_node_framing_trace_and_reply_bounds() -> None:
    node = m.node_executable()
    script = m.HOST_SCRIPT.as_uri()
    done = subprocess.run([node, "--input-type=module", "-e", NODE_CHECK, script], capture_output=True, timeout=60,
                          check=False, env={**os.environ, "NODE_OPTIONS": ""})
    assert done.returncode == 0, done.stderr[-2000:]
    out: dict[str, Any] = json.loads(done.stdout)
    assert out["frames"] == ['{"a":1}', None, '{"b":2}']  # the 12-byte frame was discarded, never held
    assert out["held"] == 4 and out["tail"] is True
    assert out["full"] == {"body_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                           "body_bytes": 3, "body_complete": True}
    assert out["over"]["body_sha256"] is None and out["over"]["body_truncated"] is True
    assert json.loads(out["reply"]) == {"id": 7, "ok": False, "error": {"name": "ReplyTooLarge"}}
