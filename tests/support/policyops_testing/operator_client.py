"""Owner of the Node/Vite host that runs the web app's actual API client for the HTTP/PostgreSQL proof (T25).

`OperatorClientHost.start` launches `operator_client_host.mjs` under the pinned Node, with the unmodified
`apps/web/vite.config.ts` and its `/api` proxy aimed at an owned loopback API port, and returns once the host has
reported the real Vite origin it bound (port 0). The host executes `apps/web/src/api/client.ts` itself through Vite's
transform pipeline, so a `call` is the production client function sending a real request through the real proxy.

Fixture only: Node emulates the browser's Cookie/Origin headers and the readable CSRF cookie; this is not browser,
SameSite, CORS-preflight or rendering evidence. Session and CSRF values reach the child only over its stdin pipe,
never argv or the environment, and stderr is kept as a bounded, redacted tail.

Ownership. The exact `Popen` is owned from the line that creates it: the host object exists before any reader
thread starts, so a failure while starting readers or awaiting readiness releases the child, its pipes and every
reader that actually started, and the original error propagates. Release never replaces an active error with an
ordinary cleanup failure: each step (close stdin, wait, terminate, kill, join, close pipes) is attempted, a failing
step is recorded by type only in `issues`, and the remaining steps still run. An interrupt (`KeyboardInterrupt`,
`SystemExit`) raised by a step is re-raised after the remaining steps only when no error is propagating; an active
error (ordinary or interrupt) stays the exact top-level exception, with the interrupt recorded in `issues` and a note.
`issues` persists: a repeated `close()` returns the same truthful record, never a clean `[]` after a failure.
Each blocking step has its own timeout; there is no claim of a single total deadline. A reader still alive after its
bounded join keeps its pipe (closing a buffered pipe would wait on the live reader's lock); that is reported.
Use the host as a context manager (`ExitStack.enter_context`) so release knows the active exception.

Protocol bounds. Pipes are binary and read with `readline(limit)`: a stdout frame over `MAX_FRAME_BYTES` or more
than `MAX_BACKLOG` unread frames breaks the protocol (reported, the rest drained and discarded), and stderr keeps
`MAX_STDERR_LINES` lines of at most `MAX_STDERR_LINE_BYTES` bytes, marking truncation. Nothing larger is ever
materialised by these readers. Command writes are not deadline-bounded: they are small and the host drains stdin.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
import functools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
from types import TracebackType
from typing import IO, Any

from policyops_testing import redaction


HOST_SCRIPT = Path(__file__).with_name("operator_client_host.mjs")
PINNED_NODE = "v26.13.0"
ORIGIN_PATTERN = re.compile(r"^http://127\.0\.0\.1:[0-9]{1,5}$")
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "NODE_OPTIONS")
CHILD_POLICYOPS = ("POLICYOPS_TEMP_DIR", "POLICYOPS_WEB_CACHE_DIR", "POLICYOPS_WEB_BUILD_DIR")
# A reply carries one client value (the client accepts at most 1e6 response characters) plus its wire log; the host
# replaces a larger reply by a small error before sending it.
MAX_FRAME_BYTES = 4_000_000
MAX_COMMAND_BYTES = 65_536  # the host's own command limit
MAX_BACKLOG = 4  # one reply per command: more unread frames is a protocol violation
MAX_STDERR_LINES = 40
MAX_STDERR_LINE_BYTES = 500
WAIT_EXIT, WAIT_TERMINATE, WAIT_KILL, JOIN_READER = 20.0, 10.0, 10.0, 10.0


class HostError(RuntimeError):
    """The Node host failed to start, answered out of protocol, or did not answer in time."""


@dataclass(frozen=True)
class ClientReply:
    """The outcome of one actual client function call: its validated value or its `ApiError` fields, plus the wire
    exchanges (public headers and body hashes, never credentials) the call made through the real proxy.
    `wire_dropped` counts exchanges beyond the host's per-call wire-log cap (`wire` is complete only at 0)."""

    ok: bool
    value: Any
    error: dict[str, Any] | None
    wire: list[dict[str, Any]]
    wire_dropped: int = 0


def node_executable() -> str:
    node = shutil.which("node")
    if node is None:
        raise HostError("node is not on PATH")
    version = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=30, check=False)
    if version.stdout.strip() != PINNED_NODE:
        raise HostError(f"expected Node {PINNED_NODE}, found {version.stdout.strip()[:40]!r}")
    return node


def child_environment(proxy_port: int) -> dict[str, str]:
    """The host's environment: process-local routing (temp/cache/build) kept, every other POLICYOPS_* value
    (database and OIDC credentials among them) and any ambient proxy setting removed."""
    env = {name: value for name, value in os.environ.items()
           if not name.startswith("POLICYOPS_") and name not in PROXY_VARIABLES}
    for name in CHILD_POLICYOPS:
        value = os.environ.get(name)
        if value is None:
            raise HostError(f"{name} must be set (run through scripts/devenv.py)")
        env[name] = value
    env["POLICYOPS_API_PROXY_TARGET"] = f"http://127.0.0.1:{proxy_port}"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def checked_report_path(raw: str, temp_root: str | None, repository: Path) -> Path:
    """Validate an optional proof-report destination before anything is created: an absolute path to a new file
    whose existing parent resolves (through any symlink or junction) inside the configured POLICYOPS_TEMP_DIR and
    outside the repository, with no link on the way. Only existing paths are inspected; nothing is probed."""
    if not temp_root or not Path(temp_root).is_absolute():
        raise HostError("a proof report needs an absolute POLICYOPS_TEMP_DIR")
    path = Path(raw)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise HostError("the proof report path must be an absolute file path")
    try:
        root = Path(temp_root).resolve(strict=True)
        parent = path.parent.resolve(strict=True)
        repo = repository.resolve(strict=True)
    except OSError:
        raise HostError("the proof report directory and POLICYOPS_TEMP_DIR must already exist") from None
    if parent != root and root not in parent.parents:
        raise HostError("the proof report must be inside POLICYOPS_TEMP_DIR")
    if parent == repo or repo in parent.parents:
        raise HostError("the proof report must not be inside the repository")
    if os.path.normcase(os.path.normpath(path.parent)) != os.path.normcase(str(parent)):
        raise HostError("the proof report path must not pass through a link")
    if os.path.lexists(path):
        raise HostError("the proof report must be a new file")
    return parent / path.name


def write_report(path: Path, data: bytes) -> None:
    """Create a validated report exclusively: a file or link that appeared after validation is refused."""
    with path.open("xb") as handle:
        handle.write(data)


class OperatorClientHost:
    def __init__(self, process: subprocess.Popen[bytes], secrets: tuple[str, ...]) -> None:
        # Assignment only: the host owns the child before any reader thread exists.
        self._process = process
        self._secrets = secrets
        self._condition = threading.Condition()
        self._frames: deque[bytes] = deque()
        self._stdout_end: str | None = None  # why no further frame will be accepted
        self._stderr: deque[str] = deque(maxlen=MAX_STDERR_LINES)
        self._readers: list[tuple[threading.Thread, IO[bytes] | None]] = []
        self._next_id = 0
        self._release_state = "open"  # open -> releasing -> released
        self.origin = ""
        self.issues: list[str] = []

    # -- lifecycle ------------------------------------------------------------------------------------------

    @classmethod
    def start(cls, *, web_root: Path, proxy_port: int, secrets: tuple[str, ...] = (),
              ready_timeout: float = 90.0) -> OperatorClientHost:
        node = node_executable()
        env = child_environment(proxy_port)
        process = subprocess.Popen([node, str(HOST_SCRIPT), str(web_root)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(web_root))
        host = cls(process, secrets)
        try:
            host._start_readers()
            ready = host._read(ready_timeout)
            if ready.get("ready") is not True or not ORIGIN_PATTERN.match(str(ready.get("origin"))):
                raise HostError("the host did not report a loopback Vite origin")
            host.origin = str(ready["origin"])
        except BaseException as primary:
            host._release(primary)
            raise
        return host

    def __enter__(self) -> OperatorClientHost:
        return self

    def __exit__(self, kind: type[BaseException] | None, error: BaseException | None,
                 traceback: TracebackType | None) -> None:
        self._release(error)

    def close(self) -> list[str]:
        """Release the child with no active error to protect. Ordinary failures are recorded in the returned
        issues, never raised; an interrupt is re-raised after the remaining release steps were attempted."""
        return self._release(None)

    def _start_readers(self) -> None:
        process = self._process
        streams = ((self._pump_stdout, process.stdout), (self._pump_stderr, process.stderr))
        for target, stream in streams:
            thread = threading.Thread(target=target, args=(stream,), daemon=True)
            self._readers.append((thread, stream))  # owned before start; joined only if it really started
            thread.start()

    def _release(self, primary: BaseException | None) -> list[str]:
        if self._release_state == "released":
            return list(self.issues)
        self._release_state = "releasing"
        process = self._process
        deferred: BaseException | None = None

        def step(name: str, action: Callable[[], Any]) -> Any:
            nonlocal deferred
            try:
                return action()
            except Exception as error:
                self.issues.append(f"{name} failed: {type(error).__name__}")
            except BaseException as error:  # an interrupt: finish releasing first
                self.issues.append(f"{name} interrupted: {type(error).__name__}")
                deferred = deferred or error
            return None

        if process.stdin is not None:
            step("closing stdin", process.stdin.close)
        step("reaping the host", self._reap)
        live: set[int] = set()
        for thread, stream in self._readers:
            if thread.ident is None:
                continue  # never started: nothing to join; its pipe is closed below
            step("joining a reader", functools.partial(thread.join, JOIN_READER))
            if step("checking a reader", thread.is_alive) is not False:
                live.add(id(stream))  # closing a buffered pipe would wait on the live reader's lock
                self.issues.append("uncertain: a host output reader did not stop; its pipe is left open")
        for stream in (process.stdout, process.stderr):
            if stream is not None and id(stream) not in live:
                step("closing a pipe", stream.close)
        code = step("polling the host", process.poll)
        if code is None:
            self.issues.append("uncertain: the Node host process may still be running")
        elif code != 0:
            self.issues.append(f"the Node host exited with status {code}")
        self._release_state = "released"
        if deferred is not None:
            if primary is None:
                raise deferred
            primary.add_note(f"host release was interrupted by {type(deferred).__name__}")
        return list(self.issues)

    def _reap(self) -> None:
        """Wait for the exact child to exit; terminate then kill it only if it does not (each wait bounded). A wait
        that fails for another reason confirms nothing, so it escalates like a timeout."""
        process = self._process
        stages = ((WAIT_EXIT, process.terminate, "the host did not exit after its stdin closed; terminated"),
                  (WAIT_TERMINATE, process.kill, "the host ignored terminate; killed"),
                  (WAIT_KILL, None, "uncertain: the host was not reaped after kill"))
        for timeout, escalate, timed_out in stages:
            try:
                process.wait(timeout)
                return
            except subprocess.TimeoutExpired:
                self.issues.append(timed_out)
            except Exception as error:
                self.issues.append(f"waiting for the host failed: {type(error).__name__}")
            if escalate is not None:
                escalate()

    def stderr_tail(self) -> str:
        return redaction.redact_text("\n".join(self._stderr), self._secrets)

    # -- protocol -------------------------------------------------------------------------------------------

    def configure_session(self, *, session: str, csrf: str, session_cookie_name: str, csrf_cookie_name: str) -> None:
        """Give the fixture the minted session (HttpOnly cookie) and readable CSRF cookie values."""
        reply = self._exchange({"cmd": "session", "session": session, "csrf": csrf,
                                "session_cookie_name": session_cookie_name, "csrf_cookie_name": csrf_cookie_name})
        if reply.get("ok") is not True:
            raise HostError("the host refused the session fixture")

    def call(self, function: str, **args: Any) -> ClientReply:
        """Run one actual exported client function (`getMe`, `createCase`, `postMessage`, ...)."""
        reply = self._exchange({"cmd": "call", "fn": function, "args": args})
        dropped = reply.get("wire_dropped", 0)
        if type(dropped) is not int or dropped < 0:
            raise HostError("the host sent an invalid wire-log count")
        if reply.get("ok") is True:
            return ClientReply(True, reply.get("value"), None, list(reply.get("wire", [])), dropped)
        error = reply.get("error")
        if not isinstance(error, dict) or "wire" not in reply:
            raise HostError(f"the host could not run {function}: {redaction.redact_text(str(error), self._secrets)}")
        return ClientReply(False, None, error, list(reply["wire"]), dropped)

    def _exchange(self, command: dict[str, Any], timeout: float = 60.0) -> dict[str, Any]:
        self._next_id += 1
        data = (json.dumps({"id": self._next_id, **command}) + "\n").encode("utf-8")
        if len(data) > MAX_COMMAND_BYTES:
            raise HostError("the command exceeds the host's command limit")
        stdin = self._process.stdin
        if stdin is None or self._release_state != "open":
            raise HostError("the host is closed")
        try:
            stdin.write(data)
            stdin.flush()
        except OSError as error:
            raise HostError("the host is not accepting commands") from error
        reply = self._read(timeout)
        if reply.get("id") != self._next_id:
            raise HostError("the host answered out of order")
        return reply

    def _read(self, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._frames and self._stdout_end is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HostError("the host did not answer in time; stderr: " + self.stderr_tail()[-1000:])
                self._condition.wait(remaining)
            if not self._frames:
                raise HostError(f"no reply ({self._stdout_end}); stderr: " + self.stderr_tail()[-1000:])
            frame = self._frames.popleft()
        try:
            parsed = json.loads(frame)
        except ValueError:
            raise HostError("the host sent a frame that is not JSON") from None
        if not isinstance(parsed, dict):
            raise HostError("the host sent a non-object reply")
        return parsed

    def _end_stdout(self, reason: str) -> None:
        with self._condition:
            if self._stdout_end is None:
                self._stdout_end = reason
            self._condition.notify_all()

    def _pump_stdout(self, stream: IO[bytes]) -> None:
        """Frame stdout by newline with a bounded `readline`; after a protocol break, drain and discard."""
        try:
            while True:
                line = stream.readline(MAX_FRAME_BYTES + 1)
                if not line:
                    break
                if self._stdout_end is not None:
                    continue
                if not line.endswith(b"\n"):
                    self._end_stdout(f"a frame exceeded {MAX_FRAME_BYTES} bytes" if len(line) > MAX_FRAME_BYTES
                                     else "the host ended inside a frame")
                    continue
                with self._condition:
                    if len(self._frames) >= MAX_BACKLOG:
                        self._stdout_end = f"more than {MAX_BACKLOG} unread frames"
                    else:
                        self._frames.append(line)
                    self._condition.notify_all()
            self._end_stdout("the host closed its output")
        except Exception as error:
            self._end_stdout(f"reading the host output failed: {type(error).__name__}")

    def _pump_stderr(self, stream: IO[bytes]) -> None:
        """Keep a bounded tail of bounded diagnostic lines; the rest of an over-long line is read and discarded."""
        try:
            truncated = False
            while True:
                piece = stream.readline(MAX_STDERR_LINE_BYTES)
                if not piece:
                    break
                if not truncated:
                    text = piece.decode("utf-8", "replace").rstrip()
                    self._stderr.append(text if piece.endswith(b"\n") else f"{text} [truncated]")
                truncated = not piece.endswith(b"\n")
        except Exception as error:
            self._stderr.append(f"[stderr reader failed: {type(error).__name__}]")
