"""Typed, bounded owner of a single offline reranker process (no Torch in evaluator).

The CLI equivalent is `python scripts/devenv.py uv --project reranker run --offline
--frozen python -B -m policyops_reranker.serve --artifact DIR --expected-sha256 SHA`.
We call devenv.build_environment and launch that routed venv's Python directly, so
timeouts can kill/reap the actual worker without leaving uv/launcher descendants.
"""
from __future__ import annotations

from collections.abc import Sequence
from contextlib import suppress
import hashlib
import json
import math
import os
from pathlib import Path
from queue import Empty, Queue
import runpy
import subprocess
import threading
from types import TracebackType
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


ROOT = Path(__file__).resolve().parents[4]
MAX_LINE = 4_200_000
MAX_RESPONSE = 64_000
POLICY = "g8.bert-prefix-query128-pair384/v1"


class WorkerError(ValueError):
    """Fixed diagnostics; never contain passages, worker stderr or credentials."""


class Frozen(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Passage(Frozen):
    id: Annotated[str, Field(min_length=1, max_length=100)]
    text: Annotated[str, Field(min_length=1, max_length=20_000)]


class Truncation(Frozen):
    policy: Literal["g8.bert-prefix-query128-pair384/v1"]
    query_tokens: Annotated[int, Field(ge=0, le=100_000)]
    query_used: Annotated[int, Field(ge=0, le=128)]
    passage_tokens: Annotated[int, Field(ge=0, le=100_000)]
    passage_used: Annotated[int, Field(ge=0, le=381)]

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (self.query_used != min(self.query_tokens, 128)
                or self.passage_used != min(self.passage_tokens, 381 - self.query_used)):
            raise ValueError("truncation_contract")
        return self


class Score(Frozen):
    id: str
    score: Annotated[float, Field(allow_inf_nan=False)]
    truncation: Truncation


class Response(Frozen):
    artifact_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    scores: Annotated[list[Score], Field(min_length=1, max_length=50)]
    ranking: Annotated[list[str], Field(min_length=1, max_length=50)]


def worker_command(artifact: Path, identity: str, threads: int) -> tuple[list[str], dict[str, str]]:
    routing = runpy.run_path(str(ROOT / "scripts/devenv.py"))
    environment: dict[str, str] = routing["build_environment"](
        os.environ, ["uv", "--project", str(ROOT / "reranker"), "run", "--offline", "--frozen"], ROOT)
    environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false")
    venv = Path(environment["UV_PROJECT_ENVIRONMENT"])
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return [str(python), "-B", "-m", "policyops_reranker.serve", "--artifact", str(artifact),
            "--expected-sha256", identity, "--threads", str(threads)], environment


class CrossEncoderClient:
    def __init__(self, artifact: Path, expected_sha256: str, *, threads: int = 4, timeout: float = 120,
                 command: Sequence[str] | None = None, environment: dict[str, str] | None = None) -> None:
        if (not math.isfinite(timeout) or not 0 < timeout <= 600 or type(threads) is not int
                or not 1 <= threads <= 32):
            raise WorkerError("worker_limits")
        manifests = [p for name in ("artifact-manifest.json", "download-manifest.json")
                     if (p := artifact / name).is_file()]
        if (len(manifests) != 1 or manifests[0].stat().st_size > 1_000_000
                or hashlib.sha256(manifests[0].read_bytes()).hexdigest() != expected_sha256):
            raise WorkerError("artifact_identity")
        if command is None:
            args, env = worker_command(artifact, expected_sha256, threads)
        else:
            args, env = list(command), dict(os.environ if environment is None else environment)
        self.identity, self.timeout = expected_sha256, timeout
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._closed = False
        self.process = subprocess.Popen(args, cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, kind: type[BaseException] | None, error: BaseException | None,
                 traceback: TracebackType | None) -> None:
        try:
            self.close()
        except WorkerError:
            if error is None:
                raise
            error.add_note("worker_cleanup_unconfirmed")

    def close(self) -> None:
        if self._closed and self.process.poll() is not None and (
                self._thread is None or not self._thread.is_alive()) and all(
                    p is None or p.closed for p in (self.process.stdin, self.process.stdout)):
            return
        self._closed = True
        if self.process.poll() is None:
            # Exit may race kill. Always attempt bounded reap even if kill itself failed.
            with suppress(OSError):
                self.process.kill()
        try:
            self.process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            raise WorkerError("worker_reap_unconfirmed") from None
        if self._thread is not None:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                raise WorkerError("worker_io_cleanup_unconfirmed")
        for pipe in (self.process.stdin, self.process.stdout):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    raise WorkerError("worker_pipe_cleanup_unconfirmed") from None

    def rerank(self, query: str, passages: Sequence[Passage], *, top_k: int) -> Response:
        if (self._closed or not isinstance(query, str) or not 1 <= len(query) <= 20_000
                or not 1 <= len(passages) <= 50 or len({p.id for p in passages}) != len(passages)
                or type(top_k) is not int or not 1 <= top_k <= len(passages)):
            raise WorkerError("request_bounds_or_closed")
        for value in [query, *(p.text for p in passages)]:
            if "\x00" in value:
                raise WorkerError("request_text")
            value.encode("utf-8", errors="strict")
        if any(not p.id.isascii() or any(ord(c) < 32 for c in p.id) for p in passages):
            raise WorkerError("request_identity")
        raw = json.dumps({"query": query, "passages": [p.model_dump() for p in passages], "top_k": top_k},
                         ensure_ascii=False, allow_nan=False).encode() + b"\n"
        if len(raw) > MAX_LINE or not self._lock.acquire(blocking=False):
            raise WorkerError("line_bound_or_concurrent_request")
        replies: Queue[bytes | BaseException] = Queue(maxsize=1)

        def exchange() -> None:
            try:
                if self.process.stdin is None or self.process.stdout is None:
                    raise WorkerError("worker_pipe")
                # Unbuffered pipes may short-write; bound the entire send/receive with the same deadline.
                remaining = memoryview(raw)
                while remaining:
                    written = self.process.stdin.write(remaining)
                    if not written:
                        raise WorkerError("worker_write")
                    remaining = remaining[written:]
                reply = self.process.stdout.readline(MAX_RESPONSE + 1)
                replies.put(reply)
            except BaseException as failure:
                replies.put(failure)

        try:
            self._thread = threading.Thread(target=exchange, daemon=True, name="g8-worker-io")
            self._thread.start()
            try:
                reply = replies.get(timeout=self.timeout)
            except Empty:
                raise WorkerError("worker_timeout") from None
            if isinstance(reply, BaseException) or not reply.endswith(b"\n") or len(reply) > MAX_RESPONSE:
                raise WorkerError("worker_eof_or_line_bound")
            result = Response.model_validate_json(reply)
            ids = [p.id for p in passages]
            if (result.artifact_sha256 != self.identity or [s.id for s in result.scores] != ids
                    or result.ranking != [s.id for s in sorted(result.scores, key=lambda s: (-s.score, s.id))[:top_k]]):
                raise WorkerError("worker_response_binding")
            return result
        except BaseException as failure:
            try:
                self.close()
            except WorkerError:
                failure.add_note("worker_cleanup_unconfirmed")
            if isinstance(failure, WorkerError):
                raise
            raise WorkerError("worker_response_invalid") from None
        finally:
            self._lock.release()
