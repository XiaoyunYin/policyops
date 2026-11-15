"""Fake subprocesses exercise real pipes, backpressure, timeout, EOF and reaping."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import time

import pytest

from policyops_evals.qa_studies.cross_encoder import CrossEncoderClient, Passage, WorkerError, worker_command


WORKER = '''
import json, sys, time
mode = sys.argv[1]
identity = sys.argv[2]
if mode == "hang":
    time.sleep(60)
if mode == "eof":
    sys.exit(0)
for line in sys.stdin.buffer:
    request = json.loads(line)
    scores = [{"id": p["id"], "score": float(i), "truncation": {
        "policy": "g8.bert-prefix-query128-pair384/v1", "query_tokens": 1,
        "query_used": 1, "passage_tokens": 1, "passage_used": 1}}
        for i, p in enumerate(request["passages"])]
    result = {"artifact_sha256": identity, "scores": scores,
              "ranking": [s["id"] for s in reversed(scores)][:request["top_k"]]}
    if mode == "identity":
        result["artifact_sha256"] = "0" * 64
    if mode == "ranking":
        result["ranking"] = ["unknown"]
    if mode == "truncation":
        result["scores"][0]["truncation"]["query_used"] = 2
    if mode == "extra":
        result["extra"] = True
    if mode == "oversized":
        print("x" * 65000, flush=True)
    else:
        print(json.dumps(result), flush=True)
'''


@pytest.fixture
def fake(tmp_path: Path) -> tuple[Path, str, Path]:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    payload = b'{"files":{}}'
    (artifact / "artifact-manifest.json").write_bytes(payload)
    script = tmp_path / "fake-worker.py"
    script.write_bytes(WORKER.encode())
    return artifact, hashlib.sha256(payload).hexdigest(), script


def client(fake: tuple[Path, str, Path], mode: str, timeout: float = 5) -> CrossEncoderClient:
    artifact, identity, script = fake
    return CrossEncoderClient(artifact, identity, timeout=timeout,
                              command=[sys.executable, "-B", str(script), mode, identity])


def test_typed_response_reuse_and_owned_process_cleanup(fake: tuple[Path, str, Path]) -> None:
    with client(fake, "ok") as worker:
        passages = [Passage(id="a", text="first"), Passage(id="b", text="second")]
        response = worker.rerank("query", passages, top_k=1)
        assert response.ranking == ["b"] and response.artifact_sha256 == fake[1]
        assert worker.rerank("again", passages, top_k=2).ranking == ["b", "a"]
        assert worker.process.poll() is None
    assert worker.process.poll() is not None
    assert worker._thread is not None and not worker._thread.is_alive()


@pytest.mark.parametrize("mode", ["eof", "identity", "ranking", "truncation", "oversized", "extra"])
def test_protocol_failures_kill_and_reap(fake: tuple[Path, str, Path], mode: str) -> None:
    with client(fake, mode) as worker:
        with pytest.raises(WorkerError):
            worker.rerank("query", [Passage(id="p", text="passage")], top_k=1)
        assert worker.process.poll() is not None
        assert worker._thread is not None and not worker._thread.is_alive()


def test_timeout_includes_blocked_write_and_reaps_io(fake: tuple[Path, str, Path]) -> None:
    with client(fake, "hang", timeout=.15) as worker:
        started = time.monotonic()
        with pytest.raises(WorkerError, match="timeout"):
            worker.rerank("query", [Passage(id=str(i), text="x" * 20_000) for i in range(50)], top_k=20)
        assert time.monotonic() - started < 4
        assert worker.process.poll() is not None
        assert worker._thread is not None and not worker._thread.is_alive()


def test_identity_refused_before_launch(fake: tuple[Path, str, Path]) -> None:
    with pytest.raises(WorkerError, match="identity"):
        CrossEncoderClient(fake[0], "0" * 64, command=["must-never-launch"])


def test_client_request_bounds(fake: tuple[Path, str, Path]) -> None:
    with client(fake, "ok") as worker:
        with pytest.raises(WorkerError):
            worker.rerank("q", [Passage(id="p", text="x")] * 51, top_k=1)
        with pytest.raises(WorkerError):
            worker.rerank("q", [Passage(id="p", text="x")], top_k=True)
        with pytest.raises(WorkerError):
            worker.rerank("q", [Passage(id="p", text="x\x00")], top_k=1)


def test_devenv_reranker_routing(fake: tuple[Path, str, Path]) -> None:
    command, env = worker_command(fake[0], fake[1], 2)
    assert "reranker-raw-v1" in command[0]
    assert "policyops_reranker.serve" in command
    assert env["HF_HUB_OFFLINE"] == env["TRANSFORMERS_OFFLINE"] == "1"
