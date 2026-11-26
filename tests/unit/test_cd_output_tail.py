"""Offline subprocess and persistence checks for CD failure diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from infra.deploy import cd_agent as cd


@pytest.fixture
def agent(tmp_path: Path) -> cd.Agent:
    tooling = tmp_path / "tools"
    tooling.mkdir()
    for name in ("policyops-cd", "deploy.sh", "deploy_verify.py"):
        (tooling / name).touch()
    return cd.Agent(tmp_path, tooling, 0)


def python(code: str) -> list[str]:
    return [sys.executable, "-B", "-c", code]


def test_chatty_child_tail_reaches_freeze_and_quarantine(
    agent: cd.Agent, capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = "a" * 40
    agent.attempt_id = "1" * 32
    agent.state["in_flight"] = {
        "candidate": candidate, "previous": "b" * 40, "phase": "deploying", "attempt_id": agent.attempt_id,
        "started_at": 0, "schema": True, "rollback_attempts": 0, "rollback_in_progress": 0,
        "settle": False, "forced_stage": "",
    }
    code, stdout = agent.command("deploy", python(
        "import os; os.write(2, b'evicted-stderr\\n'); "
        "[os.write(2, b'x' * 16384) for _ in range(70)]; "
        "os.write(1, b'\\nactivation stdout\\n'); os.write(2, b'seed failed\\n'); raise SystemExit(1)"
    ), 4)
    assert (code, stdout) == (1, "")
    agent.freeze("schema_activation_failed")

    relative = f"attempts/{agent.attempt_id}/deploy.log"
    log = agent.cd / relative
    body = log.read_bytes()
    assert 60_000 < len(body) <= 65_536
    assert b"evicted-stderr" not in body
    assert body.endswith(b"activation stdout\nseed failed\n")
    if sys.platform == "linux":
        for directory in (log.parent, log.parent.parent):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            assert directory.stat().st_uid == os.geteuid()  # type: ignore[attr-defined,unused-ignore]
        assert stat.S_IMODE(log.stat().st_mode) == 0o600
        assert log.stat().st_uid == os.geteuid()  # type: ignore[attr-defined,unused-ignore]
    reference = {"deploy": {"path": relative, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}}
    audit = (agent.cd / "log.jsonl").read_text(encoding="utf-8")
    quarantine = (agent.cd / "quarantine" / f"{candidate}.json").read_text(encoding="utf-8")
    for raw in (audit, quarantine):
        assert "seed failed" not in raw
        assert json.loads(raw)["output_tails"] == reference
        assert json.loads(raw)["reason"] == "schema_activation_failed"
    assert json.loads(audit)["decision"] == "FROZEN"
    assert capsys.readouterr() == ("", "")


def test_success_preserves_full_parsed_stdout_without_saving_tail(agent: cd.Agent) -> None:
    result = agent.command("parsed", python(
        "import sys; sys.stderr.buffer.write(b'noise\\n' * 200000); "
        "sys.stdout.buffer.write(b'result\\r\\n' * 10000 + b'\\xff')"
    ), 4, output=True)
    assert result == (0, "result\r\n" * 10000 + "\udcff")
    assert agent.output_tails == {}
    assert not (agent.cd / "attempts").exists()


@pytest.mark.parametrize("output", [False, True])
@pytest.mark.parametrize("exit_code", [0, 3])
def test_descendant_holding_pipes_does_not_delay_child_verdict(
    agent: cd.Agent, tmp_path: Path, output: bool, exit_code: int,
) -> None:
    stop = tmp_path / "stop-grandchild"
    grandchild = (
        "import sys, time\nfrom pathlib import Path\n"
        "for _ in range(120):\n"
        "    if Path(sys.argv[1]).exists():\n        break\n"
        "    time.sleep(0.05)\n"
    )
    child = python(
        "import os, subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-B', '-c', {grandchild!r}, {str(stop)!r}], "
        "stdout=sys.stdout, stderr=sys.stderr); "
        f"os.write(1, b'child output\\n'); raise SystemExit({exit_code})"
    )
    start = time.monotonic()
    try:
        result = agent.command("deploy", child, 3, output=output)
        elapsed = time.monotonic() - start
    finally:
        stop.touch()

    assert result == (exit_code, "child output\n" if output else "")
    assert elapsed < 2
    if exit_code:
        assert (agent.cd / "attempts/no-attempt/deploy.log").read_bytes() == b"child output\n"
    else:
        assert agent.output_tails == {}
        assert not (agent.cd / "attempts").exists()


def test_failed_parsed_command_redacts_both_streams(agent: cd.Agent) -> None:
    stderr = (
        b'\x1b[31mpassword="two words"\x1b[0m\nsecret=other\n'
        b'password: plain\n"password": "json value",\ntoken: yaml value\n'
        b"'secret' : 'quoted value'\n"
        b'Authorization: Bearer fake-auth\n"Authorization": "Bearer fake-auth"\n'
        b"\033]0;title\007invalid \xff\n"
        b"-----BEGIN CERTIFICATE-----\nexample-body\n-----END CERTIFICATE-----\ncomplete\n"
    )
    code, parsed = agent.command("parse", python(
        "import os; os.write(1, b'to'); os.write(2, b'noise\\n'); os.write(1, b'ken=demo-value\\n'); "
        f"os.write(2, {stderr!r}); raise SystemExit(7)"
    ), 4, output=True)
    assert (code, parsed) == (7, "token=demo-value\n")
    text = (agent.cd / "attempts/no-attempt/parse.log").read_text(encoding="utf-8")
    assert text.splitlines() == [
        "token=[redacted]", "", "noise", "password=[redacted]", "secret=[redacted]",
        "password: [redacted]", '"password": [redacted]', "token: [redacted]", "'secret' : [redacted]",
        "Authorization: [redacted]", '"Authorization": [redacted]', "invalid \ufffd", "[redacted]", "complete",
    ]


@pytest.mark.parametrize("complete", [False, True])
def test_clipped_pem_is_redacted(agent: cd.Agent, complete: bool) -> None:
    ending = b"-----END CERTIFICATE-----\nnormal output\n" if complete else b""
    assert agent.command("pem", python(
        "import os; os.write(2, b'-----BEGIN CERTIFICATE-----\\n'); "
        "[os.write(2, b'example-body\\n' * 1024) for _ in range(8)]; "
        f"os.write(2, {ending!r}); raise SystemExit(1)"
    ), 4) == (1, "")
    body = (agent.cd / "attempts/no-attempt/pem.log").read_bytes()
    assert body == b"[redacted]" + (b"\nnormal output\n" if complete else b"")


def test_clipped_secret_label_still_hides_its_value(agent: cd.Agent) -> None:
    assert agent.command("clipped", python(
        "import os; os.write(2, b'password='); "
        "[os.write(2, b'x' * 16384) for _ in range(5)]; "
        "os.write(2, b'\\nnormal output\\n'); raise SystemExit(1)"
    ), 4) == (1, "")
    assert (agent.cd / "attempts/no-attempt/clipped.log").read_bytes() == b"[redacted]\nnormal output\n"


def test_clipping_through_pem_opener_hides_body(agent: cd.Agent) -> None:
    begin = b"-----BEGIN CERTIFICATE-----\n"
    end = b"\n-----END CERTIFICATE-----\nnormal output\n"
    size = 65_536 + 10 - len(begin) - len(end)
    assert agent.command("clipped_pem", python(
        f"import os; os.write(2, {begin!r} + b'x' * {size} + {end!r}); raise SystemExit(1)"
    ), 4) == (1, "")
    assert (agent.cd / "attempts/no-attempt/clipped_pem.log").read_bytes() == b"[redacted]\nnormal output\n"


def test_timeout_expired_budget_and_spawn_failure_write_tails(agent: cd.Agent) -> None:
    start = time.monotonic()
    assert agent.command("timeout", python(
        "import os, time; os.write(1, b'waiting\\n'); time.sleep(30)"
    ), 0.8, output=True) == (124, "")
    assert time.monotonic() - start < 4
    assert agent.command("budget", [], 0) == (124, "")
    assert agent.command("spawn", [str(agent.cd / "missing-program")], 2) == (126, "")
    for key, body in (("timeout", b"waiting\n"), ("budget", b""), ("spawn", b"")):
        ref = agent.output_tails[key]
        assert (agent.cd / ref["path"]).read_bytes() == body
        assert ref["bytes"] == len(body)


@pytest.mark.parametrize(("count", "size", "keep"), [(24, 1, 20), (19, 65_536, 16)])
def test_retention_prunes_oldest_without_touching_other_directories(
    agent: cd.Agent, count: int, size: int, keep: int,
) -> None:
    root = agent.cd / "attempts"
    root.mkdir()
    current_dir = root / ("f" * 32)
    current_dir.mkdir()
    current = current_dir / "current.log"
    current.write_bytes(b"x" * size)
    os.utime(current_dir, (1, 1))  # even the oldest current attempt is protected
    unrelated = root / "operator-notes"
    unrelated.mkdir()
    for index in range(count):
        directory = root / f"{index:032x}"
        directory.mkdir()
        (directory / "deploy.log").write_bytes(b"d" * size)
        os.utime(directory, (index + 2, index + 2))

    cd.prune_output_tails(root, current)

    assert current.is_file() and unrelated.is_dir()
    assert {path.name for path in root.iterdir() if path not in (current_dir, unrelated)} == {
        f"{index:032x}" for index in range(count - keep + 1, count)
    }


def test_single_oversized_attempt_keeps_current_file(agent: cd.Agent) -> None:
    directory = agent.cd / "attempts/no-attempt"
    directory.mkdir(parents=True)
    for index in range(16):
        path = directory / f"deploy_{index}.log"
        path.write_bytes(b"x" * 65_536)
        os.utime(path, (index + 1, index + 1))

    assert agent.command("new", python("import os; os.write(1, b'failure\\n'); raise SystemExit(1)"), 4) == (1, "")

    assert (directory / "new.log").read_bytes() == b"failure\n"
    assert not (directory / "deploy_0.log").exists()
    assert sum(path.stat().st_size for path in directory.iterdir()) <= 1024 * 1024


def test_diagnostic_storage_error_preserves_command_exit(agent: cd.Agent) -> None:
    (agent.cd / "attempts").touch()
    assert agent.command("deploy", python("raise SystemExit(9)"), 4) == (9, "")
    assert agent.output_tails == {}
    assert agent.output_tail_errors == {"deploy"}
