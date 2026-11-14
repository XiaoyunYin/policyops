"""Persistent QA environment ownership is checked before start, stop or removal."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
from typing import Any
from uuid import uuid4

import pytest


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("qa_env", ROOT / "scripts/qa_env.py")
assert SPEC and SPEC.loader
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)


class Docker:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.info: dict[str, Any] | None = None
        self.volume: dict[str, Any] | None = None
        self.fail_start = False
        self.fail_ps = False

    def __call__(self, args: Any) -> subprocess.CompletedProcess[str]:
        args = list(args)
        self.calls.append(args)
        output, code = "", 0
        if args[0] == "ps":
            output = "policyops-qa-postgres" if self.info else ""
            code = int(self.fail_ps)
        elif args[:2] == ["volume", "ls"]:
            output = "policyops-qa-pgdata" if self.volume else ""
        elif args[:2] == ["volume", "inspect"]:
            output = json.dumps([self.volume])
        elif args[:2] == ["volume", "rm"]:
            self.volume = None
        elif args[0] == "inspect":
            output = json.dumps([self.info])
        elif args[0] == "start":
            code = int(self.fail_start)
        elif args[0] == "rm":
            self.info = None
        return subprocess.CompletedProcess(args, code, output, "private Docker diagnostics")


@pytest.fixture
def world(tmp_path: Path) -> tuple[Any, Docker]:
    runner = Docker()
    environment = qa.Environment("policyops-qa", tmp_path, runner)
    state = {"owner": qa.OWNER, "project": "policyops-qa", "run": str(uuid4())}
    (tmp_path / "owner.json").write_text(json.dumps(state), encoding="utf-8")
    labels = environment.labels(state)
    runner.volume = {"Name": environment.volume, "Labels": labels}
    runner.info = {"Id": "a" * 64, "Name": "/" + environment.name,
        "Config": {"Labels": labels, "Image": environment.image},
        "Mounts": [{"Type": "volume", "Name": environment.volume, "Destination": qa.DESTINATION},
                   {"Type": "bind", "Destination": "/qa-secrets", "Source": str(tmp_path / "secrets"), "RW": False}],
        "HostConfig": {"PortBindings": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]},
                       "LogConfig": {"Type": "none"}}, "State": {"Running": False}}
    return environment, runner


@pytest.mark.parametrize("command", ["up", "status", "migrate", "bootstrap", "down"])
def test_command_parsing(command: str) -> None:
    assert qa.parser().parse_args([command]).command == command
    assert qa.parser().parse_args(["--project", "qa-fixture", command]).project == "qa-fixture"


def test_destroy_requires_exact_project(world: tuple[Any, Docker]) -> None:
    environment, runner = world
    with pytest.raises(SystemExit):
        qa.parser().parse_args(["destroy"])
    with pytest.raises(qa.Refused, match="confirmation"):
        environment.destroy("other")
    assert not runner.calls
    result = environment.destroy("policyops-qa")
    assert result["destroyed"] == "policyops-qa"
    assert ["rm", "-f", "a" * 64] in runner.calls
    assert runner.calls.index(["rm", "-f", "a" * 64]) < runner.calls.index(["volume", "rm", environment.volume])


@pytest.mark.parametrize("changed", ["owner", "run", "project", "image", "mount", "port", "volume"])
def test_owner_and_containment_mismatch_refuses_without_mutation(world: tuple[Any, Docker], changed: str) -> None:
    environment, runner = world
    assert runner.info is not None and runner.volume is not None
    info = deepcopy(runner.info)
    if changed in {"owner", "run", "project"}:
        key = {"owner": "policyops.owner", "run": "policyops.run", "project": "com.docker.compose.project"}[changed]
        info["Config"]["Labels"][key] = "unowned"
    elif changed == "image":
        info["Config"]["Image"] = "postgres:latest"
    elif changed == "mount":
        info["Mounts"][0]["Name"] = "foreign"
    elif changed == "port":
        info["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"] = "0.0.0.0"  # noqa: S104 - rejection fixture
    else:
        runner.volume["Labels"] = {}
    runner.info = info
    with pytest.raises(qa.Refused, match="mismatch"):
        environment.destroy("policyops-qa")
    assert not any(args[0] in {"rm", "start", "stop"} or args[:2] == ["volume", "rm"] for args in runner.calls)


def test_failed_start_never_implies_ownership_or_cleanup(world: tuple[Any, Docker]) -> None:
    environment, runner = world
    runner.fail_start = True
    with pytest.raises(qa.Refused, match="start_failed"):
        environment.up()
    assert not any(args[0] == "rm" or args[:2] == ["volume", "rm"] for args in runner.calls)
    runner.fail_ps = True
    with pytest.raises(qa.Refused, match="ps_failed"):
        environment.destroy("policyops-qa")
    assert not any(args[0] == "rm" for args in runner.calls)


def test_down_keeps_volume(world: tuple[Any, Docker]) -> None:
    environment, runner = world
    assert not environment.down()["running"]
    assert ["stop", "--time", "10", "a" * 64] in runner.calls
    assert runner.volume is not None


def test_invalid_project_and_path_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(qa.Refused, match="invalid_project"):
        qa.Environment("../foreign", tmp_path)
    monkeypatch.delenv("POLICYOPS_TEMP_DIR")
    with pytest.raises(qa.Refused, match="required"):
        qa.private_root("policyops-qa")
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(ROOT))
    with pytest.raises(qa.Refused, match="outside"):
        qa.private_root("policyops-qa")


def test_docker_desktop_bind_source_translation_is_exact(tmp_path: Path) -> None:
    # Live coordinator finding: Docker Desktop reports Windows bind sources as /run/desktop/mnt/host/<drive>/...
    bind_source_matches = qa.bind_source_matches

    expected = tmp_path / "qa root" / "secrets"
    assert bind_source_matches(str(expected), expected)
    resolved = expected.resolve()
    if resolved.drive:
        translated = f"/run/desktop/mnt/host/{resolved.drive[0].lower()}{resolved.as_posix()[len(resolved.drive):]}"
        assert bind_source_matches(translated, expected)
        assert not bind_source_matches(translated + "-other", expected)
        assert not bind_source_matches(translated.rsplit("/", 1)[0], expected)
        other_drive = translated.replace("/run/desktop/mnt/host/", "/run/desktop/mnt/host/x")
        assert not bind_source_matches(other_drive, expected)
    assert not bind_source_matches("", expected)
