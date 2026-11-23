"""Offline regressions for CD approval, preflight and reset recovery."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import json
import os
from pathlib import Path
from typing import Any

import pytest

from infra.deploy import cd_agent as cd
from tests.unit.test_cd_agent import IMAGES, A, B, audit, flight, services
from tests.unit.test_cd_agent import agent as agent
from tests.unit.test_cd_round2 import host as host
from tests.unit.test_cd_round2 import run_host_script


RESET_DAY = "2026-11-23"
REQUEST = RESET_DAY + "-" + "d" * 32


def test_release_requires_fresh_approval_for_new_schema_reason(
    agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    calls = []
    candidate = services(B)
    candidate["postgres"]["image"] = "pgvector:new-pin"
    monkeypatch.setattr(agent, "git", lambda *_: "M\0infra/deploy/deploy.sh\0M\0compose.yaml\0")
    monkeypatch.setattr(agent, "describe", lambda release, *_: candidate if release == B else services(A))

    def deploy(key: str, args: list[str], _timeout: float) -> tuple[int, str]:
        calls.append((key, args))
        return 0, ""

    monkeypatch.setattr(agent, "deploy", deploy)
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    agent.tick()
    assert audit(agent)[-1]["reason"] == "tooling"
    assert agent.operator("release", B) == 0
    agent.state = cd.load_state(agent.state_path)
    agent.tick()
    assert audit(agent)[-1]["reason"] == "schema_change"
    assert calls == [("checkout", ["--checkout-only", B])]
    assert agent.state["last_healthy"] == A
    assert agent.state["released_reasons"] == ["tooling"]
    assert capsys.readouterr().out.strip() == f"Released {B} for tooling"
    assert agent.operator("release", B) == 0
    agent.state = cd.load_state(agent.state_path)
    assert agent.state["released_reasons"] == ["schema_change", "tooling"]
    assert capsys.readouterr().out.strip() == f"Released {B} for schema_change"
    agent.tick()
    assert ("deploy", [B, agent.host, "--candidate", "--allow-schema"]) in calls
    assert agent.state["last_healthy"] == B


def check_prebuild_hold(
    agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, config: dict[str, dict[str, Any]] | None,
) -> None:
    calls = []

    def deploy(key: str, args: list[str], _timeout: float, *, output: bool = False) -> tuple[int, str]:
        calls.append(key)
        if key == "candidate_config":
            assert output and args == [B, agent.host, "--describe"]
            return (1, "") if config is None else (0, json.dumps({"services": config}))
        if key == "baseline_config":
            return 0, json.dumps({"services": services(A)})
        if key == "build":
            return 1, ""
        return 0, ""

    monkeypatch.delattr(agent, "describe")
    monkeypatch.setattr(agent, "deploy", deploy)
    monkeypatch.setattr(agent, "git", lambda *_: "M\0compose.yaml\0")
    agent.tick()
    assert calls == ["checkout", "candidate_config"]
    assert audit(agent)[-1]["decision"] == "HOLD"
    assert audit(agent)[-1]["reason"] == "tooling"
    assert agent.state["in_flight"] is None and agent.state["daily_count"] == 0
    assert not list((agent.cd / "quarantine").iterdir())


@pytest.mark.parametrize(("service", "change"), [
    ("api", {"build": {"tags": [f"policyops-app:{A}"]}}),
    ("migrate-retail", {"build": {"tags": ["example.test/arbitrary:latest"]}}),
    ("dex", {"image": f"docker.io/library/policyops-web:{A}"}),
    ("postgres", {"image": f"policyops-app:{B}"}),
    ("seed-demo", {"image": f"policyops-web:{A}"}),
])
def test_prebuild_rejects_tag_aliases(
    agent: cd.Agent, host: Path, monkeypatch: pytest.MonkeyPatch, service: str, change: dict[str, Any],
) -> None:
    config = services(A)
    config[service].update(change)
    (host / "config").write_text(json.dumps({"services": config}), encoding="ascii")
    result, trace = run_host_script(host, "deploy.sh", "--build-only", A)
    assert result.returncode == 42, (result.stderr, trace)
    assert not any(" build " in line for line in trace)
    config = services(B)
    config[service].update(change)
    check_prebuild_hold(agent, monkeypatch, config)


@pytest.mark.parametrize("change", ["missing", "renamed", "added", "one_shot_removed", "one_shot_added"])
def test_topology_is_checked_before_build(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    config = services(B)
    if change == "missing":
        del config["api"]
    elif change == "renamed":
        config["new-name"] = config.pop("retail")
    elif change == "added":
        config["sidecar"] = {"restart": "always"}
    elif change == "one_shot_removed":
        del config["seed-demo"]
    else:
        config["new-job"] = {"restart": "no"}
    check_prebuild_hold(agent, monkeypatch, config)


def test_invalid_candidate_compose_config_is_held_before_build(
    agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
) -> None:
    check_prebuild_hold(agent, monkeypatch, None)


@pytest.mark.parametrize(("failure", "step"), [
    ("TEST_RENEW_EXIT", "volume_deleted"), ("TEST_REMOVE_EXIT", "volume_owned"),
])
def test_reset_resumes_after_volume_removal(
    host: Path, monkeypatch: pytest.MonkeyPatch, failure: str, step: str,
) -> None:
    progress = host / "cd" / "reset-progress"
    monkeypatch.setenv(failure, "1")
    failed, trace = run_host_script(host, "reset.sh")
    assert failed.returncode == 1 and any(" volume rm " in line for line in trace)
    assert progress.exists()
    assert progress.read_text(encoding="ascii").split() == [RESET_DAY, A, step]
    monkeypatch.delenv(failure)
    retried, trace = run_host_script(host, "reset.sh", "--resume")
    assert retried.returncode == 0, retried.stderr
    assert not any(" volume inspect " in line or " volume rm " in line for line in trace)
    assert any("/renew.py" in line for line in trace) and any(" up " in line for line in trace)
    assert any("scenario.py seed" in line for line in trace) and not progress.exists()


def test_reset_rechecks_existing_volume_before_removal(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    progress = host / "cd" / "reset-progress"
    monkeypatch.setenv("TEST_VOLUME_OWNER", "different-owner")
    result, trace = run_host_script(host, "reset.sh")
    assert result.returncode == 1 and any(" volume inspect " in line for line in trace)
    assert not any(" volume rm " in line or " down " in line for line in trace)
    assert progress.read_text(encoding="ascii").split() == [RESET_DAY, A, "started"]
    progress.write_text(f"{RESET_DAY} {A} volume_owned\n", encoding="ascii", newline="\n")
    result, trace = run_host_script(host, "reset.sh", "--resume")
    assert result.returncode == 1 and any(" volume inspect " in line for line in trace)
    assert not any(" volume rm " in line or " down " in line for line in trace)
    assert progress.read_text(encoding="ascii").split()[-1] == "volume_owned"


def test_reset_consumes_matching_missed_before_pending_and_recovers_publication(
    host: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = host / "cd"
    missed, progress, pending = (records / f"reset-{name}" for name in ("missed", "progress", "pending"))
    missed.write_text(REQUEST + "\n", encoding="ascii", newline="\n")
    monkeypatch.setenv("TEST_INTERRUPT_PUBLISH", "1")
    failed, _ = run_host_script(host, "reset.sh", "--resume")
    assert failed.returncode == 1 and not pending.exists()
    assert not missed.exists()
    assert progress.read_text(encoding="ascii").split() == [REQUEST, A, "seeded"]
    assert (records / "reset-completed" / REQUEST).read_text(encoding="ascii").split() == [REQUEST, A]
    next_request = RESET_DAY + "-" + "e" * 32
    missed.write_text(next_request + "\n", encoding="ascii", newline="\n")
    monkeypatch.delenv("TEST_INTERRUPT_PUBLISH")
    retried, trace = run_host_script(host, "reset.sh", "--resume")
    assert retried.returncode == 0, retried.stderr
    assert not any(line.startswith("docker ") for line in trace)
    assert pending.read_text(encoding="ascii").split() == [REQUEST, A] and not progress.exists()
    assert missed.read_text(encoding="ascii").strip() == next_request


def test_completed_reset_id_cannot_start_again(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    completed = agent.cd / "reset-completed"
    completed.mkdir()
    (completed / REQUEST).write_text(f"{REQUEST} {A}\n", encoding="ascii")
    missed = agent.cd / "reset-missed"
    missed.write_text(REQUEST + "\n", encoding="ascii")
    monkeypatch.setattr(agent, "command", lambda *_args, **_kwargs: pytest.fail("completed ID started again"))
    assert not agent.process_reset(A)
    missed.write_text(RESET_DAY + "-" + "e" * 32 + "\n", encoding="ascii")
    assert agent.reset_requested()


@pytest.mark.parametrize("change", [{"scale": 0}, {"scale": 2}, {"deploy": {"replicas": 2}}])
def test_replica_count_is_checked_before_build(
    agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, change: dict[str, Any],
) -> None:
    config = services(B)
    config["worker"].update(change)
    check_prebuild_hold(agent, monkeypatch, config)


@pytest.mark.parametrize("count", ["EXTRA", "MISSING"])
def test_soak_checks_all_containers_by_project_and_service(
    host: Path, monkeypatch: pytest.MonkeyPatch, count: str,
) -> None:
    monkeypatch.setenv(f"TEST_{count}_SERVICE", "worker")
    soak, trace = run_host_script(host, "deploy.sh", A, "demo.example.test", "--soak", *[IMAGES["api"]] * 6)
    assert soak.returncode == 0, soak.stderr
    assert soak.stdout.splitlines().count("!worker") == 6
    assert soak.stdout.splitlines().count("api") == 6
    assert sum("label=com.docker.compose.project=policyops-public" in line
               and "label=com.docker.compose.service=worker" in line for line in trace) == 6
    assert sum("inspect" in line and "worker-1 worker-2" in line for line in trace) == (6 if count == "EXTRA" else 0)


@pytest.mark.parametrize(("phase", "active", "allowed"), [
    ("building", False, True), ("built", False, True), ("built", True, False),
    ("deploying", False, False), ("gating", False, False), ("rolling_back", False, False), (None, False, False),
])
def test_cancel_requires_pre_cutover_flight_without_active_marker(
    agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, phase: cd.Phase | None, active: bool, allowed: bool,
) -> None:
    record = flight(agent, phase) if phase else None
    if active:
        assert record is not None
        agent.mark_active(record)
    serving = agent.base / "current"
    serving.write_text(A, encoding="ascii")
    lock_held = False

    @contextmanager
    def lock(base: Path) -> Iterator[int]:
        nonlocal lock_held
        assert base == agent.base
        lock_held = True
        yield 9
        lock_held = False

    def config(_agent: cd.Agent) -> None:
        assert lock_held

    monkeypatch.setattr(cd, "BASE", agent.base)
    monkeypatch.setattr(cd, "TOOLS", agent.tooling)
    monkeypatch.setattr(cd, "supported_host", lambda: True)
    monkeypatch.setattr(cd, "deploy_lock", lock)
    monkeypatch.setattr(cd.Agent, "config", config)
    monkeypatch.setattr(cd.Agent, "deploy", lambda *_: pytest.fail("cancel changed the serving stack"))
    monkeypatch.setattr(os, "umask", lambda _: 0)
    assert cd.main(["cancel"]) == (0 if allowed else 1)
    state = cd.load_state(agent.state_path)
    assert state["in_flight"] == (None if allowed else record)
    assert state["last_healthy"] == A and serving.read_text(encoding="ascii") == A
    assert (agent.cd / "active").exists() is active
    if allowed:
        assert record is not None
        decision = audit(agent)[-1]
        assert (decision["decision"], decision["candidate"], decision["attempt_id"]) == (
            "CANCELLED", B, record["attempt_id"],
        )
