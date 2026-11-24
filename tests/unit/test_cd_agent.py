"""Offline checks for CD identity, release selection, and durable recovery."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any, cast

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from infra.deploy import cd_agent as cd
from scripts import deploy_probe


A, B, C = "a" * 40, "b" * 40, "c" * 40
NOW = int(datetime(2026, 11, 23, 18, tzinfo=UTC).timestamp())
IMAGES = {service: f"sha256:{index:064x}" for index, service in enumerate(cd.RUNTIME_SERVICES, 1)}


def services(release: str) -> dict[str, dict[str, Any]]:
    jobs = {"bootstrap-app": "app", "migrate-app": "app", "bootstrap-retail": "retail", "migrate-retail": "retail",
            "seed-demo": "app"}
    images = {"api": "app", "worker": "app", "retail": "retail", "caddy": "web"}
    return {**{name: {"image": name} for name in ("postgres", "dex")},
            **{name: {"image": f"policyops-{image}:{release}"} for name, image in images.items()},
            **{name: {"image": f"policyops-{image}:{release}", "restart": "no"} for name, image in jobs.items()}}


def run(**changes: object) -> dict[str, Any]:
    return {"head_sha": B, "head_branch": "main", "event": "push", "path": ".github/workflows/ci.yml",
            "repository": {"full_name": cd.REPO, "id": 42}, "head_repository": {"full_name": cd.REPO, "id": 42},
            "status": "completed", "conclusion": "success", "run_number": 2, "run_attempt": 1, **changes}


@pytest.mark.parametrize(("changed", "result"), [
    ({}, "green"), ({"event": "pull_request"}, "api_error"), ({"head_branch": "dev"}, "api_error"),
    ({"head_sha": C}, "api_error"), ({"path": ".github/workflows/fake.yml"}, "api_error"),
    ({"repository": {"full_name": cd.REPO, "id": 43}}, "api_error"),
    ({"head_repository": {"full_name": "fork/policyops", "id": 42}}, "api_error"),
    ({"head_repository": {"full_name": cd.REPO, "id": 43}}, "api_error"),
    ({"repository": {"full_name": "elsewhere/policyops", "id": 42}}, "api_error"),
    ({"conclusion": "failure"}, "red"), ({"conclusion": "cancelled"}, "red"),
    ({"status": "in_progress", "conclusion": None}, "pending"),
])
def test_github_evidence(changed: dict[str, Any], result: str) -> None:
    assert cd.ci_verdict({"workflow_runs": [run(**changed)]}, B, 42) == result


def test_newest_attempt_supersedes_older_green() -> None:
    for newest in (run(run_attempt=2, conclusion="failure"), run(run_number=3, conclusion="cancelled")):
        for attempts in ([newest, run()], [run(), newest]):
            assert cd.ci_verdict({"workflow_runs": attempts}, B, 42) == "red"
    assert cd.ci_verdict({"workflow_runs": []}, B, 42) == "pending"
    assert cd.ci_verdict({"workflow_runs": [run(), run(run_attempt=2, status="queued")]}, B, 42) == "pending"


@pytest.mark.parametrize(("status", "body", "headers", "expected"), [
    (200, b"malformed", {}, 0),
    (200, b" " * (cd.API_LIMIT + 1), {}, 0),
    (302, b"", {"location": "https://example.test"}, 0),
    (403, b"", {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(NOW + 123)}, NOW + 123),
    (429, b"", {"retry-after": "120"}, NOW + 120),
    (503, b"", {}, 0),
])
def test_api_fails_closed(monkeypatch: pytest.MonkeyPatch, status: int, body: bytes,
                          headers: dict[str, str], expected: int) -> None:
    calls = []
    stream = io.BytesIO(body)
    response = SimpleNamespace(status=status, getheaders=lambda: headers.items(),
                               getheader=lambda name, default: headers.get(name, default), read=stream.read)

    def https(host: str, *, timeout: int, context: object) -> SimpleNamespace:
        assert host == "api.github.com" and timeout == 5 and context is not None
        return SimpleNamespace(request=lambda method, path, **_kw: calls.append((method, path)),
                               getresponse=lambda: response, close=lambda: None)

    monkeypatch.setattr(http.client, "HTTPSConnection", https)
    monkeypatch.setattr(time, "time", lambda: NOW)
    assert cd.query_ci(B, 42) == ("api_error", expected)
    assert calls == [("GET", f"/repos/{cd.REPO}/actions/workflows/ci.yml/"
                             f"runs?branch=main&event=push&head_sha={B}&per_page=5")]
    assert stream.tell() <= cd.API_LIMIT + 1


@pytest.fixture
def agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> cd.Agent:
    tooling = tmp_path / "tools"
    tooling.mkdir()
    for name in ("policyops-cd", "deploy.sh", "deploy_verify.py"):
        (tooling / name).write_text(name, encoding="utf-8")
    (tmp_path / "releases" / A).mkdir(parents=True)
    (tmp_path / "logs").mkdir()
    controller = cd.Agent(tmp_path, tooling, 9)
    controller.state["last_healthy"] = A
    if "healthy_image_ids" in controller.state:
        controller.state["healthy_image_ids"] = IMAGES.copy()
    controller.host = "demo.example.test"
    controller.api_backoff = 600
    controller.build_interval = 10800
    controller.build_limit = 4
    monkeypatch.setattr(controller, "current", lambda: controller.state["last_healthy"])
    monkeypatch.setattr(controller, "project_current", lambda: None)
    monkeypatch.setattr(controller, "remote_tip", lambda: B)
    monkeypatch.setattr(controller, "fetch", lambda: B)
    monkeypatch.setattr(controller, "ci", lambda *_: ("green", 0))
    monkeypatch.setattr(controller, "describe", lambda release, *_: services(release), raising=False)
    monkeypatch.setattr(controller, "image_ids", lambda *_: IMAGES.copy(), raising=False)
    monkeypatch.setattr(controller, "retain_adopted", lambda *_: None, raising=False)
    monkeypatch.setattr(controller, "first_parent", lambda *_: True)
    monkeypatch.setattr(controller, "steal", lambda: 0)
    monkeypatch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=12 * 1024**3))
    monkeypatch.setattr(time, "time", lambda: NOW)
    controller.save()
    return controller


def audit(agent: cd.Agent) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (agent.cd / "log.jsonl").read_text(encoding="utf-8").splitlines()]


def flight(agent: cd.Agent, phase: cd.Phase, *, schema: bool = False, attempts: int = 0) -> cd.Flight:
    record: cd.Flight = {"candidate": B, "previous": A, "phase": phase, "attempt_id": "d" * 32,
                         "started_at": NOW, "schema": schema, "rollback_attempts": attempts,
                         "rollback_in_progress": 0, "settle": bool(attempts), "forced_stage": ""}
    if "rollback_in_progress" not in cd.Flight.__required_keys__:
        cast(dict[str, Any], record).pop("rollback_in_progress")
    agent.state["in_flight"] = record
    agent.save()
    agent.state = cd.load_state(agent.state_path)
    return record


@pytest.mark.parametrize(("outcome", "updates"), [
    ("api_error", {"backoff_until": NOW + 600}), ("pending", {}),
    ("red", {"last_evaluated_tip": B}),
])
def test_ci_deferral_has_only_allowed_state_changes(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                                    outcome: cd.CI, updates: dict[str, object]) -> None:
    before = dict(agent.state)
    monkeypatch.setattr(agent, "ci", lambda *_: (outcome, 0))
    agent.tick()
    assert cd.load_state(agent.state_path) == {**before, **updates}


@pytest.mark.parametrize(("first_conclusion", "second_conclusion", "expected_queries", "expected_starts"), [
    ("failure", "success", 2, 1),
    ("failure", "failure", 2, 0),
    ("success", "failure", 1, 2),
])
def test_discovery_rechecks_non_green_ci(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                         first_conclusion: str, second_conclusion: str,
                                         expected_queries: int, expected_starts: int) -> None:
    first = run(id=45274847551, conclusion=first_conclusion)
    second = {**first, "run_attempt": 2, "conclusion": second_conclusion}
    responses = iter((first, second))
    queries: list[str] = []
    starts: list[tuple[str, bool]] = []

    def ci(sha: str) -> tuple[cd.CI, int]:
        queries.append(sha)
        return cd.ci_verdict({"workflow_runs": [next(responses)]}, sha, 42), 0

    monkeypatch.setattr(agent, "ci", ci)
    monkeypatch.setattr(agent, "git", lambda *_: "M\0apps/web/runtime.ts\0")
    monkeypatch.setattr(agent, "start", lambda sha, schema: starts.append((sha, schema)))

    agent.tick()
    assert queries == [B]
    assert starts == ([(B, False)] if first_conclusion == "success" else [])
    if first_conclusion == "failure":
        assert (audit(agent)[-1]["decision"], audit(agent)[-1]["reason"]) == ("WAIT_CI", "ci_not_successful")
    agent.state = cd.load_state(agent.state_path)
    agent.tick()

    assert queries == [B] * expected_queries
    assert starts == [(B, False)] * expected_starts
    if expected_starts == 0:
        assert (audit(agent)[-1]["decision"], audit(agent)[-1]["reason"]) == ("WAIT_CI", "ci_not_successful")


@pytest.mark.parametrize(("diff", "forward", "reason"), [
    ("M\0docs/deployment.md\0", True, "skipped_non_runtime"),
    ("D\0apps/web/removed.ts\0M\0docs/deployment.md\0", True, "start"),
    ("R095\0infra/deploy/fix.sh\0docs/fix.md\0", True, "tooling"),
    ("M\0scripts/deploy_verify.py\0", True, "tooling"),
    ("M\0infra/caddy/Caddyfile\0", True, "tooling"),
    ("M\0README.md\0", False, "non_fast_forward"),
    ("M\0evals/migrations/retail/versions/old.py\0", True, "schema_change"),
    ("M\0packages/policyops/src/policyops/persistence/migrations/versions/old.py\0", True, "schema_change"),
    ("M\0packages/policyops/src/policyops/persistence/roles.py\0", True, "schema_change"),
    ("M\0packages/policyops/src/policyops/persistence/migrate.py\0", True, "schema_change"),
    ("M\0evals/src/policyops_evals/retail_sim/bootstrap.py\0", True, "schema_change"),
    ("M\0infra/compose/runtime.py\0", True, "schema_change"),
])
def test_cumulative_diff_and_holds(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, diff: str, forward: bool,
                                  reason: str) -> None:
    deploys = []
    monkeypatch.setattr(agent, "first_parent", lambda *_: forward)
    monkeypatch.setattr(agent, "git", lambda *args: diff if args[-1] == f"{A}..{B}" else pytest.fail(str(args)))
    monkeypatch.setattr(agent, "start", lambda sha, schema: deploys.append((sha, schema)))
    agent.tick()
    assert agent.state["last_healthy"] == A
    if reason == "start":
        assert deploys == [(B, False)]
    else:
        assert deploys == [] and audit(agent)[-1]["reason"] == reason
        if audit(agent)[-1]["decision"] == "HOLD":
            assert agent.operator("release", B) == 0
            agent.tick()
            if reason != "non_fast_forward":
                assert deploys == [(B, reason == "schema_change")]


@pytest.mark.parametrize("failure", [False, True])
def test_gate_retries_verifier_and_requires_every_soak_probe(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                                            failure: bool) -> None:
    seen = []
    samples = [*cd.RUNTIME_SERVICES, "readiness"]
    probes = samples * 6
    if failure:
        probes[7] = "!postgres"

    def deploy(key: str, args: list[str], _timeout: float, *, output: bool) -> tuple[int, str]:
        assert output and key == "gate_soak"
        assert args == [B, agent.host, "--soak", *IMAGES.values()]
        return 0, "\n".join(probes)

    def verifier(release: str, image: str, _seed: Path, key: str, _deadline: float) -> bool:
        assert (release, image) == (B, IMAGES["api"])
        seen.append(key)
        return key.endswith("_2")

    monkeypatch.setattr(agent, "verifier", verifier)
    monkeypatch.setattr(agent, "deploy", deploy)
    monkeypatch.setattr(time, "sleep", lambda _: None)
    assert agent.gate(B, IMAGES, agent.seed(B), "gate", time.monotonic() + 600) is not failure
    assert seen == ["gate_verify_1", "gate_verify_2"]
    assert agent.checks["gate_soak"] == 42
    assert agent.failed["gate_soak"] == (["postgres"] if failure else [])


def test_off_first_parent_candidate_is_dropped(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    flight(agent, "built")
    monkeypatch.setattr(agent, "remote_tip", lambda: C)
    monkeypatch.setattr(agent, "fetch", lambda: C)
    monkeypatch.setattr(agent, "first_parent", cd.Agent.first_parent.__get__(agent))
    monkeypatch.setattr(agent, "git", lambda *args: f"{C}\n{A}\n" if "--first-parent" in args else "")
    agent.tick()
    assert agent.state["in_flight"] is None and not list((agent.cd / "quarantine").iterdir())
    assert audit(agent)[-1]["reason"] == "candidate_off_first_parent"


def test_quarantine_precedes_any_other_release_check(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    agent.quarantine(B, "rolled_back", "candidate_failed")
    monkeypatch.setattr(agent, "ci", lambda: pytest.fail("quarantined tip queried CI"))
    agent.tick()
    assert audit(agent)[-1]["reason"] == "quarantined"


@pytest.mark.parametrize(("phase", "gate", "schema", "decision"), [
    ("building", True, False, "BUILDING"), ("built", True, False, "PROMOTED"),
    ("deploying", True, False, "ROLLED_BACK"), ("deploying", True, True, "FROZEN"),
    ("gating", True, False, "PROMOTED"), ("gating", False, False, "FROZEN"),
    ("gating", False, True, "FROZEN"), ("rolling_back", True, False, "ROLLED_BACK"),
    ("rolling_back", False, False, "FROZEN"),
])
def test_persisted_phase_recovery(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, phase: cd.Phase, gate: bool,
                                  schema: bool, decision: str) -> None:
    flight(agent, phase, schema=schema, attempts=int(phase == "rolling_back"))
    monkeypatch.setattr(agent, "gate", lambda *_: gate)
    monkeypatch.setattr(agent, "deploy", lambda *_: (0, ""))
    monkeypatch.setattr(agent, "settle", lambda *_: True)
    agent.tick()
    assert audit(agent)[-1]["decision"] == decision
    assert cd.load_state(agent.state_path)["in_flight"] is None
    assert agent.state["last_healthy"] == (B if decision == "PROMOTED" else A)
    if decision == "FROZEN":
        assert (agent.cd / "frozen").exists()
        assert cd.read_json(agent.cd / "quarantine" / f"{B}.json")["outcome"] == "inconclusive"


def test_build_retry_and_quarantine(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [NOW]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    monkeypatch.setattr(agent, "deploy", lambda key, *_: (0 if key == "checkout" else 1, ""))
    agent.candidate = B
    agent.start(B, False)
    assert agent.state["build_failures"] == {B: 1}
    agent.start(B, False)
    assert audit(agent)[-1]["reason"] == "build_budget"
    clock[0] += 10800
    agent.start(B, False)
    assert cd.read_json(agent.cd / "quarantine" / f"{B}.json")["outcome"] == "build_failed"


def test_activation_timeout_waits_for_docker_before_rollback(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    steps = []

    def deploy(key: str, _args: list[str], _timeout: float) -> tuple[int, str]:
        steps.append(key)
        return (124 if key == "deploy" else 0), ""

    def settle(_deadline: float) -> bool:
        steps.append("settle")
        return True

    monkeypatch.setattr(agent, "deploy", deploy)
    monkeypatch.setattr(agent, "settle", settle)
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    flight(agent, "built")
    agent.tick()
    assert steps == ["deploy", "settle", "rollback_1"]
    assert audit(agent)[-1]["decision"] == "ROLLED_BACK"


def test_three_rollbacks_in_24_hours_freeze(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    agent.state["rollbacks"] = [NOW - 86000, NOW - 1]
    flight(agent, "rolling_back")
    monkeypatch.setattr(agent, "deploy", lambda *_: (0, ""))
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    agent.tick()
    assert audit(agent)[-1]["reason"] == "rollback_circuit_breaker"
    assert cd.load_state(agent.state_path)["frozen"]


def test_truncated_state_freezes_without_overwrite(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cd, "deploy_lock", lambda _: nullcontext(9))
    monkeypatch.setattr(cd, "BASE", agent.base)
    monkeypatch.setattr(cd, "TOOLS", agent.tooling)
    monkeypatch.setattr(cd, "supported_host", lambda: True)
    monkeypatch.setattr(os, "umask", lambda *_: 0)
    agent.state_path.write_bytes(b'{"last_healthy":')
    assert cd.main(["tick"]) == 1
    assert agent.state_path.read_bytes() == b'{"last_healthy":'
    assert (agent.cd / "frozen").exists()


@pytest.mark.parametrize(("hour", "minute", "blocked"), [(7, 44, False), (7, 45, True), (8, 29, True), (8, 30, False)])
def test_reset_window_blocks_activation(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                        hour: int, minute: int, blocked: bool) -> None:
    clock = datetime(2026, 11, 23, hour, minute, tzinfo=UTC)
    monkeypatch.setattr(time, "time", clock.timestamp)
    monkeypatch.setattr(agent, "deploy", lambda *_: (0, ""))
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    flight(agent, "built")
    agent.tick()
    assert audit(agent)[-1]["reason"] == ("reset_window" if blocked else "gate_passed")


@pytest.mark.parametrize("passed", [True, False])
def test_post_reset_gate(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, passed: bool) -> None:
    (agent.cd / "reset-pending").write_text(A + "\n", encoding="ascii")

    def gate(release: str, images: dict[str, str], seed: Path, key: str, deadline: float) -> bool:
        assert (release, images, seed.name, key) == (A, IMAGES, "scenario-nightly.json", "post_reset")
        return passed

    monkeypatch.setattr(agent, "gate", gate)
    monkeypatch.setattr(agent, "remote_tip", lambda: pytest.fail("post-reset tick must gate first"))
    agent.tick()
    assert agent.state["frozen"] is not passed
    assert (agent.cd / "reset-pending").exists() is not passed


@pytest.mark.parametrize(("stage", "sha", "expiry", "forced"), [
    ("gate", B, NOW + 20, True), ("rollback", B, NOW + 20, True),
    ("gate", C, NOW + 20, False), ("gate", B, NOW - 1, False),
])
def test_drill_is_one_shot_scoped_and_truth_is_audited(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                                      stage: str, sha: str, expiry: int, forced: bool) -> None:
    instruction = agent.cd / "drill.json"
    cd.write_json(instruction, {"candidate": sha, "fail_stage": stage,
                                "expires_at": datetime.fromtimestamp(expiry, UTC).isoformat()})
    flight(agent, "gating")
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    monkeypatch.setattr(agent, "deploy", lambda *_: (0, ""))
    agent.tick()
    records = [item for item in audit(agent) if item["forced"]]
    assert len(records) == (2 if forced and stage == "rollback" else int(forced))
    assert all(item["true_result"] is True for item in records)
    assert instruction.exists() is not forced
    assert audit(agent)[-1]["decision"] == ("ROLLED_BACK" if forced else "PROMOTED")


@pytest.mark.skipif(sys.platform != "linux", reason="uses Linux /proc and flock")
def test_real_lock_is_inheritable_and_excludes_an_independent_opener(tmp_path: Path) -> None:
    path = tmp_path / "deploy.lock"
    with cd.deploy_lock(tmp_path) as fd:
        script = 'exec 9<&"$1"; test /proc/self/fd/9 -ef "$2"; flock -n 9'
        wrapped = subprocess.run(["bash", "-ec", script, "lock", str(fd), str(path)], pass_fds=(fd,), check=False)
        assert wrapped.returncode == 0
        with pytest.raises(BlockingIOError), cd.deploy_lock(tmp_path):
            pytest.fail("independent lock acquired")
    with cd.deploy_lock(tmp_path):
        assert path.is_file()


def test_probe_summary_reports_failures_gaps_and_release_times() -> None:
    def sample(slot: int, error: str | None) -> deploy_probe.Sample:
        return {"at": f"2026-11-23T18:00:0{slot}Z", "endpoint": "release", "slot": slot, "status": 200,
                "release": A if error is None else None, "latency_ms": 4, "error": error}

    samples = [sample(0, None), sample(1, "http_status"), sample(2, "http_status"), sample(4, None)]
    result = deploy_probe.summarize(samples, 5)
    assert result["sample_count"] == 4
    assert result["releases"] == {A: {"first": samples[0]["at"], "last": samples[-1]["at"]}}
    assert result["release_unavailable_before_first_sighting_seconds"] == 0
    assert isinstance(endpoints := result["endpoints"], dict)
    assert endpoints["release"]["gap_slots"] == [3]
    assert endpoints["release"]["longest_failing_window"]["samples"] == 2


@pytest.mark.parametrize("readiness_fails", [False, True])
def test_probe_summary_measures_outage_from_readiness(readiness_fails: bool) -> None:
    def sample(endpoint: str, slot: int, status: int, release: str | None = None) -> deploy_probe.Sample:
        return {"at": f"2026-11-23T18:00:{slot:02}Z", "endpoint": endpoint, "slot": slot, "status": status,
                "release": release, "latency_ms": 4, "error": None if status == 200 else "http_status"}

    samples = [sample("release", slot, 404) for slot in range(7)]
    samples.append(sample("release", 8, 200, A))
    samples.append(sample("release", 9, 404))
    samples.extend(sample("readiness", slot, 503 if readiness_fails and slot in {2, 4, 6} else 200)
                   for slot in range(0, 10, 2))

    result = deploy_probe.summarize(samples, 10)

    assert result["release_unavailable_before_first_sighting_seconds"] == 7
    assert isinstance(endpoints := result["endpoints"], dict)
    assert endpoints["release"]["gap_slots"] == [7]
    assert endpoints["release"]["longest_failing_window"]["sample_span_seconds"] == 6
    outage = result["longest_failing_window"]
    assert outage == endpoints["readiness"]["longest_failing_window"]
    if readiness_fails:
        assert outage == {"endpoint": "readiness", "first": "2026-11-23T18:00:02Z",
                          "last": "2026-11-23T18:00:06Z", "sample_span_seconds": 4, "samples": 3}
    else:
        assert outage is None
