"""Round 2 regressions for the CD controller and host scripts, with no external services."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from importlib.util import resolve_name
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from infra.deploy import cd_agent as cd
from tests.unit.test_cd_agent import IMAGES, A, B, C, audit, flight, run, services
from tests.unit.test_cd_agent import agent as agent
from tests.unit.test_deploy_policy import shell_binary


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("newest", [{"status": "queued", "conclusion": None}, {"conclusion": "failure"}])
def test_fresh_ci_supersedes_deferred_green(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                             newest: dict[str, object]) -> None:
    agent.state.update({"last_evaluated_tip": B, "ci_green": True})
    flight(agent, "built")
    checked = []
    commands = []

    def ci(sha: str = "") -> tuple[cd.CI, int]:
        checked.append(sha)
        return cd.ci_verdict({"workflow_runs": [run(), run(run_attempt=2, **newest)]}, B, 42), 0

    def binding(_sha: str) -> bool:
        agent.tip = C
        return True

    def deploy(key: str, *_args: object) -> tuple[int, str]:
        commands.append(key)
        return 0, ""

    monkeypatch.setattr(agent, "ci", ci)
    monkeypatch.setattr(agent, "binding", binding)
    monkeypatch.setattr(agent, "deploy", deploy)
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    agent.tick()
    assert (checked, commands) == ([B], [])
    assert agent.state["in_flight"] is None and not agent.state["ci_green"]
    assert audit(agent)[-1]["decision"] == "WAIT_CI"
    assert not list((agent.cd / "quarantine").iterdir())


@pytest.mark.parametrize("section", ["postgres", "migrate-retail"])
def test_resolved_merge_holds_schema_change(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, section: str) -> None:
    yaml_text = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    if section == "postgres":
        original = re.search(r"(?m)^    image: pgvector[^\n]+", yaml_text)
        assert original is not None
        field = original[0]
        updated = '    image: pgvector:test-new-pin'
    else:
        field = "    command: [migrate-retail]"
        updated = "    command: [bootstrap-retail]"
    before = "x-test: &test\n" + field + "\n" + yaml_text.replace(field, "    <<: *test", 1)
    # Make the added command override an existing YAML merge within the job.
    before = before.replace("    <<: *retail\n    <<: *test", "    <<: [*test, *retail]")
    after = before.replace(field, updated, 1)
    assert before.split("services:", 1)[1] == after.split("services:", 1)[1]
    trace = []

    def deploy(key: str, args: list[str], _timeout: float, *, output: bool = False) -> tuple[int, str]:
        trace.append((key, args))
        if args[-1] == "--describe":
            assert output
            config = yaml.safe_load((before if args[0] == A else after).replace(
                "${POLICYOPS_IMAGE_TAG:-local}", args[0]))
            return 0, json.dumps(config)
        return 0, ""

    monkeypatch.setattr(agent, "deploy", deploy)
    monkeypatch.delattr(agent, "describe")
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    monkeypatch.setattr(agent, "git", lambda verb, *args: "M\0compose.yaml\0" if verb == "diff" else
                        before if args[0].startswith(A) else after)
    agent.tick()
    assert [key for key, _ in trace] == ["checkout", "candidate_config", "baseline_config"]
    assert cd.load_state(agent.state_path)["in_flight"] is None
    assert audit(agent)[-1]["reason"] == "schema_change" and not (agent.cd / "active").exists()
    assert agent.operator("release", B) == 0
    agent.tick()
    assert ("deploy", [B, agent.host, "--candidate", "--allow-schema"]) in trace
    assert agent.state["last_healthy"] == B


def test_schema_set_covers_recursive_repository_migration_imports() -> None:
    app, contracts, evals = (ROOT / path for path in ("packages/policyops/src", "packages/policyops_contracts/src",
                                                     "evals/src"))
    source_roots = [app, contracts, evals, ROOT]
    runners = [app / "policyops/persistence/migrate.py", evals / "policyops_evals/retail_sim/migrate.py"]
    pending = [*runners, *(source for prefix in cd.SCHEMA_PREFIXES for source in (ROOT / prefix).rglob("*.py"))]
    visited: set[Path] = set()
    imported: set[Path] = set()

    def modules(name: str) -> set[Path]:
        parts = name.split(".")
        found = set()
        for root in source_roots:
            for i in range(1, len(parts) + 1):
                candidate = root.joinpath(*parts[:i])
                for source in (candidate / "__init__.py", candidate.with_suffix(".py")):
                    if source.is_file():
                        found.add(source)
        return found

    while pending:
        source = pending.pop()
        if source in visited:
            continue
        visited.add(source)
        tree = ast.parse(source.read_text(encoding="utf-8"))
        dependencies = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dependencies.update(modules(alias.name))
            elif isinstance(node, ast.ImportFrom):
                name = node.module or ""
                if node.level > 0:
                    package_root = next(root for root in source_roots if source.is_relative_to(root))
                    package = ".".join(source.parent.relative_to(package_root).parts)
                    name = resolve_name("." * node.level + name, package)
                dependencies.update(modules(name))
                for alias in node.names:
                    dependencies.update(modules(f"{name}.{alias.name}"))
        imported.update(dependencies)
        pending.extend(dependencies - visited)

    paths = {source.relative_to(ROOT).as_posix() for source in imported}
    assert any(path.endswith("/persistence/migration_guard.py") for path in paths)
    assert any(path.endswith("/retail_sim/schema.py") for path in paths)
    missing = {path for path in paths if path not in cd.SCHEMA_FILES and not path.startswith(cd.SCHEMA_PREFIXES)}
    assert not missing, sorted(missing)


@pytest.mark.parametrize("change", ["extra_runtime", "extra_one_shot", "removed_seed", "changed_class", "profiled"])
def test_candidate_topology_is_held(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    flight(agent, "built")
    candidate = services(B)
    if change.startswith("extra"):
        candidate["unrecognized"] = {"restart": "no" if change == "extra_one_shot" else "always"}
    elif change == "removed_seed":
        del candidate["seed-demo"]
    elif change == "profiled":
        candidate["caddy"]["profiles"] = ["optional"]
    else:
        candidate["migrate-app"]["restart"] = "always"
    monkeypatch.setattr(agent, "describe", lambda release, *_: candidate if release == B else services(A))
    monkeypatch.setattr(agent, "deploy", lambda key, *_: pytest.fail(f"unsupported topology invoked {key}"))
    agent.tick()
    assert audit(agent)[-1]["reason"] == "tooling"
    parked = cd.load_state(agent.state_path)["in_flight"]
    assert parked and parked["phase"] == "built"
    monkeypatch.setattr(agent, "remote_tip", lambda: C)
    agent.tick()
    assert agent.state["in_flight"] is None and audit(agent)[-1]["reason"] == "held_tip_superseded"


@pytest.mark.parametrize(("hour", "minute"), [(6, 58), (7, 1)])
def test_build_budget_reserves_reset_window(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                            hour: int, minute: int) -> None:
    monkeypatch.setattr(time, "time", datetime(2026, 11, 23, hour, minute, tzinfo=UTC).timestamp)
    monkeypatch.setattr(agent, "deploy", lambda key, *_: pytest.fail(f"reset overlap invoked {key}"))
    agent.start(B, False)
    assert audit(agent)[-1]["reason"] == "reset_window"
    assert agent.state["in_flight"] is None


def test_missed_reset_survives_freeze_and_has_priority(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    missed = agent.cd / "reset-missed"
    pending = agent.cd / "reset-pending"
    missed.touch()
    agent.freeze("test")
    agent.tick()
    assert missed.exists()
    agent.operator("unfreeze", "")
    calls = []

    def command(key: str, args: list[str], _timeout: float, *, inherited: bool) -> tuple[int, str]:
        assert (key, args, inherited) == ("reset", ["/usr/local/sbin/policyops-demo-reset", "--resume"], True)
        calls.append("reset")
        pending.write_text(A + "\n", encoding="ascii")
        missed.unlink()
        return 0, ""

    def gate(release: str, _images: object, seed: Path, key: str, _deadline: float) -> bool:
        assert (release, seed.name, key) == (A, "scenario-nightly.json", "post_reset")
        calls.append(key)
        return True

    monkeypatch.setattr(agent, "command", command)
    monkeypatch.setattr(agent, "gate", gate)
    monkeypatch.setattr(agent, "remote_tip", lambda: pytest.fail("discovery preceded the missed reset"))
    agent.tick()
    assert calls == ["reset", "post_reset"] and not pending.exists() and not missed.exists()


@pytest.mark.parametrize("phase", ["building", "built"])
@pytest.mark.parametrize("reset", ["reset-pending", "reset-missed"])
def test_reset_gates_baseline_before_pre_cutover_resume(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch,
                                                       phase: cd.Phase, reset: str) -> None:
    record = flight(agent, phase)
    (agent.cd / reset).write_text(A + "\n" if reset == "reset-pending" else "2026-11-23\n", encoding="ascii")
    calls = []

    def command(_key: str, _args: list[str], _timeout: float, *, inherited: bool) -> tuple[int, str]:
        assert inherited
        (agent.cd / reset).unlink()
        (agent.cd / "reset-pending").write_text(A + "\n", encoding="ascii")
        return 0, ""

    def gate(release: str, _images: object, _seed: Path, key: str, _deadline: float) -> bool:
        calls.append((release, key))
        return True

    monkeypatch.setattr(agent, "command", command)
    monkeypatch.setattr(agent, "gate", gate)
    monkeypatch.setattr(agent, "deploy", lambda key, *_: pytest.fail(f"pre-cutover phase invoked {key}"))
    agent.tick()
    assert calls == [(A, "post_reset")]
    assert cd.load_state(agent.state_path)["in_flight"] == record


def test_pre_cutover_clears_active_before_deferring(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    flight(agent, "built")
    active = agent.cd / "active"
    active.touch()
    monkeypatch.setattr(shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    agent.tick()
    assert audit(agent)[-1]["reason"] == "disk_low" and not active.exists()


def test_deploying_phase_is_durable_before_active_and_recreates_it_on_resume(
        agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    flight(agent, "built")
    active = agent.cd / "active"
    write = cd.write_json

    def interrupt(path: Path, body: object) -> None:
        if path == active:
            raise InterruptedError
        write(path, body)

    with monkeypatch.context() as patch:
        patch.setattr(cd, "write_json", interrupt)
        with pytest.raises(InterruptedError):
            agent.tick()
    agent.state = cd.load_state(agent.state_path)
    persisted = agent.state["in_flight"]
    assert persisted and persisted["phase"] == "deploying" and not active.exists()

    def rollback(_flight: cd.Flight) -> None:
        assert cd.read_json(active) == {"attempt_id": persisted["attempt_id"]}

    monkeypatch.setattr(agent, "rollback", rollback)
    agent.tick()


def test_final_rollback_attempt_resumes_after_crash_before_restore(agent: cd.Agent,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    flight(agent, "rolling_back", attempts=1)
    monkeypatch.setattr(agent, "settle", lambda *_: True)
    seen = []

    def interrupted(key: str, *_args: object) -> tuple[int, str]:
        seen.append(key)
        raise InterruptedError

    def restore(key: str, *_args: object) -> tuple[int, str]:
        seen.append(key)
        return 0, ""

    monkeypatch.setattr(agent, "deploy", interrupted)
    with pytest.raises(InterruptedError):
        agent.tick()
    agent.state = cd.load_state(agent.state_path)
    in_progress = agent.state["in_flight"]
    progress = in_progress.get("rollback_in_progress") if in_progress else None
    monkeypatch.setattr(agent, "deploy", restore)
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    agent.tick()
    assert seen == ["rollback_2", "rollback_2"]
    assert progress == 2
    assert audit(agent)[-1]["decision"] == "ROLLED_BACK"


def test_rollback_removes_only_stuck_project_ids_after_90_seconds(agent: cd.Agent,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    stuck = ["d" * 64, "e" * 64]
    removed = []

    def command(key: str, args: list[str], _timeout: float, **_options: Any) -> tuple[int, str]:
        if key == "settle":
            if "--no-trunc" not in args:  # Frozen settle only asked for lifecycle states.
                return 0, "created\nrestarting\n"
            assert "label=com.docker.compose.project=policyops-public" in args
            assert {"status=created", "status=restarting"} <= set(args)
            return 0, f"{stuck[0]} created\n{stuck[1]} restarting\n"
        assert key == "settle_remove" and args == ["docker", "rm", "-f", "--", *stuck]
        removed.append(clock[0])
        return 0, ""

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", lambda interval: clock.__setitem__(0, clock[0] + interval))
    monkeypatch.setattr(agent, "command", command)
    monkeypatch.setattr(agent, "deploy", lambda *_: (0, "") if removed else pytest.fail("containers still stuck"))
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    flight(agent, "deploying")
    agent.tick()
    assert removed == [90] and audit(agent)[-1]["decision"] == "ROLLED_BACK"


def test_adopt_imports_exact_checkout_sha_for_rewritten_main(agent: cd.Agent,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    retained = set()

    def git(*args: str) -> str:
        if args[0] == "init":
            assert args == ("init", "--bare", str(agent.mirror))
        elif args[0] == "fetch":
            assert args == ("fetch", "--no-tags", str(agent.base / "releases" / A), f"+{A}:refs/policyops/adopted/{A}")
            retained.add(A)
        else:
            assert args[-1] == f"{A}..{B}" and A in retained
            return "M\0apps/web/src/main.ts\0"
        return ""

    monkeypatch.delattr(agent, "retain_adopted")
    monkeypatch.setattr(agent, "git", git)
    monkeypatch.setattr(agent, "gate", lambda *_: True)
    monkeypatch.setattr(agent, "first_parent", lambda *_: False)
    agent.operator("adopt", "")
    agent.tick()
    assert audit(agent)[-1]["reason"] == "non_fast_forward"
    assert agent.operator("release", B) == 0


def test_readopt_uses_persisted_post_reset_fixture(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    (agent.cd / "reset-pending").write_text(A + "\n", encoding="ascii")
    nightly = agent.base / "logs" / "scenario-nightly.json"
    seen = []

    def gate(_release: str, _images: object, seed: Path, key: str, _deadline: float) -> bool:
        seen.append((key, seed))
        return seed == nightly

    monkeypatch.setattr(agent, "gate", gate)
    agent.tick()
    agent.state = cd.load_state(agent.state_path)
    agent.operator("adopt", "")
    assert seen == [("post_reset", nightly), ("adopt", nightly)]
    assert agent.state["gated_fixture"] == {"release": A, "seed_path": str(nightly)}


def test_adopt_and_promotion_record_the_image_ids_they_gate(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch) -> None:
    promoted = {name: f"sha256:{index:064x}" for index, name in enumerate(cd.RUNTIME_SERVICES, 32)}
    inspect = []

    def command(key: str, args: list[str], _timeout: float, *, output: bool) -> tuple[int, str]:
        assert output and args[:6] == ["docker", "image", "inspect", "-f", "{{.Id}}", "--"]
        inspect.append(key)
        names = IMAGES if key == "adopt_images" else promoted
        return 0, "\n".join(names.values())

    seen = []

    def gate(release: str, images: dict[str, str], *_: object) -> bool:
        seen.append((release, images))
        return True

    monkeypatch.setattr(agent, "command", command)
    monkeypatch.delattr(agent, "image_ids")
    monkeypatch.setattr(agent, "gate", gate)
    agent.operator("adopt", "")
    assert cd.load_state(agent.state_path).get("healthy_image_ids") == IMAGES
    flight(agent, "gating")
    agent.tick()
    state = cd.load_state(agent.state_path)
    assert state["healthy_image_ids"] == promoted
    assert state["gated_fixture"] == {"release": B, "seed_path": str(agent.seed(B))}
    assert inspect == ["adopt_images", "gate_images"] and seen == [(A, IMAGES), (B, promoted)]


def test_rollback_and_restored_soak_use_pinned_ids_without_tag_lookup(agent: cd.Agent,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    flight(agent, "rolling_back")
    calls = []

    def deploy(key: str, args: list[str], _timeout: float, *, output: bool = False) -> tuple[int, str]:
        calls.append(key)
        assert args == [A, agent.host, "--soak" if output else "--rollback", *IMAGES.values()]
        return 0, "\n".join([*cd.RUNTIME_SERVICES, "readiness"] * 6) if output else ""

    def verifier(release: str, image: str, *_: object) -> bool:
        assert (release, image) == (A, IMAGES["api"])
        return True

    monkeypatch.setattr(agent, "deploy", deploy)
    monkeypatch.setattr(agent, "verifier", verifier)
    monkeypatch.setattr(agent, "command", lambda *_args, **_kwargs: pytest.fail("rollback looked up a mutable tag"))
    agent.tick()
    assert calls == ["rollback_1", "rollback_1_soak"]
    assert cd.load_state(agent.state_path)["gated_fixture"] == {"release": A, "seed_path": str(agent.seed(A))}


def test_prober_imports_without_httpx() -> None:
    result = subprocess.run([sys.executable, "-IBS", "-c",
                             "import runpy, sys; sys.modules['httpx'] = None; "
                             "assert runpy.run_path(sys.argv[1])['hostname']('example.test') == 'example.test'",
                             str(ROOT / "scripts/deploy_probe.py")], capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode()


FAKE_HOST = r"""
trace() { printf '%s\n' "$*" >> "$TEST_TRACE"; }
flock() {
  trace "flock $*"
  [[ "${*: -1}" != 9 || "${TEST_LOCK_BUSY:-0}" = 0 ]]
}
sync() { trace "sync $*"; }
date() { printf '%s\n' '2026-11-23'; }
mv() {
  if [[ "${*: -1}" = */reset-pending && "${TEST_INTERRUPT_PUBLISH:-0}" = 1 ]]; then return 1; fi
  command mv "$@"
}
sleep() { :; }
chmod() { :; }
install() {
  [[ "$1" = -d && "$2" = -m ]] || return 1
  shift 3
  mkdir -p "$@"
}
python3() { "$TEST_PYTHON" "$@"; }
git() {
  case "$*" in
    *'status --porcelain') ;;
    *'rev-parse HEAD') printf '%s\n' "$TEST_SHA" ;;
    *) trace "unexpected git $*"; return 1 ;;
  esac
}
curl() {
  trace "curl $*"
  if [[ "$*" = *--resolve* ]]; then
    printf '%s' "${TEST_LOOPBACK_HTTP:-200}"
  else
    printf '%s' "${TEST_PUBLIC_HTTP:-200}"
  fi
  return "${TEST_CURL_EXIT:-0}"
}
docker() {
  trace "docker $*"
  case "$*" in
    *'config --format json') cat "$TEST_CONFIG" ;;
    *'image inspect -f '*) printf '%s\n' "$TEST_ID" ;;
    ps*'label=com.docker.compose.service='*)
      service=${*: -1}
      service=${service##*=}
      if [[ "$service" != "${TEST_MISSING_SERVICE:-}" ]]; then printf '%s-1\n' "$service"; fi
      if [[ "$service" = "${TEST_EXTRA_SERVICE:-}" ]]; then printf '%s-2\n' "$service"; fi ;;
    *'inspect -f '*'.State.Status'*)
      printf 'running 0 false %s id\n' "$TEST_ID"
      if [[ "$*" = *worker-2* ]]; then printf 'exited 1 false %s id-two\n' "$TEST_ID"; fi ;;
    'volume ls '*)
      if ! test -e "$TEST_BASE/volume-absent"; then printf 'policyops-public_pgdata\n'; fi ;;
    *'volume inspect '*'.Labels "com.docker.compose.project"'*)
      test ! -e "$TEST_BASE/volume-absent" || return 1
      printf 'policyops-public\n' ;;
    *'volume inspect '*'.Labels "policyops.run"'*) printf 'public-demo\n' ;;
    *'volume inspect '*'.Labels "policyops.owner"'*) printf '%s\n' "${TEST_VOLUME_OWNER:-policyops-compose}" ;;
    'volume rm '*)
      touch "$TEST_BASE/volume-absent"
      return "${TEST_REMOVE_EXIT:-0}" ;;
    *' -B /renew.py') return "${TEST_RENEW_EXIT:-0}" ;;
    *' psql '*|run*'print(head())') printf 'test-head\n' ;;
    *'scenario.py seed') printf '{}\n' ;;
    *'rollback-images.'*' up '*)
      for arg in "$@"; do
        if [[ "$arg" = *rollback-images.* ]]; then cat "$arg" >> "$TEST_TRACE"; break; fi
      done ;;
  esac
}
"""


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    tmp_path = tmp_path / "fake-host"
    for name in (f"releases/{A}", "cd", "tmp", "logs", "secrets"):
        (tmp_path / name).mkdir(parents=True)
    (tmp_path / "hostname").write_text("demo.example.test\n", encoding="ascii")
    # Reset only needs a resolvable current directory in this fake host.
    (tmp_path / "current").mkdir()
    (tmp_path / "cd" / "state.json").touch()
    for key, value in {"TEST_BASE": tmp_path.as_posix(), "TEST_TRACE": (tmp_path / "trace").as_posix(),
                       "TEST_CONFIG": (tmp_path / "config").as_posix(), "TEST_PYTHON": Path(sys.executable).as_posix(),
                       "TEST_SHA": A, "TEST_ID": IMAGES["api"]}.items():
        monkeypatch.setenv(key, value)
    (tmp_path / "config").write_text(json.dumps({"services": services(A)}), encoding="ascii")
    return tmp_path


def run_host_script(host: Path, name: str, *args: str, inherited: bool = True) -> tuple[
        subprocess.CompletedProcess[str], list[str]]:
    script = (ROOT / "infra/deploy" / name).read_text(encoding="utf-8").replace(
        "base=/var/lib/policyops", 'base="$TEST_BASE"').replace('test "$EUID" -eq 0', ":")
    script = script.replace('install -d -o 10001 -g 10001', 'install -d')
    script = script.replace('tool_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)',
                            f'tool_dir="{(ROOT / "infra/deploy").as_posix()}"')
    harness = host / "host-test.sh"
    lock = 'exec 9>>"$TEST_BASE/deploy.lock"\n' if inherited else ""
    harness.write_text(FAKE_HOST + lock + script, encoding="utf-8", newline="\n")
    result = subprocess.run([shell_binary("bash"), str(harness), *args], capture_output=True, encoding="utf-8",
                            check=False, timeout=30)
    trace = host / "trace"
    lines = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
    trace.unlink(missing_ok=True)
    return result, lines


@pytest.mark.parametrize("service", ["api", "retail", "caddy"])
def test_build_rejects_reused_image_tag_before_build(host: Path, service: str) -> None:
    config = host / "config"
    good = json.loads(config.read_text(encoding="ascii"))
    result, trace = run_host_script(host, "deploy.sh", "--build-only", A)
    assert result.returncode == 0, result.stderr
    assert sum(" build " in line for line in trace) == 3
    good["services"][service]["image"] = good["services"][service]["image"].replace(A, B)
    config.write_text(json.dumps(good), encoding="ascii")
    result, trace = run_host_script(host, "deploy.sh", "--build-only", A)
    assert result.returncode != 0 and f"{service} requires its commit-specific image" in result.stderr
    assert not any(" build " in line for line in trace)


def test_restore_passes_ids_to_compose(host: Path) -> None:
    result, trace = run_host_script(host, "deploy.sh", A, "demo.example.test", "--rollback", *IMAGES.values())
    assert result.returncode == 0, result.stderr
    overrides = [json.loads(line)["services"] for line in trace if line.startswith('{"services"')]
    assert overrides == [{service: {"image": image} for service, image in IMAGES.items()}] * 2
    assert not list((host / "tmp").glob("rollback-images.*"))


def test_activation_requires_normal_dns_readiness(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_PUBLIC_HTTP", "503")
    result, trace = run_host_script(host, "deploy.sh", A, "demo.example.test", "--candidate")
    curl = [line for line in trace if line.startswith("curl ")]
    assert result.returncode != 0 and any(" up " in line for line in trace), result.stderr
    assert any("--resolve" not in line for line in curl) and any("--resolve" in line for line in curl)
    assert not any("scenario.py seed" in line for line in trace)


def test_readiness_refuses_failed_transfer_with_http_200(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_CURL_EXIT", "28")
    soak, _ = run_host_script(host, "deploy.sh", A, "demo.example.test", "--soak", *[IMAGES["api"]] * 6)
    assert soak.returncode == 0, soak.stderr
    assert soak.stdout.splitlines().count("!readiness") == 6
    activation, trace = run_host_script(host, "deploy.sh", A, "demo.example.test", "--candidate")
    assert activation.returncode != 0 and any(" up " in line for line in trace), activation.stderr
    assert not any("scenario.py seed" in line for line in trace)


@pytest.mark.parametrize("cause", ["lock", "active", "frozen"])
def test_blocked_reset_marks_missed_and_fails(host: Path, monkeypatch: pytest.MonkeyPatch, cause: str) -> None:
    if cause == "lock":
        monkeypatch.setenv("TEST_LOCK_BUSY", "1")
    else:
        (host / "cd" / cause).touch()
    result, trace = run_host_script(host, "reset.sh", inherited=False)
    assert result.returncode == 1 and (host / "cd" / "reset-missed").is_file(), result.stderr
    assert any(line.startswith("sync -f ") and line.endswith("/cd") for line in trace)
    assert not any(line.startswith("docker ") for line in trace)


def test_successful_reset_accepts_inherited_lock_and_publishes_pending(host: Path) -> None:
    missed = host / "cd" / "reset-missed"
    reset_id = "2026-11-22-" + "a" * 32
    missed.write_text(reset_id + "\n", encoding="ascii", newline="\n")
    result, trace = run_host_script(host, "reset.sh")
    assert result.returncode == 0, result.stderr
    assert trace[0] == "flock -n 9"
    assert not missed.exists()
    assert (host / "cd" / "reset-pending").read_text(encoding="ascii").split() == [reset_id, A]
