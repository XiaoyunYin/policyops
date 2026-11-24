#!/usr/bin/python3 -B
"""Root-run PolicyOps demo release controller."""

from __future__ import annotations

import argparse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Literal, TypedDict, cast
from uuid import uuid4


BASE = Path("/var/lib/policyops")
TOOLS = Path("/usr/local/lib/policyops-cd")
REPO = "XiaoyunYin/policyops"
ORIGIN = f"https://github.com/{REPO}.git"
REF = "refs/heads/main"
SHA = re.compile(r"[0-9a-f]{40}")
API_LIMIT = 256 * 1024
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
RUNTIME_SERVICES = ("postgres", "dex", "retail", "caddy", "api", "worker")  # order of deploy.sh's --soak
SCHEMA_JOBS = {"bootstrap-app": "app", "migrate-app": "app", "bootstrap-retail": "retail", "migrate-retail": "retail"}
ONE_SHOTS = {*SCHEMA_JOBS, "seed-demo"}
COMMIT_IMAGES = {"api": "app", "worker": "app", "retail": "retail", "caddy": "web", "seed-demo": "app", **SCHEMA_JOBS}
REQUIRED_COMMIT_IMAGES = ("api", "worker", "retail", "caddy")
HOLD_REASONS = {"non_fast_forward", "schema_change", "tooling"}
BUILD_HELD = 42
RESET = "/usr/local/sbin/policyops-demo-reset"
RESET_ID = re.compile(r"\d{4}-\d{2}-\d{2}(?:-[0-9a-f]{32})?", re.ASCII)
BUILD_BUDGET = 1800
ACTIVATION_BUDGET = 480
GATE_BUDGET = 600
RESET_BUDGET = 900
SCHEMA_PREFIXES = ("packages/policyops/src/policyops/persistence/migrations/", "evals/migrations/retail/")
SCHEMA_FILES = {
    "infra/compose/runtime.py", "infra/compose/postgres.sh",
    "packages/policyops/src/policyops/__init__.py",
    "evals/src/policyops_evals/__init__.py",
    *(f"packages/policyops/src/policyops/persistence/{name}.py"
      for name in ("__init__", "bootstrap", "migrate", "migration_guard", "roles")),
    *(f"evals/src/policyops_evals/retail_sim/{name}.py" for name in ("__init__", "bootstrap", "migrate", "schema")),
}
VERIFY_CHECKS = {
    "https_valid_chain", "health", "http_redirect", "http_banners", "release", "login_session", "seeded_proposal",
    *(f"{page}_{header}" for page in ("root", "api", "dex")
      for header in ("hsts", "csp", "frame", "nosniff", "referrer", "banners")),
    *(f"cookie___Host-policyops_{name}" for name in ("login", "session", "csrf")),
}
Phase = Literal["building", "built", "deploying", "gating", "rolling_back"]
CI = Literal["green", "red", "pending", "api_error"]


class Flight(TypedDict):
    candidate: str
    previous: str
    phase: Phase
    attempt_id: str
    started_at: int
    schema: bool
    rollback_attempts: int
    rollback_in_progress: int
    settle: bool
    forced_stage: str


class State(TypedDict):
    last_healthy: str
    healthy_image_ids: dict[str, str]
    gated_fixture: dict[str, str]
    last_evaluated_tip: str
    ci_green: bool
    in_flight: Flight | None
    last_build_at: int
    build_day: str
    daily_count: int
    build_failures: dict[str, int]
    frozen: bool
    rollbacks: list[int]
    held: str
    held_reasons: list[str]
    released: str
    released_reasons: list[str]
    backoff_until: int


class Stop(Exception):
    """A command or local precondition failed."""


def read_json(path: Path, limit: int = 65536) -> Any:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("oversized file")
    return json.loads(raw)


def sync_dir(path: Path) -> None:
    if sys.platform == "linux":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_json(path: Path, body: object) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write((json.dumps(body, separators=(",", ":")) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            temporary.replace(path)
            sync_dir(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def remove(path: Path) -> None:
    path.unlink(missing_ok=True)
    sync_dir(path.parent)


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def empty_state() -> State:
    return {
        "last_healthy": "", "healthy_image_ids": {}, "gated_fixture": {},
        "last_evaluated_tip": "", "ci_green": False, "in_flight": None,
        "last_build_at": 0, "build_day": "", "daily_count": 0, "build_failures": {},
        "frozen": False, "rollbacks": [], "held": "", "held_reasons": [],
        "released": "", "released_reasons": [], "backoff_until": 0,
    }


def load_state(path: Path) -> State:
    state = read_json(path)
    defaults = empty_state()
    if not isinstance(state, dict):
        raise ValueError("state fields")
    for added in ("healthy_image_ids", "gated_fixture"):
        state.setdefault(added, {})
    for added in ("held_reasons", "released_reasons"):
        state.setdefault(added, [])
    if state.keys() != defaults.keys():
        raise ValueError("state fields")
    for key, default in defaults.items():
        if key != "in_flight" and type(state[key]) is not type(default):
            raise ValueError("state field type")
    if any(state[key] and not valid_sha(state[key]) for key in ("last_healthy", "last_evaluated_tip", "held",
                                                               "released")):
        raise ValueError("state SHA")
    for key in ("held", "released"):
        reasons = state[key + "_reasons"]
        if (any(not isinstance(reason, str) or reason not in HOLD_REASONS for reason in reasons)
                or len(set(reasons)) != len(reasons) or (reasons and not state[key])):
            raise ValueError("hold reasons")
    if (any(type(t) is not int or t < 0 for t in state["rollbacks"])
            or any(not valid_sha(key) or value != 1 for key, value in state["build_failures"].items())
            or min(state["daily_count"], state["last_build_at"], state["backoff_until"]) < 0):
        raise ValueError("state counters")
    images, fixture = state["healthy_image_ids"], state["gated_fixture"]
    if images and (images.keys() != set(RUNTIME_SERVICES) or any(
            not isinstance(image, str) or not IMAGE_ID.fullmatch(image) for image in images.values())):
        raise ValueError("healthy image IDs")
    if fixture and (fixture.keys() != {"release", "seed_path"} or not valid_sha(fixture["release"])
                    or not isinstance(fixture["seed_path"], str) or not Path(fixture["seed_path"]).is_absolute()):
        raise ValueError("gated fixture")
    flight = state["in_flight"]
    if isinstance(flight, dict) and "rollback_in_progress" not in flight:
        # The old format persisted the charged attempt before invoking the restore.
        attempts = flight.get("rollback_attempts")
        if flight.get("phase") == "rolling_back" and type(attempts) is int and 1 <= attempts <= 2:
            flight.update(rollback_attempts=attempts - 1, rollback_in_progress=attempts)
        else:
            flight["rollback_in_progress"] = 0
    if flight is not None and (
        not isinstance(flight, dict) or flight.keys() != Flight.__required_keys__
        or not valid_sha(flight["candidate"]) or flight["previous"] != state["last_healthy"]
        or not valid_sha(flight["previous"])
        or flight["phase"] not in ("building", "built", "deploying", "gating", "rolling_back")
        or not isinstance(flight["attempt_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", flight["attempt_id"])
        or type(flight["started_at"]) is not int or flight["started_at"] < 0
        or type(flight["rollback_attempts"]) is not int or not 0 <= flight["rollback_attempts"] <= 2
        or type(flight["rollback_in_progress"]) is not int
        or (flight["rollback_in_progress"] != 0 and (
            flight["phase"] != "rolling_back" or flight["rollback_attempts"] >= 2
            or flight["rollback_in_progress"] != flight["rollback_attempts"] + 1))
        or any(type(flight[key]) is not bool for key in ("schema", "settle"))
        or flight["forced_stage"] not in ("", "gate", "rollback")
    ):
        raise ValueError("in-flight record")
    return cast(State, state)


def ci_verdict(payload: Any, tip: str, repo_id: int) -> CI:
    if not isinstance(payload, dict) or not isinstance(runs := payload.get("workflow_runs"), list) or len(runs) > 5:
        return "api_error"
    if not runs:
        return "pending"
    for run in runs:
        if not isinstance(run, dict):
            return "api_error"
        if (any(run.get(field) != value for field, value in (
                ("head_sha", tip), ("head_branch", "main"), ("event", "push"), ("path", ".github/workflows/ci.yml")))
                or any(not isinstance(repo := run.get(field), dict) or repo.get("full_name") != REPO
                       or type(repo.get("id")) is not int or repo["id"] != repo_id
                       for field in ("repository", "head_repository"))
                or any(type(run.get(field)) is not int or run[field] < 1 for field in ("run_number", "run_attempt"))
                or run.get("status") not in ("requested", "waiting", "pending", "queued", "in_progress", "completed")
                or "conclusion" not in run or run["conclusion"] not in (
                    None, "success", "failure", "cancelled", "skipped", "neutral", "timed_out",
                    "action_required", "stale", "startup_failure")):
            return "api_error"
    ranks = [(run["run_number"], run["run_attempt"]) for run in runs]
    if len(set(ranks)) != len(ranks):
        return "api_error"
    newest = runs[ranks.index(max(ranks))]
    if newest["status"] != "completed":
        return "pending"
    if not newest["conclusion"]:
        return "api_error"
    return "green" if newest["conclusion"] == "success" else "red"


def retry_time(headers: Mapping[str, str], now: int) -> int:
    retry, reset = headers.get("retry-after", ""), headers.get("x-ratelimit-reset", "")
    until = 0
    if headers.get("x-ratelimit-remaining") == "0" and re.fullmatch(r"[0-9]{1,12}", reset):
        until = int(reset)
    if re.fullmatch(r"[0-9]{1,12}", retry):
        return max(until, now + int(retry))
    if retry:
        with suppress(ValueError, TypeError, OverflowError):
            return max(until, int(parsedate_to_datetime(retry).timestamp()))
    return until


def query_ci(tip: str, repo_id: int) -> tuple[CI, int]:
    """One direct CA-verified request, under the parent's whole-process deadline."""
    query = f"/repos/{REPO}/actions/workflows/ci.yml/runs?branch=main&event=push&head_sha={tip}&per_page=5"
    connection = http.client.HTTPSConnection("api.github.com", timeout=5, context=ssl.create_default_context())
    until = 0
    try:
        headers = {"User-Agent": "policyops-cd", "Accept": "application/vnd.github+json"}
        connection.request("GET", query, headers=headers)
        response = connection.getresponse()
        until = retry_time({key.lower(): value for key, value in response.getheaders()}, int(time.time()))
        if response.status != 200 or response.getheader("Content-Encoding", "identity").lower() != "identity":
            return "api_error", until
        length = response.getheader("Content-Length", "")
        if length and (not re.fullmatch(r"[0-9]{1,9}", length) or int(length) > API_LIMIT):
            return "api_error", until
        body = response.read(API_LIMIT + 1)
        if len(body) <= API_LIMIT and (not length or len(body) == int(length)):
            return ci_verdict(json.loads(body), tip, repo_id), until
    except (OSError, ValueError, http.client.HTTPException, RecursionError):
        pass
    finally:
        connection.close()
    return "api_error", until


def runtime_path(path: str) -> bool:
    return (path == "THIRD_PARTY_NOTICES.md" or not (
        path.startswith(("docs/", "tests/", ".github/", "infra/terraform/"))
        or ("/" not in path and path.endswith(".md"))))


def diff_paths(diff: str) -> list[str]:
    """NUL-separated name-status preserves both paths, including deletions and renames."""
    paths = []
    entries = iter(diff.rstrip("\0").split("\0")) if diff else iter(())
    for status in entries:
        paths.append(next(entries))
        if status.startswith(("R", "C")):
            paths.append(next(entries))
    return paths


def compose_schema(services: dict[str, dict[str, Any]], checkout: Path, release: str) -> tuple[object, ...]:
    root = str(checkout)

    def relative_paths(value: object) -> object:
        if isinstance(value, dict):
            return {key: relative_paths(item) for key, item in value.items()}
        if isinstance(value, list):
            return [relative_paths(item) for item in value]
        if isinstance(value, str) and (value == root or value.startswith(root + "/")):
            return "/<release>" + value[len(root):]
        return value

    jobs = []
    for name, family in SCHEMA_JOBS.items():
        job = dict(services[name])
        # The job's own image and checkout location change for every build.
        if job.get("image") == f"policyops-{family}:{release}":
            job["image"] = f"policyops-{family}:<release>"
        jobs.append(relative_paths(job))
    return services["postgres"]["image"], *jobs


def supported_topology(services: dict[str, dict[str, Any]]) -> bool:
    one_shots = {name for name, service in services.items() if service.get("restart") == "no"}
    return (one_shots == ONE_SHOTS and services.keys() - one_shots == set(RUNTIME_SERVICES)
            and not any(service.get("profiles") for service in services.values()))


def build_issue(services: dict[str, dict[str, Any]], release: str) -> str:
    if not supported_topology(services):
        return "unsupported service topology"
    for name in RUNTIME_SERVICES:
        service = services[name]
        for count in (service.get("scale", 1), (service.get("deploy") or {}).get("replicas", 1)):
            if type(count) is not int or count != 1:
                return f"{name} requires exactly one replica"
    for name, service in services.items():
        build = service.get("build")
        if isinstance(build, dict) and "tags" in build:
            return f"{name} adds build tags"
        image = service.get("image", "")
        expected = f"policyops-{COMMIT_IMAGES[name]}:{release}" if name in COMMIT_IMAGES else ""
        if name in REQUIRED_COMMIT_IMAGES and image != expected:
            return f"{name} requires its commit-specific image"
        if isinstance(image, str) and image.rsplit("/", 1)[-1].startswith("policyops-") and image != expected:
            return f"{name} uses a reserved PolicyOps image name"
    return ""


def hold_reasons(paths: list[str], *, forward: bool) -> list[str]:
    reasons = [] if forward else ["non_fast_forward"]
    if any(path in SCHEMA_FILES or path.startswith(SCHEMA_PREFIXES) for path in paths):
        reasons.append("schema_change")
    if any(path.startswith(("infra/deploy/", "infra/caddy/")) or path == "scripts/deploy_verify.py" for path in paths):
        reasons.append("tooling")
    return reasons


def reset_window(now: float) -> bool:
    stamp = datetime.fromtimestamp(now, UTC)
    return 465 <= stamp.hour * 60 + stamp.minute < 510


def build_blackout(now: float) -> bool:
    stamp = datetime.fromtimestamp(now, UTC)
    seconds = stamp.hour * 3600 + stamp.minute * 60 + stamp.second
    return 465 * 60 - (BUILD_BUDGET + ACTIVATION_BUDGET + GATE_BUDGET) <= seconds < 510 * 60


@contextmanager
def deploy_lock(base: Path) -> Iterator[int]:
    import fcntl

    with (base / "deploy.lock").open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined,unused-ignore]
        yield stream.fileno()


class Agent:
    def __init__(self, base: Path, tooling: Path, lock: int) -> None:
        self.base, self.tooling, self.lock = base, tooling, lock
        self.cd = base / "cd"
        self.mirror = self.cd / "repo.git"
        self.cd.mkdir(mode=0o700, exist_ok=True)
        (self.cd / "quarantine").mkdir(mode=0o700, exist_ok=True)
        self.state_path = self.cd / "state.json"
        self.state = empty_state()
        self.tip = ""
        self.candidate = ""
        self.attempt_id = ""
        self.durations: dict[str, float] = {}
        self.exits: dict[str, int] = {}
        self.checks: dict[str, int] = {}
        self.failed: dict[str, list[str]] = {}
        digest = hashlib.sha256()
        for name in ("policyops-cd", "deploy.sh", "deploy_verify.py"):
            digest.update((tooling / name).read_bytes())
        self.tooling_hash = digest.hexdigest()

    def config(self) -> None:
        config = read_json(self.cd / "config.json")
        self.host, self.repo_id = config["hostname"], config["repo_id"]
        self.build_interval = config.get("min_build_interval_seconds", 10800)
        self.build_limit = config.get("max_builds_per_utc_day", 4)
        self.api_backoff = config.get("api_backoff_seconds", 600)
        if (not isinstance(self.host, str) or self.host != (self.base / "hostname").read_text().strip()
                or len(self.host) > 253
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}", self.host)
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                       for label in self.host.split("."))
                or type(self.repo_id) is not int or self.repo_id < 1
                or type(self.build_interval) is not int or self.build_interval < 10800
                or type(self.build_limit) is not int or not 1 <= self.build_limit <= 4
                or type(self.api_backoff) is not int or self.api_backoff < 60):
            raise ValueError("operator config")

    def audit(self, decision: str, reason: str, *, forced: bool = False, true_result: bool | None = None) -> None:
        log = self.cd / "log.jsonl"
        if log.exists() and log.stat().st_size >= 1024 * 1024:
            log.replace(self.cd / "log.jsonl.1")
            sync_dir(self.cd)
        record = {"at": datetime.now(UTC).isoformat(), "tip": self.tip or None, "candidate": self.candidate or None,
                  "attempt_id": self.attempt_id or None, "decision": decision, "reason": reason,
                  "durations": self.durations, "exit_codes": self.exits, "check_counts": self.checks,
                  "failed_checks": self.failed, "tooling_hash": self.tooling_hash, "forced": forced,
                  "true_result": true_result}
        with log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def save(self) -> None:
        write_json(self.state_path, self.state)

    def freeze(self, reason: str, *, corrupt: bool = False) -> None:
        write_json(self.cd / "frozen", {"reason": reason})
        if not corrupt:
            if flight := self.state["in_flight"]:
                self.quarantine(flight["candidate"], "inconclusive", reason)
            self.state.update({"frozen": True, "in_flight": None})
            self.save()
            remove(self.cd / "active")
        self.audit("FROZEN", reason)

    def quarantine(self, sha: str, outcome: str, reason: str) -> None:
        write_json(self.cd / "quarantine" / f"{sha}.json", {
            "candidate": sha, "outcome": outcome, "reason": reason,
            "attempt_id": self.attempt_id, "at": datetime.now(UTC).isoformat(),
        })

    def command(self, key: str, args: list[str], timeout: float, *, output: bool = False,
                inherited: bool = False, env: dict[str, str] | None = None) -> tuple[int, str]:
        if timeout <= 0:
            self.exits[key] = 124
            self.durations[key] = 0
            return 124, ""
        if inherited:
            args = ["bash", "-c", 'exec 9<&"$1"; shift; exec "$@"', "policyops-cd", str(self.lock), *args]
        start = time.monotonic()
        try:
            with subprocess.Popen(args, stdout=subprocess.PIPE if output else subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, start_new_session=True, env=env,
                                  pass_fds=(self.lock,) if inherited else ()) as child:
                try:
                    raw, _ = child.communicate(timeout=timeout)
                    code = child.returncode
                except subprocess.TimeoutExpired:
                    with suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)  # type: ignore[attr-defined,unused-ignore]
                    child.communicate()
                    raw, code = b"", 124
        except OSError:
            raw, code = b"", 126
        self.exits[key] = code
        self.durations[key] = round(time.monotonic() - start, 3)
        return code, raw.decode("utf-8", errors="surrogateescape") if raw else ""

    def git(self, *args: str) -> str:
        env = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
        code, output = self.command("git_" + args[0], [
            "git", "-c", "http.proxy=", "-c", "http.followRedirects=false", "-c", "http.sslVerify=true",
            "--git-dir", str(self.mirror), *args,
        ], 25, output=True, env=env)
        if code:
            raise Stop("git_unavailable")
        return output

    def remote_tip(self) -> str:
        remote = self.git("ls-remote", ORIGIN, REF).split()
        if len(remote) != 2 or not valid_sha(remote[0]) or remote[1] != REF:
            raise Stop("bad_remote_ref")
        return remote[0]

    def fetch(self) -> str:
        if not self.mirror.exists():
            self.git("init", "--bare", str(self.mirror))
        self.git("fetch", "--no-tags", ORIGIN, f"+{REF}:{REF}")
        return self.git("rev-parse", REF).strip()

    def retain_adopted(self, sha: str) -> None:
        if not self.mirror.exists():
            self.git("init", "--bare", str(self.mirror))
        self.git("fetch", "--no-tags", str(self.base / "releases" / sha), f"+{sha}:refs/policyops/adopted/{sha}")

    def first_parent(self, ancestor: str, tip: str) -> bool:
        if ancestor == tip:
            return True
        return ancestor in self.git("rev-list", "--first-parent", tip).splitlines()

    def binding(self, candidate: str) -> bool:
        self.tip = self.remote_tip()
        return self.tip == candidate or (self.fetch() == self.tip and self.first_parent(candidate, self.tip))

    def ci(self, sha: str) -> tuple[CI, int]:
        code, result = self.command("ci", [sys.executable, "-B", __file__, "_ci", sha, str(self.repo_id)],
                                    12, output=True)
        if code:
            return "api_error", 0
        verdict, until = json.loads(result)
        return verdict, until

    def ci_evidence(self, sha: str) -> str:
        if time.time() < self.state["backoff_until"]:
            return "api_backoff"
        verdict, until = self.ci(sha)
        if verdict == "api_error":
            until = max(until, int(time.time()) + self.api_backoff)
        if until > self.state["backoff_until"]:
            self.state["backoff_until"] = until
            self.save()
        return verdict

    def steal(self) -> float:
        def sample() -> tuple[int, int]:
            ticks = [int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
            return sum(ticks), ticks[7]

        total, stolen = sample()
        time.sleep(3)
        end_total, end_stolen = sample()
        return (end_stolen - stolen) / max(end_total - total, 1)

    def current(self) -> str:
        link = self.base / "current"
        if not link.is_symlink():
            raise Stop("current_missing")
        target = link.resolve(strict=True)
        if target.parent != self.base / "releases" or not valid_sha(target.name):
            raise Stop("current_invalid")
        return target.name

    def project_current(self) -> None:
        target = self.base / "releases" / self.state["last_healthy"]
        if not target.is_dir():
            raise Stop("healthy_checkout_missing")
        temporary = self.base / ".cd-current"
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target)
        temporary.replace(self.base / "current")
        sync_dir(self.base)

    def deploy(self, key: str, args: list[str], timeout: float, *, output: bool = False) -> tuple[int, str]:
        return self.command(key, [str(self.tooling / "deploy.sh"), *args], timeout, output=output, inherited=True)

    def describe(self, release: str, key: str, deadline: float) -> dict[str, dict[str, Any]]:
        code, config = self.deploy(key, [release, self.host, "--describe"],
                                   min(15, deadline - time.monotonic()), output=True)
        try:
            if code:
                raise ValueError
            services = json.loads(config)["services"]
            if not isinstance(services, dict) or any(not isinstance(service, dict) for service in services.values()):
                raise ValueError
        except (ValueError, TypeError, KeyError, RecursionError) as error:
            raise Stop("compose_config_unavailable") from error
        return services

    def image_ids(self, release: str, key: str, deadline: float) -> dict[str, str]:
        services = self.describe(release, key + "_config", deadline)
        images = []
        for service in RUNTIME_SERVICES:
            image = services.get(service, {}).get("image")
            if not isinstance(image, str) or not image:
                raise Stop("release_images_unavailable")
            images.append(image)
        code, output = self.command(key + "_images", ["docker", "image", "inspect", "-f", "{{.Id}}", "--", *images],
                                    min(15, deadline - time.monotonic()), output=True)
        ids = output.splitlines()
        if code or len(ids) != len(images) or any(not IMAGE_ID.fullmatch(image) for image in ids):
            raise Stop("release_images_unavailable")
        return dict(zip(RUNTIME_SERVICES, ids, strict=True))

    def verifier(self, release: str, healthy_app: str, seed: Path, key: str, deadline: float) -> bool:
        with tempfile.TemporaryDirectory(dir=self.cd, prefix="gate-") as scratch:
            root = Path(scratch)
            reports = root / "reports"
            reports.mkdir()
            reports.chmod(0o755)
            folder = reports / "deployment"
            folder.mkdir()
            os.chown(folder, 0, 10001)  # type: ignore[attr-defined,unused-ignore]
            folder.chmod(0o770)
            fixture = root / "seed.json"
            try:
                write_json(fixture, read_json(seed, 4096))
            except (OSError, ValueError, RecursionError):
                self.exits[key], self.durations[key] = 2, 0
                self.failed[key] = ["seeded_proposal"]
                self.checks[key] = 1
                return False
            fixture.chmod(0o444)
            name = "policyops-cd-verify-" + uuid4().hex
            code, _ = self.command(key, [
                "docker", "run", "--name", name, "--rm", "--pull", "never", "--network", "host", "--read-only",
                "--cap-drop", "ALL", "--user", "10001:10001", "--security-opt", "no-new-privileges",
                "--add-host", f"{self.host}:127.0.0.1", "-e", "POLICYOPS_TEMP_DIR=/reports",
                "-v", f"{reports}:/reports", "-v", f"{fixture}:/fixture.json:ro",
                "-v", f"{self.tooling / 'deploy_verify.py'}:/opt/policyops-cd/deploy_verify.py:ro",
                "--entrypoint", "python", healthy_app, "-B",
                "/opt/policyops-cd/deploy_verify.py", self.host, "--local",
                "--expect-release", release, "--seed-json", "/fixture.json",
            ], min(180, deadline - time.monotonic()))
            if code == 124:
                self.command(key + "_cleanup", ["docker", "rm", "-f", name], min(5, deadline - time.monotonic()))
            try:
                report, = folder.glob("verify-*.json")
                if not stat.S_ISREG(report.lstat().st_mode):
                    raise ValueError("verifier report type")
                checks = read_json(report)["checks"]
                known = VERIFY_CHECKS | {"https_auth_sequence"}
                self.checks[key] = len(known.intersection(checks))
                self.failed[key] = sorted(check for check in known if checks.get(check) is False)
                if any(checks.get(check) is not True and check not in self.failed[key] for check in VERIFY_CHECKS):
                    self.failed[key].append("verifier_incomplete")
            except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
                self.failed[key] = ["verifier_report"]
                self.checks[key] = 0
            return code == 0 and not self.failed[key]

    def gate(self, release: str, images: dict[str, str], seed: Path, key: str, deadline: float) -> bool:
        healthy_app = self.state["healthy_image_ids"].get("api", images["api"])
        for attempt in (1, 2):
            stage = f"{key}_verify_{attempt}"
            try:
                if self.verifier(release, healthy_app, seed, stage, deadline):
                    break
            except OSError:
                self.exits.setdefault(stage, 126)
                self.failed[stage] = ["verifier_local_io"]
            if attempt == 2 or deadline - time.monotonic() <= 30:
                return False
            time.sleep(30)
        code, probes = self.deploy(key + "_soak", [release, self.host, "--soak",
                                                 *(images[service] for service in RUNTIME_SERVICES)],
                                   deadline - time.monotonic(), output=True)
        expected = {*RUNTIME_SERVICES, "readiness"}
        lines = probes.splitlines()
        self.checks[key + "_soak"] = len(lines)
        self.failed[key + "_soak"] = sorted({line[1:] for line in lines if line.startswith("!")
                                            and line[1:] in expected})
        if (len(lines) != 6 * len(expected)
                or any({line.lstrip("!") for line in lines[i:i + len(expected)]} != expected
                       for i in range(0, len(lines), len(expected)))):
            self.failed[key + "_soak"].append("soak_incomplete")
        return code == 0 and not self.failed[key + "_soak"]

    def seed(self, release: str) -> Path:
        return self.base / "logs" / f"scenario-{release}.json"

    def record_fixture(self, release: str, seed: Path) -> None:
        self.state["gated_fixture"] = {"release": release, "seed_path": str(seed)}

    def drill(self, candidate: str) -> str:
        instruction = self.cd / "drill.json"
        try:
            metadata = instruction.lstat()
            if not stat.S_ISREG(metadata.st_mode) or (sys.platform == "linux" and (
                    metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077)):
                return ""
            drill = read_json(instruction, 4096)
            expires = datetime.fromisoformat(drill["expires_at"])
            if (not isinstance(drill, dict) or drill.get("candidate") != candidate
                    or drill.get("fail_stage") not in ("gate", "rollback")
                    or expires.tzinfo is None or expires.timestamp() <= time.time()):
                return ""
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            return ""
        return str(drill["fail_stage"])

    def settle(self, deadline: float) -> bool:
        settle_until = min(deadline, time.monotonic() + 90)
        while time.monotonic() < deadline:
            code, output = self.command("settle", [
                "docker", "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.project=policyops-public",
                "--filter", "status=created", "--filter", "status=restarting", "--format", "{{.ID}} {{.State}}",
            ], min(5, deadline - time.monotonic()), output=True)
            stuck = []
            for row in output.splitlines():
                container, _, status = row.partition(" ")
                if not re.fullmatch(r"[0-9a-f]{64}", container) or status not in ("created", "restarting"):
                    return False
                stuck.append(container)
            if code == 0 and not stuck:
                return True
            if time.monotonic() >= settle_until:
                if code or reset_window(time.time()):
                    return False
                # rm -f stops and removes only the full IDs returned for this project.
                code, _ = self.command("settle_remove", ["docker", "rm", "-f", "--", *stuck],
                                       min(30, deadline - time.monotonic()))
                return code == 0
            time.sleep(min(2, max(0, settle_until - time.monotonic())))
        return False

    def rollback(self, flight: Flight) -> None:
        candidate, previous = flight["candidate"], flight["previous"]
        flight["phase"] = "rolling_back"
        self.save()
        while flight["rollback_attempts"] < 2:
            if reset_window(time.time()):
                self.audit("HOLD", "reset_window")
                return
            self.audit("ROLLING_BACK", "restore_last_healthy")
            deadline = time.monotonic() + 720
            settle = flight["settle"]
            attempt = flight["rollback_in_progress"] or flight["rollback_attempts"] + 1
            flight["rollback_in_progress"] = attempt
            flight["settle"] = True  # on a crash, check the daemon before the next attempt
            self.save()
            key = f"rollback_{attempt}"
            passed = False
            settled = not settle or self.settle(deadline)
            if reset_window(time.time()):
                self.audit("HOLD", "reset_window")
                return
            seed = self.seed(previous)
            if settled:
                images = self.state["healthy_image_ids"]
                code, _ = self.deploy(key, [previous, self.host, "--rollback",
                                           *(images[service] for service in RUNTIME_SERVICES)],
                                      deadline - time.monotonic())
                passed = code == 0 and self.gate(previous, images, seed, key,
                                                min(deadline, time.monotonic() + GATE_BUDGET))
                flight["settle"] = code == 124
            forced = flight["forced_stage"] == "rollback" and attempt == 1
            self.audit("ROLLING_BACK", "rollback_verdict", forced=forced, true_result=passed)
            if passed and not forced:
                now = int(time.time())
                self.quarantine(candidate, "rolled_back", "candidate_failed")
                self.state["rollbacks"] = [t for t in self.state["rollbacks"] if now - t < 86400] + [now]
                self.record_fixture(previous, seed)
                self.state["in_flight"] = None
                if len(self.state["rollbacks"]) >= 3:
                    self.freeze("rollback_circuit_breaker")
                else:
                    self.save()
                    remove(self.cd / "active")
                    self.audit("ROLLED_BACK", "restored_last_healthy")
                return
            flight.update({"rollback_attempts": attempt, "rollback_in_progress": 0})
            self.save()
        self.freeze("rollback_failed")

    def check_candidate(self, flight: Flight) -> None:
        candidate = flight["candidate"]
        started = time.monotonic()
        seed = self.seed(candidate)
        try:
            images = self.image_ids(candidate, "gate", started + GATE_BUDGET)
        except Stop as error:
            self.failed["gate_images"] = [str(error)]
            images = {}
        passed = bool(images) and self.gate(candidate, images, seed, "gate", started + GATE_BUDGET)
        self.durations["gate"] = round(time.monotonic() - started, 3)
        drill = self.drill(candidate)
        if drill and not flight["forced_stage"]:
            flight["forced_stage"] = drill
            # A crash between persistence and consumption re-enters the forced gate.
            self.save()
        if drill and flight["forced_stage"] == drill:
            remove(self.cd / "drill.json")
        drill = flight["forced_stage"]
        self.audit("GATING", "gate_verdict", forced=bool(drill), true_result=passed)
        if passed and not drill:
            if reset_window(time.time()):
                self.audit("HOLD", "reset_window")
                return
            self.state.update({"last_healthy": candidate, "healthy_image_ids": images, "in_flight": None,
                               "released": "", "released_reasons": [], "held": "", "held_reasons": []})
            self.record_fixture(candidate, seed)
            self.save()
            self.project_current()
            remove(self.cd / "active")
            self.audit("PROMOTED", "gate_passed")
        elif flight["schema"]:
            self.freeze("schema_gate_failed")
        else:
            self.rollback(flight)

    def schema_changed(self, previous: str, candidate: str, config: dict[str, dict[str, Any]],
                       deadline: float) -> bool:
        baseline = self.describe(previous, "baseline_config", deadline)
        releases = self.base / "releases"
        return compose_schema(baseline, releases / previous, previous) != compose_schema(
            config, releases / candidate, candidate)

    def unapproved(self, sha: str, reasons: list[str]) -> list[str]:
        approved = self.state["released_reasons"] if self.state["released"] == sha else []
        return [reason for reason in reasons if reason not in approved]

    def activate(self, flight: Flight) -> None:
        candidate, previous = flight["candidate"], flight["previous"]
        if reset_window(time.time()):
            self.audit("HOLD", "reset_window")
            return
        if shutil.disk_usage(self.base.parent).free < 8 * 1024**3:
            self.audit("HOLD", "disk_low")
            return
        deadline = time.monotonic() + 30
        try:
            config = self.describe(candidate, "candidate_config", deadline)
        except Stop:
            self.hold_built(candidate, "tooling")
            return
        if build_issue(config, candidate):
            self.hold_built(candidate, "tooling")
            return
        flight["schema"] = flight["schema"] or self.schema_changed(previous, candidate, config, deadline)
        if flight["schema"] and self.unapproved(candidate, ["schema_change"]):
            self.hold_built(candidate, "schema_change")
            return
        if not self.binding(candidate):
            self.state["in_flight"] = None
            self.save()
            remove(self.cd / "active")
            self.audit("NOOP", "candidate_off_first_parent")
            return
        verdict = self.ci_evidence(candidate)
        if verdict != "green":
            self.state.update({"in_flight": None, "last_evaluated_tip": "", "ci_green": False})
            self.save()
            self.audit("WAIT_CI", verdict)
            return
        if reset_window(time.time()):
            self.audit("HOLD", "reset_window")
            return
        flight["phase"] = "deploying"
        self.save()
        self.mark_active(flight)
        self.audit("DEPLOYING", "candidate_activation")
        mode = ["--candidate", "--allow-schema"] if flight["schema"] else ["--candidate"]
        code, _ = self.deploy("deploy", [candidate, self.host, *mode], ACTIVATION_BUDGET)
        if code:
            if flight["schema"]:
                self.freeze("schema_activation_failed")
            else:
                flight["settle"] = code == 124
                self.rollback(flight)
        else:
            flight["phase"] = "gating"
            self.save()
            self.audit("GATING", "candidate_checks")
            self.check_candidate(flight)

    def build_failed(self, flight: Flight, reason: str) -> None:
        candidate = flight["candidate"]
        if self.state["build_failures"].pop(candidate, 0):
            self.quarantine(candidate, "build_failed", reason)
            self.audit("QUARANTINED", reason)
        else:
            self.state["build_failures"][candidate] = 1
            self.audit("BUILDING", reason)
        self.state["in_flight"] = None
        self.save()

    def resume(self, flight: Flight) -> None:
        self.candidate, self.attempt_id = flight["candidate"], flight["attempt_id"]
        match flight["phase"]:
            case "building":
                self.build_failed(flight, "build_interrupted")
            case "built":
                self.activate(flight)
            case "deploying" if flight["schema"]:
                self.freeze("schema_activation_interrupted")
            case "deploying":
                flight["settle"] = True
                self.rollback(flight)
            case "gating":
                self.check_candidate(flight)
            case "rolling_back":
                self.rollback(flight)

    def mark_active(self, flight: Flight) -> None:
        write_json(self.cd / "active", {"attempt_id": flight["attempt_id"]})

    def start(self, sha: str, schema: bool) -> None:
        self.audit("PRECHECK", "eligible_tip")
        now = int(time.time())
        day = datetime.fromtimestamp(now, UTC).date().isoformat()
        count = self.state["daily_count"] if day == self.state["build_day"] else 0
        if build_blackout(now):
            self.audit("HOLD", "reset_window")
        elif shutil.disk_usage(self.base.parent).free < 8 * 1024**3:
            self.audit("HOLD", "disk_low")
        elif now - self.state["last_build_at"] < self.build_interval or count >= self.build_limit:
            self.audit("HOLD", "build_budget")
        elif self.steal() > 0.20:
            self.audit("HOLD", "cpu_steal")
        elif not self.binding(sha):
            self.audit("NOOP", "candidate_off_first_parent")
        elif build_blackout(time.time()):
            self.audit("HOLD", "reset_window")
        else:
            deadline = time.monotonic() + 45
            code, _ = self.deploy("checkout", ["--checkout-only", sha], 15)
            if code:
                raise Stop("checkout_failed")
            try:
                config = self.describe(sha, "candidate_config", deadline)
            except Stop:
                self.hold(sha, ["tooling"])
                return
            if build_issue(config, sha):
                self.hold(sha, ["tooling"])
                return
            previous = self.state["last_healthy"]
            schema = schema or self.schema_changed(previous, sha, config, deadline)
            if schema and self.unapproved(sha, ["schema_change"]):
                self.hold(sha, ["schema_change"])
                return
            if build_blackout(time.time()):
                self.audit("HOLD", "reset_window")
                return
            self.attempt_id = uuid4().hex
            started = int(time.time())
            day = datetime.fromtimestamp(started, UTC).date().isoformat()
            count = self.state["daily_count"] if day == self.state["build_day"] else 0
            flight: Flight = {"candidate": sha, "previous": self.state["last_healthy"], "phase": "building",
                              "attempt_id": self.attempt_id, "started_at": started, "schema": schema,
                              "rollback_attempts": 0, "rollback_in_progress": 0, "settle": False, "forced_stage": ""}
            self.state.update({"in_flight": flight, "last_build_at": flight["started_at"], "build_day": day,
                               "daily_count": count + 1})
            self.save()
            self.audit("BUILDING", "build_started")
            code, _ = self.deploy("build", ["--build-only", sha], BUILD_BUDGET)
            if code == BUILD_HELD:
                self.state["in_flight"] = None
                self.hold(sha, ["tooling"])
            elif code:
                self.build_failed(flight, "build_failed")
            else:
                self.state["build_failures"].pop(sha, None)
                flight["phase"] = "built"
                self.save()
                if not self.process_reset(flight["previous"]):
                    self.activate(flight)

    def hold(self, sha: str, reasons: list[str]) -> None:
        self.state.update({"held": sha, "held_reasons": reasons})
        self.save()
        self.audit("HOLD", ", ".join(reasons))

    def hold_built(self, sha: str, reason: str) -> None:
        self.tip = self.remote_tip()
        if self.tip == sha:
            self.hold(sha, [reason])
        else:
            self.state.update({"in_flight": None, "held": "", "held_reasons": [],
                               "released": "", "released_reasons": []})
            self.save()
            self.audit("NOOP", "held_tip_superseded")

    def discover(self) -> None:
        self.tip = self.candidate = self.remote_tip()
        sha, healthy = self.tip, self.state["last_healthy"]
        self.audit("DISCOVER", "main_tip")
        if sha == healthy or (self.cd / "quarantine" / f"{sha}.json").exists():
            self.audit("NOOP", "already_healthy" if sha == healthy else "quarantined")
            return
        if sha != self.state["last_evaluated_tip"] or not self.state["ci_green"]:
            verdict = self.ci_evidence(sha)
            if verdict not in ("green", "red"):
                self.audit("WAIT_CI", verdict)
                return
            self.state.update({"last_evaluated_tip": sha, "ci_green": verdict == "green"})
            self.save()
            if verdict == "red":
                self.audit("WAIT_CI", "ci_not_successful")
                return
        if self.fetch() != sha:
            self.audit("NOOP", "tip_moved")
            return
        paths = diff_paths(self.git("diff", "--name-status", "-z", "--find-renames", f"{healthy}..{sha}"))
        reasons = hold_reasons(paths, forward=self.first_parent(healthy, sha))
        remaining = self.unapproved(sha, reasons)
        if remaining:
            self.hold(sha, remaining)
        elif not any(map(runtime_path, paths)):
            self.audit("SKIP", "skipped_non_runtime")
        else:
            self.start(sha, "schema_change" in reasons)

    def pending_reset(self) -> tuple[str, str]:
        record = (self.cd / "reset-pending").read_text().split()
        if len(record) == 1 and valid_sha(record[0]):
            return "", record[0]  # Round 2 stored only the release.
        if len(record) != 2 or not RESET_ID.fullmatch(record[0]) or not valid_sha(record[1]):
            raise ValueError("invalid reset-pending")
        return record[0], record[1]

    def clear_reset_pending(self, reset_id: str, release: str) -> None:
        progress = self.cd / "reset-progress"
        if progress.exists() and progress.read_text().split() == [reset_id, release, "seeded"]:
            remove(progress)
        remove(self.cd / "reset-pending")

    def reset_requested(self) -> bool:
        if (self.cd / "reset-progress").exists():
            return True
        missed = self.cd / "reset-missed"
        if not missed.exists():
            return False
        reset_id = missed.read_text().strip()
        if reset_id and not RESET_ID.fullmatch(reset_id):
            raise ValueError("invalid reset-missed")
        return not (self.cd / "reset-completed" / reset_id).is_file()

    def process_reset(self, healthy: str) -> bool:
        pending = self.cd / "reset-pending"
        if not pending.exists() and self.reset_requested():
            code, _ = self.command("reset", [RESET, "--resume"], RESET_BUDGET, inherited=True)
            if code or not pending.exists():
                self.audit("IDLE", "missed_reset_failed")
                return True
        if not pending.exists():
            return False
        self.candidate = healthy
        seed = self.base / "logs" / "scenario-nightly.json"
        reset_id, release = self.pending_reset()
        if release == healthy and self.gate(
                healthy, self.state["healthy_image_ids"], seed, "post_reset", time.monotonic() + GATE_BUDGET):
            self.record_fixture(healthy, seed)
            self.save()
            self.clear_reset_pending(reset_id, release)
            self.audit("IDLE", "post_reset_gate_passed")
        else:
            self.freeze("post_reset_gate")
        return True

    def tick(self) -> None:
        if self.state["frozen"]:
            self.audit("FROZEN", "operator_required")
            return
        if (self.cd / "frozen").exists():
            self.freeze("freeze_interrupted")
            return
        flight = self.state["in_flight"]
        active = self.cd / "active"
        if flight and flight["phase"] not in ("building", "built"):
            if not self.state["healthy_image_ids"]:
                self.freeze("healthy_images_missing")
                return
            if not active.exists():
                self.mark_active(flight)
            self.resume(flight)
            return
        if flight and active.exists():
            remove(active)
        healthy = self.state["last_healthy"]
        if not healthy:
            self.audit("IDLE", "adopt_required")
            return
        if active.exists():
            self.project_current()
            remove(active)
        if self.current() != healthy:
            self.freeze("current_changed")
            return
        if not self.state["healthy_image_ids"]:
            if flight:
                self.state["in_flight"] = None
                self.save()
            self.audit("HOLD", "adopt_required_images")
            return
        if not self.process_reset(healthy):
            if flight:
                self.resume(flight)
            else:
                self.discover()

    def operator(self, action: str, sha: str) -> int:
        if action == "release":
            self.candidate = sha
            reasons = self.state["held_reasons"]
            if (self.state["held"] != sha or not reasons or self.state["last_evaluated_tip"] != sha
                    or not self.state["ci_green"]
                    or (self.cd / "quarantine" / f"{sha}.json").exists()):
                raise Stop("release_requires_held_tip")
            approved = self.state["released_reasons"] if self.state["released"] == sha else []
            self.state.update({"released": sha, "released_reasons": sorted(set(approved + reasons))})
            self.save()
            self.audit("HOLD", "operator_released")
            print(f"Released {sha} for {', '.join(reasons)}")
        elif action == "cancel":
            flight = self.state["in_flight"]
            if not flight or flight["phase"] not in ("building", "built") or (self.cd / "active").exists():
                raise Stop("cancel_requires_inactive_pre_cutover_attempt")
            self.candidate, self.attempt_id = flight["candidate"], flight["attempt_id"]
            self.state["in_flight"] = None
            self.save()
            self.audit("CANCELLED", "operator_cancelled")
        elif action == "unfreeze":
            if self.state["in_flight"]:
                if not (self.cd / "frozen").exists():
                    raise Stop("attempt_in_progress")
                self.freeze("freeze_interrupted")
            self.state["frozen"] = False
            self.save()
            remove(self.cd / "frozen")
            self.audit("IDLE", "operator_unfroze")
        else:
            if (self.cd / "reset-progress").exists():
                raise Stop("reset_in_progress")
            if self.state["in_flight"]:
                raise Stop("attempt_in_progress")
            sha = self.candidate = self.current()
            fixture = self.state["gated_fixture"]
            seed = Path(fixture["seed_path"]) if fixture.get("release") == sha else self.seed(sha)
            reset = self.cd / "reset-pending"
            reset_record = self.pending_reset() if reset.exists() else None
            if reset_record and reset_record[1] == sha:
                seed = self.base / "logs" / "scenario-nightly.json"
            deadline = time.monotonic() + GATE_BUDGET
            images = self.image_ids(sha, "adopt", deadline)
            if not self.gate(sha, images, seed, "adopt", deadline):
                raise Stop("adopt_gate_failed")
            self.retain_adopted(sha)
            self.state.update({"last_healthy": sha, "healthy_image_ids": images, "last_evaluated_tip": "",
                               "ci_green": False, "held": "", "held_reasons": [],
                               "released": "", "released_reasons": []})
            self.record_fixture(sha, seed)
            self.save()
            if reset_record:
                self.clear_reset_pending(*reset_record)
            self.audit("PROMOTED", "operator_adopted")
        return 0


def supported_host() -> bool:
    return sys.platform == "linux" and os.geteuid() == 0


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) == 3 and arguments[0] == "_ci" and valid_sha(arguments[1]):
        print(json.dumps(query_ci(arguments[1], int(arguments[2]))))
        return 0
    if len(arguments) == 2 and arguments[0] == "_check-build" and valid_sha(arguments[1]):
        issue = build_issue(json.load(sys.stdin)["services"], arguments[1])
        if issue:
            print(issue, file=sys.stderr)
            return BUILD_HELD
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("tick", "adopt", "release", "unfreeze", "cancel"))
    parser.add_argument("sha", nargs="?", default="")
    args = parser.parse_args(arguments)
    if (args.action == "release" and not valid_sha(args.sha)) or (args.action != "release" and args.sha):
        parser.error("release takes one full commit SHA")
    if not supported_host():
        parser.error("requires Linux and root")
    os.umask(0o077)
    try:
        with deploy_lock(BASE) as fd:
            agent = Agent(BASE, TOOLS, fd)
            try:
                agent.state = load_state(agent.state_path)
            except FileNotFoundError:
                if (args.action not in ("tick", "adopt")
                        or any((agent.cd / name).exists() for name in ("active", "enabled"))):
                    agent.freeze("state_missing", corrupt=True)
                    return 1
            except (OSError, ValueError, RecursionError):
                agent.freeze("state_invalid", corrupt=True)
                return 1
            try:
                agent.config()
                if args.action != "tick":
                    return agent.operator(args.action, args.sha)
                agent.tick()
            except Stop as error:
                agent.audit("HOLD", str(error))
                if args.action != "tick":
                    print(f"policyops-cd: {error}", file=sys.stderr)
                return 1 if args.action != "tick" else 0
            except (OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError):
                agent.audit("HOLD", "local_error")
                return 1
    except BlockingIOError:
        return 0 if args.action == "tick" else 1
    except OSError:
        print("policyops-cd: could not open host state or installed tooling", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
