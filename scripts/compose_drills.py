"""Operator-run real-browser recovery drills. Never run against an existing/demo project.

Builds a uniquely owned disposable Compose project, exercises browser authority, kills at the after-response seam,
then restores one coherent logical backup to a fresh separate database. Always attempts guarded cleanup.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any
from uuid import UUID


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.compose_smoke import ROOT, Driver, SmokeError, check_ownership, require


LIMITATIONS = [
    "single host / Docker Desktop Linux amd64",
    "logical full-database backup only; no PITR or WAL replay",
    "same-cluster separate database, not a separate host/cluster or disaster recovery",
    "fictional simulator and one coherent ledger/sink recovery point; no real commerce rollback",
    "after-response kill, not every crash window; no previous-image/schema rollback or non-loopback TLS",
]
CONSENT_TAG = "@t38-consent-drill"
CONSENT_GREP = r"(?:^|\s)@t38-consent-drill(?:\s|$)"
PINNED_NODE = "v26.13.0"


def selected_consent_test(raw: str) -> str:
    """Validate Playwright's real --list JSON, including project-expanded tests, before browser launch."""
    report = parse_object(raw)
    require(not report.get("errors"), "Playwright collection reported errors")
    selected = []

    def visit(suites: list[dict[str, Any]]) -> None:
        for suite in suites:
            for spec in suite.get("specs", []):
                for _test in spec.get("tests", []):
                    selected.append(spec)
            visit(suite.get("suites", []))

    visit(report.get("suites", []))
    require(len(selected) == 1, "drill must collect exactly one browser test")
    # Playwright 1.64.1 JSON reporter drops the leading @ from spec.tags.
    require(CONSENT_TAG.removeprefix("@") in selected[0].get("tags", []),
            "drill selected a test without the exact consent tag")
    title: str = selected[0]["title"]
    return title


def identifier(value: str) -> str:
    require(re.fullmatch(r"policyops_restore_[a-f0-9]{12}", value) is not None, "unsafe restore database name")
    return value


def parse_object(raw: str) -> dict[str, Any]:
    require(len(raw) <= 1024 * 1024, "driver JSON exceeds bound")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        require(len({key for key, _ in items}) == len(items), "duplicate JSON key")
        return dict(items)

    def constant(_value: str) -> Any:
        raise SmokeError("nonfinite JSON value")

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as error:
        raise SmokeError("invalid driver JSON") from error
    require(isinstance(result, dict), "driver expected a JSON object")
    return result  # type: ignore[no-any-return]


def execution(state: dict[str, Any], run_id: str) -> dict[str, Any]:
    matches = [row for row in state["executions"] if row["run_id"] == run_id]
    require(len(matches) == 1, "expected exactly one execution for the run")
    row: dict[str, Any] = matches[0]
    UUID(row["operation_id"])
    return row


def assert_recovered(before: dict[str, Any], after: dict[str, Any], run_id: str) -> dict[str, Any]:
    old, new = execution(before, run_id), execution(after, run_id)
    require(
        old["state"] == "dispatched"
        and old["receipt_sha256"] is None
        and re.fullmatch(r"[a-f0-9]{64}", old["remote_receipt_sha256"] or "") is not None,
        "kill point did not have a committed remote receipt and unresolved local execution",
    )
    require(
        new["state"] == "succeeded"
        and new["resolved_by"] == "lookup"
        and new["attempts"] == old["attempts"] == 1
        and new["operation_id"] == old["operation_id"]
        and new["receipt_sha256"] == new["remote_receipt_sha256"] == old["remote_receipt_sha256"],
        "recovery did not retain the original receipt by lookup without a resend",
    )
    require(after["case_version"] == before["case_version"], "recovery added a simulator effect")
    require(after["pending_outcomes"] == 0, "restored outcome projection remains pending")
    return new


class Drills(Driver):
    def __init__(self, root: Path, port: int) -> None:
        super().__init__(root, port)
        self.project = "policyops-t38b-" + self.run_id
        self.database = identifier("policyops_restore_" + self.run_id)
        self.report.update(project=self.project, limitations=LIMITATIONS)
        # The driver permits only these explicit, owned browser/test outputs; never uses parent client temp.
        self.env.update(
            COMPOSE_PROJECT_NAME=self.project,
            POLICYOPS_PYTHON=os.environ.get("POLICYOPS_PYTHON", sys.executable),
            POLICYOPS_E2E_ORIGIN=f"http://127.0.0.1:{port}",
            PLAYWRIGHT_BROWSERS_PATH=os.environ.get(
                "PLAYWRIGHT_BROWSERS_PATH", str(root / "tools/playwright-browsers")
            ),
            NODE_COMPILE_CACHE=str(self.root / "tmp/node"),
            npm_config_cache=str(self.root / "tmp/npm"),
        )
        self.env["POLICYOPS_E2E_APPROVE_ONLY"] = "1"
        self.override = self.root / "pause-worker.json"
        self.override.write_text(
            json.dumps(
                {
                    "services": {
                        "worker": {
                            "entrypoint": ["python", "-B", "infra/compose/drill_worker.py"],
                            "command": [],
                            "environment": {"POLICYOPS_COMPOSE_DRILL": "1"},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

    def helper(self, service: str, script: str, mode: str, *args: str) -> dict[str, Any]:
        return parse_object(
            self.compose(
                "run", "--rm", "--no-deps", "--entrypoint", "python", service, "-B", f"infra/compose/{script}.py", mode,
                *args,
            )
        )

    def inspect(self, case_id: str) -> dict[str, Any]:
        return self.helper("worker", "scenario", "inspect", "--case-id", str(UUID(case_id)))

    def worker_container(self) -> dict[str, Any]:
        items = self.containers()
        check_ownership(items, self.project, self.run_id, container=True)
        workers = [
            item
            for item in items
            if item["Config"]["Labels"]["com.docker.compose.service"] == "worker"
            and item["Config"]["Labels"].get("com.docker.compose.oneoff", "false").lower() == "false"
        ]
        require(len(workers) == 1, "worker identity is uncertain")
        return workers[0]

    def arm(self) -> None:
        self.compose("stop", "worker")
        self.compose("--file", str(self.override), "up", "-d", "--no-deps", "--force-recreate", "worker")

    def browser_approve(self, label: str) -> dict[str, Any]:
        manifest = self.root / f"{label}-scenario.json"
        self.env.update(POLICYOPS_E2E_RUN=self.run_id + "-" + label, POLICYOPS_E2E_MANIFEST=str(manifest))
        self.report.setdefault("browser_runs", []).append(
            {
                "label": label,
                "output": str(Path(self.env["POLICYOPS_TEMP_DIR"]) / "tests/T38b" / (self.run_id + "-" + label)),
            }
        )
        node = shutil.which("node")
        require(node is not None, "pinned Node must be on PATH")
        require(self.command(node or "node", "--version") == PINNED_NODE, f"drills require Node {PINNED_NODE}")
        command = (
            node or "node",
            str(ROOT / "apps/web/node_modules/@playwright/test/cli.js"),
            "test",
            "--config",
            str(ROOT / "apps/web/playwright.config.ts"),
            "--grep",
            CONSENT_GREP,
        )
        title = selected_consent_test(self.command(*command, "--list", "--reporter=json", timeout=60))
        self.report["browser_runs"][-1].update(node=node, node_version=PINNED_NODE, collected=1, title=title)
        self.command(*command, timeout=180)
        scenario = parse_object(manifest.read_text(encoding="utf-8"))
        for name in ("case_id", "run_id", "proposal_id"):
            UUID(scenario[name])
        return scenario

    def kill_after_commit(self, scenario: dict[str, Any]) -> dict[str, Any]:
        container = self.worker_container()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            state = self.inspect(scenario["case_id"])
            rows = [row for row in state["executions"] if row["run_id"] == scenario["run_id"]]
            if rows and rows[0]["remote_receipt_sha256"] is not None:
                marker = parse_object(
                    self.command(
                        "docker",
                        "exec",
                        container["Id"],
                        "python",
                        "-B",
                        "-c",
                        "from pathlib import Path; p=Path('/tmp/t38-after-response.json'); "
                        "print(p.read_text() if p.is_file() else '{}')",
                    )
                )
                if not marker:
                    time.sleep(0.1)
                    continue
                require(marker["operation_id"] == rows[0]["operation_id"], "pause marker operation differs")
                require(
                    state["case_version"] == scenario["case_version_before"] + 1,
                    "dispatch did not commit exactly one simulator effect",
                )
                self.command("docker", "kill", "--signal", "KILL", container["Id"])
                killed = self.worker_container()
                require(
                    killed["Id"] == container["Id"] and killed["State"]["Status"] == "exited",
                    "worker kill was not observed",
                )
                stopped = self.inspect(scenario["case_id"])
                old = execution(stopped, scenario["run_id"])
                require(
                    old["state"] == "dispatched" and old["receipt_sha256"] is None,
                    "missed before-local-receipt kill point",
                )
                return stopped
            time.sleep(1)
        raise SmokeError("worker did not reach after-response pause")

    def recover(self, before: dict[str, Any], run_id: str, case_id: str) -> dict[str, Any]:
        self.compose("up", "-d", "--no-deps", "--force-recreate", "worker")
        deadline = time.monotonic() + 160  # actual production lease expires; no clock/row rewriting
        while time.monotonic() < deadline:
            after = self.inspect(case_id)
            if execution(after, run_id)["state"] == "succeeded" and after["pending_outcomes"] == 0:
                assert_recovered(before, after, run_id)
                return after
            time.sleep(2)
        raise SmokeError("ordinary worker did not reconcile by the recovery deadline")

    def backup_restore(self, prior: dict[str, Any]) -> None:
        self.arm()
        scenario = self.browser_approve("restore")
        unresolved = self.kill_after_commit(scenario)
        completed = self.inspect(prior["case_id"])
        require(execution(completed, prior["run_id"])["state"] == "succeeded", "prior case is not complete")
        self.compose("stop", "worker", "api", "retail")
        original = self.helper("bootstrap-app", "recovery", "snapshot")
        self.report["assertions"]["backup_snapshot"] = original
        pg = self.compose("ps", "-q", "postgres")
        containers = self.containers()
        check_ownership(containers, self.project, self.run_id, container=True)
        require(
            any(
                item["Id"] == pg and item["Config"]["Labels"]["com.docker.compose.service"] == "postgres"
                for item in containers
            ),
            "backup container identity uncertain",
        )
        path = "/tmp/policyops-drill.dump"  # noqa: S108 - exact path in owned, private postgres tmpfs
        dump = self.root / "coherent.dump"
        self.compose("exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "policyops", "-Fc", "-f", path)
        # `docker cp` cannot read the container's tmpfs /tmp; stream the exact bytes instead and cross-check the hash.
        copied = subprocess.run(["docker", "exec", pg, "cat", path], capture_output=True, timeout=300, check=False)
        require(copied.returncode == 0 and bool(copied.stdout), "backup copy from the postgres container failed")
        dump.write_bytes(copied.stdout)
        inside = self.compose("exec", "-T", "postgres", "sha256sum", path).split()[0]
        require(inside == hashlib.sha256(copied.stdout).hexdigest(), "backup copy hash differs from the container file")
        self.report["backup"] = {
            "path": str(dump),
            "sha256": inside,
            "database": "policyops",
            "target": self.database,
            "format": "pg_dump custom",
        }
        self.compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-X",
            "-U",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            "postgres",
            "-c",
            f"CREATE DATABASE {self.database} OWNER policyops_app_migrator TEMPLATE template0",
        )
        self.compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-X",
            "-U",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            "postgres",
            "-c",
            f"REVOKE ALL ON DATABASE {self.database} FROM PUBLIC; GRANT CONNECT ON DATABASE {self.database} "
            "TO policyops_app_runtime,policyops_auth_runtime,policyops_eval_runtime,policyops_worker_discovery,"
            "retail_migrator,retail_runtime",
        )
        self.compose(
            "exec", "-T", "postgres", "pg_restore", "-U", "postgres", "--exit-on-error", "-d", self.database, path
        )
        self.compose("exec", "-T", "postgres", "rm", path)
        self.env["POLICYOPS_DATABASE"] = self.database
        restored = self.helper("bootstrap-app", "recovery", "snapshot")
        require(restored == original, "restored approvals/jobs/receipts/state/owners/grants/RLS differ")
        self.report["assertions"]["restored_snapshot_exact"] = True
        self.report["assertions"]["restored_migrations"] = self.verify("bootstrap-app", "migrations", oneshot=True)
        self.report["assertions"]["restored_runtime_roles"] = {
            service: self.verify(service, service, oneshot=True) for service in ("api", "worker", "retail")
        }
        self.report["assertions"]["restored_rls"] = {
            service: self.helper(service, "recovery", service, "--case-id", scenario["case_id"])
            for service in ("worker", "retail")
        }
        self.compose("up", "-d", "--no-deps", "--force-recreate", "retail", "api")
        self.wait_ready()
        before = self.inspect(scenario["case_id"])
        require(before == unresolved, "restored operation/receipt identity differs before recovery")
        recovered = self.recover(before, scenario["run_id"], scenario["case_id"])
        require(self.inspect(prior["case_id"]) == completed, "prior completed case changed after restore")
        # Let the ordinary scheduler pass again: completion must remain stable.
        time.sleep(3)
        require(self.inspect(scenario["case_id"]) == recovered
                and self.inspect(prior["case_id"]) == completed, "completed operations changed on another worker pass")
        self.report["assertions"]["restored_unresolved_lookup"] = assert_recovered(
            before, recovered, scenario["run_id"]
        )
        self.report["assertions"]["completed_not_reexecuted"] = True
        self.compose("stop", "worker", "api", "retail")
        self.env.pop("POLICYOPS_DATABASE")
        require(
            self.helper("bootstrap-app", "recovery", "snapshot") == original, "source database changed after cutover"
        )
        self.report["assertions"]["source_unchanged"] = True

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                if self.request_ready()[0] == 200:
                    return
            except (OSError, ValueError):
                # While the API is recreated, Caddy can answer 502 with a non-JSON body: not ready yet.
                pass
            time.sleep(1)
        raise SmokeError("restored services did not become ready")

    def run(self) -> None:
        require(
            not self.containers() and not self.resources("volume") and not self.resources("network"),
            "project identity already exists",
        )
        self.command(self.env["POLICYOPS_PYTHON"], "-B", str(ROOT / "scripts/compose_secrets.py"))
        self.command(sys.executable, "-B", str(ROOT / "scripts/check_build_context.py"), "--context", str(ROOT))
        self.compose("build", timeout=1800)
        self.compose("up", "-d", timeout=300)
        self.wait()
        self.arm()
        scenario = self.browser_approve("kill")
        before = self.kill_after_commit(scenario)
        self.report["assertions"]["kill_before_local_receipt"] = before
        after = self.recover(before, scenario["run_id"], scenario["case_id"])
        self.report["assertions"]["kill_restart_lookup"] = assert_recovered(before, after, scenario["run_id"])
        self.backup_restore(scenario)
        self.report["passed"] = True

    def cleanup(self) -> None:
        # Inventory only driver-owned nested caches. Parent client runtime and all other runs remain outside.
        target = self.root / "tmp"
        require(
            target.resolve().parent == self.root.resolve() and not target.is_symlink() and not target.is_junction(),
            "driver tmp escapes owned root",
        )
        inventory = sorted(target.rglob("*"), key=lambda path: len(path.parts), reverse=True)
        require(
            all(
                target.resolve() in path.resolve().parents and not path.is_symlink() and not path.is_junction()
                for path in inventory
            ),
            "linked/foreign driver cache; cleanup refused",
        )
        self.report["cleanup"]["tool_inventory"] = [str(path.relative_to(self.root)) for path in inventory]
        for path in inventory:
            path.rmdir() if path.is_dir() else path.unlink()
        super().cleanup()
        if self.override.exists():
            require(not self.override.is_symlink() and not self.override.is_junction(), "override is linked")
            self.override.unlink()
        self.report["cleanup"]["retained"] = (
            "report, scenario IDs, coherent dump (private), sanitized browser traces, run-tagged images"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "")
    root = Path(raw).resolve()
    if not raw or not Path(raw).is_absolute() or root == ROOT or ROOT in root.parents or not 1024 <= args.port <= 65535:
        print(
            "Set an absolute external POLICYOPS_TEMP_DIR and an unoccupied loopback port 1024..65535.", file=sys.stderr
        )
        return 2
    driver = Drills(root, args.port)
    try:
        driver.run()
    except Exception as error:
        driver.report["passed"] = False
        driver.report["failure"] = {
            "type": type(error).__name__,
            "detail": driver.failure_tail(str(error)) if isinstance(error, SmokeError) else "details omitted",
        }
    finally:
        try:
            driver.cleanup()
        except Exception as error:
            driver.report["cleanup"]["error_type"] = type(error).__name__
            driver.report["passed"] = False
        report = driver.save()
    print(json.dumps({"passed": driver.report["passed"], "report": str(report), "project": driver.project}))
    return 0 if driver.report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
