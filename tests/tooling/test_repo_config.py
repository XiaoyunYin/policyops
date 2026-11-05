"""Cross-file consistency of pins, locks and CI configuration; standard library only."""

from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib
from typing import Any
import unittest


REPO = Path(__file__).resolve().parents[2]
TAU2_COMMIT = "19f13ea3f5fba8b4c4d272d1353590f29dc53062"


def load_toml(relative: str) -> dict[str, Any]:
    return tomllib.loads((REPO / relative).read_text(encoding="utf-8"))


def lock_versions(relative: str) -> dict[str, str]:
    return {p["name"]: p.get("version", "") for p in load_toml(relative)["package"]}


class RepositoryConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    def test_actions_pinned_to_full_commit_shas(self) -> None:
        uses = re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", self.workflow, flags=re.MULTILINE)
        self.assertGreater(len(uses), 0)
        for target, comment in uses:
            with self.subTest(action=target):
                self.assertRegex(target, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
                self.assertRegex(comment, r"#\s*v\d")

    def test_workflow_is_least_privilege_and_secret_free(self) -> None:
        self.assertIn("permissions:\n  contents: read\n", self.workflow)
        self.assertNotIn("secrets.", self.workflow)
        self.assertNotIn("upload-artifact", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)
        self.assertEqual(self.workflow.count("persist-credentials: false"), self.workflow.count("actions/checkout@"))

    def test_ci_routes_temp_outside_checkout_and_disables_bytecode(self) -> None:
        blocks = self.workflow.count('root="$RUNNER_TEMP/policyops"')
        self.assertEqual(blocks, 4)
        self.assertEqual(self.workflow.count('echo "PYTHONDONTWRITEBYTECODE=1"'), blocks)
        self.assertEqual(self.workflow.count('echo "TMPDIR=$root/tmp"'), blocks)

    def test_artifact_checks_inventory_installed_tree_without_exemptions(self) -> None:
        self.assertNotIn("--allow", self.workflow)
        self.assertEqual(self.workflow.count("scripts/check_repo_artifacts.py"), 4)
        self.assertIn("--installed apps/web/node_modules", self.workflow)
        baseline = '"$POLICYOPS_TEMP_DIR/reports/web-installed.txt"'
        self.assertIn(f"--write-baseline {baseline}", self.workflow)
        self.assertIn(f"check_repo_artifacts.py --baseline {baseline}", self.workflow)

    def test_web_tooling_tests_run_only_in_the_web_job(self) -> None:
        # They need Node and node_modules, which the Python job does not install.
        command = "-B -m unittest discover -s tests/web -v"
        web_job = self.workflow[self.workflow.index("\n  web:\n"):]
        self.assertEqual(self.workflow.count(command), 1)
        self.assertIn(command, web_job)
        self.assertLess(web_job.index("npm ci"), web_job.index(command))
        self.assertLess(web_job.index(command), web_job.index("check_repo_artifacts.py --baseline"))

    def test_postgres_job_pulls_the_pinned_digest_and_checks_teardown(self) -> None:
        job = self.workflow[self.workflow.index("\n  postgres:\n"):self.workflow.index("\n  web:\n")]
        self.assertIn("runs-on: ubuntu-24.04", job)
        self.assertIn('["images"][sys.argv[1]]', job)
        self.assertIn("for name in postgres oidc; do", job)
        self.assertIn('p["image"] + "@" + p["digest"]', job)
        self.assertIn('docker pull "$image"', job)
        self.assertEqual(self.workflow.count("pytest -m postgres"), 1)
        self.assertIn("label=policyops.owner=policyops-tests", job)
        self.assertIn("if: always()", job)
        self.assertLess(job.index("volumes-before.txt"), job.index("pytest -m postgres"))
        self.assertLess(job.index("pytest -m postgres"), job.index("volumes-after.txt"))

    def test_tool_versions_agree(self) -> None:
        node = (REPO / ".nvmrc").read_text(encoding="utf-8").strip()
        package = json.loads((REPO / "apps" / "web" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["engines"]["node"], f"^{node}")
        self.assertIn("node-version-file: .nvmrc", self.workflow)
        uv_versions = set(re.findall(r'version: "(\d+\.\d+\.\d+)"', self.workflow))
        self.assertEqual(len(uv_versions), 1)
        for project in ("pyproject.toml", "evals/pyproject.toml"):
            required = load_toml(project)["tool"]["uv"]["required-version"]
            self.assertEqual(required, ">=0.13.6,<0.14")
            self.assertTrue(next(iter(uv_versions)).startswith("0.13."))

    def test_locks_record_the_same_supply_chain_cutoff(self) -> None:
        cutoffs = set()
        for project, lock in (("pyproject.toml", "uv.lock"), ("evals/pyproject.toml", "evals/uv.lock")):
            configured = load_toml(project)["tool"]["uv"]["exclude-newer"]
            recorded = load_toml(lock)["options"]["exclude-newer"]
            self.assertEqual(configured, recorded)
            cutoffs.add(configured)
        self.assertEqual(len(cutoffs), 1)

    def test_locks_stay_separate_and_share_contract_runtime(self) -> None:
        app = lock_versions("uv.lock")
        evals = lock_versions("evals/uv.lock")
        for name in ("tau2", "litellm"):
            self.assertNotIn(name, app)
        for name in ("policyops", "langgraph", "pydantic-settings"):
            self.assertNotIn(name, evals)
        for name in ("pydantic", "pydantic-core"):
            self.assertEqual(app[name], evals[name], name)

    def test_tau2_pinned_to_planned_commit_everywhere(self) -> None:
        dependencies = load_toml("evals/pyproject.toml")["project"]["dependencies"]
        tau2 = [d for d in dependencies if d.startswith("tau2")]
        self.assertEqual(tau2, [
            f"tau2[knowledge] @ git+https://github.com/sierra-research/tau2-bench@{TAU2_COMMIT}",
        ])
        package = next(p for p in load_toml("evals/uv.lock")["package"] if p["name"] == "tau2")
        self.assertTrue(package["source"]["git"].endswith(f"#{TAU2_COMMIT}"))
        init = (REPO / "evals" / "src" / "policyops_evals" / "__init__.py").read_text(encoding="utf-8")
        self.assertIn(f'TAU2_COMMIT = "{TAU2_COMMIT}"', init)

    def test_images_pinned_by_digest(self) -> None:
        images = json.loads((REPO / "infra" / "images.json").read_text(encoding="utf-8"))["images"]
        self.assertEqual(set(images), {"postgres", "oidc", "proxy"})
        for role, pin in images.items():
            with self.subTest(role=role):
                self.assertRegex(pin["digest"], r"^sha256:[0-9a-f]{64}$")
                self.assertNotIn(pin["tag"], {"latest", ""})
        self.assertIn("pg17", images["postgres"]["tag"])

    def test_web_lock_uses_public_registry_with_integrity(self) -> None:
        lock = json.loads((REPO / "apps" / "web" / "package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["lockfileVersion"], 3)
        for name, entry in lock["packages"].items():
            if not name or entry.get("link"):
                continue
            with self.subTest(package=name):
                self.assertTrue(entry["resolved"].startswith("https://registry.npmjs.org/"))
                self.assertTrue(entry["integrity"].startswith("sha512-"))


if __name__ == "__main__":
    unittest.main()
