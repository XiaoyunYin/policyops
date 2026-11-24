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
UV_PROJECTS = ("pyproject.toml", "evals/pyproject.toml", "reranker/pyproject.toml")


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
        # The Python job checks once; the web and PostgreSQL jobs (the latter installs apps/web for the API
        # contract check) record the installed tree, then check against it.
        self.assertEqual(self.workflow.count("scripts/check_repo_artifacts.py"), 5)
        self.assertEqual(self.workflow.count("--installed apps/web/node_modules"), 2)
        baseline = '"$POLICYOPS_TEMP_DIR/reports/web-installed.txt"'
        self.assertIn(f"--write-baseline {baseline}", self.workflow)
        self.assertIn(f"check_repo_artifacts.py --baseline {baseline}", self.workflow)

    def test_generated_api_types_are_checked_in_the_web_job(self) -> None:
        web = self.workflow[self.workflow.index("\n  web:\n"):]
        self.assertIn("scripts/api_types.py --check", web)
        self.assertEqual(self.workflow.count("scripts/api_types.py"), 1)

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
        # Exactly two PostgreSQL selections in the whole workflow: the application's and the evaluator's, both in
        # this Linux job (the Windows Python job has no container engine and never selects postgres explicitly).
        app_command = "python3 -B scripts/devenv.py uv run --frozen pytest -m postgres"
        evaluator_command = "python3 -B ../scripts/devenv.py uv run --frozen pytest -m postgres"
        evaluator_setup = "python3 -B scripts/devenv.py uv sync --project evals --frozen"
        self.assertEqual(self.workflow.count("pytest -m postgres"), 2)
        self.assertEqual(job.count("pytest -m postgres"), 2)
        self.assertEqual(job.count(app_command), 1)
        self.assertEqual(job.count(evaluator_command), 1)
        self.assertEqual(job.count(evaluator_setup), 1)
        self.assertIn("label=policyops.owner=policyops-tests", job)
        self.assertIn("if: always()", job)
        # Both commands run after the pinned pulls and the volume baseline and before the always-run teardown.
        # The evaluator's frozen environment is created before BOTH commands: the application's retail-client and
        # execution cases start the evaluator-owned simulator from it.
        self.assertLess(job.index("volumes-before.txt"), job.index(evaluator_setup))
        self.assertLess(job.index(evaluator_setup), job.index(app_command))
        self.assertLess(job.index(app_command), job.index(evaluator_command))
        self.assertLess(job.index(evaluator_command), job.index("if: always()"))
        self.assertLess(job.index(evaluator_command), job.index("volumes-after.txt"))
        step = job[job.index("      - name: Evaluator PostgreSQL"):]
        step = step[:step.index(evaluator_command) + len(evaluator_command)]
        self.assertIn("working-directory: evals\n", step)
        # The application and evaluator defaults exclude postgres, so only these explicit steps select it.
        for project in ("pyproject.toml", "evals/pyproject.toml"):
            with self.subTest(project=project):
                addopts = load_toml(project)["tool"]["pytest"]["addopts"]
                expected = "not postgres and not helpdesk" if project == "pyproject.toml" else "not postgres"
                self.assertEqual(addopts[addopts.index("-m") + 1], expected)
        python_job = self.workflow[self.workflow.index("\n  python:\n"):self.workflow.index("\n  postgres:\n")]
        self.assertNotIn("postgres", python_job)

    def test_tool_versions_agree(self) -> None:
        node = (REPO / ".nvmrc").read_text(encoding="utf-8").strip()
        package = json.loads((REPO / "apps" / "web" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["engines"]["node"], f"^{node}")
        self.assertIn("node-version-file: .nvmrc", self.workflow)
        uv_versions = set(re.findall(r'version: "(\d+\.\d+\.\d+)"', self.workflow))
        self.assertEqual(len(uv_versions), 1)
        for project in UV_PROJECTS:
            required = load_toml(project)["tool"]["uv"]["required-version"]
            self.assertEqual(required, ">=0.13.6,<0.14")
            self.assertTrue(next(iter(uv_versions)).startswith("0.13."))

    def test_locks_record_the_same_supply_chain_cutoff(self) -> None:
        cutoffs = set()
        for project in UV_PROJECTS:
            configured = load_toml(project)["tool"]["uv"]["exclude-newer"]
            cutoffs.add(configured)
            lock = str(Path(project).with_name("uv.lock"))
            # G8 phase 1 has no lock: the coordinator resolves it with network access
            # immediately afterward. Once present, validate it just like the other locks.
            if project == "reranker/pyproject.toml" and not (REPO / lock).exists():
                continue
            recorded = load_toml(lock)["options"]["exclude-newer"]
            self.assertEqual(configured, recorded)
        self.assertEqual(len(cutoffs), 1)

    def test_reranker_is_isolated_and_uses_only_the_explicit_cpu_torch_index(self) -> None:
        project = load_toml("reranker/pyproject.toml")
        self.assertEqual(project["project"]["name"], "policyops-reranker")
        self.assertEqual(project["project"]["requires-python"], ">=3.12,<3.13")
        members = load_toml("pyproject.toml")["tool"]["uv"]["workspace"]["members"]
        self.assertNotIn("reranker", members)
        self.assertEqual(project["tool"]["uv"]["sources"]["torch"], {"index": "pytorch-cpu"})
        self.assertEqual(project["tool"]["uv"]["index"], [{
            "name": "pytorch-cpu", "url": "https://download.pytorch.org/whl/cpu", "explicit": True,
        }])
        tools = {"mypy", "pytest", "ruff"}
        app_dev = load_toml("pyproject.toml")["dependency-groups"]["dev"]
        self.assertEqual(project["dependency-groups"]["dev"], [
            dependency for dependency in app_dev if re.split(r"[<>=]", dependency)[0] in tools
        ])
        self.assertNotIn("reranker", self.workflow)  # CPU torch CI is deferred until phase 2.

    def test_locks_stay_separate_and_share_contract_runtime(self) -> None:
        app = lock_versions("uv.lock")
        evals = lock_versions("evals/uv.lock")
        for versions in (app, evals):
            for name in ("policyops-reranker", "torch", "transformers"):
                self.assertNotIn(name, versions)
        for name in ("tau2", "litellm"):
            self.assertNotIn(name, app)
        for name in ("policyops", "langgraph", "pydantic-settings"):
            self.assertIn(name, evals)
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
        self.assertEqual(set(images), {"postgres", "oidc", "proxy", "python", "node", "observability"})
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
