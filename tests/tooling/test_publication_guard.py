"""Exercise publication safeguards in isolated repositories, never the real index."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


GUARD = Path(__file__).resolve().parents[2] / "scripts" / "check_publication.py"


class PublicationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="policyops-guard-", dir=os.environ.get("POLICYOPS_TEMP_DIR"),
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "-q")
        self.git("config", "user.email", "guard-test@example.invalid")
        self.git("config", "user.name", "Guard test")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str, input_text: str | None = None) -> str:
        result = subprocess.run(
            ["git", *args], cwd=self.root, env=self.env, input=input_text,
            text=True, capture_output=True, check=True,
        )
        return result.stdout

    def stage(self, name: str, content: str = "safe fixture\n") -> None:
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.git("add", "--", name)

    def run_guard(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(GUARD), *args], cwd=self.root,
            env=self.env, text=True, capture_output=True,
        )

    def test_empty_repository_and_public_source_pass(self) -> None:
        self.assertEqual(self.run_guard("--history").returncode, 0)
        self.stage("packages/policyops/example.py", "print('fixture')\n")
        self.assertEqual(self.run_guard().returncode, 0)

    def test_internal_names_are_blocked_case_insensitively_at_any_depth(self) -> None:
        for name in ("PLAN.md", "apps/web/Agents.MD", "tests/CLAUDE.md", "BULLETS.md"):
            with self.subTest(name=name):
                self.stage(name)
                result = self.run_guard()
                self.assertEqual(result.returncode, 1)
                self.assertIn("private path", result.stderr)
                self.git("rm", "--cached", "--", name)

    def test_reviewed_foundation_files_and_public_manifests_pass(self) -> None:
        for name in (".gitleaks.toml", ".nvmrc", "SECURITY.md", "evals/manifests/retail.json",
                     "reranker/pyproject.toml", "reranker/uv.lock", "reranker/src/policyops_reranker/__init__.py"):
            self.stage(name)
        self.assertEqual(self.run_guard().returncode, 0)

    def test_only_reviewed_docs_pages_pass(self) -> None:
        self.stage("docs/database.md")
        self.stage("docs/authentication.md")
        self.assertEqual(self.run_guard().returncode, 0)
        for name in ("docs/notes.md", "docs/review-T06.md", "docs/sub/database.md"):
            with self.subTest(name=name):
                self.stage(name)
                self.assertEqual(self.run_guard().returncode, 1)
                self.git("rm", "--cached", "--", name)

    def test_only_the_exact_policy_coverage_map_passes_among_docs_json(self) -> None:
        self.stage("docs/policy-coverage.json", '{"schema": "policyops.policy-coverage/v1"}\n')
        self.assertEqual(self.run_guard().returncode, 0)
        for name in ("docs/coverage.json", "docs/policy-coverage-raw.json", "docs/policy-coverage.json.bak",
                     "docs/sub/policy-coverage.json", "docs/traces/policy-coverage.json", "docs/results.json",
                     "evals/results/policy-coverage.json", "policy-coverage.json"):
            with self.subTest(name=name):
                self.stage(name, "{}\n")
                result = self.run_guard()
                self.assertEqual(result.returncode, 1)
                self.assertIn(repr(name), result.stderr)  # blocked: outside the allowlist, or raw output
                self.git("rm", "--cached", "--", name)

    def test_the_policy_coverage_map_is_still_scanned_for_secrets(self) -> None:
        self.stage("docs/policy-coverage.json", '{"note": "sk-' + 'x' * 30 + '"}\n')
        result = self.run_guard()
        self.assertEqual(result.returncode, 1)
        self.assertIn("provider token", result.stderr)

    def test_environment_example_only_allowed_at_root(self) -> None:
        self.stage(".env.example", "OPENAI_API_KEY=\n")
        self.assertEqual(self.run_guard().returncode, 0)
        for name in (".env", ".env.production", "apps/web/.env.example"):
            with self.subTest(name=name):
                self.stage(name)
                self.assertEqual(self.run_guard().returncode, 1)
                self.git("rm", "--cached", "--", name)

    def test_raw_outputs_and_unknown_public_roots_are_blocked(self) -> None:
        for name in ("evals/results/run.json", "notes.txt", "infra/local.db", "career/story.md",
                     "reranker/artifacts/model.safetensors", "reranker/data/triples.json", "reranker/PLAN.md"):
            with self.subTest(name=name):
                self.stage(name)
                self.assertEqual(self.run_guard().returncode, 1)
                self.git("rm", "--cached", "--", name)

    def test_scans_index_contents_not_sanitized_worktree(self) -> None:
        token = "sk-" + "x" * 30
        self.stage("apps/web/example.txt", token)
        (self.root / "apps/web/example.txt").write_text("sanitized", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 1)
        self.assertIn("provider token", result.stderr)
        self.assertNotIn(token, result.stderr)

    def test_scans_staged_example_contents(self) -> None:
        material = "-----BEGIN " + "PRIVATE KEY-----"
        self.stage(".env.example", material)
        self.assertEqual(self.run_guard().returncode, 1)

    def test_history_finds_deleted_private_file(self) -> None:
        self.stage("PLAN.md")
        self.git("commit", "-qm", "fixture: private history")
        self.git("rm", "PLAN.md")
        self.git("commit", "-qm", "fixture: delete private file")
        self.assertEqual(self.run_guard().returncode, 0)
        self.assertEqual(self.run_guard("--history").returncode, 1)

    def test_history_scans_deleted_secret_contents(self) -> None:
        self.stage("apps/example.txt", "ghp_" + "a" * 36)
        self.git("commit", "-qm", "fixture: token")
        self.stage("apps/example.txt", "safe")
        self.git("commit", "-qm", "fixture: remove token")
        self.assertEqual(self.run_guard().returncode, 0)
        result = self.run_guard("--history")
        self.assertEqual(result.returncode, 1)
        self.assertIn("GitHub token", result.stderr)

    def test_symlink_index_entry_is_blocked_without_following_it(self) -> None:
        oid = self.git("hash-object", "-w", "--stdin", input_text="../PLAN.md").strip()
        self.git("update-index", "--add", "--cacheinfo", f"120000,{oid},apps/link")
        result = self.run_guard()
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlink", result.stderr)

    def test_guard_fails_closed_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="policyops-no-git-", dir=os.environ.get("POLICYOPS_TEMP_DIR"),
        ) as directory:
            result = subprocess.run(
                [sys.executable, str(GUARD)], cwd=directory, env=self.env,
                text=True, capture_output=True,
            )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
