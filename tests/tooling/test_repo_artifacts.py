"""Checkout artifact detection in isolated repositories; standard library only."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_repo_artifacts.py"


class ArtifactCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="policyops-artifacts-", dir=os.environ.get("POLICYOPS_TEMP_DIR"))
        self.addCleanup(temp.cleanup)
        self.outside = Path(temp.name)
        self.repo = self.outside / "checkout"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        # The checker inspects the checkout it lives in, so each fixture gets its own copy.
        self.write("scripts/check_repo_artifacts.py", SCRIPT.read_text(encoding="utf-8"))
        self.write(".gitignore", "node_modules/\n*.log\n")
        self.write("apps/web/src/main.tsx", "export {};\n")
        subprocess.run(["git", "init", "-q"], cwd=self.repo, env=self.env, check=True)
        subprocess.run(["git", "add", "--", "."], cwd=self.repo, env=self.env, check=True)
        self.baseline = self.outside / "baseline.txt"

    def write(self, name: str, content: str = "fixture\n") -> None:
        target = self.repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def check(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(self.repo / "scripts" / "check_repo_artifacts.py"), *args],
            cwd=self.repo, env=self.env, capture_output=True, text=True,
        )

    def install_dependencies(self) -> None:
        self.write("apps/web/node_modules/react/index.js")
        self.write("apps/web/node_modules/.bin/vite")

    def test_clean_checkout_passes_and_untracked_or_ignored_files_fail(self) -> None:
        self.assertEqual(self.check().returncode, 0)
        for name in ("stray.txt", "apps/web/debug.log"):
            with self.subTest(name=name):
                self.write(name)
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stderr)
                (self.repo / name).unlink()

    def test_new_cache_inside_installed_dependency_tree_fails(self) -> None:
        # Regression: a blanket node_modules/ exemption and git's collapsed
        # "!! apps/web/node_modules/" entry both hid newly generated caches.
        self.install_dependencies()
        recorded = self.check("--write-baseline", str(self.baseline), "--installed", "apps/web/node_modules")
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        self.assertEqual(self.check("--baseline", str(self.baseline)).returncode, 0)
        self.write("apps/web/node_modules/.vitest-cache/new-generated-cache")
        result = self.check("--baseline", str(self.baseline))
        self.assertEqual(result.returncode, 1)
        self.assertIn("apps/web/node_modules/.vitest-cache/new-generated-cache", result.stderr)

    def test_new_paths_inside_baselined_untracked_or_ignored_directories_fail(self) -> None:
        self.install_dependencies()
        self.write("scratch/existing.txt")
        self.assertEqual(self.check("--write-baseline", str(self.baseline)).returncode, 0)
        cases = {
            "untracked directory file": "scratch/new.txt",
            "ignored directory file": "apps/web/node_modules/react/generated.js",
            "empty directory": "apps/web/node_modules/.vite/",
        }
        for label, name in cases.items():
            with self.subTest(label):
                target = self.repo / name
                if name.endswith("/"):
                    target.mkdir()
                else:
                    self.write(name)
                result = self.check("--baseline", str(self.baseline))
                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stderr)
                shutil.rmtree(target) if target.is_dir() else target.unlink()
        self.assertEqual(self.check("--baseline", str(self.baseline)).returncode, 0)

    def test_installed_baseline_rejects_files_outside_installed_directory(self) -> None:
        self.install_dependencies()
        self.write("apps/web/.npm-cache/index")
        result = self.check("--write-baseline", str(self.baseline), "--installed", "apps/web/node_modules")
        self.assertEqual(result.returncode, 1)
        self.assertIn("apps/web/.npm-cache/index", result.stderr)
        self.assertFalse(self.baseline.exists())

    def test_invalid_options_are_rejected(self) -> None:
        cases = (
            ("--write-baseline", str(self.repo / "baseline.txt")),
            ("--installed", "apps/web/node_modules"),
            ("--write-baseline", str(self.baseline), "--installed", "../outside"),
            ("--allow", "apps/web/node_modules/"),
        )
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(self.check(*args).returncode, 2)
        self.assertFalse((self.repo / "baseline.txt").exists())

    def test_missing_baseline_fails_closed(self) -> None:
        result = self.check("--baseline", str(self.outside / "missing.txt"))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
