"""Vitest's user-data output stays under the temporary root; standard library only.

Needs the installed web toolchain (Node and apps/web/node_modules), so pytest skips
this directory (tests/conftest.py) and the web CI job runs it:
python -B -m unittest discover -s tests/web -v

Vitest 5 writes an API token to <user data dir>/vitest/.vitest-secret-token before
any test runs (LOCALAPPDATA on Windows, XDG_DATA_HOME on Linux) and falls back to
apps/web/node_modules/.vitest/. The token is only checked for existence, never read.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "devenv.py"
WEB = REPO / "apps" / "web"
TOKEN = Path("vitest") / ".vitest-secret-token"
FALLBACK = WEB / "node_modules" / ".vitest"


def files_under(directory: Path) -> list[Path]:
    return sorted(Path(parent) / name for parent, _, names in os.walk(directory) for name in names)


class VitestUserDataTests(unittest.TestCase):
    def setUp(self) -> None:
        shared = os.environ.get("POLICYOPS_TEMP_DIR")
        if not shared:
            raise AssertionError("POLICYOPS_TEMP_DIR is not set")
        if shutil.which("npm") is None or not (WEB / "node_modules" / "vitest").is_dir():
            raise AssertionError("needs npm and `npm ci` in apps/web")
        temp = tempfile.TemporaryDirectory(prefix="policyops-vitest-", dir=shared)
        self.addCleanup(temp.cleanup)
        # A fresh root, so a token left by an earlier run cannot satisfy the check.
        self.root = Path(temp.name).resolve() / "root"
        self.root.mkdir()
        # Stands in for the caller's own user-data directory.
        self.inherited = Path(temp.name).resolve() / "inherited-user-data"

    def test_token_is_created_under_the_temp_root_not_inherited_user_data(self) -> None:
        fallback_before = files_under(FALLBACK)
        env = {
            **os.environ,
            "POLICYOPS_TEMP_DIR": str(self.root),
            "LOCALAPPDATA": str(self.inherited),
            "XDG_DATA_HOME": str(self.inherited),
        }
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "npm", "test"],
            cwd=WEB, env=env, capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
        self.assertTrue((self.root / "user-data" / TOKEN).is_file())
        self.assertEqual(files_under(self.inherited), [])
        self.assertEqual(files_under(FALLBACK), fallback_before)


if __name__ == "__main__":
    unittest.main()
