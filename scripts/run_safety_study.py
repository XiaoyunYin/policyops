"""Run the test-only T30 PostgreSQL/HTTP safety study or verify a sealed report offline."""

from __future__ import annotations

from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests/support"))

from policyops_testing.safety.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
