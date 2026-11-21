"""Operator-only workbench scenario evaluation."""

import os
from pathlib import Path
import sys


SMOKE_DSN_MAX_BYTES = 16 * 1024


class Refused(ValueError):
    """A fixed operator-facing diagnostic without private data."""


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise Refused("scenario input exceeds its size bound")
    return raw


def in_test_context() -> bool:
    return ("pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ
            or os.environ.get("POLICYOPS_ENV", "").lower() == "test")
