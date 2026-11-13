"""Offline browser-output guard. Reports paths/categories only, never matching values.

Scan the final uncompressed output, not source: --bundle must contain index.html
and JavaScript. This is a heuristic, not a proof against encoded/novel secrets.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_publication import SECRET_PATTERNS


PATTERNS = {
    **SECRET_PATTERNS,
    "provider environment name": re.compile(rb"(?:OPENAI_|ANTHROPIC_)[A-Z0-9_]*", re.I),
    "server configuration": re.compile(rb"\b(?:POLICYOPS_[A-Z0-9_]+|DATABASE_URL|OIDC_CLIENT_SECRET)\b"),
    "server endpoint": re.compile(rb"api\.(?:openai|anthropic)\.com|postgres(?:ql)?(?:\+psycopg)?://", re.I),
    "runtime database role": re.compile(rb"policyops_(?:app_migrator|app_runtime|auth_runtime|eval_runtime)"),
    "secret assignment": re.compile(
        rb"(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)[\"']?\s*[:=]\s*[\"'][^\"'\s]{12,}"),
    "source map reference": re.compile(rb"sourceMappingURL\s*=", re.I),
}
MAX_FILE_BYTES = 32 * 1024 * 1024


def check_bundle(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    failures: list[str] = []
    files = sorted(root.rglob("*"))
    if not (root / "index.html").is_file() or not any(p.suffix == ".js" for p in files):
        failures.append("bundle: missing index.html or JavaScript (refusing empty/incomplete scan)")
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or path.is_junction():
            failures.append(f"{relative}: linked output is not approved")
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in {".map", ".gz", ".br"}:
            failures.append(f"{relative}: source map or compressed output requires separate review")
        if path.stat().st_size > MAX_FILE_BYTES:
            failures.append(f"{relative}: file exceeds scan bound")
            continue
        data = path.read_bytes()
        failures.extend(f"{relative}: {label}" for label, pattern in PATTERNS.items() if pattern.search(data))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    try:
        failures = check_bundle(args.bundle)
    except OSError as exc:
        print(f"Bundle check could not complete ({type(exc).__name__}).", file=sys.stderr)
        return 2
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print("Browser bundle boundary passed (uncompressed files; heuristic scan).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
