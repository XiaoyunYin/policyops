"""Read-only publication boundary check; standard library and Git only.

Check staged blob contents, not working-tree contents. --history additionally
checks every tree reachable from local refs. No staging, unstaging or rewriting.
This is deliberately not a replacement for an independent secret scanner.
"""

from __future__ import annotations

import argparse
from pathlib import PurePosixPath
import re
import subprocess
import sys


PUBLIC_FILES = {
    ".gitignore", ".gitattributes", ".editorconfig", ".env.example",
    ".dockerignore", ".python-version", "readme.md", "license",
    "third_party_notices.md", "pyproject.toml", "uv.lock", "dockerfile",
    "compose.yml", "compose.yaml",
    # T02: independent scanner config, reproducible Node version, security guidance.
    ".gitleaks.toml", ".nvmrc", "security.md",
}
# G8: reviewed isolated CPU reranker source, tests and dependency configuration are public project assets.
PUBLIC_ROOTS = {"apps", "packages", "tests", "scripts", "evals", "reranker", "infra", ".github", ".githooks"}
PUBLIC_DOCS = {
    "docs/architecture.md", "docs/evaluation.md", "docs/deployment.md",
    "docs/security.md", "docs/data-provenance.md",
    # T06: public reference for the database role matrix, bootstrap/migration usage and restore/rollback limits.
    "docs/database.md",
    # T38: reproducible Compose operations, migration ownership and coherent recovery procedures.
    "docs/operations.md",
    # T07: public reference for the OIDC/session/CSRF design, local identity setup and its limits.
    "docs/authentication.md",
    # T17: the generated rule/source coverage map: rule IDs, policy line ranges and clause digests, and the IDs and
    # asserted outcomes of the executed gateway cases. It holds no traces, states, results or policy text.
    "docs/policy-coverage.json",
}
PRIVATE_NAMES = {
    "plan.md", "agents.md", "claude.md", "bullets.md",
    "technical_dossier.md", "behavioral_stories.md",
}
PRIVATE_DIRS = {
    ".private", ".agents", ".claude", ".codex", "career", "internal", "notes",
    ".aws", ".ssh", "data", "artifacts", ".artifacts", "vendor", ".cache",
    ".venv", "node_modules", "__pycache__", "test-results", "playwright-report",
}
SECRET_PATTERNS = {
    "private key material": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "provider token": re.compile(rb"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "credential-bearing URL": re.compile(rb"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:]+:[^\s/@]+@"),
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], stderr=subprocess.PIPE)


def path_error(path: str) -> str | None:
    normalized = path.replace("\\", "/").casefold()
    parts = PurePosixPath(normalized).parts
    if not parts or any(p in {"..", "."} for p in parts):
        return "invalid path"
    name = parts[-1]
    if name in PRIVATE_NAMES or any(p in PRIVATE_DIRS or "private" in p for p in parts):
        return "private path"
    if name.startswith(".env") and normalized != ".env.example":
        return "environment file"
    if re.search(r"\.(pem|key|p12|pfx|db|sqlite\d*|dump|log|har|trace)(?:-|$)", name):
        return "local data or credentials"
    if ".tfstate" in name or name.endswith(".tfvars") or name.startswith("credentials") or "service-account" in name:
        return "local state or credentials"
    if normalized.startswith(("evals/results/", "evals/raw/")):
        return "raw evaluation output"
    if normalized in PUBLIC_FILES or normalized in PUBLIC_DOCS:
        return None
    if parts[0] in PUBLIC_ROOTS or normalized.startswith("docs/assets/"):
        return None
    return "outside public allowlist (review before expanding it)"


def index_entries() -> list[tuple[str, str, str]]:
    entries = []
    for row in git("ls-files", "--stage", "-z").split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, oid, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise ValueError("unmerged index; resolve it before publication")
        entries.append((mode, oid, path.decode("utf-8", errors="surrogateescape")))
    return entries


def history_entries() -> list[tuple[str, str, str]]:
    entries = set()
    for commit in git("rev-list", "--all").decode("ascii").splitlines():
        for row in git("ls-tree", "-r", "-z", commit).split(b"\0"):
            if not row:
                continue
            metadata, path = row.split(b"\t", 1)
            mode, _kind, oid = metadata.decode("ascii").split()
            entries.add((mode, oid, path.decode("utf-8", errors="surrogateescape")))
    return sorted(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="also scan all reachable commits")
    args = parser.parse_args()
    try:
        entries = index_entries()
        if args.history:
            entries.extend(history_entries())
        failures: set[tuple[str, str]] = set()
        checked: dict[str, list[str]] = {}
        for mode, oid, path in entries:
            error = path_error(path)
            if error:
                failures.add((path, error))
            if mode not in {"100644", "100755"}:
                failures.add((path, "symlink or submodule is not approved for publication"))
                continue
            if oid not in checked:
                blob = git("cat-file", "blob", oid)
                checked[oid] = [label for label, pattern in SECRET_PATTERNS.items() if pattern.search(blob)]
            for label in checked[oid]:
                failures.add((path, label))
        if failures:
            print("Publication blocked; review these paths (matching contents are not printed):", file=sys.stderr)
            for path, reason in sorted(failures):
                print(f"  {path!r}: {reason}", file=sys.stderr)
            return 1
        scope = "index and reachable history" if args.history else "index"
        print(f"Publication boundary passed: {scope}; {len(checked)} unique blobs checked.")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        # Fail closed without printing subprocess output, which might hold data.
        print(f"Publication check could not complete ({type(exc).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
