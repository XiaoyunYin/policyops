"""Offline build-context guard; no Docker daemon or Dockerfile required.

Supports the repository's root-relative .dockerignore subset: literals, *, ?, **
path segments, comments, and ordered ! rules. Unsupported syntax fails closed.
Checks included files AND synthetic private paths, so an absent .env is no pass.
T38 must also inspect real contexts, image files/layers and installed packages;
this script does not build or certify images or emulate all Docker semantics.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import sys


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_publication import PRIVATE_DIRS, PRIVATE_NAMES, SECRET_PATTERNS, path_error


@dataclass(frozen=True)
class Rule:
    include: bool
    pattern: re.Pattern[str]


def parse_rules(text: str) -> list[Rule]:
    rules = []
    for raw in text.splitlines():
        value = raw.strip()
        if not value or value.startswith("#") or value == ".":
            continue
        include = value.startswith("!")
        value = value.removeprefix("!").strip("/")
        parts = PurePosixPath(value).parts
        if not parts or any(c in value for c in "\\[]") or any(p in {".", ".."} for p in value.split("/")):
            raise ValueError("unsupported dockerignore pattern")
        segments = []
        for index, part in enumerate(parts):
            if part == "**":
                segments.append(".*" if index == len(parts) - 1 else "(?:[^/]+/)*")
            else:
                if "**" in part:
                    raise ValueError("** must be a complete path segment")
                segments.append(re.escape(part).replace(r"\*", "[^/]*").replace(r"\?", "[^/]"))
                if index < len(parts) - 1:
                    segments.append("/")
        rules.append(Rule(include, re.compile("^" + "".join(segments) + "$")))
    if not rules or rules[0].include or rules[0].pattern.pattern != "^.*$":
        raise ValueError("build context must start closed with **")
    return rules


def included(path: str, rules: list[Rule]) -> bool:
    parts = PurePosixPath(path).parts
    ancestors = ["/".join(parts[:index]) for index in range(1, len(parts) + 1)]
    result = True  # Docker starts open; the required initial ** closes it.
    for rule in rules:
        if any(rule.pattern.fullmatch(parent) for parent in ancestors):
            result = rule.include
    return result


def check_context(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    rules = parse_rules((root / ".dockerignore").read_text(encoding="utf-8"))
    failures: list[str] = []
    # Probe every source root at multiple depths, even when private files are absent.
    private = sorted(PRIVATE_NAMES) + [f"{name}/payload.txt" for name in sorted(PRIVATE_DIRS)] + [
        ".git/config", ".env", ".env.local", ".env.example", "secret.pem", "secret.key", "secret.p12", "secret.pfx",
        "local.db", "local.sqlite3", "backup.dump", "access.log", "capture.har", "run.trace",
        "terraform.tfstate", "local.tfvars", "credentials.json", "service-account.json",
        "dist/app.js", "build/app.js", "coverage/report.json",
    ]
    for prefix in ("", "apps/", "apps/web/", "packages/", "packages/example/src/", "scripts/", "tests/", "infra/"):
        failures.extend(f"{prefix}{name}: private-path probe included" for name in private
                        if included(prefix + name, rules))
    for path in context_paths(root, rules):
        relative = path.relative_to(root).as_posix()
        if path.name.endswith(".dockerignore") and relative != ".dockerignore":
            failures.append(f"{relative}: Dockerfile-specific ignore override requires separate review")
        if not included(relative, rules):
            continue
        if path.is_symlink() or path.is_junction():
            failures.append(f"{relative}: linked context path is not approved")
            continue
        if not path.is_file():
            continue
        error = path_error(relative)
        if error:
            failures.append(f"{relative}: {error}")
            continue
        if path.stat().st_size > 32 * 1024 * 1024:
            failures.append(f"{relative}: file exceeds scan bound")
            continue
        data = path.read_bytes()
        failures.extend(f"{relative}: {label}" for label, pattern in SECRET_PATTERNS.items() if pattern.search(data))
    return sorted(set(failures))


def context_paths(root: Path, rules: list[Rule]) -> list[Path]:
    """Prune only final exclusions; later ! rules can still reopen a directory.

    Never descend into links, including Windows junctions. Pruning is an
    optimization, not an assumption that an excluded parent excludes children.
    """
    last_include = max((i for i, rule in enumerate(rules) if rule.include), default=-1)
    paths: list[Path] = []

    def on_error(error: OSError) -> None:
        raise error

    for current, dirs, files in os.walk(root, followlinks=False, onerror=on_error):
        parent = Path(current)
        paths.extend(parent / name for name in files)
        descend = []
        for name in dirs:
            path = parent / name
            paths.append(path)
            if path.is_symlink() or path.is_junction():
                continue
            relative = path.relative_to(root)
            ancestors = [relative.as_posix(), *(p.as_posix() for p in relative.parents if p != Path())]
            final_exclusion = any(not rule.include and i > last_include
                                  and any(rule.pattern.fullmatch(p) for p in ancestors)
                                  for i, rule in enumerate(rules))
            if not final_exclusion:
                descend.append(name)
        dirs[:] = descend
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        failures = check_context(args.context)
    except (OSError, ValueError) as exc:
        print(f"Build-context check could not complete ({type(exc).__name__}).", file=sys.stderr)
        return 2
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print("Build-context boundary passed (files and private-path probes; no image inspected).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
