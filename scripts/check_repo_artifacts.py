"""Fail when tooling left files or directories inside the checkout that Git does not track.

Every path on disk except .git and tracked files is listed individually,
including the contents of ignored directories and empty directories; git status
would collapse an ignored directory to one entry and hide new files below it.

Without options any such path fails (CI before dependency installs). After an
install, record the installed tree outside the checkout with
`--write-baseline FILE --installed DIR`, which fails if anything exists outside
DIR, then run `--baseline FILE` after the checks: every path added since the
baseline fails, including new caches inside the installed dependency tree.
Locally, record a baseline without --installed first, because private ignored
files legitimately exist there. Only new paths are detected; a tool rewriting
an already recorded path in place is not.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def _raise(error: OSError) -> None:
    raise error


def tracked_paths() -> set[str]:
    output = subprocess.run(
        ["git", "ls-files", "-z", "--cached"], cwd=ROOT, capture_output=True, check=True,
    ).stdout
    return {entry.decode("utf-8", errors="surrogateescape") for entry in output.split(b"\0") if entry}


def leftover_paths() -> set[str]:
    """Untracked/ignored files and directories (directories end with '/')."""
    tracked = tracked_paths()
    tracked_dirs = {str(parent) for path in tracked for parent in PurePosixPath(path).parents}
    found: set[str] = set()
    for current, dirs, files in os.walk(ROOT, onerror=_raise):
        relative = Path(current).relative_to(ROOT).as_posix()
        prefix = "" if relative == "." else f"{relative}/"
        if not prefix:
            dirs[:] = [name for name in dirs if name != ".git"]
            files = [name for name in files if name != ".git"]
        found.update(f"{prefix}{name}/" for name in dirs if f"{prefix}{name}" not in tracked_dirs)
        found.update(f"{prefix}{name}" for name in files if f"{prefix}{name}" not in tracked)
    return found


def installed_prefix(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or str(path) == ".":
        raise argparse.ArgumentTypeError("must be a relative directory inside the checkout")
    return f"{path}/"


def report(title: str, paths: list[str]) -> None:
    print(title, file=sys.stderr)
    for path in paths:
        print(f"  {path}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--baseline", type=Path, help="fail on paths not in this recorded baseline")
    group.add_argument("--write-baseline", type=Path, help="record current paths and exit")
    parser.add_argument("--installed", action="append", default=[], type=installed_prefix, metavar="DIR",
                        help="with --write-baseline: the only directory the install may populate (repeatable)")
    args = parser.parse_args()
    if args.installed and args.write_baseline is None:
        parser.error("--installed requires --write-baseline")
    for path in (args.baseline, args.write_baseline):
        if path is not None and ROOT in path.resolve().parents:
            parser.error("baseline files must be stored outside the repository")
    try:
        current = leftover_paths()
        known = set()
        if args.baseline is not None:
            known = set(args.baseline.read_text(encoding="utf-8", errors="surrogateescape").splitlines())
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Artifact check could not complete ({type(exc).__name__}).", file=sys.stderr)
        return 2
    if args.write_baseline is not None:
        outside = sorted(p for p in current if args.installed and not p.startswith(tuple(args.installed)))
        if outside:
            report("Files outside the installed directories (route them to POLICYOPS_TEMP_DIR):", outside)
            return 1
        args.write_baseline.parent.mkdir(parents=True, exist_ok=True)
        args.write_baseline.write_text("".join(f"{p}\n" for p in sorted(current)), encoding="utf-8",
                                       errors="surrogateescape")
        print(f"Recorded {len(current)} existing untracked/ignored paths.")
        return 0
    unexpected = sorted(current - known)
    if unexpected:
        report("Unexpected files inside the checkout (route them to POLICYOPS_TEMP_DIR):", unexpected)
        return 1
    print(f"No unexpected repository artifacts ({len(current)} paths, {len(known)} in baseline).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
