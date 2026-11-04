"""Install and run the pinned gitleaks scanner; standard library only, fail closed.

Modes:
  install  download (or take --archive), verify the pinned release checksum,
           extract only the binary and verify its pinned hash
  staged   scan staged changes (pre-commit)
  history  scan every commit reachable from local refs (pre-push and CI)

Scans always use the repository's .gitleaks.toml, ignore inline gitleaks:allow
comments and .gitleaksignore files, and print only redacted locations. Scans
require POLICYOPS_TEMP_DIR (absolute, outside the checkout) even when
POLICYOPS_GITLEAKS names the scanner: scratch files and the scanner's TEMP/TMP
go to $POLICYOPS_TEMP_DIR/tmp, never to the caller's temp directory. Exit
codes: 0 clean, 1 findings, 2 scanner unavailable/unverified, temporary root
invalid or scan error. This complements, and does not replace,
scripts/check_publication.py.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


VERSION = "8.30.1"
RELEASE_URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}"
# Archive digests from gitleaks_8.30.1_checksums.txt (matching the GitHub release
# asset digests); binary digests were computed from those verified archives.
PINS = {
    "windows_x64": ("gitleaks_8.30.1_windows_x64.zip",
                    "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
                    "gitleaks.exe",
                    "17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c"),
    "linux_x64": ("gitleaks_8.30.1_linux_x64.tar.gz",
                  "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
                  "gitleaks",
                  "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"),
    "linux_arm64": ("gitleaks_8.30.1_linux_arm64.tar.gz",
                    "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
                    "gitleaks",
                    "00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b"),
    "darwin_x64": ("gitleaks_8.30.1_darwin_x64.tar.gz",
                   "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
                   "gitleaks",
                   "cee01fea7173f1b779dff188e1c26ecbcb4027d394acc573b23aaf0be260e291"),
    "darwin_arm64": ("gitleaks_8.30.1_darwin_arm64.tar.gz",
                     "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
                     "gitleaks",
                     "ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f"),
}
ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".gitleaks.toml"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


class GateError(Exception):
    """Scanner cannot be trusted or run; callers must fail closed."""


def platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    key = f"{system}_{arch}"
    if arch is None or key not in PINS:
        raise GateError(f"no pinned gitleaks {VERSION} build for {system}/{machine}")
    return key


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def temp_root() -> Path:
    """The validated external temporary root; the caller's TEMP/TMP are never used."""
    raw = os.environ.get("POLICYOPS_TEMP_DIR", "").strip()
    if not raw:
        raise GateError("POLICYOPS_TEMP_DIR is not set; it must name the external temporary root")
    root = Path(raw)
    if not root.is_absolute():
        raise GateError("POLICYOPS_TEMP_DIR must be an absolute path")
    root = root.resolve()
    if _inside(root, ROOT):
        raise GateError("POLICYOPS_TEMP_DIR must be outside the repository")
    return root


def scratch_environment(scratch: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}
    env.update(TEMP=str(scratch), TMP=str(scratch), TMPDIR=str(scratch))
    return env


def default_install_dir() -> Path:
    return temp_root() / "tools" / f"gitleaks-{VERSION}"


def resolve_binary(key: str) -> Path:
    configured = os.environ.get("POLICYOPS_GITLEAKS")
    if configured:
        candidate = Path(configured)
    else:
        candidate = default_install_dir() / PINS[key][2]
        if not candidate.is_file():
            found = shutil.which("gitleaks")
            if found is None:
                raise GateError("gitleaks not installed; run: python -B scripts/gitleaks_gate.py install")
            candidate = Path(found)
    if not candidate.is_file():
        raise GateError(f"gitleaks binary not found at {candidate}")
    if sha256_file(candidate) != PINS[key][3]:
        raise GateError(f"{candidate} is not the pinned gitleaks {VERSION} {key} binary")
    return candidate


def extract_binary(archive: bytes, asset: str, member: str) -> bytes:
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            return bundle.read(member)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        info = bundle.getmember(member)
        handle = bundle.extractfile(info) if info.isfile() else None
        if handle is None:
            raise GateError(f"{member} in {asset} is not a regular file")
        return handle.read()


def install(dest: Path, archive_path: Path | None, key: str) -> Path:
    asset, archive_sha, member, binary_sha = PINS[key]
    if archive_path is None:
        # Fixed https URL; integrity comes from the pinned checksum below.
        with urllib.request.urlopen(f"{RELEASE_URL}/{asset}", timeout=60) as response:  # noqa: S310
            archive = response.read(MAX_ARCHIVE_BYTES + 1)
    else:
        archive = archive_path.read_bytes()
    if len(archive) > MAX_ARCHIVE_BYTES or hashlib.sha256(archive).hexdigest() != archive_sha:
        raise GateError(f"{asset} does not match the pinned release checksum")
    binary = extract_binary(archive, asset, member)
    if hashlib.sha256(binary).hexdigest() != binary_sha:
        raise GateError(f"{member} in {asset} does not match the pinned binary hash")
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / member
    partial = dest / f".{member}.partial"
    partial.write_bytes(binary)
    partial.chmod(0o755)
    partial.replace(target)
    return target


def repo_toplevel(env: dict[str, str]) -> Path:
    output = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, encoding="utf-8", check=True, env=env,
    ).stdout.strip()
    return Path(output).resolve()


def has_commits(repo: Path, env: dict[str, str]) -> bool:
    refs = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--all", "--max-count=1"],
        capture_output=True, text=True, check=True, env=env,
    ).stdout.strip()
    return bool(refs)


def scan(binary: Path, mode: str, repo: Path, scratch: Path) -> int:
    if not CONFIG.is_file():
        raise GateError(f"scanner configuration missing: {CONFIG}")
    # gitleaks always honours <repo>/.gitleaksignore, whatever --gitleaks-ignore-path says.
    if (repo / ".gitleaksignore").exists():
        raise GateError(".gitleaksignore in the repository root would suppress findings; remove it")
    env = scratch_environment(scratch)
    if mode == "history" and not has_commits(repo, env):
        print("gitleaks: repository has no commits; nothing to scan.")
        return 0
    with tempfile.TemporaryDirectory(prefix="gitleaks-noignore-", dir=scratch) as empty_ignore_dir:
        command = [
            str(binary), "git", "--config", str(CONFIG), "--no-banner", "--redact",
            "--ignore-gitleaks-allow", "--gitleaks-ignore-path", empty_ignore_dir,
            "--report-format", "json", "--report-path", "-", "--log-level", "error",
        ]
        if mode == "staged":
            command += ["--pre-commit", "--staged"]
        else:
            command += ["--log-opts=--all"]
        result = subprocess.run(
            [*command, str(repo)], capture_output=True, encoding="utf-8", errors="replace", env=env, cwd=repo,
        )
    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError:
        findings = None
    if not isinstance(findings, list) or result.returncode not in {0, 1} or (
        result.returncode == 1) != bool(findings):
        detail = result.stderr.strip()[-2000:]
        raise GateError(f"gitleaks {mode} scan failed (exit {result.returncode}). {detail}")
    if not findings:
        print(f"gitleaks {VERSION} {mode} scan passed.")
        return 0
    print(f"gitleaks {VERSION} {mode} scan found {len(findings)} potential secret(s) "
          "(values redacted):", file=sys.stderr)
    for finding in findings:
        commit = str(finding.get("Commit") or "staged")[:12]
        print(f"  {finding.get('File')}:{finding.get('StartLine')} "
              f"rule={finding.get('RuleID')} commit={commit}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["install", "staged", "history"])
    parser.add_argument("--dest", type=Path, help="install directory (default: $POLICYOPS_TEMP_DIR/tools)")
    parser.add_argument("--archive", type=Path, help="install from an already downloaded release archive")
    args = parser.parse_args()
    try:
        key = platform_key()
        if args.mode == "install":
            dest = (args.dest or default_install_dir()).resolve()
            if _inside(dest, ROOT):
                raise GateError("install directory must be outside the repository")
            target = install(dest, args.archive, key)
            print(f"Installed verified gitleaks {VERSION} ({key}) at {target}")
            return 0
        # Validate the temporary root before anything runs, even with POLICYOPS_GITLEAKS set.
        root = temp_root()
        scratch = root / "tmp"
        repo = repo_toplevel(scratch_environment(scratch))
        if _inside(root, repo):
            raise GateError("POLICYOPS_TEMP_DIR must be outside the scanned repository")
        scratch.mkdir(parents=True, exist_ok=True)
        return scan(resolve_binary(key), args.mode, repo, scratch)
    except GateError as exc:
        print(f"gitleaks gate failed closed: {exc}", file=sys.stderr)
        return 2
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, tarfile.TarError,
            subprocess.CalledProcessError) as exc:
        print(f"gitleaks gate failed closed ({type(exc).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
