"""Generate or check the web app's API types from the committed OpenAPI document (T08).

    python scripts/devenv.py python -B scripts/api_types.py --write   regenerate apps/web/src/api/schema.d.ts
    python scripts/devenv.py python -B scripts/api_types.py --check   exit 1 if it differs from a fresh generation

The generator is an isolated, exactly locked npm project (`scripts/api-types`: openapi-typescript 7.13.0 needs
TypeScript 5, so it is kept apart from the web app's TypeScript 6 toolchain). Each run copies it into a new
directory under `$POLICYOPS_TEMP_DIR/tmp`, installs the lock with `npm ci --ignore-scripts` and empty user/global
npm configuration files, and runs the installed module with `node` (never npx, so there is no download fallback).
Generation runs with a minimal environment: no inherited variables (such as registry or Redocly tokens), and
HTTP(S)_PROXY with NODE_USE_ENV_PROXY pointing at a closed local port, so any network access by the generator
fails instead of silently succeeding. The run directory is removed afterwards unless `--keep` is given.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "api-types"
GENERATOR_FILES = ("package.json", "package-lock.json", ".npmrc", "generate.mjs")
OPENAPI = ROOT / "packages" / "policyops" / "openapi" / "v1.json"
OUTPUT = ROOT / "apps" / "web" / "src" / "api" / "schema.d.ts"
CLOSED_PROXY = "http://127.0.0.1:9"


class GenerationError(RuntimeError):
    pass


def temp_root() -> Path:
    value = os.environ.get("POLICYOPS_TEMP_DIR")
    if not value:
        raise GenerationError("POLICYOPS_TEMP_DIR is not set (run through scripts/devenv.py)")
    root = Path(value).resolve()
    if root == ROOT or ROOT in root.parents:
        raise GenerationError("POLICYOPS_TEMP_DIR must be outside the repository")
    return root


def tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise GenerationError(f"{name} is not on PATH")
    return found


def run(argv: list[str], *, env: dict[str, str], cwd: Path) -> None:
    completed = subprocess.run(argv, env=env, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise GenerationError(f"{Path(argv[0]).name} exited with {completed.returncode}")


def generate(work: Path) -> bytes:
    work.mkdir(parents=True)
    for name in GENERATOR_FILES:
        shutil.copyfile(GENERATOR / name, work / name)
    empty_user, empty_global = work / "empty-user-npmrc", work / "empty-global-npmrc"
    empty_user.write_bytes(b"")
    empty_global.write_bytes(b"")
    install_env = {**os.environ, "npm_config_userconfig": str(empty_user),
                   "npm_config_globalconfig": str(empty_global), "npm_config_ignore_scripts": "true"}
    run([tool("npm"), "ci", "--ignore-scripts", "--no-audit", "--no-fund"], env=install_env, cwd=work)
    node = tool("node")
    minimal = {"PATH": str(Path(node).parent), "TEMP": str(work), "TMP": str(work), "TMPDIR": str(work),
               "HTTP_PROXY": CLOSED_PROXY, "HTTPS_PROXY": CLOSED_PROXY, "NODE_USE_ENV_PROXY": "1",
               "NO_COLOR": "1"}
    if os.name == "nt":
        minimal["SystemRoot"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
    output = work / "schema.d.ts"
    run([node, str(work / "generate.mjs"), str(OPENAPI), str(output)], env=minimal, cwd=work)
    return output.read_bytes()


def remove(work: Path, root: Path) -> None:
    resolved = work.resolve()
    if resolved.parent != (root / "tmp").resolve() or not resolved.name.startswith("api-types-"):
        raise GenerationError(f"refusing to remove {resolved}")
    shutil.rmtree(resolved)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the temporary generator directory")
    args = parser.parse_args(argv)
    try:
        root = temp_root()
        work = root / "tmp" / f"api-types-{uuid.uuid4().hex}"
        try:
            generated = generate(work)
        finally:
            if not args.keep and work.exists():
                remove(work, root)
    except GenerationError as exc:
        print(f"api_types: {exc}", file=sys.stderr)
        return 2
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(generated)
        print(f"wrote {OUTPUT.relative_to(ROOT).as_posix()}")
        return 0
    if not OUTPUT.is_file() or OUTPUT.read_bytes() != generated:
        print(f"{OUTPUT.relative_to(ROOT).as_posix()} differs from a fresh generation", file=sys.stderr)
        return 1
    print("API types match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
