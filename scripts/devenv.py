"""Run one development command with process-local temp, cache and report paths.

Usage: python -B scripts/devenv.py [--print-env] [--] COMMAND [ARGS...]

POLICYOPS_TEMP_DIR must name an absolute directory outside this checkout
(locally D:\\coding agent files\\PolicyOps; in CI a runner-temp directory).
Every variable below is overridden for the child process only, so caches,
virtual environments, temporary files and reports cannot default into the
repository or the system temp folder. Machine-wide settings are not touched.

The uv project is resolved as uv 0.13 does: `--directory` (or UV_WORKING_DIR)
relative to the working directory, then `--project` (or UV_PROJECT) relative to
that. evals/ selects the evaluator venv; the root workspace selects the
application venv. The child also receives UV_PROJECT pinned to that project, so
uv cannot discover a different one (e.g. from a script's directory in `uv run
evals/x.py`, or in nested uv calls). Forms whose meaning depends on uv's full
option grammar fail before anything runs: options other than --directory and
--project before the subcommand, --directory/--project after `run`/`tool`
(child-command arguments are ambiguous; use `uv --project P run ... -- CMD`),
--active, repeated options and other uv projects inside the checkout.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
EVALS = ROOT / "evals"
# Members of the root uv workspace (pyproject.toml [tool.uv.workspace]); they share uv.lock.
APP_MEMBERS = (ROOT / "packages" / "policyops", ROOT / "packages" / "policyops_contracts")
# uv option -> environment variable uv reads when the option is absent.
UV_PATH_OPTIONS = {"--directory": "UV_WORKING_DIR", "--project": "UV_PROJECT"}
# Subcommands whose trailing arguments belong to a child command.
UV_CHILD_COMMANDS = {"run", "tool"}


class EnvironmentErrorReport(Exception):
    """The requested environment would violate the containment rules."""


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def temp_root(base: Mapping[str, str]) -> Path:
    raw = base.get("POLICYOPS_TEMP_DIR", "").strip()
    if not raw:
        raise EnvironmentErrorReport("POLICYOPS_TEMP_DIR is not set")
    root = Path(raw)
    if not root.is_absolute():
        raise EnvironmentErrorReport("POLICYOPS_TEMP_DIR must be an absolute path")
    resolved = root.resolve()
    if _inside(resolved, ROOT):
        raise EnvironmentErrorReport("POLICYOPS_TEMP_DIR must be outside the repository")
    return resolved


def uv_path_options(argv: Sequence[str]) -> dict[str, str]:
    """--directory/--project given to uv itself; reject forms that cannot be read reliably."""
    if not argv or Path(argv[0]).stem.lower() != "uv":
        return {}
    args = list(argv[1:])
    if "--" in args:
        args = args[: args.index("--")]
    values: dict[str, str] = {}
    subcommand = None
    index = 0
    while index < len(args):
        name, separator, value = args[index].partition("=")
        if name in UV_PATH_OPTIONS or name == "--active":
            if subcommand in UV_CHILD_COMMANDS:
                raise EnvironmentErrorReport(
                    f"uv {subcommand}: {name} may belong to the child command; pass it before `{subcommand}` "
                    "and separate the child command with --")
            if name == "--active":
                raise EnvironmentErrorReport("uv --active would bypass the routed project environment")
            if not separator:
                index += 1
                if index == len(args):
                    raise EnvironmentErrorReport(f"uv {name} needs a value")
                value = args[index]
            if name in values:
                raise EnvironmentErrorReport(f"uv {name} given more than once")
            values[name] = value
        elif subcommand is None:
            if name.startswith("-"):
                raise EnvironmentErrorReport(
                    f"uv option {name} before the subcommand is not supported here; place it after the subcommand")
            subcommand = name
        index += 1
    return values


def uv_target(base: Mapping[str, str], argv: Sequence[str], cwd: Path) -> Path:
    """Directory uv will start project discovery from (command-line options override environment)."""
    values = uv_path_options(argv)
    for option, variable in UV_PATH_OPTIONS.items():
        if option not in values and variable in base:
            values[option] = base[variable]
    for option, value in values.items():
        if not value:
            raise EnvironmentErrorReport(f"uv {option} needs a value")
    directory = cwd / values.get("--directory", ".")
    return (directory / values.get("--project", ".")).resolve()


def project_root(target: Path) -> Path:
    """The uv project (ROOT or EVALS) whose lock discovery from target selects."""
    for directory in (target, *target.parents):
        if directory in (ROOT, EVALS):
            return directory
        if (directory / "pyproject.toml").is_file() and directory not in APP_MEMBERS:
            raise EnvironmentErrorReport(f"{directory} is a separate uv project; only the root and evals/ are routed")
    raise EnvironmentErrorReport(f"command targets {target}, outside this repository")


def build_environment(base: Mapping[str, str], argv: Sequence[str], cwd: Path) -> dict[str, str]:
    root = temp_root(base)
    project = project_root(uv_target(base, argv, cwd))
    tmp = root / "tmp"
    paths = {
        "TEMP": tmp,
        "TMP": tmp,
        "TMPDIR": tmp,
        "UV_CACHE_DIR": root / "cache" / "uv",
        "UV_PYTHON_INSTALL_DIR": root / "tools" / "uv-python",
        # A matched pair: uv may only sync this project's lock into this venv.
        "UV_PROJECT": project,
        "UV_PROJECT_ENVIRONMENT": root / "venvs" / ("evals" if project == EVALS else "app"),
        "RUFF_CACHE_DIR": root / "cache" / "ruff",
        "MYPY_CACHE_DIR": root / "cache" / "mypy",
        "COVERAGE_FILE": root / "reports" / "coverage" / ".coverage",
        "npm_config_cache": root / "cache" / "npm",
        "POLICYOPS_WEB_BUILD_DIR": root / "build" / "web",
        "POLICYOPS_WEB_CACHE_DIR": root / "cache" / "vite",
        "POLICYOPS_REPORT_DIR": root / "reports",
        # Per-user application data (e.g. Vitest's API token file): Windows reads
        # LOCALAPPDATA, Linux XDG_DATA_HOME. macOS uses ~/Library and is not routed.
        "LOCALAPPDATA": root / "user-data",
        "XDG_DATA_HOME": root / "user-data",
    }
    env = dict(base)
    env.update({name: str(path) for name, path in paths.items()})
    env.update(
        POLICYOPS_TEMP_DIR=str(root),
        PYTHONDONTWRITEBYTECODE="1",
        # uv-managed CPython, without user bin shims or Windows registry entries.
        UV_PYTHON_PREFERENCE="only-managed",
        UV_PYTHON_INSTALL_BIN="0",
        UV_PYTHON_INSTALL_REGISTRY="0",
        npm_config_update_notifier="false",
        npm_config_fund="false",
        # tau2 calls load_dotenv() at import; never pull a developer .env (and its
        # keys) into the evaluator implicitly.
        PYTHON_DOTENV_DISABLED="1",
        # litellm otherwise downloads a remote pricing map during import.
        LITELLM_LOCAL_MODEL_COST_MAP="True",
    )
    for name in ("TEMP", "UV_CACHE_DIR", "COVERAGE_FILE", "npm_config_cache", "LOCALAPPDATA"):
        target = Path(env[name])
        (target.parent if name == "COVERAGE_FILE" else target).mkdir(parents=True, exist_ok=True)
    return env


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print-env", action="store_true", help="print the overridden variables first")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")
    try:
        env = build_environment(os.environ, command, Path.cwd())
    except EnvironmentErrorReport as exc:
        print(f"devenv: {exc}", file=sys.stderr)
        return 2
    if args.print_env:
        for name in sorted(k for k in env if os.environ.get(k) != env[k]):
            print(f"{name}={env[name]}")
    executable = shutil.which(command[0], path=env.get("PATH"))
    if executable is None:
        print(f"devenv: command not found: {command[0]}", file=sys.stderr)
        return 127
    return subprocess.run([executable, *command[1:]], env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main())
