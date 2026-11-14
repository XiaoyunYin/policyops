"""Process-local environment routing; standard library only."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "devenv.py"
REPO = SCRIPT.parents[1]
EVALS = REPO / "evals"
RERANKER = REPO / "reranker"
# Virtual environment directory per selected project (isolated projects are versioned).
VENV_NAMES = {"app": "app", "evals": "evals-raw-v1", "reranker": "reranker-raw-v1"}
_spec = importlib.util.spec_from_file_location("policyops_devenv", SCRIPT)
assert _spec is not None and _spec.loader is not None
devenv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(devenv)
UV = os.environ.get("UV") or shutil.which("uv")
TREE = ["tree", "--frozen", "--offline", "--depth", "0"]
UV_LOCATION_VARIABLES = ("UV_PROJECT", "UV_WORKING_DIR", "VIRTUAL_ENV")


def tree_project(stdout: str) -> str | None:
    if "policyops-evals v" in stdout:
        return "evals"
    return "app" if "policyops v" in stdout else None


class DevenvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="policyops-devenv-", dir=os.environ.get("POLICYOPS_TEMP_DIR"),
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.base = {"POLICYOPS_TEMP_DIR": str(self.root), "PATH": os.environ.get("PATH", "")}

    def env_for(self, argv: list[str], cwd: Path = REPO) -> dict[str, str]:
        result: dict[str, str] = devenv.build_environment(self.base, argv, cwd)
        return result

    def test_all_routed_paths_are_under_temp_root(self) -> None:
        env = self.env_for(["uv", "sync", "--frozen"])
        for name in ("TEMP", "TMP", "TMPDIR", "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR",
                     "UV_PROJECT_ENVIRONMENT", "RUFF_CACHE_DIR", "MYPY_CACHE_DIR", "TIKTOKEN_CACHE_DIR",
                     "COVERAGE_FILE", "npm_config_cache", "POLICYOPS_WEB_BUILD_DIR", "POLICYOPS_WEB_CACHE_DIR",
                     "LOCALAPPDATA", "XDG_DATA_HOME"):
            with self.subTest(name=name):
                self.assertIn(self.root, Path(env[name]).parents)
        self.assertEqual(Path(env["TIKTOKEN_CACHE_DIR"]), self.root / "cache" / "tiktoken")
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(env["PYTHON_DOTENV_DISABLED"], "1")
        self.assertEqual(env["LITELLM_LOCAL_MODEL_COST_MAP"], "True")
        self.assertEqual(env["PYTHONUTF8"], "1")
        self.assertEqual(env["UV_PYTHON_INSTALL_REGISTRY"], "0")
        self.assertEqual(env["UV_PYTHON_INSTALL_BIN"], "0")
        self.assertEqual(Path(env["UV_PROJECT"]), REPO)

    def test_evaluator_uses_its_own_versioned_cache_and_venv(self) -> None:
        app = self.env_for(["uv", "sync", "--frozen"])
        evals = self.env_for(["uv", "sync", "--project", "evals", "--frozen"])
        self.assertEqual(Path(app["UV_CACHE_DIR"]), self.root / "cache" / "uv")
        self.assertEqual(Path(app["UV_PROJECT_ENVIRONMENT"]), self.root / "venvs" / "app")
        self.assertEqual(Path(evals["UV_CACHE_DIR"]), self.root / "cache" / "uv-evals-raw-v1")
        self.assertEqual(Path(evals["UV_PROJECT_ENVIRONMENT"]), self.root / "venvs" / "evals-raw-v1")
        self.assertEqual((evals["GIT_CONFIG_KEY_0"], evals["PYTHONUTF8"]), ("core.autocrlf", "1"))

    def test_git_children_never_convert_line_endings(self) -> None:
        env = self.env_for(["uv", "sync", "--frozen"])
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual((env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]), ("core.autocrlf", "false"))

    def test_reranker_resolution_uses_its_own_versioned_cache_and_venv(self) -> None:
        cases: tuple[tuple[list[str], Path, dict[str, str]], ...] = (
            (["uv", "--project", "reranker", "sync"], REPO, {}),
            (["uv", "sync", "--project=reranker"], REPO, {}),
            (["uv", "--directory", "reranker", "sync"], REPO, {}),
            (["uv", "--directory=reranker", "--project", "src", "sync"], REPO, {}),
            (["uv", "sync"], RERANKER, {}),
            (["uv", "sync"], REPO, {"UV_PROJECT": "reranker"}),
            (["uv", "sync"], REPO, {"UV_WORKING_DIR": "reranker"}),
        )
        for argv, cwd, variables in cases:
            with self.subTest(argv=argv, cwd=cwd, variables=variables):
                env = devenv.build_environment({**self.base, **variables}, argv, cwd)
                self.assertEqual(Path(env["UV_PROJECT"]), RERANKER)
                self.assertEqual(Path(env["UV_PROJECT_ENVIRONMENT"]), self.root / "venvs" / "reranker-raw-v1")
                self.assertEqual(Path(env["UV_CACHE_DIR"]), self.root / "cache" / "uv-reranker-raw-v1")
        app = self.env_for(["uv", "--directory", "reranker", "--project", "..", "sync"])
        self.assertEqual(Path(app["UV_PROJECT_ENVIRONMENT"]).name, "app")

    def test_git_config_overrides_append_to_existing_entries(self) -> None:
        self.base.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="user.name", GIT_CONFIG_VALUE_0="x")
        env = self.env_for(["uv", "sync", "--frozen"])
        self.assertEqual(env["GIT_CONFIG_COUNT"], "2")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "user.name")
        self.assertEqual((env["GIT_CONFIG_KEY_1"], env["GIT_CONFIG_VALUE_1"]), ("core.autocrlf", "false"))
        self.base["GIT_CONFIG_COUNT"] = "many"
        with self.assertRaises(devenv.EnvironmentErrorReport):
            self.env_for(["uv", "sync", "--frozen"])

    def test_inherited_cache_settings_are_overridden(self) -> None:
        self.base["UV_CACHE_DIR"] = str(REPO / ".cache")
        self.base["TEMP"] = str(REPO)
        env = self.env_for(["uv", "sync"])
        self.assertIn(self.root, Path(env["UV_CACHE_DIR"]).parents)
        self.assertIn(self.root, Path(env["TEMP"]).parents)

    def test_user_data_directory_is_routed_and_created_before_the_command(self) -> None:
        # Regression: Vitest wrote its API token to the caller's LOCALAPPDATA/XDG_DATA_HOME.
        inherited = self.root / "inherited-user-data"
        self.base.update(LOCALAPPDATA=str(inherited), XDG_DATA_HOME=str(inherited))
        env = self.env_for(["npm", "test"])
        user_data = self.root / "user-data"
        self.assertEqual(Path(env["LOCALAPPDATA"]), user_data)
        self.assertEqual(Path(env["XDG_DATA_HOME"]), user_data)
        self.assertTrue(user_data.is_dir())
        self.assertFalse(inherited.exists())

    def test_app_and_evals_never_share_a_virtual_environment(self) -> None:
        cases = {
            ("uv", "sync", "--frozen"): "app",
            ("uv", "run", "pytest"): "app",
            ("uv", "sync", "--project", "evals", "--frozen"): "evals",
            ("uv", "sync", "--project=evals"): "evals",
            ("uv", "--directory", "evals", "run", "pytest"): "evals",
            ("uv", "run", "pytest", "--", "--project", "evals"): "app",
            ("uv", "--project", "evals", "run", "pytest"): "evals",
            ("uv", "--directory", "evals", "--project", "..", "sync"): "app",
            ("uv.exe", "lock", "--project", "evals"): "evals",
            # uv would discover evals/ from the script's directory; the pin keeps it on the app.
            ("uv", "run", "evals/src/policyops_evals/__init__.py"): "app",
            ("npm", "ci"): "app",
        }
        for argv, expected in cases.items():
            with self.subTest(argv=argv):
                env = self.env_for(list(argv))
                self.assertEqual(Path(env["UV_PROJECT_ENVIRONMENT"]).name, VENV_NAMES[expected])
                self.assertEqual(Path(env["UV_PROJECT"]), EVALS if expected == "evals" else REPO)
        from_evals_cwd = self.env_for(["uv", "run", "pytest"], cwd=EVALS)
        self.assertEqual(Path(from_evals_cwd["UV_PROJECT_ENVIRONMENT"]).name, "evals-raw-v1")
        back_to_root = self.env_for(["uv", "sync", "--project", ".."], cwd=EVALS)
        self.assertEqual(Path(back_to_root["UV_PROJECT_ENVIRONMENT"]).name, "app")

    def test_ambiguous_or_unsupported_uv_forms_are_rejected(self) -> None:
        # Regression: the first --project/--directory token won, including a child
        # command's argument that uv passes through (`uv run python ... --project evals`).
        cases = (
            ["uv", "run", "python", "--project", "evals"],
            ["uv", "run", "--project", "evals", "pytest"],
            ["uv", "run", "--directory=evals", "pytest"],
            ["uv", "tool", "run", "ruff", "--directory", "evals"],
            ["uv", "--offline", "--project", "evals", "sync"],
            ["uv", "sync", "--active"],
            ["uv", "sync", "--project", "evals", "--project", "."],
            ["uv", "--project", "evals", "sync", "--project=."],
            ["uv", "sync", "--project"],
            ["uv", "sync", "--project="],
        )
        for argv in cases:
            with self.subTest(argv=argv), self.assertRaises(devenv.EnvironmentErrorReport):
                self.env_for(argv)
        for variable in ("UV_PROJECT", "UV_WORKING_DIR"):
            with self.subTest(variable=variable), self.assertRaises(devenv.EnvironmentErrorReport):
                devenv.build_environment({**self.base, variable: ""}, ["uv", "sync"], REPO)

    def test_rejected_uv_form_never_starts_the_command(self) -> None:
        env = {**os.environ, "POLICYOPS_TEMP_DIR": str(self.root)}
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "uv", "run", "python", "--project", "evals"],
            cwd=REPO, env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("may belong to the child command", result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_other_uv_projects_inside_the_checkout_are_rejected(self) -> None:
        checkout = self.root / "checkout"
        for project in ("", "evals/", "reranker/", "tools/other/", "evals/other/", "reranker/other/"):
            (checkout / project).mkdir(parents=True, exist_ok=True)
            (checkout / project / "pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
        with mock.patch.multiple(
            devenv, ROOT=checkout, EVALS=checkout / "evals", RERANKER=checkout / "reranker", APP_MEMBERS=(),
        ):
            for project in ("tools/other", "evals/other", "reranker/other"):
                for suffix in ("", "/src"):
                    for option in ("--project", "--directory"):
                        with (
                            self.subTest(project=project, suffix=suffix, option=option),
                            self.assertRaises(devenv.EnvironmentErrorReport),
                        ):
                            devenv.build_environment(self.base, ["uv", option, project + suffix, "sync"], checkout)
            env = devenv.build_environment(self.base, ["uv", "sync", "--project", "tools"], checkout)
            self.assertEqual(Path(env["UV_PROJECT_ENVIRONMENT"]).name, "app")

    def test_app_members_match_the_workspace_definition(self) -> None:
        pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        members = pyproject["tool"]["uv"]["workspace"]["members"]
        self.assertEqual(devenv.APP_MEMBERS, tuple(REPO / member for member in members))

    def test_rejects_missing_relative_or_repository_temp_root(self) -> None:
        for value in ("", "relative/temp", str(REPO), str(REPO / "tmp")):
            with self.subTest(value=value), self.assertRaises(devenv.EnvironmentErrorReport):
                devenv.build_environment({"POLICYOPS_TEMP_DIR": value}, ["uv", "sync"], REPO)

    def test_rejects_command_targeting_outside_repository(self) -> None:
        with self.assertRaises(devenv.EnvironmentErrorReport):
            self.env_for(["uv", "sync", "--project", str(self.root)])

    def test_cli_runs_child_with_routed_environment_and_propagates_exit_code(self) -> None:
        env = {**os.environ, "POLICYOPS_TEMP_DIR": str(self.root)}
        code = "import os,sys,tempfile; print(tempfile.gettempdir()); sys.exit(7)"
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), sys.executable, "-c", code],
            cwd=REPO, env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(Path(result.stdout.strip()).resolve(), self.root / "tmp")

    def test_cli_fails_closed_without_temp_root(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "POLICYOPS_TEMP_DIR"}
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), sys.executable, "-c", "print('ran')"],
            cwd=REPO, env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("ran", result.stdout)


class RealUvSelectionTests(unittest.TestCase):
    """The selected venv must match the project the real uv resolves for the same
    command line. `uv tree --frozen --offline` reads the lock without installing."""

    def setUp(self) -> None:
        if UV is None:
            raise AssertionError("uv executable not found; these tests compare against the real uv")
        self.uv = UV
        temp = tempfile.TemporaryDirectory(prefix="policyops-devenv-uv-", dir=os.environ.get("POLICYOPS_TEMP_DIR"))
        self.addCleanup(temp.cleanup)
        self.never_created = Path(temp.name) / "venv"
        # Shared caches and the managed interpreter come from the real temp root.
        self.base = {k: v for k, v in os.environ.items() if k not in UV_LOCATION_VARIABLES}

    def test_reranker_is_a_standalone_project_without_resolving_dependencies(self) -> None:
        # `uv version` reads project metadata without a lock, downloads or installs.
        # G8 phase 1 deliberately leaves the lock for the coordinator to resolve.
        cases = (
            (["--project", "reranker", "version", "--offline"], REPO),
            (["--directory", "reranker", "version", "--offline"], REPO),
            (["version", "--offline"], RERANKER),
        )
        for args, cwd in cases:
            with self.subTest(args=args, cwd=cwd):
                env = devenv.build_environment(self.base, ["uv", *args], cwd)
                self.assertEqual(Path(env["UV_PROJECT_ENVIRONMENT"]).name, VENV_NAMES["reranker"])
                env["UV_PROJECT_ENVIRONMENT"] = str(self.never_created)
                result = subprocess.run([self.uv, *args], cwd=cwd, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "policyops-reranker 0.1.0")
        self.assertFalse(self.never_created.exists())

    def test_selected_venv_matches_project_uv_resolves(self) -> None:
        cases: tuple[tuple[list[str], Path, dict[str, str], str], ...] = (
            (TREE, REPO, {}, "app"),
            (["--project", "evals", *TREE], REPO, {}, "evals"),
            (["--project=evals", *TREE], REPO, {}, "evals"),
            # Regression: --directory was taken as the target, ignoring --project resolved within it.
            (["--directory", "evals", "--project", "..", *TREE], REPO, {}, "app"),
            (["--project", "..", "--directory", "evals", *TREE], REPO, {}, "app"),
            ([*TREE, "--directory", "evals", "--project", ".."], REPO, {}, "app"),
            (["--directory", "evals", *TREE], REPO, {}, "evals"),
            (TREE, EVALS, {}, "evals"),
            (["--project", "..", *TREE], EVALS, {}, "app"),
            (["--project", "evals/src", *TREE], REPO, {}, "evals"),
            (["--project", "packages/policyops", *TREE], REPO, {}, "app"),
            (TREE, REPO, {"UV_PROJECT": "evals"}, "evals"),
            (["--project", ".", *TREE], REPO, {"UV_PROJECT": "evals"}, "app"),
            (["--project", "..", *TREE], REPO, {"UV_WORKING_DIR": "evals"}, "app"),
        )
        for args, cwd, variables, expected in cases:
            with self.subTest(args=args, cwd=cwd.name, variables=variables):
                env = devenv.build_environment({**self.base, **variables}, ["uv", *args], cwd)
                self.assertEqual(Path(env["UV_PROJECT_ENVIRONMENT"]).name, VENV_NAMES[expected])
                env["UV_PROJECT_ENVIRONMENT"] = str(self.never_created)
                result = subprocess.run([self.uv, *args], cwd=cwd, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(tree_project(result.stdout), expected, result.stdout)
        self.assertFalse(self.never_created.exists())

    def test_nested_uv_follows_the_pinned_project(self) -> None:
        # devenv cannot parse uv calls made by a child, so it pins UV_PROJECT next to
        # UV_PROJECT_ENVIRONMENT; a nested uv started inside evals/ must stay on the app.
        code = (
            "import os, subprocess, sys; "
            "r = subprocess.run([sys.argv[1], *sys.argv[2:]], cwd='evals', capture_output=True, text=True); "
            "print(os.path.basename(os.environ['UV_PROJECT_ENVIRONMENT'])); print(r.stdout)"
        )
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), sys.executable, "-c", code, self.uv, *TREE],
            cwd=REPO, env=self.base, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        venv, _, tree = result.stdout.partition("\n")
        self.assertEqual(venv.strip(), "app")
        self.assertEqual(tree_project(tree), "app", tree)


if __name__ == "__main__":
    unittest.main()
