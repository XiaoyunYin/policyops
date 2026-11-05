"""Static dependency-direction checks between packages and projects."""

import ast
from collections.abc import Iterator
from pathlib import Path
import sys
import tomllib

import pytest


REPO = Path(__file__).resolve().parents[2]
APP = REPO / "packages" / "policyops" / "src" / "policyops"
CONTRACTS = REPO / "packages" / "policyops_contracts"
EVALS = REPO / "evals"

FRAMEWORKS = {
    "fastapi", "starlette", "uvicorn", "sqlalchemy", "alembic", "psycopg", "langgraph",
    "langchain_core", "openai", "anthropic", "httpx", "litellm", "tau2",
}
DOMAIN_FORBIDDEN_LAYERS = {
    "policyops.api", "policyops.persistence", "policyops.adapters", "policyops.orchestration",
    "policyops.worker", "policyops.services", "policyops.retrieval",
}


def imported_modules(root: Path) -> Iterator[tuple[Path, str]]:
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield path, alias.name
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                yield path, node.module


def matches(module: str, prefixes: set[str]) -> bool:
    return any(module == prefix or module.startswith(prefix + ".") for prefix in prefixes)


def test_domain_imports_no_framework_or_outer_layer() -> None:
    violations = [
        (str(path.relative_to(REPO)), module)
        for path, module in imported_modules(APP / "domain")
        if matches(module, FRAMEWORKS | DOMAIN_FORBIDDEN_LAYERS)
    ]
    assert violations == []


def test_contracts_import_only_stdlib_and_pydantic() -> None:
    allowed = set(sys.stdlib_module_names) | {"pydantic", "policyops_contracts"}
    violations = [
        (str(path.relative_to(REPO)), module)
        for path, module in imported_modules(CONTRACTS / "src")
        if module.split(".")[0] not in allowed
    ]
    assert violations == []


def test_contracts_declare_only_pydantic() -> None:
    project = tomllib.loads((CONTRACTS / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert [dep.split(">")[0].split("=")[0].strip() for dep in project["dependencies"]] == ["pydantic"]


@pytest.mark.parametrize("subdir", ["src", "tests"])
def test_evaluator_never_imports_application_package(subdir: str) -> None:
    violations = [
        (str(path.relative_to(REPO)), module)
        for path, module in imported_modules(EVALS / subdir)
        if module.split(".")[0] == "policyops"
    ]
    assert violations == []


def test_evaluator_project_does_not_depend_on_application() -> None:
    project = tomllib.loads((EVALS / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    names = {dep.split("[")[0].split(">")[0].split("=")[0].split("@")[0].strip()
             for dep in project["dependencies"]}
    assert "policyops" not in names
    assert "policyops-contracts" in names


def test_import_scan_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("import fastapi\nfrom policyops.api import app\n", encoding="utf-8")
    found = [module for _, module in imported_modules(tmp_path)]
    assert found == ["fastapi", "policyops.api"]
    assert all(matches(module, FRAMEWORKS | DOMAIN_FORBIDDEN_LAYERS) for module in found)


def test_budget_rules_import_no_provider_framework_or_database_layer() -> None:
    """Pricing, configuration, ledger rules and preflight stay pure: no SDK, HTTP or SQL; the stores live in
    `persistence.budget`. (`persistence.records` is plain pydantic, for the shared exact-USD check.)"""
    outer = {"policyops.api", "policyops.runtime", "policyops.persistence.budget", "policyops.persistence.database",
             "policyops.persistence.repositories", "policyops.persistence.runs"}
    violations = [
        (str(path.relative_to(REPO)), module)
        for path, module in imported_modules(APP / "budget")
        if matches(module, FRAMEWORKS | outer)
    ]
    assert violations == []
