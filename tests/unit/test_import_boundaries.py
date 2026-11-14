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


# The minimal agent (T20) parses and validates steps itself: no gateway, business adapter, persistence, HTTP,
# worker, runtime, retrieval or framework import (later tasks substitute those behind its ports).
MINIMAL_AGENT_FILES = ("minimal.py", "ports.py")
MINIMAL_AGENT_FORBIDDEN = {
    "policyops.gateway", "policyops.adapters", "policyops.persistence", "policyops.api", "policyops.worker",
    "policyops.services", "policyops.runtime", "policyops.retrieval", "policyops.studies",
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


def test_the_minimal_agent_imports_no_gateway_persistence_or_framework() -> None:
    seen = {path.name for path, _ in imported_modules(APP / "orchestration")}
    assert set(MINIMAL_AGENT_FILES) <= seen
    violations = [
        (str(path.relative_to(REPO)), module)
        for path, module in imported_modules(APP / "orchestration")
        if path.name in MINIMAL_AGENT_FILES and matches(module, FRAMEWORKS | MINIMAL_AGENT_FORBIDDEN)
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


EVAL_COMPOSITION_IMPORTS = {
    "policyops.orchestration.minimal", "policyops.orchestration.ports", "policyops.budget",
    "policyops.providers", "policyops.persistence.budget", "policyops.persistence.evaluation",
    "policyops.runtime.clock",
}
EVAL_COMPOSITION_FILES = {
    "harness/inprocess.py", "harness/actors.py", "studies/config.py", "studies/runner.py",
    # T32 registration/runtime composition and trusted SQL normalization use
    # the existing minimal-agent and ledger APIs. Frozen reporting stays pure.
    "studies/registration.py", "studies/runner_v2.py", "studies/snapshots.py",
    # G0: the dataset builder counts query tokens with the app tokenizer, and the QA contract prices and registers
    # through the existing budget/evaluation ledger APIs (no new application modules).
    "datasets/multidoc2dial.py", "qa_studies/config.py", "qa_studies/registration.py",
    # G6 composes the bounded provider, tokenizer, budget and evaluation registration APIs.
    "qa_studies/judges.py", "qa_studies/calibration.py",
}
EVAL_TEST_ONLY_IMPORTS = {"policyops.persistence.database", "policyops.persistence.roles"}


@pytest.mark.parametrize("subdir", ["src", "tests"])
def test_evaluator_application_imports_are_limited_to_composition(subdir: str) -> None:
    violations = [
        (str(path.relative_to(REPO)), module)
        for path, module in imported_modules(EVALS / subdir)
        if module.split(".")[0] == "policyops"
        and (not matches(module, EVAL_COMPOSITION_IMPORTS | (EVAL_TEST_ONLY_IMPORTS if subdir == "tests" else set())) or
             (subdir == "src" and path.relative_to(EVALS / "src" / "policyops_evals").as_posix()
              not in EVAL_COMPOSITION_FILES))
    ]
    assert violations == []


def test_frozen_reporting_imports_no_application_or_execution_runtime() -> None:
    files = {"reports.py", "report_models.py", "statistics.py", "bundles.py"}
    forbidden = {"policyops", "tau2", "httpx", "httpx2", "psycopg", "sqlalchemy", "subprocess",
                 "policyops_evals.upstream", "policyops_evals.build", "policyops_evals.studies.config",
                 "policyops_evals.studies.runner", "policyops_evals.studies.runner_v2"}
    assert [(path.name, module) for path, module in imported_modules(EVALS / "src/policyops_evals/studies")
            if path.name in files and matches(module, forbidden)] == []


def test_evaluator_declares_local_application_composition_dependency() -> None:
    project = tomllib.loads((EVALS / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    names = {dep.split("[")[0].split(">")[0].split("=")[0].split("@")[0].strip()
             for dep in project["dependencies"]}
    assert "policyops" in names
    assert "policyops-contracts" in names
    config = tomllib.loads((EVALS / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["uv"]["sources"]["policyops"] == {
        "path": "../packages/policyops", "editable": True,
    }


def test_application_never_imports_upstream_or_evaluator() -> None:
    assert [(str(path), module) for path, module in imported_modules(APP)
            if matches(module, {"tau2", "litellm", "policyops_evals"})] == []


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
