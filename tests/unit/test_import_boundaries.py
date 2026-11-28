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
    "policyops.persistence.database", "policyops.persistence.embeddings", "policyops.persistence.retrieval",
    "policyops.retrieval.rank",  # G0.4 composes runtime-role snapshots and the existing embedding/cache path.
    "policyops.retrieval.rerank",  # G0.4b reuses T14's bounded input/schema and deterministic ordering.
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
    "qa_studies/runner.py",
    "qa_studies/answers.py",
    "qa_studies/g8_mining.py",
}
EVAL_TEST_ONLY_IMPORTS = {"policyops.persistence.database", "policyops.persistence.roles",
                          "policyops.retrieval.ingest"}  # G0.4 real structural-corpus integration fixture.

# N2-S1 uses the workbench service and worker with its own local operator profile.
SCENARIO_IMPORTS = {
    "src/policyops_evals/scenarios/cli.py": {
        "policyops.persistence.database", "policyops.persistence.roles", "policyops.providers.tokenizer",
        "policyops.persistence.evaluation",
    },
    "src/policyops_evals/scenarios/grading.py": {
        "policyops.providers.canonical", "policyops.orchestration.investigation_prompt",
        "policyops.orchestration.minimal",
    },
    "src/policyops_evals/scenarios/recording.py": {"policyops.providers.results", "policyops.providers.transport"},
    "src/policyops_evals/scenarios/runtime.py": {
        # N3 composes the P1 profile through the same workbench entry point.
        "policyops.gateway.ports", "policyops.orchestration.profile",
        "policyops.adapters.retail_client", "policyops.auth.service", "policyops.budget.config",
        "policyops.domain.roles", "policyops.persistence.database", "policyops.persistence.records",
        "policyops.persistence.repositories", "policyops.persistence.runs", "policyops.providers.calls",
        "policyops.providers.contract", "policyops.providers.tokenizer", "policyops.retrieval.parse",
        "policyops.runtime.clock", "policyops.runtime.investigation", "policyops.runtime.spec",
        "policyops.runtime.worker", "policyops.services.runs",
        "policyops.domain.retail_rules",  # N15 reduces the policy decision to an allowed flag.
        "policyops.gateway.steps",  # N15 receives the typed write result at the runtime boundary.
    },
    # N13 drives the real proposal, review and execution services from the local acceptance harness.
    "src/policyops_evals/scenarios/n13_acceptance.py": {
        "policyops", "policyops.adapters.retail_client", "policyops.auth.service", "policyops.domain.roles",
        "policyops.orchestration.profile", "policyops.persistence", "policyops.persistence.database",
        "policyops.persistence.records", "policyops.providers.tokenizer", "policyops.runtime.clock",
        "policyops.runtime.review", "policyops.runtime.spec", "policyops.runtime.worker", "policyops.services.cases",
        "policyops.services.decisions", "policyops.services.proposal_views", "policyops.settings",
        "policyops.telemetry.sdk",
    },
    # The private replay uses the production target predicate and customer-source parser.
    "src/policyops_evals/scenarios/n13_replay.py": {"policyops.domain.retail_rules", "policyops.gateway.stores"},
    "tests/test_scenario_n13.py": {"policyops.providers.results", "policyops.providers.serialize",
                                  "policyops.providers.tokenizer", "policyops.providers.tools"},
    "tests/test_scenario_n13_pg.py": {
        "policyops.adapters.retail_client", "policyops.domain.retail_rules", "policyops.domain.session",
        "policyops.gateway.facts", "policyops.gateway.ports", "policyops.gateway.steps",
        "policyops.persistence.database", "policyops.runtime.clock",
    },
    "src/policyops_evals/scenarios/n15_canary.py": {
        "policyops.api.logging",  # Apply the shared allowlisted JSON formatter on the canary host.
        "policyops.persistence.roles",  # Open the disposable app database with runtime and auth roles.
        "policyops.providers.tokenizer",  # Count scripted request tokens with the pinned app vocabulary.
        "policyops.settings",  # Validate canary OTLP settings before configuring the exporter.
        "policyops.telemetry",  # Start the opt-in canary telemetry backend through its facade.
    },
    "src/policyops_evals/scenarios/n15_scorer.py": {
        "policyops.telemetry",  # Publish window metrics through the application facade.
        "policyops.telemetry.attributes",  # Share the registered metric names and closed label sets.
    },
    "tests/test_scenario_n15.py": {
        "policyops.providers.tokenizer",  # Exercise the scripted transport with the pinned tokenizer.
        "policyops.settings",  # Configure the telemetry backend for the in-memory contract test.
        "policyops.telemetry",  # Verify metric publication and filtering through the facade.
        "policyops.telemetry.attributes",  # Check the exported gauge series against their registered label sets.
        "policyops.telemetry.sdk",  # Inspect the memory exporter's actual OTel metrics.
    },
    "tests/test_scenario_n15_pg.py": {
        "policyops.runtime.worker",  # Verify canary slots never invoke the worker discovery path.
    },
    "src/policyops_evals/scenarios/setup.py": {
        "policyops.persistence.database", "policyops.persistence.migrate", "policyops.persistence.records",
        "policyops.persistence.repositories", "policyops.persistence.roles", "policyops.providers.calls",
        "policyops.providers.tokenizer", "policyops.retrieval.ingest",
    },
    # N2-S2/S3: labels are proven with the deterministic retail rules and session binding; the grader reads the
    # graph and minimal-agent control-tool constants so it parses exactly what the agent emitted.
    "src/policyops_evals/scenarios/generator.py": {"policyops.domain.retail_rules", "policyops.domain.session"},
    # N2-S4/S5: registration, slot fencing and ledger reconciliation reuse the evaluation, budget, record and
    # checkpoint persistence APIs; the study binds the runtime/prompt digests it registers.
    "src/policyops_evals/scenarios/batch.py": {
        "policyops.persistence", "policyops.persistence.checkpoints", "policyops.persistence.database",
        "policyops.persistence.evaluation", "policyops.persistence.records",
    },
    "src/policyops_evals/scenarios/reporting.py": {"policyops.budget.config"},
    "src/policyops_evals/scenarios/study.py": {
        "policyops.orchestration", "policyops.persistence.budget", "policyops.persistence.evaluation",
        "policyops.persistence.records", "policyops.retrieval.parse", "policyops.runtime.investigation",
    },
    # N3 binds the P1 runtime, prompt, catalog, tokenizer and diagnostics in each arm.
    "src/policyops_evals/scenarios/arms.py": {
        "policyops.orchestration", "policyops.orchestration.profile", "policyops.providers.tokenizer",
        "policyops.providers.tool_diagnostics", "policyops.runtime.investigation", "policyops.runtime.spec",
    },
    # N3 uses evaluation receipts and the existing retrieval chunk identity.
    "src/policyops_evals/scenarios/n3.py": {
        "policyops.persistence.budget", "policyops.persistence.evaluation", "policyops.persistence.records",
        "policyops.retrieval.parse",
    },
    # The N3 CLI opens the evaluation receipt store and binds each app runtime spec before dispatch.
    "src/policyops_evals/scenarios/n3_cli.py": {"policyops.persistence.evaluation", "policyops.runtime.spec"},
    # The rolling runner validates exact app-ledger amounts and pins the dispatched runtime spec.
    "src/policyops_evals/scenarios/n3_runner.py": {"policyops.persistence.records", "policyops.runtime.spec"},
    # N3 offline tests exercise the P1 prompt composition and reference spec preflight.
    "tests/test_scenario_n3.py": {"policyops.orchestration", "policyops.providers.tokenizer"},
    # The N3 PostgreSQL restart test verifies the real runtime spec and app ledger binding.
    "tests/test_scenario_runtime.py": {"policyops.orchestration", "policyops.runtime.investigation",
                                       "policyops.runtime.spec"},
    # The lock hashes the registered profiles. The scripted gate observes gateway dispatch and persisted stops.
    "src/policyops_evals/scenarios/lock.py": {"policyops.orchestration.profile", "policyops.providers.tokenizer"},
    "tests/scenario_support.py": {"policyops.providers.tokenizer"},
    # The local driver smoke verifies the application v1 schema in the memory exporter.
    "tests/test_observability_demo.py": {"policyops.settings", "policyops.telemetry", "policyops.telemetry.sdk"},
    "tests/test_scenario_gate.py": {"policyops.gateway.steps", "policyops.orchestration",
                                    "policyops.orchestration.adapters", "policyops.orchestration.profile",
                                    "policyops.persistence"},
    # N18 reads the same durable timestamps as the live recorder and instruments only the bound runtime.
    "src/policyops_evals/run_latency.py": {
        "policyops.orchestration.profile", "policyops.persistence.database", "policyops.persistence.runs",
        "policyops.runtime.investigation", "policyops.runtime.live_agent", "policyops.runtime.spec",
    },
    "tests/test_typed_scenario_gate.py": {
        "policyops.orchestration", "policyops.orchestration.adapters", "policyops.orchestration.profile",
        "policyops.persistence", "policyops.persistence.database",
    },
    "tests/test_scenario_lock.py": {"policyops.orchestration", "policyops.orchestration.profile",
                                    "policyops.providers.tokenizer", "policyops.providers.tool_diagnostics"},
    # N7 composes the locked workbench with cache-aware reservations and audits live app ledger rows.
    "src/policyops_evals/scenarios/n7.py": {
        "policyops.budget.prices", "policyops.orchestration", "policyops.persistence.budget",
        "policyops.persistence.evaluation", "policyops.persistence.records", "policyops.providers.canonical",
        "policyops.providers.serialize", "policyops.providers.tokenizer", "policyops.retrieval.parse",
    },
    "src/policyops_evals/scenarios/n7_cli.py": {"policyops.persistence.evaluation", "policyops.runtime.spec"},
    "src/policyops_evals/scenarios/n7_report.py": {
        "policyops.budget.config", "policyops.orchestration.minimal", "policyops.persistence.database",
        "policyops.providers.canonical",
    },
    "tests/test_scenario_n7.py": {"policyops.orchestration", "policyops.providers.serialize"},
    # N8 reuses the N7 registration and request bindings, wraps the scoped RetailPort through bind_spec, seeds a
    # staff-note case message through the runtime's repository seed path and joins persisted outcomes read-only.
    "src/policyops_evals/scenarios/n8.py": {
        "policyops.budget.prices", "policyops.orchestration", "policyops.persistence.budget",
        "policyops.persistence.evaluation", "policyops.persistence.records", "policyops.providers.canonical",
        "policyops.providers.serialize", "policyops.providers.tokenizer", "policyops.retrieval.parse",
    },
    "src/policyops_evals/scenarios/n8_cli.py": {"policyops.persistence.evaluation", "policyops.runtime.spec"},
    "src/policyops_evals/scenarios/n8_grading.py": {"policyops.orchestration.investigation_prompt",
                                                     "policyops.providers.canonical"},
    "src/policyops_evals/scenarios/n8_port.py": {
        "policyops.adapters.retail_client", "policyops.gateway.ports", "policyops.persistence.database",
        "policyops.persistence.records", "policyops.persistence.repositories", "policyops.runtime.clock",
        "policyops.runtime.investigation", "policyops.runtime.spec",
    },
    "src/policyops_evals/scenarios/n8_report.py": {"policyops.persistence.database", "policyops.runtime.spec"},
    # The offline carrier test compares real gateway fact collection with and without the label wrapper.
    "tests/test_scenario_n8.py": {"policyops.adapters.retail_client", "policyops.gateway.facts",
                                  "policyops.gateway.ports"},
    # The PostgreSQL negative control writes another run's handoff message through the trusted seed path.
    "tests/test_scenario_n8_pg.py": {"policyops.persistence.repositories", "policyops.runtime.spec"},
    # N18 consumes existing offline wire diagnostics, receipt hashes, review evidence views and pinned rates.
    "src/policyops_evals/scenarios/n18_cache.py": {"policyops.budget.prices"},
    "src/policyops_evals/scenarios/n18_diagnosis.py": {
        "policyops.orchestration.investigation_prompt", "policyops.orchestration.mechanics",
        "policyops.persistence.evaluation", "policyops.providers.tool_diagnostics", "policyops.providers.tools",
        "policyops.retrieval.grounding", "policyops.services.run_reads",
    },
    "src/policyops_evals/scenarios/n18_evidence.py": {"policyops.persistence.evaluation"},
    "src/policyops_evals/scenarios/proposal_grading.py": {"policyops.services.run_reads"},
    "tests/test_scenario_n18.py": {"policyops.domain.examples", "policyops.domain.retail_rules",
                                   "policyops.providers.tool_diagnostics", "policyops.services.run_reads"},
}


@pytest.mark.parametrize("subdir", ["src", "tests"])
def test_evaluator_application_imports_are_limited_to_composition(subdir: str) -> None:
    violations = [
        (str(path.relative_to(REPO)), module)
        for path, module in imported_modules(EVALS / subdir)
        if module.split(".")[0] == "policyops"
        and module not in SCENARIO_IMPORTS.get(path.relative_to(EVALS).as_posix(), ())
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
