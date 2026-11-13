"""Adversarial fixtures for offline publication checks; synthetic credentials only."""

from __future__ import annotations

from importlib import metadata
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import audit_licenses as licenses  # noqa: E402
from scripts import check_build_context as context  # noqa: E402
from scripts import check_bundle as bundle  # noqa: E402


def put(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode())
    return path


def cli(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / script), *args],
                          capture_output=True, text=True, check=False)


def built(root: Path) -> None:
    put(root, "index.html", '<script src="/assets/app.js"></script>')
    put(root, "assets/app.js", 'console.log("public application");')


def test_clean_bundle_and_cli(tmp_path: Path) -> None:
    built(tmp_path)
    assert not bundle.check_bundle(tmp_path)
    assert cli("check_bundle.py", "--bundle", str(tmp_path)).returncode == 0


@pytest.mark.parametrize("payload", [
    "sk-" + "proj-" + "A9bc" * 12,
    "sk-" + "ant-" + "K8yz" * 12,
    "OPENAI_" + "API_KEY", "ANTHROPIC_" + "BASE_URL",
    "POLICYOPS_DB_" + "HOST", "POLICYOPS_OIDC_" + "CLIENT_SECRET",
    "POLICYOPS_" + "MODEL", "api." + "openai.com", "postgresql://" + "example.invalid/database",
    "policyops_" + "app_migrator", 'apiKey: "' + "synthetic-canary-credential" + '"',
    "//# sourceMappingURL=" + "data:application/json;base64,e30=",
    "https://user:" + "synthetic-canary-password" + "@example.invalid/",
])
def test_bundle_detects_leaks_without_echoing_values(tmp_path: Path, payload: str) -> None:
    built(tmp_path)
    put(tmp_path, "assets/app.js", payload)
    failures = bundle.check_bundle(tmp_path)
    assert failures and payload not in "\n".join(failures)
    result = cli("check_bundle.py", "--bundle", str(tmp_path))
    assert result.returncode == 1 and payload not in result.stderr


def test_bundle_refuses_missing_empty_maps_and_oversize(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert bundle.check_bundle(tmp_path)
    assert cli("check_bundle.py", "--bundle", str(tmp_path / "missing")).returncode == 2
    built(tmp_path)
    put(tmp_path, "assets/app.js.map", "{}")
    assert any("source map" in failure for failure in bundle.check_bundle(tmp_path))
    monkeypatch.setattr(bundle, "MAX_FILE_BYTES", 2)
    assert any("scan bound" in failure for failure in bundle.check_bundle(tmp_path))


def context_fixture(root: Path) -> None:
    put(root, ".dockerignore", (ROOT / ".dockerignore").read_text(encoding="utf-8"))
    put(root, "packages/app/src/main.py", "# public source\n")


def test_context_excludes_private_nested_files_and_keeps_sources(tmp_path: Path) -> None:
    context_fixture(tmp_path)
    for name in (".env", "PLAN.md", "apps/web/.env.local", "packages/app/internal/report.md",
                 "packages/app/local.p12", "apps/web/node_modules/pkg/package.json", "infra/state.tfstate",
                 "packages/app/career/BULLETS.md", "packages/app/data/snapshot.json"):
        put(tmp_path, name, "synthetic private canary")
    rules = context.parse_rules((tmp_path / ".dockerignore").read_text(encoding="utf-8"))
    assert context.included("packages/app/src/main.py", rules)
    assert not context.check_context(tmp_path)
    assert cli("check_build_context.py", "--context", str(tmp_path)).returncode == 0


def test_context_probes_missing_private_files_and_detects_reinclusion(tmp_path: Path) -> None:
    context_fixture(tmp_path)
    with (tmp_path / ".dockerignore").open("a", encoding="utf-8") as handle:
        handle.write("\n!packages/**/.env*\n!apps/**/internal/**\n")
    failures = context.check_context(tmp_path)
    assert any(".env" in item for item in failures)
    assert any("internal" in item for item in failures)
    assert cli("check_build_context.py", "--context", str(tmp_path)).returncode == 1


def test_context_rejects_secret_content_and_per_dockerfile_override(tmp_path: Path) -> None:
    context_fixture(tmp_path)
    secret = "sk-" + "proj-" + "X9yz" * 12
    put(tmp_path, "packages/app/config.py", secret)
    put(tmp_path, "app.Dockerfile.dockerignore", "**")
    failures = context.check_context(tmp_path)
    assert any("provider token" in item for item in failures)
    assert any("override" in item for item in failures)
    assert secret not in "\n".join(failures)


@pytest.mark.parametrize("rules", ["!apps/**", "**\n!../outside", "**\n!apps/[ab]", "**\n!apps/**suffix"])
def test_context_fails_closed_on_unsupported_rules(rules: str) -> None:
    with pytest.raises(ValueError):
        context.parse_rules(rules)


def test_dockerignore_glob_order_and_depth() -> None:
    rules = context.parse_rules("**\n!apps/**\n**/.env*\n!apps/public.env\n")
    assert context.included("apps/public.env", rules)
    assert not context.included("apps/nested/.env", rules)
    assert not context.included("apps/.env", rules)
    assert not context.included("outside/file.py", rules)
    assert context.included("apps/src/index.ts", rules)


def test_context_walker_preserves_reopened_descendants(tmp_path: Path) -> None:
    put(tmp_path, ".dockerignore", "**\n!packages/**\npackages/*\n!packages/app/src/**\n")
    source = put(tmp_path, "packages/app/src/main.py", "# public source")
    rules = context.parse_rules((tmp_path / ".dockerignore").read_text(encoding="utf-8"))
    assert source in context.context_paths(tmp_path, rules)
    assert context.included("packages/app/src/main.py", rules)


@pytest.mark.parametrize(("expression", "expected"), [
    ("MIT", "permissive"), ("MIT-0", "permissive"),
    ("Apache-2.0 AND CNRI-Python", "permissive"), ("(MIT OR ISC)", "permissive"),
    ("LGPL-3.0-only", "copyleft-review"), ("MPL-2.0 AND (Apache-2.0 OR MIT)", "copyleft-review"),
    ("MIT OR GPL-3.0-only", "copyleft-review"), ("AGPL-3.0-or-later", "copyleft-review"),
    ("", "unknown"), ("BSD", "unknown"), ("LicenseRef-Custom", "unknown"),
    ("MIT OR", "unknown"), ("(MIT", "unknown"), ("MIT WITH custom-exception", "unknown"),
    ("MIT AND " * 1000, "unknown"),
])
def test_license_policy_flags_copyleft_unknown_and_malformed(expression: str, expected: str) -> None:
    assert licenses.license_policy(expression) == expected


def web_fixture(root: Path, **changes: Any) -> None:
    entry = {"version": "1.0", "license": "MIT"} | changes
    put(root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/pkg": entry}}))
    put(root, "node_modules/pkg/package.json", json.dumps({"name": "pkg", "version": "1.0", "license": "MIT"}))


def test_inventory_reconciles_lock_installed_and_extraneous(tmp_path: Path) -> None:
    web_fixture(tmp_path)
    rows = licenses.web_inventory(tmp_path)
    assert len(rows) == 1 and rows[0]["policy"] == "permissive"
    web_fixture(tmp_path, version="2.0", license="GPL-3.0-only")
    rows = licenses.web_inventory(tmp_path)
    assert {"version-mismatch", "license-mismatch"} <= set(rows[0]["reasons"])
    put(tmp_path, "node_modules/extra/package.json", "{}")
    assert any(row["policy"] == "extraneous-review" for row in licenses.web_inventory(tmp_path))


def test_missing_optional_metadata_stays_in_inventory(tmp_path: Path) -> None:
    web_fixture(tmp_path, optional=True, license="MPL-2.0")
    (tmp_path / "node_modules/pkg/package.json").unlink()
    row = licenses.web_inventory(tmp_path)[0]
    assert row["installed"] is False and row["policy"] == "copyleft-review"
    web_fixture(tmp_path)
    (tmp_path / "node_modules/pkg/package.json").unlink()
    assert "missing-installed-package" in licenses.web_inventory(tmp_path)[0]["reasons"]


def test_inventory_rejects_traversal_and_missing_modules(tmp_path: Path) -> None:
    web_fixture(tmp_path)
    put(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"../outside": {}}}))
    with pytest.raises(ValueError, match="outside"):
        licenses.web_inventory(tmp_path)
    with pytest.raises(FileNotFoundError):
        licenses.web_inventory(tmp_path / "missing")


def test_python_metadata_is_inventoried_without_importing_the_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    put(tmp_path, "canary-1.dist-info/METADATA",
        "Metadata-Version: 2.4\nName: canary\nVersion: 1\nLicense-Expression: LGPL-3.0-only\n")
    put(tmp_path, "legacy-1.dist-info/METADATA",
        "Metadata-Version: 2.4\nName: legacy\nVersion: 1\nClassifier: License :: OSI Approved :: MIT License\n")
    distributions = list(metadata.distributions(path=[str(tmp_path)]))
    monkeypatch.setattr(metadata, "distributions", lambda: distributions)
    rows = licenses.python_inventory()
    assert [row["policy"] for row in rows] == ["copyleft-review", "permissive"]
    assert all(row["metadata_sha256"] for row in rows)


def test_license_cli_refuses_repository_output_and_missing_web(tmp_path: Path) -> None:
    # Rejected before writing, so the source checkout receives no probe.
    assert cli("audit_licenses.py", "--output", str(ROOT / "forbidden.json")).returncode == 2
    assert cli("audit_licenses.py", "--output", str(tmp_path / "report.json"),
               "--web", str(tmp_path / "absent")).returncode == 2
