"""Offline driver safety tests. Real Docker/browser/recovery acceptance belongs to the coordinator."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock
from uuid import UUID, uuid4
from zipfile import ZipFile

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import compose_drills as drills
from scripts import compose_smoke
from scripts import redact_playwright as traces


ROOT = Path(__file__).resolve().parents[2]


def collection(count: int = 1, tag: str = drills.CONSENT_TAG.removeprefix("@")) -> str:
    return json.dumps({"errors": [], "suites": [{"title": "workbench.spec.ts", "suites": [{
        "title": "nested suite", "specs": [{"title": "customer consent fixture", "tags": [tag],
        "tests": [{"projectName": "chromium"}] * count}]}]}]})


def test_drill_selects_tag_in_full_title_path_and_counts_project_expansion() -> None:
    full_title = "workbench.spec.ts nested suite customer consent fixture " + drills.CONSENT_TAG
    assert re.search(drills.CONSENT_GREP, full_title)
    assert not re.search(drills.CONSENT_GREP, full_title + "-other")
    assert not re.search(drills.CONSENT_GREP, "workbench.spec.ts two real reviewer browsers")
    assert drills.selected_consent_test(collection()) == "customer consent fixture"


@pytest.mark.parametrize("raw", [collection(0), collection(2), collection(tag="@other"),
                               '{"suites":[],"errors":[{"message":"collection failed"}]}'])
def test_drill_refuses_missing_ambiguous_or_failed_collection(raw: str) -> None:
    with pytest.raises(compose_smoke.SmokeError):
        drills.selected_consent_test(raw)


@pytest.mark.parametrize("version,count", [("v22.0.0", 1), (drills.PINNED_NODE, 0), (drills.PINNED_NODE, 2)])
def test_drill_preflight_refuses_to_launch_browser_on_wrong_node_or_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str, count: int,
) -> None:
    driver = drills.Drills(tmp_path, 8080)
    monkeypatch.setattr(shutil, "which", lambda _: "fixture-node")
    calls: list[tuple[str, ...]] = []

    def command(*args: str, **kwargs: Any) -> str:
        calls.append(args)
        if args[-1] == "--version":
            return version
        assert "--list" in args and "--reporter=json" in args
        return collection(count)

    monkeypatch.setattr(driver, "command", command)
    with pytest.raises(compose_smoke.SmokeError):
        driver.browser_approve("kill")
    assert len(calls) == (1 if version != drills.PINNED_NODE else 2)


def test_drill_launches_same_verified_selection_and_pinned_node_after_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = drills.Drills(tmp_path, 8080)
    monkeypatch.setattr(shutil, "which", lambda _: "fixture-node")
    calls: list[tuple[str, ...]] = []
    scenario = {key: str(uuid4()) for key in ("case_id", "run_id", "proposal_id")}

    def command(*args: str, **kwargs: Any) -> str:
        calls.append(args)
        if args[-1] == "--version":
            return drills.PINNED_NODE
        if "--list" in args:
            return collection()
        Path(driver.env["POLICYOPS_E2E_MANIFEST"]).write_text(json.dumps(scenario), encoding="utf-8")
        return ""

    monkeypatch.setattr(driver, "command", command)
    assert driver.browser_approve("kill") == scenario
    assert calls[1][:-2] == calls[2]
    assert calls[2][0] == "fixture-node" and calls[2][-1] == drills.CONSENT_GREP
    assert driver.report["browser_runs"][0]["collected"] == 1


def test_fresh_case_fixture_bindings_survive_worker_refresh_and_reject_unrelated_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = runpy.run_path(str(ROOT / "infra/compose/runtime.py"))
    config = runtime["demo"]()
    run_ids = [uuid4(), uuid4()]
    case_ids = [runtime["browser_case_id"](run_id) for run_id in run_ids]
    assert len(set(case_ids)) == 2 and UUID(config["case_id"]) not in case_ids
    now = datetime.now(UTC)
    rows = [(run_id, case_id, now) for run_id, case_id in zip(run_ids, case_ids, strict=True)]
    rows.append((uuid4(), uuid4(), now))

    class Connection:
        def execute(self, statement: Any, parameters: Any) -> Any:
            assert parameters["w"] == UUID(config["workspace_id"])
            assert parameters["u"] == config["customer_id"]
            return self

        def all(self) -> Any:
            return rows

    @contextmanager
    def transaction(*args: Any) -> Any:
        yield Connection()

    monkeypatch.setattr("policyops.persistence.database.workspace_transaction", transaction)
    monkeypatch.setenv("POLICYOPS_ENV", "local")
    first = runtime["demo_bindings"](object())
    second = runtime["demo_bindings"](object())
    assert first == second and len(first) == 3
    assert {binding.scope.case_id for binding in first[1:]} == set(case_ids)
    assert all(binding.user_id == config["customer_id"] for binding in first)
    rows[:] = rows[:1] * 1001
    with pytest.raises(RuntimeError, match="limit exceeded"):
        runtime["demo_bindings"](object())
    monkeypatch.setenv("POLICYOPS_ENV", "production")
    with pytest.raises(RuntimeError, match="local Compose"):
        runtime["demo_bindings"](object())


def test_scenario_seed_twice_keeps_active_runs_and_simulator_cases_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "infra/compose"))
    scenario = runpy.run_path(str(ROOT / "infra/compose/scenario.py"))
    namespace = scenario["seed"].__globals__
    monkeypatch.setitem(namespace, "SECRETS", tmp_path)
    monkeypatch.setenv("POLICYOPS_RETAIL_ORIGIN", "http://unused.invalid")
    (tmp_path / "retail_key").write_bytes(b"fixture-key-only")
    config = namespace["demo"]()
    cases: dict[UUID, Any] = {}
    active: dict[UUID, UUID] = {}
    simulators: list[UUID] = []

    @contextmanager
    def transaction(*args: Any) -> Any:
        yield object()

    class Retail:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.case_id = kwargs["case_id"]

        def initialize(self) -> object:
            assert self.case_id not in simulators
            simulators.append(self.case_id)
            return object()

        def read(self, call: Any) -> Any:
            if isinstance(call, namespace["GetUserDetails"]):
                user = Mock(spec=namespace["UserOutput"], user=SimpleNamespace(email="fixture@example.invalid"))
                return SimpleNamespace(output=user, case_version=1)
            return SimpleNamespace(output=namespace["UserIdOutput"](user_id=config["customer_id"]))

        def close(self) -> None:
            pass

    def create_case(connection: Any, case: Any) -> None:
        assert case.id not in cases
        cases[case.id] = case

    def create_run(connection: Any, **kwargs: Any) -> object:
        # Keep each first run active: reuse would fail just as the real active-run constraint does.
        assert kwargs["case_id"] not in active, "ActiveRunExists"
        active[kwargs["case_id"]] = kwargs["run_id"]
        return object()

    monkeypatch.setitem(namespace, "own_engine", transaction)
    monkeypatch.setitem(namespace, "workspace_transaction", transaction)
    monkeypatch.setitem(namespace, "RetailClient", Retail)
    monkeypatch.setattr(namespace["repo"], "create_case", create_case)
    monkeypatch.setattr(namespace["repo"], "lock_case", lambda conn, case: SimpleNamespace(version=1))
    monkeypatch.setattr(namespace["runs"], "create_run", create_run)
    monkeypatch.setattr(namespace["runs"], "set_state", Mock())
    monkeypatch.setattr(namespace["runs"], "append_event", Mock())
    monkeypatch.setattr(namespace["customer_authentications"], "record", Mock())
    monkeypatch.setitem(namespace, "load_scope", Mock())
    monkeypatch.setitem(namespace, "collect", Mock(return_value=Mock(spec=namespace["Collected"])))
    proposal = SimpleNamespace(proposal_id=uuid4(), proposal_version=1, action_digest="a" * 64)
    service = Mock()
    service.create.return_value = Mock(spec=namespace["Created"], proposal=proposal)
    service.present.return_value = Mock(spec=namespace["Presented"])
    monkeypatch.setitem(namespace, "ProposalService", Mock(return_value=service))
    first, second = scenario["seed"](), scenario["seed"]()
    assert first["run_id"] != second["run_id"] and first["case_id"] != second["case_id"]
    assert set(simulators) == set(cases) == set(active) and len(active) == 2
    assert all(case.customer_user_id == config["customer_id"] for case in cases.values())


@pytest.mark.parametrize("raw", ["[]", "null", '{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', "{", "x" * 1048577])
def test_driver_json_rejects_malformed_duplicate_nonfinite_and_oversized(raw: str) -> None:
    with pytest.raises(compose_smoke.SmokeError):
        drills.parse_object(raw)


def test_driver_json_accepts_an_object() -> None:
    assert drills.parse_object('{"run":"example","state":{"count":1}}') == {"run": "example", "state": {"count": 1}}


@pytest.mark.parametrize(
    "value",
    [
        "policyops",
        "policyops_restore_other",
        "policyops_restore_123456789abc;DROP",
        "policyops_restore_ABCDEF012345",
        "../policyops_restore_123456789abc",
    ],
)
def test_restore_database_identifier_is_not_a_sql_channel(value: str) -> None:
    with pytest.raises(compose_smoke.SmokeError):
        drills.identifier(value)


def states() -> tuple[dict[str, Any], dict[str, Any], str]:
    run = str(uuid4())
    row = {
        "run_id": run,
        "operation_id": str(uuid4()),
        "state": "dispatched",
        "attempts": 1,
        "receipt_sha256": None,
        "remote_receipt_sha256": "a" * 64,
        "resolved_by": None,
    }
    before: dict[str, Any] = {"executions": [row], "case_version": 2, "pending_outcomes": 0}
    after = deepcopy(before)
    after["executions"][0].update(state="succeeded", receipt_sha256="a" * 64, resolved_by="lookup")
    return before, after, run


def test_recovery_requires_the_original_remote_receipt_and_no_resend() -> None:
    before, after, run = states()
    assert drills.assert_recovered(before, after, run) == after["executions"][0]


@pytest.mark.parametrize(
    "change",
    ["duplicate", "operation", "receipt", "resend", "response", "effect", "pending", "missed-kill", "absent-remote"],
)
def test_recovery_sensitivity_controls_detect_unsafe_or_unproven_results(change: str) -> None:
    before, after, run = states()
    row = after["executions"][0]
    if change == "duplicate":
        after["executions"].append(deepcopy(row))
    elif change == "operation":
        row["operation_id"] = str(uuid4())
    elif change == "receipt":
        row["receipt_sha256"] = "b" * 64
    elif change == "resend":
        row["attempts"] = 2
    elif change == "response":
        row["resolved_by"] = "response"
    elif change == "effect":
        after["case_version"] += 1
    elif change == "pending":
        after["pending_outcomes"] = 1
    elif change == "missed-kill":
        before["executions"][0]["receipt_sha256"] = "a" * 64
    else:
        before["executions"][0]["remote_receipt_sha256"] = None
    with pytest.raises(compose_smoke.SmokeError):
        drills.assert_recovered(before, after, run)


def test_drill_failure_always_cleans_and_seals_a_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["compose_drills.py"])
    calls = []

    def fail(_self: Any) -> None:
        raise subprocess.TimeoutExpired(["docker", "up"], 1)

    monkeypatch.setattr(drills.Drills, "run", fail)
    monkeypatch.setattr(drills.Drills, "cleanup", lambda self: calls.append(self.project))
    assert drills.main() == 1
    assert len(calls) == 1 and calls[0].startswith("policyops-t38b-")
    report = json.loads(next((tmp_path / "compose").glob("*/report.json")).read_bytes())
    assert report["failure"] == {"type": "TimeoutExpired", "detail": "details omitted"}
    assert report["passed"] is False and "logical" in report["limitations"][1]


def test_drill_cleanup_refuses_foreign_resources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver = drills.Drills(tmp_path, 8080)
    monkeypatch.setattr(driver, "containers", lambda: [{"Config": {"Labels": {"policyops.owner": "foreign"}}}])
    called = []
    monkeypatch.setattr(driver, "compose", lambda *args, **kwargs: called.append(args))
    with pytest.raises(compose_smoke.SmokeError, match="foreign"):
        driver.cleanup()
    assert called == [] and driver.override.exists()


def test_drill_failures_reuse_bounded_secret_redaction(tmp_path: Path) -> None:
    driver = drills.Drills(tmp_path, 8080)
    driver.secrets.mkdir()
    canary = "fictional-credential-canary-123456"
    (driver.secrets / "bob").write_text(canary, encoding="utf-8")
    dsn = "postgresql" + "://u:" + "credential" + "@host/db"
    tail = driver.failure_tail("\n".join(["ordinary"] * 80) + "\n" + canary + "\n" + dsn)
    assert canary not in tail and "credential@" not in tail
    assert "[REDACTED]" in tail and len(tail.splitlines()) <= 60


def test_trace_drops_resources_headers_cookies_queries_and_known_secrets(tmp_path: Path) -> None:
    raw, safe = tmp_path / "raw.zip", tmp_path / "safe.zip"
    record = {
        "url": "http://127.0.0.1:8080/api?code=secret",
        "headers": [{"name": "Cookie", "value": "session"}],
        "nested": {
            "cookies": ["session"],
            "postData": "customer",
            "text": "known-canary",
            "content": {"text": "inline body must be omitted"},
        },
    }
    with ZipFile(raw, "w") as archive:
        archive.writestr("0.trace", json.dumps(record) + "\n")
        archive.writestr("0.network", json.dumps({"request": record}))
        archive.writestr("resources/secret", "raw body session known-canary")
        archive.writestr("../escape.trace", "{}")
    traces.sanitize(raw, safe, tmp_path, ("known-canary",))
    assert not raw.exists()
    with ZipFile(safe) as archive:
        assert archive.namelist() == ["0.trace", "0.network"]
        text = archive.read("0.trace").decode()
        assert all(value not in text for value in ("session", "customer", "known-canary", "code=secret", "inline body"))
        assert json.loads(text)["url"] == "http://127.0.0.1:8080/api"


def test_trace_raw_removed_on_parse_failure(tmp_path: Path) -> None:
    raw, safe = tmp_path / "raw.zip", tmp_path / "safe.zip"
    with ZipFile(raw, "w") as archive:
        archive.writestr("0.trace", "not-json")
    with pytest.raises(ValueError):
        traces.sanitize(raw, safe, tmp_path)
    assert not raw.exists() and not safe.exists()


def test_trace_refuses_repository_or_foreign_paths(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        traces.external_zip(ROOT / "unsafe.zip", ROOT.parent)
    with pytest.raises(ValueError):
        traces.external_zip(tmp_path.parent / "foreign.zip", tmp_path)


@pytest.mark.parametrize("env,flag", [("local", ""), ("production", "1"), ("test", "1")])
def test_normal_runtime_refuses_injected_execution_hook(env: str, flag: str, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = runpy.run_path(str(ROOT / "infra/compose/runtime.py"))
    monkeypatch.setenv("POLICYOPS_ENV", env)
    monkeypatch.setenv("POLICYOPS_COMPOSE_DRILL", flag)
    with pytest.raises(RuntimeError, match="explicit local Compose drill"):
        runtime["worker"](execution_hooks=object())


def test_local_dex_seed_uses_encoded_user_and_connector_identity() -> None:
    runtime = runpy.run_path(str(ROOT / "infra/compose/runtime.py"))
    subjects = []
    for user in runtime["demo"]()["users"]:
        subject = runtime["dex_subject"](user["subject"])
        assert subject != user["subject"] and "=" not in subject
        decoded = base64.urlsafe_b64decode(subject + "=" * (-len(subject) % 4))
        assert decoded == bytes([10, 36]) + user["subject"].encode() + bytes([18, 5]) + b"local"
        subjects.append(subject)
    assert len(set(subjects)) == 3
    with pytest.raises(ValueError):
        runtime["dex_subject"]("alice@example.invalid")
