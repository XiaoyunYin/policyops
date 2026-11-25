"""Offline regressions for the N10 round 2 review."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from io import BytesIO, StringIO, TextIOWrapper
import json
from pathlib import Path
import socket
import sys
from typing import Any
from unittest.mock import MagicMock, Mock
from uuid import UUID, uuid5

import httpx
import pytest
from sqlalchemy.exc import SQLAlchemyError


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from infra.compose import load_identity, loadcheck, loadseed, runtime
from policyops.api.openapi import document, schema_app
from policyops.domain.examples import World
from policyops.domain.retail_rules import RetailFacts
from policyops.domain.roles import Role
from policyops.persistence import repositories as repo
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.services.decisions import Refusal, evaluate
from policyops.services.proposal_views import DecisionRequest
from policyops.services.proposals import Presented, ProposalService
from policyops.services.review_outcomes import RefusalReason, refusal_message_id, refusal_text
from policyops_contracts.digest import canonical_bytes, sha256_hex
from policyops_contracts.events import EventEnvelope, ReviewOutcome, ReviewReason, RunStateChanged
from policyops_contracts.scalars import RunScope
from scripts import load_report, load_sampler, loadgen


NOW = datetime(2026, 11, 24, tzinfo=UTC)
TOKEN = "ab" * 32
DENIED_HOST = "protected.example.invalid"
DENIED_IP = "192.0.2.20"
ISSUER = "http://127.0.0.1:18081/dex"


def test_identity_gate_before_seed_or_checker_access(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "SECRETS", tmp_path)
    monkeypatch.setenv("POLICYOPS_ENV", "local")
    monkeypatch.setenv("POLICYOPS_N10_RUN_ID", "n10-unit")
    monkeypatch.setenv("POLICYOPS_N10_ISSUER", ISSUER)
    (tmp_path / "n10_load_token").write_text(TOKEN, encoding="ascii")
    (tmp_path / "n10_deny_hosts").write_text(DENIED_HOST + "\n", encoding="ascii")
    db = MagicMock()
    execute = db.connect.return_value.__enter__.return_value.execute
    reads = Mock(side_effect=AssertionError("study evidence was read before DB verification"))
    monkeypatch.setattr(sys, "stdin", Mock(readline=reads))
    write = Mock(side_effect=AssertionError("fixture mutated before DB verification"))
    monkeypatch.setattr(loadseed, "membership", write)
    monkeypatch.setattr(loadseed, "seed_wave", write)
    context = Mock(side_effect=lambda _role: MagicMock(__enter__=Mock(return_value=db)))
    monkeypatch.setattr(loadseed, "own_engine", context)
    monkeypatch.setattr(loadcheck, "own_engine", context)

    monkeypatch.setenv("POLICYOPS_PUBLIC_ORIGIN", "https://sub." + DENIED_HOST.upper() + ".")
    monkeypatch.setattr(sys, "argv", ["loadseed", "base", "--seed", "10"])
    assert loadseed.main() == 1
    context.assert_not_called()
    monkeypatch.delenv("POLICYOPS_PUBLIC_ORIGIN")

    identity = load_identity.load_config()
    execute.side_effect = SQLAlchemyError("missing schema")
    assert loadseed.main() == 1
    execute.side_effect = None
    for run, digest in (("n10-other", identity.token_sha256), (identity.run_id, "ff" * 32)):
        execute.return_value.one_or_none.return_value = Mock(run_id=run, token_sha256=digest)
        monkeypatch.setattr(sys, "argv", ["loadseed", "wave", "--seed", "10", "--name", "wave", "--count", "1"])
        assert loadseed.main() == 1
        monkeypatch.setattr(sys, "argv", ["loadcheck", "check"])
        assert loadcheck.main() == 2
    write.assert_not_called()
    reads.assert_not_called()
    execute.return_value.one_or_none.return_value = Mock(run_id=identity.run_id, token_sha256=identity.token_sha256)
    load_identity.verify_identity(db, identity)


def test_one_shot_enrollment_refuses_prior_identity_and_nonfixture_rows() -> None:
    demo = runtime.demo()
    workspace = UUID(demo["workspace_id"])
    members = [uuid5(workspace, user["name"]) for user in demo["users"]]
    rows = {
        "app.cases": [UUID(demo["case_id"])],
        "identity.workspaces": [workspace],
        "identity.principals": members,
        "identity.memberships": [uuid5(principal, "membership") for principal in members],
        "app.jobs": [],
    }
    installed = False
    conn = MagicMock()
    identity = load_identity.LoadIdentity("n10-unit", TOKEN, ISSUER)

    def query(statement: Any, _params: Any = None) -> MagicMock:
        return MagicMock(
            scalar_one=Mock(return_value=not installed if "to_regnamespace" in str(statement) else True),
            scalars=Mock(return_value=Mock(all=Mock(return_value=(
                [ISSUER] if "SELECT DISTINCT issuer" in str(statement) else list(rows)
            )))),
            first=Mock(return_value=(1,)),
        )

    def sql(statement: str) -> Mock:
        if not statement.startswith("SELECT"):
            return Mock()
        table = statement.split()[3]
        return Mock(scalars=Mock(return_value=rows[table]), first=Mock(return_value=next(iter(rows[table]), None)))

    conn.execute.side_effect = query
    conn.exec_driver_sql.side_effect = sql
    rows["app.jobs"] = [UUID(int=1)]
    with pytest.raises(load_identity.SeedError, match="beyond the bootstrap"):
        load_identity.initialize(conn, identity)
    assert all("CREATE" not in str(call) for call in conn.exec_driver_sql.call_args_list)
    rows["app.jobs"] = []
    load_identity.initialize(conn, identity)
    assert any("CREATE TABLE n10_load.identity" in str(call) for call in conn.exec_driver_sql.call_args_list)
    assert conn.execute.call_args.args[1] == {"run": identity.run_id, "digest": identity.token_sha256}
    installed = True
    conn.exec_driver_sql.reset_mock()
    with pytest.raises(load_identity.SeedError, match="already has load identity"):
        load_identity.initialize(conn, identity)
    conn.exec_driver_sql.assert_not_called()


@pytest.mark.parametrize("answer", ["64:ff9b::c000:214", "::ffff:192.0.2.10", "192.0.2.11"])
def test_non_loopback_and_rtt_refuse_any_answer_other_than_the_expected_ipv4(
    answer: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = loadgen.target("https://disposable.example.invalid", [DENIED_HOST])
    connect = Mock(side_effect=AssertionError("connection attempted to an unverified address"))
    monkeypatch.setattr(asyncio, "open_connection", connect)
    answers = Mock(
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443)),
            (socket.AF_INET6 if ":" in answer else socket.AF_INET, socket.SOCK_STREAM, 6, "", (answer, 443)),
        ]
    )
    monkeypatch.setattr(socket, "getaddrinfo", answers)
    with pytest.raises(loadgen.Refused, match="requires --expect-ip"):
        loadgen.approved_address(url, [DENIED_IP])
    answers.assert_not_called()
    with pytest.raises(loadgen.Refused, match="exclusively"):
        asyncio.run(loadgen.record_rtt(argparse.Namespace(deny_ip=[DENIED_IP], expect_ip="192.0.2.10"), url))
    connect.assert_not_called()


def start_utc(offset: float) -> str:
    return (NOW + timedelta(seconds=offset)).isoformat()


def raw_trial(stage: loadgen.Stage) -> list[dict[str, Any]]:
    return [
        {
            "kind": "meta",
            "stage": asdict(stage),
            "run": "unit",
            "environment": "workstation",
            "seed": 10,
            "generator_cadence_s": 1,
        },
        {"kind": "stage_start", "utc": start_utc(0)},
        *(
            {
                "kind": "slot",
                "endpoint": slot.route,
                "phase": stage.phase(slot.offset),
                "index": slot.index,
                "intended": slot.offset,
                "sent": slot.offset + 0.001,
                "done": slot.offset + 0.1,
                "status": 200,
            }
            for slot in loadgen.schedule(stage, 10)
        ),
        *(
            {"kind": "generator", "offset": stage.warmup + index + 0.25, "cpu_percent": 10}
            for index in range(int(stage.measured))
        ),
        {"kind": "stage_end", "aborted": False, "utc": start_utc(stage.total)},
    ]


def test_report_refuses_missing_or_duplicate_arrivals_and_generator_gaps() -> None:
    rows = raw_trial(loadgen.Stage("slots", 32, warmup=1, measured=180, drain=1))
    assert load_report.summarize(rows)["generator_valid"]
    for evidence in (rows[:2] + rows[3:], [*rows, rows[2]], [{**rows[0], "seed": 14}, *rows[1:]]):
        result = load_report.summarize(evidence)
        assert result["outcome"] == "invalid" and not result["schedule_ok"]
    for evidence in (
        [row for row in rows if row["kind"] != "generator" or row["offset"] == 1.25],
        [row for row in rows if row["kind"] != "generator" or not 5 < row["offset"] < 7],
    ):
        result = load_report.summarize(evidence)
        assert result["outcome"] == "invalid" and result["schedule_ok"] and not result["generator_coverage"]


def trial(label: str, stage: str, *, start: int = 1, value: float = 1, ok: bool = True) -> dict[str, Any]:
    return {
        "meta": {
            "run": label,
            "stage": asdict(loadgen.Stage(stage, 32)),
            "environment": "lightsail",
            "seed": 10,
            "target_sha256": TOKEN,
            "dataset_sha256": TOKEN,
            "profile_sha256": TOKEN,
            "setup_utc": start_utc(start),
        },
        "stage_start_utc": start_utc(start),
        "outcome": "passed" if ok else "failed",
        "generator_valid": True,
        "checker": {"ok": ok},
        "server": {"coverage_ok": True},
        "problems": [],
        "credits": {side: {"BurstCapacityPercentage": 95} for side in ("before", "after")},
        "browse": {"succeeded": 200},
        "workflow": {"succeeded": 0},
        "routes": {"messages": {"successful_latency_s": {"p95": value}}},
    }


def plan_for(*trials: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"run": row["meta"]["run"], "stage": row["meta"]["stage"]["id"], "rate": row["meta"]["stage"]["w1"]}
        for row in trials
    ]


def test_capacity_retains_missing_failed_and_retried_attempts_and_enforces_abort() -> None:
    rows = [
        trial("sweep", "w1-32", start=1),
        trial("r1", "repeat-pass-1", start=2),
        trial("r2", "repeat-pass-2", start=3),
        trial("r3", "repeat-pass-3", start=4),
    ]
    failing = trial("r4", "repeat-pass-4", ok=False, start=5)
    fixed = trial("r4-retry", "repeat-pass-4", start=6)
    assert load_report.capacity(rows, plan_for(*rows))["passing_rps"] == 32
    missing = load_report.capacity(rows, plan_for(*rows, failing))
    assert missing["passing_rps"] is None and missing["attempts"][-1]["outcome"] == "missing"
    result = load_report.capacity([*rows, failing], plan_for(*rows, failing))
    assert result["passing_rps"] is None and result["correctness_disqualified_rps"] == [32]
    assert result["correctness_abort_pending"] == "r4"
    continued = load_report.capacity([*rows, failing, fixed], plan_for(*rows, failing, fixed))
    assert continued["kind"] == "correctness_abort_violated"
    plan = plan_for(*rows, failing, fixed)
    plan[-1].update(replaces="r4", reason="Coordinator approved after diagnosing the failed checker.")
    authorized = load_report.capacity([*rows, failing, fixed], plan)
    assert authorized["passing_rps"] == 32 and authorized["correctness_abort_pending"] is None
    assert authorized["attempts"][-2]["outcome"] == "failed"
    assert authorized["attempts"][-2]["replaced_by"] == "r4-retry"


def test_report_command_signals_correctness_abort_and_preserves_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "unit.jsonl"
    rows = raw_trial(loadgen.Stage("report", 2, warmup=0, measured=2, drain=1))
    evidence.write_text("\n".join(map(json.dumps, rows)), encoding="utf-8")
    evidence.with_suffix(".check.json").write_text(
        json.dumps({"ok": False, "raw_sha256": sha256_hex(evidence.read_bytes())}), encoding="utf-8",
    )
    prefix = tmp_path / "report"
    monkeypatch.setattr(sys, "argv", ["load_report", str(evidence), "--output-prefix", str(prefix)])
    assert load_report.main() == 1
    report = json.loads(prefix.with_suffix(".json").read_bytes())
    assert report["capacity"]["correctness_abort_pending"] == "unit"
    assert report["trials"][0]["outcome"] == "failed"


def worker_drain_pairs(metric: str) -> dict[str, Any]:
    return {
        "arms": {"A": "drain=0", "B": "drain=1"},
        "pairs": [[f"a{i}", f"b{i}"] for i in range(1, 6)],
        "metric": metric,
        "credit_band": [90, 100],
    }


def test_paired_report_rejects_reuse_duplicate_labels_wrong_assignment_and_wrong_order() -> None:
    order = ("a1", "b1", "b2", "a2", "a3", "b3", "b4", "a4", "a5", "b5")
    rows = [
        trial(label, "fix-" + label, start=i, value=1 if label.startswith("a") else 0.7)
        for i, label in enumerate(order)
    ]
    plan = worker_drain_pairs("messages")
    pairs = plan["pairs"]
    assert load_report.paired_analysis(list(reversed(rows)), plan)["claim"]
    with pytest.raises(ValueError, match="ten distinct"):
        load_report.paired_analysis(rows, dict(plan, pairs=[pairs[0]] * 5))
    with pytest.raises(ValueError, match="duplicate"):
        load_report.paired_analysis([*rows, rows[0]], plan)
    with pytest.raises(ValueError, match="A/B assignment"):
        load_report.paired_analysis(rows, dict(plan, pairs=[list(reversed(pairs[0])), *pairs[1:]]))
    rows[0]["stage_start_utc"], rows[1]["stage_start_utc"] = rows[1]["stage_start_utc"], rows[0]["stage_start_utc"]
    with pytest.raises(ValueError, match="chronological ABBA"):
        load_report.paired_analysis(rows, plan)


def test_id_fields_cover_the_actual_exercised_response_models() -> None:
    api = document(schema_app())
    routes = [
        ("get", "/me", "200"),
        ("get", "/cases", "200"),
        ("get", "/cases/{case_id}", "200"),
        ("get", "/cases/{case_id}/messages", "200"),
        ("post", "/cases/{case_id}/messages", "201"),
        ("get", "/cases/{case_id}/proposals", "200"),
        ("get", "/approvals", "200"),
        ("get", "/proposals/{proposal_id}", "200"),
        ("post", "/proposals/{proposal_id}/decision", "201"),
        ("get", "/runs/{run_id}/snapshot", "200"),
    ]
    schemas = api["components"]["schemas"]
    todo = [schemas["EventEnvelope"]]
    for method, route, status in routes:
        response = api["paths"][loadgen.API + route][method]["responses"][status]
        todo.append(response["content"]["application/json"]["schema"])
    checked: set[str] = set()
    fields: set[str] = set()
    while todo:
        node = todo.pop()
        if isinstance(node, list):
            todo.extend(node)
        if not isinstance(node, dict):
            continue
        reference = node.get("$ref")
        if reference and reference not in checked:
            checked.add(reference)
            todo.append(schemas[reference.rsplit("/", 1)[1]])
        fields.update(
            name
            for name, field in node.get("properties", {}).items()
            if name.endswith(("_id", "_ids", "_by")) or '"uuid"' in json.dumps(field)
        )
        todo.extend(value for value in node.values() if isinstance(value, dict | list))
    assert fields == loadgen.RESPONSE_ID_FIELDS


def workbook(client: httpx.AsyncClient) -> tuple[loadgen.Workload, loadgen.Session, RunScope, EventEnvelope]:
    workspace, case, run, principal, event, consent, approval, execution, operation = (
        UUID(int=i) for i in range(1, 10)
    )
    scope = RunScope(workspace_id=workspace, case_id=case, run_id=run)
    event_row = EventEnvelope(
        event_id=event,
        scope=scope,
        occurred_at=NOW,
        sequence=1,
        payload=RunStateChanged(previous="running", current="succeeded"),
    )
    ws, cid, rid = map(str, (workspace, case, run))
    owner = {"case_id": cid, "run_id": rid}
    accounting = {
        "messages": {},
        "consents": {str(consent): owner},
        "decisions": {str(approval): owner},
        "executions": {str(execution): {**owner, "operation_id": str(operation)}},
    }
    manifest = {
        "demo": ws,
        "principals": {"alice": str(principal)},
        "workspaces": {
            ws: {
                "cases": [cid],
                "proposals": [],
                "runs": {rid: cid},
                "messages": {},
                "events": {str(event): rid},
                "run_principals": {rid: str(principal)},
                "event_digests": {str(event): sha256_hex(canonical_bytes(event_row.payload))},
            }
        },
        "accounting": {ws: accounting},
    }
    session = loadgen.Session("alice", ws, client, str(principal), "csrf")
    log = loadgen.Log(StringIO(), loadgen.Stage("checks", 2), 0)
    return loadgen.Workload(manifest, [session], log, asyncio.Event()), session, scope, event_row


def test_tenant_validation_checks_optional_and_nested_ids() -> None:
    work, session, scope, _ = workbook(Mock(spec=httpx.AsyncClient))
    request = loadgen.ReadRequest("/runs/snapshot", str(scope.case_id), str(scope.run_id))
    body: dict[str, Any] = {
        "run": {"initiated_by": session.principal},
        "latest_review": {
            "payload": {
                "consent_id": str(UUID(int=6)),
                "decision_id": str(UUID(int=7)),
                "execution_id": str(UUID(int=8)),
                "operation_id": str(UUID(int=9)),
            }
        },
        "decision": {"approval_id": str(UUID(int=7))},
    }
    work.check_ids(body, session, request)
    for field in tuple(body["latest_review"]["payload"]):
        corrupted = json.loads(json.dumps(body))
        corrupted["latest_review"]["payload"][field] = str(UUID(int=42))
        with pytest.raises(loadgen.Violation, match="_mismatch"):
            work.check_ids(corrupted, session, request)
    for item, field in ((body["run"], "initiated_by"), (body["decision"], "approval_id")):
        item[field] = str(UUID(int=42))
        with pytest.raises(loadgen.Violation, match="_mismatch"):
            work.check_ids(item, session, request)


def test_checker_owns_event_references_even_when_the_digests_agree() -> None:
    work, session, scope, _ = workbook(Mock(spec=httpx.AsyncClient))
    inventory = work.manifest["accounting"][session.workspace]
    execution, operation = str(UUID(int=8)), str(UUID(int=9))
    event = {"execution_id": execution, "operation_id": operation}
    case, run = str(scope.case_id), str(scope.run_id)
    assert loadcheck.event_refs_owned(event, inventory, case, run, [])
    assert not loadcheck.event_refs_owned(dict(event, operation_id=str(UUID(int=42))), inventory, case, run, [])
    assert not loadcheck.event_refs_owned(event, inventory, "foreign-case", run, [])


@pytest.mark.parametrize("unexpected", [False, True])
def test_stream_logs_only_digests_and_rejects_extra_fields(unexpected: bool) -> None:
    async def run() -> tuple[list[dict[str, Any]], bool]:
        def response(_request: httpx.Request) -> httpx.Response:
            body = event.model_dump(mode="json")
            if unexpected:
                body["payload"]["credential"] = "never-log-this"
            return httpx.Response(
                200,
                text=(f"id: 1\nevent: run.state_changed\ndata: {json.dumps(body)}\n\n"),
                headers={"content-type": "text/event-stream"},
            )

        async with httpx.AsyncClient(
            base_url="https://disposable.example.invalid", transport=httpx.MockTransport(response)
        ) as client:
            work, session, scope, event = workbook(client)
            work.log.start += work.log.now()
            await work.stream(
                session,
                str(scope.case_id),
                str(scope.run_id),
                1,
                loadgen.Record("slot", "workflow", "measured", 0),
                workflow=not unexpected,
            )
            output = work.log.output
            assert isinstance(output, StringIO)
            evidence = output.getvalue()
            assert "never-log-this" not in evidence
            return [json.loads(line) for line in evidence.splitlines()], work.abort.is_set()

    rows, aborted = asyncio.run(run())
    events = [row for row in rows if row["kind"] == "event"]
    assert aborted == unexpected
    if unexpected:
        assert not events and any(row.get("correctness") for row in rows)
    else:
        assert len(events) == 1 and "payload" not in events[0]
        assert events[0]["payload_sha256"] == sha256_hex(
            canonical_bytes(
                RunStateChanged(previous="running", current="succeeded"),
            )
        )


def test_checker_detects_extra_rows_and_dead_jobs_outside_write_cohort(monkeypatch: pytest.MonkeyPatch) -> None:
    workspaces = [str(UUID(int=i)) for i in (1, 2, 3)]
    empty: dict[str, Any] = {table: {} for table in ("decisions", "executions", "jobs", "messages", "consents")}
    manifest = {
        "demo": workspaces[0],
        "second": workspaces[1],
        "foreign": workspaces[2],
        "principals": {},
        "workspaces": {workspace: {} for workspace in workspaces[:2]},
        "writes": [],
        "accounting": dict.fromkeys(workspaces, empty),
    }
    after = {
        workspaces[0]: {
            **empty,
            "jobs": {
                "new": {"kind": "run.review", "state": "dead", "run_id": "browse", "review_trigger": "expiry"},
            },
        },
        workspaces[1]: {**empty, "decisions": {"approval": {"case_id": "browse", "decision": "approve"}}},
        workspaces[2]: {**empty, "messages": {"message": {"case_id": "canary", "source": "agent"}}},
    }
    scoped = []

    @contextmanager
    def workspace_transaction(_engine: Any, workspace: UUID) -> Any:
        scoped.append(str(workspace))
        yield str(workspace)

    monkeypatch.setattr(loadcheck, "workspace_transaction", workspace_transaction)
    monkeypatch.setattr(loadcheck, "transaction", MagicMock())
    monkeypatch.setattr(loadcheck, "workspace_accounting", after.__getitem__)
    monkeypatch.setattr(loadcheck, "workspace_job_health", lambda _: {})
    result = loadcheck.check(Mock(), Mock(), manifest, [])
    assert scoped == workspaces
    assert {(row["workspace"], row["error"]) for row in result["violations"] if "workspace" in row} == set(
        zip(
            workspaces,
            ("unexpected_jobs_inventory", "unexpected_decisions_inventory", "unexpected_messages_inventory"),
            strict=True,
        )
    )


@pytest.mark.parametrize("legacy", [False, True])
def test_round5_checker_distinguishes_abort_from_started_workflow_violations(
    monkeypatch: pytest.MonkeyPatch, legacy: bool,
) -> None:
    workspaces = [str(UUID(int=i)) for i in (1, 2, 3)]
    empty: dict[str, Any] = {table: {} for table in ("decisions", "executions", "jobs", "messages", "consents")}
    writes = [
        {"case_id": case, "run_id": f"run-{case}", "workspace_id": workspaces[0], "control": control,
         "simulator_version": 5, "proposal_id": f"proposal-{case}", "proposal_version": 1}
        for case, control in (("cancelled", "approve"), ("unstarted", "replay"), ("violated", "expired"))
    ]
    manifest = {
        "demo": workspaces[0], "second": workspaces[1], "foreign": workspaces[2], "principals": {},
        "workspaces": {workspace: {} for workspace in workspaces[:2]},
        "writes": writes, "accounting": dict.fromkeys(workspaces, empty),
    }
    baseline = loadcheck.Observed((), (), 0, (), (), 0, (), 5, 0, 0, "running", None)
    cancelled = replace(baseline, messages=("message",), consents=("consent",), message_audit=1,
                        decision_ids=("approval",), decision_kinds=("approve",), decision_audit=1)
    read = Mock(side_effect=lambda _, fixture: cancelled if fixture["case_id"] == "cancelled" else baseline)
    monkeypatch.setattr(loadcheck, "read_case", read)
    monkeypatch.setattr(loadcheck, "workspace_transaction", MagicMock())
    monkeypatch.setattr(loadcheck, "transaction", MagicMock())
    monkeypatch.setattr(loadcheck, "workspace_accounting", lambda _: empty)
    monkeypatch.setattr(loadcheck, "workspace_job_health", lambda _: {})
    monkeypatch.setattr(loadcheck, "check_workspace", lambda *args, **kwargs: [])
    rows: list[dict[str, Any]] = [
        {"kind": "write", "case_id": "violated", "control": "expired", "run_id": "run-violated", "decisions": [409]},
        {"kind": "slot", "endpoint": "workflow", "index": 2, "sent": 10, "done": 11, "error": None},
        {"kind": "http", "endpoint": "consent", "case_id": "cancelled", "status": 201},
        {"kind": "http", "endpoint": "decision", "case_id": "cancelled", "status": 201},
        {"kind": "generator", "offset": 56.0},
        {"kind": "abort", "reason": "generator_send_lag", **({} if legacy else {"offset": 56.004})},
        {"kind": "write", "case_id": "cancelled", "control": "approve", "run_id": "run-cancelled",
         "consent_status": 201, "decisions": [201], "message_id": "message", "consent_id": "consent",
         "approval_id": "approval"},
        {"kind": "slot", "endpoint": "workflow", "index": 0, "sent": 55, "done": 56.005,
         "error": "drain_deadline" if legacy else "cancelled_by_abort"},
        {"kind": "slot", "endpoint": "workflow", "index": 1, "sent": None, "done": 56.006, "error": "aborted"},
        {"kind": "stage_end", "aborted": True, **({} if legacy else {"abort_offset": 56.004})},
    ]
    result = loadcheck.check(Mock(), Mock(), manifest, rows)
    offset = 56.0 if legacy else 56.004
    assert result["ok"] is False
    assert result["not_started"] == [{"case_id": "unstarted", "abort_offset": offset}]
    assert result["cancelled_by_abort"] == [{"case_id": "cancelled", "abort_offset": offset}]
    assert result["violations"] == [{"case_id": "violated", "error": "stale_refusal"}]
    assert [call.args[1]["case_id"] for call in read.call_args_list] == ["cancelled", "violated"]

    raw = raw_trial(loadgen.Stage("aborted", 2, warmup=0, measured=60, drain=1))
    next(row for row in raw if row["kind"] == "stage_end")["aborted"] = True
    trial = load_report.summarize(raw, result)
    report = load_report.markdown({"trials": [trial], "repeats": [], "capacity": load_report.capacity([trial])})
    assert trial["outcome"] == "failed" and trial["correctness_failed"]
    assert "Checker violations\n\n- `stale_refusal` (case `violated`)." in report
    assert f"Case `unstarted` not started (aborted at offset {offset:.3f} s)" in report
    assert f"Case `cancelled` cancelled_by_abort (aborted at offset {offset:.3f} s)" in report
    assert not load_report.summarize(raw, {**result, "violations": []})["correctness_failed"]


def sampler_evidence(measured: int, drain: int) -> list[dict[str, Any]]:
    return [
        {"kind": "sampler_meta", "utc": start_utc(-1), "cadence_s": load_sampler.SAMPLE_CADENCE},
        *(
            {
                "kind": "host",
                "utc": start_utc(i),
                "cpu_percent": dict.fromkeys(
                    ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"), 0,
                ),
                "memory_kib": dict.fromkeys(("MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached", "SwapTotal",
                                            "SwapFree"), 1),
                "swap_pages": {"pswpin": 0, "pswpout": 0},
            }
            for i in range(measured + drain + 1)
        ),
        *(
            {"kind": "postgres", "utc": start_utc(i), "activity": [], "due": {"count": 0, "oldest_s": 0}}
            for i in range(measured + drain + 1)
        ),
        *(
            {
                "kind": "containers",
                "utc": start_utc(i),
                "inspect": {key: {"id": key, "image": "sha256:unit", "status": "running", "restarts": 0,
                                  "memory_limit": 0, "oom": False, "health": None} for key in load_sampler.SERVICES},
                "stats": {key: {"CPUPerc": "0.00%", "MemUsage": "5.2MiB / 1GiB", "MemPerc": "0.51%",
                                "NetIO": "2.3kB / 1MB", "BlockIO": "0B / 0B", "PIDs": "1"}
                          for key in load_sampler.SERVICES},
            }
            for i in range(0, measured + drain + 1, 5)
        ),
        *(
            {
                "kind": "pg_counters",
                "utc": start_utc(i),
                "database": {**dict.fromkeys(("xact_rollback", "blks_read", "blks_hit", "tup_returned", "tup_fetched",
                                             "tup_inserted", "tup_updated", "tup_deleted", "conflicts", "temp_files",
                                             "temp_bytes", "deadlocks", "blk_read_time", "blk_write_time"), 0),
                             "stats_reset": None, "xact_commit": i},
                "tables": [{**dict.fromkeys(("seq_scan", "seq_tup_read", "idx_scan", "idx_tup_fetch", "n_tup_ins",
                                             "n_tup_upd", "n_tup_del", "n_tup_hot_upd", "n_live_tup", "n_dead_tup"), 0),
                            "name": "app.jobs"}],
            }
            for i in range(0, measured + 1, 5)
        ),
    ]


def test_sampler_requires_each_source_and_full_drain_coverage() -> None:
    rows = raw_trial(loadgen.Stage("coverage", 2, warmup=0, measured=20, drain=10))
    samples = sampler_evidence(20, 10)
    assert load_report.summarize(rows, {"ok": True}, samples)["outcome"] == "passed"
    for partial in (
        [row for row in samples if row["kind"] != "containers"],
        [row for row in samples if row["utc"] <= start_utc(21)],
        [row for row in samples if row["kind"] != "host" or row["utc"] != start_utc(22)],
        [row for row in samples if row["kind"] != "postgres" or row["utc"] != start_utc(25)],
    ):
        assert load_report.summarize(rows, {"ok": True}, partial)["outcome"] == "unverified"


def decision_trial() -> list[dict[str, Any]]:
    rows = raw_trial(loadgen.Stage("decision", 2, w3=1, warmup=0, measured=2, drain=1))
    rows.extend({"kind": "write", "index": index, "phase": "measured", "case_id": f"case-{index}",
                 "control": "race", "decisions": outcomes}
                for index, outcomes in enumerate(([201, 409], [None, 500])))
    for i, status in enumerate((201, 409, None, 500)):
        rows.append(
            {
                "kind": "http",
                "phase": "measured",
                "endpoint": "decision",
                "case_id": f"case-{i // 2}",
                "intended": 0,
                "sent": 0,
                "status": status,
                "done": (0.1, 1.5, 2.0, 0.7)[i],
                "error": ("", "", "deadline", "http_500")[i] or None,
            }
        )
    rows.append(
        {
            "kind": "timing",
            "phase": "measured",
            "endpoint": "approval_to_terminal",
            "case_id": "case-0",
            "choice": "approve",
            "intended": 0,
            "sent": 0,
            "done": 0.5,
            "status": 200,
        }
    )
    return rows


def test_decision_latency_includes_losing_race_and_transport_error() -> None:
    result = load_report.summarize(decision_trial(), {"ok": True})
    assert result["decision_http_s"]["p95"] == 2.0 and result["decision_http_s"]["n"] == 4
    assert result["decision_http_by_status_s"]["409"]["p95"] == 1.5
    assert result["decision_http_by_status_s"]["no_response"]["n"] == 1
    assert result["outcome"] == "failed"


def test_dispatch_rechecks_lateness_after_task_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> list[dict[str, Any]]:
        now = 0.0
        output = StringIO()
        stage = loadgen.Stage("spacing", 32, warmup=0, measured=1, drain=1)
        log = loadgen.Log(output, stage, 0)
        monkeypatch.setattr(log, "now", lambda: now)
        actual_create_task = asyncio.create_task
        sent: list[int] = []

        async def wait(when: float) -> None:
            nonlocal now
            now = max(now, when)
            await asyncio.sleep(0)
            await asyncio.sleep(0)

        def create_task(coro: Any) -> asyncio.Task[Any]:
            async def delayed() -> Any:
                nonlocal now
                if coro.cr_code.co_name == "run" and not sent:
                    now = max(now, 0.03)
                return await coro

            return actual_create_task(delayed())

        async def execute(slot: loadgen.Slot, row: loadgen.Record) -> None:
            sent.append(slot.index)
            row.status = 200

        monkeypatch.setattr(loadgen, "wait_until", wait)
        monkeypatch.setattr(asyncio, "create_task", create_task)
        await loadgen.dispatch(loadgen.schedule(stage, 10)[:2], log, execute, asyncio.Event())
        assert sent == [1]
        return [json.loads(line) for line in output.getvalue().splitlines()]

    first, second = asyncio.run(run())
    assert first["error"] == "missed_slot" and first["sent"] is None
    assert first["dispatch_lag"] == first["done"] - first["intended"] > loadgen.SEND_LAG_LIMIT
    assert second["status"] == 200


@pytest.mark.parametrize("marker", [None, True])
def test_round3_enrollment_refuses_wrong_volume_or_live_issuer_before_lock(
    marker: bool | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime, "SECRETS", tmp_path)
    monkeypatch.setenv("POLICYOPS_ENV", "local")
    monkeypatch.setenv("POLICYOPS_N10_RUN_ID", "n10-unit")
    monkeypatch.setenv("POLICYOPS_N10_ISSUER", ISSUER)
    (tmp_path / "n10_load_token").write_text(TOKEN, encoding="ascii")
    (tmp_path / "n10_deny_hosts").write_text(DENIED_HOST + "\n", encoding="ascii")
    config = load_identity.load_config()
    commands = []

    def query(sql: Any, _params: Any = None) -> Mock:
        statement = str(sql)
        commands.append(statement)
        if "shobj_description" in statement:
            return Mock(scalar_one=Mock(return_value=marker))
        if statement == "SELECT DISTINCT issuer FROM identity.principals":
            return Mock(scalars=Mock(return_value=Mock(all=Mock(return_value=[f"https://{DENIED_HOST}/dex"]))))
        raise AssertionError(f"unexpected SQL before safety checks: {statement}")

    conn = Mock(execute=Mock(side_effect=query))
    with pytest.raises(load_identity.SeedError, match="stored issuer" if marker else "volume marker"):
        load_identity.initialize(conn, config)
    assert len(commands) == (2 if marker else 1)
    conn.exec_driver_sql.assert_not_called()


def test_round3_cloud_preflight_refuses_before_docker_and_pins_local_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import load_preflight

    host = "disposable.example.invalid"
    (tmp_path / "hostname").write_text(host, encoding="ascii")
    deny_file = tmp_path / "deny"
    deny_file.write_text(DENIED_HOST, encoding="ascii")
    machine_id = tmp_path / "machine-id"
    machine_id.write_text("machine-1", encoding="ascii")
    marker_file = tmp_path / "n10-instance.json"
    marker = {"run_id": "n10-unit", "instance": "policyops-load", "machine_id": "machine-1", "docker_id": "daemon-1"}
    monkeypatch.setattr(load_preflight, "STATE", tmp_path)
    monkeypatch.setattr(load_preflight, "Path", lambda _: machine_id)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    docker = Mock(return_value=Mock(stdout="daemon-2\n"))
    monkeypatch.setattr("scripts.load_preflight.subprocess.run", docker)

    def check() -> None:
        load_preflight.preflight("n10-unit", "policyops-load", host, deny_file)

    with pytest.raises(FileNotFoundError):
        check()
    marker_file.write_text(json.dumps(dict(marker, instance="other-instance")), encoding="ascii")
    with pytest.raises(ValueError, match="instance marker"):
        check()
    marker_file.write_text(json.dumps(marker), encoding="ascii")
    deny_file.write_text(host, encoding="ascii")
    with pytest.raises(ValueError, match="hostname check"):
        check()
    deny_file.write_text(DENIED_HOST, encoding="ascii")
    with monkeypatch.context() as context:
        context.setenv("DOCKER_CONTEXT", "other-host")
        with pytest.raises(ValueError, match="local daemon"):
            check()
    cd_dir = tmp_path / "cd"
    cd_dir.mkdir()
    with pytest.raises(ValueError, match="CD state"):
        check()
    cd_dir.rmdir()
    docker.assert_not_called()
    with pytest.raises(ValueError, match="daemon does not match"):
        check()
    docker.return_value.stdout = "daemon-1\n"
    check()
    assert docker.call_args.args[0] == ["docker", "--host", load_preflight.LOCAL_DOCKER, "info", "--format", "{{.ID}}"]


def test_round3_handoff_guards_deploy_and_compose() -> None:
    path = Path(__file__).resolve().parents[2] / "HANDOFF.md"
    if not path.is_file():
        pytest.skip("private operator handoff is external to published sources")
    handoff = path.read_text(encoding="utf-8")
    cloud = handoff.split("## Lightsail", 1)[1].split("## Offline gates", 1)[0]
    assert "n10_preflight && docker --host unix:///var/run/docker.sock compose" in cloud
    assert "n10_preflight && DOCKER_HOST=unix:///var/run/docker.sock bash infra/deploy/deploy.sh" in cloud
    assert "n10_compose -p policyops-public" in cloud
    assert "compose=(n10_compose " in cloud
    assert "\n  docker compose " not in cloud


@pytest.mark.parametrize("mismatch", ["environment", "stage", "profile_sha256", "target_sha256", "seed", "invalid"])
def test_round3_unmatched_or_invalid_replacement_cannot_clear_correctness_failure(mismatch: str) -> None:
    rows = [trial("sweep", "w1-32", start=1)]
    rows.extend(trial(f"r{i}", f"repeat-pass-{i}", start=i + 1) for i in range(1, 4))
    original = trial("failure", "repeat-pass-4", ok=False, start=5)
    retry = trial("retry", "repeat-pass-4", start=6)
    if mismatch == "invalid":
        retry["outcome"] = "invalid"
        retry["generator_valid"] = False
    elif mismatch == "stage":
        retry["meta"]["stage"]["warmup"] = 0
    else:
        retry["meta"][mismatch] = 11 if mismatch == "seed" else "different"
    rows.extend((original, retry))
    plan = plan_for(*rows)
    plan[-1].update(replaces="failure", reason="Coordinator approved the retry.")
    result = load_report.capacity(rows, plan)
    assert result["passing_rps"] is None and result["correctness_abort_pending"] == "failure"
    assert "replaced_by" not in result["attempts"][-2]


@pytest.mark.parametrize("mismatch", ["target_sha256", "w1", "warmup", "seed", "dataset_sha256"])
def test_round3_paired_analysis_requires_single_configuration_across_pairs(mismatch: str) -> None:
    order = ("a1", "b1", "b2", "a2", "a3", "b3", "b4", "a4", "a5", "b5")
    rows = [trial(label, "fix-" + label, start=i, value=1 if label.startswith("a") else 0.7)
            for i, label in enumerate(order)]
    for row in rows[-2:]:
        if mismatch in {"w1", "warmup"}:
            row["meta"]["stage"][mismatch] = 8
        else:
            row["meta"][mismatch] = 11 if mismatch == "seed" else "different"
    plan = worker_drain_pairs("messages")
    with pytest.raises(ValueError, match="all ten"):
        load_report.paired_analysis(rows, plan)


def error_body() -> dict[str, Any]:
    return {
        "schema_version": "policyops.error/v1", "code": "not_found", "detail": "No such resource.",
        "rule_id": "api.case_not_found", "correlation_id": "6b400901-7068-4b1f-9dbe-ab550cd983bd", "retryable": False,
    }


@pytest.mark.parametrize("route", ["rest", "stream", "canary_rest", "canary_stream"])
@pytest.mark.parametrize("malformed", [{"case_id": "foreign-case"}, {"correlation_id": "invalid"}])
def test_round3_error_envelopes_reject_extra_or_malformed_ids(route: str, malformed: dict[str, str]) -> None:
    async def run() -> None:
        response = Mock(side_effect=lambda _: httpx.Response(404, json={**error_body(), **malformed}))
        async with httpx.AsyncClient(base_url="https://disposable.example.invalid",
                                     transport=httpx.MockTransport(response)) as client:
            work, session, scope, _ = workbook(client)
            work.log.start += work.log.now()
            case, run = str(scope.case_id), str(scope.run_id)
            if route.startswith("canary_"):
                def canary_response(request: httpx.Request) -> httpx.Response:
                    selected = request.url.path.endswith("/events") == (route == "canary_stream")
                    resource = "run" if request.url.path.endswith("/events") else "case"
                    return httpx.Response(404, json={**error_body(), "detail": f"No such {resource}.",
                                                    "rule_id": f"api.{resource}_not_found",
                                                    **(malformed if selected else {})})

                response.side_effect = canary_response
                work.manifest["canary"] = {
                    "workspace_id": "foreign-workspace", "case_id": "foreign-case", "run_id": "foreign-run",
                    "proposal_id": "foreign-proposal", "proposal_version": 1,
                }
                with pytest.raises(loadgen.Violation, match="invalid_error_envelope"):
                    await work.canaries(measured=True)
            elif route == "stream":
                with pytest.raises(loadgen.Violation, match="invalid_error_envelope"):
                    await work.stream(session, case, run, 1, loadgen.Record("slot", "workflow", "measured", 0),
                                      workflow=True)
            else:
                with pytest.raises(loadgen.Violation, match="invalid_error_envelope"):
                    await work.request(session, loadgen.ReadRequest("/cases/" + case, case),
                                       loadgen.Record("slot", "case_detail", "measured", 0))

    asyncio.run(run())


def test_round3_persisted_http_rule_ids_use_only_api_codes() -> None:
    for rule, label in [("api.case_not_found", "api.case_not_found"), ("private-diagnostic-9f832cd8", "unrecognized")]:
        row = loadgen.Record("http", "case_detail", "measured", 0)
        loadgen.status(row, httpx.Response(404, json={**error_body(), "rule_id": rule}))
        output = StringIO()
        loadgen.Log(output, loadgen.Stage("rule-ids", 2), 0).record(row)
        assert json.loads(output.getvalue())["rule_id"] == label
        if rule != label:
            assert rule not in output.getvalue()


def test_round3_checker_flags_unchanged_unhealthy_jobs_in_all_study_workspaces(monkeypatch: pytest.MonkeyPatch) -> None:
    workspaces = [str(UUID(int=i)) for i in (1, 2, 3)]
    empty: dict[str, Any] = {table: {} for table in ("decisions", "executions", "jobs", "messages", "consents")}
    states = {"dead_jobs": "dead", "overdue_queued_jobs": "queued", "expired_job_leases": "leased"}
    inventories = {workspace: {**empty, "jobs": {"existing": {"state": state}}}
                   for workspace, state in zip(workspaces, states.values(), strict=True)}
    manifest = {"demo": workspaces[0], "second": workspaces[1], "foreign": workspaces[2], "principals": {},
                "workspaces": {}, "writes": [], "accounting": inventories}

    @contextmanager
    def scoped(_app: Any, workspace: UUID) -> Any:
        key = list(states)[workspaces.index(str(workspace))]

        def execute(statement: Any) -> Mock:
            assert "available_at <= statement_timestamp()" in str(statement)
            assert "lease_expires_at <= statement_timestamp()" in str(statement)
            return Mock(mappings=Mock(return_value=Mock(one=Mock(return_value={key: 1}))))

        yield Mock(workspace=str(workspace), execute=execute)

    monkeypatch.setattr(loadcheck, "workspace_transaction", scoped)
    monkeypatch.setattr(loadcheck, "transaction", MagicMock())
    monkeypatch.setattr(loadcheck, "workspace_accounting", lambda conn: inventories[conn.workspace])
    result = loadcheck.check(Mock(), Mock(), manifest, [{"kind": "stage_end", "aborted": False}])
    assert {(row["workspace"], row["error"], row["count"]) for row in result["violations"] if "workspace" in row} == {
        (workspace, key, 1) for workspace, key in zip(workspaces, states, strict=True)
    }


@pytest.mark.parametrize("missing", ["inspect", "stats", "steal", "postgres", "counter_brackets", "counter_fields"])
def test_round3_sampler_requires_actual_measurements_and_counter_brackets(missing: str) -> None:
    samples = sampler_evidence(20, 10)
    valid = load_report.summarize_sampler(samples, NOW, NOW + timedelta(seconds=20), NOW + timedelta(seconds=30))
    assert valid["coverage_ok"] and valid["counter_deltas"]["seconds"] == 20
    if missing == "counter_brackets":
        adjacent = {start_utc(5), start_utc(10)}
        samples = [row for row in samples if row["kind"] != "pg_counters" or row["utc"] in adjacent]
    for row in samples:
        if row["kind"] == "containers" and missing in {"inspect", "stats"}:
            row[missing]["api"] = {}
        elif row["kind"] == "host" and missing == "steal":
            row["cpu_percent"].pop("steal")
        elif row["kind"] == "postgres" and missing == "postgres":
            row["activity"] = None
        elif row["kind"] == "pg_counters" and missing == "counter_fields":
            row["database"].pop("xact_commit")
    trial_rows = raw_trial(loadgen.Stage("coverage", 2, warmup=0, measured=20, drain=10))
    assert load_report.summarize(trial_rows, {"ok": True}, samples)["outcome"] == "unverified"


def test_round3_missing_race_loser_latency_invalidates_stage() -> None:
    rows = decision_trial()
    rows = [row for row in rows if row["kind"] != "http" or row["status"] != 409]
    result = load_report.summarize(rows, {"ok": True})
    assert result["outcome"] == "invalid" and not result["decision_evidence_ok"]
    assert result["decision_http_s"]["p95"] is None
    assert "decision" not in result["routes"]


def test_round3_missed_slots_keep_unsent_status_and_count_towards_dispatch_p99() -> None:
    rows = raw_trial(loadgen.Stage("late", 10, warmup=0, measured=10, drain=1))
    slots = [row for row in rows if row["kind"] == "slot"]
    for row in slots[:2]:
        row.update(sent=None, status=None, error="missed_slot", dispatch_lag=0.009, done=row["intended"] + 0.009)
    result = load_report.summarize(rows)
    assert result["outcome"] == "invalid" and not result["generator_valid"]
    assert result["send_lag_p99_s"] == 0.009 and result["browse"]["sent"] == 98


@pytest.mark.parametrize(
    ("offered", "reason", "failure", "outcome"),
    [
        (26, "missed_slot", None, "failed"),
        (90, "overflow", None, "failed"),
        (99, "missed_slot", None, "failed"),
        (100, "overflow", None, "unverified"),
        (100, "missed_slot", "receipt", "failed"),
        (100, "overflow", "checker", "failed"),
        (100, "missed_slot", "lag", "invalid"),
    ],
)
def test_round6_report_counts_dispatch_misses_and_started_failures(
    offered: int, reason: str, failure: str | None, outcome: str,
) -> None:
    rows = raw_trial(loadgen.Stage("w3", 2, w3=0.5, warmup=0, measured=offered * 2, drain=1))
    slots = [row for row in rows if row.get("endpoint") == "workflow"]
    slots[0].update(sent=None, status=None, error=reason, dispatch_lag=0.009)
    for slot in slots[1:]:
        index = slot["index"]
        case = f"case-{index}"
        rows.extend([
            {"kind": "write", "index": index, "phase": "measured", "case_id": case,
             "control": "approve", "decisions": [201]},
            {"kind": "http", "endpoint": "decision", "phase": "measured", "case_id": case,
             "status": 201, "intended": 0, "sent": 0, "done": 0.1},
            {"kind": "timing", "endpoint": "approval_to_terminal", "phase": "measured", "case_id": case,
             "choice": "approve", "status": 200, "intended": 0, "sent": 0, "done": 1},
        ])
    violations = []
    if failure == "receipt":
        slots[-1]["error"] = "terminal_receipt_missing"
        rows.pop()
    elif failure == "checker":
        violations.append({"error": "decision_status", "case_id": "case-1"})
    elif failure == "lag":
        for slot in slots[1:8]:
            slot["sent"] = slot["intended"] + 0.009
    check = {"ok": not violations, "violations": violations,
             "not_dispatched": [{"index": 0, "case_id": "case-0", "reason": reason}]}
    result = load_report.summarize(rows, check)
    assert result["generator_valid"] == (failure != "lag") and result["outcome"] == outcome
    assert result["workflow"]["offered"] == offered
    assert result["workflow"]["generator_misses"] == 1
    assert result["workflow"]["generator_miss_allowance"] == offered // 100
    assert result["workflow"]["sut_failures"] == int(failure in {"receipt", "checker"})
    assert result["correctness_failed"] == bool(violations)
    report = load_report.markdown({"trials": [result], "repeats": [], "capacity": load_report.capacity([result])})
    assert f"Slot 0 (case `case-0`) `{reason}`" in report


@pytest.mark.parametrize("reason", ["missed_slot", "overflow"])
def test_round6_checker_verifies_undispatched_fixtures(monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    workspaces = [str(UUID(int=index)) for index in (1, 2, 3)]
    workspace = workspaces[0]
    expiry = {"kind": "run.review", "review_trigger": "expiry", "state": "queued",
              "run_id": "run", "proposal_id": "proposal", "proposal_version": 1}
    before: dict[str, Any] = {"decisions": {}, "executions": {}, "jobs": {"expiry": expiry},
                              "messages": {}, "consents": {}}
    empty: dict[str, Any] = {table: {} for table in before}
    manifest = {
        "demo": workspace, "second": workspaces[1], "foreign": workspaces[2], "principals": {}, "workspaces": {},
        "writes": [{"workspace_id": workspace, "case_id": "case", "run_id": "run", "simulator_version": 5}],
        "accounting": {**dict.fromkeys(workspaces, empty), workspace: before},
    }
    baseline = loadcheck.Observed((), (), 0, (), (), 0, (), 5, 0, 0, "waiting_input", None)
    read = Mock(return_value=baseline)
    after = Mock(return_value=before)
    monkeypatch.setattr(loadcheck, "read_case", read)
    monkeypatch.setattr(loadcheck, "workspace_transaction", lambda _, scope: nullcontext(str(scope)))
    monkeypatch.setattr(loadcheck, "transaction", MagicMock())
    monkeypatch.setattr(loadcheck, "workspace_accounting", lambda scope: after() if scope == workspace else empty)
    monkeypatch.setattr(loadcheck, "workspace_job_health", lambda _: {})
    digest = sha256_hex(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    rows: list[dict[str, Any]] = [
        {"kind": "meta", "stage": {"limiter": True}, "manifest_sha256": digest},
        {"kind": "slot", "endpoint": "workflow", "index": 0, "sent": None, "error": reason},
        {"kind": "stage_end", "aborted": False},
    ]
    result = loadcheck.check(Mock(), Mock(), manifest, rows)
    assert result["ok"] and result["violations"] == []
    assert result["not_dispatched"] == [{"index": 0, "case_id": "case", "reason": reason}]

    for change in ({"consents": ("consent",)}, {"decision_ids": ("approval",)}, {"simulator_version": 6},
                   {"executions": (loadcheck.Execution("proposal", 1, "pending", None, None, None, None),)}):
        read.return_value = replace(baseline, **change)
        result = loadcheck.check(Mock(), Mock(), manifest, rows)
        assert not result["ok"]
        assert {"error": "undispatched_workflow_effect", "case_id": "case"} in result["violations"]

    read.return_value = baseline
    after.return_value = {**before, "jobs": {"expiry": {**expiry, "state": "done",
                                                        "last_error_code": "proposal_expired"}}}
    result = loadcheck.check(Mock(), Mock(), manifest, rows)
    assert not result["ok"] and {"error": "jobs_inventory_changed", "workspace": workspace} in result["violations"]


def test_round3_prior_wave_expiry_requires_exact_persisted_decision_binding() -> None:
    binding = {"run_id": "prior-wave-run", "proposal_id": "prior-wave-proposal", "proposal_version": 1}
    before = {"decisions": {"prior": {**binding, "case_id": "prior-case", "decision": "approve"}},
              "jobs": {"expiry": {**binding, "kind": "run.review", "review_trigger": "expiry", "state": "queued"}},
              "messages": {}, "consents": {}, "executions": {}}
    after = deepcopy(before)
    after["jobs"]["expiry"].update(state="done", last_error_code="superseded_by_decision")
    assert loadcheck.check_workspace(before, after, []) == []
    for field in binding:
        wrong_before, wrong_after = deepcopy(before), deepcopy(after)
        for inventory in (wrong_before, wrong_after):
            inventory["decisions"]["prior"][field] = "other"
        assert loadcheck.check_workspace(wrong_before, wrong_after, []) == ["jobs_inventory_changed"]


@pytest.mark.parametrize("mode", ["check", "explain"])
@pytest.mark.parametrize("source", ["stdin", "file"])
def test_round4_checker_reads_bom_and_crlf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str, source: str,
) -> None:
    raw = b'\xef\xbb\xbf{"kind":"stage_end","aborted":false}\r\n'
    bundle = b'\xef\xbb\xbf{"v":2,"load_run_id":"n10-unit"}\r\n' + (raw if mode == "check" else b"")
    argv = ["loadcheck", mode]
    if source == "file":
        path = tmp_path / "input.jsonl"
        path.write_bytes(bundle)
        argv.extend(("--input", str(path)))
    else:
        monkeypatch.setattr(sys, "stdin", TextIOWrapper(BytesIO(bundle), encoding="utf-8"))
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(loadcheck, "load_config", lambda: Mock(run_id="n10-unit"))
    monkeypatch.setattr(loadcheck, "verify_identity", Mock())
    monkeypatch.setattr(loadcheck, "own_engine", lambda _role: MagicMock())
    monkeypatch.setattr(loadcheck, "check", lambda _app, _auth, manifest, rows: {
        "ok": manifest["v"] == 2 and list(rows) == [{"kind": "stage_end", "aborted": False}],
    })
    monkeypatch.setattr(loadcheck, "explain", lambda _app, _auth, manifest: {"version": manifest["v"]})
    assert loadcheck.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result == ({"ok": True, "raw_sha256": sha256_hex(raw)} if mode == "check"
                      else {"ok": True, "plans": {"version": 2}})


@pytest.mark.parametrize("overshoot", [0.0, 0.0015])
def test_round5_windows_slot_uses_waitable_timer_and_bounded_yields(
    monkeypatch: pytest.MonkeyPatch, overshoot: float,
) -> None:
    async def trial_wait() -> None:
        now = 0.0
        yields = []
        timers = []

        async def sleep(delay: float) -> None:
            nonlocal now
            assert delay == 0
            yields.append(now)
            now += 0.0005

        def waitable_timer(delay: float) -> None:
            nonlocal now
            timers.append(delay)
            now += delay + overshoot

        async def to_thread(wait: Any, delay: float) -> None:
            wait(delay)

        with monkeypatch.context() as patch:
            patch.setattr(sys, "platform", "win32")
            patch.setattr(loadgen, "time", Mock(perf_counter=lambda: now, sleep=waitable_timer))
            patch.setattr(asyncio, "sleep", sleep)
            patch.setattr(asyncio, "to_thread", to_thread)
            await loadgen.wait_until(0.125)
        assert timers == pytest.approx([0.123])
        assert 1 <= len(yields) <= 5
        assert 0.123 <= yields[0] <= 0.125
        assert 0.125 <= now <= 0.1255

    asyncio.run(trial_wait())


def test_round4_pilot_pins_and_checks_docker_and_buildx() -> None:
    handoff = Path("HANDOFF.md")
    if not handoff.is_file():
        pytest.skip("private operator handoff is external to published sources")
    pilot = handoff.read_text(encoding="utf-8").split("## Coordinator pilot on Windows", 1)[1].split(chr(96) * 3, 2)[1]
    assert "$env:DOCKER_CONTEXT = 'desktop-linux'" in pilot
    assert "$localDocker = @('--context', 'desktop-linux')" in pilot
    assert "$dc = $localDocker +" in pilot
    assert "docker @localDocker context inspect desktop-linux" in pilot
    assert "npipe:////./pipe/dockerDesktopLinuxEngine" in pilot
    assert "docker @localDocker info --format '{{.Name}}|{{.OperatingSystem}}|{{.ID}}'" in pilot
    assert "(Get-N10DockerId) -cne $dockerId" in pilot
    assert "$env:BUILDX_CONFIG = (New-Item" in pilot
    for command in ("build", "up -d --no-build", "down --volumes"):
        assert f"\nConfirm-N10Docker\n& docker @dc {command}" in pilot
    assert "--builder desktop-linux" not in pilot
    assert "--count $waveCount --warm-slots $warmSlots" in pilot
    assert "-RedirectStandardInput $InputPath" in pilot and "--input $containerInput" in pilot


def test_round4_sampler_abort_cannot_supersede_correctness_abort() -> None:
    original = trial("original", "w1-32", ok=False)
    retry = trial("retry", "w1-32", start=2)
    retry["outcome"] = "failed"
    retry["server"]["abort"] = ["TimeoutExpired"]
    plan = plan_for(original, retry)
    plan[-1].update(replaces="original", reason="Authorized rerun")
    result = load_report.capacity([original, retry], plan)
    assert result["correctness_abort_pending"] == "original"
    assert "replaced_by" not in result["attempts"][0]


def test_round4_dataset_metadata_changes_with_message_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, profile = tmp_path / "token", tmp_path / "profile.json"
    token.write_text(TOKEN, encoding="ascii")
    profile.write_text("{}", encoding="ascii")
    args = argparse.Namespace(
        deny_ip=[], expect_ip=None, token_file=token, ca_file=None, seed=10, profile=profile,
        environment="workstation", run="unit",
    )
    monkeypatch.setattr(loadgen, "approved_address", lambda *_args: "127.0.0.1")
    monkeypatch.setattr(loadgen, "PinnedTransport", Mock(side_effect=loadgen.Refused("metadata collected")))
    case, run, message = (UUID(int=index) for index in (31, 32, 33))
    event = Mock(id=UUID(int=34), run_id=run, sequence=1, payload={"type": "run.state_changed"})
    case_row = Mock(id=case, created_by=None, status="open", version=2, scenario="retail", customer_user_id="fictional")
    run_row = Mock(id=run, case_id=case, initiated_by=None, state="waiting_input")
    tables = {"app.cases": [case_row], "app.runs": [run_row], "app.action_proposals": [], "app.run_events": [event]}
    conn = Mock(execute=lambda query: Mock(all=lambda: tables[str(query).split("FROM ")[1].split()[0]]))
    scoped = MagicMock(__enter__=Mock(return_value=conn))
    message_row = {"case_id": str(case), "sequence": 1, "source": "seeded", "entered_by": None,
                   "text_sha256": sha256_hex(b"fictional message")}
    monkeypatch.setattr(loadseed, "workspace_transaction", lambda *_args: scoped)
    monkeypatch.setattr(loadseed, "workspace_accounting", lambda _conn: {
        "messages": {str(message): message_row}, "consents": {}, "decisions": {},
    })
    manifest: dict[str, Any] = {
        "v": 2, "seed": 10, "principals": {"alice": "alice"}, "customer_user_id": "fictional",
        "counts": {"workspace": {"messages": 1}}, "canary": {}, "writes": [], "workspaces": {},
    }

    def metadata() -> dict[str, Any]:
        inv = loadseed.inventory(Mock(), UUID(int=30))
        inv.pop("accounting")
        manifest["workspaces"]["workspace"] = inv
        output = StringIO()
        with pytest.raises(loadgen.Refused, match="metadata collected"):
            asyncio.run(loadgen.experiment(args, httpx.URL(ISSUER), loadgen.Stage("unit", 2), manifest, output))
        row: dict[str, Any] = json.loads(output.getvalue())
        return row

    baseline = metadata()["dataset_sha256"]
    event.id = UUID(int=35)
    assert metadata()["dataset_sha256"] == baseline
    message_row["text_sha256"] = sha256_hex(b"changed fictional message")
    assert metadata()["dataset_sha256"] != baseline


@pytest.mark.parametrize("disclosure", ["detail", "correlation_id", "rule_id", "retryable"])
def test_round4_canary_requires_the_endpoint_diagnostic(disclosure: str) -> None:
    async def run() -> None:
        foreign = {key: str(UUID(int=index)) for index, key in
                   enumerate(("workspace_id", "case_id", "run_id", "proposal_id"), 100)}
        injected = {
            "detail": f"No such run. Foreign workspace {foreign['workspace_id']}.",
            "correlation_id": foreign["workspace_id"],
            "rule_id": "api.case_not_found",
            "retryable": True,
        }
        leak = False

        def respond(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            resource = "proposal" if "/proposals/" in path else ("run" if "/runs/" in path else "case")
            body = {**error_body(), "detail": f"No such {resource}.", "rule_id": f"api.{resource}_not_found"}
            if leak and path.endswith("/events"):
                body[disclosure] = injected[disclosure]
            return httpx.Response(404, json=body)

        async with httpx.AsyncClient(base_url=ISSUER, transport=httpx.MockTransport(respond)) as client:
            work, *_ = workbook(client)
            work.manifest["canary"] = {**foreign, "proposal_version": 1}
            await work.canaries()
            leak = True
            with pytest.raises(loadgen.Violation, match="invalid_canary_error"):
                await work.canaries(measured=True)

    asyncio.run(run())


@pytest.mark.parametrize(("field", "invalid"), [
    ("CPUPerc", "N/A"), ("MemPerc", "0.5"), ("MemUsage", "5.2GB / 1Gi"), ("NetIO", "30% / 8%"), ("PIDs", "2.5"),
])
def test_round4_unparseable_docker_measurement_leaves_trial_unverified(field: str, invalid: str) -> None:
    rows = raw_trial(loadgen.Stage("coverage", 2, warmup=0, measured=20, drain=10))
    samples = sampler_evidence(20, 10)
    assert load_report.summarize(rows, {"ok": True}, samples)["outcome"] == "passed"
    next(row for row in samples if row["kind"] == "containers")["stats"]["api"][field] = invalid
    assert load_report.summarize(rows, {"ok": True}, samples)["outcome"] == "unverified"


@pytest.mark.parametrize("problem", ["missing", "duplicate", "wrong_case"])
def test_round4_measured_approval_requires_exactly_one_terminal_timing(problem: str) -> None:
    rows = decision_trial()
    assert load_report.summarize(rows)["outcome"] == "failed"
    timing = rows.pop()
    if problem == "duplicate":
        rows.extend((timing, dict(timing)))
    elif problem == "wrong_case":
        rows.append({**timing, "case_id": "case-1"})
    result = load_report.summarize(rows)
    assert result["outcome"] == "invalid"
    assert result["approval_to_terminal_s"]["p95"] is None


def test_round4_prior_expiry_without_decision_matches_the_durable_projection() -> None:
    workspace, run, job, proposal, case = (UUID(int=index) for index in range(1, 6))
    binding = {"run_id": str(run), "proposal_id": str(proposal), "proposal_version": 1}
    before: dict[str, Any] = {
        "jobs": {str(job): {**binding, "kind": "run.review", "review_trigger": "expiry",
                            "state": "queued", "last_error_code": None}},
        "decisions": {}, "messages": {}, "consents": {}, "executions": {}, "expiry_outcomes": {},
    }
    after = deepcopy(before)
    after["jobs"][str(job)].update(state="done", last_error_code="proposal_expired")
    identifier = refusal_message_id(workspace, run, job)
    after["messages"][str(identifier)] = {
        "case_id": str(case), "source": "agent", "entered_by": None,
        "text_sha256": sha256_hex(refusal_text(RefusalReason.PROPOSAL_EXPIRED).encode()),
    }
    after["expiry_outcomes"]["event"] = {
        "case_id": str(case), "run_id": str(run),
        "payload": ReviewOutcome(proposal_id=proposal, proposal_version=1, outcome="refused",
                                 reason=ReviewReason.PROPOSAL_EXPIRED, message_id=identifier).model_dump(mode="json"),
    }
    assert loadcheck.check_workspace(before, after, [], workspace=workspace) == []
    after["expiry_outcomes"]["event"]["payload"]["proposal_version"] = 2
    assert loadcheck.check_workspace(before, after, [], workspace=workspace) == [
        "jobs_inventory_changed", "unexpected_messages_inventory",
    ]


def test_round4_sampler_redacts_unknown_postgres_application_names(monkeypatch: pytest.MonkeyPatch) -> None:
    pg_result = {"activity": [{"application_name": label, "count": 1}
                              for label in ("policyops-api-app", "fictional-credential", None)]}
    monkeypatch.setattr(load_sampler, "run", Mock(return_value=json.dumps(pg_result)))
    evidence = load_sampler.postgres("fixture", "policyops", load_sampler.ACTIVITY)
    assert [row["application_name"] for row in evidence["activity"]] == ["policyops-api-app", "other", "other"]


@pytest.mark.parametrize("mismatch", ["target_sha256", "dataset_sha256", "seed", "warmup"])
def test_round4_capacity_does_not_pool_mismatched_contributors(mismatch: str) -> None:
    rows = [trial("sweep", "w1-32"), *(trial(f"r{i}", f"repeat-pass-{i}", start=i + 1) for i in range(1, 4))]
    plan = plan_for(*rows)
    assert load_report.capacity(rows, plan)["passing_rps"] == 32
    if mismatch == "warmup":
        rows[-1]["meta"]["stage"]["warmup"] = 30
    else:
        rows[-1]["meta"][mismatch] = 11 if mismatch == "seed" else "different"
    assert load_report.capacity(rows, plan)["passing_rps"] is None


@pytest.mark.parametrize("problem", ["different_raw", "stale", "within_measurement", "after_end"])
def test_round4_report_binds_checker_and_brackets_credit_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, problem: str,
) -> None:
    evidence = tmp_path / "unit.jsonl"
    rows = raw_trial(loadgen.Stage("credit", 2, warmup=0, measured=20, drain=10))
    rows[0].update(environment="lightsail", setup_utc=start_utc(-10))
    raw = ("\n".join(map(json.dumps, rows)) + "\n").encode()
    evidence.write_bytes(raw)
    check = evidence.with_suffix(".check.json")
    credits = evidence.with_suffix(".credits.json")
    evidence.with_suffix(".sampler.jsonl").write_text(
        "\n".join(map(json.dumps, sampler_evidence(20, 10))), encoding="utf-8",
    )

    def report(label: str, digest: str, before: int, after: int) -> dict[str, Any]:
        check.write_text(json.dumps({"ok": True, "raw_sha256": digest}), encoding="utf-8")
        credits.write_text(json.dumps({
            side: {"utc": start_utc(offset), "BurstCapacityPercentage": 95, "CPUUtilization": 10}
            for side, offset in (("before", before), ("after", after))
        }), encoding="utf-8")
        prefix = tmp_path / label
        monkeypatch.setattr(sys, "argv", ["load_report", str(evidence), "--output-prefix", str(prefix)])
        assert load_report.main() == 0
        result: dict[str, Any] = json.loads(prefix.with_suffix(".json").read_bytes())["trials"][0]
        return result

    assert report("bound", sha256_hex(raw), -5, 25)["outcome"] == "passed"
    digest, before, after = {
        "different_raw": (sha256_hex(raw + b"\n"), -5, 25),
        "stale": (sha256_hex(raw), -86400, -86370),
        "within_measurement": (sha256_hex(raw), 1, 19),
        "after_end": (sha256_hex(raw), -5, 31),
    }[problem]
    assert report("unbound", digest, before, after)["outcome"] == "unverified"


def test_round4_paired_decision_metric_includes_unsuccessful_attempts() -> None:
    order = ("a1", "b1", "b2", "a2", "a3", "b3", "b4", "a4", "a5", "b5")
    rows = [trial(label, "fix-" + label, start=index) for index, label in enumerate(order)]
    for row, label in zip(rows, order, strict=True):
        baseline = label.startswith("a")
        row["routes"]["decision"] = {"successful_latency_s": {"p95": 0.8 if baseline else 0.3}}
        row["decision_http_s"] = {"p95": 1.0 if baseline else 1.5}
    plan = worker_drain_pairs("decision")
    assert not load_report.paired_analysis(rows, plan)["claim"]


@pytest.fixture
def terminal_trials() -> list[dict[str, Any]]:
    order = ("a1", "b1", "b2", "a2", "a3", "b3", "b4", "a4", "a5", "b5")
    rows = [trial(label, "fix-" + label, start=index) for index, label in enumerate(order)]
    for row, label in zip(rows, order, strict=True):
        baseline = label.startswith("a")
        row["meta"]["stage"].update(w1=2, batch=5)
        row["outcome"] = "failed" if baseline else "passed"
        row["workflow"]["succeeded"] = 5
        row["approval_to_terminal_s"] = {"p95": 12.0 if baseline else 6.0}
    return rows


@pytest.mark.parametrize("variant,claim", [("improvement", True), ("small", False), ("mixed", False),
                                          ("regression", False)])
def test_paired_approval_to_terminal_gate(terminal_trials: list[dict[str, Any]], variant: str, claim: bool) -> None:
    plan = worker_drain_pairs("approval_to_terminal")
    if variant == "small":
        for row in terminal_trials:
            if row["meta"]["run"].startswith("b"):
                row["approval_to_terminal_s"]["p95"] = 10.0
    elif variant == "mixed":
        terminal_trials[-1]["approval_to_terminal_s"]["p95"] = 13.0
    elif variant == "regression":
        terminal_trials[-1]["workflow"]["succeeded"] = 4
    result = load_report.paired_analysis(terminal_trials, plan)
    assert result["claim"] is claim
    assert result["arms"] == plan["arms"]
    assert result["regressions"] == (["b5"] if variant == "regression" else [])
    if claim:
        assert result["paired_improvement"] == [0.5] * 5
        assert result["bootstrap_ci95"] == [0.5, 0.5]


@pytest.mark.parametrize("index", [0, 1])
def test_paired_approval_to_terminal_requires_both_p95s(terminal_trials: list[dict[str, Any]], index: int) -> None:
    terminal_trials[index]["approval_to_terminal_s"]["p95"] = None
    with pytest.raises(ValueError, match="requires observations for both runs"):
        load_report.paired_analysis(terminal_trials, worker_drain_pairs("approval_to_terminal"))


@pytest.mark.parametrize("arms", [None, ["drain=0", "drain=1"], {"A": "drain=0"},
                                  {"A": "drain=0", "B": "drain=1", "C": "drain=1"}, {"A": "drain=0", "B": " "},
                                  {"A": "drain=0", "B": "drain=0"}, {"A": 0, "B": 1}])
def test_paired_plan_requires_distinct_arm_descriptions(terminal_trials: list[dict[str, Any]], arms: Any) -> None:
    plan = worker_drain_pairs("approval_to_terminal")
    if arms is None:
        del plan["arms"]
    else:
        plan["arms"] = arms
    with pytest.raises(ValueError, match="paired plan requires distinct, non-empty arm descriptions"):
        load_report.paired_analysis(terminal_trials, plan)


def test_wave_admission_denies_concurrent_seed_and_releases_lock() -> None:
    engine = MagicMock()
    conn = engine.connect.return_value.execution_options.return_value.__enter__.return_value
    conn.execute.return_value.scalar_one.return_value = False
    with pytest.raises(load_identity.SeedError, match="volume lock"), load_identity.wave_admission(engine):
        pytest.fail("concurrent seed admitted")
    conn.execute.return_value.scalar_one.return_value = True
    with pytest.raises(RuntimeError, match="fixture failed"), load_identity.wave_admission(engine):
        raise RuntimeError("fixture failed")
    assert "pg_advisory_unlock" in str(conn.execute.call_args.args[0])


def test_expired_control_is_presented_and_refused_by_its_timestamp(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = loadseed.workspaces(10)[0]
    transaction = MagicMock()
    conn = transaction.__enter__.return_value
    conn.execute.return_value.scalar_one.return_value = 0
    monkeypatch.setattr(loadseed, "workspace_transaction", Mock(return_value=transaction))
    facts = RetailFacts(world.customer(user_id=runtime.demo()["customer_id"]))
    monkeypatch.setattr(loadseed, "fixture", Mock(return_value=(facts, 1, TOKEN)))
    monkeypatch.setattr(loadseed, "waiting_run", Mock())
    monkeypatch.setattr(repo, "create_case", Mock(return_value=Mock(version=1)))
    monkeypatch.setattr(repo, "get_case", Mock(return_value=Mock(version=2)))
    monkeypatch.setattr(repo, "insert_proposal", Mock())
    set_status = Mock()
    monkeypatch.setattr(repo, "set_proposal_status", set_status)
    monkeypatch.setattr(DatabaseLeaseClock, "now", lambda *_: NOW)
    saved = []
    original_seal = loadseed.seal

    def seal(*args: Any, **kwargs: Any) -> Any:
        proposal = original_seal(*args, **kwargs)
        saved.append(proposal)
        return proposal

    def present(service: ProposalService, *args: Any) -> Any:
        assert service.clock.now(conn) < saved[0].expires_at < NOW
        return Presented(Mock(), Mock(message_id=UUID(int=20)))

    monkeypatch.setattr(loadseed, "seal", seal)
    monkeypatch.setattr(ProposalService, "_present_tx", present)
    (fixture,) = loadseed.seed_wave(Mock(), workspace, 10, "elapsed", ["expired"])
    set_status.assert_not_called()
    assert fixture["presentation_message_id"] == str(UUID(int=20))
    assert "UPDATE app.jobs SET available_at" in str(conn.execute.call_args.args[0])
    proposal = saved[0]
    refusal = evaluate(
        principal_id=uuid5(workspace, "bob"),
        roles=frozenset({Role.REVIEWER}),
        run_terminal=False,
        row_status="presented",
        proposal=proposal,
        existing=None,
        consent=None,
        request=DecisionRequest(
            proposal_version=1,
            action_digest=proposal.action_digest,
            decision="approve",
            reason="Fictional review.",
        ),
        approval_id=UUID(int=21),
        now=NOW,
    )
    assert isinstance(refusal, Refusal) and refusal.rule_id == "api.proposal_expired"
