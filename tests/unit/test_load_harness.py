"""Offline regression coverage for the N10 measurement and safety boundaries."""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from io import StringIO
from itertools import pairwise
import json
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from typing import Any
from unittest.mock import Mock

import httpx
import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from infra.compose import loadcheck, loadseed, runtime
from policyops.api.openapi import schema_app
from policyops.domain.examples import World
from policyops.domain.retail_rules import RetailFacts
from policyops_contracts.scalars import RunScope
from scripts import check_publication, load_report, load_sampler, loadgen


ROOT = Path(__file__).resolve().parents[2]
TOKEN = "ab" * 32
DENY = ["live.example.invalid"]


def test_schedule_reproduces_arrivals_routes_and_cases() -> None:
    stage = loadgen.Stage("sweep", w1=32)
    first = loadgen.schedule(stage, 14)
    assert first == loadgen.schedule(stage, 14)
    assert first != loadgen.schedule(stage, 15)
    assert len(first) == 240 * 32
    assert all(a.offset < b.offset for a, b in pairwise(first))
    assert Counter(slot.route for slot in first[:21]) == Counter((*loadgen.MIX, "inbox"))


def test_profiles_have_at_least_100_measured_w1_slots_for_send_lag_p99() -> None:
    for path in (ROOT / "infra/load").glob("*.json"):
        profile = json.loads(path.read_bytes())
        for item in profile["stages"]:
            # The smallest rate in the coordinator's sweep is 1 rps.
            rate = 1 if item["w1"] is None else None
            stage = loadgen.read_stage(path, item["id"], rate)
            measured = [slot for slot in loadgen.schedule(stage, 10)
                        if slot.route != "workflow" and stage.phase(slot.offset) == "measured"]
            assert len(measured) >= 100, (path, stage.id)

    with pytest.raises(loadgen.Refused, match="at least 100 measured W1 slots"):
        loadgen.read_stage(ROOT / "infra/load/repeat.json", "repeat-pass-1", 0.5)


def test_generator_rows_measure_a_blocked_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loadgen, "cpu_ticks", Mock(side_effect=[(0, 0), (100, 100)]))

    async def run() -> list[dict[str, Any]]:
        stage = loadgen.Stage("lag", 2, warmup=0, measured=0.2, drain=0.05)
        output = StringIO()
        log = loadgen.Log(output, stage, time.perf_counter())
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200))) as client:
            workload = Mock(log=log, abort=asyncio.Event())
            sampler = asyncio.create_task(loadgen.monitor(workload, client))
            await asyncio.sleep(0)
            time.sleep(0.17)
            await sampler
        return [json.loads(line) for line in output.getvalue().splitlines()]

    generator, = (row for row in asyncio.run(run()) if row["kind"] == "generator")
    assert generator["event_loop_lag_samples"] >= 1
    assert generator["event_loop_lag_max_s"] >= 0.05


def test_generator_distinguishes_cancellation_from_unsent_workflow() -> None:
    async def run() -> list[dict[str, Any]]:
        stage = loadgen.Stage("cancel", 2, warmup=0, measured=1, drain=0.05)
        output = StringIO()
        log = loadgen.Log(output, stage, time.perf_counter() + 0.02)
        abort = asyncio.Event()

        async def execute(_slot: loadgen.Slot, row: loadgen.Record) -> None:
            row.status = 201
            log.stop(abort, "test_abort")
            await asyncio.Event().wait()

        slots = [loadgen.Slot(index, index / 20, "workflow", 1, 0) for index in range(2)]
        await loadgen.dispatch(slots, log, execute, abort)
        return [json.loads(line) for line in output.getvalue().splitlines()]

    abort, cancelled, unstarted = asyncio.run(run())
    assert abort["kind"] == "abort" and abort["offset"] >= 0
    assert cancelled["error"] == "cancelled_by_abort" and cancelled["status"] == 201
    assert unstarted["error"] == "aborted" and unstarted["sent"] is None


def test_stalled_fake_server_preserves_arrival_latency_and_drops_overflow() -> None:
    async def run() -> list[dict[str, Any]]:
        async def handler(_request: httpx.Request) -> httpx.Response:
            await loadgen.wait_until(time.perf_counter() + 0.12)
            return httpx.Response(200)

        stage = loadgen.Stage("stall", 20, warmup=0, measured=0.15, drain=0.25)
        output = StringIO()
        log = loadgen.Log(output, stage, time.perf_counter())
        slots = [loadgen.Slot(index, index / 20, "messages", 1, 4) for index in range(3)]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:

            async def work(_slot: loadgen.Slot, row: loadgen.Record) -> None:
                response = await client.get("https://fake.example.invalid/")
                row.status = response.status_code

            await loadgen.dispatch(slots, log, work, asyncio.Event(), cap=1)
        return sorted((json.loads(line) for line in output.getvalue().splitlines()), key=lambda row: row["index"])

    first, *overflows = asyncio.run(run())
    assert first["status"] == 200 and first["intended"] == 0
    assert 0 <= first["sent"] <= 0.005
    assert first["done"] - first["sent"] >= 0.10
    assert load_report.elapsed(first) >= 0.10
    assert len(overflows) == 2
    assert all(row["error"] == "overflow" and row["sent"] is None for row in overflows)


def test_terraform_default_resources_and_budget_address() -> None:
    directory = ROOT / "infra/terraform/aws"
    main = (directory / "main.tf").read_text(encoding="utf-8")
    variables = (directory / "variables.tf").read_text(encoding="utf-8")
    parsed = dict(re.findall(r'^variable "([^"]+)" \{(.*?)^\}', variables, re.M | re.S))
    defaults = {name: re.search(r"^\s*default\s*=\s*(.*)$", body, re.M) for name, body in parsed.items()}
    assert {
        name: m.group(1)
        for name, m in defaults.items()
        if m is not None and name in {"name_suffix", "create_budget", "create_loadgen", "loadgen_bundle"}
    } == {"name_suffix": '""', "create_budget": "true", "create_loadgen": "false", "loadgen_bundle": '"nano_3_0"'}
    blocks = {
        (kind, name): body
        for kind, name, body in re.findall(r'^resource "([^"]+)" "([^"]+)" \{(.*?)^\}', main, re.M | re.S)
    }
    assert len(blocks) == len(re.findall(r"^resource ", main, re.M))
    live = {kind: body.replace("${var.name_suffix}", "") for (kind, name), body in blocks.items() if name == "demo"}
    assert live.keys() == {
        "aws_lightsail_key_pair",
        "aws_lightsail_instance",
        "aws_lightsail_static_ip",
        "aws_lightsail_static_ip_attachment",
        "aws_lightsail_instance_public_ports",
        "aws_budgets_budget",
    }
    assert all(not re.search(r"^\s*(count|for_each)\s*=", body, re.M) for body in live.values())
    assert '"policyops-demo-key"' in live["aws_lightsail_key_pair"]
    assert '"policyops-demo"' in live["aws_lightsail_instance"] and '"small_3_0"' in live["aws_lightsail_instance"]
    assert '"policyops-demo-ip"' in live["aws_lightsail_static_ip"]
    assert '"policyops-monthly"' in live["aws_budgets_budget"] and '"20"' in live["aws_budgets_budget"]
    assert all(value in live["aws_budgets_budget"] for value in ('"USD"', '"COST"', '"MONTHLY"', '"FORECASTED"'))
    assert 'var.name_suffix == "" ? ["0.0.0.0/0"]' in main
    ports = dict(re.findall(
        r'from_port\s*=\s*(\d+)\s+to_port\s*=\s*\1\s+cidrs\s*=\s*([^\n]+)',
        live["aws_lightsail_instance_public_ports"],
    ))
    assert ports == {"22": "[var.admin_cidr]", "80": '["0.0.0.0/0"]', "443": "local.https_cidrs"}
    assert re.search(r'https_cidrs\s*=\s*var.name_suffix == "" \? \[\"0.0.0.0/0\"\]', main)
    additions = [body for (_, name), body in blocks.items() if name == "loadgen"]
    assert len(additions) == 4
    assert all(re.search(r"count\s*=\s*var.create_loadgen \? 1 : 0", body) for body in additions)
    override = (ROOT / "infra/load/budget_override.tf").read_text(encoding="utf-8")
    assert re.search(r"count\s*=\s*var.create_budget \? 1 : 0", override)
    assert check_publication.path_error("docs/performance.md") is None


def test_guard_refuses_live_name_denied_resolution_and_missing_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    for host in (DENY[0].upper() + ".", "sub." + DENY[0]):
        with pytest.raises(loadgen.Refused, match="live hostname denied"):
            loadgen.target("https://" + host, DENY)
    url = loadgen.target("https://load.example.invalid", DENY)
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443))],
    )
    with pytest.raises(loadgen.Refused, match="address was denied"):
        loadgen.approved_address(url, ["192.0.2.10"], "192.0.2.10")
    with pytest.raises(loadgen.Refused, match="deny-ip"):
        loadgen.approved_address(url, [], "192.0.2.10")
    assert loadgen.approved_address(url, ["192.0.2.21"], "192.0.2.10") == "192.0.2.10"
    with pytest.raises(SystemExit) as error:
        loadgen.parser().parse_args(
            [
                "--target",
                str(url),
                "--deny-ip",
                "192.0.2.20",
                "--token-file",
                "none",
                "--password-dir",
                "none",
                "--manifest",
                "none",
                "--profile",
                "none",
                "--stage",
                "none",
                "--run",
                "none",
                "--environment",
                "lightsail",
                "--output",
                "none",
            ]
        )
    assert error.value.code == 2


def test_overlay_token_public_absence_and_guard_refusal() -> None:
    async def inspect() -> None:
        for supplied in (None, TOKEN):
            app = schema_app()
            transport = httpx.ASGITransport(app=runtime.ReadyApp(app, load_token=supplied))
            async with httpx.AsyncClient(base_url="https://example.invalid", transport=transport) as client:
                if supplied is None:
                    marker = await client.get(loadgen.MARKER)
                    ordinary = await client.get("/api/v1/no-such-route")
                    assert marker.status_code == ordinary.status_code == 404
                    envelope, expected = marker.json(), ordinary.json()
                    assert envelope.keys() == expected.keys()
                    assert {key: value for key, value in envelope.items() if key != "correlation_id"} == {
                        key: value for key, value in expected.items() if key != "correlation_id"
                    }
                    assert dict(marker.headers) == dict(ordinary.headers)
                    with pytest.raises(loadgen.Refused, match="token missing"):
                        await loadgen.check_marker(client, TOKEN)
                else:
                    await loadgen.check_marker(client, TOKEN)
                    with pytest.raises(loadgen.Refused, match="mismatched"):
                        await loadgen.check_marker(client, "cd" * 32)

    asyncio.run(inspect())
    for path in ("compose.yaml", "infra/compose/public.yaml", "infra/compose/observability.yaml"):
        assert "n10_load_token" not in (ROOT / path).read_text(encoding="utf-8")
    assert "n10_load_token" in (ROOT / "infra/compose/load.yaml").read_text(encoding="utf-8")
    disclosure = (ROOT / "docs/performance.md").read_text(encoding="utf-8")
    assert "disables the public limiter" in disclosure and "`policyops_auth_runtime` secret on the worker" in disclosure


def test_pinned_connections_preserve_tls_identity_and_refuse_cross_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []

    async def request(_transport: httpx.AsyncHTTPTransport, outgoing: httpx.Request) -> httpx.Response:
        seen.append((outgoing.url.host, outgoing.headers["host"], outgoing.extensions["sni_hostname"]))
        return httpx.Response(200)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", request)

    async def inspect() -> None:
        origin = loadgen.target("https://disposable.example.invalid", DENY)
        transport = loadgen.PinnedTransport(origin, "192.0.2.10", ssl.create_default_context())
        async with httpx.AsyncClient(base_url=origin, transport=transport) as client:
            assert (await client.get("/api/v1/health/n10-load?test=1")).status_code == 200
            with pytest.raises(loadgen.Refused, match="left the checked origin"):
                await client.get("https://different.example.invalid/")

    asyncio.run(inspect())
    assert seen == [("192.0.2.10", "disposable.example.invalid", "disposable.example.invalid")]


def test_sse_parser_handles_heartbeats_multiple_lines_gaps_and_duplicates() -> None:
    parser = loadgen.SSEParser()
    assert parser.feed(": heartbeat") == loadgen.Frame(None, None, "", heartbeat=True)
    for line in ("id: 1", "event: run.state_changed", 'data: {"a":', "data: 1}"):
        assert parser.feed(line) is None
    event = parser.feed("")
    assert event is not None and json.loads(event.data) == {"a": 1}
    assert loadgen.advance(0, event) == 1
    with pytest.raises(loadgen.Violation, match="duplicate"):
        loadgen.advance(1, event)
    with pytest.raises(loadgen.Violation, match="gap"):
        loadgen.advance(0, replace(event, sequence=2))
    payload = {"type": "run.state_changed", "current": "waiting_input", "previous": "queued"}
    from policyops_contracts.digest import canonical_bytes, sha256_hex
    from policyops_contracts.events import RunStateChanged

    digest = sha256_hex(canonical_bytes(RunStateChanged(previous="queued", current="waiting_input")))
    result = [{"sequence": 1, "event_id": "event", "payload_sha256": digest}]
    expected = [(1, "event", payload)]
    assert not loadcheck.check_stream(expected, result, {"sequence": 1})
    assert loadcheck.check_stream(expected, result * 2, {"sequence": 1}) == ["stream_db_continuity"]
    assert loadcheck.check_stream(expected, [dict(result[0], event_id="foreign")], {"sequence": 1})


def test_offline_report_from_fixed_jsonl(tmp_path: Path) -> None:
    spec = loadgen.Stage("tiny", 2, warmup=0, measured=2, drain=1)
    stage = asdict(spec)
    rows = [
        {"kind": "meta", "stage": stage, "environment": "lightsail", "seed": 10, "run": "trial",
         "generator_cadence_s": 1},
        {"kind": "generator", "phase": "measured", "cpu_percent": 20, "offset": 0.25},
        {"kind": "generator", "phase": "measured", "cpu_percent": 22, "offset": 1.25},
        {
            "kind": "slot",
            "endpoint": "messages",
            "phase": "measured",
            "intended": 0,
            "sent": 0.001,
            "done": 0.125,
            "status": 200,
        },
        {
            "kind": "slot",
            "endpoint": "messages",
            "phase": "measured",
            "intended": 0.5,
            "sent": 0.502,
            "done": 0.75,
            "status": 200,
        },
        {
            "kind": "slot",
            "endpoint": "case_list",
            "phase": "measured",
            "intended": 1,
            "sent": 1.001,
            "done": 1.1,
            "status": 429,
            "rule_id": "api.public_rate_limit",
            "error": "http_429",
        },
        {
            "kind": "slot",
            "endpoint": "case_list",
            "phase": "measured",
            "intended": 1.5,
            "sent": None,
            "done": 1.501,
            "dispatch_lag": 0.001,
            "status": None,
            "error": "overflow",
        },
        {"kind": "stage_end", "aborted": False},
    ]
    for slot, row in zip(loadgen.schedule(spec, 10), rows[3:-1], strict=True):
        row.update(endpoint=slot.route, index=slot.index)
    raw = tmp_path / "trial.jsonl"
    raw.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    result = load_report.summarize(load_report.read_rows(raw), {"ok": True})
    assert result["outcome"] == "failed" and result["generator_valid"]
    assert result["browse"]["offered_rate"] == 2
    assert result["browse"]["sent_rate"] == 1.5 and result["browse"]["completed_rate"] == 1.5
    assert result["browse"]["goodput"] == 1
    assert result["errors"] == {"- - overflow": 1, "429 api.public_rate_limit http_429": 1}
    assert result["browse"]["successful_latency_s"] == {"n": 2, "p50": 0.125, "p95": 0.25, "max": 0.25}
    assert "p99" not in load_report.stats(range(999))
    assert load_report.stats(range(1000))["p99"] == 989
    rows[1]["cpu_percent"] = 51
    assert load_report.summarize(rows)["outcome"] == "invalid"
    assert load_report.paired([(10.0, 7.0)] * 5)["claim"]
    assert not load_report.paired([(10.0, 7.0)] * 4 + [(10.0, 11.0)])["claim"]


def test_sustained_credit_series_rejects_dips_and_missing_intervals() -> None:
    start = datetime(2026, 11, 24, tzinfo=UTC)
    rows = [
        {"utc": (start + timedelta(minutes=index)).isoformat(), "BurstCapacityPercentage": 95} for index in range(31)
    ]
    assert load_report.credits_hold(rows, start, 1800)
    assert not load_report.credits_hold(rows[1:], start, 1800)
    assert not load_report.credits_hold(rows[:4] + rows[5:], start, 1800)
    rows[5]["BurstCapacityPercentage"] = 94
    assert not load_report.credits_hold(rows, start, 1800)


def test_checker_detects_every_mutation_violation_class() -> None:
    fixture = {
        "case_id": "case",
        "run_id": "run",
        "proposal_id": "proposal",
        "proposal_version": 1,
        "simulator_version": 3,
        "control": "approve",
    }
    write = {
        "run_id": "run",
        "control": "approve",
        "consent_status": 201,
        "decisions": [201],
        "receipt": TOKEN,
        "message_id": "message",
        "consent_id": "consent",
        "approval_id": "approval",
    }
    execution = loadcheck.Execution("proposal", 1, "succeeded", "committed", TOKEN, TOKEN, "committed")
    observed = loadcheck.Observed(
        ("message",), ("consent",), 1, ("approval",), ("approve",), 1, (execution,), 4, 0, 0, "succeeded", TOKEN
    )
    assert not loadcheck.check_case(fixture, write, observed)
    corruptions: dict[str, dict[str, Any]] = {
        "execution_count": {"executions": (execution, execution)},
        "execution_binding": {"executions": (replace(execution, version=2),)},
        "receipt_hash": {"executions": (replace(execution, remote_hash="dog"),)},
        "terminal_receipt": {"terminal_projection": None},
        "simulator_version": {"simulator_version": 5},
        "stuck_jobs": {"stuck_jobs": 1},
        "pending_outcomes": {"pending_outcomes": 1},
        "audit_accounting": {"decision_audit": 2},
        "message_accounting": {"messages": ("other",)},
        "decision_accounting": {"decision_ids": ("other",)},
    }
    for error, changes in corruptions.items():
        assert error in loadcheck.check_case(fixture, write, replace(observed, **changes))
    race_fixture = dict(fixture, control="race")
    assert "race" in loadcheck.check_case(race_fixture, dict(write, control="race", decisions=[200, 201]), observed)
    assert not loadcheck.check_case(race_fixture, dict(write, control="race", decisions=[409, 201]), observed)
    replay_fixture = dict(fixture, control="replay")
    replay = dict(
        write,
        control="replay",
        decisions=[201, 200],
        consent_replay_status=201,
        consent_replay_equal=True,
        decision_replay_equal=True,
    )
    assert not loadcheck.check_case(replay_fixture, replay, observed)
    assert "replay_bytes" in loadcheck.check_case(replay_fixture, dict(replay, consent_replay_equal=False), observed)
    for mode, rule in loadcheck.STALE.items():
        stale = dict(fixture, control=mode)
        refusal = {"control": mode, "run_id": "run", "decisions": [409], "stale_rule_id": rule}
        no_effect = loadcheck.Observed((), (), 0, (), (), 0, (), 3, 0, 0, "waiting_approval", None)
        assert not loadcheck.check_case(stale, refusal, no_effect)
        assert "stale_refusal" in loadcheck.check_case(stale, dict(refusal, stale_rule_id="other"), no_effect)
        assert "refusal_effect" in loadcheck.check_case(stale, refusal, replace(no_effect, simulator_version=4))


def test_validation_refuses_foreign_scope_and_digests() -> None:
    stage = loadgen.Stage("seed", w1=2)
    workspace, case, run, principal = ("workspace", "case", "run", "principal")
    proposal = {
        "workspace_id": workspace,
        "case_id": case,
        "run_id": run,
        "proposal_id": "proposal",
        "proposal_version": 1,
        "action_digest": TOKEN,
    }
    manifest = {
        "demo": workspace,
        "workspaces": {
            workspace: {
                "proposals": [proposal],
                "cases": [case],
                "runs": {run: case},
                "messages": {},
                "events": {},
            }
        },
        "principals": {"bob": principal},
    }
    request = loadgen.proposal_request(proposal)
    session = loadgen.Session("bob", workspace, Mock(spec=httpx.AsyncClient), principal, "csrf")
    work = loadgen.Workload(manifest, [session], loadgen.Log(StringIO(), stage, time.perf_counter()), asyncio.Event())
    work.check_ids(proposal, session, request)
    for field, code in (
        ("workspace_id", "workspace_mismatch"),
        ("case_id", "case_mismatch"),
        ("run_id", "run_mismatch"),
        ("action_digest", "proposal_mismatch"),
    ):
        with pytest.raises(loadgen.Violation, match=code):
            work.check_ids({**proposal, field: "foreign"}, session, request)


def test_seed_seals_a_real_proposal_and_allocates_write_controls(world: World) -> None:
    workspace = loadseed.workspaces(10)[0]
    run = loadseed.scoped_id(10, "wave:first:0")
    scope = RunScope(workspace_id=workspace, run_id=run, case_id=runtime.browser_case_id(run))
    customer = world.customer(user_id=runtime.demo()["customer_id"])
    connection = Mock()
    proposal = loadseed.seal(connection, scope, RetailFacts(customer), TOKEN, loadseed.HISTORY)
    assert proposal.scope == scope
    assert (
        proposal.proposal_id
        == loadseed.seal(connection, scope, RetailFacts(customer), TOKEN, loadseed.HISTORY).proposal_id
    )
    assert connection.execute.call_count == 2
    modes = loadseed.controls(240, 60, 10, "first", sanity=False)
    assert modes == loadseed.controls(240, 60, 10, "first", sanity=False)
    assert modes[:60] == ["approve"] * 60
    assert modes.count("race") == 24 and modes.count("replay") == 12
    assert all(modes.count(mode) == 1 for mode in (*loadcheck.STALE, "reject"))
    assert loadseed.controls(1, 0, 10, "single", sanity=True) == ["approve"]


def test_sampler_detects_restarts_oom_and_stopped_containers() -> None:
    baseline = {"api": {"id": "a", "status": "running", "oom": False, "restarts": 0}}
    assert load_sampler.safety(baseline, baseline) is None
    for key, value, failure in (
        ("restarts", 1, "restarted"),
        ("id", "b", "restarted"),
        ("oom", True, "oom"),
        ("status", "exited", "status"),
    ):
        assert load_sampler.safety({"api": dict(baseline["api"], **{key: value})}, baseline) == "api_" + failure
