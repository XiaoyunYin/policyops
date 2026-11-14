"""Report denominators/derivation and paid smoke admission, without Docker or provider access."""

import asyncio
from collections.abc import AsyncIterator
from decimal import Decimal
import json
from pathlib import Path
import sys
from typing import Any

import httpx2
from mcp import types
from pydantic import SecretStr
import pytest

from policyops.mcp.contracts import TOOLS, Result, arguments, input_schema
from policyops.providers.adapters import invoke
from policyops.providers.calls import CallReport
from policyops.providers.schema import check_schema, validation_errors
from policyops.providers.serialize import prepare
from policyops_contracts.model import Message, ModelRequest, TextPart, ToolSpec


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import mcp_luna_smoke as smoke
from scripts import mcp_parity_report as parity


def test_frozen_read_projection_denominators() -> None:
    assert len(parity.expected_ids(("matrix",))) == 44
    assert len(parity.expected_ids(("e05",))) == 120
    assert len(parity.expected_ids(("identity",))) == 3
    assert len(parity.expected_ids()) == 167


def test_metric_derivation_retains_failures_and_negative_overhead() -> None:
    rows = [{"decision_parity": True, "code_parity": True, "payload_parity": True, "framing_valid": True,
             "direct_allowed": True, "mcp_allowed": True, "oracle_allowed": True,
             "untrusted_text_preserved": True, "overhead_ms": -2},
            {"decision_parity": False, "code_parity": False, "payload_parity": False, "framing_valid": True,
             "direct_allowed": False, "mcp_allowed": True, "oracle_allowed": False,
             "untrusted_text_preserved": False, "overhead_ms": 10},
            {"decision_parity": False, "code_parity": False, "payload_parity": False, "framing_valid": True,
             "direct_allowed": True, "mcp_allowed": False, "oracle_allowed": True,
             "untrusted_text_preserved": True, "overhead_ms": 20}]
    stats = parity.summary(rows)
    assert stats["calls"] == 3 and stats["parity"] == 1
    assert stats["unauthorized_disclosures"] == stats["false_denials_vs_direct"] == 1
    assert stats["text_preservation_failures"] == 1
    assert stats["overhead_ms"] == {"p50": 10, "p95": 20, "max": 20}


def test_latency_separates_cold_warm_and_facade_including_failures() -> None:
    rows = [{"worker_phase": phase, "direct_ms": 10, "mcp_ms": remote, "overhead_ms": remote - 10}
            for phase, remote in (("cold", 200), ("warm", 12), ("warm", 8), ("facade", 1))]
    for row in rows:
        row.update(decision_parity=False, code_parity=False, payload_parity=False, framing_valid=True,
                   mcp_allowed=False, direct_allowed=True, oracle_allowed=True, untrusted_text_preserved=True)
    stats = parity.summary(rows)["latency_by_worker_phase"]
    assert stats["cold"]["calls"] == 1 and stats["cold"]["overhead_ms"]["max"] == 190
    assert stats["warm"]["calls"] == 2
    assert stats["warm"]["direct_ms"] == {"p50": 10, "p95": 10, "max": 10}
    assert stats["warm"]["mcp_ms"] == {"p50": 8, "p95": 12, "max": 12}
    assert stats["warm"]["overhead_ms"] == {"p50": -2, "p95": 2, "max": 2}
    assert stats["facade"]["calls"] == 1


def test_e05_setup_finishes_sync_job_work_before_event_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env: Any = object()
    calls = []
    async def job() -> None:
        calls.append("job")
    def publish(prepared: object, root: Path) -> None:
        assert prepared is env and root == tmp_path / "policy"
        # Same event-loop restriction as ingest's run_job_sync, without a DB or provider dependency.
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        asyncio.run(job())
    async def replay(base: object, suites: tuple[str, ...], **kwargs: Any) -> list[parity.Row]:
        assert asyncio.get_running_loop().is_running()
        assert calls == ["job"] and kwargs["e05_env"] is env
        return []
    monkeypatch.setattr(parity, "study_case", lambda base: env)
    monkeypatch.setattr(parity, "publish", publish)
    monkeypatch.setattr(parity, "replay", replay)
    assert parity.run_replay(env, tmp_path, ("e05",)) == []


def test_async_replay_requires_prepared_e05_corpus() -> None:
    env: Any = object()
    with pytest.raises(ValueError, match="publication must precede"):
        asyncio.run(parity.replay(env, ("e05",)))


@pytest.mark.parametrize("usd,calls,counts,seconds", [
    ("0.051", 4, 4, 120), ("0", 4, 4, 120), ("NaN", 4, 4, 120), ("0.05", 5, 4, 120),
    ("0.05", 4, 5, 120), ("0.05", 4, 4, 181), ("0.000001", 4, 4, 120),
])
def test_paid_smoke_rejects_missing_or_unsafe_caps(usd: str, calls: int, counts: int, seconds: int) -> None:
    with pytest.raises(ValueError):
        smoke.planning(Decimal(usd), calls, counts, seconds)


def test_smoke_without_optin_writes_only_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("execution started without opt-in")
    monkeypatch.setattr(smoke, "owned_postgres", forbidden)
    target = tmp_path / "plan.json"
    assert smoke.main(["--max-usd", "0.05", "--max-calls", "4", "--max-counts", "4",
                       "--max-seconds", "120", "--output", str(target)]) == 0
    report = json.loads(target.read_text(encoding="utf-8"))
    assert not report["paid_opt_in"] and not report["tasks"]
    assert report["planning"]["model"] == "gpt-6-luna"
    assert report["planning"]["authorizes_paid_execution"] is False


def test_report_refuses_repo_and_reviewer_outputs(tmp_path: Path) -> None:
    for path in (parity.REPO / "bad.json", tmp_path / "reviewer" / "bad.json"):
        with pytest.raises(ValueError):
            parity.output_path(str(path))
def smoke_tools() -> tuple[ToolSpec, ...]:
    # Include the SDK's list-tools serialization round trip, as on stdio.
    return tuple(smoke.tool_spec(types.Tool.model_validate_json(types.Tool(
        name=name, input_schema=input_schema(name)).model_dump_json())) for name in TOOLS)


@pytest.mark.parametrize("name,values", [
    ("find_user_id_by_email", {"email": "fictional@example.com"}),
    ("find_user_id_by_name_zip", {"first_name": "James", "last_name": "Johnson", "zip": "12345"}),
    ("get_user_details", {"user_id": "james_johnson_9321"}),
    ("get_order_details", {"order_id": "#W1006327"}),
    ("get_product_details", {"product_id": "1000000000"}),
    ("get_item_details", {"item_id": "1000000000"}),
    ("list_all_product_types", {}),
    ("search_policy", {"query": "fixture000"}),
])
def test_every_mcp_schema_round_trip_matches_adapter_and_server(name: str, values: dict[str, Any]) -> None:
    config, _, _ = smoke.planning(Decimal("0.05"), 4, 4, 120)
    tools = smoke_tools()
    prepared = prepare(ModelRequest(instructions=smoke.PROMPT, tools=tools, max_output_tokens=512,
        messages=(Message(role="user", parts=(TextPart(text="Read the fixture."),)),)), config, "agent")
    spec = next(t for t in tools if t.name == name)
    assert json.loads(spec.parameters_schema_json) == input_schema(name)
    checked = prepared.tools[name]
    assert not validation_errors(checked, values)
    assert not isinstance(arguments(name, values), Result)
    invalids = [{**values, "tenant": "foreign"}, {**values, "tool": name}]
    if values:
        invalids.append({})
    for invalid in invalids:
        assert validation_errors(checked, invalid)
        assert isinstance(arguments(name, invalid), Result)
    wire = next(t["parameters"] for t in prepared.params()["tools"] if t["name"] == name)
    assert wire == json.loads(checked.wire)
    assert wire["additionalProperties"] is False
    assert sorted(wire.get("required", [])) == sorted(wire.get("properties", {}))


def test_order_format_is_local_constraint_and_explicit_in_smoke_prompt() -> None:
    checked = check_schema(next(t.parameters_schema_json for t in smoke_tools() if t.name == "get_order_details"))
    assert "pattern" in checked.projected_away
    assert "pattern" not in json.loads(checked.wire)["properties"]["order_id"]
    for value in ("W1006327", "1006327", "#W1006327."):
        assert validation_errors(checked, {"order_id": value}) == ("pattern@/order_id",)
        assert isinstance(arguments("get_order_details", {"order_id": value}), Result)
    assert "#W followed by exactly seven digits" in smoke.PROMPT
    assert "Copy the entire supplied ID" in smoke.PROMPT


class SmokeChunks(httpx2.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body, self.closed = body, False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for start in range(0, len(self.body), 123):
            yield self.body[start:start + 123]

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize("name,args,reason,errors", [
    ("get_order_details", '{"order_id":"W1006327"}', "tool_arguments_schema", ["pattern@/order_id"]),
    ("get_order_details", '{}', "tool_arguments_schema", ["required@/"]),
    ("get_order_details", '{"order_id":"#W1006327","tenant":"foreign"}', "tool_arguments_schema",
     ["additionalProperties@/"]),
    ("get_order_details", '{broken', "tool_arguments_not_json", ["tool_arguments_not_json@/"]),
    ("unknown", '{}', "unknown_tool", ["unknown_tool@/"]),
    ("search_policy", json.dumps({"query": "x" * 2049}), "tool_arguments_schema", ["maxLength@/query"]),
])
def test_scripted_adapter_refusal_retains_arguments_paths_and_usage(
        name: str, args: str, reason: str, errors: list[str]) -> None:
    config, _, _ = smoke.planning(Decimal("0.05"), 4, 4, 120)
    tools = smoke_tools()
    diagnostics = smoke.ToolDiagnostics(tools)
    prepared = prepare(ModelRequest(instructions=smoke.PROMPT, tools=tools, max_output_tokens=512,
        messages=(Message(role="user", parts=(TextPart(text="Read the fixture."),)),)), config, "agent")
    body = {"id": "resp_fixture", "model": "gpt-6-luna", "status": "completed", "service_tier": "default",
        "output": [{"type": "function_call", "call_id": "call_fixture", "name": name, "arguments": args}],
        "usage": {"input_tokens": 409, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                  "output_tokens": 23, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 432}}
    stream = SmokeChunks(json.dumps(body).encode())
    def response(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "application/json"}, stream=stream)
    invocation = asyncio.run(invoke(prepared, smoke.DiagnosticTransport(httpx2.MockTransport(response), diagnostics),
                                   SecretStr("synthetic-test-credential-0000"), cache_mode="none"))
    model = invocation.result
    assert model is not None and model.reason_code == reason and not model.tool_calls
    assert invocation.evidence is not None and invocation.evidence.usage is not None
    assert invocation.cleanup_confirmed and stream.closed
    report = smoke.call_report(CallReport(model, "result", reason), diagnostics)
    assert report["reason"] == reason and report["outcome"] == "invalid_output"
    assert report["usage"]["input_total"] == 409 and report["usage"]["output"] == 23
    assert report["tool_diagnostics"] == {"state": "captured", "calls": [{"name": name,
        "arguments": args[:512], "arguments_truncated": len(args) > 512, "validation_errors": errors}]}
    diagnostics.reset()
    assert not diagnostics.calls and report["tool_diagnostics"]["calls"]
    assert "synthetic-test-credential" not in json.dumps(report)


@pytest.mark.parametrize("body,state", [
    (b"x" * (smoke.DIAGNOSTIC_RESPONSE_BYTES + 1), "response_exceeds_diagnostic_bound"),
    (b'{broken', "response_not_json"),
    (b'{}', "response_output_missing"),
])
def test_diagnostic_bounds_preserve_delivery_and_close(body: bytes, state: str) -> None:
    diagnostics = smoke.ToolDiagnostics(smoke_tools())
    source = SmokeChunks(body)
    async def read() -> bytes:
        stream = smoke.DiagnosticStream(source, diagnostics)
        try:
            return b"".join([chunk async for chunk in stream])
        finally:
            await stream.aclose()
    assert asyncio.run(read()) == body
    assert source.closed and diagnostics.state == state and not diagnostics.calls


def test_nested_exception_group_report_contains_leaf_types_only() -> None:
    report: dict[str, Any] = {}
    smoke.record_failure(report, ExceptionGroup("secret outer", [ValueError("secret input"),
        ExceptionGroup("secret inner", [RuntimeError("secret credential"), TimeoutError("secret URL")])]))
    assert report == {"failure": "ExceptionGroup", "failure_leaf_types": ["ValueError", "RuntimeError", "TimeoutError"],
                      "failure_leaf_types_truncated": False}


def test_diagnostic_tool_count_name_and_argument_bounds() -> None:
    diagnostics = smoke.ToolDiagnostics(smoke_tools())
    args = json.dumps({"query": "x" * 10000})
    diagnostics.capture(bytearray(json.dumps({"output": [{"type": "function_call", "name": "x" * 1000,
        "arguments": args}] * 5}).encode()))
    assert diagnostics.state == "tool_calls_truncated" and len(diagnostics.calls) == 4
    assert all(c == {"name": "x" * 64, "arguments": args[:512], "arguments_truncated": True,
                     "validation_errors": ["validation_skipped_argument_bound@/"]} for c in diagnostics.calls)


def test_diagnostic_failure_cannot_replace_response_or_skip_close(monkeypatch: pytest.MonkeyPatch) -> None:
    diagnostics = smoke.ToolDiagnostics(smoke_tools())
    def fail(body: bytearray) -> None:
        raise ValueError("synthetic diagnostic failure")
    monkeypatch.setattr(diagnostics, "capture", fail)
    source = SmokeChunks(b'{"output":[]}')
    async def read() -> bytes:
        stream = smoke.DiagnosticStream(source, diagnostics)
        try:
            return b"".join([chunk async for chunk in stream])
        finally:
            await stream.aclose()
    assert asyncio.run(read()) == source.body
    assert source.closed and diagnostics.state == "diagnostic_failed"


def test_smoke_main_persists_exception_group_leaf_types(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise ExceptionGroup("secret setup", [RuntimeError("secret message")])
    monkeypatch.setattr(smoke, "owned_postgres", fail)
    monkeypatch.setattr(smoke, "cleanup_runtime", lambda *args: [])
    target = tmp_path / "failed.json"
    assert smoke.main(["--execute-paid", "--max-usd", "0.05", "--max-calls", "4", "--max-counts", "4",
                       "--max-seconds", "120", "--output", str(target)]) == 1
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["failure_leaf_types"] == ["RuntimeError"] and not report["passed"]
    assert not report["failure_leaf_types_truncated"] and "secret" not in target.read_text(encoding="utf-8")


