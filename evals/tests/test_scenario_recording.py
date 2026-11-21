"""Offline transport, first-decision, replay and operator admission checks."""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
from uuid import uuid4

import httpx2
from pydantic import SecretStr
import pytest

from policyops.providers.adapters import count, invoke
from policyops.providers.serialize import prepare
from policyops_contracts.model import Message, ModelRequest, TextPart
from policyops_evals.cli import main
from policyops_evals.scenarios.recording import (
    MAX_BODY_BYTES,
    Exchange,
    Recorder,
    Redactor,
    Replay,
    ReplayMismatch,
    Tape,
    digest,
    first_consequential_call,
)
from policyops_evals.scenarios.runtime import Slot, configuration, preflight
from policyops_testing.retrieval_fixtures import count_reply, luna_reply


def exchange(index: int, output: list[object]) -> Exchange:
    raw = json.dumps({"status": "completed", "output": output})
    return Exchange(index=index, attempt=index, phase="create", request="{}", request_sha256=digest("{}"),
                    response=raw, response_sha256=digest(raw), complete=True, status=200)


def test_first_consequential_call_cannot_be_replaced_by_later_success() -> None:
    read = {"type": "function_call", "name": "get_order_details"}
    malformed = {"type": "function_call", "name": "cancel_pending_order", "arguments": "{"}
    correct = dict(malformed, arguments='{"order_id":"#W1006327","reason":"no longer needed"}', call_id="call_3")
    first = first_consequential_call([exchange(0, [read]), exchange(1, [read, malformed]), exchange(2, [correct])])
    assert first is not None
    assert (first.name, first.arguments, first.call_id, first.exchange_index, first.only_call) == (
        "cancel_pending_order", "{", None, 1, False)
    transfer = first_consequential_call([exchange(0, [{"name": "transfer_to_human_agents", "arguments": 123}])])
    assert transfer is not None and transfer.name == "transfer_to_human_agents"
    assert first_consequential_call([exchange(0, [read])]) is None


class Pieces(httpx2.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.content = content

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.content[:16]
        yield self.content[16:]


@pytest.mark.parametrize("streamed", [False, True])
def test_record_redact_reopen_and_digest_replay(tmp_path: Path, streamed: bool) -> None:
    slot = Slot(uuid4(), uuid4())
    secret = "fake-secret-should-never-appear"
    redactor = slot.redactor((secret,))
    tape = Tape(tmp_path)
    endpoint = "https://api.openai.com/v1/responses/input_tokens"
    body = json.dumps({"text": f"[seeded; {slot.message}] request for {slot.run}",
                       "extra": f"Bearer {secret}",
                       "dsn": "postgresql://" "login:password@example.invalid/db"}).encode()
    response = (b'{"input_tokens":160,"authorization":"fake-secret-should-never-appear",'
                b'"headers":{"nested":{"extra":"nested-header-do-not-save"}}}')

    def reply(_: httpx2.Request) -> httpx2.Response:
        headers = {"X-Secret": "header-do-not-save"}
        if streamed:
            return httpx2.Response(200, stream=Pieces(response), headers=headers)
        return httpx2.Response(200, content=response, headers=headers)

    async def run() -> None:
        async with httpx2.AsyncClient(transport=Recorder(httpx2.MockTransport(reply), tape, redactor)) as client:
            actual = await client.post(endpoint, content=body, headers={"X-Secret": "request-header-do-not-save"})
            assert actual.content == response

    asyncio.run(run())
    reopened = Tape(tmp_path)
    assert reopened.records == tape.records
    record = reopened.records[0]
    assert record.complete and record.status == 200 and record.attempt == 0 and record.phase == "count"
    assert record.request_sha256 == digest(record.request) and record.response_sha256 == digest(record.response)
    assert record.request and "[message]" in record.request and "[run]" in record.request
    saved = (tmp_path / "00.json").read_text(encoding="utf-8")
    for value in (secret, "header-do-not-save", "nested-header-do-not-save", "postgresql:",
                  str(slot.message), str(slot.run)):
        assert value not in saved

    other = Slot(uuid4(), uuid4())
    same = body.replace(str(slot.message).encode(), str(other.message).encode()).replace(
        str(slot.run).encode(), str(other.run).encode())
    replay = Replay(tuple(reopened.records), other.redactor((secret,)), other.run)
    assert replay(httpx2.Request("POST", endpoint, content=same)).json()["input_tokens"] == 160
    replay.verify()
    changed = Replay(tuple(reopened.records), other.redactor((secret,)), other.run)
    with pytest.raises(ReplayMismatch, match="digest mismatch"):
        changed(httpx2.Request("POST", endpoint, content=same.replace(b"request", b"another request")))
    with pytest.raises(ReplayMismatch, match="digest mismatch"):
        changed.verify()


def test_sdk_replay_can_settle_every_response_in_the_original_workspace() -> None:
    original = Slot(uuid4(), uuid4())
    target = Slot(original.workspace, uuid4())
    tape = Tape()
    credential = SecretStr("synthetic-test-credential-0000")
    provider_ids: set[str] = set()  # Same workspace/provider uniqueness constraint as app.usage_attempts.

    def script(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("input_tokens"):
            response = count_reply(900)(request)
        else:
            response = luna_reply("A scripted reply.", id=f"resp_test_{len(provider_ids)}")(request)
        assert isinstance(response, httpx2.Response)
        return response

    async def settle(slot: Slot, transport: Recorder) -> list[str]:
        settled = []
        for step in range(2):
            request = ModelRequest(instructions="Respond briefly.", max_output_tokens=128, messages=(
                Message(role="user", parts=(TextPart(text=f"[seeded; {slot.message}] Request {step}"),)),))
            prepared = prepare(request, configuration(), "agent")
            assert (await count(prepared, transport, credential)).tokens == 900
            reply = await invoke(prepared, transport, credential, cache_mode="none")
            assert reply.result is not None and reply.result.text == "A scripted reply."
            assert reply.evidence is not None and reply.evidence.usage is not None
            provider_id = reply.evidence.provider_request_id
            assert provider_id is not None
            if provider_id in provider_ids:
                break  # A settlement collision stops the graph before its next token count.
            provider_ids.add(provider_id)
            settled.append(provider_id)
        return settled

    redactor = original.redactor()
    assert asyncio.run(settle(original, Recorder(httpx2.MockTransport(script), tape, redactor))) == [
        "resp_test_0", "resp_test_1"]
    redactor = target.redactor()
    replay = Replay(tuple(tape.records), redactor, target.run)
    replay_tape = Tape()
    settled = asyncio.run(settle(target, Recorder(httpx2.MockTransport(replay), replay_tape, redactor)))
    replay.verify()
    assert len(settled) == 2 and len(provider_ids) == 4
    assert [(item.phase, item.attempt) for item in replay_tape.records] == [
        ("count", 0), ("create", 0), ("count", 1), ("create", 1)]
    for item, replayed in zip(tape.records, replay_tape.records, strict=True):
        assert replayed.request_sha256 == item.request_sha256
        assert item.response is not None
        expected = item.response if item.phase == "count" else item.response.replace(
            f'"resp_test_{item.attempt}"', f'"{settled[item.attempt]}"', 1)
        assert replayed.response == expected


def test_recorder_bound_and_unparseable_body() -> None:
    assert Redactor().body(b'{"oversized":"' + b"x" * MAX_BODY_BYTES + b'"}') is None
    assert Redactor().body(b"opaque failure body") is None


def test_preflight_rejects_above_hard_limit() -> None:
    config = configuration()
    assert preflight(config, 2) == Decimal("0.02419200")
    with pytest.raises(ValueError, match="aggregate smoke cap"):
        preflight(config, 3)
    with pytest.raises(ValueError, match="aggregate smoke cap"):
        preflight(replace(config, caps=replace(config.caps, run_usd=Decimal("0.02"))), 2)


@pytest.mark.parametrize("paid", [False, True])
def test_cli_cannot_select_paid_transport_under_pytest(paid: bool, capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["scenarios", "smoke", "--dsn-file", "missing", "--workspace", str(uuid4()),
            "--fixture-root", "missing", "--policy-file", "missing", "--trace-dir", "missing"]
    assert main(argv + (["--allow-paid"] if paid else [])) == 1
    output = capsys.readouterr()
    assert not output.out and "requires operator execution" in output.err
