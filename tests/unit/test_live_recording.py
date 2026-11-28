"""Offline transport and output-boundary regressions."""

import asyncio
from collections.abc import AsyncIterator
import json
from pathlib import Path
from uuid import uuid4

import httpx2
import pytest

from policyops.runtime.live_recording import Recorder, Redactor, Tape, measurements, tape_root


class Pieces(httpx2.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b'{"input_tokens":10,'
        yield b'"headers":{"x-api-key":"body-header"},"authorization":"body-auth"}'


@pytest.mark.parametrize("failed", [False, True])
def test_tape_keeps_timing_and_diagnostics_without_secrets(tmp_path: Path, failed: bool) -> None:
    run, claim = uuid4(), uuid4()
    secret = "opaque-unit-fixture-value"
    tape = Tape(tmp_path / str(run) / str(claim), Redactor(secret))
    tape.tool("read", 13)
    encoded = json.dumps({"input": "a diagnostic detail", "arguments": json.dumps(
        {"api_key": "nested-body-credential", "detail": secret})})

    def provider(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["authorization"] == "header-only-fixture"
        assert request.content.decode() == encoded
        if failed:
            raise httpx2.ConnectError("synthetic disconnect")
        return httpx2.Response(200, stream=Pieces(), headers={"x-private": "response-header"})

    async def request() -> None:
        async with httpx2.AsyncClient(transport=Recorder(httpx2.MockTransport(provider), tape)) as client:
            response = await client.post("https://api.openai.com/v1/responses/input_tokens",
                                         content=encoded, headers={"authorization": "header-only-fixture"})
            assert response.json()["authorization"] == "body-auth"

    if failed:
        with pytest.raises(httpx2.ConnectError):
            asyncio.run(request())
    else:
        asyncio.run(request())
    exchanges, tools = measurements(tmp_path, run)
    (exchange,) = exchanges
    assert exchange.phase == "count" and exchange.elapsed_ms is not None
    assert (exchange.complete, exchange.status) == ((False, None) if failed else (True, 200))
    assert exchange.request is not None and "a diagnostic detail" in exchange.request
    assert tools[0].elapsed_ms == 13
    raw = (tape.directory / "00.json").read_text(encoding="utf-8")
    for value in (secret, "nested-body-credential", "header-only-fixture", "body-header", "body-auth",
                  "response-header"):
        assert value not in raw


def test_recording_requires_existing_external_root(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    internal = checkout / "internal"
    internal.mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    assert tape_root(external, checkout) == external.resolve()
    for invalid in (Path("relative"), checkout, internal):
        with pytest.raises(ValueError, match="external"):
            tape_root(invalid, checkout)
