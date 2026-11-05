"""The loopback test server helper always releases what it acquired (T09 review finding F2)."""

from __future__ import annotations

import socket
import time
from typing import Any

import httpx
import pytest

from policyops_testing import live_server, network


class Recording:
    def __init__(self) -> None:
        self.sockets: list[socket.socket] = []

    def __call__(self) -> socket.socket:
        created = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockets.append(created)
        return created

    def closed(self) -> bool:
        if not self.sockets:
            return False
        return all(item.fileno() == -1 for item in self.sockets)


async def hello(scope: Any, receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok"})


def test_normal_use_serves_and_then_closes_everything() -> None:
    recording = Recording()
    with live_server.serve(hello, listener_factory=recording) as url:
        assert httpx.get(url, timeout=10).text == "ok"
        assert not recording.closed()
    assert recording.closed() and network.registered() == frozenset()


class ExitsBeforeReady:
    started = False
    should_exit = False

    def __init__(self, app: Any) -> None:
        del app

    def run(self, sockets: Any = None) -> None:
        return  # the thread ends without ever becoming ready


class FailsToConstruct:
    def __init__(self, app: Any) -> None:
        raise RuntimeError("construction failed (injected)")


class NeverReady(ExitsBeforeReady):
    def run(self, sockets: Any = None) -> None:
        while not self.should_exit:
            time.sleep(0.01)


def test_a_server_thread_that_exits_before_ready_still_closes_the_listener() -> None:
    recording = Recording()
    with pytest.raises(live_server.ServerError, match="exited"), live_server.serve(
            hello, listener_factory=recording, server_factory=ExitsBeforeReady):
        pytest.fail("must not be reached")
    assert recording.closed()


def test_a_server_that_is_never_ready_times_out_stops_and_closes() -> None:
    recording = Recording()
    with pytest.raises(live_server.ServerError, match="in time"), live_server.serve(
            hello, listener_factory=recording, server_factory=NeverReady, startup_timeout=0.2):
        pytest.fail("must not be reached")
    assert recording.closed()


def test_early_setup_failures_close_the_listener() -> None:
    recording = Recording()
    with pytest.raises(RuntimeError, match="construction"), live_server.serve(
            hello, listener_factory=recording, server_factory=FailsToConstruct):
        pytest.fail("must not be reached")
    assert recording.closed()

    class FailsToBind(socket.socket):
        def bind(self, address: Any) -> None:
            raise OSError("bind failed (injected)")

    created: list[socket.socket] = []

    def failing() -> socket.socket:
        created.append(FailsToBind(socket.AF_INET, socket.SOCK_STREAM))
        return created[-1]

    with pytest.raises(OSError, match="bind"), live_server.serve(hello, listener_factory=failing):
        pytest.fail("must not be reached")
    assert created and created[0].fileno() == -1
