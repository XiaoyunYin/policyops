"""The default-suite network guard blocks real destinations and permits only registered loopback endpoints."""

import asyncio
from collections.abc import Callable, Iterator
import contextlib
import socket
import urllib.request

import httpx
import pytest

from policyops_testing import network
from policyops_testing.network import NetworkBlocked


@contextlib.contextmanager
def listener(family: int = socket.AF_INET, host: str = "127.0.0.1") -> Iterator[int]:
    server = socket.socket(family, socket.SOCK_STREAM)
    try:
        server.bind((host, 0))
        server.listen(1)
        yield server.getsockname()[1]
    finally:
        server.close()


def test_guard_is_installed_for_the_whole_session() -> None:
    assert network.installed()
    assert socket.socket.connect is network._connect
    assert socket.getaddrinfo is network._getaddrinfo


def _socket_call(family: int, kind: int, call: Callable[[socket.socket], object]) -> Callable[[], object]:
    def attempt() -> object:
        with socket.socket(family, kind) as sock:
            return call(sock)
    return attempt


@pytest.mark.parametrize("attempt", [
    lambda: urllib.request.urlopen("http://203.0.113.10/", timeout=2),
    lambda: httpx.get("http://example.com/", timeout=2),
    lambda: httpx.get("http://198.51.100.7:8080/", timeout=2),
    lambda: socket.getaddrinfo("example.com", 443),
    lambda: socket.create_connection(("example.org", 80), timeout=2),
    lambda: socket.create_connection(("192.0.2.1", 443), timeout=2),
    _socket_call(socket.AF_INET, socket.SOCK_STREAM, lambda s: s.connect_ex(("198.51.100.1", 443))),
    _socket_call(socket.AF_INET, socket.SOCK_DGRAM, lambda s: s.sendto(b"x", ("192.0.2.53", 53))),
    _socket_call(socket.AF_INET6, socket.SOCK_STREAM, lambda s: s.connect_ex(("2001:db8::1", 443, 0, 0))),
])
def test_external_destinations_and_dns_are_blocked(attempt: Callable[[], object]) -> None:
    with pytest.raises(NetworkBlocked):
        attempt()


def test_unregistered_loopback_is_blocked_and_registration_is_exact_and_revoked() -> None:
    with listener() as port:
        with socket.socket() as client, pytest.raises(NetworkBlocked):
            client.connect(("127.0.0.1", port))
        with network.allow("127.0.0.1", port):
            assert ("127.0.0.1", port) in network.registered()
            with socket.socket() as other, pytest.raises(NetworkBlocked):
                other.connect_ex(("127.0.0.1", port + 1 if port < 65535 else port - 1))
            with socket.socket() as client:
                client.connect(("127.0.0.1", port))
        assert ("127.0.0.1", port) not in network.registered()
        with socket.socket() as late, pytest.raises(NetworkBlocked):
            late.connect(("127.0.0.1", port))


def test_ipv6_loopback_needs_registration_too() -> None:
    try:
        context = listener(socket.AF_INET6, "::1")
        port = context.__enter__()
    except OSError:
        pytest.skip("IPv6 loopback is not available on this host")
    try:
        with socket.socket(socket.AF_INET6) as blocked, pytest.raises(NetworkBlocked):
            blocked.connect(("::1", port, 0, 0))
        with network.allow("::1", port), socket.socket(socket.AF_INET6) as probe:
            probe.connect(("::1", port, 0, 0))
    finally:
        context.__exit__(None, None, None)


def test_only_loopback_ip_endpoints_can_be_allowed() -> None:
    for host in ("203.0.113.10", "localhost", "example.com"):
        with pytest.raises(ValueError), network.allow(host, 80):
            pass


def test_internal_socketpair_and_asyncio_still_work() -> None:
    left, right = socket.socketpair()
    left.sendall(b"ok")
    assert right.recv(2) == b"ok"
    left.close()
    right.close()
    assert asyncio.run(asyncio.sleep(0, result="done")) == "done"


def test_libpq_style_targets_are_checked_explicitly() -> None:
    with pytest.raises(NetworkBlocked):
        network.require_registered("127.0.0.1", 5432)
    with network.allow("127.0.0.1", 5432):
        network.require_registered("127.0.0.1", 5432)
    with pytest.raises(NetworkBlocked):
        network.require_registered("203.0.113.10", 5432)


def test_fixture_registration_a(allow_endpoint: Callable[[str, int], tuple[str, int]]) -> None:
    allow_endpoint("127.0.0.1", 47001)
    assert ("127.0.0.1", 47001) in network.registered()


def test_fixture_registration_b_was_revoked_at_teardown() -> None:
    # Runs after test_fixture_registration_a (file order): the fixture's endpoint must be gone.
    assert ("127.0.0.1", 47001) not in network.registered()
