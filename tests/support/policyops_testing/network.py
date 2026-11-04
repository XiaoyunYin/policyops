"""In-process network guard for default test runs.

`install()` replaces the Python-level socket entry points:
- `socket.socket.connect`, `connect_ex` and `sendto`;
- `socket.create_connection`;
- `socket.getaddrinfo`.

Non-loopback destinations and hostnames (which would need DNS) raise `NetworkBlocked`. Loopback is refused too,
except for exact `(ip, port)` endpoints a fixture registers with `allow()` and revokes when it exits. The internal
loopback pair `socket.socketpair()` builds on Windows (used by asyncio) is permitted while socketpair runs.

What this does **not** cover, and must not be claimed as offline proof:
- child processes;
- C extensions that open their own sockets (libpq inside psycopg, for example; the PostgreSQL fixture checks its
  connection targets itself);
- references to the original functions captured before installation;
- raw OS calls through ctypes.

Physical isolation (a network-disabled container or host) is a separate control.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
import contextlib
import ipaddress
import socket
import threading
from typing import Any


class NetworkBlocked(RuntimeError):
    """A test tried to reach a destination that is not an explicitly registered loopback endpoint.

    Deliberately not an OSError, so network libraries cannot treat it as a transient connection error and retry.
    """


_lock = threading.Lock()
_allowed: dict[tuple[str, int], int] = {}
_internal = threading.local()
_originals: dict[str, Any] = {}


def _normalize(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.split("%", 1)[0]))
    except ValueError:
        return None


def _check(address: Any, family: int) -> None:
    if getattr(_internal, "socketpair", False):
        return
    if family == getattr(socket, "AF_UNIX", object()):
        return
    if not isinstance(address, tuple) or len(address) < 2:
        raise NetworkBlocked(f"unsupported socket address {address!r}")
    host, port = address[0], address[1]
    ip = _normalize(str(host))
    if ip is None:
        raise NetworkBlocked(f"connection to hostname {host!r} needs DNS and is blocked in tests")
    if not ipaddress.ip_address(ip).is_loopback:
        raise NetworkBlocked(f"network access to {ip}:{port} is blocked in tests")
    with _lock:
        if (ip, int(port)) not in _allowed:
            raise NetworkBlocked(f"loopback endpoint {ip}:{port} is not registered by a fixture")


def _connect(self: socket.socket, address: Any) -> None:
    _check(address, self.family)
    _originals["connect"](self, address)


def _connect_ex(self: socket.socket, address: Any) -> int:
    _check(address, self.family)
    result: int = _originals["connect_ex"](self, address)
    return result


def _sendto(self: socket.socket, data: Any, *args: Any) -> int:
    address = args[-1]
    _check(address, self.family)
    result: int = _originals["sendto"](self, data, *args)
    return result


def _create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
    _check(address, socket.AF_INET)
    connection: socket.socket = _originals["create_connection"](address, *args, **kwargs)
    return connection


def _getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
    if (host is not None and not getattr(_internal, "socketpair", False)
            and _normalize(str(host.decode() if isinstance(host, bytes) else host)) is None):
        raise NetworkBlocked(f"DNS lookup of {host!r} is blocked in tests")
    return _originals["getaddrinfo"](host, port, *args, **kwargs)


def _socketpair(*args: Any, **kwargs: Any) -> tuple[socket.socket, socket.socket]:
    _internal.socketpair = True
    try:
        pair: tuple[socket.socket, socket.socket] = _originals["socketpair"](*args, **kwargs)
        return pair
    finally:
        _internal.socketpair = False


def installed() -> bool:
    return bool(_originals)


def install() -> None:
    if installed():
        return
    _originals.update(connect=socket.socket.connect, connect_ex=socket.socket.connect_ex,
                      sendto=socket.socket.sendto, create_connection=socket.create_connection,
                      getaddrinfo=socket.getaddrinfo, socketpair=socket.socketpair)
    socket.socket.connect = _connect  # type: ignore[assignment,method-assign]
    socket.socket.connect_ex = _connect_ex  # type: ignore[assignment,method-assign]
    socket.socket.sendto = _sendto  # type: ignore[assignment,method-assign]
    socket.create_connection = _create_connection
    socket.getaddrinfo = _getaddrinfo
    socket.socketpair = _socketpair


def uninstall() -> None:
    if not installed():
        return
    socket.socket.connect = _originals["connect"]  # type: ignore[method-assign]
    socket.socket.connect_ex = _originals["connect_ex"]  # type: ignore[method-assign]
    socket.socket.sendto = _originals["sendto"]  # type: ignore[method-assign]
    socket.create_connection = _originals["create_connection"]
    socket.getaddrinfo = _originals["getaddrinfo"]
    socket.socketpair = _originals["socketpair"]
    _originals.clear()
    with _lock:
        _allowed.clear()


def registered() -> frozenset[tuple[str, int]]:
    with _lock:
        return frozenset(_allowed)


@contextlib.contextmanager
def allow(host: str, port: int) -> Iterator[tuple[str, int]]:
    """Register one loopback endpoint for the duration of the block (re-entrant; revoked on exit)."""
    ip = _normalize(host)
    if ip is None or not ipaddress.ip_address(ip).is_loopback:
        raise ValueError("only loopback IP endpoints can be allowed")
    key = (ip, int(port))
    with _lock:
        _allowed[key] = _allowed.get(key, 0) + 1
    try:
        yield key
    finally:
        with _lock:
            remaining = _allowed[key] - 1
            if remaining:
                _allowed[key] = remaining
            else:
                del _allowed[key]


def require_registered(host: str, port: int) -> None:
    """For clients that bypass Python sockets (libpq): refuse targets that are not registered endpoints."""
    _check((host, port), socket.AF_INET6 if ":" in host else socket.AF_INET)


Probe = Callable[[], object]
