"""Serve an ASGI app on a real loopback socket with uvicorn, for tests that need true incremental HTTP (T09 SSE).

The socket is bound to 127.0.0.1 on an OS-chosen port, and only that endpoint is registered with the test network
guard while the server runs; the server runs in a thread and the block yields its base URL. Everything from
acquiring the socket onwards is inside the cleanup: whether binding, constructing or starting the server, or
waiting for it to be ready fails, the listener is always closed. Stopping is bounded; a server thread that does not
stop is reported (unless another error is already propagating, which is never masked).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import socket
import threading
import time
from typing import Any

import uvicorn

from policyops_testing import network


class ServerError(RuntimeError):
    """The test server did not become ready, or did not stop."""


def _listener() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def _server(app: Any) -> Any:
    return uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False, lifespan="off"))


@contextmanager
def serve(app: Any, *, listener_factory: Callable[[], socket.socket] = _listener,
          server_factory: Callable[[Any], Any] = _server, startup_timeout: float = 15.0,
          stop_timeout: float = 15.0) -> Iterator[str]:
    listener = listener_factory()
    server: Any = None
    thread: threading.Thread | None = None
    completed = False
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = server_factory(app)
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + startup_timeout
        while not server.started:
            if not thread.is_alive():
                raise ServerError("the test server thread exited before it was ready")
            if time.monotonic() > deadline:
                raise ServerError("the test server was not ready in time")
            time.sleep(0.02)
        with network.allow("127.0.0.1", port):
            yield f"http://127.0.0.1:{port}"
        completed = True
    finally:
        stuck = False
        try:
            if server is not None:
                server.should_exit = True
            if thread is not None and thread.ident is not None:
                thread.join(stop_timeout)
                stuck = thread.is_alive()
        finally:
            listener.close()
        if stuck and completed:
            raise ServerError("the test server did not stop in time")
