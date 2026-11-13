"""Owned loopback relay: commit a real mutation, then withhold all downstream bytes.

Only a successful committed mutation is gated. Signed request bytes/headers/path pass
through unchanged. No captured authorization header is persisted or exposed.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.parse import urlsplit

from policyops_contracts.retail_service import OperationResult
from policyops_testing import network


class ReplyGate:
    def __init__(self, upstream: str) -> None:
        parsed = urlsplit(upstream)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None or parsed.path:
            raise ValueError("relay requires an explicit loopback HTTP origin")
        self.host, self.port = parsed.hostname, parsed.port
        self.committed = threading.Event()
        self.release = threading.Event()
        self.drained = threading.Event()
        self.receipt: OperationResult | None = None
        self.errors: list[str] = []
        self._lock = threading.Lock()
        self._armed = True

    @contextmanager
    def running(self) -> Iterator[str]:
        gate = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, format: str, *args: object) -> None:
                pass  # headers, tokens and payloads never enter server logs

            def do_GET(self) -> None:
                self.forward()

            def do_POST(self) -> None:
                self.forward()

            def do_PUT(self) -> None:
                self.forward()

            def forward(self) -> None:
                upstream = HTTPConnection(gate.host, gate.port, timeout=5)
                gated = False
                try:
                    self.connection.settimeout(5)
                    length = int(self.headers.get("content-length", "0"))
                    if not 0 <= length <= 65536 or self.headers.get("transfer-encoding"):
                        self.send_error(413)
                        return
                    body = self.rfile.read(length)
                    if len(body) != length:
                        return
                    headers = {key: value for key, value in self.headers.items()
                               if key.lower() not in ("host", "connection")}
                    upstream.request(self.command, self.path, body=body, headers=headers)
                    reply = upstream.getresponse()
                    data = reply.read(1024 * 1024 + 1)
                    if len(data) > 1024 * 1024:
                        raise ValueError("relay upstream response exceeds cap")
                    if self.command == "PUT" and "/operations/" in self.path and reply.status == 200:
                        result = OperationResult.model_validate_json(data)
                        with gate._lock:
                            if gate._armed and result.outcome == "committed":
                                gate._armed = False
                                gate.receipt = result
                                gated = True
                        if gated:
                            gate.committed.set()  # only after the full successful response was buffered
                            if not gate.release.wait(5):
                                gate.errors.append("release_deadline")
                            return  # zero downstream bytes; RetailClient must already have read-timed-out
                    self.send_response(reply.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (OSError, ValueError) as error:
                    gate.errors.append(type(error).__name__)
                finally:
                    upstream.close()
                    if gated:
                        gate.drained.set()

        server: ThreadingHTTPServer | None = None
        thread: threading.Thread | None = None
        primary: BaseException | None = None
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            # server_close joins non-daemon handlers; all their socket and event waits are bounded.
            server.daemon_threads = False
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                                      name="t30-reply-gate")
            thread.start()
            with network.allow("127.0.0.1", server.server_port), network.allow(self.host, self.port):
                yield f"http://127.0.0.1:{server.server_port}"
        except BaseException as error:
            primary = error
            raise
        finally:
            self.release.set()
            if server is not None:
                if thread is not None and thread.is_alive():
                    server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(6)
                if thread.is_alive():
                    if primary is None:
                        raise RuntimeError("relay thread did not stop")
                    primary.add_note("relay thread did not stop")
