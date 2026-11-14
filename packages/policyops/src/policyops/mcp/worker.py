"""Serial framed worker. The stdin reader also kills the process immediately on parent EOF."""

from __future__ import annotations

from contextlib import ExitStack
import os
from queue import Queue
import sys
import threading

from pydantic import SecretStr

from policyops.adapters.retail_client import RetailClient
from policyops.api.serve import RuntimeConnector
from policyops.auth.oidc import OidcClient
from policyops.auth.service import AuthService
from policyops.mcp.config import Configuration, load
from policyops.mcp.contracts import MAX_ARGUMENT_BYTES, Result, bounded, error
from policyops.mcp.service import ReadService
from policyops.persistence.database import make_engine, verify_runtime_role
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers.canonical import strict_loads
from policyops.settings import AuthSettings, DatabaseSettings
from policyops_contracts.clock import SystemClock
from policyops_contracts.errors import ErrorCode


def read_exact(size: int) -> bytes:
    body = bytearray()
    while len(body) < size:
        chunk = sys.stdin.buffer.read(size - len(body))
        if not chunk:
            # No grandchildren. Exit closes sockets; PostgreSQL applies its own disconnect/SQL deadlines.
            os._exit(1)
        body.extend(chunk)
    return bytes(body)


def parent_watch(requests: Queue[bytes] | None = None) -> None:
    # Sole stdin reader: never compete with a second buffered read for the next request or EOF.
    try:
        while True:
            size = int.from_bytes(read_exact(4), "big")
            if not 0 < size <= MAX_ARGUMENT_BYTES + 1024 or requests is None:
                os._exit(2)
            requests.put_nowait(read_exact(size))
    except Exception:
        os._exit(2)


def service(stack: ExitStack, config: Configuration, cookie: SecretStr) -> ReadService:
    settings, database = AuthSettings(), DatabaseSettings()
    engines = []
    for role in (AUTH_RUNTIME, APP_RUNTIME):
        connector = RuntimeConnector(database, role)
        stack.callback(connector.close)
        engine = make_engine(connector, pool_size=1)
        stack.callback(engine.dispose)
        engines.append(engine)
    auth_engine, app_engine = engines
    clock = SystemClock()
    oidc = OidcClient(settings, clock)
    stack.callback(oidc.close)
    auth = AuthService(settings, oidc, auth_engine, clock)
    key = SecretStr(os.environ["POLICYOPS_MCP_RETAIL_KEY_HEX"])
    if len(key.get_secret_value()) != 64:
        raise ValueError("invalid retail key")
    retail = RetailClient(os.environ["POLICYOPS_MCP_RETAIL_ORIGIN"], bytes.fromhex(key.get_secret_value()),
                          tenant_id=config.workspace_id, case_id=config.binding.scope.case_id,
                          customer_id=config.binding.user_id, fixture_sha256=config.fixture_sha256,
                          timeout_seconds=min(5, config.timeout_seconds))
    stack.callback(retail.close)
    return ReadService(config, cookie, auth, app_engine, retail, clock)


def execute(reader: ReadService, name: str, values: dict[str, object]) -> Result:
    # These bounded SQL checks exercise pooled connections and verify privileges again on every call.
    # HTTP clients check their connections on each request; transport/DB failures return unavailable or raise,
    # and the parent discards the worker. No service, authorization result or transaction is cached per call.
    verify_runtime_role(reader.auth.auth_engine, AUTH_RUNTIME)
    verify_runtime_role(reader.engine, APP_RUNTIME)
    return reader.call(name, values)


def main() -> None:
    requests: Queue[bytes] = Queue(maxsize=1)
    threading.Thread(target=parent_watch, args=(requests,), daemon=True).start()
    with ExitStack() as stack:
        reader = None
        config, cookie = load()
        while True:
            raw = requests.get()
            try:
                request = strict_loads(raw)
                if not isinstance(request, dict) or set(request) != {"name", "arguments"}:
                    raise ValueError("invalid request")
                name, values = request["name"], request["arguments"]
                if not isinstance(name, str) or not isinstance(values, dict):
                    raise ValueError("invalid request")
                if not config.issued_at <= SystemClock().now() < config.expires_at:
                    result = error(ErrorCode.UNAUTHENTICATED, "identity_refused")
                else:
                    if reader is None:
                        reader = service(stack, config, cookie)
                    result = execute(reader, name, values)
            except Exception:
                # No exception text, connection representations or peer data reach transport diagnostics.
                result = error(ErrorCode.UNAVAILABLE, "call_failed")
            body = bounded(result).model_dump_json().encode("utf-8")
            sys.stdout.buffer.write(len(body).to_bytes(4, "big") + body)
            sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
