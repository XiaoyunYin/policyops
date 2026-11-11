"""The environment-configured API server (offline): import without side effects, sanitized configuration errors
(synthetic canary values never rendered), pinned runtime connections, and resource ownership through the actual
`open_runtime`/`ServedApp` lifespan with failures injected at each startup stage. The database parts are fakes here;
real PostgreSQL, Dex and HTTP are in tests/integration/test_serve.py."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
import contextlib
import io
import logging
import logging.config
import os
import secrets
import subprocess
import sys
import traceback
from typing import Any
from urllib.parse import urlunsplit

import httpx
import psycopg
from pydantic import SecretStr
import pytest
import uvicorn

from policyops.api import app as app_module
from policyops.api import serve
from policyops.api.logging import LOG_CONFIG
from policyops.auth.oidc import OidcClient
from policyops.persistence.database import RuntimeRoleError
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.settings import DatabaseSettings
from policyops_contracts.clock import SystemClock
from policyops_testing import live_server


CANARY = "canary-7Qe2-do-not-render"
SHORT = "canary-short"
PRIVILEGED = "has privileges a runtime role must not have"
SECRETS = {"POLICYOPS_OIDC_CLIENT_SECRET": CANARY + "-oidc", "POLICYOPS_DB_AUTH_PASSWORD": CANARY + "-auth",
           "POLICYOPS_DB_APP_PASSWORD": CANARY + "-app"}
VALID = {"POLICYOPS_ENV": "local", "POLICYOPS_PUBLIC_ORIGIN": "http://127.0.0.1:8000",
         "POLICYOPS_OIDC_ISSUER": "http://127.0.0.1:5556/dex", "POLICYOPS_OIDC_CLIENT_ID": "policyops-local",
         "POLICYOPS_DB_HOST": "127.0.0.1", "POLICYOPS_DB_PORT": "5432", "POLICYOPS_DB_NAME": "policyops",
         "POLICYOPS_DB_SSLMODE": "disable", **SECRETS}


def clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("POLICYOPS_") or name in serve.REFUSED_LIBPQ_ENV:
            monkeypatch.delenv(name)


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    clear(monkeypatch)
    for name, value in VALID.items():
        monkeypatch.setenv(name, value)
    return dict(VALID)


def rendered(error: BaseException) -> str:
    return "".join(traceback.format_exception(error)) + repr(error) + str(error)


def url_with_userinfo(scheme: str, host: str, path: str, user: str, secret: str) -> str:
    """A synthetic credential-bearing URL assembled at runtime from explicit components (fake values only)."""
    return urlunsplit((scheme, f"{user}:{secret}@{host}", path, "", ""))


def assert_no_canary(*texts: str) -> None:
    for text in texts:
        assert CANARY not in text


# -- import and configuration ------------------------------------------------------------------------------------

def test_import_reads_no_settings_and_opens_nothing() -> None:
    code = ("import socket, psycopg\n"
            "def refuse(*a, **k): raise AssertionError('opened a connection on import')\n"
            "socket.socket.connect = refuse\npsycopg.connect = refuse\n"
            "import policyops.api.serve as s, policyops.api.openapi\n"
            "assert s.create_served_app and not any(n.startswith('POLICYOPS_') for n in __import__('os').environ)\n"
            "print('imported')\n")
    env = {name: value for name, value in os.environ.items() if not name.startswith(("POLICYOPS_", "PG"))}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    done = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code], env=env, capture_output=True,
                          timeout=120, check=False)
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")[-2000:]
    assert done.stdout.strip() == b"imported"


def test_valid_configuration_keeps_secrets_out_of_reprs(configured: dict[str, str]) -> None:
    config = serve.load_config()
    assert config.auth.env == "local" and config.database.host == "127.0.0.1" and config.database.port == 5432
    assert (config.database.sslmode, config.database.connect_timeout_seconds, config.database.pool_size) == (
        "disable", 5, 5)
    assert config.database.auth_password.get_secret_value() == SECRETS["POLICYOPS_DB_AUTH_PASSWORD"]
    assert_no_canary(repr(config), repr(config.auth), repr(config.database), str(config.database))


def test_missing_configuration_names_variables_and_no_values(monkeypatch: pytest.MonkeyPatch) -> None:
    clear(monkeypatch)
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(serve.ServeConfigError) as raised:
        serve.load_config()
    text = rendered(raised.value)
    for name in ("POLICYOPS_ENV", "POLICYOPS_PUBLIC_ORIGIN", "POLICYOPS_OIDC_ISSUER", "POLICYOPS_OIDC_CLIENT_ID",
                 "POLICYOPS_DB_HOST", "POLICYOPS_DB_NAME"):
        assert f"{name}: Field required" in text
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    assert_no_canary(text)


def test_both_database_passwords_are_required_separately(configured: dict[str, str],
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POLICYOPS_DB_APP_PASSWORD")
    legacy = url_with_userinfo("postgresql", "127.0.0.1", "/db", "u", CANARY)
    monkeypatch.setenv("POLICYOPS_DATABASE_URL", legacy)  # never read
    with pytest.raises(serve.ServeConfigError) as raised:
        serve.load_config()
    assert raised.value.problems == ("POLICYOPS_DB_APP_PASSWORD: Field required",)
    assert_no_canary(rendered(raised.value))


@pytest.mark.parametrize(("changes", "expected"), [
    ({"POLICYOPS_DB_HOST": f"db.example.test,{CANARY}"}, "POLICYOPS_DB_*: Value error, host must be one IP"),
    ({"POLICYOPS_DB_HOST": f"host={CANARY}"}, "POLICYOPS_DB_*: Value error, host must be one IP"),
    ({"POLICYOPS_DB_NAME": f"db={CANARY}"}, "POLICYOPS_DB_NAME: String should match pattern"),
    ({"POLICYOPS_DB_NAME": f"postgresql://x/{CANARY}"}, "POLICYOPS_DB_NAME: String should match pattern"),
    ({"POLICYOPS_DB_PORT": CANARY}, "POLICYOPS_DB_PORT: Input should be a valid integer"),
    ({"POLICYOPS_DB_PORT": "70000"}, "POLICYOPS_DB_PORT: Input should be less than or equal to 65535"),
    ({"POLICYOPS_DB_SSLMODE": CANARY}, "POLICYOPS_DB_SSLMODE: Input should be 'disable'"),
    ({"POLICYOPS_DB_SSLMODE": "disable", "POLICYOPS_DB_HOST": "10.0.0.5"}, "sslmode=disable is allowed only"),
    ({"POLICYOPS_DB_CONNECT_TIMEOUT_SECONDS": "1"}, "POLICYOPS_DB_CONNECT_TIMEOUT_SECONDS: Input should be greater"),
    ({"POLICYOPS_DB_POOL_SIZE": "51"}, "POLICYOPS_DB_POOL_SIZE: Input should be less than or equal to 50"),
    ({"POLICYOPS_DB_AUTH_PASSWORD": SHORT}, "auth_password must have 16 to 1024 characters"),
    ({"POLICYOPS_DB_APP_PASSWORD": CANARY * 60}, "app_password must have 16 to 1024 characters"),
    ({"POLICYOPS_DB_APP_PASSWORD": ""}, "app_password must have 16 to 1024 characters"),
    ({"POLICYOPS_OIDC_CLIENT_SECRET": SHORT}, "oidc_client_secret must have at least 16 characters"),
    ({"POLICYOPS_OIDC_ISSUER": url_with_userinfo("http", "127.0.0.1:5556", "/dex", "u", CANARY)},
     "must not contain credentials"),
    ({"POLICYOPS_ENV": CANARY}, "POLICYOPS_ENV: Input should be 'test', 'local' or 'deployment'"),
    ({"POLICYOPS_ENV": "test"}, "POLICYOPS_ENV: test is for the test suite"),
    ({"POLICYOPS_ENV": "deployment", "POLICYOPS_PUBLIC_ORIGIN": "https://policyops.example.test",
      "POLICYOPS_OIDC_ISSUER": "https://id.example.test/dex", "POLICYOPS_DB_HOST": "db.example.test",
      "POLICYOPS_DB_SSLMODE": "require"}, "POLICYOPS_DB_SSLMODE: deployment requires verify-full"),
    ({"PGSERVICE": CANARY}, "PGSERVICE: must not be set for the API server"),
    ({"PGHOSTADDR": "10.9.8.7"}, "PGHOSTADDR: must not be set for the API server"),
])
def test_malformed_configuration_is_refused_without_rendering_values(
        configured: dict[str, str], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        changes: dict[str, str], expected: str) -> None:
    for name, value in changes.items():
        monkeypatch.setenv(name, value)
    with caplog.at_level(logging.DEBUG), pytest.raises(serve.ServeConfigError) as raised:
        serve.create_served_app()
    assert expected in str(raised.value)
    assert len(str(raised.value)) < 2000
    assert_no_canary(rendered(raised.value), caplog.text)


def test_main_reports_configuration_errors_without_values(configured: dict[str, str],
                                                          monkeypatch: pytest.MonkeyPatch,
                                                          capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("POLICYOPS_DB_NAME", f"db={CANARY}")
    monkeypatch.setattr(uvicorn, "Server", None)  # never reached
    assert serve.main([]) == 2
    out, err = capsys.readouterr()
    assert "policyops serve: invalid API server configuration: POLICYOPS_DB_NAME" in err
    assert_no_canary(out, err)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "localhost", "::"])  # noqa: S104
def test_main_binds_only_loopback(configured: dict[str, str], host: str,
                                  capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        serve.main(["--host", host])
    assert raised.value.code == 2 and "--host must be a loopback IP" in capsys.readouterr().err


def test_entry_log_config_keeps_the_access_redaction() -> None:
    assert serve.SERVE_LOG_CONFIG["handlers"]["access"] == LOG_CONFIG["handlers"]["access"]
    assert serve.SERVE_LOG_CONFIG["filters"]["redact_query"] == LOG_CONFIG["filters"]["redact_query"]
    assert serve.SERVE_LOG_CONFIG["handlers"]["default"]["filters"] == ["safe_errors"]
    assert serve.SERVE_LOG_CONFIG["root"]["handlers"] == ["default"]
    assert serve.SERVE_LOG_CONFIG["loggers"]["uvicorn.access"] == LOG_CONFIG["loggers"]["uvicorn.access"]
    assert "redact_query" in serve.SERVE_LOG_CONFIG["handlers"]["access"]["filters"]


# -- runtime connections -----------------------------------------------------------------------------------------

def test_connector_pins_endpoint_identity_and_session(configured: dict[str, str],
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    def connect(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return "connection"
    monkeypatch.setattr(psycopg, "connect", connect)
    database = serve.load_config().database
    auth, app = serve.RuntimeConnector(database, AUTH_RUNTIME), serve.RuntimeConnector(database, APP_RUNTIME)
    opened: list[Any] = [auth(), app()]
    assert opened == ["connection", "connection"]
    common = {"host": "127.0.0.1", "hostaddr": "127.0.0.1", "port": 5432, "dbname": "policyops",
              "sslmode": "disable", "gssencmode": "disable", "require_auth": "scram-sha-256", "connect_timeout": 5,
              "options": "-c timezone=UTC", "client_encoding": "UTF8"}
    assert calls[0] == {**common, "user": AUTH_RUNTIME, "password": SECRETS["POLICYOPS_DB_AUTH_PASSWORD"],
                        "application_name": "policyops-api-auth"}
    assert calls[1] == {**common, "user": APP_RUNTIME, "password": SECRETS["POLICYOPS_DB_APP_PASSWORD"],
                        "application_name": "policyops-api-app"}
    assert_no_canary(repr(auth), repr(app))
    auth.close()
    with pytest.raises(serve.ServerClosed):
        auth()
    assert len(calls) == 2
    with pytest.raises(ValueError, match="only as the auth or app runtime role"):
        serve.RuntimeConnector(database, "postgres")


def test_connector_leaves_hostaddr_unset_for_a_dns_name(configured: dict[str, str],
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_DB_HOST", "db.example.test")
    monkeypatch.setenv("POLICYOPS_DB_SSLMODE", "verify-full")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: calls.append(kwargs))
    serve.RuntimeConnector(serve.load_config().database, APP_RUNTIME)()
    assert calls[0]["host"] == "db.example.test" and calls[0]["hostaddr"] is None
    assert calls[0]["sslmode"] == "verify-full"


def test_database_settings_accept_ipv6_loopback_without_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    clear(monkeypatch)
    settings = DatabaseSettings(host="::1", name="policyops", sslmode="disable", auth_password=SecretStr("a" * 16),
                                app_password=SecretStr("b" * 16))
    assert settings.host_is_ip


# -- ownership through the actual lifespan (fake engines) --------------------------------------------------------

class FakeEngine:
    def __init__(self, connector: serve.RuntimeConnector, pool_size: int, log: list[str],
                 fail_dispose: bool = False) -> None:
        self.connector, self.pool_size, self.log, self.fail_dispose = connector, pool_size, log, fail_dispose
        self.disposed = False

    def dispose(self) -> None:
        self.disposed = True
        self.log.append(f"dispose {self.connector.role}")
        if self.fail_dispose:
            raise OSError("dispose failed")


class World:
    """Fakes for the database and observation of the real OIDC clients the real wiring opens."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.log: list[str] = []
        self.engines: list[FakeEngine] = []
        self.oidc: list[OidcClient] = []
        self.fail_dispose: set[str] = set()
        self.fail_role: str | None = None
        monkeypatch.setattr(serve, "make_engine", self.make_engine)
        monkeypatch.setattr(serve, "verify_runtime_role", self.verify)
        monkeypatch.setattr(app_module, "verify_runtime_role", self.verify)
        real_init = OidcClient.__post_init__

        def record(client: OidcClient) -> None:
            real_init(client)
            self.oidc.append(client)
        monkeypatch.setattr(OidcClient, "__post_init__", record)

    def make_engine(self, connector: serve.RuntimeConnector, *, pool_size: int) -> FakeEngine:
        engine = FakeEngine(connector, pool_size, self.log, connector.role in self.fail_dispose)
        self.engines.append(engine)
        return engine

    def verify(self, engine: FakeEngine, role: str) -> None:
        assert engine.connector.role == role
        self.log.append(f"verify {role}")
        if role == self.fail_role:
            raise RuntimeRoleError(f"{role} {PRIVILEGED}")

    def released(self) -> bool:
        return (all(engine.disposed and engine.connector._closed for engine in self.engines)
                and all(client._http.is_closed for client in self.oidc))


class Lifespan:
    """Drives the ASGI lifespan protocol as a server does."""

    def __init__(self, app: serve.ServedApp) -> None:
        self.app, self.inbox, self.sent = app, asyncio.Queue[dict[str, Any]](), list[dict[str, Any]]()
        self.task: asyncio.Task[None] | None = None

    async def receive(self) -> dict[str, Any]:
        return await self.inbox.get()

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    async def startup(self) -> dict[str, Any]:
        self.task = asyncio.create_task(self.app({"type": "lifespan", "asgi": {"version": "3.0"}},
                                                 self.receive, self.send))  # type: ignore[arg-type]
        await self.inbox.put({"type": "lifespan.startup"})
        while not self.sent and not self.task.done():
            await asyncio.sleep(0)
        if self.task.done():
            self.task.result()
        return self.sent[-1]

    async def shutdown(self) -> dict[str, Any]:
        assert self.task is not None
        await self.inbox.put({"type": "lifespan.shutdown"})
        await asyncio.wait_for(self.task, 5)
        return self.sent[-1]


def run(coroutine_factory: Callable[[], Any]) -> Any:
    return asyncio.run(coroutine_factory())


@pytest.fixture
def world(configured: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    yield World(monkeypatch)


def test_lifespan_opens_serves_and_releases_everything(world: World) -> None:
    served = serve.create_served_app()
    assert world.engines == [] and world.oidc == []  # the factory opens nothing

    async def scenario() -> tuple[dict[str, Any], int, dict[str, Any], int, dict[str, Any]]:
        lifespan = Lifespan(served)
        started = await lifespan.startup()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=served), base_url="http://127.0.0.1") as c:
            live = (await c.get("/api/v1/health/live")).status_code
            me = (await c.get("/api/v1/me")).json()
            stopped = await lifespan.shutdown()
            after = await c.get("/api/v1/health/live")
        return started, live, me, after.status_code, {"stopped": stopped, "after": after.json()}

    started, live, me, after, rest = run(scenario)
    assert started == {"type": "lifespan.startup.complete"} and live == 200
    assert me["code"] == "unauthenticated"  # the real authenticated routes are installed
    assert rest["stopped"] == {"type": "lifespan.shutdown.complete"}
    assert after == 503 and rest["after"]["rule_id"] == "server.not_started"
    assert [engine.pool_size for engine in world.engines] == [5, 5] and len(world.oidc) == 1
    assert world.released()
    assert world.log == [f"verify {AUTH_RUNTIME}", f"verify {APP_RUNTIME}", f"verify {AUTH_RUNTIME}",
                         f"verify {APP_RUNTIME}", f"dispose {APP_RUNTIME}", f"dispose {AUTH_RUNTIME}"]
    assert served.close() == []  # idempotent


def test_requests_before_startup_are_refused_and_a_second_startup_is_refused(world: World) -> None:
    served = serve.create_served_app()

    async def scenario() -> tuple[httpx.Response, dict[str, Any], dict[str, Any]]:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=served), base_url="http://127.0.0.1") as c:
            before = await c.get("/api/v1/health/live")
        first = Lifespan(served)
        await first.startup()
        second = await Lifespan(served).startup()
        await first.shutdown()
        return before, second, first.sent[-1]

    before, second, stopped = run(scenario)
    assert before.status_code == 503 and before.headers["cache-control"] == "no-store"
    assert before.json()["code"] == "unavailable"
    assert second == {"type": "lifespan.startup.failed", "message": "this server instance was already started"}
    assert stopped["type"] == "lifespan.shutdown.complete" and world.released()


def _fail_app(*_args: Any, **_kwargs: Any) -> Any:
    raise RuntimeError(CANARY)


def _fail_service(*_args: Any, **_kwargs: Any) -> Any:
    raise RuntimeError(CANARY)


@pytest.mark.parametrize(("inject", "stage", "category", "oidc_opened"), [
    ("auth role", "auth runtime role check", f"RuntimeRoleError: {AUTH_RUNTIME} {PRIVILEGED}", False),
    ("app role", "app runtime role check", f"RuntimeRoleError: {APP_RUNTIME} {PRIVILEGED}", False),
    ("auth service", "authentication wiring", "RuntimeError", True),
    ("create_app", "application", "RuntimeError", True),
])
def test_partial_startup_releases_everything_acquired(world: World, monkeypatch: pytest.MonkeyPatch, inject: str,
                                                      stage: str, category: str, oidc_opened: bool) -> None:
    if inject == "auth role":
        world.fail_role = AUTH_RUNTIME
    elif inject == "app role":
        world.fail_role = APP_RUNTIME
    elif inject == "auth service":
        monkeypatch.setattr(app_module, "AuthService", _fail_service)  # after the OIDC client is opened
    else:
        monkeypatch.setattr(serve, "create_app", _fail_app)
    served = serve.create_served_app()
    lifespan = Lifespan(served)
    failed = run(lifespan.startup)
    assert failed["type"] == "lifespan.startup.failed"
    assert failed["message"] == f"API server startup failed at {stage}: {category}"
    assert_no_canary(failed["message"])
    assert len(world.engines) == 2 and len(world.oidc) == (1 if oidc_opened else 0)
    assert world.released()
    assert served.close() == []


def test_cleanup_failures_are_noted_and_every_release_is_still_attempted(world: World,
                                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    world.fail_dispose = {AUTH_RUNTIME}
    monkeypatch.setattr(serve, "create_app", _fail_app)

    def failing_close(client: OidcClient) -> None:
        client._http.close()
        raise OSError(CANARY)
    monkeypatch.setattr(OidcClient, "close", failing_close)
    with pytest.raises(serve.ServeStartupError) as raised:
        serve.open_runtime(serve.load_config())
    error = raised.value
    assert str(error) == "API server startup failed at application: RuntimeError"
    assert isinstance(error.__cause__, RuntimeError) and str(error.__cause__) == CANARY  # primary error preserved
    assert error.__notes__ == ["release also failed: OIDC client: OSError; auth runtime engine: OSError"]
    assert world.released()  # the app engine and both connectors were still released

    lifespan = Lifespan(serve.create_served_app())
    failed = run(lifespan.startup)
    assert failed["message"] == ("API server startup failed at application: RuntimeError "
                                 "(release also failed: OIDC client: OSError; auth runtime engine: OSError)")


def test_shutdown_release_failure_is_reported_after_attempting_all(world: World) -> None:
    world.fail_dispose = {APP_RUNTIME}
    lifespan = Lifespan(serve.create_served_app())

    async def scenario() -> dict[str, Any]:
        await lifespan.startup()
        return await lifespan.shutdown()

    assert run(scenario) == {"type": "lifespan.shutdown.failed",
                             "message": "release failed: app runtime engine: OSError"}
    assert world.released()


def test_a_cancelled_lifespan_still_releases(world: World) -> None:
    served = serve.create_served_app()

    async def scenario() -> None:
        lifespan = Lifespan(served)
        await lifespan.startup()
        assert lifespan.task is not None
        lifespan.task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lifespan.task

    run(scenario)
    assert world.released() and served.close() == []


def test_an_interruption_during_startup_releases_and_propagates(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt
    monkeypatch.setattr(serve, "create_app", interrupted)
    with pytest.raises(KeyboardInterrupt):
        serve.open_runtime(serve.load_config())
    assert len(world.oidc) == 1 and world.released()


def test_build_auth_runtime_closes_its_oidc_client_when_wiring_fails(world: World,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "AuthService", _fail_service)
    config = serve.load_config()
    engine: Any = FakeEngine(serve.RuntimeConnector(config.database, AUTH_RUNTIME), 1, [])
    app_engine: Any = FakeEngine(serve.RuntimeConnector(config.database, APP_RUNTIME), 1, [])
    with pytest.raises(RuntimeError) as raised:
        app_module.build_auth_runtime(config.auth, auth_engine=engine, app_engine=app_engine,
                                      clock=SystemClock())
    assert str(raised.value) == CANARY and len(world.oidc) == 1 and world.oidc[0]._http.is_closed
    assert not engine.disposed and not app_engine.disposed  # caller-owned engines are not touched


@pytest.mark.parametrize(("message", "label"), [
    (f'connection to server at "127.0.0.1", port 1 failed: FATAL:  password authentication failed for user "x" '
     f'{CANARY}', "password authentication refused"),
    ('connection to server at "127.0.0.1", port 1 failed: Connection refused', "connection refused"),
    ("connection to server failed: timeout expired", "connect timeout"),
    (f"something new {CANARY}", "connection failed"),
])
def test_connection_failures_render_fixed_labels_only(message: str, label: str) -> None:
    category = serve._category(psycopg.OperationalError(message))
    assert category == f"OperationalError (no SQLSTATE: {label})"
    assert_no_canary(category)


# -- served error logging (synthetic canaries are generated per test and must never be rendered) -----------------

@pytest.fixture
def logging_state() -> Iterator[None]:
    """`SERVE_LOG_CONFIG` reconfigures process-wide loggers; restore them so no handler outlives the test."""
    names = ("", "uvicorn", "uvicorn.error", "uvicorn.access", "policyops.test")
    saved = {name: (lg.handlers[:], lg.filters[:], lg.level, lg.propagate, lg.disabled)
             for name in names for lg in [logging.getLogger(name)]}
    yield
    for name, (handlers, filters, level, propagate, disabled) in saved.items():
        lg = logging.getLogger(name)
        for handler in lg.handlers:
            if handler not in handlers:
                handler.close()
        lg.handlers[:], lg.filters[:] = handlers, filters
        lg.level, lg.propagate, lg.disabled = level, propagate, disabled


def _configured_output() -> io.StringIO:
    output = io.StringIO()
    with contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
        logging.config.dictConfig(serve.SERVE_LOG_CONFIG)  # the handler streams are resolved here
    return output


def test_logged_exceptions_render_categories_and_locations_only(logging_state: None) -> None:
    canary = "log-canary-" + secrets.token_hex(12)
    output = _configured_output()

    def fail() -> None:
        try:
            raise OSError(canary + "-context")
        except OSError as context:
            raise RuntimeError(canary) from context
    try:
        fail()
    except RuntimeError as error:
        logging.getLogger("uvicorn.error").error("Exception in ASGI application\n", exc_info=error)
        logging.getLogger("uvicorn.error").error("Error loading ASGI app factory: %s", error)
        logging.getLogger("uvicorn.error").error(error)
        logging.getLogger("policyops.test").exception("library failure")  # through the root handler
        logging.getLogger("policyops.test").warning("stack", stack_info=True)
    text = output.getvalue()
    lines = text.splitlines()
    assert canary not in text and "Traceback" not in text and len(lines) == 5  # one bounded line per record
    assert lines[0].startswith("ERROR:    Exception in ASGI application [RuntimeError <- OSError at ")
    assert lines[0].endswith(" fail; traceback withheld]")
    assert lines[1:3] == ["ERROR:    Error loading ASGI app factory: RuntimeError", "ERROR:    RuntimeError"]
    assert lines[3].startswith("ERROR:    library failure [RuntimeError <- OSError at ")
    assert lines[4] == "WARNING:  stack"


def test_driver_errors_in_logs_keep_only_the_fixed_category(logging_state: None) -> None:
    canary = "driver-canary-" + secrets.token_hex(12)
    output = _configured_output()
    error = psycopg.OperationalError(f"password authentication failed for user {canary}")
    logging.getLogger("uvicorn.error").error("x\r\nforged line %s", "arg", exc_info=error)
    assert output.getvalue() == ("ERROR:    x\\r\\nforged line arg "
                                 "[OperationalError (no SQLSTATE: password authentication refused); "
                                 "traceback withheld]\n")


def test_exceptions_in_named_and_nested_log_arguments_render_categories_only(logging_state: None) -> None:
    canary = "args-canary-" + secrets.token_hex(12)
    output = _configured_output()
    error, log = RuntimeError(canary), logging.getLogger("policyops.test")
    log.error("operation failed: %(error)s", {"error": error})  # `LogRecord` unwraps the mapping: `args` is a dict
    log.warning("%(count)d retries at %(rate).2f for %(name)s, %(name)r", {"count": 3, "rate": 0.5, "name": "pool"})
    log.warning("%d of %s at %.1f", 2, "pool", 1.25)
    log.error("context %s", {"error": error})  # the whole mapping
    log.error("%s", {error: 1})  # an exception as a key
    log.error("nested %s %r", [error, (error,)], {"key": {error}})
    log.error({"error": error})  # a non-string message object
    log.error("%s", [[[[error]]]])  # deeper than `MAX_ARG_DEPTH`
    text = output.getvalue()
    assert canary not in text and "Traceback" not in text
    assert text.splitlines() == ["ERROR:    operation failed: RuntimeError",
                                 "WARNING:  3 retries at 0.50 for pool, 'pool'",
                                 "WARNING:  2 of pool at 1.2",
                                 "ERROR:    context {'error': 'RuntimeError'}",
                                 "ERROR:    {'RuntimeError': 1}",
                                 "ERROR:    nested ['RuntimeError', ('RuntimeError',)] {'key': {'RuntimeError'}}",
                                 "ERROR:    {'error': 'RuntimeError'}",
                                 "ERROR:    [[['<list withheld>']]]"]


def test_an_unexpected_request_error_over_real_uvicorn_logs_no_secret(configured: dict[str, str],
                                                                      logging_state: None) -> None:
    canary = "served-canary-" + secrets.token_hex(12)
    application = app_module.create_app()

    @application.get("/api/v1/__failing_probe")
    async def failing() -> None:
        raise RuntimeError(canary)
    releases: list[bool] = []
    runtime = serve.ServedRuntime()
    runtime.app = application
    runtime.own("probe", lambda: releases.append(True))
    served = serve.ServedApp(serve.load_config())
    output = io.StringIO()

    def factory(asgi: Any) -> uvicorn.Server:
        return uvicorn.Server(uvicorn.Config(asgi, log_config=serve.SERVE_LOG_CONFIG, lifespan="on", ws="none",
                                             proxy_headers=False, server_header=False, timeout_graceful_shutdown=1))
    with (contextlib.redirect_stdout(output), contextlib.redirect_stderr(output),
          pytest.MonkeyPatch.context() as patch):
        patch.setattr(serve, "open_runtime", lambda _config: runtime)
        with (live_server.serve(served, server_factory=factory, startup_timeout=5, stop_timeout=5) as url,
              httpx.Client(base_url=url, trust_env=False, timeout=3) as client):
            live = client.get("/api/v1/health/live")  # first: uvicorn closes the connection after the error
            failed = client.get("/api/v1/__failing_probe", params={"code": canary})
    text = output.getvalue()
    assert failed.status_code == 500 and canary not in failed.text and live.status_code == 200
    assert canary not in text and "Traceback" not in text
    assert '"GET /api/v1/__failing_probe?[REDACTED] HTTP/1.1" 500' in text
    assert "Exception in ASGI application [RuntimeError at " in text and " failing; traceback withheld]" in text
    assert releases == [True] and served.close() == []


# -- an error in flight is never replaced by a release failure ---------------------------------------------------

def test_a_cleanup_interruption_does_not_mask_the_startup_failure(configured: dict[str, str],
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    primary, connectors = ValueError("setup " + CANARY), list[serve.RuntimeConnector]()

    class Engine:
        def dispose(self) -> None:
            raise KeyboardInterrupt

    def make_engine(connector: serve.RuntimeConnector, **_kwargs: Any) -> Engine:
        connectors.append(connector)
        if len(connectors) == 2:
            raise primary
        return Engine()
    monkeypatch.setattr(serve, "make_engine", make_engine)
    with pytest.raises(serve.ServeStartupError) as raised:
        serve.open_runtime(serve.load_config())
    assert raised.value.__cause__ is primary
    assert str(raised.value) == "API server startup failed at app runtime engine: ValueError"
    assert raised.value.__notes__ == ["release also failed: auth runtime engine: KeyboardInterrupt"]
    assert len(connectors) == 2 and all(connector._closed for connector in connectors)
    assert_no_canary(str(raised.value), *raised.value.__notes__)


def test_an_interruption_in_flight_keeps_its_identity_and_notes_release_failures(
        world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    interruption = KeyboardInterrupt()
    world.fail_dispose = {APP_RUNTIME}

    def interrupted(*_args: Any, **_kwargs: Any) -> Any:
        raise interruption
    monkeypatch.setattr(serve, "create_app", interrupted)
    with pytest.raises(KeyboardInterrupt) as raised:
        serve.open_runtime(serve.load_config())
    assert raised.value is interruption
    assert interruption.__notes__ == ["release also failed: app runtime engine: OSError"]
    assert world.released()


def _raise_keyboard_interrupt() -> None:
    raise KeyboardInterrupt


def test_close_without_an_error_in_flight_reraises_an_interruption_after_all_releases() -> None:
    runtime, released = serve.ServedRuntime(), list[str]()

    def interrupt() -> None:
        released.append("second")
        _raise_keyboard_interrupt()
    runtime.own("first", lambda: released.append("first"))
    runtime.own("second", interrupt)
    with pytest.raises(KeyboardInterrupt):
        runtime.close()
    assert released == ["second", "first"] and runtime.close() == []


def test_a_cancelled_lifespan_propagates_cancellation_despite_a_release_interruption(world: World) -> None:
    served = serve.create_served_app()

    async def scenario() -> asyncio.CancelledError:
        lifespan = Lifespan(served)
        await lifespan.startup()
        assert served._runtime is not None and lifespan.task is not None
        served._runtime.own("interrupting", _raise_keyboard_interrupt)
        lifespan.task.cancel()
        with pytest.raises(asyncio.CancelledError) as raised:
            await lifespan.task
        return raised.value

    cancelled = run(scenario)
    assert cancelled.__notes__ == ["release also failed: interrupting: KeyboardInterrupt"]
    assert world.released()


def test_main_propagates_the_server_error_not_a_release_failure(configured: dict[str, str],
                                                                monkeypatch: pytest.MonkeyPatch,
                                                                capsys: pytest.CaptureFixture[str]) -> None:
    served, primary = serve.ServedApp(serve.load_config()), RuntimeError("server " + CANARY)
    runtime = serve.ServedRuntime()
    runtime.own("interrupting", _raise_keyboard_interrupt)
    served._runtime = runtime

    class Server:
        def __init__(self, _config: Any) -> None:
            pass

        def run(self) -> None:
            raise primary
    monkeypatch.setattr(serve, "create_served_app", lambda: served)
    monkeypatch.setattr(uvicorn, "Server", Server)
    with pytest.raises(RuntimeError) as raised:
        serve.main([])
    assert raised.value is primary and primary.__notes__ == ["release also failed: interrupting: KeyboardInterrupt"]
    assert capsys.readouterr().err == "policyops serve: release failed: interrupting: KeyboardInterrupt\n"


def test_build_auth_runtime_keeps_the_wiring_error_when_closing_is_interrupted(
        world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "AuthService", _fail_service)

    def interrupted_close(client: OidcClient) -> None:
        client._http.close()
        _raise_keyboard_interrupt()
    monkeypatch.setattr(OidcClient, "close", interrupted_close)
    config = serve.load_config()
    engine: Any = FakeEngine(serve.RuntimeConnector(config.database, AUTH_RUNTIME), 1, [])
    app_engine: Any = FakeEngine(serve.RuntimeConnector(config.database, APP_RUNTIME), 1, [])
    with pytest.raises(RuntimeError) as raised:
        app_module.build_auth_runtime(config.auth, auth_engine=engine, app_engine=app_engine, clock=SystemClock())
    assert str(raised.value) == CANARY
    assert raised.value.__notes__ == ["closing the OIDC client also failed: KeyboardInterrupt"]
    assert world.oidc[0]._http.is_closed


def test_engine_release_closes_the_connector_gate_before_disposing(world: World,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    gate_closed: list[bool] = []
    real_dispose = FakeEngine.dispose

    def dispose(engine: FakeEngine) -> None:
        gate_closed.append(engine.connector._closed)
        real_dispose(engine)
    monkeypatch.setattr(FakeEngine, "dispose", dispose)
    runtime = serve.open_runtime(serve.load_config())
    assert runtime.close() == [] and gate_closed == [True, True] and world.released()
    with pytest.raises(serve.ServerClosed):
        world.engines[0].connector()
