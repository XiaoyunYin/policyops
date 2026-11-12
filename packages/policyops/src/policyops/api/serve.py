"""The environment-configured API server: an ASGI factory and the supported local entry command.

    python -m policyops.api.serve [--host 127.0.0.1] [--port 8000]

Configuration comes from explicit `POLICYOPS_*` variables only (`AuthSettings`, `DatabaseSettings`; no `.env` file
is read). Importing this module reads no settings and opens nothing.

Lifetime. `create_served_app()` validates configuration and returns a `ServedApp` without any I/O. Resources are
acquired only in the ASGI lifespan startup: the auth and app runtime engines, a check that each authenticates as
its restricted runtime role (`build_auth_runtime`), the OIDC HTTP client, then `create_app(auth)`. Everything
acquired is owned, and its release is attempted if any later step fails and at lifespan shutdown
(`ServedApp.close()`; idempotent). A release that fails is reported by type (a startup note, `lifespan.shutdown.failed`
or the entry command's stderr), never as released, and the error that caused the release stays the one raised.
Startup runs synchronously on the event loop, before any request is served, so no cancellation can land between
acquiring a resource and recording it. Engine release first closes its connector gate (no new runtime connection
opens after that), then disposes the pool, closing checked-in connections; a connection still checked out by a
request that outlived graceful shutdown is not forcibly closed (it closes when returned or collected). Releases run
synchronously on the event loop and are not bounded by uvicorn's 10 s graceful-shutdown window, which covers only
in-flight requests; closing a pooled connection is socket I/O. There is no database statement timeout here, so a
running query is not guaranteed to be cancelled.

Not configured here: database schema, roles, migrations or seed data (startup never creates or changes them), and
no investigation runtime (starting a run answers 503 `runtime.unconfigured`). Clocks: authentication uses the
process `SystemClock` (UTC); leases, runs and events use the database clock via `create_app`'s default runs
runtime. The two are not interchangeable.

Logging. `main()` installs one allowlisted JSON formatter for access, error and library logs.
Free-form messages, arguments, raw paths, exception messages, stack frames and traceback text are never rendered.
Only fixed event codes, safe typed fields, exception type names and active trace/span IDs are emitted.
Startup configuration diagnostics remain fixed categories with no configured values or driver messages.

"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import ipaddress
import logging
import os
import sys
from typing import Any

from fastapi import FastAPI
import psycopg
from pydantic import ValidationError
from sqlalchemy.exc import DBAPIError
from starlette.types import Receive, Scope, Send
import uvicorn

from policyops.api.app import build_auth_runtime, create_app
from policyops.api.auth import error_response
from policyops.api.logging import LOG_CONFIG
from policyops.auth.service import AuthError
from policyops.persistence.database import DatabaseUnavailable, RuntimeRoleError, make_engine, verify_runtime_role
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.settings import AuthSettings, DatabaseSettings, TelemetrySettings
from policyops.telemetry import configure
from policyops_contracts.clock import SystemClock
from policyops_contracts.errors import ErrorCode


# libpq fills any parameter not passed explicitly from PG* variables, and a service entry may supply hostaddr, TLS
# files and more. These two could silently redirect the configured endpoint, so the server refuses to start with
# them; every other connection parameter that matters is passed explicitly (see `RuntimeConnector`).
REFUSED_LIBPQ_ENV = ("PGSERVICE", "PGHOSTADDR")
SESSION_OPTIONS = ("-c timezone=UTC -c statement_timeout=5000 -c lock_timeout=1000 "
                   "-c idle_in_transaction_session_timeout=5000")  # no ambient PGOPTIONS
APPLICATION_NAMES = {AUTH_RUNTIME: "policyops-api-auth", APP_RUNTIME: "policyops-api-app"}
GRACEFUL_SHUTDOWN_SECONDS = 10
MAX_PROBLEMS, MAX_TEXT = 20, 240
CONNECT_FAILURES = (("password authentication failed", "password authentication refused"),
                    ("authentication method requirement", "authentication method refused"),
                    ("timeout expired", "connect timeout"), ("Connection refused", "connection refused"),
                    ("could not translate host name", "host name not resolved"),
                    ("does not exist", "role or database does not exist"))

class ServeConfigError(ValueError):
    """The server configuration is missing or invalid. Names variables and fixed reasons only, never values."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = tuple(problem[:MAX_TEXT] for problem in problems[:MAX_PROBLEMS])
        super().__init__("invalid API server configuration: " + "; ".join(self.problems))


class ServeStartupError(RuntimeError):
    """Startup failed; the release of everything acquired was attempted, and a failed release is a note (`name:
    ExceptionType`), not a release. The message is a fixed category; the original error is `__cause__` (in-process
    diagnosis only: driver messages are not part of the rendered category)."""

    def __init__(self, phase: str, cause: Exception) -> None:
        self.phase, self.category = phase, _category(cause)
        super().__init__(f"API server startup failed at {phase}: {self.category}")


class ServerClosed(RuntimeError):
    """A connection was requested from a runtime engine after the server released it."""


class ServeConfig:
    """Validated server configuration (both settings objects keep their secrets as `SecretStr`)."""

    __slots__ = ("auth", "database", "telemetry")

    def __init__(self, auth: AuthSettings, database: DatabaseSettings,
                 telemetry: TelemetrySettings | None = None) -> None:
        self.auth, self.database = auth, database
        self.telemetry = telemetry or TelemetrySettings(enabled=False)

    def __repr__(self) -> str:
        return f"ServeConfig(env={self.auth.env!r})"


def _problems(error: ValidationError, prefix: str) -> list[str]:
    problems = []
    for item in error.errors(include_url=False, include_context=False, include_input=False):
        location = item["loc"]
        name = prefix + str(location[0]).upper() if location else prefix + "*"
        problems.append(f"{name}: {item['msg']}")
    return problems


def _auth_settings(problems: list[str]) -> AuthSettings | None:
    try:
        return AuthSettings()
    except ValidationError as error:
        problems.extend(_problems(error, "POLICYOPS_"))
    except Exception as error:  # a settings source failure: its type only, no text
        problems.append(f"POLICYOPS_*: could not be read ({type(error).__name__})")
    return None


def _database_settings(problems: list[str]) -> DatabaseSettings | None:
    try:
        return DatabaseSettings()
    except ValidationError as error:
        problems.extend(_problems(error, "POLICYOPS_DB_"))
    except Exception as error:  # as above
        problems.append(f"POLICYOPS_DB_*: could not be read ({type(error).__name__})")
    return None


def load_config() -> ServeConfig:
    """Read and validate the server configuration from the process environment (no `.env` file, no I/O)."""
    problems: list[str] = []
    auth, database = _auth_settings(problems), _database_settings(problems)
    try:
        telemetry = TelemetrySettings()
    except ValidationError as error:
        problems.extend(_problems(error, "POLICYOPS_TELEMETRY_"))
        telemetry = TelemetrySettings(enabled=False)
    problems += [f"{name}: must not be set for the API server (libpq would take connection parameters from it)"
                 for name in REFUSED_LIBPQ_ENV if os.environ.get(name)]
    if auth is not None and auth.env == "test":
        problems.append("POLICYOPS_ENV: test is for the test suite; the API server runs as local or deployment")
    if auth is not None and database is not None and auth.env == "deployment" and database.sslmode != "verify-full":
        problems.append("POLICYOPS_DB_SSLMODE: deployment requires verify-full")
    if problems or auth is None or database is None:
        raise ServeConfigError(problems)
    return ServeConfig(auth, database, telemetry)


class RuntimeConnector:
    """The connection factory of one runtime engine (`make_engine`): every libpq parameter that selects the
    endpoint, identity, authentication or session options is explicit, the password is revealed only for the call,
    and after `close()` no new connection is opened."""

    def __init__(self, database: DatabaseSettings, role: str) -> None:
        passwords = {AUTH_RUNTIME: database.auth_password, APP_RUNTIME: database.app_password}
        if role not in passwords:
            raise ValueError("the API server connects only as the auth or app runtime role")
        self.role, self._database, self._password = role, database, passwords[role]
        self._closed = False

    def __call__(self) -> psycopg.Connection[Any]:
        if self._closed:
            raise ServerClosed(f"the {self.role} engine was released")
        database = self._database
        return psycopg.connect(
            host=database.host, hostaddr=database.host if database.host_is_ip else None, port=database.port,
            dbname=database.name, user=self.role, password=self._password.get_secret_value(),
            sslmode=database.sslmode, gssencmode="disable", require_auth="scram-sha-256",
            connect_timeout=database.connect_timeout_seconds, options=SESSION_OPTIONS, client_encoding="UTF8",
            application_name=APPLICATION_NAMES[self.role])

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return f"RuntimeConnector(role={self.role!r})"


class ServedRuntime:
    """What a started server owns. `close()` and `close_after()` attempt every release once, most recent first, and
    return the failures (as `name: ExceptionType`)."""

    def __init__(self) -> None:
        self.app: FastAPI | None = None
        self._releases: list[tuple[str, Callable[[], None]]] = []

    def own(self, name: str, release: Callable[[], None]) -> None:
        self._releases.append((name, release))

    def _release(self) -> tuple[list[str], BaseException | None]:
        failures: list[str] = []
        interrupted: BaseException | None = None
        while self._releases:
            name, release = self._releases.pop()
            try:
                release()
            except BaseException as error:  # reported by type; the remaining releases still run
                failures.append(f"{name}: {type(error).__name__}")
                if not isinstance(error, Exception):
                    interrupted = interrupted or error
        return failures, interrupted

    def close(self) -> list[str]:
        """Release with no error in flight: a release interruption (not an `Exception`) is re-raised after the
        remaining releases."""
        failures, interrupted = self._release()
        if interrupted is not None:
            raise interrupted
        return failures

    def close_after(self, primary: BaseException) -> list[str]:
        """Release while `primary` propagates: nothing is raised here, so `primary` stays the error raised; each
        failed release, an interruption included, is noted on it by type."""
        failures, _ = self._release()
        if failures:
            primary.add_note("release also failed: " + "; ".join(failures))
        return failures


def _gated_release(connector: RuntimeConnector, engine: Any) -> Callable[[], None]:
    def release() -> None:
        connector.close()  # first, so the pool cannot open a new connection during or after its disposal
        engine.dispose()
    return release


def _category(error: BaseException) -> str:
    """A fixed description: exception type, SQLSTATE and the (value-free) runtime-role refusal text only."""
    if isinstance(error, DatabaseUnavailable):
        if isinstance(error.__cause__, (DBAPIError, psycopg.Error)):
            return _category(error.__cause__)  # retain the safe driver category through transaction wrapping
        if error.sqlstate:
            return f"DatabaseUnavailable (SQLSTATE {error.sqlstate})"
    if isinstance(error, DBAPIError) and error.orig is not None:
        error = error.orig
    if isinstance(error, RuntimeRoleError):
        return f"RuntimeRoleError: {str(error)[:MAX_TEXT]}"
    if isinstance(error, psycopg.Error):
        if error.sqlstate:
            return f"{type(error).__name__} (SQLSTATE {error.sqlstate})"
        # libpq connection-phase failures carry no SQLSTATE: a fixed label from known (English) message
        # fragments; the driver text itself is never rendered.
        text = str(error)
        label = next((label for fragment, label in CONNECT_FAILURES if fragment in text), "connection failed")
        return f"{type(error).__name__} (no SQLSTATE: {label})"
    return type(error).__name__


class SafeErrorFilter(logging.Filter):
    """Retain only a type name; never evaluate arbitrary objects or render message/argument text."""

    def filter(self, record: logging.LogRecord) -> bool:
        error = record.exc_info[1] if record.exc_info else None
        if error is None and isinstance(record.msg, BaseException):
            error = record.msg
        if error is not None:
            record.exception_type = type(error).__name__
        record.exc_info, record.exc_text, record.stack_info = None, None, None
        return True


SERVE_LOG_CONFIG: dict[str, Any] = {
    **LOG_CONFIG,
    "filters": {**LOG_CONFIG["filters"], "safe_errors": {"()": SafeErrorFilter}},
    "formatters": LOG_CONFIG["formatters"],
    "handlers": {**LOG_CONFIG["handlers"],
                 "default": {"class": "logging.StreamHandler", "formatter": "default", "filters": ["safe_errors"],
                             "stream": "ext://sys.stderr"}},
    "loggers": {**LOG_CONFIG["loggers"],
                "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False}},
    # every other logger (SQLAlchemy pool, asyncio, the project) renders through the same filter, not `lastResort`
    "root": {"handlers": ["default"], "level": "WARNING"},
}


def open_runtime(config: ServeConfig) -> ServedRuntime:
    """Acquire and wire everything the server needs. On any failure the release of everything already acquired is
    attempted and `ServeStartupError` bound to the failure (or the original non-`Exception` interruption)
    propagates, with any failed release noted on it; a release failure never replaces it."""
    runtime = ServedRuntime()
    stage = "auth runtime engine"
    try:
        telemetry = configure(config.telemetry)
        if telemetry is not None:
            runtime.own("telemetry", telemetry.close)
        engines = {}
        for role, label in ((AUTH_RUNTIME, "auth"), (APP_RUNTIME, "app")):
            stage = f"{label} runtime engine"
            connector = RuntimeConnector(config.database, role)
            runtime.own(f"{label} runtime connector", connector.close)
            engine = make_engine(connector, pool_size=config.database.pool_size)
            runtime.own(f"{label} runtime engine", _gated_release(connector, engine))
            engines[role] = engine
        for role, label in ((AUTH_RUNTIME, "auth"), (APP_RUNTIME, "app")):
            stage = f"{label} runtime role check"
            verify_runtime_role(engines[role], role)
        stage = "authentication wiring"
        auth = build_auth_runtime(config.auth, auth_engine=engines[AUTH_RUNTIME], app_engine=engines[APP_RUNTIME],
                                  clock=SystemClock())
        runtime.own("OIDC client", auth.service.oidc.close)
        stage = "application"
        runtime.app = create_app(auth)
    except BaseException as error:
        if not isinstance(error, Exception):
            runtime.close_after(error)
            raise
        startup = ServeStartupError(stage, error)
        runtime.close_after(startup)
        raise startup from error
    return runtime


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ServedApp:
    """The served ASGI application: `create_app(auth)` once lifespan startup has opened its runtime. Without a
    started lifespan (a host running with lifespan off) every HTTP request is answered 503."""

    def __init__(self, config: ServeConfig) -> None:
        self._config = config
        self._runtime: ServedRuntime | None = None
        self._lifespan_used = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        runtime = self._runtime
        if runtime is not None and runtime.app is not None:
            await runtime.app(scope, receive, send)
        elif scope["type"] == "http":
            await error_response(AuthError(503, ErrorCode.UNAVAILABLE, "The API server is not started.",
                                           "server.not_started"))(scope, receive, send)

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        if (await receive())["type"] != "lifespan.startup":
            return
        if self._lifespan_used:
            await send({"type": "lifespan.startup.failed", "message": "this server instance was already started"})
            return
        self._lifespan_used = True
        try:
            self._runtime = open_runtime(self._config)
        except ServeStartupError as error:
            logging.getLogger("uvicorn.error").error("api.startup_failed", extra={
                "event": "api.startup_failed", "startup_phase": error.phase, "startup_category": error.category,
            })
            notes = " (" + "; ".join(error.__notes__) + ")" if getattr(error, "__notes__", None) else ""
            await send({"type": "lifespan.startup.failed", "message": str(error) + notes})
            return
        try:
            await send({"type": "lifespan.startup.complete"})
            await receive()  # lifespan.shutdown
        except BaseException as error:  # cancelled or the channel broke: release, then propagate it
            self.close_after(error)
            raise
        failures = self.close()
        if failures:
            await send({"type": "lifespan.shutdown.failed", "message": "release failed: " + "; ".join(failures)})
        else:
            await send({"type": "lifespan.shutdown.complete"})

    def close(self) -> list[str]:
        """Release the started runtime, if any (idempotent); later requests are answered 503."""
        runtime, self._runtime = self._runtime, None
        return [] if runtime is None else runtime.close()

    def close_after(self, primary: BaseException) -> list[str]:
        """`close()` while `primary` propagates (`ServedRuntime.close_after`)."""
        runtime, self._runtime = self._runtime, None
        return [] if runtime is None else runtime.close_after(primary)


def create_served_app() -> ServedApp:
    """ASGI factory (`uvicorn --factory policyops.api.serve:create_served_app`, lifespan on): validated
    configuration only; nothing is opened until lifespan startup. Raises `ServeConfigError`."""
    return ServedApp(load_config())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m policyops.api.serve",
                                     description="Serve the PolicyOps API locally (loopback only).")
    parser.add_argument("--host", default="127.0.0.1", help="loopback IP to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="TCP port (default 8000)")
    args = parser.parse_args(argv)
    if not _loopback(args.host):
        parser.error("--host must be a loopback IP (127.0.0.1 or ::1); public binding is deployment wiring")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        served = create_served_app()
    except ServeConfigError as error:
        print(f"policyops serve: {error}", file=sys.stderr)
        return 2
    config = uvicorn.Config(served, host=args.host, port=args.port, log_config=SERVE_LOG_CONFIG, lifespan="on",
                            ws="none", proxy_headers=False, server_header=False,
                            timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS)
    try:
        uvicorn.Server(config).run()  # exits with status 3 when startup (lifespan or bind) fails
    except BaseException as error:  # the release is attempted; this error, not a release failure, propagates
        _report_release(served.close_after(error))
        raise
    failures = served.close()  # e.g. the bind failed after lifespan startup had opened the runtime
    _report_release(failures)
    return 1 if failures else 0


def _report_release(failures: list[str]) -> None:
    if failures:
        print("policyops serve: release failed: " + "; ".join(failures), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
