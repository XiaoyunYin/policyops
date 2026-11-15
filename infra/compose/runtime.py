"""Container-only composition. Secrets are read from files, never argv or logged environment.

No test auth, provider client or model is installed by this launcher. Slice A seeds
identity/case only; Slice B supplies a fresh deterministic proposal through real services.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
import json
import logging.config
import os
from pathlib import Path
import signal
import sys
import threading
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid5

import httpx
import psycopg
from sqlalchemy import Engine, create_engine, text

from policyops.settings import REFUSED_LIBPQ_ENV, validate_sslrootcert


if TYPE_CHECKING:
    from policyops_contracts.seeds import CaseCustomerBinding


ROOT = Path(__file__).resolve().parents[2]
SECRETS = Path("/run/secrets")
HEARTBEAT = Path("/tmp/worker-heartbeat")  # noqa: S108 - private per-container mode-0700 tmpfs


def secret(name: str) -> str:
    value = (SECRETS / name).read_text(encoding="utf-8").strip()
    if len(value) < 24:
        raise ValueError("secret is too short")
    return value


def connect(role: str, database: str | None = None, *, autocommit: bool = False) -> psycopg.Connection[Any]:
    # All Compose roles, including maintenance helpers, use the same explicit pinned trust root.
    sslmode = os.environ.get("POLICYOPS_DB_SSLMODE")
    sslrootcert = validate_sslrootcert(os.environ.get("POLICYOPS_DB_SSLROOTCERT"))
    if sslmode != "verify-full" or sslrootcert is None or any(os.environ.get(name) for name in REFUSED_LIBPQ_ENV):
        raise ValueError("Compose database requires explicit verify-full and sslrootcert; ambient libpq refused")
    return psycopg.connect(host=os.environ["POLICYOPS_DB_HOST"],
        port=int(os.environ["POLICYOPS_DB_PORT"]), dbname=database or os.environ["POLICYOPS_DB_NAME"],
        user=role, password=secret(role), sslmode=sslmode, sslrootcert=sslrootcert,
        gssencmode="disable", require_auth="scram-sha-256",
        connect_timeout=3, options="-c timezone=UTC -c statement_timeout=5000 -c lock_timeout=1000 "
        "-c idle_in_transaction_session_timeout=5000", application_name="policyops-compose", autocommit=autocommit)


def engine(role: str) -> Engine:
    return create_engine("postgresql+psycopg://", creator=lambda: connect(role), pool_size=2, max_overflow=0,
                         pool_reset_on_return="rollback")


@contextmanager
def own_engine(role: str) -> Iterator[Engine]:
    db = engine(role)
    try:
        yield db
    except BaseException as primary:
        try:
            db.dispose()
        except BaseException as cleanup:
            primary.add_note(f"database release also failed: {type(cleanup).__name__}")
        raise
    else:
        db.dispose()


def demo() -> dict[str, Any]:
    result: dict[str, Any] = json.loads((ROOT / "infra/compose/demo.json").read_bytes())
    return result


def browser_case_id(run_id: UUID) -> UUID:
    """Server-owned local fixture identity: one independent case/simulator per scenario invocation."""
    return uuid5(UUID(demo()["workspace_id"]), "t38-browser:" + str(run_id))


def demo_bindings(app: Engine) -> tuple[CaseCustomerBinding, ...]:
    """Refresh only this local fixture's bindings; never derive customer authority from browser input."""
    from policyops.persistence.database import workspace_transaction
    from policyops_contracts.scalars import CaseScope
    from policyops_contracts.seeds import CaseCustomerBinding

    if os.environ.get("POLICYOPS_ENV") != "local":
        raise RuntimeError("demo bindings require the local Compose environment")
    config = demo()
    workspace = UUID(config["workspace_id"])
    bindings = [CaseCustomerBinding(scope=CaseScope(workspace_id=workspace, case_id=UUID(config["case_id"])),
        seed_id=config["seed_id"], user_id=config["customer_id"], bound_at=datetime(2026, 11, 1, tzinfo=UTC))]
    with workspace_transaction(app, workspace) as conn:
        rows = conn.execute(text(
            "SELECT r.id,c.id,c.created_at FROM app.runs r JOIN app.cases c ON c.id=r.case_id "
            "AND c.workspace_id=r.workspace_id WHERE c.workspace_id=:w AND c.scenario='retail' "
            "AND c.customer_user_id=:u AND c.created_by=:p ORDER BY r.id LIMIT 1001"
        ), {"w": workspace, "u": config["customer_id"], "p": uuid5(workspace, "alice")}).all()
    if len(rows) > 1000:
        raise RuntimeError("local browser fixture binding limit exceeded; use a fresh disposable stack")
    for run_id, case_id, created_at in rows:
        if case_id == browser_case_id(run_id):
            bindings.append(CaseCustomerBinding(scope=CaseScope(workspace_id=workspace, case_id=case_id),
                seed_id=config["seed_id"], user_id=config["customer_id"], bound_at=created_at))
    return tuple(bindings)


def dex_subject(user_id: str) -> str:
    """Dex v2 local-password connector subject: raw base64url protobuf (user_id=1, conn_id=2).

    demo.json's historical `subject` field is the configured staticPasswords.userID, not the OIDC `sub`.
    Keep this codec limited to our canonical 36-byte UUID fixtures; never derive identity from email.
    """
    raw = str(UUID(user_id)).encode("ascii")
    return base64.urlsafe_b64encode(b"\x0a\x24" + raw + b"\x12\x05local").decode("ascii").rstrip("=")


def bootstrap_app() -> None:
    from policyops.persistence import bootstrap
    from policyops.persistence.roles import ALL_ROLES, RolePassword

    database = os.environ["POLICYOPS_DB_NAME"]
    with connect("postgres", "postgres", autocommit=True) as conn:
        bootstrap.bootstrap(conn, database=database,
            passwords=[RolePassword(role, secret(role)) for role in ALL_ROLES],
            connect_database=lambda name: connect("postgres", name, autocommit=True))


def bootstrap_retail() -> None:
    from policyops.persistence.roles import scram_sha256_verifier
    from policyops_evals.retail_sim import bootstrap

    with connect("postgres", autocommit=True) as conn:
        bootstrap.provision(conn, os.environ["POLICYOPS_DB_NAME"],
                            {role: scram_sha256_verifier(secret(role)) for role in bootstrap.ROLES})


def migration(retail: bool) -> None:
    if retail:
        from policyops_evals.retail_sim import migrate as retail_migrate

        upgrade, current, head = retail_migrate.upgrade, retail_migrate.current, retail_migrate.head
    else:
        from policyops.persistence import migrate as app_migrate

        upgrade, current, head = app_migrate.upgrade, app_migrate.current, app_migrate.head
    role = "retail_migrator" if retail else "policyops_app_migrator"
    with own_engine(role) as db, db.connect() as conn:
        upgrade(conn)
        if current(conn) != head():
            raise RuntimeError("migration did not reach head")


def seed_demo() -> None:
    from policyops.persistence import repositories as repo
    from policyops.persistence.database import transaction, workspace_transaction
    from policyops.persistence.records import Membership, NewCase, Principal, Workspace

    config = demo()
    workspace, case = UUID(config["workspace_id"]), UUID(config["case_id"])
    now = datetime.now(UTC)
    with own_engine("policyops_auth_runtime") as auth, own_engine("policyops_app_runtime") as app:
        with transaction(auth) as conn:
            exists = conn.execute(text("SELECT 1 FROM identity.workspaces WHERE id=:id"), {"id": workspace}).first()
            if exists is None:
                repo.create_workspace(conn, Workspace(id=workspace, slug="compose-demo", name="Fictional retail demo",
                                                     created_at=now))
                for user in config["users"]:
                    principal = uuid5(workspace, user["name"])
                    repo.create_principal(conn, Principal(id=principal, issuer=os.environ["POLICYOPS_OIDC_ISSUER"],
                        subject=dex_subject(user["subject"]), display_name=user["name"].title() + " (fictional)",
                        created_at=now))
                    repo.add_membership(conn, Membership(id=uuid5(principal, "membership"), workspace_id=workspace,
                        principal_id=principal, role=user["role"], created_at=now))
        with workspace_transaction(app, workspace) as conn:
            exists = conn.execute(text("SELECT 1 FROM app.cases WHERE id=:id"), {"id": case}).first()
            if exists is None:
                repo.create_case(conn, NewCase(id=case, workspace_id=workspace, scenario="retail",
                    customer_user_id=config["customer_id"], created_by=uuid5(workspace, "alice"), created_at=now))


def get_health(origin: str, path: str) -> bool:
    try:
        with httpx.Client(trust_env=False, timeout=2, follow_redirects=False) as client:
            response = client.get(origin + path)
            if response.status_code != 200:
                return False
            body = response.json()
            return isinstance(body, dict) and body.get("status") == "ok"
    except (httpx.HTTPError, ValueError):
        return False


def readiness() -> tuple[int, dict[str, Any]]:
    checks = {}
    for role, label in (("policyops_auth_runtime", "auth_database"), ("policyops_app_runtime", "app_database")):
        try:
            with connect(role) as conn:
                checks[label] = conn.execute("SELECT current_user").fetchone() == (role,)
        except psycopg.Error:
            checks[label] = False
    checks["retail"] = get_health(os.environ["POLICYOPS_RETAIL_ORIGIN"], "/healthz")
    ok = all(checks.values())
    return (200 if ok else 503), {"status": "ok" if ok else "unavailable", "checks": checks}


class ReadyApp:
    """Add dependency readiness to the supported API ASGI/lifespan implementation."""

    def __init__(self, app: Any, probe: Callable[[], tuple[int, dict[str, Any]]] = readiness) -> None:
        self.app, self.probe, self.started = app, probe, False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        from starlette.concurrency import run_in_threadpool
        from starlette.responses import JSONResponse

        async def lifecycle(message: Any) -> None:
            if message["type"] == "lifespan.startup.complete":
                self.started = True
            if message["type"].startswith("lifespan.shutdown"):
                self.started = False
            await send(message)

        if scope["type"] == "http" and scope["path"] == "/api/v1/health/ready":
            if scope["method"] not in {"GET", "HEAD"}:
                await JSONResponse({"status": "method_not_allowed"}, status_code=405)(scope, receive, send)
                return
            status, body = await run_in_threadpool(self.probe) if self.started else (503, {"status": "starting"})
            await JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})(scope, receive, send)
            return
        await self.app(scope, receive, lifecycle if scope["type"] == "lifespan" else send)


def api() -> None:
    import uvicorn

    from policyops.api.serve import GRACEFUL_SHUTDOWN_SECONDS, SERVE_LOG_CONFIG, create_served_app

    # Existing settings stay unchanged; values are introduced only in this process after reading mounted files.
    for variable, name in (("POLICYOPS_DB_AUTH_PASSWORD", "policyops_auth_runtime"),
                           ("POLICYOPS_DB_APP_PASSWORD", "policyops_app_runtime"),
                           ("POLICYOPS_OIDC_CLIENT_SECRET", "client_secret")):
        os.environ[variable] = secret(name)
    served = create_served_app()
    try:
        from policyops.api.rate_limit import PublicRateLimit

        application = ReadyApp(served)
        public = os.environ.get("POLICYOPS_PUBLIC_RATE_LIMIT") == "1"
        uvicorn.run(PublicRateLimit(application) if public else application,
                    host="127.0.0.1", port=8000, lifespan="on", log_config=SERVE_LOG_CONFIG,
                    ws="none", proxy_headers=False, server_header=False,
                    timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS)
    except BaseException as primary:
        served.close_after(primary)
        raise
    else:
        if served.close():
            raise RuntimeError("API resource release failed")


def retail() -> None:
    import uvicorn

    from policyops.api.serve import SERVE_LOG_CONFIG
    from policyops_evals.retail_sim import auth, fixture
    from policyops_evals.retail_sim.app import create_app
    from policyops_evals.retail_sim.store import Store

    with own_engine("retail_runtime") as db:
        loaded = fixture.load(Path("/opt/fixture"))
        store = Store(db, loaded, fixture.upstream(loaded))
        store.require_head()
        uvicorn.run(create_app(store, auth.Key((SECRETS / "retail_key").read_bytes())),
                    host="0.0.0.0", port=8001, log_level="warning", access_log=False, server_header=False,  # noqa: S104 - internal network only
                    timeout_graceful_shutdown=10, log_config=SERVE_LOG_CONFIG)


def worker_loop(stop: threading.Event, passes: tuple[Callable[[], Any], ...], *, idle: float = 1) -> None:
    """One bounded batch per pass; SIGTERM stops discovery, in-flight writes keep their operation IDs."""
    while not stop.is_set():
        for run in passes:
            if stop.is_set():
                break
            run()
        HEARTBEAT.touch()
        stop.wait(idle)


def worker(*, execution_hooks: Any = None) -> None:
    from policyops.api.serve import SERVE_LOG_CONFIG
    from policyops.runtime.executions import build_execution_dispatcher
    from policyops.runtime.outbox import build_dispatcher
    from policyops.runtime.review import BoundScopes, build_review_runtime
    from policyops.runtime.worker import build_worker
    from policyops_contracts.retail_service import FIXTURE_SHA256

    if execution_hooks is not None and (os.environ.get("POLICYOPS_COMPOSE_DRILL") != "1"
                                        or os.environ.get("POLICYOPS_ENV") != "local"):
        raise RuntimeError("execution fault hooks require the explicit local Compose drill")
    logging.config.dictConfig(SERVE_LOG_CONFIG)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda _number, _frame: stop.set())
    signal.signal(signal.SIGINT, lambda _number, _frame: stop.set())
    with ExitStack() as owned:
        app = owned.enter_context(own_engine("policyops_app_runtime"))
        discovery = owned.enter_context(own_engine("policyops_worker_discovery"))
        review = build_review_runtime(env="local", app_engine=app, bindings=demo_bindings(app),
            fixture_sha256=FIXTURE_SHA256,
            retail_origin=os.environ["POLICYOPS_RETAIL_ORIGIN"], retail_key=(SECRETS / "retail_key").read_bytes())
        jobs = build_worker(env="local", app_engine=app, discovery_engine=discovery, review=review,
                            clock=review.executor.clock, batch=1)
        executions = build_execution_dispatcher(env="local" if execution_hooks is None else "test",
            app_engine=app, discovery_engine=discovery, hooks=execution_hooks,
            scopes=review.executor.scopes, retail=review.executor.retail, clock=review.executor.clock, batch=1)
        outbox = build_dispatcher(env="local", app_engine=app, discovery_engine=discovery, clock=review.executor.clock)
        def refresh_bindings() -> None:
            scopes = BoundScopes(app, demo_bindings(app), FIXTURE_SHA256)
            review.executor.scopes = executions.executor.scopes = scopes

        worker_loop(stop, (refresh_bindings, jobs.run_once, executions.dispatch_once, outbox.dispatch_once))


def main() -> int:
    commands: dict[str, Callable[[], Any]] = {
        "bootstrap-app": bootstrap_app, "bootstrap-retail": bootstrap_retail,
        "migrate-app": lambda: migration(False), "migrate-retail": lambda: migration(True),
        "seed-demo": seed_demo, "api": api, "retail": retail, "worker": worker,
    }
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=commands)
    args = parser.parse_args()
    try:
        result = commands[args.command]()
        return int(result is False)
    except Exception as error:
        # Third-party tracebacks can carry credentials. Emit only the exception type.
        print(json.dumps({"command": args.command, "error_type": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
