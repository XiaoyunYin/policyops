"""Container-only composition. Secrets are read from files, never argv or logged environment.

By default this launcher installs no investigation provider. The local live-agent
overlay explicitly enables a credential-free API catalog and a provider-backed worker.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from functools import partial
import json
import logging.config
import os
from pathlib import Path
import signal
import sys
import threading
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit
from uuid import UUID, uuid5

import httpx
import psycopg
from sqlalchemy import Connection, Engine, create_engine, text

from policyops.settings import REFUSED_LIBPQ_ENV, HelpdeskSettings, TelemetrySettings, validate_sslrootcert
from policyops.telemetry import configure


if TYPE_CHECKING:
    from policyops.persistence.runs import Run
    from policyops.runtime.spec import RuntimeCatalog
    from policyops.services.execution import Step
    from policyops_contracts.scalars import CaseScope
    from policyops_contracts.seeds import CaseCustomerBinding


ROOT = Path(__file__).resolve().parents[2]
SECRETS = Path("/run/secrets")
HEARTBEAT = Path("/tmp/worker-heartbeat")  # noqa: S108 - private per-container mode-0700 tmpfs
LOAD_MARKER = "/api/v1/health/n10-load"


def secret(name: str) -> str:
    value = (SECRETS / name).read_text(encoding="utf-8").strip()
    if len(value) < 24:
        raise ValueError("secret is too short")
    return value


def helpdesk_settings() -> HelpdeskSettings | None:
    if os.environ.get("POLICYOPS_ENV") == "local" and os.environ.get("POLICYOPS_HELPDESK") == "1":
        return HelpdeskSettings.from_secret_file(SECRETS / "helpdesk")
    return None


def live_agent_enabled() -> bool:
    if os.environ.get("POLICYOPS_LIVE_AGENT") != "1":
        return False
    from policyops.runtime.live_agent import LiveAgentRefused

    origin = urlsplit(os.environ.get("POLICYOPS_PUBLIC_ORIGIN", ""))
    if os.environ.get("POLICYOPS_ENV") != "local" or (origin.scheme, origin.hostname) != (
            "http", "127.0.0.1"):
        raise LiveAgentRefused("live_agent.local_only")
    return True


def api_catalog(app: Engine) -> RuntimeCatalog:
    from policyops.runtime.spec import UNCONFIGURED

    if not live_agent_enabled():
        return UNCONFIGURED
    from policyops.runtime.live_agent import INPUTS, catalog, inputs, selected_profile, unavailable_providers

    return catalog(env=os.environ["POLICYOPS_ENV"], engine=app, loaded=inputs(INPUTS),
                   workspace=UUID(demo()["workspace_id"]), providers=unavailable_providers,
                   profile=selected_profile())


def live_recording_root() -> Path | None:
    if os.environ.get("POLICYOPS_LIVE_AGENT_RECORD") != "1":
        return None
    if not live_agent_enabled():
        raise ValueError("transport recording requires the local live-agent overlay")
    from policyops.runtime.live_recording import tape_root

    return tape_root(Path("/recordings"), ROOT)


def summarize_live_agent(run_id: UUID) -> None:
    from policyops.orchestration.profile import InvestigationProfile, InvestigationProfileV2
    from policyops.persistence import runs
    from policyops.persistence.database import workspace_transaction
    from policyops.runtime.investigation import graph_digest
    from policyops.runtime.live_agent import configuration, timing
    from policyops.runtime.live_recording import measurements

    root = live_recording_root()
    if root is None:
        raise ValueError("transport recording overlay required")
    workspace = UUID(demo()["workspace_id"])
    with own_engine("policyops_app_runtime") as app, workspace_transaction(app, workspace) as connection:
        run = runs.get_run(connection, run_id)
        if run is None:
            raise ValueError("unknown live run")
        times = timing(connection, run)
    profiles = (InvestigationProfile.TOOL_CONTRACT_V1R1, InvestigationProfileV2.TOOL_CONTRACT_V2)
    profile = next((item for item in profiles if graph_digest(item) == run.graph_sha256), None)
    if profile is None:
        raise ValueError("run did not use a live-agent investigation graph")
    exchanges, tools = measurements(root, run.id)

    def elapsed(at: datetime | None) -> int | None:
        return None if at is None else int((at - times.created_at).total_seconds() * 1000)

    print(json.dumps({"run_id": str(run.id), "state": run.state, **times.model_dump(mode="json"),
        "profile": profile, "model": configuration().reservation("agent").model, "turn": 1,
        "first_model_exchange_at": exchanges[0].started_at.isoformat() if exchanges else None,
        "proposal_elapsed_ms": elapsed(times.proposal_persisted_at),
        "terminal_elapsed_ms": elapsed(times.investigation_ended_at),
        "provider_attempts": [{"phase": e.phase, "started_at": e.started_at.isoformat(), "elapsed_ms": e.elapsed_ms,
                               "status": e.status, "complete": e.complete,
                               "captured": e.request is not None and e.response is not None} for e in exchanges],
        "tool_steps": [item.model_dump(mode="json") for item in tools]}))


def live_agent_seed(*, create_case: bool) -> None:
    from policyops.runtime import live_agent

    if not live_agent_enabled():
        raise live_agent.LiveAgentRefused("live_agent.overlay_required")
    workspace = UUID(demo()["workspace_id"])
    providers = live_agent.provider_access(live_agent.provider_secret(SECRETS / "openai_api_key"))
    with own_engine("policyops_app_runtime") as app:
        generation = live_agent.prepare_corpus(
            app, workspace, live_agent.INPUTS, lambda: providers, live_agent.max_usd(),
            env=os.environ["POLICYOPS_ENV"])
        if create_case:
            case = live_agent.seed_case(app, workspace, retail_origin=os.environ["POLICYOPS_RETAIL_ORIGIN"],
                                       retail_key=(SECRETS / "retail_key").read_bytes())
            print(f"/cases/{case}")
        else:
            print(json.dumps({"generation_id": str(generation)}))


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
    from policyops_evals.retail_sim import bootstrap  # type: ignore[import-not-found]  # retail image only

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

    def __init__(self, app: Any, probe: Callable[[], tuple[int, dict[str, Any]]] = readiness,
                 load_token: str | None = None, load_limiter: bool = False) -> None:
        self.app, self.probe, self.started = app, probe, False
        self.load_token = load_token
        self.load_limiter = load_limiter

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        from starlette.concurrency import run_in_threadpool
        from starlette.responses import JSONResponse

        async def lifecycle(message: Any) -> None:
            if message["type"] == "lifespan.startup.complete":
                self.started = True
            if message["type"].startswith("lifespan.shutdown"):
                self.started = False
            await send(message)

        if self.load_token is not None and scope["type"] == "http" and scope["path"] == LOAD_MARKER:
            found = scope["method"] == "GET"
            await JSONResponse({"load_token": self.load_token, "limiter": self.load_limiter}
                               if found else {"detail": "Not Found"},
                               status_code=200 if found else 404,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)
            return
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
    helpdesk = helpdesk_settings()
    if live_agent_enabled():
        from policyops.runtime.live_agent import usage_router

        served = create_served_app(helpdesk=helpdesk, catalog=api_catalog,
                                   local_router=usage_router(UUID(demo()["workspace_id"])))
    else:
        served = create_served_app() if helpdesk is None else create_served_app(helpdesk=helpdesk)
    try:
        from policyops.api.rate_limit import PublicRateLimit

        token = secret("n10_load_token") if (SECRETS / "n10_load_token").is_file() else None
        public = os.environ.get("POLICYOPS_PUBLIC_RATE_LIMIT") == "1"
        application = ReadyApp(served, load_token=token, load_limiter=public)
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
    from policyops_evals.retail_sim.app import create_app  # type: ignore[import-not-found]  # retail image only
    from policyops_evals.retail_sim.store import Store  # type: ignore[import-not-found]  # retail image only

    with own_engine("retail_runtime") as db:
        loaded = fixture.load(Path("/opt/fixture"))
        store = Store(db, loaded, fixture.upstream(loaded))
        store.require_head()
        uvicorn.run(create_app(store, auth.Key((SECRETS / "retail_key").read_bytes())),
                    host="0.0.0.0", port=8001, log_level="warning", access_log=False, server_header=False,  # noqa: S104 - internal network only
                    timeout_graceful_shutdown=10, log_config=SERVE_LOG_CONFIG)


def worker_loop(stop: threading.Event, passes: tuple[Callable[[], int | list[Step] | None], ...], *,
                idle: float = 1, drain: bool = False) -> None:
    """One bounded batch per pass; SIGTERM stops discovery, in-flight writes keep their operation IDs."""
    busy_passes = 0
    while not stop.is_set():
        busy = False
        for run in passes:
            if stop.is_set():
                break
            result = run()
            if drain:
                busy |= result > 0 if isinstance(result, int) else bool(result)
        HEARTBEAT.touch()
        if drain and stop.is_set():
            break
        if not busy:
            busy_passes = 0
            stop.wait(idle)
        else:
            busy_passes += 1
            if busy_passes == 50:
                busy_passes = 0
                stop.wait(0.05)


def worker(*, execution_hooks: Any = None) -> None:
    from policyops.api.serve import SERVE_LOG_CONFIG
    from policyops.runtime.executions import build_execution_dispatcher
    from policyops.runtime.helpdesk import HelpdeskWorker
    from policyops.runtime.outbox import build_dispatcher
    from policyops.runtime.review import BoundScopes, build_review_runtime
    from policyops.runtime.spec import UNCONFIGURED
    from policyops.runtime.worker import build_worker
    from policyops_contracts.retail_service import FIXTURE_SHA256

    live = live_agent_enabled()
    providers = None
    if live:
        from policyops.runtime.live_agent import provider_access, provider_secret

        providers = provider_access(provider_secret(SECRETS / "openai_api_key"))

    drain_setting = os.environ.get("POLICYOPS_WORKER_DRAIN", "0")
    if drain_setting not in {"0", "1"}:
        raise ValueError("POLICYOPS_WORKER_DRAIN must be 0 or 1")
    drain = drain_setting == "1"
    recording_root = live_recording_root()
    if execution_hooks is not None and (os.environ.get("POLICYOPS_COMPOSE_DRILL") != "1"
                                        or os.environ.get("POLICYOPS_ENV") != "local"):
        raise RuntimeError("execution fault hooks require the explicit local Compose drill")
    logging.config.dictConfig(SERVE_LOG_CONFIG)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda _number, _frame: stop.set())
    signal.signal(signal.SIGINT, lambda _number, _frame: stop.set())
    with ExitStack() as owned:
        telemetry = configure(TelemetrySettings(), role="worker")
        if telemetry is not None:
            owned.callback(telemetry.close)
        app = owned.enter_context(own_engine("policyops_app_runtime"))
        discovery = owned.enter_context(own_engine("policyops_worker_discovery"))
        helpdesk = helpdesk_settings()
        retail_key = (SECRETS / "retail_key").read_bytes()
        retail_origin = os.environ["POLICYOPS_RETAIL_ORIGIN"]
        env = os.environ["POLICYOPS_ENV"] if live else "local"
        review = build_review_runtime(env=env, app_engine=app, bindings=demo_bindings(app),
            fixture_sha256=FIXTURE_SHA256,
            retail_origin=retail_origin, retail_key=retail_key, helpdesk_settings=helpdesk)
        catalog = UNCONFIGURED
        refusal: Callable[[Connection, Run], str | None] | None = None
        binding: Callable[[Connection, CaseScope], CaseCustomerBinding | None] | None = None
        if providers is not None:
            from policyops.runtime import live_agent
            from policyops.runtime.live_recording import bind_recording

            workspace = UUID(demo()["workspace_id"])
            aggregate, worst = live_agent.max_usd(), live_agent.preflight(live_agent.configuration())
            loaded = live_agent.inputs(live_agent.INPUTS)
            catalog = live_agent.catalog(
                env=env, engine=app, loaded=loaded, workspace=workspace, providers=lambda: providers,
                retail_origin=retail_origin, retail_key=retail_key, clock=review.executor.clock, aggregate=aggregate,
                profile=live_agent.selected_profile(),
                record_run=partial(bind_recording, recording_root, providers) if recording_root is not None else None)
            refusal = partial(live_agent.claim_refusal, workspace=workspace, aggregate=aggregate,
                              worst=worst, vocab=loaded[1])
            binding = partial(live_agent.case_binding, workspace=workspace)
            print(json.dumps({"event": "live_agent.preflight", "run_max_usd": str(worst),
                              "workspace_max_usd": str(aggregate)}), flush=True)
        jobs = build_worker(env=env, app_engine=app, discovery_engine=discovery, review=review,
                            clock=review.executor.clock, batch=1, catalog=catalog, claim_refusal=refusal)
        executions = build_execution_dispatcher(env="local" if execution_hooks is None else "test",
            app_engine=app, discovery_engine=discovery, hooks=execution_hooks,
            scopes=review.executor.scopes, retail=review.executor.retail, clock=review.executor.clock, batch=1)
        outbox = build_dispatcher(env="local", app_engine=app, discovery_engine=discovery, clock=review.executor.clock)
        def refresh_bindings() -> None:
            scopes = BoundScopes(app, demo_bindings(app), FIXTURE_SHA256, case_binding=binding)
            review.executor.scopes = executions.executor.scopes = scopes

        passes: tuple[Callable[[], int | list[Step] | None], ...] = (
            refresh_bindings, jobs.run_once, executions.dispatch_once, outbox.dispatch_once,
        )
        if helpdesk is not None:
            connector = HelpdeskWorker(env="local", app=app, discovery=discovery, settings=helpdesk)
            passes = (*passes, connector.run_once)
        worker_loop(stop, passes, drain=drain)


def main() -> int:
    commands: dict[str, Callable[[], Any]] = {
        "bootstrap-app": bootstrap_app, "bootstrap-retail": bootstrap_retail,
        "migrate-app": lambda: migration(False), "migrate-retail": lambda: migration(True),
        "seed-demo": seed_demo, "api": api, "retail": retail, "worker": worker,
        "ingest-live-agent": partial(live_agent_seed, create_case=False),
        "seed-live-agent": partial(live_agent_seed, create_case=True),
        "summarize-live-agent": lambda: summarize_live_agent(args.run),
    }
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=commands)
    parser.add_argument("--run", type=UUID)
    args = parser.parse_args()
    if (args.run is not None) != (args.command == "summarize-live-agent"):
        parser.error("--run is required for summarize-live-agent only")
    try:
        result = commands[args.command]()
        return int(result is False)
    except Exception as error:
        # Third-party tracebacks can carry credentials. Emit only the exception type.
        details = {"command": args.command, "error_type": type(error).__name__}
        if os.environ.get("POLICYOPS_LIVE_AGENT") == "1" or args.command.endswith("-live-agent"):
            from policyops.runtime.live_agent import LiveAgentRefused

            if isinstance(error, LiveAgentRefused):
                details["category"] = str(error)
        print(json.dumps(details), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
