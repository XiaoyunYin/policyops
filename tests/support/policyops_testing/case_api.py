"""HTTP harness for the case API on real PostgreSQL (T08).

It serves exactly the production composition, `create_app(build_auth_runtime(...))`, with the actual auth/app
runtime roles, the test-only fake issuer (allowed only with `env="test"`) and a controlled clock; it adds no
routes. Every response passing through `call` is checked against the committed OpenAPI document and recorded,
so the contract tests can also type-check real bodies against the generated TypeScript.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import json
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import httpx
from pydantic import SecretStr

from policyops.api.app import build_auth_runtime, create_app
from policyops.api.auth import AuthRuntime
from policyops.api.runs import StreamSettings, build_runs_runtime
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction
from policyops.persistence.records import Membership, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import DatabaseLeaseClock, FixedLeaseClock, LeaseClock
from policyops.runtime.outbox import OutboxDispatcher, build_dispatcher
from policyops.runtime.spec import UNCONFIGURED, RuntimeCatalog
from policyops.runtime.worker import Worker, build_worker
from policyops.settings import AuthSettings
from policyops_contracts.clock import FixedClock
from policyops_testing import openapi_check
from policyops_testing.app_database import AppDatabase
from policyops_testing.oidc_fake import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIssuer
from policyops_testing.openapi_check import Reply


ORIGIN = "http://127.0.0.1:8000"
START = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
SETTINGS = AuthSettings(env="test", public_origin=ORIGIN, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID,
                        oidc_client_secret=SecretStr(CLIENT_SECRET), session_absolute_ttl=timedelta(hours=8),
                        session_idle_ttl=timedelta(hours=4))
CSRF_COOKIE = "policyops_csrf_local"


@dataclass(frozen=True)
class Recorded:
    operation_id: str
    status: int
    body: Any


@dataclass
class CaseApi:
    db: AppDatabase
    clock: FixedClock
    fake: FakeIssuer
    runtime: AuthRuntime
    app: Any
    recorded: list[Recorded] = field(default_factory=list)

    # -- identities -----------------------------------------------------------------------------------------

    def workspace(self, label: str) -> UUID:
        workspace_id = uuid4()
        with transaction(self.db.engine(AUTH_RUNTIME)) as conn:
            repo.create_workspace(conn, Workspace(id=workspace_id, slug=f"{label}-{workspace_id.hex[:8]}",
                                                  name=label.title(), created_at=START))
        return workspace_id

    def principal(self, subject: str) -> UUID:
        with transaction(self.db.engine(AUTH_RUNTIME)) as conn:
            found = repo.find_principal(conn, ISSUER, subject)
        assert found is not None
        return found.id

    def grant(self, subject: str, workspace: UUID, role: str) -> UUID:
        membership = Membership(id=uuid4(), workspace_id=workspace, principal_id=self.principal(subject),
                                role=role, created_at=self.clock.now())  # type: ignore[arg-type]
        with transaction(self.db.engine(AUTH_RUNTIME)) as conn:  # trusted synthetic provisioning
            repo.add_membership(conn, membership)
        return membership.id

    def browser(self) -> TestClient:
        return TestClient(self.app, base_url=ORIGIN, follow_redirects=False)

    def signed_in(self, subject: str) -> TestClient:
        browser = self.browser()
        started = self.get(browser, "/api/v1/auth/login", "/api/v1/auth/login", return_to="/cases")
        code, state = self.fake.issue_code(started.headers["location"], self.clock.now(), code=f"code-{uuid4()}",
                                           sub=subject)
        done = self.get(browser, "/api/v1/auth/callback", "/api/v1/auth/callback", code=code, state=state)
        assert done.status_code == 303
        return browser

    def member(self, subject: str, workspace: UUID, role: str | None) -> TestClient:
        """A signed-in browser with `workspace` selected; `role=None` selects nothing (no membership)."""
        browser = self.signed_in(subject)
        if role is not None:
            self.grant(subject, workspace, role)
            selected = self.call(browser, "POST", "/api/v1/auth/workspace", "/api/v1/auth/workspace",
                                 json={"workspace_id": str(workspace)}, key=None)
            assert selected.status_code == 204
        return browser

    def clone(self, browser: TestClient) -> TestClient:
        """Another client with the same session and CSRF cookies (for concurrent requests)."""
        other = self.browser()
        for name, value in browser.cookies.items():
            other.cookies.set(name, value)
        return other

    # -- requests -------------------------------------------------------------------------------------------

    def call(self, browser: TestClient, method: str, path: str, template: str, *, json: Any = None,
             content: bytes | Iterator[bytes] | None = None, key: str | None = None, if_match: str | None = None,
             headers: dict[str, str] | None = None, csrf: bool = True) -> Reply:
        """One request, its response checked against the OpenAPI document (status, body, headers) and recorded."""
        sent: dict[str, str] = {}
        if method != "GET" and csrf:
            sent = {"Origin": ORIGIN, "X-CSRF-Token": browser.cookies.get(CSRF_COOKIE) or ""}
        if key is not None:
            sent["Idempotency-Key"] = key
        if if_match is not None:
            sent["If-Match"] = if_match
        sent.update(headers or {})
        response = browser.request(method, path, json=json, content=content, headers=sent)
        operation_id = openapi_check.check_response(response, method, template)
        self.recorded.append(Recorded(operation_id, response.status_code,
                                      response.json() if response.content else None))
        return response

    def create(self, browser: TestClient, key: str | None = None) -> Reply:
        return self.call(browser, "POST", "/api/v1/cases", "/api/v1/cases", json={"scenario": "retail"},
                         key=key or new_key())

    def patch(self, browser: TestClient, case_id: Any, status: str, if_match: str | None,
              key: str | None = None) -> Reply:
        return self.call(browser, "PATCH", f"/api/v1/cases/{case_id}", "/api/v1/cases/{case_id}",
                         json={"status": status}, key=key or new_key(), if_match=if_match)

    def post(self, browser: TestClient, case_id: Any, text: str, if_match: str | None, *,
             source: str = "staff_note", key: str | None = None) -> Reply:
        return self.call(browser, "POST", f"/api/v1/cases/{case_id}/messages", "/api/v1/cases/{case_id}/messages",
                         json={"source": source, "text": text}, key=key or new_key(), if_match=if_match)

    def get(self, browser: TestClient, path: str, template: str, **params: Any) -> Reply:
        return self.call(browser, "GET", path + (f"?{httpx.QueryParams(params)}" if params else ""), template)

    def case(self, browser: TestClient, case_id: Any) -> Reply:
        return self.get(browser, f"/api/v1/cases/{case_id}", "/api/v1/cases/{case_id}")

    # -- runs (T09) -----------------------------------------------------------------------------------------

    def start_run(self, browser: TestClient, case_id: Any, if_match: str | None, *, key: str | None = None,
                  json: Any = None) -> Reply:
        return self.call(browser, "POST", f"/api/v1/cases/{case_id}/runs", "/api/v1/cases/{case_id}/runs",
                         json={"mode": "workbench"} if json is None else json, key=key or new_key(),
                         if_match=if_match)

    def run(self, browser: TestClient, run_id: Any) -> Reply:
        return self.get(browser, f"/api/v1/runs/{run_id}", "/api/v1/runs/{run_id}")

    def cancel_run(self, browser: TestClient, run_id: Any, *, key: str | None = None) -> Reply:
        return self.call(browser, "POST", f"/api/v1/runs/{run_id}/cancel", "/api/v1/runs/{run_id}/cancel",
                         key=key or new_key())

    def worker(self, catalog: RuntimeCatalog, *, database_clock: bool = False, **options: Any) -> Worker:
        clock: LeaseClock = DatabaseLeaseClock() if database_clock else FixedLeaseClock(self.clock)
        return build_worker(env=SETTINGS.env, app_engine=self.runtime.app_engine,
                            discovery_engine=self.db.engine(WORKER_DISCOVERY, pool_size=4), clock=clock,
                            catalog=catalog, **options)

    def dispatcher(self, *, database_clock: bool = False) -> OutboxDispatcher:
        clock: LeaseClock = DatabaseLeaseClock() if database_clock else FixedLeaseClock(self.clock)
        return build_dispatcher(env=SETTINGS.env, app_engine=self.runtime.app_engine,
                                discovery_engine=self.db.engine(WORKER_DISCOVERY, pool_size=4), clock=clock)

    # -- inspection (superuser; bypasses RLS) ---------------------------------------------------------------

    def scalar(self, sql: str, *params: Any) -> Any:
        with self.db.superuser() as conn:
            row = conn.execute(sql, params).fetchone()
        return None if row is None else row[0]

    def rows(self, sql: str, *params: Any) -> list[tuple[Any, ...]]:
        with self.db.superuser() as conn:
            return list(conn.execute(sql, params).fetchall())


def new_key() -> str:
    return f"key-{uuid4().hex}"


def build(db: AppDatabase, *, pool_size: int = 12, wrap: Callable[[Any], Any] | None = None,
          catalog: RuntimeCatalog | None = None, database_clock: bool = False,
          stream: StreamSettings | None = None) -> CaseApi:
    """The served app. With `catalog`, the run API uses it (test-only specs are allowed: env is "test") and the
    controlled clock as lease clock, or the database clock with `database_clock`; without it, the production
    default (database clock, no installed runtime)."""
    clock = FixedClock(START)
    fake = FakeIssuer(redirect_uri=SETTINGS.redirect_uri)
    app_engine = db.engine(APP_RUNTIME, pool_size=pool_size)
    runtime = build_auth_runtime(SETTINGS, auth_engine=db.engine(AUTH_RUNTIME, pool_size=pool_size),
                                 app_engine=app_engine, clock=clock, oidc_transport=fake.transport)
    runs = None
    if catalog is not None or stream is not None:
        lease_clock: LeaseClock = DatabaseLeaseClock() if database_clock else FixedLeaseClock(clock)
        runs = build_runs_runtime(env=SETTINGS.env, app_engine=app_engine, ledger_clock=clock, clock=lease_clock,
                                  catalog=catalog or UNCONFIGURED, stream=stream)
    app = create_app(runtime, runs)
    return CaseApi(db, clock, fake, runtime, wrap(app) if wrap else app)


def body_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()
