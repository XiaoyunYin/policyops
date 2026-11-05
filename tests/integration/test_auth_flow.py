"""Authentication and authorization end to end on real PostgreSQL (actual auth/app runtime roles) with the
test-only fake issuer and a controlled clock: login state, sessions, CSRF/origin, membership and role/resource."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
import pytest
from sqlalchemy import text

from policyops.api.app import build_auth_runtime, create_app
from policyops.api.auth import AuthRuntime, require_action
from policyops.auth.service import Authorized
from policyops.domain.roles import PERMISSIONS, Action, Role
from policyops.persistence import repositories as repo
from policyops.persistence.database import RuntimeRoleError, transaction, verify_runtime_role, workspace_transaction
from policyops.persistence.records import Membership, NewCase, Workspace
from policyops.persistence.roles import APP_MIGRATOR, APP_RUNTIME, AUTH_RUNTIME
from policyops.settings import AuthSettings
from policyops_contracts.clock import FixedClock
from policyops_testing.app_database import AppCluster, AppDatabase
from policyops_testing.oidc_fake import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIssuer


pytestmark = pytest.mark.postgres
ORIGIN = "http://127.0.0.1:8000"
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SETTINGS = AuthSettings(env="test", public_origin=ORIGIN, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID,
                        oidc_client_secret=SecretStr(CLIENT_SECRET), session_absolute_ttl=timedelta(hours=2),
                        session_idle_ttl=timedelta(minutes=30))
SESSION, CSRF, LOGIN = SETTINGS.session_cookie, "policyops_csrf_local", SETTINGS.login_cookie


@pytest.fixture(scope="module")
def auth_db(app_cluster: AppCluster) -> Iterator[AppDatabase]:
    database = app_cluster.create_database("auth")
    database.upgrade()
    yield database
    database.dispose()


@dataclass
class Harness:
    db: AppDatabase
    clock: FixedClock
    fake: FakeIssuer
    runtime: AuthRuntime
    app: Any

    def browser(self) -> TestClient:
        return TestClient(self.app, base_url=ORIGIN, follow_redirects=False)

    def login(self, browser: TestClient, subject: str, **claims: Any) -> Any:
        started = browser.get("/api/v1/auth/login", params={"return_to": "/cases"})
        assert started.status_code == 302 and started.cookies.get(LOGIN)
        code, state = self.fake.issue_code(started.headers["location"], self.clock.now(), code=f"code-{uuid4()}",
                                           sub=subject, **claims)
        return browser.get("/api/v1/auth/callback", params={"code": code, "state": state})

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

    def workspace(self, label: str) -> UUID:
        workspace_id = uuid4()
        with transaction(self.db.engine(AUTH_RUNTIME)) as conn:
            repo.create_workspace(conn, Workspace(id=workspace_id, slug=f"{label}-{workspace_id.hex[:8]}",
                                                  name=label.title(), created_at=START))
        return workspace_id


def unsafe(browser: TestClient, path: str, json: Any = None, **headers: str) -> Any:
    sent = {"Origin": ORIGIN, "X-CSRF-Token": browser.cookies.get(CSRF) or "", **headers}
    return browser.post(path, json=json, headers={k: v for k, v in sent.items() if v != "-"})


@pytest.fixture
def harness(auth_db: AppDatabase) -> Harness:
    clock = FixedClock(START)
    fake = FakeIssuer(redirect_uri=SETTINGS.redirect_uri)
    runtime = build_auth_runtime(SETTINGS, auth_engine=auth_db.engine(AUTH_RUNTIME),
                                 app_engine=auth_db.engine(APP_RUNTIME), clock=clock, oidc_transport=fake.transport)
    app = create_app(runtime)

    @app.get("/api/v1/test/cases/{case_id}")
    def read_case(case_id: UUID,
                  authorized: Annotated[Authorized, Depends(require_action(Action.VIEW_CASE))]) -> dict[str, str]:
        with workspace_transaction(runtime.app_engine, authorized.workspace_id) as conn:
            case = repo.get_case(conn, case_id)
        if case is None:
            from policyops.auth.service import AuthError
            from policyops_contracts.errors import ErrorCode

            raise AuthError(404, ErrorCode.NOT_FOUND, "No such case.", "resource.case")
        return {"case_id": str(case.id)}

    for action in Action:
        app.add_api_route(f"/api/v1/test/actions/{action.value}", lambda: {"ok": True},
                          dependencies=[Depends(require_action(action))], methods=["GET"])
    return Harness(auth_db, clock, fake, runtime, app)


# -- login and sessions ---------------------------------------------------------------------------------------

def test_login_select_workspace_and_logout(harness: Harness) -> None:
    w1 = harness.workspace("alpha")
    browser = harness.browser()
    done = harness.login(browser, "subject-flow")
    assert done.status_code == 303 and done.headers["location"] == "/cases"
    assert done.headers["cache-control"] == "no-store" and done.headers["referrer-policy"] == "no-referrer"
    assert not browser.cookies.get(LOGIN)  # the binding cookie is cleared
    me = browser.get("/api/v1/me").json()
    assert me["workspace_id"] is None and me["workspaces"] == [] and me["roles"] == []  # no implicit membership
    denied = browser.get("/api/v1/workspace/members")
    assert denied.status_code == 403 and denied.json()["rule_id"] == "auth.workspace_required"
    assert unsafe(browser, "/api/v1/auth/workspace", {"workspace_id": str(w1)}).status_code == 404
    harness.grant("subject-flow", w1, "admin")
    first_cookie = browser.cookies.get(SESSION)
    assert unsafe(browser, "/api/v1/auth/workspace", {"workspace_id": str(w1)}).status_code == 204
    rotated = browser.cookies.get(SESSION)
    assert rotated and rotated != first_cookie
    assert first_cookie is not None
    stale = TestClient(harness.app, base_url=ORIGIN, cookies={SESSION: first_cookie})
    assert stale.get("/api/v1/me").status_code == 401  # rotation revoked the old session
    me = browser.get("/api/v1/me").json()
    assert me["workspace_id"] == str(w1) and me["roles"] == ["admin"]
    assert browser.get("/api/v1/workspace/members").status_code == 200
    old_csrf = browser.cookies.get(CSRF)
    assert unsafe(browser, "/api/v1/auth/logout").status_code == 204
    assert not browser.cookies.get(SESSION)
    assert old_csrf is not None
    replay = TestClient(harness.app, base_url=ORIGIN, cookies={SESSION: rotated, CSRF: old_csrf})
    assert replay.get("/api/v1/me").status_code == 401
    assert unsafe(replay, "/api/v1/auth/logout").status_code == 401


def test_login_state_is_browser_bound_single_use_and_expiring(harness: Harness) -> None:
    a, b = harness.browser(), harness.browser()
    started = a.get("/api/v1/auth/login")
    code, state = harness.fake.issue_code(started.headers["location"], harness.clock.now(), code="c-a", sub="s-a")
    b.get("/api/v1/auth/login")  # B has its own binding cookie
    assert b.get("/api/v1/auth/callback", params={"code": code, "state": state}).status_code == 401  # A's state
    no_cookie = harness.browser()
    assert no_cookie.get("/api/v1/auth/callback", params={"code": code, "state": state}).status_code == 401
    assert a.get("/api/v1/auth/callback", params={"code": code, "state": state}).status_code == 303
    again = harness.browser()
    again.cookies.set(LOGIN, started.cookies.get(LOGIN) or "")
    replayed = again.get("/api/v1/auth/callback", params={"code": code, "state": state})
    assert replayed.status_code == 401 and replayed.json()["rule_id"] == "auth.login_state"
    late = harness.browser()
    started = late.get("/api/v1/auth/login")
    code, state = harness.fake.issue_code(started.headers["location"], harness.clock.now(), code="c-late")
    harness.clock.advance(SETTINGS.login_request_ttl)
    assert late.get("/api/v1/auth/callback", params={"code": code, "state": state}).status_code == 401
    denied = harness.browser()
    started = denied.get("/api/v1/auth/login")
    _, state = harness.fake.issue_code(started.headers["location"], harness.clock.now(), code="c-denied")
    refused = denied.get("/api/v1/auth/callback", params={"error": "access_denied", "state": state})
    assert refused.status_code == 401 and refused.json()["rule_id"] == "auth.login_denied"
    assert denied.get("/api/v1/auth/callback", params={"code": "c-denied", "state": state}).status_code == 401


def test_a_failed_id_token_creates_no_principal_or_session(harness: Harness) -> None:
    browser = harness.browser()
    with harness.db.superuser() as conn:
        before = conn.execute("SELECT count(*) FROM identity.sessions").fetchone()
    response = harness.login(browser, "subject-bad", nonce="forged-nonce")
    assert response.status_code == 401 and response.json()["rule_id"] == "auth.id_token"
    body = response.text
    assert "forged-nonce" not in body and "code-" not in body and not browser.cookies.get(SESSION)
    with harness.db.superuser() as conn:
        assert conn.execute("SELECT count(*) FROM identity.sessions").fetchone() == before
        assert conn.execute("SELECT count(*) FROM identity.principals WHERE subject = 'subject-bad'").fetchone() == (0,)


@pytest.mark.parametrize("target", ["//evil.example", "https://evil.example/", "/../admin", "/a?b=1", "/a/", "cases",
                                    "/a%2F..", "/" + "a" * 201])
def test_only_plain_same_origin_return_paths_are_accepted(harness: Harness, target: str) -> None:
    response = harness.browser().get("/api/v1/auth/login", params={"return_to": target})
    assert response.status_code == 422 and response.json()["rule_id"] == "auth.return_to"


def test_idle_and_absolute_expiry_and_rotation_never_extends_lifetime(harness: Harness) -> None:
    w1 = harness.workspace("expiry")
    idle = harness.browser()
    harness.login(idle, "subject-idle")
    harness.clock.advance(SETTINGS.session_idle_ttl)
    assert idle.get("/api/v1/me").status_code == 401
    active = harness.browser()
    harness.login(active, "subject-active")
    harness.grant("subject-active", w1, "analyst")
    for _ in range(5):  # active use keeps the idle window open...
        harness.clock.advance(timedelta(minutes=20))
        assert active.get("/api/v1/me").status_code == 200
    assert unsafe(active, "/api/v1/auth/workspace", {"workspace_id": str(w1)}).status_code == 204  # rotation
    harness.clock.advance(timedelta(minutes=19, seconds=59))
    assert active.get("/api/v1/me").status_code == 200
    harness.clock.advance(timedelta(seconds=1))  # ...but not past the original absolute expiry (2 h)
    assert active.get("/api/v1/me").status_code == 401


def test_session_fixation_a_planted_cookie_never_becomes_a_session(harness: Harness) -> None:
    planted = "attacker-chosen-" + "x" * 30
    browser = harness.browser()
    browser.cookies.set(SESSION, planted, domain="127.0.0.1", path="/")  # as a browser would hold it
    assert browser.get("/api/v1/me").status_code == 401
    assert harness.login(browser, "subject-fixation").status_code == 303
    issued = browser.cookies.get(SESSION)
    assert issued and issued != planted
    attacker = TestClient(harness.app, base_url=ORIGIN, cookies={SESSION: planted})
    assert attacker.get("/api/v1/me").status_code == 401
    second = harness.browser()
    harness.login(second, "subject-fixation")  # every login gets a new session, even for the same principal
    assert second.cookies.get(SESSION) != issued


@pytest.mark.parametrize(("headers", "rule"), [
    ({"X-CSRF-Token": "-"}, "auth.csrf"), ({"X-CSRF-Token": "wrong-token"}, "auth.csrf"),
    ({"Origin": "http://evil.example"}, "auth.origin"), ({"Origin": "http://127.0.0.1:8001"}, "auth.origin"),
    ({"Origin": "null"}, "auth.origin"), ({"Origin": "-"}, "auth.origin"),
    ({"Origin": "-", "Referer": "http://evil.example/x"}, "auth.origin"),
    ({"Origin": "-", "Referer": "http://127.0.0.1:8000.evil.example/"}, "auth.origin"),
])
def test_unsafe_requests_need_exact_origin_and_the_session_csrf_token(harness: Harness, headers: dict[str, str],
                                                                      rule: str) -> None:
    browser = harness.browser()
    harness.login(browser, f"subject-csrf-{uuid4().hex[:6]}")
    response = unsafe(browser, "/api/v1/auth/logout", **headers)
    assert response.status_code == 403 and response.json()["rule_id"] == rule
    assert browser.get("/api/v1/me").status_code == 200  # not logged out


def test_csrf_token_of_another_session_is_refused_and_referer_fallback_works(harness: Harness) -> None:
    a, b = harness.browser(), harness.browser()
    harness.login(a, "subject-csrf-a")
    harness.login(b, "subject-csrf-b")
    response = unsafe(a, "/api/v1/auth/logout", **{"X-CSRF-Token": b.cookies.get(CSRF) or ""})
    assert response.status_code == 403
    assert unsafe(a, "/api/v1/auth/logout", Origin="-", Referer=ORIGIN + "/cases").status_code == 204


# -- membership, roles and resources ---------------------------------------------------------------------------

def _member(harness: Harness, subject: str, workspace: UUID, role: str) -> tuple[TestClient, UUID]:
    browser = harness.browser()
    harness.login(browser, subject)
    membership = harness.grant(subject, workspace, role)
    assert unsafe(browser, "/api/v1/auth/workspace", {"workspace_id": str(workspace)}).status_code == 204
    return browser, membership


def test_role_action_matrix_through_the_real_dependencies(harness: Harness) -> None:
    workspace = harness.workspace("matrix")
    for role in Role:
        browser, _ = _member(harness, f"subject-{role.value}-{uuid4().hex[:6]}", workspace, role.value)
        for action in Action:
            status = browser.get(f"/api/v1/test/actions/{action.value}").status_code
            assert status == (200 if action in PERMISSIONS[role] else 403), (role, action)
    admin, _ = _member(harness, f"subject-admin-{uuid4().hex[:6]}", workspace, "admin")
    assert admin.get(f"/api/v1/test/actions/{Action.DECIDE_PROPOSAL.value}").status_code == 403  # not a reviewer


def test_membership_revocation_is_immediate_and_scoped(harness: Harness) -> None:
    w1, w2 = harness.workspace("revoke-one"), harness.workspace("revoke-two")
    admin, _ = _member(harness, "subject-admin-revoke", w1, "admin")
    analyst, analyst_membership = _member(harness, "subject-analyst-revoke", w1, "analyst")
    _, other_workspace_membership = _member(harness, "subject-other-revoke", w2, "analyst")
    assert analyst.get(f"/api/v1/test/actions/{Action.VIEW_CASE.value}").status_code == 200
    assert analyst.get("/api/v1/workspace/members").status_code == 403  # not an admin
    assert unsafe(analyst, f"/api/v1/workspace/members/{analyst_membership}/revoke").status_code == 403
    cross = unsafe(admin, f"/api/v1/workspace/members/{other_workspace_membership}/revoke")
    assert cross.status_code == 404  # another workspace's membership is invisible
    assert unsafe(admin, f"/api/v1/workspace/members/{analyst_membership}/revoke").status_code == 204
    revoked = analyst.get(f"/api/v1/test/actions/{Action.VIEW_CASE.value}")
    assert revoked.status_code == 403 and revoked.json()["rule_id"] == "auth.membership"  # same session, at once
    assert unsafe(admin, f"/api/v1/workspace/members/{analyst_membership}/revoke").status_code == 404  # already
    listed = admin.get("/api/v1/workspace/members").json()
    assert {m["membership_id"]: m["active"] for m in listed}[str(analyst_membership)] is False


def test_resources_of_another_workspace_are_not_found(harness: Harness) -> None:
    w1, w2 = harness.workspace("res-one"), harness.workspace("res-two")
    viewer, _ = _member(harness, "subject-viewer", w1, "auditor")
    own, foreign = uuid4(), uuid4()
    for workspace, case_id in ((w1, own), (w2, foreign)):
        with workspace_transaction(harness.db.engine(APP_RUNTIME), workspace) as conn:
            repo.create_case(conn, NewCase(id=case_id, workspace_id=workspace, scenario="retail",
                                           customer_user_id=None, created_by=None, created_at=START))
    assert viewer.get(f"/api/v1/test/cases/{own}").status_code == 200
    assert viewer.get(f"/api/v1/test/cases/{foreign}").status_code == 404


def test_only_digests_of_browser_tokens_are_stored(harness: Harness) -> None:
    browser = harness.browser()
    started = browser.get("/api/v1/auth/login")
    binding = started.cookies.get(LOGIN)
    code, state = harness.fake.issue_code(started.headers["location"], harness.clock.now(), code="c-digest",
                                          sub="subject-digest")
    browser.get("/api/v1/auth/callback", params={"code": code, "state": state})
    raw = [binding, state, browser.cookies.get(SESSION), browser.cookies.get(CSRF)]
    assert all(raw)
    with harness.db.superuser() as conn:
        dump = "\n".join(str(row) for table in ("identity.login_requests", "identity.sessions")
                         for row in conn.execute(f"SELECT * FROM {table}").fetchall())  # noqa: S608 - fixed names
    assert not [value for value in raw if value and value in dump]


def test_runtime_wiring_refuses_wrong_or_privileged_database_users(harness: Harness) -> None:
    db = harness.db
    verify_runtime_role(db.engine(AUTH_RUNTIME), AUTH_RUNTIME)
    verify_runtime_role(db.engine(APP_RUNTIME), APP_RUNTIME)
    for engine, expected in ((db.engine(APP_MIGRATOR), APP_RUNTIME), (db.engine(APP_RUNTIME), AUTH_RUNTIME)):
        with pytest.raises(RuntimeRoleError, match="authenticates as"):
            verify_runtime_role(engine, expected)
    with pytest.raises(RuntimeRoleError, match="not a runtime role"):
        verify_runtime_role(db.engine(APP_MIGRATOR), APP_MIGRATOR)
    with pytest.raises(RuntimeRoleError):
        build_auth_runtime(SETTINGS, auth_engine=db.engine(APP_MIGRATOR), app_engine=db.engine(APP_RUNTIME),
                           clock=harness.clock)
    with db.superuser() as conn:  # a runtime role that gained a privilege is refused too
        conn.execute("ALTER ROLE policyops_auth_runtime CREATEDB")
        try:
            with pytest.raises(RuntimeRoleError, match="privileges"):
                verify_runtime_role(db.engine(AUTH_RUNTIME), AUTH_RUNTIME)
        finally:
            conn.execute("ALTER ROLE policyops_auth_runtime NOCREATEDB")
    with transaction(db.engine(AUTH_RUNTIME)) as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == AUTH_RUNTIME


def test_the_database_also_refuses_dot_segment_return_paths(harness: Harness) -> None:
    from psycopg import errors

    with harness.db.superuser() as conn:
        for path in ("/../admin", "/a/./b", "/.."):
            with pytest.raises(errors.CheckViolation, match="login_requests_return_path"):
                conn.execute("INSERT INTO identity.login_requests (id, binding_sha256, state_sha256, nonce_sha256, "
                             "code_verifier, return_to, created_at, expires_at) VALUES (gen_random_uuid(), "
                             "md5(random()::text) || md5(random()::text), md5(random()::text) || md5(random()::text), "
                             "repeat('a', 64), repeat('v', 43), %s, now(), now() + interval '1 minute')", (path,))


# -- races --------------------------------------------------------------------------------------------------

def _race(workers: int, fn: Any) -> list[Any]:
    from concurrent.futures import ThreadPoolExecutor
    import threading

    barrier = threading.Barrier(workers)

    def one(index: int) -> Any:
        barrier.wait(timeout=30)
        try:
            return fn(index)
        except Exception as exc:  # collected for assertions
            return exc

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, range(workers)))


def test_concurrent_callbacks_for_one_login_create_exactly_one_session(harness: Harness) -> None:
    from policyops.auth.service import AuthError, IssuedSession

    service = harness.runtime.service
    start = service.begin_login("/")
    code, state = harness.fake.issue_code(start.redirect_url, harness.clock.now(), code="c-race",
                                          sub="subject-race")
    results = _race(6, lambda i: service.complete_login(binding=start.login_cookie, state=state, code=code,
                                                       error=None))
    issued = [r for r in results if isinstance(r, IssuedSession)]
    assert len(issued) == 1 and all(isinstance(r, AuthError) and r.rule_id == "auth.login_state"
                                    for r in results if not isinstance(r, IssuedSession))
    with harness.db.superuser() as conn:
        sessions = conn.execute("SELECT count(*) FROM identity.sessions s JOIN identity.principals p "
                                "ON p.id = s.principal_id WHERE p.subject = 'subject-race'").fetchone()
    assert sessions == (1,)


def test_concurrent_rotation_and_logout_of_one_session_leave_one_live_session(harness: Harness) -> None:
    from policyops.auth.service import AuthError, IssuedSession

    workspace = harness.workspace("rotation-race")
    browser = harness.browser()
    harness.login(browser, "subject-rotate")
    harness.grant("subject-rotate", workspace, "analyst")
    service = harness.runtime.service
    session = service.resolve(browser.cookies.get(SESSION))
    results = _race(6, lambda i: service.select_workspace(session, workspace))
    winners = [r for r in results if isinstance(r, IssuedSession)]
    assert len(winners) == 1
    assert all(isinstance(r, AuthError) and r.status == 401 for r in results if not isinstance(r, IssuedSession))
    with harness.db.superuser() as conn:
        live = conn.execute("SELECT count(*) FROM identity.sessions s JOIN identity.principals p ON p.id = "
                            "s.principal_id WHERE p.subject = 'subject-rotate' AND s.revoked_at IS NULL").fetchone()
    assert live == (1,)  # the old session is revoked exactly once; one rotated session exists
    rotated = service.resolve(winners[0].cookie)
    outcome = _race(2, lambda i: service.logout(rotated) if i == 0 else service.select_workspace(rotated, workspace))
    with harness.db.superuser() as conn:
        live = conn.execute("SELECT count(*) FROM identity.sessions s JOIN identity.principals p ON p.id = "
                            "s.principal_id WHERE p.subject = 'subject-rotate' AND s.revoked_at IS NULL").fetchone()
    rotated_again = isinstance(outcome[1], IssuedSession)
    assert live == ((1,) if rotated_again else (0,))  # never two live sessions from one, never a resurrection
    assert outcome[0] is None  # logout itself never fails


# -- C2 regressions (review findings F3/F4/N1 on pre1) ----------------------------------------------------------

def _masked_engine(db: AppDatabase, statement: str) -> Any:
    """A superuser login made to look like the auth runtime role (the reviewer's F4 trigger)."""
    from policyops.persistence.database import make_engine

    def connect() -> Any:
        conn = db.server.connect("postgres", db.name)
        conn.execute(statement)
        conn.commit()  # SET is transactional; committed, it lasts for the session
        return conn

    return make_engine(connect, pool_size=1)


@pytest.mark.parametrize("statement", ["SET ROLE policyops_auth_runtime",
                                       "SET SESSION AUTHORIZATION policyops_auth_runtime"])
def test_masked_superuser_logins_are_refused(harness: Harness, statement: str) -> None:
    engine = _masked_engine(harness.db, statement)
    try:
        with engine.connect() as conn:  # the SQL identities look right...
            identities = conn.execute(text("SELECT session_user, current_user")).one()
            conn.rollback()
        assert identities[1] == AUTH_RUNTIME
        with pytest.raises(RuntimeRoleError, match="authenticates as 'postgres'"):  # ...the driver login does not
            verify_runtime_role(engine, AUTH_RUNTIME)
    finally:
        engine.dispose()


def test_every_checkout_rechecks_the_driver_identity(harness: Harness) -> None:
    from policyops.persistence.database import make_engine

    masked = {"on": False}

    def connect() -> Any:
        if masked["on"]:
            conn = harness.db.server.connect("postgres", harness.db.name)
            conn.execute("SET SESSION AUTHORIZATION policyops_auth_runtime")
            conn.commit()
            return conn
        return harness.db.server.connect(AUTH_RUNTIME, harness.db.name)

    engine = make_engine(connect, pool_size=2)
    try:
        verify_runtime_role(engine, AUTH_RUNTIME)  # verified with a genuine connection
        with engine.connect() as first:
            masked["on"] = True  # the pool now opens a second, masked connection
            with pytest.raises(RuntimeRoleError, match="different role"), engine.connect():
                pass
            first.rollback()
        outcomes = []
        for _ in range(4):  # later checkouts may get either pooled connection: the masked one is always refused
            try:
                with engine.connect() as again:
                    outcomes.append(again.connection.driver_connection.info.user)  # type: ignore[union-attr]
            except RuntimeRoleError:
                outcomes.append("refused")
        assert set(outcomes) <= {AUTH_RUNTIME, "refused"} and outcomes
    finally:
        engine.dispose()


def _harness_with(harness: Harness, **status: int) -> Harness:
    fake = FakeIssuer(redirect_uri=SETTINGS.redirect_uri)
    fake.status_override.update(status)
    runtime = build_auth_runtime(SETTINGS, auth_engine=harness.db.engine(AUTH_RUNTIME),
                                 app_engine=harness.db.engine(APP_RUNTIME), clock=harness.clock,
                                 oidc_transport=fake.transport)
    return Harness(harness.db, harness.clock, fake, runtime, create_app(runtime))


def _safe_error(response: Any, status: int, rule: str) -> None:
    assert response.status_code == status and response.headers["content-type"] == "application/json"
    body = response.json()
    assert body["rule_id"] == rule and body["schema_version"] == "policyops.error/v1"
    assert response.headers["cache-control"] == "no-store" and response.headers["referrer-policy"] == "no-referrer"


def test_provider_outages_are_safe_503s(harness: Harness) -> None:
    down = _harness_with(harness, **{"openid-configuration": 503})
    with down.db.superuser() as conn:
        before = conn.execute("SELECT count(*) FROM identity.login_requests").fetchone()
    _safe_error(down.browser().get("/api/v1/auth/login"), 503, "auth.provider")
    with down.db.superuser() as conn:  # nothing was stored for a login that could not start
        assert conn.execute("SELECT count(*) FROM identity.login_requests").fetchone() == before
    token_down = _harness_with(harness, token=503)
    browser = token_down.browser()
    started = browser.get("/api/v1/auth/login")
    code, state = token_down.fake.issue_code(started.headers["location"], harness.clock.now(), code="c-outage")
    response = browser.get("/api/v1/auth/callback", params={"code": code, "state": state})
    _safe_error(response, 503, "auth.provider")
    assert code not in response.text and state not in response.text
    refused = _harness_with(harness, token=400)
    browser = refused.browser()
    started = browser.get("/api/v1/auth/login")
    code, state = refused.fake.issue_code(started.headers["location"], harness.clock.now(), code="c-refused")
    _safe_error(browser.get("/api/v1/auth/callback", params={"code": code, "state": state}), 401, "auth.id_token")


def test_validation_and_unexpected_errors_use_the_safe_envelope(harness: Harness) -> None:
    w1 = harness.workspace("envelope")
    browser = harness.browser()
    harness.login(browser, "subject-envelope")
    harness.grant("subject-envelope", w1, "admin")
    invalid = unsafe(browser, "/api/v1/auth/workspace", {"workspace_id": "not-a-uuid-<script>"})
    _safe_error(invalid, 422, "api.invalid_input")
    assert "not-a-uuid" not in invalid.text and "<script>" not in invalid.text
    _safe_error(unsafe(browser, "/api/v1/auth/workspace", {"workspace_id": str(w1), "extra": 1}), 422,
                "api.invalid_input")
    assert unsafe(browser, "/api/v1/auth/workspace", {"workspace_id": str(w1)}).status_code == 204
    members = browser.get("/api/v1/workspace/members")
    assert members.status_code == 200 and members.headers["cache-control"] == "no-store"
    assert members.headers["referrer-policy"] == "no-referrer"

    app: FastAPI = harness.app

    @app.get("/api/v1/test/boom")
    def boom() -> None:
        raise RuntimeError("internal detail that must not leak")

    crashed = TestClient(harness.app, base_url=ORIGIN, raise_server_exceptions=False).get("/api/v1/test/boom")
    _safe_error(crashed, 500, "api.internal")
    assert "internal detail" not in crashed.text


def test_framework_404_and_405_use_the_safe_envelope(harness: Harness) -> None:
    browser = harness.browser()
    missing = browser.get("/api/v1/no-such-route")
    _safe_error(missing, 404, "api.http_404")
    wrong_method = browser.put("/api/v1/me")
    _safe_error(wrong_method, 405, "api.http_405")
    assert "GET" in wrong_method.headers["allow"]  # the framework's own headers are kept


def test_short_idle_windows_stay_open_while_active_and_close_exactly_after_inactivity(harness: Harness) -> None:
    """Review F5 on C3: with the minimum idle TTL (60 s) and requests every 20 s, sessions must stay open. The exact
    inactivity boundary uses separate sessions, because a request at 59 s would itself be activity."""
    from policyops.auth.service import touch_interval

    short = AuthSettings(env="test", public_origin=ORIGIN, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID,
                         oidc_client_secret=SecretStr(CLIENT_SECRET), session_absolute_ttl=timedelta(hours=2),
                         session_idle_ttl=timedelta(minutes=1))
    assert touch_interval(short.session_idle_ttl) == timedelta(seconds=15)
    assert touch_interval(SETTINGS.session_idle_ttl) == timedelta(seconds=60)  # default behavior unchanged
    runtime = build_auth_runtime(short, auth_engine=harness.db.engine(AUTH_RUNTIME),
                                 app_engine=harness.db.engine(APP_RUNTIME), clock=harness.clock,
                                 oidc_transport=harness.fake.transport)
    short_harness = Harness(harness.db, harness.clock, harness.fake, runtime, create_app(runtime))
    before, at = short_harness.browser(), short_harness.browser()
    assert short_harness.login(before, "subject-idle-before").status_code == 303
    assert short_harness.login(at, "subject-idle-at").status_code == 303
    for _ in range(9):  # three minutes of activity: three times the idle window
        harness.clock.advance(timedelta(seconds=20))
        assert before.get("/api/v1/me").status_code == 200 and at.get("/api/v1/me").status_code == 200
    harness.clock.advance(timedelta(seconds=59))  # both sessions are now inactive for 59 s
    assert before.get("/api/v1/me").status_code == 200  # just inside the window
    harness.clock.advance(timedelta(seconds=1))  # the other session: exactly 60 s without activity
    assert at.get("/api/v1/me").status_code == 401


def test_default_idle_window_still_closes_at_its_exact_boundary(harness: Harness) -> None:
    before, at = harness.browser(), harness.browser()
    harness.login(before, "subject-default-before")
    harness.login(at, "subject-default-at")
    for _ in range(3):  # activity every 10 minutes keeps a 30-minute window open
        harness.clock.advance(timedelta(minutes=10))
        assert before.get("/api/v1/me").status_code == 200 and at.get("/api/v1/me").status_code == 200
    harness.clock.advance(SETTINGS.session_idle_ttl - timedelta(seconds=1))
    assert before.get("/api/v1/me").status_code == 200
    harness.clock.advance(timedelta(seconds=1))
    assert at.get("/api/v1/me").status_code == 401
