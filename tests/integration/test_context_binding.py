"""Expected-context binding (T25a) over HTTP on real PostgreSQL, as the actual auth/app runtime roles.

Two tabs share one cookie jar. Tab A composed its requests for (principal P, workspace W1) from its own `/me`;
tab B then rotates the session (another workspace, or another principal signing in). Every workspace-bound
operation must refuse tab A's request with 409 `context_changed` before any role, resource or write work, and the
refused writes must leave no domain, idempotency, audit, outbox, decision, job or budget effect. Row contents are
read as superuser; the session rows themselves are excluded because resolving a session may refresh its
`last_seen_at`.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import threading
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import httpx
import pytest

from policyops.api.auth import EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER
from policyops.api.runs import StreamSettings
from policyops.runtime.spec import RuntimeCatalog
from policyops_testing import case_api, live_server
from policyops_testing.app_database import AppDatabase
from policyops_testing.background import BackgroundCall
from policyops_testing.case_api import CaseApi, new_key
from policyops_testing.openapi_check import Reply
from policyops_testing.scripted import ScriptedExecutor, scripted_spec


pytestmark = pytest.mark.postgres
ROOT = Path(__file__).resolve().parents[2]
STREAM = StreamSettings(poll_interval=0.05, heartbeat_interval=0.2, max_lifetime=2.0, batch=10)
DECISION = {"proposal_version": 1, "action_digest": "0" * 64, "decision": "reject", "reason": "Not this one."}
# Request shape per workspace-bound operation: (body, Idempotency-Key, If-Match). The set of keys must equal the
# operations documenting the expected-context headers in the committed OpenAPI document.
SHAPES: dict[str, tuple[Any, bool, bool]] = {
    "list_cases": (None, False, False), "create_case": ({"scenario": "retail"}, True, False),
    "get_case": (None, False, False), "change_status": ({"status": "in_progress"}, True, True),
    "list_messages": (None, False, False), "post_message": ({"source": "staff_note", "text": "hi"}, True, True),
    "start_run": ({"mode": "workbench"}, True, True), "get_run": (None, False, False),
    "cancel_run": (None, True, False), "run_events": (None, False, False), "list_approvals": (None, False, False),
    "list_case_proposals": (None, False, False), "get_proposal": (None, False, False),
    "decide": (DECISION, False, False), "members": (None, False, False), "revoke_member": (None, False, False),
    "list_case_runs": (None, False, False), "run_snapshot": (None, False, False),
    "list_run_citations": (None, False, False), "historical_evidence": (None, False, False),
}


def bound_operations() -> dict[str, tuple[str, str]]:
    """operationId -> (method, path template) for every operation that documents both headers."""
    document = json.loads((ROOT / "packages/policyops/openapi/v1.json").read_bytes())
    found = {}
    for path, operations in document["paths"].items():
        for method, operation in operations.items():
            names = {p["name"] for p in operation.get("parameters", []) if p["in"] == "header"}
            if {EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER} <= names:
                found[operation["operationId"]] = (method.upper(), path)
    return found


OPERATIONS = bound_operations()


def test_the_table_covers_every_bound_operation() -> None:
    assert set(SHAPES) == set(OPERATIONS) and len(OPERATIONS) == 20


@pytest.fixture
def api(shared_db: AppDatabase) -> CaseApi:
    built = scripted_spec(ScriptedExecutor(events=1))
    return case_api.build(shared_db, catalog=RuntimeCatalog.of([built], default=built.spec_id), stream=STREAM)


def subject() -> str:
    return f"subject-{uuid4().hex[:12]}"


@dataclass
class World:
    api: CaseApi
    who: str
    principal: UUID
    w1: UUID
    w2: UUID
    tab: TestClient  # bound to (principal, w1)
    ids: dict[str, str]


def world(api: CaseApi) -> World:
    """P is admin, analyst and reviewer in W1 and W2; W1 holds a case, a run and another member's membership."""
    w1, w2, who = api.workspace("one"), api.workspace("two"), subject()
    tab = api.member(who, w1, "admin")
    for workspace in (w1, w2):
        for role in ("analyst", "reviewer") + (("admin",) if workspace == w2 else ()):
            api.grant(who, workspace, role)
    case = api.create(tab).json()["case_id"]
    run = api.start_run(tab, case, '"1"').json()["run_id"]
    other = subject()
    api.signed_in(other)
    membership = api.grant(other, w1, "analyst")
    ids = {"case_id": case, "run_id": run, "proposal_id": str(uuid4()), "membership_id": str(membership),
           "citation_id": str(uuid4())}
    return World(api, who, api.principal(who), w1, w2, tab, ids)


def send(w: World, operation: str, browser: TestClient | None = None, *, key: str | None = None,
         headers: dict[str, str] | None = None, ids: dict[str, str] | None = None) -> Reply:
    method, template = OPERATIONS[operation]
    body, needs_key, needs_version = SHAPES[operation]
    path = template.format(**(ids or w.ids))
    if operation == "historical_evidence":
        path += f"?run_id={w.ids['run_id']}"
    if_match = None
    if needs_version:
        if_match = w.api.rows("SELECT version FROM app.cases WHERE id = %s", UUID(w.ids["case_id"]))[0][0]
        if_match = f'"{if_match}"'
    return w.api.call(browser or w.tab, method, path, template, json=body, key=(key or new_key()) if needs_key
                      else None, if_match=if_match, headers=headers)


def select(api: CaseApi, browser: TestClient, workspace: UUID) -> None:
    """Tab B's action on the shared jar: rotate the session to `workspace` (tab A's headers are left alone)."""
    saved = {name: browser.headers.pop(name) for name in case_api.CONTEXT_HEADERS if name in browser.headers}
    selected = api.call(browser, "POST", "/api/v1/auth/workspace", "/api/v1/auth/workspace",
                        json={"workspace_id": str(workspace)})
    assert selected.status_code == 204
    browser.headers.update(saved)


def sign_in_again(api: CaseApi, browser: TestClient, who: str) -> None:
    """Tab B's action on the shared jar: sign in (as `who`) in the same browser profile."""
    saved = {name: browser.headers.pop(name) for name in case_api.CONTEXT_HEADERS if name in browser.headers}
    started = api.get(browser, "/api/v1/auth/login", "/api/v1/auth/login", return_to="/cases")
    code, state = api.fake.issue_code(started.headers["location"], api.clock.now(), code=f"code-{uuid4()}", sub=who)
    assert api.get(browser, "/api/v1/auth/callback", "/api/v1/auth/callback", code=code,
                   state=state).status_code == 303
    browser.headers.update(saved)


def snapshot(api: CaseApi) -> dict[str, str]:
    """A digest of every row of every table except the session/login bookkeeping, as superuser (bypassing RLS)."""
    tables = api.rows("SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' "
                      "AND table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1, 2")
    digests = {}
    for schema, table in tables:
        if (schema, table) in {("identity", "sessions"), ("identity", "login_requests")}:
            continue
        digests[f"{schema}.{table}"] = api.scalar(  # identifiers from information_schema, quoted
            "SELECT count(*)::text || ':' || md5(coalesce(string_agg(t::text, ',' ORDER BY t::text), '')) "  # noqa: S608
            f'FROM "{schema}"."{table}" t')
    return digests


def assert_refused(reply: Reply, status: int, code: str, rule_id: str) -> None:
    assert reply.status_code == status, reply.text
    body = reply.json()
    assert (body["code"], body["rule_id"], body["retryable"]) == (code, rule_id, False)
    assert reply.headers["cache-control"] == "no-store"


# -- the race the binding closes -------------------------------------------------------------------------------

def test_a_workspace_rotated_in_another_tab_refuses_every_operation_without_effects(api: CaseApi) -> None:
    w = world(api)
    key = new_key()
    select(api, w.tab, w.w2)  # tab B; the jar now carries a live W2 session, tab A still expects W1
    before = snapshot(api)
    # The inventory discovers all tables; require the checkpoint tables explicitly so their rows also
    # participate in the full before/after no-effect comparison, without pinning the total table count.
    assert {"app.request_idempotency", "app.outbox_events", "app.jobs", "app.approval_decisions", "app.usage_events",
            "app.audit_events", "identity.memberships", "checkpoints.threads", "checkpoints.snapshots",
            "checkpoints.writes"} <= set(before)
    for operation in OPERATIONS:
        assert_refused(send(w, operation, key=key), 409, "context_changed", "auth.workspace_changed")
    assert snapshot(api) == before
    # The same Idempotency-Key, sent again in a context that matches, is a first write rather than a replay.
    select(api, w.tab, w.w1)
    created = send(w, "create_case", key=key)
    assert created.status_code == 201 and "idempotent-replayed" not in created.headers


def test_another_principal_signing_in_refuses_every_operation_without_effects(api: CaseApi) -> None:
    w = world(api)
    other = subject()
    api.signed_in(other)
    for role in ("admin", "analyst", "reviewer"):
        api.grant(other, w.w1, role)  # a legitimate member of the same workspace, with every role
    sign_in_again(api, w.tab, other)
    select(api, w.tab, w.w1)  # same workspace, different principal: tab A still expects P
    before = snapshot(api)
    for operation in OPERATIONS:
        assert_refused(send(w, operation), 409, "context_changed", "auth.principal_changed")
    assert snapshot(api) == before


def test_the_same_context_proceeds_to_the_usual_checks(api: CaseApi) -> None:
    w = world(api)
    expected = {"list_cases": 200, "create_case": 201, "get_case": 200, "change_status": 200, "list_messages": 200,
                "post_message": 201, "start_run": 409, "get_run": 200, "cancel_run": 200, "run_events": 404,
                "list_approvals": 200, "list_case_proposals": 200, "get_proposal": 404, "decide": 404,
                "list_case_runs": 200, "run_snapshot": 200, "list_run_citations": 200, "historical_evidence": 404,
                "members": 200, "revoke_member": 204}
    unknown_run = dict(w.ids, run_id=str(uuid4()))  # a stream of an unknown run: refused after the binding
    for operation, status in expected.items():
        reply = send(w, operation, ids=unknown_run if operation == "run_events" else None)
        assert reply.status_code == status, (operation, reply.text)
        if operation == "start_run":
            assert reply.json()["rule_id"] == "api.run_active"  # an ordinary conflict, not context_changed


def test_foreign_and_unknown_resources_stay_not_found_once_the_context_matches(api: CaseApi) -> None:
    w = world(api)
    beta = api.member(subject(), w.w2, "analyst")
    foreign = api.create(beta).json()["case_id"]
    for case_id in (foreign, str(uuid4())):
        reply = api.call(w.tab, "GET", f"/api/v1/cases/{case_id}", "/api/v1/cases/{case_id}")
        assert_refused(reply, 404, "not_found", "api.case_not_found")


def test_a_header_naming_another_or_unknown_workspace_gets_the_same_refusal(api: CaseApi) -> None:
    w = world(api)
    outsider = api.workspace("outsider")  # P is no member here
    bodies = []
    for workspace in (w.w2, outsider, uuid4()):
        reply = api.call(w.tab, "GET", "/api/v1/cases", "/api/v1/cases",
                         headers={EXPECTED_WORKSPACE_HEADER: str(workspace)})
        assert_refused(reply, 409, "context_changed", "auth.workspace_changed")
        bodies.append({k: v for k, v in reply.json().items() if k != "correlation_id"})
    assert bodies[0] == bodies[1] == bodies[2]


# -- refusal order ---------------------------------------------------------------------------------------------

def test_authentication_and_csrf_come_before_the_headers(api: CaseApi) -> None:
    w = world(api)
    anonymous = api.browser()
    for operation in ("list_cases", "create_case", "run_events"):
        for bad in ({}, {EXPECTED_WORKSPACE_HEADER: "nope", EXPECTED_PRINCIPAL_HEADER: "nope"}):
            assert_refused(send(w, operation, anonymous, headers=bad), 401, "unauthenticated", "auth.session")
    select(api, w.tab, w.w2)  # a mismatched context as well
    origin = send(w, "create_case", headers={"Origin": "http://evil.example"})
    assert_refused(origin, 403, "forbidden", "auth.origin")
    csrf = send(w, "change_status", headers={"X-CSRF-Token": "forged"})
    assert_refused(csrf, 403, "forbidden", "auth.csrf")
    select(api, w.tab, w.w1)
    fresh = send(w, "post_message")  # the rotated CSRF cookie is the one the client sends
    assert fresh.status_code == 201


def test_header_refusals_are_bounded_and_not_echoed(api: CaseApi) -> None:
    w = world(api)
    clean = api.clone(w.tab, context=False)
    principal, workspace = str(w.principal), str(w.w1)
    missing = api.call(clean, "GET", "/api/v1/cases", "/api/v1/cases", headers={EXPECTED_WORKSPACE_HEADER: workspace})
    assert_refused(missing, 400, "invalid_input", "api.expected_principal_required")
    missing = api.call(clean, "GET", "/api/v1/cases", "/api/v1/cases", headers={EXPECTED_PRINCIPAL_HEADER: principal})
    assert_refused(missing, 400, "invalid_input", "api.expected_workspace_required")
    for value in (workspace.upper(), "{" + workspace + "}", "urn:uuid:" + workspace, UUID(workspace).hex,
                  workspace + "0", "", "<script>", f"{workspace}, {workspace}"):
        reply = api.call(clean, "GET", "/api/v1/cases", "/api/v1/cases",
                         headers={EXPECTED_PRINCIPAL_HEADER: principal, EXPECTED_WORKSPACE_HEADER: value})
        assert_refused(reply, 422, "invalid_input", "api.invalid_expected_workspace")
        assert (value == "" or value not in reply.text) and "<script>" not in reply.text
    duplicate = clean.get("/api/v1/cases", headers=[(EXPECTED_PRINCIPAL_HEADER, principal),
                                                    (EXPECTED_WORKSPACE_HEADER, workspace),
                                                    (EXPECTED_WORKSPACE_HEADER, workspace)])
    assert_refused(duplicate, 422, "invalid_input", "api.invalid_expected_workspace")
    stream = clean.get(f"/api/v1/runs/{w.ids['run_id']}/events", headers={EXPECTED_PRINCIPAL_HEADER: "x" * 300,
                                                                          EXPECTED_WORKSPACE_HEADER: workspace})
    assert_refused(stream, 422, "invalid_input", "api.invalid_expected_principal")


def test_a_context_mismatch_precedes_role_and_body_checks(api: CaseApi) -> None:
    w = world(api)
    auditor_subject = subject()
    auditor = api.member(auditor_subject, w.w1, "auditor")
    assert_refused(send(w, "create_case", auditor), 403, "forbidden", "auth.role")  # matching context: the role
    api.grant(auditor_subject, w.w2, "auditor")
    select(api, auditor, w.w2)
    assert_refused(send(w, "create_case", auditor), 409, "context_changed", "auth.workspace_changed")  # not 403
    invalid_body = api.call(auditor, "POST", "/api/v1/cases", "/api/v1/cases", json={"scenario": "x"}, key=new_key())
    assert_refused(invalid_body, 409, "context_changed", "auth.workspace_changed")  # before body validation
    # Malformed JSON keeps the framework's earlier refusal (it is read before dependencies run).
    malformed = api.call(auditor, "POST", "/api/v1/cases", "/api/v1/cases", content=b'{"scenario":', key=new_key(),
                         headers={"Content-Type": "application/json"})
    assert_refused(malformed, 422, "invalid_input", "api.invalid_input")


def test_an_expired_session_is_unauthenticated_whatever_the_headers(api: CaseApi) -> None:
    w = world(api)
    api.clock.advance(case_api.SETTINGS.session_idle_ttl)  # this test's own clock
    assert_refused(send(w, "list_cases"), 401, "unauthenticated", "auth.session")
    assert_refused(send(w, "run_events"), 401, "unauthenticated", "auth.session")


# -- requests already in flight --------------------------------------------------------------------------------

def test_a_request_authorized_before_the_rotation_completes_in_its_own_context(api: CaseApi) -> None:
    """Tab A's PATCH (W1 cookie, W1 headers) is authorized and then waits on a case lock; tab B rotates to W2. The
    PATCH completes in W1, as its label says; tab A's next request carries the W2 cookie and is refused, and the
    old (revoked) cookie is unauthenticated."""
    w = world(api)
    in_flight = api.clone(w.tab)
    old_cookie = api.clone(w.tab)
    case = UUID(w.ids["case_id"])
    # Contexts exit in reverse order: the transaction (and its lock) ends first, then the worker is joined, bounded,
    # on every path out, including a failed readiness wait, query or select.
    with (BackgroundCall(lambda: send(w, "change_status", in_flight)) as worker,
          api.db.superuser() as conn, conn.transaction()):
        conn.execute("SELECT 1 FROM app.cases WHERE id = %s FOR UPDATE", (case,))
        worker.start()
        deadline = threading.Event()
        for _ in range(400):
            if api.scalar("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                          "AND wait_event_type = 'Lock'"):
                break
            deadline.wait(0.05)
        else:
            raise AssertionError("the request never waited for the lock")
        select(api, w.tab, w.w2)
    patched = worker.result()
    assert patched.status_code == 200 and patched.json()["status"] == "in_progress"
    assert api.rows("SELECT workspace_id, status FROM app.cases WHERE id = %s", case) == [(w.w1, "in_progress")]
    assert_refused(send(w, "get_case"), 409, "context_changed", "auth.workspace_changed")
    assert_refused(send(w, "get_case", old_cookie), 401, "unauthenticated", "auth.session")


@pytest.mark.parametrize("column", ["workspace_id", "principal_id"])
def test_an_open_stream_ends_when_its_session_no_longer_matches_the_captured_context(api: CaseApi,
                                                                                     column: str) -> None:
    """Each poll checks the session (by the captured cookie) against the captured expected context; it never
    re-reads a cookie jar. Changing the session row in place (a trusted superuser write the application never
    makes) to another workspace of P, or to another principal who is also a W1 member, ends the stream at the next
    poll instead of at the lifetime limit."""
    w = world(api)
    other = api.rows("SELECT principal_id FROM identity.memberships WHERE id = %s", UUID(w.ids["membership_id"]))
    replacement = w.w2 if column == "workspace_id" else other[0][0]
    session_id = api.rows("SELECT id FROM identity.sessions WHERE principal_id = %s AND revoked_at IS NULL "
                          "AND workspace_id = %s", w.principal, w.w1)[0][0]
    jar = dict(w.tab.cookies.items())
    started = threading.Event()
    lines: list[str] = []
    statuses: list[int] = []
    with live_server.serve(api.app) as url, httpx.Client(base_url=url, cookies=jar, headers=api.context(w.tab),
                                                          timeout=15) as viewer:
        def read() -> None:
            with viewer.stream("GET", f"/api/v1/runs/{w.ids['run_id']}/events") as response:
                statuses.append(response.status_code)
                for line in response.iter_lines():
                    lines.append(line)
                    if line.startswith("id:"):
                        started.set()

        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        try:
            assert started.wait(10), statuses
            with api.db.superuser() as conn, conn.transaction():
                conn.execute(f"UPDATE identity.sessions SET {column} = %s WHERE id = %s",  # noqa: S608 (parametrize)
                             (replacement, session_id))
        finally:
            thread.join(STREAM.connection_deadline + 5)
    assert not thread.is_alive() and statuses == [200]
    assert not any(line.startswith("event: reconnect") for line in lines)  # ended by the check, not the lifetime
