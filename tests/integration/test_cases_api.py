"""Case and message API (T08) end to end over HTTP on real PostgreSQL, as the actual auth/app runtime roles.

Every response is checked against the committed OpenAPI document by the harness. Counts are read as superuser
(bypassing RLS) so that what the API did not write is verified directly.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from functools import partial
import threading
import time
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import pytest

from policyops.persistence import idempotency as idem
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops_testing import case_api
from policyops_testing.app_database import AppDatabase
from policyops_testing.case_api import CaseApi, new_key
from policyops_testing.openapi_check import Reply


pytestmark = pytest.mark.postgres
CASES, CASE, MESSAGES = "/api/v1/cases", "/api/v1/cases/{case_id}", "/api/v1/cases/{case_id}/messages"


@pytest.fixture
def api(shared_db: AppDatabase) -> CaseApi:
    return case_api.build(shared_db)


def subject() -> str:
    return f"subject-{uuid4().hex[:12]}"


def counts(api: CaseApi, workspace: UUID) -> dict[str, int]:
    return {
        "cases": api.scalar("SELECT count(*) FROM app.cases WHERE workspace_id = %s", workspace),
        "messages": api.scalar("SELECT count(*) FROM app.case_messages WHERE workspace_id = %s", workspace),
        "audit": api.scalar("SELECT count(*) FROM app.audit_events WHERE workspace_id = %s", workspace),
        "ledger": api.scalar("SELECT count(*) FROM app.request_idempotency WHERE workspace_id = %s", workspace),
        "version_sum": api.scalar("SELECT coalesce(sum(version), 0) FROM app.cases WHERE workspace_id = %s",
                                  workspace),
    }


def assert_error(response: Reply, status: int, code: str, rule_id: str, *, echo: str | None = None) -> None:
    assert response.status_code == status, response.text
    body = response.json()
    assert (body["code"], body["rule_id"]) == (code, rule_id)
    assert response.headers["cache-control"] == "no-store" and response.headers["referrer-policy"] == "no-referrer"
    if echo is not None:
        assert echo not in response.text


def team(api: CaseApi, label: str = "team") -> tuple[UUID, TestClient]:
    workspace = api.workspace(label)
    return workspace, api.member(subject(), workspace, "analyst")


def new_case(api: CaseApi, browser: TestClient) -> dict[str, Any]:
    created = api.create(browser)
    assert created.status_code == 201
    return created.json()  # type: ignore[no-any-return]


# -- create, read, list ---------------------------------------------------------------------------------------

def test_create_read_and_audit(api: CaseApi) -> None:
    workspace, who = api.workspace("team"), subject()
    browser = api.member(who, workspace, "analyst")
    actor = api.principal(who)
    created = api.create(browser, key="create-key-0001")
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "open" and body["scenario"] == "retail" and body["customer_bound"] is False
    assert body["version"] == 1 and created.headers["etag"] == '"1"'
    assert created.headers["location"] == f"/api/v1/cases/{body['case_id']}"
    assert "idempotent-replayed" not in created.headers
    assert created.headers["cache-control"] == "no-store"
    fetched = api.case(browser, body["case_id"])
    assert fetched.status_code == 200 and fetched.json() == body and fetched.headers["etag"] == '"1"'
    assert api.rows("SELECT customer_user_id, scenario, created_by FROM app.cases WHERE id = %s",
                    UUID(body["case_id"])) == [(None, "retail", actor)]
    assert api.rows("SELECT action, target_type, target_id, actor_kind, actor_principal_id FROM app.audit_events "
                    "WHERE workspace_id = %s", workspace) == [("case.created", "case", UUID(body["case_id"]),
                                                               "principal", actor)]
    ledger = api.rows("SELECT principal_id, operation, idempotency_key, case_id, message_id, response_status, "
                      "response_etag FROM app.request_idempotency WHERE workspace_id = %s", workspace)
    assert ledger == [(actor, "case.create", "create-key-0001", UUID(body["case_id"]), None, 201, '"1"')]
    listed = api.get(browser, CASES, CASES)
    assert listed.status_code == 200 and listed.json() == {"items": [body], "next_cursor": None}


def test_create_rejects_unknown_scenario_fields_and_missing_key(api: CaseApi) -> None:
    workspace, browser = team(api)
    payloads: list[Any] = [{"scenario": "banking"}, {"scenario": "retail", "customer_user_id": "u1"},
                           {"scenario": "retail", "workspace_id": str(uuid4())}, {}, [], "retail"]
    for payload in payloads:
        refused = api.call(browser, "POST", CASES, CASES, json=payload, key=new_key())
        assert_error(refused, 422, "invalid_input", "api.invalid_input", echo="banking")
    missing = api.call(browser, "POST", CASES, CASES, json={"scenario": "retail"})
    assert_error(missing, 400, "invalid_input", "api.idempotency_key_required")
    for bad in ("short", "has space in it", "x" * 129, "key/with/slash", "key=padding=", "key,second-key"):
        refused = api.call(browser, "POST", CASES, CASES, json={"scenario": "retail"},
                           headers={"Idempotency-Key": bad})
        assert_error(refused, 422, "invalid_input", "api.invalid_idempotency_key")
    assert counts(api, workspace)["cases"] == 0 and counts(api, workspace)["ledger"] == 0


# -- roles, tenancy and foreign identifiers -----------------------------------------------------------------

ALLOWED = {"analyst": True, "reviewer": True, "admin": True, "auditor": False}


@pytest.mark.parametrize("role", sorted(ALLOWED))
def test_role_matrix(api: CaseApi, role: str) -> None:
    workspace, owner = team(api)
    case = new_case(api, owner)
    browser = api.member(subject(), workspace, role)
    before = counts(api, workspace)
    attempts = [api.create(browser), api.patch(browser, case["case_id"], "in_progress", '"1"'),
                api.post(browser, case["case_id"], "note", '"1"'),
                api.post(browser, case["case_id"], "customer said hi", '"1"', source="operator_entered_customer")]
    if ALLOWED[role]:
        assert [r.status_code for r in attempts] == [201, 200, 409, 409]  # the status change advanced the version
        assert [r.json()["rule_id"] for r in attempts[2:]] == ["api.stale_version"] * 2
    else:
        for refused in attempts:
            assert_error(refused, 403, "forbidden", "auth.role")
        assert counts(api, workspace) == before
    assert api.case(browser, case["case_id"]).status_code == 200  # every role reads
    assert api.get(browser, CASES, CASES).status_code == 200
    assert api.get(browser, f"{CASES}/{case['case_id']}/messages", MESSAGES).status_code == 200


def test_allowed_roles_write_each_operation(api: CaseApi) -> None:
    workspace, _ = team(api)
    for role in ("analyst", "reviewer", "admin"):
        who = subject()
        browser = api.member(who, workspace, role)
        case = new_case(api, browser)
        assert api.patch(browser, case["case_id"], "in_progress", '"1"').status_code == 200
        assert api.post(browser, case["case_id"], "note", '"2"').status_code == 201
        posted = api.post(browser, case["case_id"], "customer turn", '"3"', source="operator_entered_customer")
        assert posted.status_code == 201
        message = posted.json()["message"]
        assert message["source"] == "operator_entered_customer"
        assert message["entered_by"] == str(api.principal(who)) and posted.json()["case"]["version"] == 4


def test_unauthenticated_unselected_and_csrf(api: CaseApi) -> None:
    workspace, owner = team(api)
    case = new_case(api, owner)
    anonymous = api.browser()
    for response in (api.get(anonymous, CASES, CASES), api.case(anonymous, case["case_id"]),
                     api.create(anonymous), api.patch(anonymous, case["case_id"], "in_progress", '"1"')):
        assert response.status_code in (401, 403)
    assert_error(api.get(anonymous, CASES, CASES), 401, "unauthenticated", "auth.session")
    unselected = api.bind(api.member(subject(), workspace, None))  # no workspace to expect yet
    assert_error(api.get(unselected, CASES, CASES), 400, "invalid_input", "api.expected_workspace_required")
    assert_error(api.call(unselected, "GET", CASES, CASES, headers={"PolicyOps-Expected-Workspace": str(workspace)}),
                 409, "context_changed", "auth.workspace_changed")  # the session has none selected
    no_csrf = api.call(owner, "POST", CASES, CASES, json={"scenario": "retail"}, key=new_key(), csrf=False,
                       headers={"Origin": case_api.ORIGIN})
    assert_error(no_csrf, 403, "forbidden", "auth.csrf")
    wrong_origin = api.call(owner, "POST", CASES, CASES, json={"scenario": "retail"}, key=new_key(),
                            headers={"Origin": "http://evil.example"})
    assert_error(wrong_origin, 403, "forbidden", "auth.origin")
    assert counts(api, workspace)["cases"] == 1


def test_foreign_and_unknown_ids_are_not_found(api: CaseApi) -> None:
    alpha, a_browser = team(api, "alpha")
    beta, b_browser = team(api, "beta")
    case = new_case(api, a_browser)["case_id"]
    before = counts(api, alpha)
    for target in (case, str(uuid4())):
        assert_error(api.case(b_browser, target), 404, "not_found", "api.case_not_found")
        assert_error(api.get(b_browser, f"{CASES}/{target}/messages", MESSAGES), 404, "not_found",
                     "api.case_not_found")
        assert_error(api.patch(b_browser, target, "in_progress", '"1"'), 404, "not_found", "api.case_not_found")
        assert_error(api.post(b_browser, target, "hello", '"1"'), 404, "not_found", "api.case_not_found")
    assert api.get(b_browser, CASES, CASES).json()["items"] == []
    assert counts(api, alpha) == before and counts(api, beta)["ledger"] == 0
    assert_error(api.call(a_browser, "GET", f"{CASES}/not-a-uuid", CASE), 422, "invalid_input", "api.invalid_input")


def test_cached_reply_is_not_returned_for_a_case_outside_the_selected_workspace(api: CaseApi) -> None:
    """The same principal, same key and same path in another selected workspace: 404, never the cached reply.
    The workspace-scoped ledger under RLS already hides the other workspace's record; the service's explicit
    case-visibility check before replay is defense in depth (mutation M2 removing it does not fail this test)."""
    alpha, beta = api.workspace("alpha"), api.workspace("beta")
    who = subject()
    browser = api.member(who, alpha, "analyst")
    case = new_case(api, browser)["case_id"]
    key = new_key()
    assert api.patch(browser, case, "in_progress", '"1"', key=key).status_code == 200
    api.grant(who, beta, "analyst")
    assert api.call(browser, "POST", "/api/v1/auth/workspace", "/api/v1/auth/workspace",
                    json={"workspace_id": str(beta)}).status_code == 204
    api.bind(browser)  # the tab reloads /me and now expects beta
    assert_error(api.patch(browser, case, "in_progress", '"1"', key=key), 404, "not_found", "api.case_not_found")
    assert counts(api, beta)["ledger"] == 0


# -- idempotency ----------------------------------------------------------------------------------------------

def test_replay_returns_the_original_response_after_later_changes(api: CaseApi) -> None:
    workspace, browser = team(api)
    created = api.create(browser, key="create-original-1")
    case = created.json()["case_id"]
    changed = api.patch(browser, case, "in_progress", '"1"', key="status-original-1")
    posted = api.post(browser, case, "first note", '"2"', key="message-original-1")
    assert (changed.status_code, posted.status_code) == (200, 201)
    assert api.patch(browser, case, "resolved", '"3"').status_code == 200
    after = counts(api, workspace)
    retries: list[tuple[Reply, Callable[[], Reply]]] = [
        (created, partial(api.create, browser, key="create-original-1")),
        (changed, partial(api.patch, browser, case, "in_progress", '"1"', key="status-original-1")),
        (posted, partial(api.post, browser, case, "first note", '"2"', key="message-original-1"))]
    for original, retry in retries:
        replayed = retry()
        assert replayed.status_code == original.status_code
        assert replayed.content == original.content  # byte-identical original body
        assert replayed.headers["etag"] == original.headers["etag"]
        assert replayed.headers.get("location") == original.headers.get("location")
        assert replayed.headers["idempotent-replayed"] == "true"
    assert counts(api, workspace) == after
    assert api.case(browser, case).json()["status"] == "resolved"


def test_lost_response_is_recovered_by_retrying_the_key(shared_db: AppDatabase) -> None:
    class DropOnce:
        def __init__(self, app: Any) -> None:
            self.app, self.armed = app, False

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if not (self.armed and scope["type"] == "http"):
                await self.app(scope, receive, send)
                return
            self.armed = False

            async def gone(_message: Any) -> None:
                raise ConnectionResetError("client disconnected before the response")

            await self.app(scope, receive, gone)

    holder: list[DropOnce] = []

    def wrap(app: Any) -> Any:
        holder.append(DropOnce(app))
        return holder[0]

    api = case_api.build(shared_db, wrap=wrap)
    workspace, browser = team(api)
    holder[0].armed = True
    with pytest.raises(ConnectionResetError):
        api.create(browser, key="lost-create-0001")
    assert counts(api, workspace)["cases"] == 1  # committed although the client saw nothing
    retried = api.create(browser, key="lost-create-0001")
    assert retried.status_code == 201 and retried.headers["idempotent-replayed"] == "true"
    case = retried.json()["case_id"]
    assert api.rows("SELECT id FROM app.cases WHERE workspace_id = %s", workspace) == [(UUID(case),)]
    holder[0].armed = True
    with pytest.raises(ConnectionResetError):
        api.post(browser, case, "lost note", '"1"', key="lost-message-01")
    again = api.post(browser, case, "lost note", '"1"', key="lost-message-01")
    assert again.status_code == 201 and again.headers["idempotent-replayed"] == "true"
    assert again.json()["message"]["sequence"] == 1 and again.json()["case"]["version"] == 2
    assert counts(api, workspace) == {"cases": 1, "messages": 1, "audit": 2, "ledger": 2, "version_sum": 2}


def test_reusing_a_key_for_a_different_request_conflicts(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    other = new_case(api, browser)["case_id"]
    key = new_key()
    assert api.patch(browser, case, "in_progress", '"1"', key=key).status_code == 200
    before = counts(api, workspace)
    for response in (api.patch(browser, case, "resolved", '"1"', key=key),       # body
                     api.patch(browser, case, "in_progress", '"2"', key=key),    # precondition
                     api.patch(browser, other, "in_progress", '"1"', key=key)):  # path
        assert_error(response, 409, "conflict", "api.idempotency_mismatch")
    assert counts(api, workspace) == before
    note_key = new_key()
    assert api.post(browser, other, "same words", '"1"', key=note_key).status_code == 201
    assert_error(api.post(browser, other, "same words", '"1"', key=note_key, source="operator_entered_customer"),
                 409, "conflict", "api.idempotency_mismatch")
    assert_error(api.post(browser, other, "other words", '"1"', key=note_key), 409, "conflict",
                 "api.idempotency_mismatch")
    # Keys are scoped by operation and principal: the same key elsewhere is a new request.
    assert api.post(browser, case, "status key reused", '"2"', key=key).status_code == 201
    colleague = api.member(subject(), workspace, "analyst")
    assert api.patch(colleague, other, "in_progress", '"2"', key=key).status_code == 200


def run_together(calls: list[Callable[[], Reply]]) -> list[Reply]:
    barrier = threading.Barrier(len(calls))
    results: list[Reply | BaseException | None] = [None] * len(calls)

    def worker(index: int) -> None:
        barrier.wait()
        try:
            results[index] = calls[index]()
        except BaseException as exc:  # reported below
            results[index] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(calls))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(result is None or isinstance(result, BaseException) for result in results), results
    return results  # type: ignore[return-value]


def test_eight_concurrent_requests_with_one_key_make_one_change(api: CaseApi) -> None:
    workspace, browser = team(api)
    clients = [api.clone(browser) for _ in range(8)]
    created = run_together([partial(api.create, c, key="race-create-0001") for c in clients])
    assert {r.status_code for r in created} == {201} and len({r.content for r in created}) == 1
    assert sum(r.headers.get("idempotent-replayed") == "true" for r in created) == 7
    case = created[0].json()["case_id"]
    posted = run_together([partial(api.post, c, case, "race note", '"1"', key="race-message-01") for c in clients])
    assert {r.status_code for r in posted} == {201} and len({r.content for r in posted}) == 1
    changed = run_together([partial(api.patch, c, case, "in_progress", '"2"', key="race-status-001")
                            for c in clients])
    assert {r.status_code for r in changed} == {200} and len({r.content for r in changed}) == 1
    assert counts(api, workspace) == {"cases": 1, "messages": 1, "audit": 3, "ledger": 3, "version_sum": 3}


def test_concurrent_messages_with_separate_keys_get_contiguous_sequences(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    clients = [api.clone(browser) for _ in range(8)]

    def post_until_accepted(client: TestClient, index: int) -> Reply:
        key = new_key()  # a failed attempt stores nothing, so the same key is retried with the fresh version
        for _ in range(40):
            version = api.case(client, case).headers["etag"]
            response = api.post(client, case, f"note {index}", version, key=key)
            if response.status_code != 409:
                return response
            assert response.json()["rule_id"] == "api.stale_version"
        raise AssertionError("never accepted")

    results = run_together([partial(post_until_accepted, c, i) for i, c in enumerate(clients)])
    assert {r.status_code for r in results} == {201}
    sequences = sorted(r.json()["message"]["sequence"] for r in results)
    assert sequences == list(range(1, 9))
    assert api.case(browser, case).json()["version"] == 9
    assert counts(api, workspace) == {"cases": 1, "messages": 8, "audit": 9, "ledger": 9, "version_sum": 9}
    page = api.get(browser, f"{CASES}/{case}/messages", MESSAGES, limit=200).json()
    assert [m["sequence"] for m in page["items"]] == list(range(1, 9)) and page["next_after_sequence"] is None


# -- preconditions and status transitions ---------------------------------------------------------------------

def test_stale_version_and_replay_before_stale_rejection(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    key = new_key()
    first = api.patch(browser, case, "in_progress", '"1"', key=key)
    assert first.status_code == 200 and first.headers["etag"] == '"2"'
    assert_error(api.patch(browser, case, "in_progress", '"1"'), 409, "stale_version", "api.stale_version")
    assert_error(api.post(browser, case, "late", '"1"'), 409, "stale_version", "api.stale_version")
    before = counts(api, workspace)
    replay = api.patch(browser, case, "in_progress", '"1"', key=key)  # old precondition, committed: replay
    assert replay.status_code == 200 and replay.content == first.content
    assert counts(api, workspace) == before


def test_precondition_headers(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    calls: list[Callable[[str | None], Reply]] = [partial(api.patch, browser, case, "in_progress"),
                                                  partial(api.post, browser, case, "x")]
    for call in calls:
        assert_error(call(None), 428, "invalid_input", "api.precondition_required")
        for malformed in ('W/"1"', "*", "1", '"0"', '"01"', '"1", "2"', '"x"', '"99999999999999999"', '""'):
            assert_error(call(malformed), 422, "invalid_input", "api.invalid_precondition", echo="99999999")
    assert counts(api, workspace) == {"cases": 1, "messages": 0, "audit": 1, "ledger": 1, "version_sum": 1}


def test_status_transitions_and_noop(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    assert_error(api.patch(browser, case, "resolved", '"1"'), 409, "conflict", "api.status_transition")
    assert_error(api.patch(browser, case, "closed", '"1"'), 409, "conflict", "api.status_transition")
    before = counts(api, workspace)
    noop = api.patch(browser, case, "open", '"1"')
    assert noop.status_code == 200 and noop.headers["etag"] == '"1"' and noop.json()["version"] == 1
    after_noop = counts(api, workspace)
    assert after_noop["audit"] == before["audit"] and after_noop["version_sum"] == before["version_sum"]
    assert after_noop["ledger"] == before["ledger"] + 1  # the key still records its (no-op) response
    path = [("in_progress", '"1"'), ("resolved", '"2"'), ("in_progress", '"3"'), ("resolved", '"4"'),
            ("closed", '"5"')]
    for status, version in path:
        assert api.patch(browser, case, status, version).json()["status"] == status
    for status in ("open", "in_progress", "resolved"):
        assert_error(api.patch(browser, case, status, '"6"'), 409, "conflict", "api.status_transition")
    assert api.patch(browser, case, "closed", '"6"').status_code == 200  # closed -> closed is a no-op
    audit = api.rows("SELECT action FROM app.audit_events WHERE workspace_id = %s ORDER BY occurred_at, action",
                     workspace)
    assert [a for (a,) in audit] == ["case.created"] + ["case.status_changed"] * 5
    assert_error(api.call(browser, "PATCH", f"{CASES}/{case}", CASE, json={"status": "archived"}, key=new_key(),
                          if_match='"6"'), 422, "invalid_input", "api.invalid_input", echo="archived")
    assert_error(api.call(browser, "PATCH", f"{CASES}/{case}", CASE, json={"status": "closed", "version": 6},
                          key=new_key(), if_match='"6"'), 422, "invalid_input", "api.invalid_input")


# -- message provenance and bounds -----------------------------------------------------------------------------

def test_message_provenance_is_server_owned(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    path = f"{CASES}/{case}/messages"
    for payload in ({"source": "agent", "text": "x"}, {"source": "seeded", "text": "x"},
                    {"source": "simulated_customer", "text": "x"}, {"text": "x"},
                    {"source": "staff_note", "text": "x", "entered_by": str(uuid4())},
                    {"source": "staff_note", "text": "x", "sequence": 1},
                    {"source": "staff_note", "text": "x", "created_at": "2026-01-01T00:00:00Z"},
                    {"source": "staff_note", "text": "x", "workspace_id": str(uuid4())},
                    {"source": "staff_note", "text": "x", "text_sha256": "0" * 64},
                    {"source": "staff_note", "text": 5}, {"source": "staff_note", "text": None}):
        assert_error(api.call(browser, "POST", path, MESSAGES, json=payload, key=new_key(), if_match='"1"'), 422,
                     "invalid_input", "api.invalid_input")
    assert counts(api, workspace)["messages"] == 0
    posted = api.post(browser, case, "a staff note", '"1"').json()["message"]
    assert posted["source"] == "staff_note" and posted["sequence"] == 1 and posted["entered_by"] is not None
    stored = api.rows("SELECT source, entered_by, text, text_sha256 FROM app.case_messages WHERE case_id = %s",
                      UUID(case))
    assert stored == [("staff_note", UUID(posted["entered_by"]), "a staff note", posted["text_sha256"])]


def test_message_text_bounds_and_unicode(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    path = f"{CASES}/{case}/messages"

    def raw(body: bytes) -> Reply:
        return api.call(browser, "POST", path, MESSAGES, content=body, key=new_key(),
                        if_match=api.case(browser, case).headers["etag"],
                        headers={"Content-Type": "application/json"})

    assert api.post(browser, case, "x" * 4000, '"1"').status_code == 201
    supplementary = "\U0001F600" * 4000  # 4000 code points, 16000 UTF-8 bytes
    accepted = api.post(browser, case, supplementary, '"2"')
    assert accepted.status_code == 201 and accepted.json()["message"]["text"] == supplementary
    for text in ("", "x" * 4001, "\U0001F600" * 4001, "bell\x07", "nul\x00", "c1\x85", "del\x7f"):
        assert_error(api.post(browser, case, text, '"3"'), 422, "invalid_input", "api.invalid_input")
    assert_error(raw(b'{"source":"staff_note","text":"lone \\ud800 surrogate"}'), 422, "invalid_input",
                 "api.invalid_input", echo="surrogate")
    assert_error(raw(b'{"source":"staff_note","text":"bad \xff\xfe bytes"}'), 400, "invalid_input", "api.http_400",
                 echo="bytes")
    assert_error(raw(b'{"source":"staff_note","text":'), 422, "invalid_input", "api.invalid_input")
    stored = api.scalar("SELECT char_length(text) FROM app.case_messages WHERE case_id = %s AND sequence = 2",
                        UUID(case))
    assert stored == 4000 and counts(api, workspace)["messages"] == 2


def test_received_body_is_bounded_to_64_kib(api: CaseApi) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    path = f"{CASES}/{case}/messages"
    prefix, suffix = b'{"source":"staff_note","text":"padded"', b"}"
    exact = prefix + b" " * (65536 - len(prefix) - len(suffix)) + suffix
    assert len(exact) == 65536
    accepted = api.call(browser, "POST", path, MESSAGES, content=exact, key=new_key(), if_match='"1"',
                        headers={"Content-Type": "application/json"})
    assert accepted.status_code == 201
    over = exact[:-1] + b" }"
    assert_error(api.call(browser, "POST", path, MESSAGES, content=over, key=new_key(), if_match='"2"',
                          headers={"Content-Type": "application/json"}), 413, "invalid_input", "api.http_413")
    def chunks() -> Iterator[bytes]:  # no Content-Length: chunked transfer
        yield prefix
        for _ in range(64):
            yield b" " * 4096

    streamed = api.call(browser, "POST", path, MESSAGES, content=chunks(), key=new_key(), if_match='"2"',
                        headers={"Content-Type": "application/json"})
    assert_error(streamed, 413, "invalid_input", "api.http_413")
    assert counts(api, workspace)["messages"] == 1 and counts(api, workspace)["ledger"] == 2


# -- pagination ----------------------------------------------------------------------------------------------

def test_case_queue_pages_by_creation_with_ties_and_live_inserts(api: CaseApi) -> None:
    _, browser = team(api)
    made = []
    for index in range(7):
        if index % 3 == 0:
            api.clock.advance(timedelta(seconds=1))  # groups of equal created_at exercise the id tie-break
        made.append(new_case(api, browser))
    expected = [c["case_id"] for c in sorted(made, key=lambda c: (c["created_at"], c["case_id"]), reverse=True)]
    seen: list[str] = []
    cursor: str | None = None
    while True:
        params: dict[str, Any] = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        page = api.get(browser, CASES, CASES, **params).json()
        seen.extend(item["case_id"] for item in page["items"])
        if len(seen) == 3:
            api.clock.advance(timedelta(seconds=5))
            new_case(api, browser)  # newer than the cursor: not shown in later pages
            assert api.patch(browser, page["items"][0]["case_id"], "in_progress", '"1"').status_code == 200
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == expected  # no duplicates or gaps; updates do not reorder the queue
    first = api.get(browser, CASES, CASES, limit=100).json()["items"]
    assert len(first) == 8
    open_only = api.get(browser, CASES, CASES, status="open", limit=2).json()
    assert all(item["status"] == "open" for item in open_only["items"])
    in_progress = api.get(browser, CASES, CASES, status="in_progress").json()
    assert [i["case_id"] for i in in_progress["items"]] == [expected[0]] and in_progress["next_cursor"] is None
    # A cursor is bound to its filter and workspace.
    assert_error(api.get(browser, CASES, CASES, status="resolved", cursor=open_only["next_cursor"]), 422,
                 "invalid_input", "api.invalid_cursor")
    assert_error(api.get(browser, CASES, CASES, cursor=open_only["next_cursor"]), 422, "invalid_input",
                 "api.invalid_cursor")
    _, other = team(api, "other")
    assert_error(api.get(other, CASES, CASES, status="open", cursor=open_only["next_cursor"]), 422,
                 "invalid_input", "api.invalid_cursor")
    for limit in (0, 101, -1, "x"):
        assert_error(api.get(browser, CASES, CASES, limit=limit), 422, "invalid_input", "api.invalid_input")
    assert_error(api.get(browser, CASES, CASES, status="archived"), 422, "invalid_input", "api.invalid_input")


def test_tampered_cursors_are_refused_safely(api: CaseApi) -> None:
    import base64
    import json

    _, browser = team(api)
    for _ in range(3):
        new_case(api, browser)
    cursor = api.get(browser, CASES, CASES, limit=1).json()["next_cursor"]
    payload = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))

    def encode(value: Any, *, pad: bool = False) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()
        return raw if pad else raw.rstrip("=")

    tampered = [
        encode({**payload, "v": True}), encode({**payload, "v": 1}),
        encode({**payload, "v": "policyops.case-cursor/v2"}),
        encode({**payload, "i": 5}), encode({**payload, "i": "not-a-uuid"}), encode({**payload, "i": None}),
        encode({**payload, "w": str(uuid4())}), encode({**payload, "c": "2026-03-01T09:00:00"}),
        encode({**payload, "c": "yesterday"}), encode({**payload, "c": 1}), encode({**payload, "s": "open"}),
        encode({**payload, "x": 1}), encode({k: v for k, v in payload.items() if k != "i"}), encode([payload]),
        encode("text"), encode(None), cursor + "A", cursor.replace("-", "+").replace("_", "/") + "==",
        "!!!!", "a" * 401, "é" * 10, encode(payload, pad=True),
    ]
    for value in tampered:
        if value == cursor:
            continue
        assert_error(api.get(browser, CASES, CASES, limit=1, cursor=value), 422, "invalid_input",
                     "api.invalid_cursor" if len(value) <= 400 else "api.invalid_input")
    assert api.get(browser, CASES, CASES, limit=1, cursor=cursor).status_code == 200


def test_message_pages(api: CaseApi) -> None:
    _, browser = team(api)
    case = new_case(api, browser)["case_id"]
    for index in range(5):
        assert api.post(browser, case, f"m{index}", f'"{index + 1}"').status_code == 201
    path = f"{CASES}/{case}/messages"
    first = api.get(browser, path, MESSAGES, limit=2).json()
    assert [m["sequence"] for m in first["items"]] == [1, 2] and first["next_after_sequence"] == 2
    rest = api.get(browser, path, MESSAGES, after_sequence=2, limit=200).json()
    assert [m["sequence"] for m in rest["items"]] == [3, 4, 5] and rest["next_after_sequence"] is None
    assert api.get(browser, path, MESSAGES, after_sequence=5).json() == {"items": [], "next_after_sequence": None}
    for params in ({"limit": 201}, {"limit": 0}, {"after_sequence": -1}, {"after_sequence": "x"}):
        assert_error(api.get(browser, path, MESSAGES, **params), 422, "invalid_input", "api.invalid_input")


# -- revocation after waiting, and rollback ---------------------------------------------------------------------

@contextmanager
def held(api: CaseApi, sql: str, *params: Any) -> Iterator[None]:
    """Hold a lock in a separate superuser transaction until the block exits."""
    with api.db.superuser() as conn, conn.transaction():
        conn.execute(sql, params)
        yield


def wait_for_lock_waiter(api: CaseApi) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if api.scalar("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                      "AND wait_event_type = 'Lock'"):
            return
        time.sleep(0.05)
    raise AssertionError("the request never waited for the lock")


def revoke(api: CaseApi, workspace: UUID, membership: UUID) -> None:
    with workspace_transaction(api.runtime.app_engine, workspace) as conn:
        assert repo.revoke_membership(conn, membership, api.clock.now())


def background(call: Callable[[], Reply]) -> tuple[threading.Thread, list[Reply]]:
    out: list[Reply] = []
    thread = threading.Thread(target=lambda: out.append(call()))
    thread.start()
    return thread, out


def test_membership_revoked_while_waiting_for_the_case_lock(api: CaseApi) -> None:
    workspace, owner = team(api)
    case = new_case(api, owner)["case_id"]
    who = subject()
    browser = api.member(who, workspace, "analyst")
    membership = api.rows("SELECT id FROM identity.memberships WHERE principal_id = %s", api.principal(who))[0][0]
    before = counts(api, workspace)
    with held(api, "SELECT 1 FROM app.cases WHERE id = %s FOR UPDATE", UUID(case)):
        thread, out = background(lambda: api.patch(browser, case, "in_progress", '"1"'))
        wait_for_lock_waiter(api)
        revoke(api, workspace, membership)
    thread.join(timeout=30)
    assert_error(out[0], 403, "forbidden", "auth.membership")
    assert counts(api, workspace) == before


def test_membership_revoked_while_waiting_for_the_key_gets_no_replay(api: CaseApi) -> None:
    workspace, _ = team(api)
    who = subject()
    browser = api.member(who, workspace, "analyst")
    principal = api.principal(who)
    membership = api.rows("SELECT id FROM identity.memberships WHERE principal_id = %s", principal)[0][0]
    original = api.create(browser, key="revoked-replay-1")
    assert original.status_code == 201
    scope = f"idempotency:{workspace}:{principal}:case.create:revoked-replay-1"
    with held(api, "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", scope):
        thread, out = background(lambda: api.create(browser, key="revoked-replay-1"))
        wait_for_lock_waiter(api)
        revoke(api, workspace, membership)
    thread.join(timeout=30)
    assert_error(out[0], 403, "forbidden", "auth.membership")
    assert original.json()["case_id"] not in out[0].text


def test_failure_after_the_mutation_rolls_everything_back(api: CaseApi, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    before = counts(api, workspace)
    failing = TestClient(api.app, base_url=case_api.ORIGIN, follow_redirects=False, raise_server_exceptions=False)
    for name, value in browser.cookies.items():
        failing.cookies.set(name, value)
    failing.headers.update(api.context(browser))

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("ledger write failed")

    monkeypatch.setattr(idem, "store", boom)
    key = new_key()
    for response in (api.post(failing, case, "never stored", '"1"', key=key),
                     api.patch(failing, case, "in_progress", '"1"'), api.create(failing)):
        assert_error(response, 500, "internal", "api.internal", echo="ledger")
    assert counts(api, workspace) == before
    monkeypatch.undo()
    retried = api.post(browser, case, "never stored", '"1"', key=key)  # nothing was recorded for the key
    assert retried.status_code == 201 and "idempotent-replayed" not in retried.headers
    assert retried.json()["message"]["sequence"] == 1 and retried.json()["case"]["version"] == 2


# -- refusal order, raw ASGI boundaries and stored rows the API does not create ------------------------------

def test_refusal_order_around_authorization(api: CaseApi) -> None:
    workspace, owner = team(api)
    case = new_case(api, owner)["case_id"]
    anonymous = api.browser()
    path = f"{CASES}/{case}/messages"
    schema_invalid = {"source": "agent", "text": 5, "extra": True}
    # Body model validation comes after authorization ...
    assert_error(api.call(anonymous, "POST", CASES, CASES, json={"scenario": "x"}, key=new_key()), 401,
                 "unauthenticated", "auth.session")
    auditor = api.member(subject(), workspace, "auditor")
    assert_error(api.call(auditor, "POST", path, MESSAGES, json=schema_invalid, key=new_key(), if_match='"1"'),
                 403, "forbidden", "auth.role")
    assert_error(api.call(auditor, "PATCH", f"{CASES}/{case}", CASE, json={"status": "x"}), 403, "forbidden",
                 "auth.role")
    # ... and so does header parsing; but undecodable or malformed JSON is refused while reading the body.
    assert_error(api.call(anonymous, "PATCH", f"{CASES}/{case}", CASE, json={"status": "resolved"}), 401,
                 "unauthenticated", "auth.session")
    assert_error(api.call(anonymous, "POST", CASES, CASES, content=b'{"scenario":', key=new_key(),
                          headers={"Content-Type": "application/json"}), 422, "invalid_input", "api.invalid_input")
    assert_error(api.call(anonymous, "POST", CASES, CASES, content=b'{"scenario":"\xff"}', key=new_key(),
                          headers={"Content-Type": "application/json"}), 400, "invalid_input", "api.http_400")
    assert counts(api, workspace) == {"cases": 1, "messages": 0, "audit": 1, "ledger": 1, "version_sum": 1}


def test_a_stored_non_retail_case_is_reported_as_stored(api: CaseApi) -> None:
    """The API creates only retail cases; a row from another (trusted) path keeps its own scenario label."""
    workspace, browser = team(api)
    case_id = uuid4()
    with api.db.superuser() as conn:
        conn.execute("INSERT INTO app.cases (id, workspace_id, scenario, status, customer_user_id, created_by, "
                     "created_at, updated_at, version) VALUES (%s, %s, 'banking_knowledge', 'open', NULL, NULL, "
                     "%s, %s, 1)", (case_id, workspace, case_api.START, case_api.START))
    fetched = api.case(browser, case_id).json()
    assert fetched["scenario"] == "banking_knowledge" and fetched["status"] == "open"
    assert api.get(browser, CASES, CASES).json()["items"][0]["scenario"] == "banking_knowledge"
    changed = api.patch(browser, case_id, "in_progress", '"1"')
    assert changed.status_code == 200 and changed.json()["scenario"] == "banking_knowledge"


def asgi_request(app: Any, method: str, path: str, headers: list[tuple[bytes, bytes]],
                 chunks: list[bytes]) -> tuple[int, dict[str, str], bytes, int]:
    """Drive the ASGI app directly (no client normalization); return status, headers, body and chunks pulled."""
    import asyncio

    pulled = 0
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal pulled
        if pulled < len(chunks):
            pulled += 1
            return {"type": "http.request", "body": chunks[pulled - 1], "more_body": pulled < len(chunks)}
        if not chunks and pulled == 0:
            pulled = 0
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)  # a client that never finishes
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
             "headers": [(b"host", b"127.0.0.1:8000"), *headers], "client": ("127.0.0.1", 5000),
             "server": ("127.0.0.1", 8000)}
    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=30))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], {k.decode().lower(): v.decode() for k, v in start["headers"]}, body, pulled


def raw_headers(browser: TestClient, *extra: tuple[str, str]) -> list[tuple[bytes, bytes]]:
    cookie = "; ".join(f"{name}={value}" for name, value in browser.cookies.items())
    base = [("cookie", cookie), ("origin", case_api.ORIGIN), ("x-csrf-token", browser.cookies.get(
        case_api.CSRF_COOKIE) or ""), ("content-type", "application/json"),
            *((name.lower(), browser.headers[name]) for name in case_api.CONTEXT_HEADERS)]
    return [(k.encode(), v.encode()) for k, v in (*base, *extra)]


def test_raw_asgi_body_and_header_boundaries(api: CaseApi) -> None:
    import json

    workspace, browser = team(api)
    case = new_case(api, browser)["case_id"]
    path = f"{CASES}/{case}/messages"
    note = json.dumps({"source": "staff_note", "text": "raw"}).encode()

    def post(*extra: tuple[str, str], chunks: list[bytes] | None = None) -> tuple[int, dict[str, str], bytes, int]:
        version = api.case(browser, case).headers["etag"]
        headers = raw_headers(browser, ("idempotency-key", new_key()), ("if-match", version), *extra)
        return asgi_request(api.app, "POST", path, headers, [note] if chunks is None else chunks)

    status, _, _, _ = post(("content-length", str(len(note))))
    assert status == 201
    # A declared length over the limit is refused without reading the body.
    status, headers, body, pulled = post(("content-length", "65537"), chunks=[b" " * 10])
    assert (status, pulled, json.loads(body)["rule_id"]) == (413, 0, "api.http_413")
    assert headers["cache-control"] == "no-store"
    # Omitted or understated lengths: the received bytes are counted, and reading stops at the overflow.
    for declared in ((), (("content-length", "10"),)):
        chunks = [note[:-1]] + [b" " * 8192] * 20 + [b"}"]
        status, _, body, pulled = post(*declared, chunks=chunks)
        assert (status, json.loads(body)["rule_id"]) == (413, "api.http_413")
        assert pulled == 9  # the first chunk and 8 padding chunks: the 8th crosses 64 KiB; never all 22
    exact = [note[:-1], b" " * (65536 - len(note)), b"}"]
    assert sum(map(len, exact)) == 65536
    status, _, _, _ = post(chunks=exact)
    assert status == 201
    for extra in ((("content-length", "12"), ("content-length", "12")), (("content-length", "1e3"),),
                  (("content-length", "-1"),), (("content-length", " 12"),), (("content-length", "9" * 20),)):
        status, _, body, pulled = post(*extra)
        assert (status, json.loads(body)["rule_id"], pulled) == (400, "api.http_400", 0)
    status, _, body, _ = asgi_request(api.app, "GET", "/api/v1/health/live", [(b"content-length", b"x")], [])
    assert (status, json.loads(body)["rule_id"]) == (400, "api.http_400")
    # Repeated precondition and key headers are refused, not merged.
    status, _, body, _ = post(("if-match", '"1"'))
    assert (status, json.loads(body)["rule_id"]) == (422, "api.invalid_precondition")
    status, _, body, _ = post(("idempotency-key", new_key()))
    assert (status, json.loads(body)["rule_id"]) == (422, "api.invalid_idempotency_key")
    non_ascii = [*raw_headers(browser, ("if-match", '"3"')), (b"idempotency-key", "ключ-ключ-ключ".encode())]
    status, _, body, _ = asgi_request(api.app, "POST", path, non_ascii, [note])
    assert (status, json.loads(body)["rule_id"]) == (422, "api.invalid_idempotency_key")
    assert counts(api, workspace)["messages"] == 2


def test_actual_responses_type_check_against_the_generated_types(api: CaseApi, tmp_path: Any) -> None:
    """Real bodies of every operation family (successes, replays and error envelopes) compile against the
    generated TypeScript; a body with a missing field or an undocumented extra one does not."""
    from policyops_testing import ts_samples
    from policyops_testing.case_api import Recorded

    workspace, browser = team(api)
    admin = api.member(subject(), workspace, "admin")
    case = new_case(api, browser)["case_id"]
    key = new_key()
    api.patch(browser, case, "in_progress", '"1"', key=key)
    api.patch(browser, case, "in_progress", '"1"', key=key)  # replay
    api.post(browser, case, "typed \U0001F600 note", '"2"')
    api.post(browser, case, "customer", '"3"', source="operator_entered_customer")
    api.get(browser, CASES, CASES, limit=1)
    api.get(browser, f"{CASES}/{case}/messages", MESSAGES, limit=1)
    api.case(browser, case)
    api.get(browser, "/api/v1/me", "/api/v1/me")
    api.get(admin, "/api/v1/workspace/members", "/api/v1/workspace/members")
    api.patch(browser, case, "open", '"4"')                         # 409 transition
    api.patch(browser, case, "resolved", None)                     # 428
    api.post(browser, str(uuid4()), "x", '"1"')                    # 404
    api.get(api.browser(), CASES, CASES)                           # 401
    api.get(browser, CASES, CASES, cursor="!!!!")                  # 422
    api.call(browser, "POST", CASES, CASES, json={"scenario": "retail"})  # 400
    leaving = api.signed_in(subject())
    logout = api.call(leaving, "POST", "/api/v1/auth/logout", "/api/v1/auth/logout")
    probe = api.browser()
    api.get(probe, "/api/v1/auth/login", "/api/v1/auth/login", return_to="/cases")
    refused = api.get(probe, "/api/v1/auth/callback", "/api/v1/auth/callback", state="not-a-state", code="x")
    assert logout.status_code == 204 and "set-cookie" in logout.headers
    assert refused.status_code == 401 and "set-cookie" in refused.headers  # the login binding is cleared
    statuses = {(r.operation_id, r.status) for r in api.recorded}
    assert {("create_case", 201), ("change_status", 200), ("post_message", 201), ("list_cases", 200),
            ("list_messages", 200), ("get_case", 200), ("me", 200), ("members", 200), ("change_status", 409),
            ("change_status", 428), ("post_message", 404), ("list_cases", 401), ("list_cases", 422),
            ("create_case", 400), ("login", 302), ("callback", 303), ("callback", 401), ("logout", 204),
            ("select_workspace", 204)} <= statuses
    try:
        compiled = ts_samples.compile_samples(api.recorded, tmp_path / "good")
    except ts_samples.ToolchainMissing as exc:
        pytest.fail(f"TypeScript sample check: {exc}")
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    view = next(r for r in api.recorded if r.operation_id == "get_case" and r.status == 200)
    broken = [Recorded("get_case", 200, {k: v for k, v in view.body.items() if k != "version"}),
              Recorded("get_case", 200, {**view.body, "workspace_id": str(workspace)}),
              Recorded("get_case", 200, {**view.body, "status": "archived"})]
    for index, sample in enumerate(broken):
        rejected = ts_samples.compile_samples([sample], tmp_path / f"bad{index}")
        assert rejected.returncode != 0 and "samples.ts" in rejected.stdout, rejected.stdout


def test_the_in_transaction_recheck_uses_only_the_selected_workspace_roles(api: CaseApi) -> None:
    """A stale or forged authorization (analyst) for a workspace where the principal is now only an auditor is
    refused by the service's own recheck, although the principal is an analyst in another workspace."""
    from policyops.auth.service import AuthError, Authorized, SessionContext
    from policyops.domain.roles import Role
    from policyops.services.cases import CaseService

    alpha, beta = api.workspace("alpha"), api.workspace("beta")
    who = subject()
    api.member(who, alpha, "auditor")
    api.grant(who, beta, "analyst")
    principal = api.principal(who)
    session = SessionContext(session_id=uuid4(), principal_id=principal, workspace_id=alpha,
                             expires_at=case_api.START + timedelta(hours=1), csrf_sha256="0" * 64)
    forged = Authorized(session=session, workspace_id=alpha, roles=frozenset({Role.ANALYST}))
    service = CaseService(app_engine=api.runtime.app_engine, clock=api.clock)
    with pytest.raises(AuthError) as refused:
        service.create_case(forged, key=new_key())
    assert (refused.value.status, refused.value.rule_id) == (403, "auth.role")
    assert counts(api, alpha)["cases"] == 0
