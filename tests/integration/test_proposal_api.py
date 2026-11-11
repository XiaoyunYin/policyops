"""T18 proposal review routes end to end over HTTP on real PostgreSQL (the production `create_app` composition, actual
auth/app runtime roles, the controlled clock through `catalog=UNCONFIGURED`). Every response is checked against the
committed OpenAPI document by the harness. An unknown COMMIT outcome is produced by explicit test-only fault injection
on the served engine (`CommitFault`), never by a production switch.
"""

from __future__ import annotations

from datetime import timedelta
import hashlib
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import event

from policyops.domain.consent_rules import Consented
from policyops.domain.examples import World
from policyops.gateway.facts import Collected, collect
from policyops.gateway.ports import IncompleteHistory, load_scope
from policyops.persistence import customer_authentications as auth_rows
from policyops.persistence import repositories as repo
from policyops.persistence.database import workspace_transaction
from policyops.persistence.records import NewCase, NewRun
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.spec import UNCONFIGURED
from policyops.services.proposals import Created, Presented, ProposalService
from policyops_contracts.consent import ApprovalDecision
from policyops_contracts.digest import text_sha256
from policyops_contracts.proposal import ActionProposal
from policyops_contracts.retail import CancelPendingOrder
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CaseCustomerBinding, CustomerAuthentication
from policyops_testing import case_api
from policyops_testing.app_database import AppDatabase
from policyops_testing.case_api import CaseApi
from policyops_testing.gateway_cases import FakeRetail, state


pytestmark = pytest.mark.postgres
W = World()
APPROVALS, PROPOSAL, DECISION = "/api/v1/approvals", "/api/v1/proposals/{proposal_id}", \
    "/api/v1/proposals/{proposal_id}/decision"
CASE_PROPOSALS = "/api/v1/cases/{case_id}/proposals"


@pytest.fixture
def api(shared_db: AppDatabase) -> CaseApi:
    return case_api.build(shared_db, catalog=UNCONFIGURED)  # the run/proposal lease clock is the controlled clock


def subject() -> str:
    return f"subject-{uuid4().hex[:12]}"


def consented_proposal(api: CaseApi, workspace: UUID) -> tuple[RunScope, ActionProposal]:
    engine = api.runtime.app_engine
    now = api.clock.now()
    case, run = uuid4(), uuid4()
    with workspace_transaction(engine, workspace) as conn:
        record = repo.create_case(conn, NewCase(id=case, workspace_id=workspace, scenario="retail",
                                                customer_user_id=W.user_id, created_by=None, created_at=now))
        repo.create_run(conn, NewRun(id=run, workspace_id=workspace, case_id=case, case_version=record.version,
                                     mode="workbench", graph_sha256=text_sha256("g"), prompt_sha256=text_sha256("p"),
                                     config_sha256=text_sha256("c"), deadline_at=now + timedelta(hours=2),
                                     created_at=now))
        run_scope = RunScope(workspace_id=workspace, case_id=case, run_id=run)
        auth_rows.record(conn, CustomerAuthentication(
            scope=run_scope, user_id=W.user_id, lookup_tool="find_user_id_by_email",
            lookup_call_sha256=hashlib.sha256(str(run).encode()).hexdigest(), step_sequence=1, authenticated_at=now))
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=workspace, case_id=case), seed_id="retail-demo-9999",
                                  user_id=W.user_id, bound_at=now)
    scope = load_scope(engine, workspace_id=workspace, run_id=run, binding=binding, fixture_sha256=FIXTURE_SHA256)
    call = CancelPendingOrder(order_id=W.order_id, reason="no longer needed")
    collected = collect(FakeRetail(state(), tenant_id=workspace, case_id=case, customer_id=W.user_id), scope, call,
                        IncompleteHistory())
    assert isinstance(collected, Collected)
    service = ProposalService(app_engine=engine, clock=FixedLeaseClock(api.clock))
    created = service.create(scope, call, collected, rationale="Customer asked to cancel.")
    assert isinstance(created, Created)
    proposal = created.proposal
    assert isinstance(service.present(run_scope, proposal.proposal_id, 1), Presented)
    api.clock.advance(timedelta(seconds=1))
    with workspace_transaction(engine, workspace) as conn:
        reply = repo.append_message(conn, message_id=uuid4(), scope=CaseScope(workspace_id=workspace, case_id=case),
                                    source="simulated_customer", entered_by=None, text_value="yes",
                                    created_at=api.clock.now())
    assert isinstance(service.record_customer_reply(run_scope, reply.message_id), Consented)
    return run_scope, proposal


def body(proposal: ActionProposal, **overrides: Any) -> dict[str, Any]:
    return {"proposal_version": proposal.proposal_version, "action_digest": proposal.action_digest,
            "decision": "approve", "reason": "Order and policy checked.", **overrides}


def decide(api: CaseApi, browser: Any, proposal: ActionProposal, **overrides: Any) -> Any:
    return api.call(browser, "POST", f"/api/v1/proposals/{proposal.proposal_id}/decision", DECISION,
                    json=body(proposal, **overrides))


def test_reviewer_inbox_decision_replay_and_detail(api: CaseApi) -> None:
    workspace = api.workspace("t18")
    reviewer_subject = subject()
    reviewer = api.member(reviewer_subject, workspace, "reviewer")
    analyst = api.member(subject(), workspace, "analyst")
    run_scope, proposal = consented_proposal(api, workspace)

    inbox = api.get(reviewer, APPROVALS, APPROVALS)
    assert inbox.status_code == 200
    assert [item["proposal_id"] for item in inbox.json()["items"]] == [str(proposal.proposal_id)]
    assert api.get(analyst, APPROVALS, APPROVALS).status_code == 403  # the inbox is reviewer-only

    first = decide(api, reviewer, proposal)
    assert first.status_code == 201 and "Idempotent-Replayed" not in first.headers
    decision = ApprovalDecision.model_validate_json(first.content)
    assert decision.principal_id == api.principal(reviewer_subject) and decision.decision == "approve"
    again = decide(api, reviewer, proposal)
    assert (again.status_code, again.headers.get("Idempotent-Replayed")) == (200, "true")
    assert again.content == first.content  # the original immutable record, byte for byte

    detail = api.get(analyst, f"/api/v1/proposals/{proposal.proposal_id}", PROPOSAL)
    assert detail.status_code == 200 and "ETag" not in detail.headers
    data = detail.json()
    assert data["proposal"] == proposal.model_dump(mode="json") and data["state"] == "approved"
    assert data["decision"] == decision.model_dump(mode="json")
    history = api.get(analyst, f"/api/v1/cases/{run_scope.case_id}/proposals", CASE_PROPOSALS, limit=1)
    assert history.status_code == 200 and history.json()["next_cursor"] is None
    assert api.get(reviewer, APPROVALS, APPROVALS).json()["items"] == []
    assert api.scalar("SELECT count(*) FROM app.tool_executions WHERE workspace_id = %s", workspace) == 0


def test_refusals_over_http(api: CaseApi) -> None:
    workspace, other_workspace = api.workspace("t18"), api.workspace("other")
    reviewer = api.member(subject(), workspace, "reviewer")
    outsider = api.member(subject(), other_workspace, "reviewer")
    _run, proposal = consented_proposal(api, workspace)
    path = f"/api/v1/proposals/{proposal.proposal_id}/decision"

    no_csrf = api.call(reviewer, "POST", path, DECISION, json=body(proposal), csrf=False)
    assert no_csrf.status_code == 403
    extra = api.call(reviewer, "POST", path, DECISION, json={**body(proposal), "role": "admin"})
    assert extra.status_code == 422
    stringly = api.call(reviewer, "POST", path, DECISION, json=body(proposal, proposal_version="1"))
    assert stringly.status_code == 422
    forged = decide(api, reviewer, proposal, action_digest="0" * 64)
    assert (forged.status_code, forged.json()["rule_id"]) == (409, "api.proposal_digest_mismatch")
    foreign = decide(api, outsider, proposal)
    assert (foreign.status_code, foreign.json()["rule_id"]) == (404, "api.proposal_not_found")
    hidden = api.get(outsider, f"/api/v1/proposals/{proposal.proposal_id}", PROPOSAL)
    assert hidden.status_code == 404
    bad_cursor = api.get(reviewer, APPROVALS, APPROVALS, cursor="not-a-cursor")
    assert (bad_cursor.status_code, bad_cursor.json()["rule_id"]) == (422, "api.invalid_cursor")
    api.clock.advance(timedelta(minutes=16))
    expired = decide(api, reviewer, proposal)
    assert (expired.status_code, expired.json()["rule_id"]) == (409, "api.proposal_expired")
    assert api.scalar("SELECT count(*) FROM app.approval_decisions WHERE workspace_id = %s", workspace) == 0


class CommitFault:
    """Test-only fault injection on the served app's engine: the COMMIT of the next transaction that inserted an
    approval decision raises a driver error, either after the real COMMIT (a lost acknowledgement: the decision is
    durable) or instead of it (the transaction is then rolled back). Nothing else is affected; it fires once."""

    def __init__(self, engine: Any, monkeypatch: pytest.MonkeyPatch, *, committed: bool) -> None:
        self.engine, self.committed, self.fired = engine, committed, 0
        self._pending: set[int] = set()
        dialect = engine.dialect
        original = dialect.do_commit

        def do_commit(connection: Any) -> None:
            key = id(getattr(connection, "dbapi_connection", connection))
            if key not in self._pending or self.fired:
                original(connection)
                return
            self._pending.discard(key)
            self.fired += 1
            if self.committed:
                original(connection)
            raise psycopg.OperationalError("simulated test fault at COMMIT")

        monkeypatch.setattr(dialect, "do_commit", do_commit)
        event.listen(engine, "after_cursor_execute", self._seen)

    def _seen(self, conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, many: bool) -> None:
        if statement.lstrip().startswith("INSERT INTO app.approval_decisions"):
            self._pending.add(id(conn.connection.dbapi_connection))

    def remove(self) -> None:
        event.remove(self.engine, "after_cursor_execute", self._seen)


@pytest.mark.parametrize("committed", [True, False], ids=["lost_acknowledgement", "commit_failed"])
def test_an_unknown_commit_outcome_is_503_and_the_identical_request_recovers(
        api: CaseApi, monkeypatch: pytest.MonkeyPatch, committed: bool) -> None:
    workspace = api.workspace("t18")
    reviewer = api.member(subject(), workspace, "reviewer")
    _run, proposal = consented_proposal(api, workspace)
    decisions = "SELECT count(*) FROM app.approval_decisions WHERE workspace_id = %s"
    fault = CommitFault(api.runtime.app_engine, monkeypatch, committed=committed)
    try:
        unknown = decide(api, reviewer, proposal)
    finally:
        fault.remove()
    assert fault.fired == 1
    envelope = unknown.json()
    assert unknown.status_code == 503 and (envelope["rule_id"], envelope["retryable"]) == (
        "api.decision_outcome_unknown", True)  # never reported as decided
    assert api.scalar(decisions, workspace) == (1 if committed else 0)
    retry = decide(api, reviewer, proposal)  # the documented recovery: resend the identical request
    if committed:
        assert (retry.status_code, retry.headers.get("Idempotent-Replayed")) == (200, "true")
    else:
        assert retry.status_code == 201 and "Idempotent-Replayed" not in retry.headers
    stored = api.scalar("SELECT id FROM app.approval_decisions WHERE workspace_id = %s", workspace)
    assert ApprovalDecision.model_validate_json(retry.content).approval_id == stored
    assert api.scalar(decisions, workspace) == 1
    assert api.scalar("SELECT count(*) FROM app.tool_executions WHERE workspace_id = %s", workspace) == 0
