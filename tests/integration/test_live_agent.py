"""The local profile across the workbench API, worker, ledger and owned retail simulator."""

from collections import deque
from contextlib import closing
from dataclasses import replace
from decimal import Decimal
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
import shutil
import time
from uuid import UUID, uuid4, uuid5

import httpx2
from pydantic import SecretStr
import pytest

from policyops.adapters.retail_client import Unknown
from policyops.persistence import executions
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Principal, Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops.providers.calls import Providers
from policyops.providers.tokenizer import VOCABULARY_FILE, default_vocabulary_path
from policyops.runtime import live_agent
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.runtime.executions import build_execution_dispatcher
from policyops.runtime.review import BoundScopes, build_review_runtime
from policyops.runtime.spec import binding
from policyops.runtime.worker import build_worker
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail import GetOrderDetails
from policyops_contracts.retail_service import FIXTURE_SHA256, OrderOutput
from policyops_contracts.scalars import CaseScope
from policyops_testing import case_api
from policyops_testing.app_database import NewDatabase
from policyops_testing.corpus_fixtures import CredentialReads, ScriptedEmbeddings
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.safety.retail import Service, reviewed_tree


pytestmark = pytest.mark.postgres


def test_live_profile_from_api_start_to_verified_receipt(postgres: OwnedPostgres, new_app_database: NewDatabase,
                                                         tmp_path: Path) -> None:
    db = new_app_database("live_agent")
    simulator = Service(postgres, db, tmp_path / "retail")
    app = db.engine(APP_RUNTIME, pool_size=8)
    discovery = db.engine(WORKER_DISCOVERY)
    workspace = uuid4()
    # The HTTP harness supplies only OIDC. Use the demo's server-owned seeding identity.
    clock = DatabaseLeaseClock()
    policy = tmp_path / RETAIL_POLICY.path
    policy.parent.mkdir(parents=True)
    shutil.copyfile(reviewed_tree() / RETAIL_POLICY.path, policy)
    shutil.copyfile(default_vocabulary_path(), tmp_path / VOCABULARY_FILE)
    loaded = live_agent.inputs(tmp_path)
    api_catalog = live_agent.catalog(env="test", engine=app, loaded=loaded, workspace=workspace,
                                    providers=live_agent.unavailable_providers)
    api = case_api.build(db, catalog=api_catalog, database_clock=True)
    api.app.include_router(live_agent.usage_router(workspace), prefix="/api/v1", include_in_schema=False)
    with transaction(db.engine(AUTH_RUNTIME)) as connection:
        repo.create_workspace(connection, Workspace(id=workspace, slug="live-" + workspace.hex, name="Live test",
                                                     created_at=case_api.START))
        repo.create_principal(connection, Principal(
            id=uuid5(workspace, "alice"), issuer="https://seed.policyops.invalid", subject="local-seeding-identity",
            display_name="Seed analyst", created_at=case_api.START))

    def align_api_clock() -> None:
        # The harness API clock is fixed; the worker and ledger use the database clock. Consent ordering compares
        # the API-stamped reply with the worker-stamped presentation, so keep the API clock at database time.
        database_now = api.scalar("SELECT clock_timestamp()")
        api.clock.advance(database_now - api.clock.now())

    align_api_clock()
    alice = api.member("live-investigation-analyst", workspace, "analyst")
    bob = api.member("live-investigation-reviewer", workspace, "reviewer")
    embeddings = ScriptedEmbeddings()
    embedding_access = CredentialReads(embeddings)
    maximum = Decimal("0.50")
    generation = live_agent.prepare_corpus(app, workspace, tmp_path, embedding_access, maximum, env="test")
    assert embeddings.requests and embedding_access.reads == 1
    counts = api.scalar("SELECT count(*) FROM app.usage_attempts WHERE workspace_id = %s", workspace)
    assert counts == len(embeddings.requests)
    assert live_agent.prepare_corpus(app, workspace, tmp_path, embedding_access, maximum,
                                     env="test") == generation
    assert embedding_access.reads == 1
    assert api.scalar("SELECT count(*) FROM app.usage_attempts WHERE workspace_id = %s", workspace) == counts

    calls = deque([
        ("find_user_id_by_email", {"email": live_agent.EMAIL}),
        ("get_user_details", {"user_id": live_agent.CUSTOMER}),
        ("get_order_details", {"order_id": live_agent.ORDER}),
        ("search_policy", {"query": "cancel pending orders"}),
        ("cancel_pending_order", {"order_id": live_agent.ORDER, "reason": "no longer needed"}),
    ])
    expected_calls = len(calls)
    paths: list[str] = []

    def respond(request: httpx2.Request) -> httpx2.Response:
        assert request.url.host == "api.openai.com"
        paths.append(request.url.path)
        body = json.loads(request.content)
        assert body["model"] == "gpt-6-luna"
        if request.url.path == "/v1/responses/input_tokens":
            return httpx2.Response(200, json={"object": "response.input_tokens", "input_tokens": 900})
        assert request.url.path == "/v1/responses"
        assert body["reasoning"]["effort"] == "low"
        tool, arguments = calls.popleft()
        sequence = expected_calls - len(calls)
        return httpx2.Response(200, json={
            "id": f"resp_live_script_{sequence}", "object": "response", "model": "gpt-6-luna",
            "status": "completed", "service_tier": "default",
            "output": [{"type": "function_call", "id": f"fc_{sequence}", "call_id": f"call_{sequence}",
                        "status": "completed", "name": tool, "arguments": json.dumps(arguments)}],
            "usage": {"input_tokens": 900, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                      "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8}, "total_tokens": 940},
        })

    def providers() -> Providers:
        return Providers({"openai": SecretStr("synthetic-test-credential")}, lambda _: httpx2.MockTransport(respond))

    with simulator.running() as origin:
        worker_catalog = live_agent.catalog(
            env="test", engine=app, loaded=loaded, workspace=workspace, providers=providers, retail_origin=origin,
            retail_key=simulator.key, clock=clock, aggregate=maximum)
        assert api_catalog.start_spec is not None and worker_catalog.start_spec is not None
        assert binding(api_catalog.start_spec) == binding(worker_catalog.start_spec)
        resolve_case = partial(live_agent.case_binding, workspace=workspace)
        scopes = BoundScopes(app, (), FIXTURE_SHA256, case_binding=resolve_case)
        review = build_review_runtime(env="test", app_engine=app, bindings=(), fixture_sha256=FIXTURE_SHA256,
                                      retail_origin=origin, retail_key=simulator.key, clock=clock)
        review.executor.scopes = scopes
        admission = partial(live_agent.claim_refusal, workspace=workspace, aggregate=maximum,
                            worst=live_agent.preflight(live_agent.configuration()), vocab=loaded[1])
        worker = build_worker(env="test", app_engine=app, discovery_engine=discovery, clock=clock,
                              catalog=worker_catalog, review=review, claim_refusal=admission)
        dispatch = build_execution_dispatcher(env="test", app_engine=app, discovery_engine=discovery,
                                              clock=clock, scopes=scopes, retail=review.executor.retail)
        case = live_agent.seed_case(app, workspace, retail_origin=origin, retail_key=simulator.key)
        started = api.start_run(alice, case, '"1"')
        assert started.status_code == 202
        run = UUID(started.json()["run_id"])
        assert worker.run_once() == 1 and not calls
        assert paths == ["/v1/responses/input_tokens", "/v1/responses"] * expected_calls
        snapshot_path = f"/api/v1/runs/{run}/snapshot"
        snapshot_template = "/api/v1/runs/{run_id}/snapshot"
        waiting = api.get(alice, snapshot_path, snapshot_template).json()
        assert waiting["run"]["state"] == "waiting_approval"
        ref = waiting["proposal_ref"]
        proposal_path = f"/api/v1/proposals/{ref['proposal_id']}"
        detail = api.get(alice, proposal_path, "/api/v1/proposals/{proposal_id}",
                         version=ref["proposal_version"]).json()
        assert detail["proposal"]["evidence"]
        assert detail["proposal"]["action"] == {"tool": "cancel_pending_order", "order_id": live_agent.ORDER,
                                                 "reason": "no longer needed"}
        align_api_clock()
        etag = api.case(alice, case).headers["etag"]
        assert api.post(alice, case, "yes", etag, source="operator_entered_customer").status_code == 201
        decision = api.call(bob, "POST", proposal_path + "/decision", "/api/v1/proposals/{proposal_id}/decision",
                            json={"proposal_version": ref["proposal_version"],
                                  "action_digest": detail["proposal"]["action_digest"], "decision": "approve",
                                  "reason": "Checked the policy and simulated consent."})
        assert decision.status_code == 201

        for _ in range(20):
            worker.run_once()
            dispatch.dispatch_once()
            snapshot = api.get(bob, snapshot_path, snapshot_template).json()
            if snapshot["run"]["state"] == "succeeded":
                break
            time.sleep(0.1)
        assert snapshot["run"]["state"] == "succeeded"
        event = snapshot["latest_review"]["payload"]
        assert event["decision_id"] == decision.json()["approval_id"] and event["reason"] == "committed"
        with workspace_transaction(app, workspace) as connection:
            execution = executions.get(connection, UUID(event["execution_id"]))
        assert execution is not None
        case_scope = CaseScope(workspace_id=workspace, case_id=case)
        with closing(live_agent.client(origin, simulator.key, case_scope, live_agent.CUSTOMER)) as client:
            observed = client.lookup(execution.operation_id, execution.request)
            assert not isinstance(observed, Unknown) and observed.result is not None
            receipt = observed.result.receipt
            assert receipt is not None
            assert event["receipt_sha256"] == sha256(receipt.model_dump_json().encode()).hexdigest()
            order = client.read(GetOrderDetails(order_id=live_agent.ORDER))
            assert not isinstance(order, Unknown) and isinstance(order.output, OrderOutput)
            assert order.output.order.status == "cancelled"
        usage = bob.get(f"/api/v1/live-agent/runs/{run}/usage")
        assert usage.status_code == 200
        assert usage.json()["call_count"] == expected_calls
        assert Decimal(usage.json()["settled_usd"]) > 0 and Decimal(usage.json()["held_usd"]) == 0

        second = live_agent.seed_case(app, workspace, retail_origin=origin, retail_key=simulator.key)
        response = api.start_run(alice, second, '"1"')
        assert response.status_code == 202
        # Enough for one pristine run. The completed model and embedding liabilities consume that headroom.
        constrained = replace(worker, claim_refusal=partial(admission, aggregate=live_agent.preflight(
            live_agent.configuration())))
        assert constrained.run_once() == 0
        refused = api.get(alice, f"/api/v1/runs/{response.json()['run_id']}/snapshot", snapshot_template).json()
        assert refused["run"]["state"] == "failed"
        assert any(e.get("payload", {}).get("rule_id") == "live_agent.aggregate_cap" for e in refused["events"])
        assert len(paths) == 2 * expected_calls
