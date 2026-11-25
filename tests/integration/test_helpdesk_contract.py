"""N11 acceptance on real PostgreSQL runtime roles and a fake Zammad transport."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta
from threading import Barrier
from typing import Any
from uuid import UUID, uuid4, uuid5

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from policyops.adapters.retail_client import Unknown
from policyops.api.body_limit import BodyLimit
from policyops.api.helpdesk import build_router
from policyops.gateway.facts import Collected, collect
from policyops.persistence import customer_authentications, executions, runs
from policyops.persistence import helpdesk as store
from policyops.persistence import repositories as repo
from policyops.persistence.database import sqlstate, transaction, workspace_transaction
from policyops.persistence.migration_guard import DataLossRefused
from policyops.persistence.records import Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops.runtime.clock import FixedLeaseClock
from policyops.runtime.helpdesk import HelpdeskWorker
from policyops.runtime.review import BoundScopes, ProjectOutcome, build_review_runtime
from policyops.services.execution import LedgerHistory
from policyops.services.helpdesk_inbound import Inbound
from policyops.services.helpdesk_writeback import QUIESCENCE
from policyops.services.proposals import Created, Presented, ProposalService
from policyops.settings import HelpdeskSettings
from policyops_contracts.clock import FixedClock
from policyops_contracts.digest import text_sha256
from policyops_contracts.retail import FindUserIdByEmail, GetUserDetails
from policyops_contracts.retail_service import FIXTURE_SHA256, UserIdOutput, UserOutput
from policyops_contracts.scalars import CaseScope, RunScope
from policyops_contracts.seeds import CustomerAuthentication
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.zammad import NOW, FakeZammad, settings, sign, webhook
from tests.integration import test_execution_retail as retail_tests
from tests.integration.test_proposal_decisions import grant, principal
from tests.integration.test_review_continuation import job_of, run_state
from tests.integration.test_review_outcomes import decide, post


pytestmark = pytest.mark.postgres
env = retail_tests.env
live = retail_tests.live


def workspace(database: AppDatabase) -> UUID:
    identity = uuid4()
    with transaction(database.engine(AUTH_RUNTIME)) as connection:
        repo.create_workspace(connection, Workspace(
            id=identity, slug=f"n11-{identity.hex}", name="Fictional help desk", created_at=NOW))
    return identity


def bind(app: Engine, config: HelpdeskSettings, *, customer: str = "james_johnson_9321", requester: int = 11) -> None:
    [endpoint] = config.connections
    with workspace_transaction(app, endpoint.workspace_id) as connection:
        store.seed_binding(connection, workspace=endpoint.workspace_id, connection_id=endpoint.connection_id,
                          requester_id=requester, customer=customer, seed_id="retail-demo-9999", now=NOW)


def signed(service: Inbound, body: bytes, delivery: bytes = b"delivery") -> int:
    [config] = service.settings.connections
    return service.receive(config.connection_id, body, [sign(config, body)], [delivery])


def ids(app: Engine, tenant: UUID, queue: store.Queue) -> list[UUID]:
    with workspace_transaction(app, tenant) as connection:
        query = text(f"SELECT id FROM app.{queue} ORDER BY created_at, id")  # noqa: S608
        return list(connection.execute(query).scalars())


def state(app: Engine, tenant: UUID, queue: store.Queue, identity: UUID) -> tuple[str, str | None]:
    with workspace_transaction(app, tenant) as connection:
        row = store.lock_row(connection, queue, identity)
        assert row is not None
        return row.state, row.reason


def test_inbox_redelivery_revives_in_place_up_to_cap(new_app_database: NewDatabase) -> None:
    db = new_app_database("helpdesk_revival")
    tenant = workspace(db)
    app = db.engine(APP_RUNTIME)
    cfg = settings(tenant)
    bind(app, cfg)
    clock = FixedClock(NOW)
    lease = FixedLeaseClock(clock)
    ingress = Inbound(cfg, app, lease)
    fake = FakeZammad(cfg.connections[0])
    worker = HelpdeskWorker(env="test", app=app, discovery=db.engine(WORKER_DISCOVERY),
                            settings=cfg, clock=lease, transport=fake.transport)
    queue = store.Queue.EVENTS

    def status(identity: UUID) -> tuple[str, str | None, int, int, int, datetime]:
        with workspace_transaction(app, tenant) as connection:
            row = store.lock_row(connection, queue, identity)
            assert row is not None
            return row.state, row.reason, row.attempts, row.revivals, row.version, row.next_attempt_at

    raw = webhook()
    assert signed(ingress, raw) == 202
    [original] = ids(app, tenant, queue)
    fake.lookup_outage = True
    for _ in range(store.EVENT_ATTEMPTS):
        worker.run_once()
        clock.advance(timedelta(minutes=1))
    failed = status(original)
    assert failed[:4] == ("failed", "pre_send", store.EVENT_ATTEMPTS, 0)

    fake.lookup_outage = False
    assert signed(ingress, raw, b"recovery") == 202
    assert ids(app, tenant, queue) == [original]
    assert status(original) == ("pending", None, 0, 1, failed[4] + 1, clock.now())
    worker.run_once()
    applied = status(original)
    assert applied[:4] == ("applied", None, 1, 1)
    with workspace_transaction(app, tenant) as connection:
        case_id = connection.execute(text("SELECT case_id FROM app.helpdesk_ticket_links")).scalar_one()
        scope = CaseScope(workspace_id=tenant, case_id=case_id)
        assert [message.text for message in repo.list_messages(connection, scope)] == ["yes"]
    assert signed(ingress, raw, b"after-applied") == 202
    assert status(original) == applied

    fake.articles = [fake.articles[0] | {"id": n} for n in range(1, 202)]
    oversized = webhook(updated_at=clock.now())
    assert signed(ingress, oversized) == 202
    [_, capped] = ids(app, tenant, queue)
    for revival in range(store.EVENT_REVIVALS + 1):
        worker.run_once()
        terminal = status(capped)
        assert terminal[:4] == ("incomplete_scan", "incomplete_scan", 1, revival)
        assert signed(ingress, oversized) == 202
        expected = (terminal if revival == store.EVENT_REVIVALS
                    else ("pending", None, 0, revival + 1, terminal[4] + 1, clock.now()))
        assert status(capped) == expected


def test_inbox_race_mapping_order_and_fenced_older_fetch(new_app_database: NewDatabase) -> None:
    db = new_app_database("helpdesk_inbox")
    tenant = workspace(db)
    app = db.engine(APP_RUNTIME, pool_size=6)
    cfg = settings(tenant)
    bind(app, cfg)
    clock = FixedClock(NOW)
    lease = FixedLeaseClock(clock)
    ingress = Inbound(cfg, app, lease)
    fake = FakeZammad(cfg.connections[0])
    workers = [HelpdeskWorker(env="test", app=app, discovery=db.engine(WORKER_DISCOVERY),
                             settings=cfg, clock=lease, transport=fake.transport) for _ in range(2)]
    queue = store.Queue.EVENTS
    raw = webhook()
    barrier = Barrier(2)

    def submit(delivery: bytes) -> int:
        barrier.wait(timeout=5)
        return signed(ingress, raw, delivery)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(submit, [b"first", b"second"])) == [202, 202]
    [original] = ids(app, tenant, queue)
    assert workers[0].process_event(tenant, original)
    assert state(app, tenant, queue, original) == ("applied", None)
    with workspace_transaction(app, tenant) as connection:
        case_id = connection.execute(text("SELECT case_id FROM app.helpdesk_ticket_links")).scalar_one()
        scope = CaseScope(workspace_id=tenant, case_id=case_id)
        case = repo.get_case(connection, case_id)
        assert case is not None and case.created_by is None
        assert [(message.source, message.text) for message in repo.list_messages(connection, scope)] == [
            ("helpdesk_ticket", "yes")]
        assert connection.execute(text("SELECT count(*) FROM app.customer_consents")).scalar_one() == 0

    # A worker returns an old snapshot after another fetch advanced the link.
    def event() -> UUID:
        clock.advance(timedelta(seconds=1))
        assert signed(ingress, webhook(updated_at=clock.now())) == 202
        return ids(app, tenant, queue)[-1]

    older = event()
    newer = event()
    older_ticket = dict(fake.ticket)

    def delayed(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tickets/42"):
            return httpx.Response(200, json=older_ticket)
        fake.ticket.update(state_id=8, updated_at=clock.now().isoformat())
        assert workers[1].process_event(tenant, newer)
        return fake.handle(request)

    workers[0].transport = httpx.MockTransport(delayed)
    assert workers[0].process_event(tenant, older)
    assert state(app, tenant, queue, older) == ("stale", None)
    workers[0].transport = fake.transport
    with workspace_transaction(app, tenant) as connection:
        assert connection.execute(text("SELECT state_id FROM app.helpdesk_ticket_links")).scalar_one() == 8

    fenced = event()

    def overrun(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tickets/42"):
            return httpx.Response(200, json=older_ticket)
        clock.advance(store.LEASE)
        fake.ticket.update(state_id=9, updated_at=clock.now().isoformat())
        assert workers[1].process_event(tenant, fenced)
        return fake.handle(request)

    workers[0].transport = httpx.MockTransport(overrun)
    assert workers[0].process_event(tenant, fenced)
    assert state(app, tenant, queue, fenced) == ("applied", None)
    workers[0].transport = fake.transport

    for fields, expected in [
        ({"group_id": 99}, ("rejected_mapping", "disallowed_group")),
        ({"group_id": 7, "customer_id": 12}, ("rejected_mapping", "requester_changed")),
    ]:
        fake.ticket.update(fields)
        identity = event()
        workers[0].process_event(tenant, identity)
        assert state(app, tenant, queue, identity) == expected
    fake.ticket.update(customer_id=11, updated_at=clock.now().isoformat())
    fake.add("integration echo", article_id=102)
    own_echo = event()
    workers[0].process_event(tenant, own_echo)
    assert state(app, tenant, queue, own_echo) == ("applied", None)
    fake.articles = [fake.articles[0] | {"id": n} for n in range(1, 202)]
    oversized = event()
    workers[0].process_event(tenant, oversized)
    assert state(app, tenant, queue, oversized) == ("incomplete_scan", "incomplete_scan")
    with workspace_transaction(app, tenant) as connection:
        assert len(repo.list_messages(connection, scope)) == 1
        assert connection.execute(text("""
            SELECT count(*) FROM app.audit_events WHERE actor_kind = 'system' AND action = 'helpdesk.rejected_mapping'
        """)).scalar_one() == 2


def test_rls_cross_tenant_fks_discovery_and_downgrade(new_app_database: NewDatabase) -> None:
    db = new_app_database("helpdesk_security")
    db.downgrade("0017")
    assert db.current() == "0017"
    db.upgrade()
    tenant, other = workspace(db), workspace(db)
    app = db.engine(APP_RUNTIME)
    cfg = settings(tenant)
    bind(app, cfg)
    bind(app, settings(other))
    clock = FixedClock(NOW)
    lease = FixedLeaseClock(clock)
    fake = FakeZammad(cfg.connections[0])
    ingress = Inbound(cfg, app, lease)
    worker = HelpdeskWorker(env="test", app=app, discovery=db.engine(WORKER_DISCOVERY), settings=cfg,
                            clock=lease, transport=fake.transport)
    assert signed(ingress, webhook()) == 202
    worker.run_once()
    with workspace_transaction(app, tenant) as connection:
        case_id = connection.execute(text("SELECT case_id FROM app.helpdesk_ticket_links")).scalar_one()
        link = store.case_link(connection, case_id)
        assert link is not None
        message = repo.append_message(connection, message_id=uuid4(), source="agent", entered_by=None,
            scope=CaseScope(workspace_id=tenant, case_id=case_id), text_value="Fixture outcome.", created_at=NOW)
        store.enqueue_writeback(connection, link, message.message_id, NOW)
    with workspace_transaction(app, other) as connection:
        for table in ("helpdesk_events", "helpdesk_ticket_links", "helpdesk_customer_bindings", "helpdesk_writebacks"):
            count = connection.execute(text(f"SELECT count(*) FROM app.{table} WHERE workspace_id = :a"),  # noqa: S608
                                       {"a": tenant}).scalar_one()
            assert count == 0
        with pytest.raises(IntegrityError) as failure, connection.begin_nested():
            connection.execute(text("""
                INSERT INTO app.helpdesk_ticket_links
                (id, workspace_id, connection_id, ticket_id, requester_id, customer_user_id, destination_sha256,
                 case_id, group_id, state_id, ticket_updated_at, max_article_id, created_at)
                VALUES (:id, :workspace, 'fixture', 42, 11, 'james_johnson_9321', :digest, :case, 7, 2, :now, 0, :now)
            """), {"id": uuid4(), "workspace": other, "digest": "a" * 64, "case": case_id, "now": NOW})
        assert sqlstate(failure.value) == "23503"
    with transaction(db.engine(WORKER_DISCOVERY)) as connection:
        assert len(store.due(connection, store.Queue.WRITEBACKS, NOW)) == 1
    with pytest.raises(Exception) as denied, transaction(db.engine(WORKER_DISCOVERY)) as connection:
        connection.execute(text("SELECT payload FROM app.helpdesk_events"))
    assert sqlstate(denied.value) == "42501"

    # The original POST has committed. Another worker claims after expiry and records the remote receipt
    # while the original worker still sees a lost response. Only the current fence may update the local row.
    [operation] = ids(app, tenant, store.Queue.WRITEBACKS)
    restarted = HelpdeskWorker(env="test", app=app, discovery=db.engine(WORKER_DISCOVERY),
                               settings=cfg, clock=lease, transport=fake.transport)

    def commit_then_pause(request: httpx.Request) -> httpx.Response:
        response = fake.handle(request)
        if request.method == "POST":
            clock.advance(store.LEASE)
            assert restarted.process_writeback(tenant, operation)
            raise httpx.ReadTimeout("simulated paused worker response loss", request=request)
        return response

    worker.transport = httpx.MockTransport(commit_then_pause)
    assert worker.process_writeback(tenant, operation)
    assert state(app, tenant, store.Queue.WRITEBACKS, operation) == ("succeeded", None)
    assert len(fake.posts) == 1

    with pytest.raises(DataLossRefused, match="imported help desk messages"):
        db.downgrade("0017", allow_data_loss=True)
    # Migrations run one at a time: 0019's downgrade drops the empty import tables, then 0018 refuses.
    assert db.current() == "0018"


def test_signed_ticket_to_receipt_note_and_outcome_rollback(env: retail_tests.Env,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    tenant, app = env.run.workspace_id, env.app
    cfg = settings(tenant)
    [endpoint] = cfg.connections
    bind(app, cfg, customer=env.customer)
    lease = FixedLeaseClock(env.clock)
    fake = FakeZammad(endpoint)
    inbound = Inbound(cfg, app, lease)
    ingress = FastAPI()
    ingress.add_middleware(BodyLimit)
    ingress.include_router(build_router(inbound), prefix="/api/v1")
    route = "/api/v1/integrations/zammad/fixture/events"
    queue = store.Queue.WRITEBACKS
    discovery = env.db.engine(WORKER_DISCOVERY)
    worker = HelpdeskWorker(env="test", app=app, discovery=discovery, settings=cfg, clock=lease,
                            transport=fake.transport)
    with TestClient(ingress) as http:
        body = webhook(updated_at=env.clock.now())
        assert http.post(route, content=body, headers={"X-Hub-Signature": "invalid"}).status_code == 401
        assert http.post(route, content=body + b" " * 65536).status_code == 413
        assert ids(app, tenant, store.Queue.EVENTS) == []
        headers = {"X-Hub-Signature": sign(endpoint, body).decode()}
        assert http.post(route, content=body, headers=headers).status_code == 202
    [wake] = ids(app, tenant, store.Queue.EVENTS)
    worker.process_event(tenant, wake)
    operator = principal(env.db, "helpdesk-initiator")
    grant(env.db, tenant, operator, "analyst")
    now, run_id = env.clock.now(), uuid4()
    with workspace_transaction(app, tenant) as connection:
        case_id = connection.execute(text("SELECT case_id FROM app.helpdesk_ticket_links")).scalar_one()
        case = repo.lock_case(connection, case_id)
        assert case is not None
        run = runs.create_run(connection, run_id=run_id, workspace_id=tenant, case_id=case_id,
            case_version=case.version, graph_sha256=text_sha256("scripted"), prompt_sha256=text_sha256("no model"),
            config_sha256=text_sha256("helpdesk"), deadline_at=now + timedelta(hours=1), initiated_by=operator, now=now)
        runs.set_state(connection, run, "waiting_approval", now)
    run_scope = RunScope(workspace_id=tenant, run_id=run_id, case_id=case_id)
    resolver = BoundScopes(app, (), FIXTURE_SHA256)
    linked = replace(env, scope=resolver.scope(run_scope))
    with closing(linked.client()) as retail:
        assert not isinstance(retail.initialize(), Unknown)
        user = retail.read(GetUserDetails(user_id=linked.customer))
        assert not isinstance(user, Unknown) and isinstance(user.output, UserOutput)
        call = FindUserIdByEmail(email=user.output.user.email)
        auth = retail.read(call)
        assert not isinstance(auth, Unknown) and isinstance(auth.output, UserIdOutput)
        assert auth.output.user_id == linked.customer
        with workspace_transaction(app, tenant) as connection:
            customer_authentications.record(connection, CustomerAuthentication(
                scope=run_scope, user_id=linked.customer, lookup_tool="find_user_id_by_email",
                lookup_call_sha256=text_sha256(call.model_dump_json()), step_sequence=1, authenticated_at=now))
        facts = collect(retail, linked.scope, retail_tests.CANCEL, LedgerHistory(app, run_scope))
    assert isinstance(facts, Collected)
    proposals = ProposalService(app, lease)
    made = proposals.create(linked.scope, retail_tests.CANCEL, facts, rationale="Fictional request.")
    assert isinstance(made, Created)
    proposal = made.proposal
    assert isinstance(proposals.present(run_scope, proposal.proposal_id, proposal.proposal_version), Presented)

    env.clock.advance(timedelta(seconds=1))
    fake.add("yes", article_id=102, author=11, internal=False)
    assert signed(inbound, webhook(updated_at=env.clock.now())) == 202
    for identity in ids(app, tenant, store.Queue.EVENTS):
        worker.process_event(tenant, identity)
    with workspace_transaction(app, tenant) as connection:
        article = repo.list_messages(connection, CaseScope(workspace_id=tenant, case_id=case_id))[-1]
        assert article.text == "yes" and article.source == "helpdesk_ticket"
    proposals.record_customer_reply(run_scope, article.message_id)
    with workspace_transaction(app, tenant) as connection:
        assert connection.execute(text("SELECT count(*) FROM app.customer_consents")).scalar_one() == 0
        with pytest.raises(IntegrityError) as bad_source, connection.begin_nested():
            connection.execute(text("""
                INSERT INTO app.customer_consents
                (id, workspace_id, case_id, run_id, proposal_id, proposal_version, action_digest,
                 presentation_sha256, presented_message_sequence, customer_message_id, customer_message_sequence,
                 customer_message_sha256, message_source, basis, confirmed_at, expires_at)
                SELECT :id, p.workspace_id, p.case_id, p.run_id, p.proposal_id, p.proposal_version,
                       p.action_digest, p.presentation_sha256, p.message_sequence, :message, :seq, :sha,
                       'helpdesk_ticket', 'explicit_affirmation', :now, :expires
                FROM app.proposal_presentations p WHERE p.proposal_id = :proposal
            """), {"id": uuid4(), "message": article.message_id, "seq": article.sequence, "sha": article.text_sha256,
                   "now": env.clock.now(), "expires": env.clock.now() + timedelta(minutes=1),
                   "proposal": proposal.proposal_id})
        assert sqlstate(bad_source.value) == "23514"
        assert "customer_consents_source_values" in str(bad_source.value.orig)
    env.clock.advance(timedelta(seconds=1))
    post(linked)
    decide(linked, proposal)
    review = build_review_runtime(env="test", app_engine=app, bindings=(), fixture_sha256=FIXTURE_SHA256,
        retail_origin=linked.origin, retail_key=linked.service.key, clock=lease, helpdesk_settings=cfg)
    assert review.process(job_of(linked).id, tenant, uuid4())
    with workspace_transaction(app, tenant) as connection:
        [execution] = executions.case_executions(connection, case_id)
    dispatcher = linked.dispatcher()
    dispatcher.executor.scopes = resolver
    assert dispatcher.executor.step(tenant, execution.id).state == "succeeded"
    outcome = job_of(linked, "outcome")
    token = review.claim(outcome.id, tenant, uuid4())
    assert token is not None

    def abort(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("abort after inserting the outbox row")

    with monkeypatch.context() as scoped, pytest.raises(RuntimeError, match="abort after"):
        scoped.setattr(runs, "end_job", abort)
        review.finish(token, ProjectOutcome())
    assert ids(app, tenant, queue) == [] and run_state(linked) == "reconciling"
    review.finish(token, ProjectOutcome())
    [operation] = ids(app, tenant, queue)
    with workspace_transaction(app, tenant) as connection:
        row = store.lock_row(connection, queue, operation)
        assert row is not None and operation == uuid5(row.link_id, str(row.outcome_message_id))
        assert connection.execute(text("SELECT model_calls FROM app.runs WHERE id = :id"),
                                  {"id": run_id}).scalar_one() == 0
    fake.fault = "lost"
    assert worker.process_writeback(tenant, operation)
    assert state(app, tenant, queue, operation) == ("dispatching", "unavailable")
    restarted = HelpdeskWorker(env="test", app=app, discovery=discovery, settings=cfg, clock=lease,
                               transport=fake.transport)
    assert not restarted.process_writeback(tenant, operation)
    env.clock.advance(QUIESCENCE)
    assert restarted.process_writeback(tenant, operation)
    assert len(fake.posts) == 1 and linked.effects() == 1 and run_state(linked) == "succeeded"
    with workspace_transaction(app, tenant) as connection:
        row = store.lock_row(connection, queue, operation)
        assert row is not None and (row.state, row.article_id) == ("succeeded", fake.articles[-1]["id"])
