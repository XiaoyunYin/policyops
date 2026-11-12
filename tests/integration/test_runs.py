"""Runs, leased jobs, fencing, dead letters, cancellation and the outbox (T09) on real PostgreSQL, as the actual
app-runtime and worker-discovery roles, through the served HTTP app (in-process client) and in-process workers.

The executor is the deterministic test-only scripted executor (no model or provider). Time is the controlled
clock unless a test says `database_clock`. The killed-process test runs a real OS worker process.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from functools import partial
import logging
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import pytest

from policyops.persistence import runs as store
from policyops.persistence.database import workspace_transaction
from policyops.persistence.roles import APP_RUNTIME
from policyops.runtime.spec import RuntimeCatalog
from policyops_testing import case_api
from policyops_testing.app_database import AppDatabase, NewDatabase
from policyops_testing.case_api import CaseApi
from policyops_testing.scripted import ScriptedExecutor, scripted_spec


pytestmark = pytest.mark.postgres


def subject() -> str:
    return f"subject-{uuid4().hex[:12]}"


def catalog_of(executor: ScriptedExecutor, **spec: Any) -> RuntimeCatalog:
    built = scripted_spec(executor, **spec)
    return RuntimeCatalog.of([built], default=built.spec_id)


@pytest.fixture
def scripted() -> ScriptedExecutor:
    return ScriptedExecutor(events=2)


@pytest.fixture
def fresh(new_app_database: NewDatabase) -> AppDatabase:
    """A migrated database per test: workers discover every workspace's jobs, so tests must not share them."""
    return new_app_database("runs")


@pytest.fixture
def api(fresh: AppDatabase, scripted: ScriptedExecutor) -> CaseApi:
    return case_api.build(fresh, catalog=catalog_of(scripted))


def built(db: AppDatabase, executor: ScriptedExecutor, **spec: Any) -> tuple[CaseApi, RuntimeCatalog]:
    """An app whose run start uses this executor's spec (a run only runs on the spec of all its digests)."""
    catalog = catalog_of(executor, **spec)
    return case_api.build(db, catalog=catalog), catalog


def team(api: CaseApi, role: str = "analyst") -> tuple[UUID, Any, str]:
    workspace, who = api.workspace("team"), subject()
    return workspace, api.member(who, workspace, role), who


def new_case(api: CaseApi, browser: Any) -> str:
    created = api.create(browser)
    assert created.status_code == 201
    return str(created.json()["case_id"])


def counts(api: CaseApi, workspace: UUID) -> dict[str, int]:
    one = api.scalar
    return {"runs": one("SELECT count(*) FROM app.runs WHERE workspace_id = %s", workspace),
            "jobs": one("SELECT count(*) FROM app.jobs WHERE workspace_id = %s", workspace),
            "events": one("SELECT count(*) FROM app.run_events WHERE workspace_id = %s", workspace),
            "outbox": one("SELECT count(*) FROM app.outbox_events WHERE workspace_id = %s", workspace),
            "ledger": one("SELECT count(*) FROM app.request_idempotency WHERE workspace_id = %s AND run_id IS NOT "
                          "NULL", workspace),
            "audit": one("SELECT count(*) FROM app.audit_events WHERE workspace_id = %s AND target_type = 'run'",
                         workspace)}


def event_types(api: CaseApi, run_id: Any) -> list[tuple[int, str]]:
    return [(s, t) for s, t in api.rows("SELECT sequence, event_type FROM app.run_events WHERE run_id = %s "
                                        "ORDER BY sequence", UUID(str(run_id)))]


def states(api: CaseApi, run_id: Any) -> list[str]:
    rows = api.rows("SELECT payload->>'current' FROM app.run_events WHERE run_id = %s AND event_type = "
                    "'run.state_changed' ORDER BY sequence", UUID(str(run_id)))
    return [state for (state,) in rows]


def job_of(api: CaseApi, run_id: Any) -> dict[str, Any]:
    row = api.rows("SELECT state, attempts, last_error_code, claim_id, lease_owner FROM app.jobs WHERE run_id = %s",
                   UUID(str(run_id)))[0]
    return dict(zip(("state", "attempts", "error", "claim_id", "owner"), row, strict=True))


def run_state(api: CaseApi, run_id: Any) -> str:
    return str(api.scalar("SELECT state FROM app.runs WHERE id = %s", UUID(str(run_id))))


def assert_error(response: Any, status: int, rule_id: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["rule_id"] == rule_id
    assert response.headers["cache-control"] == "no-store"


# -- start, read, idempotency --------------------------------------------------------------------------------

def test_start_is_unavailable_without_an_installed_runtime(fresh: AppDatabase) -> None:
    api = case_api.build(fresh)  # the production default: database clock, empty catalog
    workspace, browser, _ = team(api)
    case = new_case(api, browser)
    refused = api.start_run(browser, case, '"1"')
    assert_error(refused, 503, "runtime.unconfigured")
    assert counts(api, workspace) == {"runs": 0, "jobs": 0, "events": 0, "outbox": 0, "ledger": 0, "audit": 0}


def test_start_creates_run_job_event_outbox_and_audit_atomically(api: CaseApi) -> None:
    workspace, browser, who = team(api)
    case = new_case(api, browser)
    started = api.start_run(browser, case, '"1"', key="run-start-00001")
    assert started.status_code == 202, started.text
    body = started.json()
    assert started.headers["location"] == f"/api/v1/runs/{body['run_id']}"
    assert started.headers["etag"] == f'"{body["version"]}"' and "idempotent-replayed" not in started.headers
    spec = next(iter(catalog_of(ScriptedExecutor(events=2)).specs.values()))
    assert (body["state"], body["mode"], body["case_version"], body["initiated_by"]) == (
        "queued", "workbench", 1, str(api.principal(who)))
    assert (body["graph_sha256"], body["prompt_sha256"], body["config_sha256"]) == (
        spec.graph_sha256, spec.prompt_sha256, spec.config_sha256)
    assert body["event_highwater"] == 1
    assert counts(api, workspace) == {"runs": 1, "jobs": 1, "events": 1, "outbox": 1, "ledger": 1, "audit": 1}
    assert job_of(api, body["run_id"])["state"] == "queued" and states(api, body["run_id"]) == ["queued"]
    assert api.run(browser, body["run_id"]).json() == body
    replay = api.start_run(browser, case, '"1"', key="run-start-00001")
    assert replay.status_code == 202 and replay.content == started.content
    assert replay.headers["idempotent-replayed"] == "true" and replay.headers["location"] == started.headers["location"]
    assert_error(api.start_run(browser, case, '"2"', key="run-start-00001"), 409, "api.idempotency_mismatch")
    assert counts(api, workspace)["runs"] == 1


def test_start_preconditions_and_one_active_run(api: CaseApi) -> None:
    workspace, browser, _ = team(api)
    case = new_case(api, browser)
    assert_error(api.start_run(browser, case, None), 428, "api.precondition_required")
    assert api.patch(browser, case, "in_progress", '"1"').status_code == 200
    assert_error(api.start_run(browser, case, '"1"'), 409, "api.stale_version")
    for payload in ({"mode": "evaluation"}, {"mode": "workbench", "graph_sha256": "0" * 64}, {}):
        assert_error(api.start_run(browser, case, '"2"', json=payload), 422, "api.invalid_input")
    first = api.start_run(browser, case, '"2"')
    assert first.status_code == 202
    assert_error(api.start_run(browser, case, '"2"'), 409, "api.run_active")
    assert api.cancel_run(browser, first.json()["run_id"]).status_code == 200
    assert api.start_run(browser, case, '"2"').status_code == 202  # a terminal run frees the case
    assert counts(api, workspace)["runs"] == 2


def run_together(calls: list[Any]) -> list[Any]:
    barrier = threading.Barrier(len(calls))
    results: list[Any] = [None] * len(calls)

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
    assert not any(r is None or isinstance(r, BaseException) for r in results), results
    return results


def test_concurrent_starts_make_one_run(api: CaseApi) -> None:
    workspace, browser, _ = team(api)
    case = new_case(api, browser)
    clients = [api.clone(browser) for _ in range(8)]
    separate = run_together([partial(api.start_run, c, case, '"1"') for c in clients])
    assert sorted(r.status_code for r in separate) == [202] + [409] * 7
    assert {r.json()["rule_id"] for r in separate if r.status_code == 409} == {"api.run_active"}
    other = new_case(api, browser)
    same = run_together([partial(api.start_run, c, other, '"1"', key="run-race-000001") for c in clients])
    assert {r.status_code for r in same} == {202} and len({r.content for r in same}) == 1
    assert counts(api, workspace)["runs"] == 2 and counts(api, workspace)["jobs"] == 2


def test_roles_and_foreign_runs(api: CaseApi) -> None:
    workspace, browser, _ = team(api)
    case = new_case(api, browser)
    run = api.start_run(browser, case, '"1"').json()["run_id"]
    auditor = api.member(subject(), workspace, "auditor")
    assert_error(api.start_run(auditor, case, '"1"'), 403, "auth.role")
    assert_error(api.cancel_run(auditor, run), 403, "auth.role")
    assert api.run(auditor, run).status_code == 200
    _, stranger, _ = team(api)
    for target in (run, str(uuid4())):
        assert_error(api.run(stranger, target), 404, "api.run_not_found")
        assert_error(api.cancel_run(stranger, target), 404, "api.run_not_found")
    assert_error(api.start_run(stranger, case, '"1"'), 404, "api.case_not_found")
    assert run_state(api, run) == "queued"


# -- cancel ----------------------------------------------------------------------------------------------------

def test_cancel_is_an_idempotent_desired_state_action(api: CaseApi) -> None:
    workspace, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    first = api.cancel_run(browser, run, key="cancel-key-0001")
    assert first.status_code == 200 and first.json()["state"] == "cancelled"
    assert job_of(api, run) | {"claim_id": None, "owner": None} == {
        "state": "done", "attempts": 0, "error": "run_cancelled", "claim_id": None, "owner": None}
    before = counts(api, workspace)
    replay = api.cancel_run(browser, run, key="cancel-key-0001")
    assert replay.content == first.content and replay.headers["idempotent-replayed"] == "true"
    again = api.cancel_run(browser, run)  # a new key on a terminal run: a no-op
    assert again.status_code == 200 and again.json() == first.json()
    after = counts(api, workspace)
    assert after == before | {"ledger": before["ledger"] + 1}  # no event, outbox or audit for the no-op
    assert states(api, run) == ["queued", "cancelled"]


# -- the worker -------------------------------------------------------------------------------------------------

def test_two_workers_contend_and_exactly_one_runs_the_job(api: CaseApi, scripted: ScriptedExecutor) -> None:
    workspace, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    catalog = catalog_of(scripted)
    workers = [api.worker(catalog), api.worker(catalog)]
    claimed = run_together([w.run_once for w in workers])
    assert sorted(claimed) == [0, 1] and scripted.calls == 1
    assert run_state(api, run) == "succeeded"
    assert event_types(api, run) == [(1, "run.state_changed"), (2, "run.state_changed"),
                                     (3, "escalation.requested"), (4, "escalation.requested"),
                                     (5, "run.state_changed")]
    assert states(api, run) == ["queued", "running", "succeeded"]
    assert job_of(api, run) | {"claim_id": None, "owner": None} == {
        "state": "done", "attempts": 1, "error": None, "claim_id": None, "owner": None}
    assert api.scalar("SELECT event_highwater FROM app.runs WHERE id = %s", UUID(run)) == 5
    assert counts(api, workspace)["outbox"] == 5
    assert sum(w.run_once() for w in workers) == 0  # nothing left


def test_an_unconfigured_queued_job_fails_visibly(api: CaseApi) -> None:
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(RuntimeCatalog())  # this worker has no spec for the run's digests
    assert worker.run_once() == 0
    assert run_state(api, run) == "failed"
    assert job_of(api, run)["state"] == "dead" and job_of(api, run)["error"] == "executor_unavailable"
    error = api.rows("SELECT payload FROM app.run_events WHERE run_id = %s AND event_type = 'error.raised'", UUID(run))
    assert error[0][0]["code"] == "unavailable" and error[0][0]["rule_id"] == "runtime.executor_unavailable"
    assert worker.run_once() == 0 and job_of(api, run)["attempts"] == 0  # no retry loop


def test_a_changed_graph_or_prompt_digest_does_not_run_on_the_config_match(api: CaseApi,
                                                                           scripted: ScriptedExecutor) -> None:
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    with api.db.superuser() as conn:  # the run records another graph than the installed spec, same config
        conn.execute("UPDATE app.runs SET graph_sha256 = %s WHERE id = %s", ("f" * 64, UUID(run)))
    assert api.worker(catalog_of(scripted)).run_once() == 0
    assert scripted.calls == 0 and job_of(api, run)["error"] == "executor_unavailable"


def test_an_unsupported_job_kind_is_dead_lettered_without_touching_its_run(api: CaseApi,
                                                                           scripted: ScriptedExecutor) -> None:
    from policyops.persistence import repositories as repo
    from policyops.persistence.records import NewJob

    workspace, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    api.cancel_run(browser, run)
    now = api.clock.now()
    with workspace_transaction(api.runtime.app_engine, workspace) as conn:
        job_id, _ = repo.enqueue_job(conn, NewJob(id=uuid4(), workspace_id=workspace, run_id=UUID(run),
                                                  dedupe_key="future-kind", kind="run.future_kind", run_generation=0,
                                                  max_attempts=3, available_at=now, deadline_at=now + timedelta(1),
                                                  created_at=now))
    worker = api.worker(catalog_of(scripted))
    assert (job_id, workspace) not in worker.discover()
    assert not worker.process(job_id, workspace) and scripted.calls == 0
    assert api.rows("SELECT state, last_error_code FROM app.jobs WHERE id = %s", job_id) == [
        ("dead", "unsupported_job_kind")]
    assert run_state(api, run) == "cancelled"


@pytest.mark.parametrize("review_state", ["queued", "leased"])
def test_review_backlog_cannot_starve_a_worker_without_review(api: CaseApi, scripted: ScriptedExecutor,
                                                           review_state: str) -> None:
    from policyops.persistence import review_jobs
    from tests.integration.test_proposal_decisions import created, tenant

    t = tenant(api.db)
    worker = api.worker(catalog_of(scripted))
    assert worker.review is None
    for _ in range(worker.batch + 1):
        proposal = created(t)
        with workspace_transaction(t.engine, t.run.workspace_id) as conn:
            review_jobs.enqueue(conn, review_jobs.NewReviewJob(workspace_id=t.run.workspace_id, run_id=t.run.run_id,
                binding=review_jobs.ExpiryBinding(proposal_id=proposal.proposal_id,
                                                  proposal_version=proposal.proposal_version),
                created_at=t.clock.now(), available_at=t.clock.now()))
    api.clock.advance(timedelta(minutes=2))
    if review_state == "leased":
        with api.db.superuser() as conn:
            conn.execute("UPDATE app.jobs SET state = 'leased', claim_id = gen_random_uuid(), lease_owner = %s, "
                         "lease_expires_at = %s WHERE kind = 'run.review'",
                         (uuid4(), api.clock.now() - timedelta(seconds=1)))
    workspace, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    assert worker.discover() == [(api.rows("SELECT id FROM app.jobs WHERE run_id = %s", UUID(run))[0][0], workspace)]
    assert worker.run_once() == 1 and scripted.calls == 1 and run_state(api, run) == "succeeded"
    assert api.rows("SELECT state, attempts FROM app.jobs WHERE kind = 'run.review'") == [
        (review_state, 0)] * (worker.batch + 1)


def test_lease_expiry_reclaim_fences_the_first_worker(fresh: AppDatabase) -> None:
    started, release = threading.Event(), threading.Event()
    slow = ScriptedExecutor(events=1, started=started, release=release)
    api, catalog = built(fresh, slow)
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    first = api.worker(catalog)
    thread = threading.Thread(target=first.run_once)
    thread.start()
    assert started.wait(20)
    claim_one = job_of(api, run)["claim_id"]
    api.clock.advance(timedelta(seconds=31))  # the first lease has expired; nobody has reclaimed it yet
    second = api.worker(catalog)
    fast = ScriptedExecutor(events=1)
    second.catalog = RuntimeCatalog.of([scripted_spec(fast)], default="test.scripted-v1")  # same definition
    assert second.run_once() == 1 and fast.calls == 1  # reclaimed: attempt 2, new claim and generation
    assert job_of(api, run)["attempts"] == 2 and run_state(api, run) == "succeeded"
    release.set()
    thread.join(20)
    # The first worker's late finish was fenced out: exactly one success, one escalation per executor run
    # that held a valid claim when it emitted.
    assert states(api, run) == ["queued", "running", "succeeded"]
    assert claim_one != job_of(api, run)["claim_id"]


def test_an_expired_but_unreclaimed_claim_cannot_write(api: CaseApi, scripted: ScriptedExecutor) -> None:
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(catalog_of(scripted, lease=timedelta(seconds=30)))
    discovered = worker.discover()
    claimed = worker.claim(*discovered[0])
    assert claimed is not None
    token, case_id, spec = claimed
    api.clock.advance(timedelta(seconds=30))  # exactly at expiry: no longer current
    context = __import__("policyops.runtime.worker", fromlist=["Context"]).Context(worker, token, case_id, spec)
    from policyops_contracts.events import EscalationRequested

    with pytest.raises(store.Fenced) as fenced:
        context.emit(EscalationRequested(rule_id="test.late"))
    assert fenced.value.reason == "lease_expired"
    assert context.heartbeat() is False  # an expired lease cannot be revived
    before = event_types(api, run)
    worker.finish(token, __import__("policyops.runtime.spec", fromlist=["Succeeded"]).Succeeded())
    assert event_types(api, run) == before and run_state(api, run) == "running"


def test_heartbeat_keeps_the_same_fence(api: CaseApi, scripted: ScriptedExecutor) -> None:
    from policyops.runtime.worker import Context
    from policyops_contracts.events import EscalationRequested

    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(catalog_of(scripted, lease=timedelta(seconds=30)))
    token, case_id, spec = worker.claim(*worker.discover()[0]) or (None, None, None)
    assert token is not None and spec is not None and case_id is not None
    context = Context(worker, token, case_id, spec)
    for _ in range(3):  # 3 x 20 s > one lease, but each heartbeat came before expiry
        api.clock.advance(timedelta(seconds=20))
        assert context.heartbeat() is True
    assert context.emit(EscalationRequested(rule_id="test.alive")) > 0
    assert job_of(api, run)["claim_id"] == token.claim_id


def test_deadline_and_attempt_exhaustion_dead_letter_with_typed_codes(fresh: AppDatabase) -> None:
    retrying = ScriptedExecutor(events=0, outcome="retry")
    api, catalog = built(fresh, retrying, max_attempts=2, run_timeout=timedelta(hours=1))
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(catalog)
    assert worker.run_once() == 1 and job_of(api, run)["state"] == "queued"
    assert job_of(api, run)["error"] == "test_scripted_retry"
    assert worker.run_once() == 0  # backoff: not yet available
    api.clock.advance(timedelta(seconds=3))
    assert worker.run_once() == 1  # the second and last attempt
    assert job_of(api, run)["state"] == "dead" and job_of(api, run)["error"] == "max_attempts"
    assert run_state(api, run) == "failed" and retrying.calls == 2
    late = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    api.clock.advance(timedelta(hours=2))
    assert worker.run_once() == 0
    assert job_of(api, late)["error"] == "active_time" and run_state(api, late) == "budget_exceeded"


def test_initiator_permission_is_rechecked_before_work(api: CaseApi, scripted: ScriptedExecutor) -> None:
    from policyops.persistence import repositories as repo

    workspace, browser, _ = team(api)
    later = new_case(api, browser)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    logout = browser.post("/api/v1/auth/logout", headers={
        "Origin": case_api.ORIGIN, "X-CSRF-Token": browser.cookies.get(case_api.CSRF_COOKIE) or ""})
    assert logout.status_code == 204
    worker = api.worker(catalog_of(scripted))
    # Logout alone does not stop already authorized background work ...
    assert worker.run_once() == 1 and run_state(api, run) == "succeeded"
    # ... but a membership revoked before the work starts does.
    who = subject()
    third = api.start_run(api.member(who, workspace, "analyst"), later, '"1"').json()
    initiator = api.rows("SELECT id FROM identity.memberships WHERE principal_id = %s", api.principal(who))[0][0]
    with workspace_transaction(api.runtime.app_engine, workspace) as conn:
        assert repo.revoke_membership(conn, initiator, api.clock.now())
    calls = scripted.calls
    assert worker.run_once() == 0 and scripted.calls == calls
    assert job_of(api, third["run_id"])["error"] == "initiator_not_authorized"
    assert run_state(api, third["run_id"]) == "failed"


def test_cancel_during_execution_fences_the_worker(fresh: AppDatabase) -> None:
    started, release = threading.Event(), threading.Event()
    slow = ScriptedExecutor(events=1, started=started, release=release)
    api, catalog = built(fresh, slow)
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(catalog)
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    assert started.wait(20)
    cancelled = api.cancel_run(browser, run)
    assert cancelled.status_code == 200 and cancelled.json()["state"] == "cancelled"
    release.set()
    thread.join(20)
    assert run_state(api, run) == "cancelled"
    assert states(api, run) == ["queued", "running", "cancelled"]  # no success after the cancel
    assert job_of(api, run)["state"] == "done" and job_of(api, run)["error"] == "run_cancelled"


def test_a_failing_finish_rolls_back_state_event_and_outbox(api: CaseApi, scripted: ScriptedExecutor,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(catalog_of(scripted))
    real_end = store.end_job

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("database refused (injected)")

    monkeypatch.setattr(store, "end_job", boom)
    assert worker.run_once() == 0  # contained; the job error is logged as a type name only
    monkeypatch.setattr(store, "end_job", real_end)
    assert run_state(api, run) == "running" and states(api, run) == ["queued", "running"]
    outbox = api.scalar("SELECT count(*) FROM app.outbox_events WHERE run_id = %s", UUID(run))
    assert outbox == len(event_types(api, run))  # every event has its outbox row, and only committed ones
    assert job_of(api, run)["state"] == "leased"
    assert counts(api, workspace)["runs"] == 1


def test_executor_errors_are_logged_without_their_text(api: CaseApi, caplog: pytest.LogCaptureFixture) -> None:
    canary = f"secret-canary-{uuid4().hex}"

    class Leaky:
        test_only = True

        def execute(self, context: Any) -> Any:
            raise RuntimeError(canary)

    spec = scripted_spec(ScriptedExecutor(events=2))  # the definition the fixture's runs start with
    leaky = type(spec)(**{**spec.__dict__, "executor": Leaky()})
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    with caplog.at_level(logging.DEBUG):
        assert api.worker(RuntimeCatalog.of([leaky], default=leaky.spec_id)).run_once() == 1
    assert canary not in caplog.text and "Traceback" not in caplog.text
    assert "executor_error" in caplog.text and job_of(api, run)["error"] == "executor_error"
    assert canary not in str(api.rows("SELECT * FROM app.jobs WHERE run_id = %s", UUID(run)))


# -- the database clock -----------------------------------------------------------------------------------------

@contextmanager
def held(api: CaseApi, sql: str, *params: Any) -> Iterator[None]:
    with api.db.superuser() as conn, conn.transaction():
        conn.execute(sql, params)
        yield


def test_the_claim_clock_is_read_after_waiting_for_locks(fresh: AppDatabase) -> None:
    """Observe the SQL lock waiter, advance the controlled lease clock, then unlock. The claim clock must be
    sampled after the wait. This avoids contention sleeps exceeding the configured SQL lock timeout."""
    from policyops.runtime.worker import Context
    from policyops_contracts.events import EscalationRequested

    executor = ScriptedExecutor()
    catalog = catalog_of(executor, lease=timedelta(seconds=1), run_timeout=timedelta(minutes=5))
    api = case_api.build(fresh, catalog=catalog)
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(catalog)
    token, case_id, spec = worker.claim(*worker.discover()[0]) or (None, None, None)
    assert token is not None and case_id is not None and spec is not None
    context = Context(worker, token, case_id, spec)
    outcome: list[BaseException | int] = []

    def late_emit() -> None:
        try:
            outcome.append(context.emit(EscalationRequested(rule_id="test.waited")))
        except BaseException as exc:  # recorded below
            outcome.append(exc)

    with held(api, "SELECT 1 FROM app.runs WHERE id = %s FOR UPDATE", UUID(run)):
        thread = threading.Thread(target=late_emit)
        thread.start()  # its transaction starts now, before the lease expires, then waits for the run lock
        end = time.monotonic() + 5
        with api.db.superuser() as watcher:
            while not watcher.execute("SELECT 1 FROM pg_stat_activity WHERE datname = current_database() "
                                      "AND wait_event_type = 'Lock'").fetchone():
                assert time.monotonic() < end
                time.sleep(0.005)
        api.clock.advance(timedelta(seconds=2))
    thread.join(20)
    assert isinstance(outcome[0], store.Fenced) and outcome[0].reason == "lease_expired"
    assert [t for _, t in event_types(api, run)].count("escalation.requested") == 0


# -- the outbox --------------------------------------------------------------------------------------------------

def test_outbox_publication_notifies_on_commit_with_an_empty_payload(api: CaseApi, scripted: ScriptedExecutor,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    api.worker(catalog_of(scripted)).run_once()  # the producer's lease is over (job done) before publication
    pending = api.scalar("SELECT count(*) FROM app.outbox_events WHERE run_id = %s AND delivered_at IS NULL",
                         UUID(run))
    assert pending == 5
    dispatcher = api.dispatcher()
    with api.db.superuser() as listener:
        listener.execute("LISTEN policyops_run_events")
        # A failing publication commits nothing: no notification, nothing marked.
        real = store.publish_outbox

        def fail_after(connection: Any, **kwargs: Any) -> int:
            real(connection, **kwargs)
            raise RuntimeError("injected failure before commit")

        monkeypatch.setattr(store, "publish_outbox", fail_after)
        with pytest.raises(RuntimeError):
            dispatcher.dispatch_once()
        monkeypatch.setattr(store, "publish_outbox", real)
        assert list(listener.notifies(timeout=0.5, stop_after=1)) == []
        assert api.scalar("SELECT count(*) FROM app.outbox_events WHERE run_id = %s AND delivered_at IS NULL",
                          UUID(run)) == 5
        published = dispatcher.dispatch_once()
        assert published >= 5
        notes = list(listener.notifies(timeout=1.0, stop_after=10))
    # One coalesced, empty wake-up per publishing transaction (one transaction per workspace here).
    assert len(notes) >= 1 and all(note.payload == "" for note in notes)
    assert all(note.channel == "policyops_run_events" for note in notes)
    assert api.scalar("SELECT count(*) FROM app.outbox_events WHERE workspace_id = %s AND delivered_at IS NULL",
                      workspace) == 0
    assert dispatcher.dispatch_once() == 0  # nothing is published twice


# -- a real worker process ---------------------------------------------------------------------------------------

def test_a_killed_worker_process_is_reclaimed_after_its_lease(fresh: AppDatabase) -> None:
    from policyops_testing import worker_process

    executor = ScriptedExecutor()
    catalog = catalog_of(executor, lease=timedelta(seconds=2), run_timeout=timedelta(minutes=5))
    api = case_api.build(fresh, catalog=catalog, database_clock=True)
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    process = worker_process.start(fresh, run_id=run)
    try:
        worker_process.wait_until_claimed(process, timeout=60)
        claim = job_of(api, run)["claim_id"]
        process.kill()  # TerminateProcess / SIGKILL: no cleanup in the worker
    finally:
        worker_process.stop(process)
    assert job_of(api, run)["state"] == "leased" and run_state(api, run) == "running"
    worker = api.worker(catalog, database_clock=True)
    deadline = time.monotonic() + 30
    while worker.run_once() == 0:  # the lease ends after 2 s of database time
        assert time.monotonic() < deadline, "the lease was never reclaimed"
        time.sleep(0.25)
    assert job_of(api, run)["attempts"] == 2 and job_of(api, run)["claim_id"] is None
    assert run_state(api, run) == "succeeded" and claim is not None
    assert states(api, run) == ["queued", "running", "succeeded"]


def test_a_retry_without_active_time_for_backoff_stops(fresh: AppDatabase) -> None:
    """The backoff would land at or after the job's deadline (which must stay after `available_at`): the claim is
    still valid, but no retry can be scheduled. A typed active-time stop and its message commit with job completion
    instead of failing a database check and rolling back."""
    from policyops.runtime.spec import Retry

    retrying = ScriptedExecutor(events=0, outcome="retry")
    api, catalog = built(fresh, retrying, run_timeout=timedelta(seconds=61), lease=timedelta(seconds=60))
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    worker = api.worker(catalog)
    token, _case, _spec = worker.claim(*worker.discover()[0]) or (None, None, None)
    assert token is not None
    api.clock.advance(timedelta(seconds=59.5))  # deadline in 1.5 s, first backoff 2 s; the lease is still current
    worker.finish(token, Retry("test_scripted_retry"))
    assert job_of(api, run)["state"] == "done" and job_of(api, run)["error"] == "active_time"
    assert run_state(api, run) == "budget_exceeded"
    assert api.scalar("SELECT request_sha256 FROM app.jobs WHERE run_id = %s", UUID(run)) is not None


@pytest.mark.parametrize("paused", ["waiting_input", "waiting_approval", "reconciling"])
def test_paused_runs_are_not_executed(api: CaseApi, scripted: ScriptedExecutor, paused: str) -> None:
    workspace, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    with workspace_transaction(api.db.engine(APP_RUNTIME), workspace) as conn:
        row = store.get_run(conn, UUID(run), lock=True)
        assert row is not None
        store.set_state(conn, row, paused, api.clock.now())  # type: ignore[arg-type]
    assert api.worker(catalog_of(scripted)).run_once() == 0
    assert scripted.calls == 0 and run_state(api, run) == paused
    assert job_of(api, run)["state"] == "dead" and job_of(api, run)["error"] == "run_not_runnable"


def test_other_topics_cannot_starve_run_event_publication(api: CaseApi, scripted: ScriptedExecutor) -> None:
    """Undelivered rows of a topic this dispatcher does not publish, in many older workspaces, neither block
    run-event publication nor get marked delivered."""
    stale = [api.workspace(f"legacy{i}") for i in range(25)]  # more than one discovery pass covers
    # Older than the run's events on the SAME clock the run uses (the controlled lease clock), so that without the
    # topic filter these workspaces really are discovered first. Real database now() would make them newer.
    older = api.clock.now() - timedelta(days=1)
    with api.db.superuser() as conn:
        for workspace in stale:
            conn.execute("INSERT INTO app.outbox_events (id, workspace_id, dedupe_key, topic, payload, created_at) "
                         "VALUES (gen_random_uuid(), %s, 'legacy', 'legacy.topic', '{}', %s)", (workspace, older))
    _, browser, _ = team(api)
    run = api.start_run(browser, new_case(api, browser), '"1"').json()["run_id"]
    assert api.dispatcher().dispatch_once() == 1
    assert api.scalar("SELECT count(*) FROM app.outbox_events WHERE run_id = %s AND delivered_at IS NULL",
                      UUID(run)) == 0
    assert api.scalar("SELECT count(*) FROM app.outbox_events WHERE topic = 'legacy.topic' AND delivered_at IS NULL"
                      ) == 25


def test_worker_composition_verifies_both_engine_roles(fresh: AppDatabase, scripted: ScriptedExecutor) -> None:
    """The supported factories accept only engines that authenticate as their restricted roles."""
    from policyops.persistence.database import RuntimeRoleError
    from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
    from policyops.runtime.outbox import build_dispatcher
    from policyops.runtime.worker import build_worker

    app, discovery, auth = (fresh.engine(role, pool_size=1) for role in (APP_RUNTIME, WORKER_DISCOVERY, AUTH_RUNTIME))
    catalog = catalog_of(scripted)
    assert build_worker(env="test", app_engine=app, discovery_engine=discovery, catalog=catalog).catalog is catalog
    assert build_dispatcher(env="test", app_engine=app, discovery_engine=discovery) is not None
    for app_engine, discovery_engine in ((discovery, discovery), (app, app), (auth, discovery), (app, auth)):
        with pytest.raises(RuntimeRoleError):
            build_worker(env="test", app_engine=fresh.engine(_role(app_engine), pool_size=2),
                         discovery_engine=fresh.engine(_role(discovery_engine), pool_size=2), catalog=catalog)
        with pytest.raises(RuntimeRoleError):
            build_dispatcher(env="test", app_engine=fresh.engine(_role(app_engine), pool_size=2),
                             discovery_engine=fresh.engine(_role(discovery_engine), pool_size=2))


def _role(engine: Any) -> str:
    """The role an engine authenticates as (each check then gets a fresh pool-size-2 engine for it, so earlier
    verification state does not carry over)."""
    with engine.connect() as connection:
        user: str = connection.connection.driver_connection.info.user
    return user
