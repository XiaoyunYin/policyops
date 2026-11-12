"""Review bindings, safe summaries and composition boundaries without external services."""

from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

from pydantic import ValidationError
import pytest

from policyops.persistence import review_jobs as jobs
from policyops.persistence import runs as store
from policyops.runtime.clock import FixedLeaseClock, UnsafeTestHook
from policyops.runtime.review import ReviewRuntime, build_review_runtime
from policyops.runtime.spec import RuntimeCatalog
from policyops.runtime.worker import Worker
from policyops.services.review_outcomes import RefusalReason, refusal_message_id, refusal_text
from policyops_contracts.clock import FixedClock


NOW = datetime(2026, 11, 11, tzinfo=UTC)


@pytest.mark.parametrize("with_review", [False, True])
def test_discovery_selects_only_composed_job_kinds(monkeypatch: pytest.MonkeyPatch, with_review: bool) -> None:
    from policyops.runtime import worker as worker_module

    connection: Any = object()
    engine: Any = object()
    candidates = [(uuid4(), uuid4())]

    def discover(conn: Any, now: datetime, limit: int, *, kinds: tuple[str, ...]) -> list[tuple[Any, Any]]:
        assert conn is connection and now == NOW and limit == 10
        assert kinds == ((store.EXECUTE_KIND, jobs.REVIEW_KIND) if with_review else (store.EXECUTE_KIND,))
        return candidates

    monkeypatch.setattr(worker_module, "transaction", lambda engine, **kwargs: nullcontext(connection))
    monkeypatch.setattr(store, "discover_jobs", discover)
    worker = Worker(app_engine=engine, discovery_engine=engine, clock=FixedLeaseClock(FixedClock(NOW)),
                    catalog=RuntimeCatalog(), review=cast(ReviewRuntime, object()) if with_review else None)
    assert worker.discover() == candidates


def job(**changes: Any) -> store.Job:
    return store.Job.model_validate(dict(id=uuid4(), workspace_id=uuid4(), run_id=uuid4(), kind=jobs.REVIEW_KIND,
        state="queued", claim_id=None, lease_owner=None, lease_expires_at=None, attempts=0, max_attempts=10,
        available_at=NOW, deadline_at=NOW, last_error_code=None, version=1,
        review_trigger="expiry", proposal_id=uuid4(), proposal_version=1) | changes)


@pytest.mark.parametrize("changes", [
    {"review_trigger": None}, {"proposal_id": None}, {"proposal_version": None}, {"proposal_version": 0},
    {"proposal_version": 2**63}, {"decision_id": uuid4()}, {"execution_id": uuid4()},
    {"execution_version": 1}, {"review_trigger": "decision"},
    {"review_trigger": "outcome", "decision_id": uuid4(), "execution_id": uuid4()},
    {"review_trigger": "decision", "decision_id": uuid4(), "execution_version": 1},
])
def test_incomplete_or_mixed_bindings_fail_closed(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        jobs.binding_of(job(**changes))


def test_job_decoding_and_binding_are_typed_for_all_triggers() -> None:
    assert isinstance(jobs.binding_of(job()), jobs.ExpiryBinding)
    assert isinstance(jobs.binding_of(job(review_trigger="decision", decision_id=uuid4())), jobs.DecisionBinding)
    assert isinstance(jobs.binding_of(job(review_trigger="outcome", decision_id=uuid4(), execution_id=uuid4(),
                                         execution_version=3)), jobs.OutcomeBinding)
    for column in jobs.REFERENCE_COLUMNS:
        assert column in store.JOB_COLUMNS.split(", ")


def test_dedupe_keys_are_bounded_and_distinguish_source_versions() -> None:
    proposal, decision, execution = uuid4(), uuid4(), uuid4()
    bindings: list[jobs.DecisionBinding | jobs.ExpiryBinding | jobs.OutcomeBinding] = [
                jobs.ExpiryBinding(proposal_id=proposal, proposal_version=2**63-1),
                jobs.DecisionBinding(proposal_id=proposal, proposal_version=2**63-1, decision_id=decision),
                jobs.OutcomeBinding(proposal_id=proposal, proposal_version=1, decision_id=decision,
                                    execution_id=execution, execution_version=1),
                jobs.OutcomeBinding(proposal_id=proposal, proposal_version=1, decision_id=decision,
                                    execution_id=execution, execution_version=2)]
    keys = [jobs.NewReviewJob(workspace_id=uuid4(), run_id=uuid4(), binding=binding,
                             created_at=NOW, available_at=NOW).key for binding in bindings]
    assert len(set(keys)) == 4 and all(len(key) <= 200 for key in keys)


@pytest.mark.parametrize("reason", list(RefusalReason))
def test_refusal_messages_are_bounded_and_never_claim_success(reason: RefusalReason) -> None:
    text = refusal_text(reason)
    assert len(text) <= 4000 and reason.value in text and "No action was executed" in text
    workspace, run, job_id = uuid4(), uuid4(), uuid4()
    assert refusal_message_id(workspace, run, job_id) == refusal_message_id(workspace, run, job_id)
    assert refusal_message_id(workspace, run, job_id) != refusal_message_id(workspace, run, uuid4())


@pytest.mark.parametrize("env", ["local", "deployment"])
@pytest.mark.parametrize("seam", ["clock", "scopes", "retail"])
def test_injected_review_parts_are_rejected_before_database_io(env: str, seam: str) -> None:
    changes: dict[str, Any] = {seam: object()}
    if seam == "clock":
        changes[seam] = FixedLeaseClock(FixedClock(NOW))
    with pytest.raises(UnsafeTestHook):
        build_review_runtime(env=env, app_engine=None, bindings=(), fixture_sha256="0"*64,  # type: ignore[arg-type]
                             retail_origin="http://127.0.0.1:1", retail_key=b"x"*32, **changes)


@pytest.mark.parametrize("fault", [None, "run_binding", "owner", "generation", "lease", "deadline"])
def test_completion_fence_keeps_identity_lease_and_delivery_deadline_even_on_cancelled_run(
        monkeypatch: pytest.MonkeyPatch, fault: str | None) -> None:
    from tests.unit.test_runs_unit import run_record

    run = run_record().model_copy(update={"state": "cancelled", "deadline_at": None, "active_started_at": None})
    row = job(workspace_id=run.workspace_id, run_id=run.id, state="leased", attempts=1,
              claim_id=uuid4(), lease_owner=uuid4(),
              lease_expires_at=NOW+timedelta(seconds=30), deadline_at=NOW+timedelta(hours=24))
    assert row.claim_id is not None and row.lease_owner is not None
    token = store.ClaimToken(workspace_id=run.workspace_id, run_id=run.id, job_id=row.id,
                             claim_id=row.claim_id, owner=row.lease_owner, generation=run.generation, attempt=1)
    if fault == "run_binding":
        row = row.model_copy(update={"run_id": uuid4()})
    elif fault == "owner":
        token = replace(token, owner=uuid4())
    elif fault == "generation":
        token = replace(token, generation=token.generation+1)
    elif fault == "lease":
        row = row.model_copy(update={"lease_expires_at": NOW})
    elif fault == "deadline":
        row = row.model_copy(update={"deadline_at": NOW})
    monkeypatch.setattr(store, "get_run", lambda *args, **kwargs: run)
    monkeypatch.setattr(store, "get_job", lambda *args, **kwargs: row)
    connection: Any = object()
    clock = FixedLeaseClock(FixedClock(NOW))
    if fault is None:
        assert jobs.check_claim(connection, token, clock) == (run, row, NOW)
        with pytest.raises(store.Fenced):  # completion capability never grants reservation authority
            store.check_fence(connection, token, clock)
    else:
        with pytest.raises(store.Fenced):
            jobs.check_claim(connection, token, clock)
