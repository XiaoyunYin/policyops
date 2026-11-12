"""T19 execution routing, limits and test-only composition guards (offline)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
import pytest

from policyops.persistence import executions as ledger
from policyops.runtime import executions as runtime
from policyops.runtime.clock import UnsafeTestHook
from policyops.runtime.executions import ExecutionDispatcher, build_execution_dispatcher
from policyops.services.execution import ExecutionLimits, Step, _slug, route
from policyops_contracts.events import ExecutionChanged
from policyops_contracts.retail import ToolName
from policyops_contracts.retail_service import OperationResult
from policyops_testing.evidence import EvidenceError
from policyops_testing.execution_faults import CrashHooks, Trial, fault_plan, summarize, write_report


def result(outcome: str) -> OperationResult:
    return OperationResult.model_validate({"operation_id": str(uuid4()), "operation_sha256": "a" * 64,
                                           "outcome": outcome, "replayed": False})


@pytest.mark.parametrize(("outcome", "expected"), [
    ("fenced", ("reconciled", "fenced")), ("upstream_rejected", ("failed", "upstream_rejected")),
    ("effect_mismatch", ("failed", "effect_mismatch")), ("money_unrepresentable", ("failed", "money_unrepresentable")),
    ("version_conflict", ("failed", "version_conflict"))])
def test_every_stored_outcome_routes_the_same_way_whatever_its_source(outcome: str, expected: tuple[str, str]) -> None:
    assert route(result(outcome)) == expected


def test_limits_keep_a_claim_longer_than_one_bounded_request_and_caps_finite() -> None:
    for bad in ({"lease": timedelta(seconds=30)}, {"max_dispatches": 0}, {"max_reconciles": 51},
                {"authority_margin": timedelta(seconds=-1)}):
        with pytest.raises(ValueError):
            ExecutionLimits(**bad)


def test_test_hooks_are_refused_outside_the_test_environment_before_any_database_access() -> None:
    with pytest.raises(UnsafeTestHook):
        build_execution_dispatcher(env="production", app_engine=None, discovery_engine=None,  # type: ignore[arg-type]
                                   scopes=None, retail=None, hooks=CrashHooks())  # type: ignore[arg-type]


def test_codes_are_bounded_slugs() -> None:
    assert _slug("HTTP 503!") == "http_503" and _slug("409") == "c_409" and len(_slug("x" * 200)) == 64


def test_the_execution_event_carries_identifiers_and_digests_only() -> None:
    event = ExecutionChanged(execution_id=uuid4(), operation_id=uuid4(), tool=ToolName.CANCEL_PENDING_ORDER,
                             state="unknown", attempt=1, code="http_503")
    assert set(event.model_dump()) == {"type", "execution_id", "operation_id", "tool", "state", "attempt", "outcome",
                                       "code", "receipt_sha256"}
    with pytest.raises(ValidationError):
        ExecutionChanged.model_validate({**event.model_dump(mode="json"), "request": {"address": "x"}})


def test_the_fault_plan_is_reproducible_and_the_summary_keeps_every_trial() -> None:
    assert fault_plan(7, 5) == fault_plan(7, 5)
    trials = [Trial(seed=1, index=0, arm="ledger", fault="none", final_state="succeeded", outcome="committed",
                    attempts=1, reconcile_attempts=0, effects=1, receipt_sha256=["b" * 64]),
              Trial(seed=1, index=1, arm="ledger", fault="fail_503_before", final_state="unknown", outcome=None,
                    attempts=1, reconcile_attempts=8, effects=0)]
    summary = summarize(trials)["ledger"]
    assert summary["trials"] == 2 and summary["unresolved"] == 1 and summary["duplicate_effects"] == 0


def test_a_long_dispatch_loop_retains_no_step_history(monkeypatch: pytest.MonkeyPatch) -> None:
    passes = iter(range(1, 10_000))

    class Transaction:
        def __enter__(self) -> object:
            return object()

        def __exit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(runtime, "transaction", lambda engine: Transaction())
    monkeypatch.setattr(ledger, "discover", lambda connection, now, limit: [
        (UUID(int=1), UUID(int=next(passes))) for _ in range(limit)])
    executor: Any = SimpleNamespace(step=lambda workspace, execution: Step(execution, "unknown", "unknown"))
    clock: Any = SimpleNamespace(now=lambda connection: datetime(2026, 11, 11, tzinfo=UTC))
    dispatcher = ExecutionDispatcher(discovery_engine=None, executor=executor, clock=clock, batch=3)  # type: ignore
    for _ in range(500):
        assert len(dispatcher.dispatch_once()) == 3  # the caller gets the bounded batch
    held = [value for value in vars(dispatcher).values() if isinstance(value, list | tuple | set | dict)]
    assert held == []  # nothing accumulates across passes


def test_the_report_destination_is_contained_before_any_filesystem_write(tmp_path: Path,
                                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(root))
    written = write_report(root / "e04" / "ok.json", {"seed": 1}, [])
    assert written["summary"] == {} and (root / "e04" / "ok.json").is_file()
    writes: list[str] = []

    def tripwire(*args: object, **kwargs: object) -> None:
        writes.append("mkdir")
        raise AssertionError("filesystem mutation before containment")

    monkeypatch.setattr(Path, "mkdir", tripwire)
    for outside in (tmp_path / "outside" / "r.json", root / ".." / "escape" / "r.json"):
        with pytest.raises(EvidenceError):
            write_report(outside, {"seed": 1}, [])
    assert writes == [] and not (tmp_path / "outside").exists() and not (tmp_path / "escape").exists()


def test_the_summary_keeps_aborted_trials_and_counts_a_failure_with_an_effect() -> None:
    rows = [Trial(seed=1, index=0, arm="naive_new_id", fault="commit_then_503", final_state="failed",
                  outcome="version_conflict", attempts=2, reconcile_attempts=0, effects=1),
            Trial(seed=1, index=1, arm="naive_new_id", fault="none", final_state="aborted", outcome=None,
                  attempts=0, reconcile_attempts=0, effects=0, error="RuntimeError")]
    summary = summarize(rows)["naive_new_id"]
    assert (summary["trials"], summary["aborted"], summary["failed_with_effect"]) == (2, 1, 1)
    assert summary["effects_without_receipt"] == 1
