"""Hand-calculated safety scoring, frozen denominators and offline CLI failure controls."""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from pydantic import ValidationError
import pytest

from policyops.adapters.retail_client import RetailClient, Unknown
from policyops.services.execution import Reserved
from policyops_contracts.clock import FixedClock
from policyops_contracts.evidence import CodeIdentity
from policyops_contracts.money import Money, MoneyError, money_from_upstream
from policyops_contracts.retail import CancelEffect, RefundLine
from policyops_contracts.retail_service import FIXTURE_SHA256, Receipt
from policyops_testing.evidence import EvidenceError
from policyops_testing.gateway_cases import CASES, W
from policyops_testing.safety import cli, e04, matrix, sensitivity
from policyops_testing.safety import environment as environments
from policyops_testing.safety.config import DEFAULT_CONFIG, REPO, Config, canonical, digest, load_config, schedule
from policyops_testing.safety.e04 import Hooks, ProcessCrash, client_factory
from policyops_testing.safety.fixtures import recovery_test_pairs
from policyops_testing.safety.reports import (
    Envelope,
    Sensitivity,
    State,
    Trial,
    assert_ledger,
    changes,
    completeness,
    public_summary,
    score,
    seal,
    settlement,
    summarize,
    verify,
)
from policyops_testing.safety.rls import assert_foreign_hidden


NOW = datetime(2026, 11, 12, tzinfo=UTC)
CODE = CodeIdentity(git_head="1" * 40, git_tree="2" * 40, dirty_patch_sha256=None)


def test_current_matrix_config_only_extends_frozen_helpdesk_grants() -> None:
    v1_path = DEFAULT_CONFIG.with_name("t30-v1.json")
    v1_bytes = v1_path.read_bytes()
    expected = json.loads(v1_bytes)
    assert v1_bytes == canonical(expected) + b"\n"
    assert load_config(v1_path).study_id == "t30-slice-a-v1"

    grants = expected["role_grants"]
    runtime_updates = {
        "app.helpdesk_customer_bindings": [],
        "app.helpdesk_events": [
            "attempts", "lease_expires_at", "lease_owner", "next_attempt_at", "reason", "revivals", "state", "version",
        ],
        "app.helpdesk_ticket_links": ["group_id", "max_article_id", "state_id", "ticket_updated_at"],
        "app.helpdesk_writebacks": [
            "article_created_at", "article_id", "attempts", "dispatch_started_at", "duplicate_article_ids",
            "lease_expires_at", "lease_owner", "next_attempt_at", "reason", "reconciles", "state", "version",
        ],
    }
    runtime = grants["policyops_app_runtime"]
    assert not (runtime.keys() & runtime_updates.keys())
    for table, columns in runtime_updates.items():
        runtime[table] = {"table": ["INSERT", "SELECT"], "update_columns": columns, "select_columns": []}
    discovery = grants["policyops_worker_discovery"]
    for table in ("app.helpdesk_events", "app.helpdesk_writebacks"):
        assert table not in discovery
        discovery[table] = {
            "table": [], "update_columns": [],
            "select_columns": ["id", "lease_expires_at", "next_attempt_at", "state", "workspace_id"],
        }
    privileges_source = REPO / "tests/integration/test_app_privileges.py"
    expected.update(
        grants_source_sha256=hashlib.sha256(privileges_source.read_bytes()).hexdigest(),
        schema_version="policyops.safety-config/v2",
        study_id="t30-slice-a-v2",
    )
    assert DEFAULT_CONFIG.name == "t30-v2.json"
    assert DEFAULT_CONFIG.read_bytes() == canonical(expected) + b"\n"
    assert load_config().study_id == "t30-slice-a-v2"


def golden() -> Trial:
    """A manufactured one-effect scoring example, never a simulator trial or study result."""
    pair = next(p for p in load_config().pairs if p.variant == "cancel")
    before = State(version=1, full_sha256=digest({"status": "pending"}), scoped={"status": "pending"})
    after = State(version=2, full_sha256=digest({"status": "cancelled"}), scoped={"status": "cancelled"})
    effect = CancelEffect(order_id="#W0000001", reason="no longer needed", refunds=(RefundLine(
        payment_method_id="credit_card_0000001", amount=Money(amount_minor=1200), timing="5 to 7 business days"),))
    receipt = Receipt(operation_id=str(UUID(int=4)), operation_sha256="a" * 64, tool="cancel_pending_order",
        actual_effect=effect, case_version_before=1, case_version_after=2, resource_versions_after=(),
        state_sha256_after=after.full_sha256, committed_at=NOW)
    return Trial(pair_id=pair.pair_id, seed=pair.seed, arm="ledger", fault=pair.fault, variant=pair.variant,
        case_id=str(pair.identity("ledger", "case")), run_id=str(pair.identity("ledger", "run")),
        started_at=NOW, finished_at=NOW, application_clock_start=NOW, fault_reached=True,
        fault_evidence=("golden_unit_example",), sends=1, reconciles=0, passes=1, final_state="succeeded",
        dispatch_checkpoints=1, mutation_operations=(receipt.operation_id,),
        outcome="committed", before=before, after=after, expected_diff=tuple(changes(before.scoped, after.scoped)),
        actual_diff=tuple(changes(before.scoped, after.scoped)), remote_receipts=(receipt,), held_receipts=(receipt,),
        expected_effect=effect, expected_full_sha256=after.full_sha256,
        operations={receipt.operation_id: receipt.operation_sha256})


def envelope() -> Envelope:
    row = golden()
    pair = next(p for p in load_config().pairs if p.pair_id == row.pair_id)
    receipt = row.remote_receipts[0].model_copy(update={"operation_id": str(UUID(int=5)),
                                                      "operation_sha256": "b" * 64})
    naive = row.model_copy(update={"arm": "naive_new_id", "case_id": str(pair.identity("naive_new_id", "case")),
        "run_id": str(pair.identity("naive_new_id", "run")), "operations": {receipt.operation_id: "b" * 64},
        "mutation_operations": (receipt.operation_id,), "remote_receipts": (receipt,), "held_receipts": (receipt,)})
    trials = [row, naive]
    checks = [*sensitivity.report_controls(load_config(), row), Sensitivity(
        check_id="real_subprocess_kill_restart", detected=True, evidence={"unit_example": True})]
    config = load_config()
    return Envelope(study_id=config.study_id, config=config, config_sha256=digest(config.model_dump(mode="json")),
        source_hashes={"uv.lock": "1" * 64}, code_identity=CODE.model_dump(mode="json"),
        environment={"postgresql": "not_used_unit_example"}, versions={"fixture_sha256": FIXTURE_SHA256},
        command=("unit_example",), exit_code=0, started_at=NOW, finished_at=NOW, suites=("e04",),
        pair_ids=(row.pair_id,), matrix=[], trials=trials, sensitivity=checks, supplements={}, failures=(),
        summary=summarize(trials), limitations=config.limitations)


def test_frozen_schedule_is_balanced_reproducible_and_has_distinct_arm_identities() -> None:
    config = load_config()
    assert config.pairs == schedule() and len(config.pairs) == 100
    assert set(Counter(p.fault for p in config.pairs).values()) == {20}
    assert Counter(p.variant for p in config.pairs) == {"cancel": 34, "pending_address": 33, "delivered_return": 33}
    assert len({p.identity(a, "case") for p in config.pairs for a in p.arms}) == 200
    assert len({p.identity(a, "run") for p in config.pairs for a in p.arms}) == 200
    assert len({p.arms for p in config.pairs}) == 2
    assert config.matrix_ids == matrix.matrix_ids()
    assert len({r.split("/")[1] for r in config.matrix_ids if r.startswith("action/")}) == 11
    assert len(matrix.WRITE_TOOLS) == 7


def test_recovery_module_pair_selections_are_distinct_for_every_fault() -> None:
    config = load_config()
    selected = recovery_test_pairs(config)
    assert set(selected) == {pair.fault for pair in config.pairs}
    for paired, fenced_pair in selected.values():
        pair_ids = [paired.pair_id]
        if fenced_pair is not None:
            pair_ids.append(fenced_pair.pair_id)
        assert len(pair_ids) == len(set(pair_ids))


def test_schedule_changes_and_duplicate_matrix_cells_are_rejected() -> None:
    raw = load_config().model_dump(mode="json")
    raw["pairs"][0]["seed"] += 1
    with pytest.raises(ValidationError):
        Config.model_validate(raw)
    raw = load_config().model_dump(mode="json")
    raw["matrix_ids"][1] = raw["matrix_ids"][0]
    with pytest.raises(ValidationError):
        Config.model_validate(raw)


def test_hand_calculated_success_and_receipt_removal_and_false_failure() -> None:
    row = golden()
    assert_ledger(row)
    assert score(row).effects == 1 and score(row).missing_receipts == 0
    lost = row.model_copy(update={"held_receipts": (), "final_state": "failed", "outcome": "version_conflict"})
    measured = score(lost)
    assert measured.effects == 1 and measured.missing_receipts == 1 and measured.failed_with_effect
    assert not measured.false_success
    with pytest.raises(ValueError):
        assert_ledger(lost)
    assert score(lost.model_copy(update={"final_state": "succeeded"})).false_success


def test_unknown_observation_is_null_and_stays_in_the_denominator() -> None:
    row = golden().model_copy(update={"after": None, "final_state": "aborted", "error": "RuntimeError"})
    assert score(row).effects is None and score(row).missing_receipts is None
    summary = summarize([row])["arms"]["ledger"]
    assert summary["scheduled"] == summary["aborted"] == summary["unobserved_trials"] == 1
    assert summary["effect_count"] is None and summary["observed_effect_count"] == 0


def fenced() -> Trial:
    row = golden()
    return row.model_copy(update={"after": row.before, "final_state": "reconciled", "outcome": "fenced",
                                  "actual_diff": (), "remote_receipts": (), "held_receipts": ()})


def test_fenced_no_effect_passes_and_summary_exposes_availability_by_fault_and_variant() -> None:
    row = fenced()
    assert_ledger(row)
    assert settlement(row) == "fenced_no_effect"
    arm = summarize([golden(), row])["arms"]["ledger"]
    assert arm["completed_once"] == arm["fenced_no_effect"] == 1
    assert arm["scheduled"] == 2 and arm["effect_count"] == 1
    assert arm["fault_variant_breakdown"] == [{"fault": row.fault, "variant": row.variant,
        "scheduled": 2, "completed_once": 1, "fenced_no_effect": 1}]
    report = envelope()
    report = report.model_copy(update={"trials": [row, report.trials[1]],
                                       "summary": summarize([row, report.trials[1]])})
    assert verify(report) == []
    assert public_summary(report)["arms"]["ledger"]["fenced_no_effect"] == 1


@pytest.mark.parametrize("corruption", ["state_change", "remote_receipt", "held_receipt", "failed",
                                       "wrong_outcome", "zero_committed", "two_committed"])
def test_settlement_rejects_invalid_fences_and_commit_counts(corruption: str) -> None:
    row = fenced()
    assert row.before is not None
    if corruption == "state_change":
        # Even an out-of-scope hash change with unchanged scoped data must fail.
        row = row.model_copy(update={"after": row.before.model_copy(update={"full_sha256": "f" * 64})})
    elif corruption == "remote_receipt":
        row = row.model_copy(update={"remote_receipts": golden().remote_receipts})
    elif corruption == "held_receipt":
        row = row.model_copy(update={"held_receipts": golden().held_receipts})
    elif corruption == "failed":
        row = row.model_copy(update={"final_state": "failed"})
    elif corruption == "wrong_outcome":
        row = row.model_copy(update={"outcome": "committed"})
    elif corruption == "zero_committed":
        row = row.model_copy(update={"final_state": "succeeded", "outcome": "committed"})
    else:
        row = golden()
        assert row.after is not None
        first = row.remote_receipts[0]
        second = first.model_copy(update={"operation_id": str(UUID(int=5)), "case_version_before": 2,
                                          "case_version_after": 3})
        row = row.model_copy(update={"after": row.after.model_copy(update={"version": 3}),
            "remote_receipts": (first, second), "held_receipts": (first, second),
            "operations": {r.operation_id: r.operation_sha256 for r in (first, second)}})
        assert not score(row).errors  # Reject the duplicate even when every receipt link is valid.
    assert settlement(row) is None
    with pytest.raises(ValueError):
        assert_ledger(row)


@pytest.mark.parametrize("committed", [False, True])
def test_duplicate_delivery_derives_version_and_records_old_claimant_http_response(
        monkeypatch: pytest.MonkeyPatch, committed: bool) -> None:
    row = golden() if committed else fenced()
    record: Any = SimpleNamespace(id=UUID(int=8), state=row.final_state, outcome=row.outcome,
                             receipt=row.held_receipts[0] if committed else None)
    env: Any = SimpleNamespace(approve=lambda _: None, reserve=lambda _: record.id, origin="http://127.0.0.1:1",
                          scope=None,
                          run=SimpleNamespace(workspace_id=UUID(int=1)))

    class Executor:
        def __init__(self, hooks: Any, mutations: Any, responses: Any) -> None:
            self.hooks, self.mutations, self.responses = hooks, mutations, responses

        def reserve(self, *args: Any) -> Any:
            return Reserved(record, False)

        def step(self, *args: Any) -> Any:
            if type(self.hooks).__name__ == "Delayed":
                self.hooks.before_send(record)
                self.mutations.append("old-operation")
                self.responses.extend(["http_status_200", f"service_outcome_{record.outcome}"])
                return SimpleNamespace(action="lost_claim", state=record.state, code=None)
            return SimpleNamespace(action="unchanged", state=record.state, code=None)

    def worker(env: Any, hooks: Any, origin: Any, *, mutations: Any, responses: Any = None) -> Any:
        return SimpleNamespace(executor=Executor(hooks, mutations, responses))

    monkeypatch.setattr(e04, "call_for", lambda *args: None)
    monkeypatch.setattr(e04, "worker", worker)
    monkeypatch.setattr(e04, "due", lambda _: None)
    monkeypatch.setattr(e04, "ledger_record", lambda *args: record)
    monkeypatch.setattr(e04, "observe", lambda _: (row.after, {}, ()))
    pair = next(p for p in load_config().pairs if p.fault == "duplicate_delivery")
    evidence: list[str] = []
    mutations: list[str] = []
    result, _ = e04.ledger_arm(env, pair, load_config(), evidence, [], mutations)
    assert result is record and mutations == ["old-operation"]
    assert "old_claimant_http_mutations_1" in evidence
    assert "old_claimant_http_status_200" in evidence
    assert f"old_claimant_service_outcome_{record.outcome}" in evidence
    assert "old_claimant_action_lost_claim_state_" + record.state + "_code_None" in evidence
    assert e04.settled_version(record) == (2 if committed else 1)
    with pytest.raises(ValueError):
        e04.settled_version(SimpleNamespace(state="unknown", outcome=None))  # type: ignore[arg-type]


def test_pending_items_execution_fixture_avoids_refused_float_money_without_changing_rule_prices(
        monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, Any]] = []

    class Connection:
        def execute(self, sql: str, params: Any) -> None:
            if sql.startswith("UPDATE retail.case_states"):
                captured.append(json.loads(params[0]))

    class Database:
        @contextmanager
        def superuser(self) -> Any:
            yield Connection()

    env = environments.Env(Database(), None, "http://127.0.0.1:1", FixedClock(NOW),  # type: ignore[arg-type]
        SimpleNamespace(run=SimpleNamespace(workspace_id=UUID(int=1), case_id=UUID(int=2))),  # type: ignore[arg-type]
        UUID(int=3), UUID(int=4), customer="example_user_0001")
    monkeypatch.setattr(matrix, "observe", lambda _: (None, {
        "users": {env.customer: {}}, "orders": {}, "products": {}}, ()))
    case = next(c for c in CASES if c.tool == "modify_pending_order_items" and c.expect.kind == "preview")
    matrix.seed_rule_fixture(env, case)
    matrix.seed_rule_fixture(env, case, execution=True)
    differences = []
    for full in captured:
        order = full["orders"][W.order_id]
        price = order["items"][0]["price"]
        target = full["products"][W.product]["variants"][W.item_c]["price"]
        differences.append(target - price)
        assert money_from_upstream(order["payment_history"][0]["amount"]).amount_minor == sum(
            money_from_upstream(i["price"]).amount_minor for i in order["items"])
        assert full["products"][W.product]["variants"][W.item_a]["price"] == price
    assert captured[0]["orders"][W.order_id]["items"][0]["price"] == 19.99
    assert differences[0] == 10.010000000000002
    with pytest.raises(MoneyError):
        money_from_upstream(differences[0])
    assert money_from_upstream(differences[1]) == Money(amount_minor=1000)


@pytest.mark.parametrize("corruption", ["operation", "effect", "state_hash", "diff", "remote_omitted"])
def test_receipts_are_matched_to_operation_effect_version_and_actual_state(corruption: str) -> None:
    row = golden()
    raw = row.remote_receipts[0].model_dump(mode="json")
    if corruption == "operation":
        raw["operation_sha256"] = "f" * 64
    elif corruption == "effect":
        raw["actual_effect"]["reason"] = "ordered by mistake"
    elif corruption == "state_hash":
        raw["state_sha256_after"] = "f" * 64
    receipt = Receipt.model_validate_json(canonical(raw))
    row = row.model_copy(update={"held_receipts": (receipt,), "remote_receipts": (receipt,)})
    if corruption == "diff":
        row = row.model_copy(update={"actual_diff": ()})
    if corruption == "remote_omitted":
        row = row.model_copy(update={"remote_receipts": ()})
    with pytest.raises(ValueError):
        assert_ledger(row)


def test_extra_effect_count_is_not_the_count_of_duplicate_trials() -> None:
    row = golden()
    assert row.after is not None
    receipt = row.remote_receipts[0]
    second = receipt.model_copy(update={"operation_id": str(UUID(int=5)), "case_version_before": 2,
                                        "case_version_after": 3})
    third = receipt.model_copy(update={"operation_id": str(UUID(int=6)), "case_version_before": 3,
                                       "case_version_after": 4})
    row = row.model_copy(update={"after": row.after.model_copy(update={"version": 4}),
        "remote_receipts": (receipt, second, third), "held_receipts": (receipt, second, third),
        "operations": {r.operation_id: r.operation_sha256 for r in (receipt, second, third)}})
    arm = summarize([row])["arms"]["ledger"]
    assert arm["duplicate_trials"] == 1 and arm["extra_effects"] == 2 and arm["effect_count"] == 3


def test_missing_same_count_duplicate_and_wrong_schedule_slots_fail_completeness() -> None:
    report = envelope()
    assert verify(report) == []
    assert completeness(report.config, [], report.trials, report.suites, report.pair_ids) == []
    assert "e04_manifest_mismatch" in completeness(report.config, [], [report.trials[0]], ("e04",), report.pair_ids)
    assert "e04_manifest_mismatch" in completeness(report.config, [], [report.trials[0]] * 2, ("e04",), report.pair_ids)
    wrong = report.trials[0].model_copy(update={"seed": 0})
    assert "e04_schedule_mismatch" in completeness(report.config, [], [wrong, report.trials[1]],
                                                   ("e04",), report.pair_ids)


def test_all_report_mutation_sensitivity_controls_detect_corruption() -> None:
    assert all(c.detected for c in sensitivity.report_controls(load_config(), golden()))
    assert_foreign_hidden(0)
    with pytest.raises(ValueError):
        assert_foreign_hidden(1)


def test_modelled_crash_is_not_swallowed_by_ordinary_application_exception_handlers() -> None:
    hooks = Hooks("before_send")
    with pytest.raises(ProcessCrash):
        try:
            hooks.before_send(None)  # type: ignore[arg-type]
        except Exception:
            pytest.fail("ordinary application handler swallowed process crash")
    assert hooks.fired == ["before_send"]
    hooks.before_send(None)  # type: ignore[arg-type]


def test_timeout_gate_applies_to_mutation_only_and_restores_client_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    env = SimpleNamespace(service=SimpleNamespace(key=b"x" * 32),
                          run=SimpleNamespace(workspace_id=UUID(int=1), case_id=UUID(int=2)),
                          customer="example_user_0001")
    observed = []

    def mutate(client: RetailClient, *args: Any, **kwargs: Any) -> Unknown:
        observed.append(client._http.timeout.read)
        raise RuntimeError("synthetic timeout control")

    monkeypatch.setattr(RetailClient, "mutate", mutate)
    with client_factory(env, "http://127.0.0.1:1", timeout=0.25) as client:  # type: ignore[arg-type]
        assert client._http.timeout.read == 10
        with pytest.raises(RuntimeError):
            client.mutate(UUID(int=3), None)  # type: ignore[arg-type]
        assert client._http.timeout.read == 10
    assert observed == [0.25]


def test_long_study_cases_do_not_reuse_a_stale_transport_lease_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    old = FixedClock(datetime(2020, 1, 1, tzinfo=UTC))
    base = environments.Env(None, None, "http://127.0.0.1:1", old, None, UUID(int=1), UUID(int=2))  # type: ignore[arg-type]
    captured = []

    def fresh(previous: environments.Env, *args: Any, **kwargs: Any) -> environments.Env:
        captured.append(previous.clock.now())
        return previous

    monkeypatch.setattr(environments, "fresh_case", fresh)
    before = datetime.now(UTC)
    env = environments.study_case(base)
    assert before <= env.clock.now() <= datetime.now(UTC)
    assert captured == [env.clock.now()] and base.clock.now().year == 2020


def test_public_summary_has_only_allowlisted_fields_and_no_raw_or_local_metadata() -> None:
    report = envelope()
    summary = public_summary(report)
    assert summary["schema_version"] == "policyops.safety-summary/v1" and summary["acceptance_passed"]
    assert set(summary) == {"schema_version", "study_id", "config_sha256", "source_sha256", "fixture_sha256",
        "report_sha256", "provider_mode", "arms", "matrix_scheduled", "matrix_executed", "matrix_passed",
        "limits", "acceptance_passed", "limitations", "partial_rerun", "suites", "counts"}
    text = canonical(summary).decode()
    assert "raw" not in summary and "local_path" not in text and "code_identity" not in text
    assert report.trials[0].case_id not in text and report.trials[0].remote_receipts[0].operation_id not in text


def test_sealed_artifact_replay_detects_modified_and_missing_trial_files(tmp_path: Path,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    recorder = cli.output_recorder(tmp_path / "study")
    report = envelope()
    recorder.write_artifact("raw/trials/golden.json", canonical(report.trials[0].model_dump(mode="json")), "output")
    seal(recorder, report)
    path = recorder.root / "raw/study.json"
    assert cli.verify_file(path) == []
    trial = recorder.root / "raw/trials/golden.json"
    trial.write_bytes(b"{}")
    assert "artifact_hash_or_size_mismatch" in cli.verify_file(path)
    trial.unlink()
    assert "artifact_hash_or_size_mismatch" in cli.verify_file(path)


def test_output_refuses_outside_root_existing_output_and_reviewer_paths(tmp_path: Path,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    with pytest.raises(EvidenceError):
        cli.output_recorder(tmp_path.parent / "escape-t30-no-create")
    for component in ("reviewer", "ReVieWeR"):
        target = tmp_path / component / "builder"
        with pytest.raises(EvidenceError):
            cli.output_recorder(target)
        assert not target.parent.exists()
    target = tmp_path / "already-present"
    target.mkdir()
    with pytest.raises(EvidenceError):
        cli.output_recorder(target)


def test_setup_failure_is_sealed_with_both_slots_and_without_exception_text(tmp_path: Path,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    canary = "private-diagnostic-t30-must-not-persist"

    @contextmanager
    def unavailable(*args: Any) -> Any:
        if args:
            raise RuntimeError(canary)
        yield  # pragma: no cover

    monkeypatch.setattr(cli, "owned_postgres", unavailable)
    monkeypatch.setattr(cli, "git_identity", lambda _: CODE)
    recorder = cli.output_recorder(tmp_path / "setup-failure")
    config = load_config()
    pair_id = config.pairs[0].pair_id
    report = cli.execute(config, recorder, ("e04",), (pair_id,), ("unit_failure_control",))
    assert report.exit_code == 1 and len(report.trials) == 2
    assert {row.final_state for row in report.trials} == {"aborted"}
    assert all(score(row).effects is None for row in report.trials)
    seal(recorder, report)
    assert canary not in (recorder.root / "raw/study.json").read_text(encoding="utf-8")


def test_cli_invalid_selection_and_malformed_config_fail_before_output_creation(tmp_path: Path,
                                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    target = tmp_path / "should-not-exist"
    assert cli.main(["--suite", "unknown", "--out", str(target)]) == 2
    assert cli.main(["--pair-id", "pair-999", "--out", str(target)]) == 2
    config_path = tmp_path / "malformed.json"
    config_path.write_text(json.dumps({"unexpected": True}), encoding="utf-8")
    assert cli.main(["--config", str(config_path), "--out", str(target)]) == 2
    assert not target.exists()
