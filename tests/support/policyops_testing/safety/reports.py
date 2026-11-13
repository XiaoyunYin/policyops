"""Raw observations and independently recomputable safety scoring and sealed reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from policyops_contracts.evidence import CodeIdentity
from policyops_contracts.retail import Effect
from policyops_contracts.retail_service import Receipt
from policyops_testing.evidence import EvidenceRecorder
from policyops_testing.safety.config import Arm, Config, Fault, StrictModel, Variant, canonical, digest


Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[int, Field(ge=0, le=10000)]


class State(StrictModel):
    version: Annotated[int, Field(ge=1)]
    full_sha256: Sha
    scoped: dict[str, Any]  # fixture-scoped JSON only, bounded on construction

    @model_validator(mode="after")
    def bounded(self) -> State:
        if len(canonical(self.scoped)) > 256 * 1024:
            raise ValueError("scoped observation exceeds 256 KiB")
        return self


class Change(StrictModel):
    path: Annotated[str, Field(min_length=1, max_length=256)]
    before: Any
    after: Any


def changes(before: object, after: object, path: str = "") -> list[Change]:
    if before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        return [c for key in sorted(before.keys() | after.keys())
                for c in changes(before.get(key), after.get(key), f"{path}/{key}")]
    # Lists stay atomic: quantities and payment entries must remain in their exact order.
    return [Change(path=path or "/", before=before, after=after)]


class Trial(StrictModel):
    row_type: Literal["e04"] = "e04"
    pair_id: str
    seed: int
    arm: Arm
    fault: Fault
    variant: Variant
    case_id: str
    run_id: str
    started_at: datetime
    finished_at: datetime
    application_clock_start: datetime
    transport_clock: Literal["per-request system wall clock"] = "per-request system wall clock"
    fault_reached: bool
    fault_evidence: Annotated[tuple[str, ...], Field(max_length=32)] = ()
    sends: Count
    dispatch_checkpoints: Count = 0
    mutation_operations: Annotated[tuple[str, ...], Field(max_length=16)] = ()
    reconciles: Count
    passes: Count
    final_state: Literal["succeeded", "failed", "reconciled", "pending", "dispatched", "unknown", "aborted"]
    outcome: str | None
    before: State | None
    after: State | None
    expected_diff: Annotated[tuple[Change, ...], Field(max_length=128)] = ()
    expected_effect: Effect | None = None
    expected_full_sha256: Sha | None = None
    operations: dict[str, Sha] = Field(default_factory=dict)
    actual_diff: Annotated[tuple[Change, ...], Field(max_length=128)] = ()
    remote_receipts: Annotated[tuple[Receipt, ...], Field(max_length=16)] = ()
    held_receipts: Annotated[tuple[Receipt, ...], Field(max_length=16)] = ()
    unknowns: Annotated[tuple[str, ...], Field(max_length=64)] = ()
    error: str | None = None  # exception TYPE only


class MatrixRow(StrictModel):
    row_type: Literal["matrix"] = "matrix"
    cell_id: str
    action: str | None = None
    tool: str | None = None
    rule: str | None = None
    roles: tuple[str, ...] = ()
    relationship: str
    preconditions: tuple[str, ...] = ()
    expected: str
    expected_code: str | None = None
    expected_rule: str | None = None
    observed: str
    code: str | None = None
    observed_rule: str | None = None
    layer: str
    identities: dict[str, tuple[str, str, bool, bool, bool]] = Field(default_factory=dict)
    database_evidence: dict[str, Any] = Field(default_factory=dict)
    before_sha256: Sha
    after_sha256: Sha
    passed: bool
    error: str | None = None


class Sensitivity(StrictModel):
    check_id: str
    detected: bool
    evidence: dict[str, Any]


class Scored(StrictModel):
    effects: int | None
    extra_effects: int | None
    forbidden_effects: int | None
    missing_receipts: int | None
    false_success: bool
    failed_with_effect: bool
    unresolved: bool
    errors: tuple[str, ...]


def score(row: Trial) -> Scored:
    errors: list[str] = []
    if row.sends != len(row.mutation_operations) or any(op not in row.operations for op in row.mutation_operations):
        errors.append("send_observation_mismatch")
    if row.sends > 3 or row.dispatch_checkpoints > 3 or row.reconciles > 8:
        errors.append("execution_cap_exceeded")
    if row.before is None or row.after is None:
        return Scored(effects=None, extra_effects=None, forbidden_effects=None, missing_receipts=None,
                      false_success=row.final_state == "succeeded", failed_with_effect=False, unresolved=True,
                      errors=("unobserved_effects",))
    count = row.after.version - row.before.version
    if count < 0:
        errors.append("version_regressed")
    receipts = sorted(row.remote_receipts, key=lambda r: r.case_version_before)
    if len(receipts) != count or len({r.operation_id for r in receipts}) != count:
        errors.append("effect_receipt_count_mismatch")
    version = row.before.version
    for receipt in receipts:
        if row.operations.get(receipt.operation_id) != receipt.operation_sha256:
            errors.append("receipt_operation_link_mismatch")
        if receipt.case_version_before != version:
            errors.append("effect_version_chain_mismatch")
        version = receipt.case_version_after
        if receipt.actual_effect != row.expected_effect:
            errors.append("receipt_effect_mismatch")
    if receipts and receipts[-1].state_sha256_after != row.after.full_sha256:
        errors.append("effect_state_hash_mismatch")
    actual = tuple(changes(row.before.scoped, row.after.scoped))
    if actual != row.actual_diff:
        errors.append("recorded_diff_mismatch")
    forbidden = int(count > 0 and (actual != row.expected_diff or row.after.full_sha256 != row.expected_full_sha256))
    if count == 0 and actual:
        errors.append("state_changed_without_version")
        forbidden += 1
    remote_keys = {digest(r.model_dump(mode="json")) for r in receipts}
    held_keys = {digest(r.model_dump(mode="json")) for r in row.held_receipts}
    if not held_keys <= remote_keys:
        errors.append("held_receipt_not_observed")
    missing = len(remote_keys - held_keys)
    if not row.fault_reached:
        errors.append("fault_not_reached")
    if row.error:
        errors.append("aborted")
    false_success = row.final_state == "succeeded" and (count != 1 or missing > 0 or bool(errors) or forbidden > 0)
    return Scored(effects=count, extra_effects=max(count - 1, 0), forbidden_effects=forbidden,
                  missing_receipts=missing, false_success=false_success,
                  failed_with_effect=row.final_state == "failed" and count > 0,
                  unresolved=row.final_state in ("pending", "dispatched", "unknown", "aborted"), errors=tuple(errors))


def settlement(row: Trial) -> Literal["completed_once", "fenced_no_effect"] | None:
    """One acceptance rule for runtime checks, summaries and offline report replay."""
    scored = score(row)
    if (scored.errors or scored.extra_effects or scored.forbidden_effects
            or scored.missing_receipts or scored.false_success or scored.unresolved or scored.failed_with_effect):
        return None
    if row.final_state == "succeeded" and row.outcome == "committed" and scored.effects == 1:
        return "completed_once"
    if (row.final_state == "reconciled" and row.outcome == "fenced" and scored.effects == 0
            and not row.remote_receipts and not row.held_receipts and row.before is not None
            and row.after is not None and row.before.full_sha256 == row.after.full_sha256):
        return "fenced_no_effect"
    return None


def assert_ledger(row: Trial) -> None:
    if settlement(row) is None:
        raise ValueError("ledger safety/effect/receipt assertion failed")


def summarize(rows: list[Trial]) -> dict[str, Any]:
    arms: dict[str, Any] = {}
    for arm in ("ledger", "naive_new_id"):
        selected = [row for row in rows if row.arm == arm]
        scored = [score(row) for row in selected]
        arms[arm] = {
            "completed_once": sum(settlement(row) == "completed_once" for row in selected),
            "fenced_no_effect": sum(settlement(row) == "fenced_no_effect" for row in selected),
            "fault_variant_breakdown": [
                {"fault": fault, "variant": variant, "scheduled": len(group),
                 "completed_once": sum(settlement(row) == "completed_once" for row in group),
                 "fenced_no_effect": sum(settlement(row) == "fenced_no_effect" for row in group)}
                for fault, variant in sorted({(r.fault, r.variant) for r in selected})
                for group in [[r for r in selected if (r.fault, r.variant) == (fault, variant)]]],
            "scheduled": len(selected), "observed": sum(s.effects is not None for s in scored),
            "effect_count": None if any(s.effects is None for s in scored) else sum(s.effects or 0 for s in scored),
            "observed_effect_count": sum(s.effects or 0 for s in scored),
            "unobserved_trials": sum(s.effects is None for s in scored),
            "duplicate_trials": sum(s.effects is not None and s.effects > 1 for s in scored),
            "extra_effects": sum(s.extra_effects or 0 for s in scored),
            "forbidden_effects": sum(s.forbidden_effects or 0 for s in scored),
            "effects_missing_held_receipt": sum(s.missing_receipts or 0 for s in scored),
            "terminal_failure_with_effect": sum(s.failed_with_effect for s in scored),
            "false_success": sum(s.false_success for s in scored), "unresolved": sum(s.unresolved for s in scored),
            "aborted": sum(row.error is not None for row in selected),
            "transient_unknowns": sum(len(row.unknowns) for row in selected),
            "faults": dict(Counter(row.fault for row in selected)),
            "variants": dict(Counter(row.variant for row in selected)),
            "scoring_errors": sum(bool(s.errors) for s in scored),
        }
    differences = []
    for pair_id in sorted({row.pair_id for row in rows}):
        pair = {row.arm: row for row in rows if row.pair_id == pair_id}
        if len(pair) != 2:
            continue
        left, right = score(pair["ledger"]), score(pair["naive_new_id"])
        differences.append({"pair_id": pair_id, "seed": pair["ledger"].seed,
                            "fault": pair["ledger"].fault, "variant": pair["ledger"].variant,
                            "effects_ledger_minus_naive": None if left.effects is None or right.effects is None
                            else left.effects - right.effects,
                            "missing_receipts_ledger_minus_naive": None if left.missing_receipts is None
                            or right.missing_receipts is None else left.missing_receipts - right.missing_receipts})
    return {"arms": arms, "paired_differences": differences}


def completeness(config: Config, matrix: list[MatrixRow], trials: list[Trial], suites: tuple[str, ...],
                 pair_ids: tuple[str, ...] = ()) -> list[str]:
    errors = []
    if "matrix" in suites:
        actual = [row.cell_id for row in matrix]
        if len(actual) != len(set(actual)) or set(actual) != set(config.matrix_ids):
            errors.append("matrix_manifest_mismatch")
        if any(not row.passed or row.error for row in matrix):
            errors.append("matrix_failed")
        if any(row.expected != row.observed or (
                (row.cell_id.startswith("rule/") or row.expected_code is not None) and row.code != row.expected_code)
               or (row.expected_rule is not None and row.observed_rule != row.expected_rule) for row in matrix):
            errors.append("matrix_observation_mismatch")
    if "e04" in suites:
        pairs = [p for p in config.pairs if not pair_ids or p.pair_id in pair_ids]
        expected = {(p.pair_id, a) for p in pairs for a in p.arms}
        actual_trials = [(r.pair_id, r.arm) for r in trials]
        if len(actual_trials) != len(set(actual_trials)) or set(actual_trials) != expected:
            errors.append("e04_manifest_mismatch")
        if len({r.case_id for r in trials}) != len(trials) or len({r.run_id for r in trials}) != len(trials):
            errors.append("e04_case_or_run_reused")
        operation_ids = [op for r in trials for op in r.operations]
        if len(set(operation_ids)) != len(operation_ids):
            errors.append("e04_operation_reused_between_arms")
        by_pair = {p.pair_id: p for p in pairs}
        for row in trials:
            pair = by_pair.get(row.pair_id)
            if pair is None or (row.seed, row.fault, row.variant) != (pair.seed, pair.fault, pair.variant):
                errors.append("e04_schedule_mismatch")
            if pair is not None and (row.case_id, row.run_id) != (str(pair.identity(row.arm, "case")),
                                                               str(pair.identity(row.arm, "run"))):
                errors.append("e04_identity_mismatch")
            if row.arm == "ledger":
                try:
                    assert_ledger(row)
                except ValueError:
                    errors.append("ledger_failed")
            elif score(row).errors:
                errors.append("naive_observation_failed")
        for pair in pairs:
            matching = [r for r in trials if r.pair_id == pair.pair_id]
            if (len(matching) == 2 and all(r.before is not None for r in matching)
                    and digest(matching[0].before.scoped) != digest(matching[1].before.scoped)):  # type: ignore[union-attr]
                errors.append("paired_initial_state_mismatch")
    return sorted(set(errors))


class Envelope(StrictModel):
    schema_version: Literal["policyops.safety-study/v1"] = "policyops.safety-study/v1"
    study_id: str
    config: Config
    config_sha256: Sha
    source_hashes: dict[str, Sha]
    code_identity: dict[str, Any]
    environment: dict[str, str]
    versions: dict[str, str]
    command: tuple[str, ...]
    exit_code: int
    started_at: datetime
    finished_at: datetime
    suites: tuple[str, ...]
    pair_ids: tuple[str, ...]
    provider_mode: Literal["none"] = "none"
    effective_model: Literal["none"] = "none"
    matrix: Annotated[list[MatrixRow], Field(max_length=2000)]
    trials: Annotated[list[Trial], Field(max_length=200)]
    sensitivity: Annotated[list[Sensitivity], Field(max_length=32)]
    supplements: dict[str, Any]
    failures: tuple[str, ...]
    summary: dict[str, Any]
    limitations: tuple[str, ...]
    execution_counts: dict[str, dict[str, int]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def exact_counts(self) -> Envelope:
        observed = counts(self)
        if self.execution_counts and self.execution_counts != observed:
            raise ValueError("execution counts differ from raw rows")
        object.__setattr__(self, "execution_counts", observed)
        return self


def counts(envelope: Envelope) -> dict[str, dict[str, int]]:
    return {
        "matrix": {"scheduled": len(envelope.config.matrix_ids) if "matrix" in envelope.suites else 0,
                   "executed": sum(r.error is None and r.observed != "aborted" for r in envelope.matrix),
                   "aborted": sum(r.error is not None or r.observed == "aborted" for r in envelope.matrix),
                   "skipped": 0,
                   "admission_only": sum(r.layer == "auth_admission_only" for r in envelope.matrix)},
        "e04": {"scheduled": 2 * (len(envelope.pair_ids) if envelope.pair_ids else 100)
                if "e04" in envelope.suites else 0,
                "executed": sum(r.error is None for r in envelope.trials),
                "aborted": sum(r.error is not None for r in envelope.trials), "skipped": 0},
    }


def verify(envelope: Envelope) -> list[str]:
    errors = completeness(envelope.config, envelope.matrix, envelope.trials, envelope.suites, envelope.pair_ids)
    if digest(envelope.config.model_dump(mode="json")) != envelope.config_sha256:
        errors.append("config_hash_mismatch")
    if summarize(envelope.trials) != envelope.summary:
        errors.append("summary_mismatch")
    if envelope.execution_counts != counts(envelope):
        errors.append("execution_counts_mismatch")
    for item in envelope.sensitivity:
        if not item.detected:
            errors.append("sensitivity_not_detected")
    required = ({"reviewer_role_guard_removed", "authentication_rls_disabled"}
                if "matrix" in envelope.suites else set()) \
        | ({"held_receipt_removed", "effect_link_tampered", "trial_row_omitted", "real_subprocess_kill_restart"}
           if "e04" in envelope.suites else set())
    if len(envelope.sensitivity) != len(required) or {c.check_id for c in envelope.sensitivity} != required:
        errors.append("sensitivity_incomplete")
    if envelope.exit_code != int(bool(envelope.failures)):
        errors.append("exit_code_mismatch")
    return sorted(set(errors))


def public_summary(envelope: Envelope) -> dict[str, Any]:
    return {"schema_version": "policyops.safety-summary/v1", "study_id": envelope.study_id,
            "config_sha256": envelope.config_sha256,
            "source_sha256": digest(envelope.source_hashes), "fixture_sha256": envelope.versions["fixture_sha256"],
            "report_sha256": digest(envelope.model_dump(mode="json")), "provider_mode": "none",
            "suites": list(envelope.suites), "counts": counts(envelope),
            "arms": envelope.summary["arms"], "matrix_scheduled": len(envelope.config.matrix_ids),
            "matrix_executed": len(envelope.matrix), "matrix_passed": sum(r.passed for r in envelope.matrix),
            "limits": {"naive_max_sends": 3, "ledger_dispatches": 3, "ledger_reconciles": 8},
            "acceptance_passed": not envelope.failures and not verify(envelope),
            "limitations": list(envelope.limitations), "partial_rerun": bool(envelope.pair_ids)}


def seal(recorder: EvidenceRecorder, envelope: Envelope) -> None:
    recorder.write_artifact("raw/config.json", canonical(envelope.config.model_dump(mode="json")), role="config")
    recorder.write_artifact("raw/matrix.json", canonical([r.model_dump(mode="json") for r in envelope.matrix]),
                            role="output")
    for row in envelope.trials:
        recorder.write_artifact(f"raw/trials/{row.pair_id}-{row.arm}.json", canonical(row.model_dump(mode="json")),
                                role="output")
    recorder.write_artifact("raw/study.json", canonical(envelope.model_dump(mode="json")), role="report")
    recorder.write_artifact("raw/summary.json", canonical(public_summary(envelope)), role="report")
    recorder.finish(CodeIdentity.model_validate(envelope.code_identity))


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
