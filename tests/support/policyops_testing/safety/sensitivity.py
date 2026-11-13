"""Counterfactual guard and report-corruption controls, outside mandatory denominators."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction
from policyops.persistence.roles import AUTH_RUNTIME
from policyops.services.execution import ExecutionHooks
from policyops_contracts.retail_service import Receipt
from policyops_testing.app_database import AppCluster
from policyops_testing.safety.config import Config, canonical
from policyops_testing.safety.e04 import observe
from policyops_testing.safety.environment import Env, make_env
from policyops_testing.safety.reports import Sensitivity, Trial, assert_ledger, completeness
from policyops_testing.safety.rls import assert_foreign_hidden, foreign_read


def assert_zero_effect(env: Env) -> None:
    state, _, receipts = observe(env)
    if state.version != 1 or receipts:
        raise ValueError("forbidden committed effect")


def reviewer_guard(base: Env) -> Sensitivity:
    observations: dict[str, Any] = {}
    for removed in (False, True):
        env = make_env((base.service, base.origin), base.db)
        refs = env.approve()
        execution_id = env.reserve(refs)

        class Revoke(ExecutionHooks):
            test_only = True

            def __init__(self, target: Env) -> None:
                self.target = target

            def before_checkpoint(self, execution: Any) -> None:
                with transaction(self.target.db.engine(AUTH_RUNTIME)) as conn:
                    assert repo.revoke_membership(conn, self.target.membership, self.target.clock.now())

        dispatcher = env.dispatcher(hooks=Revoke(env))
        original = dispatcher.executor._checkpoint

        def checkpoint(execution: Any, cleared: Any, original: Any = original) -> Any:
            # Exactly the final checkpoint, after successful real precheck AND membership revocation.
            with patch.object(repo, "locked_roles", return_value=["reviewer"]):
                return original(execution, cleared)

        if removed:
            dispatcher.executor._checkpoint = checkpoint  # type: ignore[method-assign]
        step = dispatcher.executor.step(env.run.workspace_id, execution_id)
        detected = False
        try:
            assert_zero_effect(env)  # IDENTICAL assertion in both arms
        except ValueError:
            detected = True
        state, _, receipts = observe(env)
        observations["removed" if removed else "restored"] = {
            "assertion_failed": detected, "case_version": state.version,
            "receipts": [r.model_dump(mode="json") for r in receipts], "step": step.action,
        }
    return Sensitivity(check_id="reviewer_role_guard_removed",
        detected=observations["removed"]["assertion_failed"] and not observations["restored"]["assertion_failed"],
        evidence=observations)


def rls_guard(base: Env, cluster: AppCluster) -> Sensitivity:
    # Disposable migrated DB: no shared DB policy is ever disabled.
    db = cluster.create_database("t30_rls_control")
    try:
        db.upgrade()
        env = make_env((base.service, base.origin), db)
        foreign = make_env((base.service, base.origin), db)
        counts = []
        failures = []
        for removed in (False, True, False):
            with db.superuser() as conn:
                conn.execute("ALTER TABLE app.customer_authentications " + (
                    "DISABLE ROW LEVEL SECURITY" if removed else "ENABLE ROW LEVEL SECURITY"))
            count = foreign_read(env, "app.customer_authentications", "run_id", env.run.run_id,
                                 foreign.run.workspace_id)
            counts.append(count)
            failed = False
            try:
                assert_foreign_hidden(count)  # IDENTICAL assertion before, during and after mutation
            except ValueError:
                failed = True
            failures.append(failed)
        return Sensitivity(check_id="authentication_rls_disabled", detected=failures == [False, True, False],
                           evidence={"foreign_read_rows": counts, "assertion_failed": failures,
                                     "actor": "app_runtime", "disposable_database": True})
    finally:
        try:
            with db.superuser() as conn:
                conn.execute("ALTER TABLE app.customer_authentications ENABLE ROW LEVEL SECURITY")
                conn.execute("ALTER TABLE app.customer_authentications FORCE ROW LEVEL SECURITY")
        finally:
            db.dispose()


def report_controls(config: Config, completed: Trial) -> list[Sensitivity]:
    assert_ledger(completed)
    controls = []
    changed = completed.model_copy(update={"held_receipts": ()})
    failed = False
    try:
        assert_ledger(changed)
    except ValueError:
        failed = True
    controls.append(Sensitivity(check_id="held_receipt_removed", detected=failed,
                                evidence={"pair_id": completed.pair_id, "assertion_failed": failed}))
    receipt = completed.remote_receipts[0]
    raw = receipt.model_dump(mode="json")
    if completed.variant == "cancel":
        raw["actual_effect"]["reason"] = "ordered by mistake"
    elif completed.variant == "pending_address":
        raw["actual_effect"]["address_after"]["city"] = "Tampered City"
    else:
        raw["actual_effect"]["refund_payment_method_id"] = "credit_card_9999999"
    tampered = Receipt.model_validate_json(canonical(raw))
    failed = False
    try:
        assert_ledger(completed.model_copy(update={"remote_receipts": (tampered,), "held_receipts": (tampered,)}))
    except ValueError:
        failed = True
    controls.append(Sensitivity(check_id="effect_link_tampered", detected=failed,
                                evidence={"pair_id": completed.pair_id, "assertion_failed": failed}))
    # Both arm slots are expected even for an exact-pair rerun; dropping either is an error.
    failed = "e04_manifest_mismatch" in completeness(config, [], [completed], ("e04",), (completed.pair_id,))
    controls.append(Sensitivity(check_id="trial_row_omitted", detected=failed,
                                evidence={"pair_id": completed.pair_id, "assertion_failed": failed}))
    return controls


def e05_controls(base: Env) -> list[Sensitivity]:
    """Real stale-role and once-only replay mutations; identical E05 assertion before/after removal."""
    from contextlib import nullcontext
    import json

    from policyops.services.execution import Executor, LedgerHistory
    from policyops_contracts.retail import OrderOperationHistory
    from policyops_testing.safety import e05
    from policyops_testing.safety.config import load_e05_config
    from policyops_testing.safety.e05_cli import run_row
    from policyops_testing.safety.e05_reports import Row, assert_gateway
    from policyops_testing.safety.environment import next_run
    from policyops_testing.safety.reports import changes

    config = load_e05_config()
    stale = next(f for f in config.fixtures if f.scenario == "revoke_checkpoint")
    original = Executor._checkpoint

    def checkpoint(self: Any, execution: Any, cleared: Any) -> Any:
        with patch.object(repo, "locked_roles", return_value=["reviewer"]):
            return original(self, execution, cleared)

    outcomes: dict[str, Any] = {}
    for removed in (False, True, False):
        with patch.object(Executor, "_checkpoint", checkpoint) if removed else nullcontext():
            row = run_row(base, stale, "gateway", e05.candidate(stale))
        failed = False
        try:
            assert_gateway(row, stale)
        except ValueError:
            failed = True
        outcomes[str(len(outcomes))] = {"removed": removed, "assertion_failed": failed,
            "error": row.error, "race_reached": row.race_reached,
            "effects": None if row.before is None or row.after is None else row.after.version - row.before.version,
            "receipts": [r.model_dump(mode="json") for r in row.remote_receipts]}
    checks = [Sensitivity(check_id="e05_stale_guard_removed", detected=(
        [v["assertion_failed"] for v in outcomes.values()] == [False, True, False]
        and [v["effects"] for v in outcomes.values()] == [0, 1, 0]
        and all(v["error"] is None and v["race_reached"] for v in outcomes.values())), evidence=outcomes)]

    replay = next(f for f in config.fixtures if f.scenario == "completed_replay")
    outcomes = {}
    for removed in (False, True, False):
        env = e05.fixture_env(base, replay)
        measured = e05.prepare_fixture(env, replay, "gateway")
        env = next_run(env)
        second_call = json.loads(replay.trusted_call_json)
        second_call["address1"] = "3 Repeated Modification Way"
        second = replay.model_copy(update={"scenario": "valid_address", "category": "valid",
                                          "trusted_call_json": json.dumps(second_call)})
        code = "once_per_order_refused"
        held: tuple[Receipt, ...] = ()
        operations = {}
        with patch.object(LedgerHistory, "history", return_value=OrderOperationHistory(
                order_id=env.order, complete=True, successful_tools=())) if removed else nullcontext():
            try:
                auth = e05.authority(env, second)
            except ValueError as exc:
                if str(exc) != "trusted_proposal_unreachable":
                    raise
            else:
                execution_id = env.reserve(auth.refs)
                env.dispatcher().executor.step(env.run.workspace_id, execution_id)
                from policyops_testing.safety.environment import ledger_record
                record = ledger_record(env, execution_id)
                held = () if record.receipt is None else (record.receipt,)
                from contextlib import closing
                with closing(env.client()) as client:
                    operations[str(record.operation_id)] = client.fingerprint(record.operation_id, record.request)
                code = record.state
        after, _, receipts = observe(env)
        initial = {r.operation_id for r in measured.setup_receipts}
        remote = tuple(r for r in receipts if r.operation_id not in initial)
        row = Row(fixture_id=replay.fixture_id, seed=replay.seed, arm="gateway", proposed=e05.candidate(replay),
            layer="effect" if remote else "gateway", code=code, before=measured.before, after=after,
            expected_sha256=measured.before.full_sha256,
            actual_diff=tuple(changes(measured.before.scoped, after.scoped)),
            remote_receipts=remote, held_receipts=held, operations=operations, race_reached=True)
        failed = False
        try:
            assert_gateway(row, replay)
        except ValueError:
            failed = True
        outcomes[str(len(outcomes))] = {"removed": removed, "assertion_failed": failed,
            "effects": after.version - measured.before.version, "code": code,
            "receipts": [r.model_dump(mode="json") for r in remote]}
    checks.append(Sensitivity(check_id="e05_replay_guard_removed", detected=(
        [v["assertion_failed"] for v in outcomes.values()] == [False, True, False]
        and [v["effects"] for v in outcomes.values()] == [0, 1, 0]), evidence=outcomes))
    return checks
