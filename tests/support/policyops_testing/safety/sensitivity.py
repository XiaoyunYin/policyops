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
