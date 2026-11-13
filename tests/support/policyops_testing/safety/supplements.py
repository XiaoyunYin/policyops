"""Supplemental scenarios deliberately outside the paired study denominator."""

from __future__ import annotations

from contextlib import suppress
import socket
from typing import Any

from policyops_testing import network
from policyops_testing.safety.e04 import Hooks, ProcessCrash, observe, worker
from policyops_testing.safety.environment import Env, due, ledger_record, study_case


def run(base: Env) -> dict[str, Any]:
    results = {}
    for fault in ("commit_then_503", "crash_after_response", "capped_unknown"):
        env = study_case(base)
        execution_id = env.reserve(env.approve())
        if fault == "commit_then_503":
            env.arm("commit_then_503")
        hooks = Hooks("after_response" if fault == "crash_after_response" else None)
        for _ in range(0 if fault == "capped_unknown" else 16):
            with suppress(ProcessCrash):
                env.dispatcher(hooks=hooks).executor.step(env.run.workspace_id, execution_id)
            record = ledger_record(env, execution_id)
            if record.terminal or (record.state == "unknown" and record.next_attempt_at is None):
                break
            due(env)
        state, _, receipts = observe(env)
        record = ledger_record(env, execution_id)
        if fault == "capped_unknown":
            # Persist the dispatch checkpoint without sending, then make all subsequent
            # lookup/dispatch/fence HTTP unreachable. It remains ambiguous at the cap.
            with suppress(ProcessCrash):
                env.dispatcher(hooks=Hooks("before_send")).executor.step(env.run.workspace_id, execution_id)
            due(env)
            with socket.socket() as unavailable:
                unavailable.bind(("127.0.0.1", 0))
                port = unavailable.getsockname()[1]
                with network.allow("127.0.0.1", port):
                    for _ in range(16):
                        worker(env, Hooks(), f"http://127.0.0.1:{port}", timeout=0.25).executor.step(
                            env.run.workspace_id, execution_id)
                        record = ledger_record(env, execution_id)
                        if record.state == "unknown" and record.next_attempt_at is None:
                            break
                        due(env)
            state, _, receipts = observe(env)
            if record.state != "unknown" or record.next_attempt_at is not None or state.version != 1 or receipts:
                raise ValueError("capped unreachable outcome was not explicitly unresolved")
        elif (record.state != "succeeded" or state.version != 2 or len(receipts) != 1
              or record.receipt != receipts[0]):
            raise ValueError("finite supplemental fault did not recover one effect and its matching receipt")
        results[fault] = {"state": record.state, "outcome": record.outcome, "effects": state.version - 1,
                          "receipt_retained": record.receipt is not None, "remote_receipts": len(receipts),
                          "dispatch_checkpoints": record.attempts, "reconciles": record.reconcile_attempts,
                          "fault_points": hooks.fired, "outside_paired_denominator": True}
    return results
