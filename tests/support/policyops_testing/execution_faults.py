"""Reusable E04 development fault machinery for T19 (not the T30 study).

- `Crash`/`CrashHooks`: a finite, test-only crash plan around the one HTTP call (after the checkpoint, after the
  response). No OS signal or stuck process: the exception ends the "process" (the dispatcher call) and a new
  dispatcher plays the restart.
- `Trial`/`summarize`: one record per seeded trial with the actual receipts, the retail case-version delta (the
  committed effects), the final ledger state and every unknown/failure; `summarize` derives the totals from those
  raw records only (no score is invented, failed and unresolved trials stay in the denominator).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import random
from typing import Any

from policyops.persistence.records import ExecutionRecord
from policyops.services.execution import ExecutionHooks
from policyops_testing.evidence import _atomic_write, _contained_root


FAULTS = ("none", "commit_then_503", "fail_503_before", "crash_before_send", "crash_after_response")


class Crash(RuntimeError):
    """A modelled process death at a fault point."""


class CrashHooks(ExecutionHooks):
    test_only = True

    def __init__(self, *, before_send: int = 0, after_response: int = 0, before_checkpoint: Any = None) -> None:
        self.remaining = {"before_send": before_send, "after_response": after_response}
        self.checkpoint_action = before_checkpoint
        self.fired: list[str] = []

    def _fire(self, point: str) -> None:
        if self.remaining[point] > 0:
            self.remaining[point] -= 1
            self.fired.append(point)
            raise Crash(point)

    def before_checkpoint(self, execution: ExecutionRecord) -> None:
        if self.checkpoint_action is not None:
            action, self.checkpoint_action = self.checkpoint_action, None
            action(execution)

    def before_send(self, execution: ExecutionRecord) -> None:
        self._fire("before_send")

    def after_response(self, execution: ExecutionRecord, result: object) -> None:
        self._fire("after_response")


def fault_plan(seed: int, trials: int) -> list[str]:
    rng = random.Random(seed)  # noqa: S311 - a reproducible fault schedule, not a secret
    return [rng.choice(FAULTS) for _ in range(trials)]


@dataclass
class Trial:
    seed: int
    index: int
    arm: str  # "ledger" or "naive_new_id"
    fault: str
    final_state: str
    outcome: str | None
    attempts: int
    reconcile_attempts: int
    effects: int  # retail case_version_after - case_version_before, read from the simulator
    receipt_sha256: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    crashes: list[str] = field(default_factory=list)
    passes: int = 0
    receipts: list[dict[str, Any]] = field(default_factory=list)  # the actual receipt bodies (sha256 above)
    error: str | None = None  # an aborted trial (unexpected harness failure) stays in the denominator


def summarize(trials: list[Trial]) -> dict[str, Any]:
    """Totals per arm, derived only from the raw trial records."""
    out: dict[str, Any] = {}
    for arm in sorted({trial.arm for trial in trials}):
        rows = [trial for trial in trials if trial.arm == arm]
        out[arm] = {
            "trials": len(rows),
            "final_states": dict(Counter(trial.final_state for trial in rows)),
            "duplicate_effects": sum(trial.effects > 1 for trial in rows),
            "effects_without_receipt": sum(trial.effects > len(set(trial.receipt_sha256)) for trial in rows),
            "success_without_effect": sum(trial.final_state == "succeeded" and trial.effects == 0 for trial in rows),
            "unresolved": sum(trial.final_state in ("pending", "dispatched", "unknown") for trial in rows),
            "failed_with_effect": sum(trial.final_state == "failed" and trial.effects > 0 for trial in rows),
            "aborted": sum(trial.final_state == "aborted" for trial in rows),
            "faults": dict(Counter(trial.fault for trial in rows)),
        }
    return out


def write_report(path: Path, config: dict[str, Any], trials: list[Trial]) -> dict[str, Any]:
    """Write the report below POLICYOPS_TEMP_DIR. The destination is normalized and contained (no `..` escape, no
    link in the chain) before any directory is created; the file is replaced atomically, never followed as a link."""
    target = Path(os.path.abspath(path))  # noqa: PTH100 - lexical: a link must be refused, not followed
    parent, _ = _contained_root(target.parent)  # raises before any filesystem mutation outside the root
    report = {"config": config, "trials": [asdict(trial) for trial in trials], "summary": summarize(trials)}
    _atomic_write(parent / target.name, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return report
