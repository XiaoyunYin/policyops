"""A deterministic scripted executor and runtime spec for tests only (T09).

It never calls a model or provider. It emits a fixed number of `escalation.requested` events whose rule IDs say
`test.scripted.*`, so they cannot be mistaken for investigation output. Then it succeeds, fails or asks for a
retry, as configured. Optional threading events let a test hold it mid-run (for kill, cancel and expiry races).
The spec's digests are SHA-256 hashes of the script's own canonical definition (real bytes, not invented
values), and it is marked `test_only`, which runtime wiring refuses outside `env == "test"`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
import hashlib
import json
import threading
from typing import Literal

from policyops.runtime.spec import Failed, Outcome, Retry, RuntimeSpec, StepContext, Succeeded
from policyops_contracts.errors import ErrorCode
from policyops_contracts.events import EscalationRequested


@dataclass
class ScriptedExecutor:
    events: int = 1
    outcome: Literal["succeed", "fail", "retry"] = "succeed"
    started: threading.Event | None = None   # set once the executor is running
    release: threading.Event | None = None   # if given, wait for it before finishing
    wait_timeout: float = 30.0
    heartbeat_while_waiting: bool = False
    calls: int = 0
    emitted: list[int] = field(default_factory=list)
    test_only = True

    def execute(self, context: StepContext) -> Outcome:
        self.calls += 1
        for index in range(self.events):
            self.emitted.append(context.emit(EscalationRequested(rule_id=f"test.scripted.step-{index + 1}")))
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            while not self.release.wait(0.05 if self.heartbeat_while_waiting else self.wait_timeout):
                if self.heartbeat_while_waiting and not context.heartbeat():
                    break
        if self.outcome == "fail":
            return Failed(code=ErrorCode.POLICY_DENIED, rule_id="test.scripted.failed")
        if self.outcome == "retry":
            return Retry("test_scripted_retry")
        return Succeeded()


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def scripted_spec(executor: ScriptedExecutor, *, spec_id: str = "test.scripted-v1", max_attempts: int = 3,
                  lease: timedelta = timedelta(seconds=30), run_timeout: timedelta = timedelta(minutes=15)
                  ) -> RuntimeSpec:
    definition = {"spec_id": spec_id, "executor": "policyops_testing.scripted.ScriptedExecutor",
                  "events": executor.events, "outcome": executor.outcome}
    return RuntimeSpec(spec_id=spec_id, graph_sha256=digest({"graph": definition}),
                       prompt_sha256=digest({"prompt": "none (scripted test executor; no model)"}),
                       config_sha256=digest({"config": definition, "max_attempts": max_attempts,
                                             "lease": lease.total_seconds()}),
                       executor=executor, max_attempts=max_attempts, lease=lease, run_timeout=run_timeout,
                       test_only=True)
