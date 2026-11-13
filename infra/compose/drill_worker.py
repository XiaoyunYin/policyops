"""Explicit local drill worker: stop after a real committed response, before local receipt persistence.

Only the isolated drill driver launches this entrypoint. No fake authority, clock, port or receipt is installed.
The ordinary runtime entrypoint cannot select this hook through an environment variable.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import threading

from runtime import worker

from policyops.persistence.records import ExecutionRecord
from policyops.services.execution import ExecutionHooks
from policyops_contracts.retail_service import OperationResult


MARKER = Path("/tmp/t38-after-response.json")  # noqa: S108 - private container tmpfs, no secrets


class PauseAfterResponse(ExecutionHooks):
    test_only = True

    def after_response(self, execution: ExecutionRecord, result: object) -> None:
        if not isinstance(result, OperationResult) or result.receipt is None or result.outcome != "committed":
            raise RuntimeError("drill expected a real committed simulator response")
        MARKER.write_text(
            json.dumps(
                {
                    "execution_id": str(execution.id),
                    "operation_id": str(execution.operation_id),
                    "case_version_after": result.receipt.case_version_after,
                }
            ),
            encoding="utf-8",
        )
        # A missed kill fails the drill's dispatched/no-local-receipt assertion. Never wait indefinitely.
        threading.Event().wait(120)


if __name__ == "__main__":
    if os.environ.get("POLICYOPS_COMPOSE_DRILL") != "1" or os.environ.get("POLICYOPS_ENV") != "local":
        raise SystemExit("explicit local drill opt-in required")
    worker(execution_hooks=PauseAfterResponse())
