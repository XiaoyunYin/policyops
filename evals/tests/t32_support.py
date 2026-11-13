"""Small fictional frozen inputs and a durable-runner offline double."""

from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from policyops.budget.ledger import EvalBinding, Ledger, Settlement
from policyops.budget.pricing import Usage
from policyops.persistence.evaluation import EvaluationRun, StudyLock
from policyops_evals.canonical import canonical_bytes
from policyops_evals.studies.config import StudyV2, load_study
from policyops_evals.studies.registration import freeze
from policyops_evals.studies.report_models import FrozenStudy, Snapshot

from .t29_study_support import Repository


SOURCE = {"source_head": "1" * 40, "dirty_sha256": "0" * 64,
          "lock_sha256": {"uv.lock": "2" * 64, "evals/uv.lock": "3" * 64}}
EXAMPLE = Path(__file__).parents[1] / "studies/offline-paired-v2.json"


def bill_fixture_inference(slot_id: UUID, ledger: Ledger, binding: EvalBinding, *,
                           provider_request_id: str | None = None) -> None:
    """One distinct fake provider receipt per inference, as required by the eval ledger."""
    key, digest = uuid5(slot_id, "inference"), "a" * 64
    ledger.reserve(binding, key, "agent", "study.fixture", digest)
    ledger.claim_count(key, digest)
    ledger.record_count(key, tokens=100, source="provider")
    ledger.begin_dispatch(key, digest)
    ledger.settle(key, Settlement(Usage(100, output=10),
        provider_request_id=provider_request_id or f"private-canary-{key}"))


def example() -> StudyV2:
    return cast(StudyV2, load_study(EXAMPLE))


def frozen_fixture() -> tuple[FrozenStudy, Snapshot]:
    study = example()
    frozen = freeze(study, uuid4(), SOURCE, {"0": "db_nl", "1": "db_only"}, None)
    rows, scopes = [], []
    for variant, task, i, seed in frozen.schedule:
        v = next(v for v in frozen.variants if v.name == variant)
        slot = uuid5(uuid5(frozen.study_id, v.config_sha256), f"{task}:{i}")
        scenario = uuid5(slot, "scenario")
        rows.append({"variant": variant, "task_id": task, "trial_index": i, "seed": seed,
            "slot_id": str(slot), "scenario_id": str(scenario), "stratum": "db_nl" if task == "0" else "db_only",
            "status": "success" if i < 3 else "error", "failure_class": None if i < 3 else "judge_unavailable",
            "db_success": True, "composite_success": True if i < 3 else None,
            "cost_usd": "0", "held_usd": "0", "cost_known": True, "latency_ms": 100 + i})
        scopes.append({"id": str(scenario), "kind": "scenario", "spent_usd": "0", "held_usd": "0",
            "calls_consumed": 0, "calls_held": 0, "counts_used": 0, "blocked": False})
    scopes.append(scopes[0] | {"id": str(frozen.study_id), "kind": "study"})
    return frozen, Snapshot.model_validate_json(canonical_bytes({"created_at": "2026-11-12T00:00:00Z",
        "db_version": "180001", "trials": rows, "scopes": scopes, "attempts": [], "timings": []}))


class StudyRepository(Repository):
    def registration_precedes_claims(self, study_id: Any, registered_at: Any) -> bool:
        return True

    def run_configuration(self, run_id: Any) -> dict[str, Any] | None:
        import json

        return None if run_id not in self.runs else cast(dict[str, Any], json.loads(self.runs[run_id].config_json))

    def register(self, runs: list[EvaluationRun], payload: dict[str, Any], digest: str,
                 lease: StudyLock) -> dict[str, Any]:
        import json

        receipt = {"payload": payload, "sha256": digest, "created_at": "2026-11-12T00:00:00Z"}
        for run in runs:
            if self.schedule_rows or self.store.attempts:
                raise ValueError("registration_after_claim")
            self.ensure_run(run.model_copy(update={"config_json": json.dumps(
                json.loads(run.config_json) | {"registration": receipt})}))
        return receipt

    def finish_run(self, run_id: Any, lease: StudyLock) -> None:
        pass  # SQL finish_run is conditional for partial v2 runs

    def export_study(self, study_id: Any, lease: StudyLock) -> dict[str, Any]:
        import json

        trials = []
        for slot in self.schedule_rows.values():
            terminal = self.terminals.get(slot.id)
            trials.append({"id": slot.id, "evaluation_run_id": slot.run_id, "task_id": slot.task_id,
                "trial_index": slot.trial_index, "seed": slot.seed, "scenario_scope": slot.scenario_id,
                "state": slot.state, **({} if terminal is None else terminal.model_dump()),
                "components": {} if terminal is None else json.loads(terminal.components_json)})
        scopes = [asdict(s) for s in self.store.scopes.values() if s.kind in {"study", "scenario"}]
        return {"created_at": datetime.now(UTC), "db_version": "180001", "trials": trials,
                "attempts": [], "scopes": scopes}
