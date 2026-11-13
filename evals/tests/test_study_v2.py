"""V2 membership, pairing, registration and cooperative restart contracts."""

from datetime import datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4, uuid5

import pytest

from policyops.budget.ledger import Attempt, Ledger, LedgerConflict, Settlement
from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository
from policyops_evals.build import RETAIL_SPLIT, default_manifest_dir
from policyops_evals.canonical import canonical_bytes, id_list_digest, load_manifest, sha256_bytes
from policyops_evals.studies import registration, runner, runner_v2
from policyops_evals.studies.config import StudyV2, load_study, preflight

from .t29_study_support import StudyStore
from .t32_support import SOURCE, StudyRepository, bill_fixture_inference, example


@pytest.mark.parametrize("duplicate_receipt", [True, False])
def test_fixture_receipt_collision_rolls_back_settlement_but_keeps_dispatch(duplicate_receipt: bool) -> None:
    class UniqueReceiptStore(StudyStore):
        def update_attempt(self, attempt: Attempt, now: datetime, settlement: Settlement | None = None) -> None:
            # Model only evaluation's UNIQUE(provider, provider_request_id).
            # The inherited transaction restores attempts/scopes on conflict.
            if attempt.provider_request_id is not None and any(
                other.id != attempt.id and other.intent.provider == attempt.intent.provider
                and other.provider_request_id == attempt.provider_request_id for other in self.attempts.values()
            ):
                raise LedgerConflict("duplicate_provider_receipt")
            super().update_attempt(attempt, now, settlement)

    study, store = example(), UniqueReceiptStore()
    caps = study.limits.caps()
    identity = store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    repository = StudyRepository(store)
    variant = study.variants[0]
    # Two different scheduled slots; the first bill commits before the second
    # dispatch. No replay is needed to reproduce the review's dispatching residue.
    with repository.study_lock(identity) as lease:
        run = registration.run_record(study, variant, identity, SOURCE, None)
        repository.ensure_run(run)
        from policyops.persistence.evaluation import Slot

        invocation = store.ensure_invocation(identity, uuid4(), caps)
        for i, seed in enumerate(study.seeds[:2]):
            scenario = store.ensure_scenario(identity, study.tasks[0], i, study.variant_digest(variant), caps)
            slot = Slot(uuid5(run.id, f"{study.tasks[0]}:{i}"), run.id, identity, study.variant_digest(variant),
                        study.tasks[0], i, seed, scenario, "scheduled")
            repository.schedule(slot)
            token = repository.claim(slot, invocation, lease)
            assert token is not None
            ledger = Ledger(store, study.configuration(variant))
            request_id = "private-canary" if duplicate_receipt else None
            if duplicate_receipt and i == 1:
                with pytest.raises(LedgerConflict, match="duplicate_provider_receipt"):
                    bill_fixture_inference(slot.id, ledger, token.binding, provider_request_id=request_id)
            else:
                bill_fixture_inference(slot.id, ledger, token.binding, provider_request_id=request_id)
    attempts = list(store.attempts.values())
    assert repository.claims == 2 and len(attempts) == 2
    assert attempts[0].state == "settled" and attempts[0].actual_usd == Decimal("0.000015")
    assert attempts[1].state == ("dispatching" if duplicate_receipt else "settled")
    assert (store.scope(identity).held_usd > 0) == duplicate_receipt
    if duplicate_receipt:
        assert attempts[1].actual_usd is None and attempts[1].usage_sha256 is None
        assert store.scope(identity).held_usd == attempts[1].intent.reserved_usd
    else:
        assert attempts[0].provider_request_id != attempts[1].provider_request_id


def modify(study: StudyV2, changes: dict[str, Any]) -> StudyV2:
    return StudyV2.model_validate_json(canonical_bytes(study.model_dump(mode="json") | changes))


def test_membership_is_separate_from_tuning(tmp_path: Path) -> None:
    study = example()
    changed = modify(study, {"tasks": ["2"], "task_list_sha256": id_list_digest(["2"])})
    changed.validate_data()  # excluded from calibration, still official dev
    with pytest.raises(ValueError):
        modify(changed, {"eligibility": changed.eligibility.model_dump(mode="json") | {
            "tuning_task_ids": ["2"]}}).validate_data()
    path = tmp_path / "v2.json"
    path.write_bytes(canonical_bytes(changed.model_dump(mode="json")))
    assert isinstance(load_study(path), StudyV2)


def test_paired_order_and_remaining_preflight() -> None:
    study = example()
    order = study.schedule()
    assert order == example().schedule()
    assert len(order) == 16
    for offset in range(0, len(order), 2):
        assert {r[0] for r in order[offset:offset + 2]} == {v.name for v in study.variants}
        assert len({r[1:] for r in order[offset:offset + 2]}) == 1
    assert [order[i][0] for i in range(0, 8, 2)].count(order[0][0]) == 2
    plan = preflight(study, remaining={v.name: () for v in study.variants})
    assert plan["scheduled_slots"] == 16 and plan["remaining_slots"] == 0


def test_v2_config_refuses_excess_bootstrap_work() -> None:
    body = example().model_dump(mode="json")
    body["tasks"] = [str(i) for i in range(128)]
    body["task_list_sha256"] = id_list_digest(body["tasks"])
    body["seeds"] = list(range(32))
    body["statistics"]["ks"] = list(range(1, 9))
    body["variants"] += [body["variants"][0] | {"name": "third"}, body["variants"][1] | {"name": "fourth"}]
    with pytest.raises(ValueError, match="bootstrap workload"):
        StudyV2.model_validate_json(canonical_bytes(body))
    # This frame passed the old incomplete work count (strict/CC only).
    # The full count includes DB diagnostics and both partitioned strata.
    body["tasks"] = body["tasks"][:64]
    body["task_list_sha256"] = id_list_digest(body["tasks"])
    body["variants"] = body["variants"][:2]
    with pytest.raises(ValueError, match="bootstrap workload"):
        StudyV2.model_validate_json(canonical_bytes(body))


@pytest.mark.parametrize("change", ["judge", "prompt", "k", "purpose", "allowlist", "banking"])
def test_undeclared_or_invalid_configuration(change: str) -> None:
    body = example().model_dump(mode="json")
    if change == "judge":
        body["variants"][1]["actors"]["judge"]["effort"] = "medium"
    elif change == "prompt":
        body["variants"][1]["prompt_sha256"] = "0" * 64
    elif change == "k":
        body["statistics"]["ks"] = [1, 5]
    elif change == "purpose":
        body["purpose"] = "holdout"
    elif change == "banking":
        body["domain"] = "banking_knowledge"
    else:
        body["eligibility"]["allowlist_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        config = StudyV2.model_validate_json(canonical_bytes(body))
        config.validate_data()


def holdout() -> StudyV2:
    tasks = load_manifest(default_manifest_dir() / RETAIL_SPLIT)["splits"]["holdout"]["task_ids"]
    return modify(example(), {"purpose": "holdout", "split_id": "holdout", "tasks": tasks,
        "task_list_sha256": id_list_digest(tasks), "preregistration_sha256": "0" * 64,
        "limits": example().limits.model_dump(mode="json") | {"study_usd": "40", "invocation_usd": "40",
            "study_calls": 12000, "study_counts": 12000, "invocation_calls": 12000, "invocation_counts": 12000,
            "study_input_tokens": 192000000, "study_output_tokens": 24576000}})


def test_holdout_preserves_all_50_ids_and_registration_binds_every_field() -> None:
    study = holdout()
    study.validate_data()
    assert len(study.tasks) == 50
    with pytest.raises(ValueError):
        modify(study, {"tasks": study.tasks[:-1], "task_list_sha256": id_list_digest(study.tasks[:-1])}).validate_data()
    payload = registration.registration_payload(study, SOURCE)
    digest = sha256_bytes(canonical_bytes(payload))
    declared = modify(study, {"preregistration_sha256": digest})
    assert registration.registration_payload(declared, SOURCE) == payload
    for changes in ({"seeds": [1, 2, 3, 4]}, {"decision": study.decision.model_dump(mode="json") | {"margin": "0.11"}},
                    {"study_key": "changed"}):
        assert registration.registration_payload(modify(declared, changes), SOURCE) != payload
    assert registration.registration_payload(declared, SOURCE | {"source_head": "2" * 40}) != payload


def test_registration_missing_wrong_and_exact_readback() -> None:
    study = holdout()
    store = StudyStore()
    repository = StudyRepository(store)
    caps = study.limits.caps()
    digest = sha256_bytes(canonical_bytes(registration.registration_payload(study, SOURCE)))
    study = modify(study, {"preregistration_sha256": digest})
    identity = store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    with pytest.raises(ValueError, match="committed registration"):
        registration.registered(study, cast(EvaluationRepository, repository), identity, SOURCE)
    with repository.study_lock(identity) as lease:
        with pytest.raises(ValueError, match="declared"):
            registration.register(modify(study, {"preregistration_sha256": "0" * 64}),
                                  cast(EvaluationRepository, repository), identity, SOURCE, lease)
        receipt = registration.register(study, cast(EvaluationRepository, repository), identity, SOURCE, lease)
    assert registration.registered(study, cast(EvaluationRepository, repository), identity, SOURCE) == receipt
    assert not store.attempts and repository.claims == 0


def test_registration_timestamp_order_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    study, store = holdout(), StudyStore()
    repository = StudyRepository(store)
    digest = sha256_bytes(canonical_bytes(registration.registration_payload(study, SOURCE)))
    study = modify(study, {"preregistration_sha256": digest})
    caps = study.limits.caps()
    identity = store.ensure_study(study.study_key, study.digest(), cap_usd=caps.study_usd, cap_calls=caps.study_calls)
    with repository.study_lock(identity) as lease:
        registration.register(study, cast(EvaluationRepository, repository), identity, SOURCE, lease)
    monkeypatch.setattr(repository, "registration_precedes_claims", lambda *args: False)
    with pytest.raises(ValueError, match="registration_after_claim"):
        registration.registered(study, cast(EvaluationRepository, repository), identity, SOURCE)


def test_frozen_holdout_receipt_binds_analysis_and_private_payload() -> None:
    from uuid import uuid4

    from policyops_evals.studies.report_models import FrozenStudy

    study = holdout()
    payload = registration.registration_payload(study, SOURCE)
    digest = sha256_bytes(canonical_bytes(payload))
    study = modify(study, {"preregistration_sha256": digest})
    receipt = {"sha256": digest, "payload": payload, "created_at": "2026-11-12T00:00:00Z"}
    frozen = registration.freeze(study, uuid4(), SOURCE, dict.fromkeys(study.tasks, "db_only"), receipt)
    assert frozen.registration_sha256 == digest
    for field in ("margin", "receipt", "time"):
        body = frozen.model_dump(mode="json")
        if field == "margin":
            body["decision"]["margin"] = "0.11"
        elif field == "receipt":
            body["registration"]["payload"]["specification"]["decision"]["margin"] = "0.11"
        else:
            body["registration"]["created_at"] = "2026-11-13T00:00:00Z"
        with pytest.raises(ValueError):
            FrozenStudy.model_validate_json(canonical_bytes(body))


def test_cooperative_interrupt_resume_and_explicit_closure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    study = example()
    store = StudyStore()
    repository = StudyRepository(store)
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(runner_v2, "source_provenance", lambda: SOURCE)
    inputs = {t: runner.TrialInputs(SimpleNamespace(evaluation_criteria=SimpleNamespace(nl_assertions=[])))
              for t in study.tasks}
    visited = []

    def interrupted(*args: Any, **kwargs: Any) -> Any:
        visited.append(args[2].id)
        raise KeyboardInterrupt()

    monkeypatch.setattr(runner, "execute_trial", interrupted)

    def run(**kwargs: Any) -> dict[str, Any]:
        return runner.run_study(study, cast(EvaluationRepository, repository), cast(EvalLedgerStore, store),
            inputs=inputs, make_providers=lambda _: lambda: None, **kwargs)  # type: ignore[arg-type,return-value]

    result = run(make_ledger=lambda *args: None)
    assert not result["execution_complete"] and len(repository.terminals) == 1
    assert sum(s.state == "scheduled" for s in repository.schedule_rows.values()) == 15
    result = run(resume=True, make_ledger=lambda *args: None)
    assert len(repository.terminals) == 2 and len(set(visited)) == 2
    result = run(resume=True, close_unclaimed=True)
    assert result["execution_complete"] and len(repository.terminals) == 16
    assert repository.claims == 2
    run(resume=True, close_unclaimed=True)
    assert repository.claims == 2 and not store.attempts


def test_holdout_refuses_before_payloads_and_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    study, store = holdout(), StudyStore()
    repository = StudyRepository(store)
    monkeypatch.setattr(runner_v2, "source_provenance", lambda: SOURCE)

    def trap(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("holdout payload/provider touched without registration")

    monkeypatch.setattr(runner, "load_inputs", trap)
    with pytest.raises(ValueError, match="committed registration"):
        runner.run_study(study, cast(EvaluationRepository, repository), cast(EvalLedgerStore, store),
                         make_providers=trap)
    assert not repository.schedule_rows
