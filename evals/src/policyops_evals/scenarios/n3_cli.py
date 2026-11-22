"""Operator entry point for the distinct N3 registration and one-shot unseal."""

import argparse
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
import json
from typing import Any
from uuid import UUID

import httpx2

from policyops.persistence.evaluation import EvaluationRepository, environment_repository, registration_digest
from policyops.runtime.spec import RuntimeSpec
from policyops_evals.canonical import canonical_bytes
from policyops_evals.scenarios import Refused, n3, n3_report, n3_runner, study
from policyops_evals.scenarios.arms import ABLATIONS, Arm, identities
from policyops_evals.scenarios.batch import AppBackend, serial_lock
from policyops_evals.scenarios.cli import _credential, _operator_profile, _require_paid
from policyops_evals.scenarios.n3 import Assignment, Split
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.runtime import Profile


@contextmanager
def _repository() -> Iterator[EvaluationRepository]:
    repo = environment_repository()
    if repo is None:
        raise Refused("POLICYOPS_EVAL_DATABASE_DSN is required for N3")
    try:
        yield repo
    finally:
        repo.engine.dispose()


def require_unstarted(gate: dict[str, Any] | None, unseal: dict[str, Any] | None, *,
                      candidate_sha256: str | None = None) -> None:
    if gate is None or gate.get("verdict") != "admit":
        raise Refused("held-out execution requires an admitted dev gate")
    if candidate_sha256 is not None and gate.get("candidate_sha256") != candidate_sha256:
        raise Refused("held-out candidate digest differs from the admitted revision")
    if unseal is not None:
        raise Refused("held-out execution already unsealed")


def _gate_record(report: dict[str, Any], digest: str, candidate_sha256: str | None) -> dict[str, Any]:
    record = {"registration_sha256": digest, "verdict": report["gate"]["verdict"],
              "checks": report["gate"]["checks"], "evidence_sha256": report["evidence_sha256"]}
    if candidate_sha256 is not None:
        record["candidate_sha256"] = candidate_sha256
    return record


def _held_out_manifests() -> dict[str, str]:
    return {name: value for name, value in study.MANIFEST_SHA256.items() if name.startswith("held-out.")}


def _unexpected_dispatch(*_: object) -> Any:
    raise Refused("N3 dispatch requires an arm assignment")


def run(args: argparse.Namespace) -> int:
    if args.n3_command == "run":
        _require_paid(args.allow_paid)
        n3_runner.validate_cap(args.split, args.max_usd)
    revision = args.revision == 1
    candidate = Arm.REVISION if revision else Arm.CANDIDATE
    e1 = None
    if revision:
        if args.e1_report is None:
            raise Refused("N3 revision requires --e1-report")
        e1 = n3.historical_report(args.e1_report)
    prior_settled = n3.E1_SETTLED_USD if revision else Decimal(0)
    out = study.private_root(args.out)
    fixture = n3.fixture_inputs(args.fixture_root)
    dev = n3.load_cases(args.manifests, fixture, "dev")
    with _operator_profile(args) as (profile, redactions), _repository() as repo:
        selected = (Arm.BASELINE, candidate) if revision else (Arm.BASELINE, candidate, *ABLATIONS)
        arms = identities(profile.app, profile.policy, profile.tokenizer, arms=selected)
        inputs = n3.inputs(dev, profile.policy, arms, candidate=candidate)
        candidate_sha256 = arms[candidate].profile_sha256 if revision else None
        if args.n3_command == "register":
            generation = profile.corpus_generation(args.workspace)
            payload = study.registration_payload(inputs, args.workspace, generation,
                                                 profile.tokenizer.identity_sha256, out)
            document = n3.register(repo, payload)
            study.write_registration(out, document)
            print(json.dumps({"study_id": document["study_id"], "sha256": document["receipt"]["sha256"]}), flush=True)
            return 0
        study_id, receipt = study.read_registration(out, inputs)
        n3.verify_registration(repo, study_id, receipt)
        digest = receipt["sha256"]
        bound = receipt["payload"]
        workspace, generation = UUID(bound["workspace"]), UUID(bound["corpus_generation"])
        if profile.corpus_generation(workspace) != generation:
            raise Refused("N3 corpus generation changed")
        if profile.tokenizer.identity_sha256 != bound["tokenizer_sha256"]:
            raise Refused("N3 tokenizer digest changed")
        split: Split = args.split
        dev_blocks = n3.blocks(n3.case_groups(dev, "dev", candidate=candidate), "dev", study_id, workspace)
        dev_frame = [item for block in dev_blocks for item in block]
        credential = ""

        def dispatch(item: Assignment, tape: Tape, bind: Callable[[RuntimeSpec], RuntimeSpec]) -> None:
            _dispatch(profile, item, tape, bind, generation, credential, redactions)

        app = {arm: AppBackend(profile.app, workspace, identity.graph_sha256, identity.prompt_sha256,
                              _unexpected_dispatch, config_for=lambda slot: n3_runner.config_digest(out, slot))
               for arm, identity in arms.items()}
        backend = n3_runner.ArmBackend(app, arms, out, dispatch)
        with serial_lock(profile.app, study_id) as check_lock:
            if split == "held-out":
                gate = n3.read_record(repo, study_id, "dev-gate")
                unseal = n3.read_record(repo, study_id, "unseal")
                if args.n3_command == "run":
                    require_unstarted(gate, unseal, candidate_sha256=candidate_sha256)
                    report = _report(backend, dev_frame, digest, "dev", candidate=candidate, detail=False)
                    if gate != _gate_record(report, digest, candidate_sha256):
                        raise Refused("N3 dev gate evidence changed")
                    credential = _credential()
                    unseal = {"registration_sha256": digest, "dev_gate": gate,
                              "manifests": _held_out_manifests(),
                              "unsealed_at": datetime.now(UTC).isoformat()}
                    check_lock()
                    n3.write_record(repo, study_id, "unseal", unseal)
                    study.atomic_write(study.private_child(out, "unseal.json"), canonical_bytes(unseal))
                elif (gate is None or gate.get("verdict") != "admit" or unseal is None
                      or (revision and gate.get("candidate_sha256") != candidate_sha256)
                      or gate.get("registration_sha256") != digest or unseal.get("dev_gate") != gate
                      or unseal.get("registration_sha256") != digest
                      or unseal.get("manifests") != _held_out_manifests()):
                    raise Refused("held-out report requires the receipt-bound unseal")
                cases = n3.load_cases(args.manifests, fixture, split)
                blocks = n3.blocks(n3.case_groups(cases, split, candidate=candidate), split, study_id, workspace)
                frame = [item for block in blocks for item in block]
                prior = dev_frame
            else:
                blocks, frame, prior = dev_blocks, dev_frame, []
            closure_name = f"{split}-closure"
            closure = n3.read_record(repo, study_id, closure_name)
            if args.n3_command == "run":
                if closure is not None:
                    raise Refused("N3 split is closed as incomplete")
                if split == "held-out":
                    n3_runner.refuse_existing(backend, frame, out)
                else:
                    credential = _credential()

                def close(reason: str) -> None:
                    check_lock()
                    n3.write_record(repo, study_id, closure_name, {"registration_sha256": digest, "reason": reason})

                status = n3_runner.run_blocks(backend, blocks, out, digest, args.max_usd, prior=prior,
                                              prior_settled=prior_settled,
                                              check_lock=check_lock, close=close)
                print(json.dumps({"split": split, "status": status, "scheduled": len(frame)}), flush=True)
                return int(status != "complete")
            report = _report(backend, frame, digest, split, candidate=candidate,
                             closure=closure["reason"] if closure else None)
            report |= {"registration_sha256": digest, "requested_model": bound["model"],
                       "registered_arms": bound["arms"], "n2_historical_primary_floor": 0.021}
            if revision:
                report |= {"revision": n3.REVISION_LABEL, "candidate_sha256": candidate_sha256,
                           "prior_dev": bound["prior_dev"]}
            if split == "dev" and e1 is not None:
                report["drift"] = n3_report.drift_checks(report, e1)
            if split == "dev" and report["gate"]["verdict"] == "admit":
                check_lock()
                n3.write_record(repo, study_id, "dev-gate", _gate_record(report, digest, candidate_sha256))
            elif split == "held-out":
                assert unseal is not None  # noqa: S101
                report["unseal_sha256"] = registration_digest(unseal)
                report["all_in_v2_ledger"] = n3_report.ledger_totals(backend.accounts([*prior, *frame]),
                                                                  prior_settled=prior_settled)
            report_path = study.private_child(out, f"{split}-report.json")
            study.atomic_write(report_path, canonical_bytes(report))
            verdict = report["gate"]["verdict"] if split == "dev" else report["primary_claim"]
            print(json.dumps({"split": split, "report": str(report_path), "verdict": verdict}), flush=True)
            return int(split == "dev" and verdict != "admit")


def _dispatch(profile: Profile, item: Assignment, tape: Tape, bind: Callable[[RuntimeSpec], RuntimeSpec],
              generation: UUID, credential: str, redactions: tuple[str, ...]) -> None:
    profile._run(
        item.case, item.slot, tape, lambda: httpx2.AsyncHTTPTransport(trust_env=False, retries=0),
        env="local", credential=credential, redactor=item.slot.redactor((credential, *redactions)),
        expected_generation=generation, profile=item.arm.profile, bind_spec=bind,
    )


def _report(backend: n3_runner.ArmBackend, frame: Sequence[Assignment], digest: str, split: Split, *,
            candidate: Arm, closure: str | None = None, detail: bool = True) -> dict[str, Any]:
    evidence = n3_report.collect(backend.out, frame, digest, backend.accounts(frame))
    return n3_report.comparison(frame, evidence, split, candidate=candidate, closure=closure, detail=detail)
