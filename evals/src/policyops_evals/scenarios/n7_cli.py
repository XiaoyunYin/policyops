"""Operator commands for the receipt-bound N7 pilot and dev study."""

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal
import json
from pathlib import Path
from typing import Any, Never
from uuid import UUID

import httpx2

from policyops.persistence.evaluation import EvaluationRepository
from policyops.runtime.spec import RuntimeSpec
from policyops_evals.canonical import canonical_bytes
from policyops_evals.scenarios import Refused, n3, n3_runner, n7, n7_report, study
from policyops_evals.scenarios.batch import AppBackend, serial_lock
from policyops_evals.scenarios.cli import _credential, _operator_profile, _require_paid
from policyops_evals.scenarios.n3_cli import _repository
from policyops_evals.scenarios.recording import Tape
from policyops_evals.scenarios.runtime import Profile


@dataclass(frozen=True)
class Target:
    id: UUID
    digest: str
    workspace: UUID
    generation: UUID
    phase: n7.Phase
    out: Path
    blocks: tuple[tuple[n3.Assignment, ...], ...]

    @property
    def frame(self) -> list[n3.Assignment]:
        return [item for block in self.blocks for item in block]


def _target(repository: EvaluationRepository, profile: Profile, root: Path, phase: n7.Phase,
            inputs: n7.Inputs, pairs: Sequence[n7.Pair], *, pilot_sha256: str | None = None,
            register_workspace: UUID | None = None) -> Target:
    out = study.private_child(root, phase)
    scoped = inputs.for_phase(phase, pairs, pilot_sha256=pilot_sha256)
    tokenizer = profile.tokenizer.identity_sha256
    if register_workspace is not None:
        generation = profile.corpus_generation(register_workspace)
        payload = study.registration_payload(scoped, register_workspace, generation, tokenizer, out)
        study.write_registration(out, n7.register(repository, phase, payload))
    study_id, receipt = study.read_registration(out, scoped)
    n7.verify_registration(repository, study_id, phase, receipt)
    bound = receipt["payload"]
    workspace, generation = UUID(bound["workspace"]), UUID(bound["corpus_generation"])
    if profile.corpus_generation(workspace) != generation or tokenizer != bound["tokenizer_sha256"]:
        raise Refused("N7 corpus generation or tokenizer changed")
    return Target(study_id, receipt["sha256"], workspace, generation, phase, out,
                  n7.blocks(pairs, study_id, workspace))


def _unexpected_dispatch(*_: object) -> Never:
    raise Refused("N7 dispatch requires an arm assignment")


def _backend(profile: Profile, target: Target, inputs: n7.Inputs, redactions: tuple[str, ...],
             credential: str = "") -> n3_runner.ArmBackend:
    def dispatch(item: n3.Assignment, tape: Tape, bind: Callable[[RuntimeSpec], RuntimeSpec]) -> None:
        if not credential:
            raise Refused("N7 report cannot dispatch")
        profile._run(
            item.case, item.slot, tape, lambda: httpx2.AsyncHTTPTransport(trust_env=False, retries=0),
            env="local", credential=credential, redactor=item.slot.redactor((credential, *redactions)),
            expected_generation=target.generation, profile=n7.PROFILE, bind_spec=bind, cache_mode=n7.MODES[item.arm],
        )

    identity = inputs.identity
    backends = {
        arm: AppBackend(profile.app, target.workspace, identity.graph_sha256, identity.prompt_sha256,
                        _unexpected_dispatch, config_for=lambda slot: n3_runner.config_digest(target.out, slot),
                        cache_mode=n7.MODES[arm])
        for arm in n7.ARMS
    }
    return n3_runner.ArmBackend(backends, dict.fromkeys(n7.ARMS, identity), target.out, dispatch)


def _closure(repository: EvaluationRepository, target: Target) -> str | None:
    record = repository.run_configuration(n7.record_id(target.id, "closure"))
    if record is None:
        return None
    reason = record.get("reason")
    if record.get("registration_sha256") != target.digest or not isinstance(reason, str):
        raise Refused("N7 closure receipt differs from registration")
    return reason


def _report(repo: EvaluationRepository, profile: Profile, target: Target, inputs: n7.Inputs,
            redactions: tuple[str, ...]) -> dict[str, Any]:
    backend = _backend(profile, target, inputs, redactions)
    frame = target.frame
    report = n7_report.report(profile.app, target.workspace, target.out, frame, inputs, target.phase,
                              target.digest, backend.accounts(frame), _closure(repo, target))
    study.atomic_write(study.private_child(target.out, "report.json"), canonical_bytes(report))
    return report


def _run(repo: EvaluationRepository, profile: Profile, target: Target, inputs: n7.Inputs,
         redactions: tuple[str, ...], check_lock: Callable[[], None]) -> int:
    if _closure(repo, target) is not None:
        raise Refused("N7 phase is closed as incomplete")
    backend = _backend(profile, target, inputs, redactions, _credential())

    def close(reason: str) -> None:
        check_lock()
        n7.close(repo, target.id, target.phase, target.digest, reason)

    status = n3_runner.run_blocks(backend, target.blocks, target.out, target.digest, n7.CAPS[target.phase],
                                  check_lock=check_lock, close=close, arm_caps=n7.ARM_CAPS,
                                  stop_on_accounting_issue=True)
    print(json.dumps({"phase": target.phase, "status": status, "scheduled": len(target.frame)}), flush=True)
    return int(status != "complete")


def _preflight(target: Target) -> dict[str, object]:
    frame_worst = sum((n7.ARM_CAPS[item.arm] for item in target.frame), Decimal(0))
    block_worst = max(sum(n7.ARM_CAPS[item.arm] for item in block) for block in target.blocks)
    if block_worst > n7.CAPS[target.phase]:
        raise Refused("N7 first block would exceed its cap")
    return {"study_id": str(target.id), "registration_sha256": target.digest, "scheduled": len(target.frame),
            "first_block_worst_usd": str(block_worst), "full_schedule_worst_usd": str(frame_worst),
            "aggregate_cap_usd": str(n7.CAPS[target.phase])}


def run(args: argparse.Namespace) -> int:
    if args.n7_command in {"pilot", "run"}:
        _require_paid(args.allow_paid)
    root = study.private_root(args.out)
    fixture = n3.fixture_inputs(args.fixture_root)
    dev = n3.load_cases(args.manifests, fixture, "dev")
    register_workspace = args.workspace if args.n7_command == "register" else None
    with _operator_profile(args) as (profile, redactions), _repository() as repo:
        inputs = n7.inputs(dev, profile.app, profile.policy, profile.tokenizer)
        pilot = _target(repo, profile, root, "pilot", inputs, n7.schedule(dev, "pilot"),
                        register_workspace=register_workspace)
        if args.n7_command == "pilot" or (args.n7_command == "report" and args.phase == "pilot"):
            with serial_lock(profile.app, pilot.id) as check:
                if args.n7_command == "pilot":
                    return _run(repo, profile, pilot, inputs, redactions, check)
                return _print_report(pilot, _report(repo, profile, pilot, inputs, redactions))

        target = _target(repo, profile, root, "study", inputs, n7.schedule(dev, "study"),
                         pilot_sha256=pilot.digest, register_workspace=register_workspace)
        if (target.workspace, target.generation) != (pilot.workspace, pilot.generation):
            raise Refused("N7 pilot and study must share the registered workspace and corpus generation")
        if args.n7_command == "register":
            print(json.dumps({"pilot": _preflight(pilot), "study": _preflight(target)}), flush=True)
            return 0
        if args.n7_command == "run":
            with serial_lock(profile.app, pilot.id) as check_pilot, serial_lock(profile.app, target.id) as check:
                pilot_report = _report(repo, profile, pilot, inputs, redactions)
                check_pilot()
                if pilot_report["pilot_gate"]["verdict"] != "admit":
                    raise Refused("N7 pilot gate stopped the study. See pilot/report.json in the registered output")
                return _run(repo, profile, target, inputs, redactions, check)
        with serial_lock(profile.app, target.id):
            return _print_report(target, _report(repo, profile, target, inputs, redactions))


def _print_report(target: Target, report: dict[str, Any]) -> int:
    admitted = (report["pilot_gate"]["verdict"] == "admit" if target.phase == "pilot"
                else report["cost_claim_admissible"])
    print(json.dumps({"phase": target.phase, "report": str(target.out / "report.json"), "admitted": admitted}),
          flush=True)
    return int(not admitted)
