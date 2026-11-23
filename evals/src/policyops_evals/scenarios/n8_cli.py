"""Operator commands for the receipt-bound N8 pilot and dev injection study."""

import argparse
from collections.abc import Callable, Sequence
import contextlib
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Never
from uuid import UUID

import httpx2

from policyops.persistence.evaluation import EvaluationRepository
from policyops.runtime.spec import RuntimeSpec
from policyops_evals.canonical import canonical_bytes
from policyops_evals.retail_sim.fixture import DB_PATH, MAX_FIXTURE_BYTES
from policyops_evals.scenarios import (
    Refused,
    n3,
    n3_report,
    n3_runner,
    n7_report,
    n8,
    n8_port,
    n8_report,
    read_bounded,
    study,
)
from policyops_evals.scenarios.batch import AppBackend, RunState, Terminal, read_result, serial_lock, slot_directory
from policyops_evals.scenarios.cli import _credential, _operator_profile, _require_paid
from policyops_evals.scenarios.n3_cli import _repository
from policyops_evals.scenarios.recording import Redactor, Tape
from policyops_evals.scenarios.runtime import Profile


MANIFEST_FILE = "attack-manifest.json"
STOP_FILE = "stop-audit.json"


@dataclass(frozen=True)
class Target:
    id: UUID
    digest: str
    workspace: UUID
    generation: UUID
    phase: n8.Phase
    out: Path
    blocks: tuple[tuple[n3.Assignment, ...], ...]
    plan: dict[UUID, n8.Planned]

    @property
    def frame(self) -> list[n3.Assignment]:
        return [item for block in self.blocks for item in block]


def _manifest(out: Path, inputs: n8.Inputs, *, write: bool) -> None:
    """The grader-only attack manifest beside the registration. Its digest is bound into the registration."""
    path = study.private_child(out, MANIFEST_FILE)
    data = canonical_bytes(inputs.panel.manifest())
    if sha256(data).hexdigest() != inputs.panel.sha256:
        raise Refused("N8 attack manifest digest is not canonical")
    if write and not path.exists():
        study.atomic_write(path, data)
    if not path.is_file() or read_bounded(path, 16 << 20) != data:
        raise Refused("N8 attack manifest differs from the registered panel")


def _target(repository: EvaluationRepository, profile: Profile, root: Path, phase: n8.Phase, inputs: n8.Inputs,
            planned: Sequence[n8.Planned], *, pilot_sha256: str | None = None,
            register_workspace: UUID | None = None) -> Target:
    out = study.private_child(root, phase)
    scoped = inputs.for_phase(phase, planned, pilot_sha256=pilot_sha256)
    tokenizer = profile.tokenizer.identity_sha256
    if register_workspace is not None:
        generation = profile.corpus_generation(register_workspace)
        payload = study.registration_payload(scoped, register_workspace, generation, tokenizer, out)
        study.write_registration(out, n8.register(repository, phase, payload))
    _manifest(out, inputs, write=register_workspace is not None)
    study_id, receipt = study.read_registration(out, scoped)
    n8.verify_registration(repository, study_id, phase, receipt)
    bound = receipt["payload"]
    workspace, generation = UUID(bound["workspace"]), UUID(bound["corpus_generation"])
    if profile.corpus_generation(workspace) != generation or tokenizer != bound["tokenizer_sha256"]:
        raise Refused("N8 corpus generation or tokenizer changed")
    blocks = n8.blocks(planned, study_id, workspace)
    plan = {block[0].slot.id: item for block, item in zip(blocks, planned, strict=True)}
    return Target(study_id, receipt["sha256"], workspace, generation, phase, out, blocks, plan)


def _unexpected_dispatch(*_: object) -> Never:
    raise Refused("N8 dispatch requires a planned slot")


def _backend(profile: Profile, target: Target, inputs: n8.Inputs, redactions: tuple[str, ...],
             credential: str = "") -> n3_runner.ArmBackend:
    def dispatch(item: n3.Assignment, tape: Tape, bind: Callable[[RuntimeSpec], RuntimeSpec]) -> None:
        if not credential:
            raise Refused("N8 report cannot dispatch")
        stimulus = target.plan[item.slot.id].stimulus
        if stimulus.channel == "C-msg":
            if stimulus.text is None:
                raise Refused("N8 C-msg stimulus has no note")
            n8_port.seed_note(profile, item.slot, item.case.world.customer_id, item.case.visible.message,
                              stimulus.text)
        carrier = n8_port.binder(stimulus, inputs.panel.sha256)
        base = item.slot.redactor((credential, *redactions))
        redactor = Redactor({**base.ids, n8_port.note_id(item.slot): "note"}, base.secrets)
        profile._run(
            item.case, item.slot, tape, lambda: httpx2.AsyncHTTPTransport(trust_env=False, retries=0),
            env="local", credential=credential, redactor=redactor, expected_generation=target.generation,
            profile=n8.PROFILE, bind_spec=lambda spec: bind(carrier(spec)), cache_mode=n8.CACHE_MODE,
        )

    identity = inputs.identity
    backend = AppBackend(profile.app, target.workspace, identity.graph_sha256, identity.prompt_sha256,
                         _unexpected_dispatch, config_for=lambda slot: n3_runner.config_digest(target.out, slot),
                         cache_mode=n8.CACHE_MODE)
    return n3_runner.ArmBackend({n8.ARM: backend}, {n8.ARM: identity}, target.out, dispatch)


class Stop(Refused):
    def __init__(self, reason: str) -> None:
        super().__init__(f"N8 stop rule: {reason}")
        self.reason = reason


class Guarded:
    """Audit each finished slot before the next admission (restored slots before the first), then apply the stop
    rules run_blocks does not know. Any failed audit stops the phase with one closure reason."""

    def __init__(self, inner: n3_runner.ArmBackend, profile: Profile, target: Target, inputs: n8.Inputs,
                 auditor: Callable[[n3.Assignment], tuple[str, ...]] | None = None) -> None:
        self.inner, self.profile, self.target, self.inputs = inner, profile, target, inputs
        self.auditor = auditor or self.audit
        self.pending: list[n3.Assignment] = []
        self.audited: set[UUID] = set()
        self.failures: dict[str, list[str]] = {}
        self.started = False
        self.stopped: str | None = None
        self.harness = 0

    def accounts(self, frame: Sequence[n3.Assignment]) -> dict[UUID, RunState]:
        return self.inner.accounts(frame)

    def terminal(self, item: n3.Assignment) -> Terminal | None:
        return self.inner.terminal(item)

    def execute(self, item: n3.Assignment, tape: Tape) -> None:
        self.started = True
        try:
            self.inner.execute(item, tape)
        finally:
            self.pending.append(item)

    def audit(self, item: n3.Assignment) -> tuple[str, ...]:
        target, key = self.target, item.slot.id
        stimulus = target.plan[key].stimulus
        attempts, runs = n7_report.fetch(self.profile.app, target.workspace, [item])
        evidence = n8_report.with_simulator(self.profile.retail, target.workspace, [item],
                                            n8_report.fetch(self.profile.app, target.workspace, [item]))
        return n8_report.audit_slot(
            item, stimulus, n8_report.tape(target.out, item), attempts.get(key, []),
            self.inputs.requests[item.case.key, stimulus.condition], self.inner.accounts([item]).get(key),
            read_result(target.out, item.slot, target.digest), runs.get(key, n7_report.RunData()), evidence.get(key),
            self.inputs.components, [spec.canary for spec in self.inputs.panel.goals[item.case.key]]).problems

    def verify(self, item: n3.Assignment) -> tuple[str, ...]:
        """File evidence without the database: the tape digest equals the result's and the frozen grader reproduces
        its grade (n3_report.collect, applied to this slot alone)."""
        try:
            n3_report.collect(self.target.out, [item], self.target.digest, {})
        except Refused:
            return ("result_tape_mismatch",)
        return ()

    def _check(self, item: n3.Assignment, *, executed: bool = False) -> None:
        if item.slot.id in self.audited:
            return
        try:
            result = read_result(self.target.out, item.slot, self.target.digest)
            if result is None and not executed:
                n8_report.tape(self.target.out, item)  # a malformed cassette raises here, before any admission
                return
            self.audited.add(item.slot.id)
            self.harness += n8_report.harness_stop(result)
            problems = ("result_missing",) if result is None else (*self.verify(item), *self.auditor(item))
        except Exception as error:  # unreadable or invalid evidence closes the phase; it is never skipped
            self.audited.add(item.slot.id)
            problems = (f"evidence_unreadable:{type(error).__name__}",)
        if problems:
            self.failures[str(item.slot.id)] = list(problems)
            self.stopped = self.stopped or f"slot_audit_failure:{item.slot.id}"

    def inspect(self) -> None:
        if not self.started:  # restored slots, before the first admission
            for item in self.target.frame:
                if slot_directory(self.target.out, item.slot).exists():
                    self._check(item)
        while self.pending:
            self._check(self.pending.pop(0), executed=True)
        if self.stopped is None and 100 * self.harness > n8.HARNESS_STOP_PERCENT * len(self.target.frame):
            self.stopped = "harness_stops"
        if self.stopped is not None:
            write_stop(self.target, self.stopped, self.failures)
            raise Stop(self.stopped)

    def check(self, lock: Callable[[], None]) -> Callable[[], None]:
        def checked() -> None:
            lock()
            self.inspect()
        return checked


def write_stop(target: Target, reason: str, failures: dict[str, list[str]] | None = None) -> None:
    """The local stop record, bound to the registration and phase. It is written before the database closure,
    so a failed closure cannot reopen the phase."""
    path = study.private_child(target.out, STOP_FILE)
    if not path.exists():
        study.atomic_write(path, canonical_bytes({"registration_sha256": target.digest, "phase": target.phase,
                                                  "reason": reason, "failures": failures or {}}))


def read_stop(target: Target) -> dict[str, Any] | None:
    path = study.private_child(target.out, STOP_FILE)
    if not path.exists():
        return None
    record = json.loads(read_bounded(path, 1 << 20))
    if (not isinstance(record, dict) or record.get("registration_sha256") != target.digest
            or record.get("phase") != target.phase or not isinstance(record.get("reason"), str)):
        raise Refused("N8 local stop record differs from the registration")
    return record


def refuse_stopped(repository: EvaluationRepository, target: Target) -> None:
    """Refuse a closed phase. A local stop record without its database closure retries the closure first, and
    refuses whether or not the retry succeeds."""
    local = read_stop(target)
    closed = _closure(repository, target)
    if local is not None:
        if closed is None:
            with contextlib.suppress(Exception):
                n8.close(repository, target.id, target.phase, target.digest, local["reason"])
        raise Refused(f"N8 phase is stopped by its local stop record ({local['reason']})")
    if closed is not None:
        raise Refused("N8 phase is closed as incomplete")


def require_pilot_unstopped(pilot: Target) -> None:
    if read_stop(pilot) is not None:
        raise Refused("N8 pilot has a local stop record; the study cannot be admitted")


def require_pilot_admitted(pilot: Target, report: dict[str, Any]) -> None:
    """The study needs an admitting pilot report and no local pilot stop, whatever the recomputed gate says."""
    require_pilot_unstopped(pilot)
    if report["pilot_gate"]["verdict"] != "admit":
        raise Refused("N8 pilot gate stopped the study. See pilot/report.json in the registered output")


def _closure(repository: EvaluationRepository, target: Target) -> str | None:
    record = repository.run_configuration(n8.record_id(target.id, "closure"))
    if record is None:
        return None
    reason = record.get("reason")
    if record.get("registration_sha256") != target.digest or not isinstance(reason, str):
        raise Refused("N8 closure receipt differs from registration")
    return reason


def _report(repo: EvaluationRepository, profile: Profile, target: Target, inputs: n8.Inputs,
            redactions: tuple[str, ...]) -> dict[str, Any]:
    backend = _backend(profile, target, inputs, redactions)
    frame = target.frame
    local = read_stop(target)
    report = n8_report.report(profile.app, profile.retail, target.workspace, target.out, frame, target.plan, inputs,
                              target.phase, target.digest, backend.accounts(frame), _closure(repo, target),
                              local_stop=None if local is None else str(local["reason"]))
    report["local_stop_record"] = local
    study.atomic_write(study.private_child(target.out, "report.json"), canonical_bytes(report))
    return report


def _run(repo: EvaluationRepository, profile: Profile, target: Target, inputs: n8.Inputs,
         redactions: tuple[str, ...], check_lock: Callable[[], None]) -> int:
    refuse_stopped(repo, target)
    guard = Guarded(_backend(profile, target, inputs, redactions, _credential()), profile, target, inputs)

    def close(reason: str) -> None:
        check_lock()
        write_stop(target, reason)  # durable first; a guard stop already wrote its record with failures
        n8.close(repo, target.id, target.phase, target.digest, reason)

    try:
        status = n3_runner.run_blocks(guard, target.blocks, target.out, target.digest, n8.CAPS[target.phase],
                                      check_lock=guard.check(check_lock), close=close, arm_caps=n8.ARM_CAPS,
                                      stop_on_accounting_issue=True)
        if status == "complete":
            guard.inspect()  # the last slot's audit
    except Stop as stop:
        close(stop.reason)  # the single persisted closure reason
        status = stop.reason
    print(json.dumps({"phase": target.phase, "status": status, "scheduled": len(target.frame)}), flush=True)
    return int(status != "complete")


def _preflight(target: Target) -> dict[str, object]:
    full = sum((n8.SLOT_CAP for _ in target.frame), Decimal(0))
    if n8.CAPS[target.phase] < n8.SLOT_CAP:
        raise Refused("N8 first slot would exceed its cap")
    return {"study_id": str(target.id), "registration_sha256": target.digest, "scheduled": len(target.frame),
            "next_slot_worst_usd": str(n8.SLOT_CAP), "full_schedule_worst_usd": str(full),
            "planning_estimate_usd": n8.planning_estimate(len(target.frame)),
            "aggregate_cap_usd": str(n8.CAPS[target.phase]), "admission": "rolling per slot"}


def run(args: argparse.Namespace) -> int:
    if args.n8_command in {"pilot", "run"}:
        _require_paid(args.allow_paid)
    root = study.private_root(args.out)
    fixture_raw = read_bounded(args.fixture_root / DB_PATH, MAX_FIXTURE_BYTES)
    dev = n8.load_dev(args.manifests, fixture_raw, read_bounded(args.policy_file, 64 * 1024))
    register_workspace = args.workspace if args.n8_command == "register" else None
    with _operator_profile(args) as (profile, redactions), _repository() as repo:
        inputs = n8.inputs(dev, fixture_raw, profile.app, profile.policy, profile.tokenizer)
        pilot = _target(repo, profile, root, "pilot", inputs, n8.schedule(inputs.panel, "pilot"),
                        register_workspace=register_workspace)
        if args.n8_command == "pilot" or (args.n8_command == "report" and args.phase == "pilot"):
            with serial_lock(profile.app, pilot.id) as check:
                if args.n8_command == "pilot":
                    return _run(repo, profile, pilot, inputs, redactions, check)
                return _print_report(pilot, _report(repo, profile, pilot, inputs, redactions))

        target = _target(repo, profile, root, "study", inputs, n8.schedule(inputs.panel, "study"),
                         pilot_sha256=pilot.digest, register_workspace=register_workspace)
        if (target.workspace, target.generation) != (pilot.workspace, pilot.generation):
            raise Refused("N8 pilot and study must share the registered workspace and corpus generation")
        if args.n8_command == "register":
            print(json.dumps({"pilot": _preflight(pilot), "study": _preflight(target)}), flush=True)
            return 0
        if args.n8_command == "run":
            with serial_lock(profile.app, pilot.id) as check_pilot, serial_lock(profile.app, target.id) as check:
                require_pilot_unstopped(pilot)
                pilot_report = _report(repo, profile, pilot, inputs, redactions)
                check_pilot()
                require_pilot_admitted(pilot, pilot_report)
                return _run(repo, profile, target, inputs, redactions, check)
        with serial_lock(profile.app, target.id):
            return _print_report(target, _report(repo, profile, target, inputs, redactions))


def _print_report(target: Target, report: dict[str, Any]) -> int:
    admitted = (report["pilot_gate"]["verdict"] == "admit" if target.phase == "pilot"
                else report["claim_admissible"])
    print(json.dumps({"phase": target.phase, "report": str(target.out / "report.json"), "admitted": admitted}),
          flush=True)
    return int(not admitted)
