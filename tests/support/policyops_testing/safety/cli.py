"""One-command owned PostgreSQL/retail lifecycle and fail-closed report replay."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
import json
from pathlib import Path
import platform
import shutil
import sys
from typing import Any
from uuid import uuid4

from policyops_contracts.evidence import EvidenceManifest
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_testing import network, redaction
from policyops_testing.app_database import AppCluster
from policyops_testing.evidence import EvidenceError, EvidenceRecorder, git_identity
from policyops_testing.postgres import OwnedPostgres, owned_postgres
from policyops_testing.safety import matrix, process_restart, rls, sensitivity, supplements
from policyops_testing.safety.config import DEFAULT_CONFIG, REPO, Config, Pair, canonical, digest, load_config
from policyops_testing.safety.e04 import pair_env, run_trial
from policyops_testing.safety.environment import make_env
from policyops_testing.safety.reports import (
    Envelope,
    MatrixRow,
    Sensitivity,
    Trial,
    completeness,
    public_summary,
    seal,
    settlement,
    sha_file,
    summarize,
    verify,
)
from policyops_testing.safety.retail import Service


def output_recorder(path: Path) -> EvidenceRecorder:
    # Refuse before EvidenceRecorder creates any component, including Windows case-insensitive spelling.
    if any(part.casefold() == "reviewer" for part in path.parts):
        raise EvidenceError("builder output cannot enter a reviewer directory")
    if path.exists():
        raise EvidenceError("output must be a fresh directory")
    return EvidenceRecorder(path, run_id=f"t30-{uuid4().hex}", task_id="T30",
                            purpose="Slice A executed safety matrix and paired recovery study", seed=2026111204)


def source_hashes() -> dict[str, str]:
    paths = {p for tree in ("packages/policyops/src", "packages/policyops_contracts/src", "tests/support")
             for p in (REPO / tree).rglob("*.py")
             if p != REPO / "packages/policyops/src/policyops/persistence/evaluation.py"}
    paths.update((REPO / "scripts/run_safety_study.py", REPO / "uv.lock", DEFAULT_CONFIG))
    paths.add(REPO / "tests/integration/test_app_privileges.py")
    return {p.relative_to(REPO).as_posix(): sha_file(p) for p in sorted(paths) if REPO in p.parents and p.is_file()}


def aborted(pair: Pair, arm: Any, error: str) -> Trial:
    now = datetime.now(UTC)
    return Trial(pair_id=pair.pair_id, seed=pair.seed, arm=arm, fault=pair.fault, variant=pair.variant,
        case_id=str(pair.identity(arm, "case")), run_id=str(pair.identity(arm, "run")),
        started_at=now, finished_at=now, application_clock_start=now, fault_reached=False,
        sends=0, reconciles=0, passes=0, final_state="aborted", outcome=None, before=None, after=None, error=error)


def missing_matrix(config: Config, rows: list[MatrixRow], error: str) -> list[MatrixRow]:
    present = {row.cell_id for row in rows}
    return [MatrixRow(cell_id=cell, relationship="not_executed", expected="mandatory", observed="aborted",
                      layer="setup", before_sha256="0" * 64, after_sha256="0" * 64, passed=False, error=error)
            for cell in config.matrix_ids if cell not in present]


def cleanup_runtime(recorder: EvidenceRecorder, server: OwnedPostgres | None, service: Service | None) -> list[str]:
    """Exact task-owned runtime trees only, after confirmed process/container release.

    Keep bounded, redacted diagnostic logs; discard fixture copies, transient credentials
    and database files. A failed ownership/release check retains the tree and fails the report.
    """
    failures = []
    for name in ("retail", "postgres"):
        target = recorder._contained(name)
        if not target.exists():
            continue
        stopped = (service is None or service.process is None or service.process.poll() is not None) \
            if name == "retail" else server is not None and not server.container_id
        if not stopped:
            failures.append(f"{name}_runtime_retained_release_uncertain")
            continue
        try:
            for log in sorted(target.rglob("*.log")):
                # Directory links are refused before any tree deletion, including Windows junctions.
                if log.is_symlink() or log.is_junction() or target not in log.resolve().parents:
                    raise EvidenceError("runtime log link")
                with log.open("rb") as stream:
                    stream.seek(max(0, log.stat().st_size - 16384))
                    text = redaction.redact_text(stream.read(16384).decode("utf-8", errors="replace"),
                                                 recorder._secrets)
                relative = log.relative_to(target).as_posix()
                recorder.write_artifact(f"raw/runtime/{name}/{relative}", text.encode(), "log")
            inventory = [target, *target.rglob("*")]
            if any(p.is_symlink() or p.is_junction() or (p != target and target not in p.resolve().parents)
                   for p in inventory):
                raise EvidenceError("runtime tree link")
            # _contained freezes the root and refuses links; resolve the exact target again before deletion.
            if recorder._contained(name).resolve() != target or recorder.root not in target.parents:
                raise EvidenceError("runtime cleanup target changed")
            shutil.rmtree(target)
        except (OSError, EvidenceError) as exc:
            failures.append(f"{name}_runtime_cleanup_{type(exc).__name__}")
    return failures


def execute(config: Config, recorder: EvidenceRecorder, suites: tuple[str, ...], pair_ids: tuple[str, ...],
            command: tuple[str, ...]) -> Envelope:
    started = datetime.now(UTC)
    code = git_identity(REPO)
    sources = source_hashes()
    pairs = [p for p in config.pairs if not pair_ids or p.pair_id in pair_ids]
    matrix_rows: list[MatrixRow] = []
    trials: list[Trial] = []
    controls: list[Sensitivity] = []
    supplement_rows: dict[str, Any] = {}
    failures: list[str] = []
    environment = {"python": platform.python_version(), "os": platform.platform(), "postgresql": "not_started"}
    owned_server: OwnedPostgres | None = None
    owned_service: Service | None = None
    recorder.write_artifact("raw/config.json", canonical(config.model_dump(mode="json")), "config")
    was_installed = network.installed()
    network.install()
    try:
        (recorder.root / "postgres").mkdir()
        with owned_postgres(recorder.root / "postgres", f"t30-{uuid4().hex[:12]}") as server:
            owned_server = server
            cluster = AppCluster.provision(server)
            db = cluster.create_database("t30_study")
            try:
                db.upgrade()
                with db.superuser() as conn:
                    environment["postgresql"] = conn.execute("SHOW server_version").fetchone()[0]
                service = Service(server, db, recorder.root / "retail")
                owned_service = service
                recorder._secrets.update(server.passwords.values())
                recorder._secrets.add(service.key.hex())
                with service.running() as origin:
                    base = make_env((service, origin), db)
                    if "matrix" in suites:
                        for runner in (matrix.action_matrix, matrix.rule_matrix, matrix.authority_matrix,
                                       matrix.tool_matrix):
                            try:
                                runner(base, matrix_rows)
                            except Exception as exc:
                                failures.append(f"matrix_{runner.__name__}_{type(exc).__name__}")
                        try:
                            rls.run(base, matrix_rows, config)
                        except Exception as exc:
                            failures.append(f"matrix_rls_{type(exc).__name__}")
                        checks: tuple[Callable[[], Sensitivity], ...] = (
                            lambda: sensitivity.reviewer_guard(base), lambda: sensitivity.rls_guard(base, cluster))
                        for check in checks:
                            try:
                                controls.append(check())
                            except Exception as exc:
                                failures.append(f"matrix_sensitivity_{type(exc).__name__}")
                    if "e04" in suites:
                        for pair in pairs:
                            for arm in pair.arms:
                                try:
                                    # Fresh controlled clock per arm; transport uses a fresh current wall clock.
                                    base = replace(base, clock=type(base.clock)(datetime.now(UTC)))
                                    env = pair_env(base, pair, arm)
                                    row = run_trial(env, pair, arm, config)
                                except Exception as exc:
                                    row = aborted(pair, arm, type(exc).__name__)
                                trials.append(row)
                                recorder.write_artifact(f"raw/trials/{pair.pair_id}-{arm}.json",
                                                        canonical(row.model_dump(mode="json")), "output")
                        completed = next((r for r in trials if r.arm == "ledger"
                                          and settlement(r) == "completed_once"), None)
                        if completed is not None:
                            controls.extend(sensitivity.report_controls(config, completed))
                        else:
                            failures.append("no_completed_ledger_for_sensitivity")
                        try:
                            controls.append(process_restart.check(base, recorder.root / "process-control"))
                            supplement_rows = supplements.run(base)
                        except Exception as exc:
                            failures.append(f"e04_supplement_{type(exc).__name__}")
            finally:
                db.dispose()
    except BaseException as exc:
        failures.append(f"study_setup_or_teardown_{type(exc).__name__}")
    finally:
        if owned_server is not None:
            recorder._secrets.update(owned_server.passwords.values())
        failures.extend(cleanup_runtime(recorder, owned_server, owned_service))
        if not was_installed:
            network.uninstall()
    if "matrix" in suites:
        matrix_rows.extend(missing_matrix(config, matrix_rows, failures[-1] if failures else "MissingExecution"))
    if "e04" in suites:
        done = {(r.pair_id, r.arm) for r in trials}
        trials.extend(aborted(p, a, "SetupAborted") for p in pairs for a in p.arms if (p.pair_id, a) not in done)
    if source_hashes() != sources:
        failures.append("executed_source_changed")
    failures.extend(completeness(config, matrix_rows, trials, suites, pair_ids))
    required = ({"reviewer_role_guard_removed", "authentication_rls_disabled"} if "matrix" in suites else set()) \
        | ({"held_receipt_removed", "effect_link_tampered", "trial_row_omitted", "real_subprocess_kill_restart"}
           if "e04" in suites else set())
    if {c.check_id for c in controls} != required or not all(c.detected for c in controls):
        failures.append("sensitivity_incomplete_or_failed")
    return Envelope(study_id=config.study_id, config=config, config_sha256=digest(config.model_dump(mode="json")),
        source_hashes=sources, code_identity=code.model_dump(mode="json"), environment=environment,
        versions={"lock_sha256": sources["uv.lock"], "fixture_sha256": FIXTURE_SHA256,
                  "policy_sha256": RETAIL_POLICY.sha256, "prompt": "none", "price": "none"},
        command=command, exit_code=int(bool(failures)), started_at=started, finished_at=datetime.now(UTC),
        suites=suites, pair_ids=pair_ids, matrix=matrix_rows, trials=trials, sensitivity=controls,
        supplements=supplement_rows, failures=tuple(sorted(set(failures))), summary=summarize(trials),
        limitations=config.limitations)


def verify_file(path: Path) -> list[str]:
    root = path.parent.parent
    # Reuse the recorder's path/link checks without permitting report creation or directory recreation.
    if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("missing or oversized study report")
    manifest_path = root / "evidence-manifest.json"
    if not manifest_path.is_file() or manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("missing or oversized manifest")
    recorder = EvidenceRecorder(root, run_id="verify", task_id="T30", purpose="read-only safety report verification")
    recorder._contained(path.relative_to(root).as_posix())
    manifest = EvidenceManifest.model_validate_json(manifest_path.read_bytes())
    errors = []
    for artifact in manifest.artifacts:
        actual = recorder._contained(artifact.path)
        if not actual.is_file() or sha_file(actual) != artifact.sha256 or actual.stat().st_size != artifact.size:
            errors.append("artifact_hash_or_size_mismatch")
    envelope = Envelope.model_validate_json(path.read_bytes())
    listed = {artifact.path for artifact in manifest.artifacts}
    expected_files = {"raw/study.json", "raw/summary.json", "raw/config.json", "raw/matrix.json"}
    expected_files.update(f"raw/trials/{row.pair_id}-{row.arm}.json" for row in envelope.trials)
    if not expected_files <= listed:
        errors.append("manifest_slot_artifact_missing")
    for row in envelope.trials:
        relative = f"raw/trials/{row.pair_id}-{row.arm}.json"
        target = recorder._contained(relative)
        if not target.is_file() or target.read_bytes() != canonical(row.model_dump(mode="json")):
            errors.append("raw_trial_envelope_mismatch")
    errors.extend(verify(envelope))
    if json.loads((root / "raw/summary.json").read_bytes()) != public_summary(envelope):
        errors.append("public_summary_mismatch")
    if json.loads((root / "raw/config.json").read_bytes()) != envelope.config.model_dump(mode="json"):
        errors.append("raw_config_mismatch")
    if json.loads((root / "raw/matrix.json").read_bytes()) != [r.model_dump(mode="json") for r in envelope.matrix]:
        errors.append("raw_matrix_mismatch")
    if envelope.failures:
        errors.append("recorded_study_failure")
    return sorted(set(errors))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--suite", default="matrix,e04", help="matrix,e04 (Slice A only)")
    result.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    result.add_argument("--out", type=Path)
    result.add_argument("--pair-id", action="append", default=[])
    result.add_argument("--verify-report", type=Path)
    result.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.worker is not None:
            return process_restart.child(args.worker)
        if args.verify_report is not None:
            errors = verify_file(args.verify_report)
            print(json.dumps({"verified": not errors, "errors": errors}, sort_keys=True))
            return int(bool(errors))
        config = load_config(args.config)
        suites = tuple(args.suite.split(","))
        if not suites or len(set(suites)) != len(suites) or not set(suites) <= {"matrix", "e04"}:
            raise ValueError("Slice A suites must be matrix and/or e04")
        if tuple(config.matrix_ids) != matrix.matrix_ids():
            raise ValueError("frozen matrix manifest differs from executable matrix")
        pair_ids = tuple(args.pair_id)
        if len(set(pair_ids)) != len(pair_ids) or not set(pair_ids) <= {p.pair_id for p in config.pairs}:
            raise ValueError("unknown or duplicate pair ID")
        if pair_ids and "e04" not in suites:
            raise ValueError("pair filter requires e04")
        if args.out is None:
            raise ValueError("--out is required")
        recorder = output_recorder(args.out)
        envelope = execute(config, recorder, suites, pair_ids,
                           tuple(sys.argv if argv is None else ("run_safety_study", *argv)))
        seal(recorder, envelope)
        print(json.dumps({"exit_code": envelope.exit_code, "matrix_rows": len(envelope.matrix),
                          "trial_rows": len(envelope.trials), "failures": envelope.failures}, sort_keys=True))
        return envelope.exit_code
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}), file=sys.stderr)  # no exception messages/credentials
        return 2
