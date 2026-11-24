"""Owned E05 runs, offline SDK smoke, paid child admission and sealed replay."""

from __future__ import annotations

import asyncio
from contextlib import closing
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any, cast
from uuid import UUID, uuid4

from policyops.budget.ledger import EvalBinding
from policyops.gateway.steps import parse_result
from policyops.persistence.budget import build_eval_ledger
from policyops.persistence.roles import EVAL_RUNTIME
from policyops.providers.contract import ENDPOINTS
from policyops_contracts.agent import ToolCallStep
from policyops_contracts.evidence import EvidenceManifest
from policyops_contracts.model import ModelResult
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail_service import FIXTURE_SHA256, MutationRequest, Receipt
from policyops_testing import network
from policyops_testing.app_database import AppCluster
from policyops_testing.evidence import EvidenceRecorder, git_identity
from policyops_testing.postgres import owned_postgres
from policyops_testing.safety import e05, e05_provider, e05_reports, sensitivity
from policyops_testing.safety.config import (
    DEFAULT_CONFIG,
    E05_ARMS,
    E05_CONFIG,
    E05_PROMPT,
    REPO,
    E05Config,
    E05Fixture,
    canonical,
    digest,
)
from policyops_testing.safety.e04 import observe
from policyops_testing.safety.e05_reports import Envelope, Row
from policyops_testing.safety.environment import Env, make_env
from policyops_testing.safety.reports import changes, sha_file
from policyops_testing.safety.retail import Service


def run_row(base: Env, fixture: E05Fixture, arm: e05.Arm, result: ModelResult | None,
            billing: dict[str, Any] | None = None) -> Row:
    env = None
    measured = None
    layer: Any = "error"
    code, error, reached = None, None, False
    held: tuple[Receipt, ...] = ()
    try:
        env = e05.fixture_env(base, fixture)
        measured = e05.prepare_fixture(env, fixture, arm)
        layer, code, reached, held = e05.dispatch(env, fixture, arm, result, measured)
    except Exception as exc:
        error = type(exc).__name__
    if env is None or measured is None:
        return Row(fixture_id=fixture.fixture_id, seed=fixture.seed, arm=arm, proposed=result,
                   layer="error", error=error or "SetupAborted", billing=billing or {})
    try:
        after, _, receipts = observe(env)
        initial_ids = {r.operation_id for r in measured.setup_receipts}
        remote = tuple(r for r in receipts if r.operation_id not in initial_ids)
        held = tuple(r for r in held if r.operation_id not in initial_ids)
        expected_hash, expected_diff = e05.exact_expected(env, fixture, measured)
        operations = {}
        for receipt in remote:
            if arm == "prompt_only":
                parsed = parse_result(result) if result is not None else None
                if not isinstance(parsed, ToolCallStep) or not isinstance(parsed.call, e05.SUPPORTED):
                    raise ValueError("effect_without_proposal")
                request = e05.mechanical(parsed.call, measured.full, measured.versions)
            else:
                with env.db.superuser() as conn:
                    execution = conn.execute("SELECT request FROM app.tool_executions WHERE operation_id = %s",
                                             (receipt.operation_id,)).fetchone()
                if execution is None:
                    raise ValueError("effect_without_execution")
                request = MutationRequest.model_validate_json(canonical(execution[0]))
            with closing(env.client()) as client:
                operations[receipt.operation_id] = client.fingerprint(UUID(receipt.operation_id), request)
        return Row(fixture_id=fixture.fixture_id, seed=fixture.seed, arm=arm, case_id=str(env.run.case_id),
            run_id=str(env.run.run_id), proposed=result, layer=layer, code=code, race_reached=reached,
            before=measured.before, after=after, expected_sha256=expected_hash, expected_diff=expected_diff,
            actual_diff=tuple(changes(measured.before.scoped, after.scoped)), remote_receipts=remote,
            held_receipts=held, setup_receipts=measured.setup_receipts, operations=operations,
            billing=billing or {}, error=error)
    except Exception as exc:
        return Row(fixture_id=fixture.fixture_id, seed=fixture.seed, arm=arm, proposed=result,
                   layer="error", error=type(exc).__name__, billing=billing or {})


def missing(fixture: E05Fixture, arm: e05.Arm, error: str, proposed: ModelResult | None = None) -> Row:
    return Row(fixture_id=fixture.fixture_id, seed=fixture.seed, arm=arm, proposed=proposed,
               layer="not_executed", error=error)


def sources() -> dict[str, str]:
    from policyops_testing.safety.cli import source_hashes
    return source_hashes() | {p.relative_to(REPO).as_posix(): sha_file(p) for p in (E05_CONFIG, E05_PROMPT)}


def execute(config: E05Config, recorder: EvidenceRecorder, mode: str, ids: tuple[str, ...],
            offline: bool, command: tuple[str, ...]) -> Envelope:
    from policyops_testing.safety.cli import cleanup_runtime

    started = datetime.now(UTC)
    source = sources()
    identity = git_identity(REPO).model_dump(mode="json")
    fixtures = [f for f in config.fixtures if not ids or f.fixture_id in ids]
    rows: list[Row] = []
    failures: list[str] = []
    controls = []
    plan = e05_provider.planning(config)
    environment = {"python": platform.python_version(), "os": platform.platform(), "postgresql": "not_started"}
    server = None
    service = None
    installed = network.installed()
    # A live child keeps the bounded provider transport enabled; every other path denies external sockets.
    if mode == "scripted":
        network.install()
    elif mode == "live":
        network.install(allowed_hosts=(ENDPOINTS["openai"].host,))
    recorder.write_artifact("raw/prompt.txt", E05_PROMPT.read_bytes(), "config")
    try:
        if offline:
            if mode != "scripted":
                raise ValueError("offline_requires_scripted")
            for fixture in fixtures:
                result, billing = asyncio.run(e05_provider.offline_complete(config, fixture))
                rows.extend(missing(fixture, cast(e05.Arm, arm), "ProviderParserOnly",
                                    e05.candidate(fixture) if arm == "gateway" else result) for arm in E05_ARMS)
                rows[-2] = rows[-2].model_copy(update={"billing": billing})
        else:
            (recorder.root / "postgres").mkdir()
            with owned_postgres(recorder.root / "postgres", f"t30-e05-{uuid4().hex[:12]}") as pg:
                server = pg
                recorder._secrets.update(pg.passwords.values())
                cluster = AppCluster.provision(pg)
                db = cluster.create_database("t30_e05")
                try:
                    db.upgrade()
                    with db.superuser() as conn:
                        environment["postgresql"] = conn.execute("SHOW server_version").fetchone()[0]
                    service = Service(pg, db, recorder.root / "retail")
                    recorder._secrets.add(service.key.hex())
                    with service.running() as origin:
                        base = make_env((service, origin), db)
                        settings = e05_provider.configuration(config)
                        ledger, store = build_eval_ledger(env="test", engine=db.engine(EVAL_RUNTIME),
                                                         configuration=settings)
                        run_key = str(recorder._identity["run_id"])
                        study = store.ensure_study(config.study_id + "-" + run_key,
                            digest(config.model_dump(mode="json")), cap_usd=settings.caps.study_usd, cap_calls=60)
                        invocation = store.ensure_invocation(study, uuid4(), settings.caps)
                        plan = e05_provider.planning(config, store.scope(study))
                        if not plan["within_caps"] or plan["budget"]["verdict"] != "within_caps":
                            raise ValueError("persisted_preflight_refused")
                        recorder.write_artifact("raw/preflight.json", canonical(plan), "output")
                        stopped = False
                        for fixture in fixtures:
                            rows.append(run_row(base, fixture, "gateway", e05.candidate(fixture)))
                            result, billing = None, {}
                            if not stopped:
                                # Scripted billing-fault fixtures have isolated study scopes: they deliberately
                                # poison admission. No money is spent and no claim of shared paid admission is made.
                                active_study, active_invocation = study, invocation
                                if mode == "scripted":
                                    active_study = store.ensure_study(run_key + fixture.fixture_id,
                                        digest(config.model_dump(mode="json")), cap_usd=settings.caps.study_usd,
                                        cap_calls=60)
                                    active_invocation = store.ensure_invocation(active_study, uuid4(), settings.caps)
                                scenario = store.ensure_scenario(active_study, fixture.fixture_id, 0,
                                    digest(config.model_dump(mode="json")), settings.caps)
                                result, billing, stop = e05_provider.complete(config, fixture, mode, ledger,
                                    EvalBinding(active_study, active_invocation, scenario))
                                billing["study_after"] = e05_provider.scope_json(store.scope(active_study))
                                billing["scenario_after"] = e05_provider.scope_json(store.scope(scenario))
                                if mode == "live" and stop:
                                    stopped = True
                                    failures.append("live_billing_or_provider_stop")
                            if stopped and not billing:
                                rows.extend(missing(fixture, arm, "StoppedAfterBillingUnknown")
                                            for arm in ("prompt_only", "replay_gateway"))
                            else:
                                rows.append(run_row(base, fixture, "prompt_only", result, billing))
                                rows.append(run_row(base, fixture, "replay_gateway", result))
                            for row in rows[-3:]:
                                recorder.write_artifact(f"raw/e05/{row.fixture_id}-{row.arm}.json",
                                    canonical(row.model_dump(mode="json")), "output")
                        controls = sensitivity.e05_controls(base)
                finally:
                    db.dispose()
    except Exception as exc:
        failures.append("study_setup_or_teardown_" + type(exc).__name__)
    finally:
        failures.extend(cleanup_runtime(recorder, server, service))
        if not installed and mode in {"scripted", "live"}:
            network.uninstall()
        elif mode == "live":
            network.revoke_hosts((ENDPOINTS["openai"].host,))
    done = {(r.fixture_id, r.arm) for r in rows}
    rows.extend(missing(f, cast(e05.Arm, a), "SetupAborted") for f in fixtures for a in E05_ARMS
                if (f.fixture_id, a) not in done)
    if sources() != source:
        failures.append("executed_source_changed")
    envelope = Envelope(config=config, config_sha256=digest(config.model_dump(mode="json")), source_hashes=source,
        code_identity=identity, environment=environment,
        versions={"fixture_sha256": FIXTURE_SHA256, "lock_sha256": source["uv.lock"],
                  "policy_sha256": RETAIL_POLICY.sha256, "price": config.price_revision},
        command=command, started_at=started, finished_at=datetime.now(UTC), provider_mode=cast(Any, mode),
        effective_model=("scripted" if mode == "scripted" else next(
            (row.proposed.returned_model for row in rows
             if row.arm == "prompt_only" and row.proposed is not None and row.proposed.returned_model is not None),
            None)),
        execution_scope="provider_parser_only" if offline else "full", fixture_ids=ids, preflight=plan,
        rows=rows, sensitivity=tuple(controls), summary=e05_reports.summarize(config, rows, ids),
        failures=tuple(failures), exit_code=int(bool(failures)), limitations=config.limitations + ((
            "Provider/parser-only smoke: no DB, dispatch, effect observation or acceptance claim.",)
            if offline else ()))
    failures.extend(e05_reports.verify(envelope))
    return envelope.model_copy(update={"failures": tuple(sorted(set(failures))), "exit_code": int(bool(failures))})


def verify_file(path: Path) -> list[str]:
    if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("missing_or_oversized_report")
    root = path.parent.parent
    manifest_file = root / "evidence-manifest.json"
    if not manifest_file.is_file() or manifest_file.stat().st_size > 1024 * 1024:
        raise ValueError("missing_or_oversized_manifest")
    manifest = EvidenceManifest.model_validate_json(manifest_file.read_bytes())
    envelope = Envelope.model_validate_json(path.read_bytes())
    recorder = EvidenceRecorder(root, run_id="verify", task_id="T30", purpose="E05 read-only verification")
    errors = []
    artifacts = {a.path: a for a in manifest.artifacts}
    expected = {"raw/study.json": canonical(envelope.model_dump(mode="json")),
                "raw/config.json": canonical(envelope.config.model_dump(mode="json")),
                "raw/summary.json": canonical(e05_reports.public_summary(envelope))}
    expected.update({f"raw/e05/{r.fixture_id}-{r.arm}.json": canonical(r.model_dump(mode="json"))
                     for r in envelope.rows})
    if not expected.keys() <= artifacts.keys():
        errors.append("manifest_slot_artifact_missing")
    for name, artifact in artifacts.items():
        actual = recorder._contained(name)
        if not actual.is_file() or sha_file(actual) != artifact.sha256 or actual.stat().st_size != artifact.size:
            errors.append("artifact_hash_or_size_mismatch")
    for name, body in expected.items():
        actual = recorder._contained(name)
        if not actual.is_file() or actual.read_bytes() != body:
            errors.append("raw_envelope_mismatch")
    errors.extend(e05_reports.verify(envelope))
    if envelope.failures:
        errors.append("recorded_study_failure")
    return sorted(set(errors))


def command(args: Any, argv: Any) -> int:
    from policyops_testing.safety.cli import output_recorder
    from policyops_testing.safety.config import load_e05_config

    config = load_e05_config(E05_CONFIG if args.config == DEFAULT_CONFIG else args.config)
    if args.preflight_only:
        print(json.dumps(e05_provider.planning(config), sort_keys=True))
        return 0
    ids = tuple(args.fixture_id)
    if len(set(ids)) != len(ids) or not set(ids) <= {f.fixture_id for f in config.fixtures}:
        raise ValueError("unknown_or_duplicate_fixture")
    if args.out is None:
        raise ValueError("out_required")
    if args.provider_mode == "live":
        if not args.allow_paid or args.offline_only:
            raise ValueError("live_requires_allow_paid")
        if not args.live_child:
            # Do not inspect credentials in the parent. Child inherits the existing T29 environment config.
            output_recorder_check = args.out
            if output_recorder_check.exists() or any(p.casefold() == "reviewer" for p in args.out.parts):
                raise ValueError("fresh_builder_output_required")
            child_args = list(sys.argv[1:] if argv is None else argv)
            result = subprocess.run([sys.executable, "-B", str(REPO / "scripts/run_safety_study.py"),
                *child_args, "--live-child"], env={**os.environ, "POLICYOPS_E05_CHILD": "1"},
                timeout=7200, check=False)
            return result.returncode
        if os.environ.get("POLICYOPS_E05_CHILD") != "1":
            raise ValueError("live_child_required")
    recorder = output_recorder(args.out)
    envelope = execute(config, recorder, args.provider_mode, ids, args.offline_only,
                       tuple(sys.argv if argv is None else ("run_safety_study", *argv)))
    e05_reports.seal(recorder, envelope)
    print(json.dumps({"exit_code": envelope.exit_code, "rows": len(envelope.rows),
                      "execution_scope": envelope.execution_scope, "failures": envelope.failures}))
    return envelope.exit_code
