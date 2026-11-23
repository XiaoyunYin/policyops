"""Operator entry points for N2 setup, registration, dev execution and reporting."""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from decimal import Decimal
import json
import os
from pathlib import Path
import sys
from typing import TYPE_CHECKING
from uuid import UUID

from policyops_evals.scenarios import SMOKE_DSN_MAX_BYTES, Refused, in_test_context, read_bounded


if TYPE_CHECKING:
    from sqlalchemy import Engine

    from policyops_evals.scenarios.runtime import Profile


def add_parser(group: argparse.ArgumentParser) -> None:
    commands = group.add_subparsers(dest="scenario_command", required=True)
    setup = commands.add_parser("setup", help="Prepare a scenario workspace and write the private smoke DSNs")
    setup.add_argument("--db-host", required=True)
    setup.add_argument("--db-port", type=int, required=True)
    setup.add_argument("--db-name", required=True)
    setup.add_argument("--superuser", default="postgres")
    for role in ("superuser", "app-migrator", "app", "auth", "retail-migrator", "retail"):
        setup.add_argument(f"--{role}-password-file", type=Path, required=True)
    setup.add_argument("--fixture-root", type=Path, required=True)
    setup.add_argument("--policy-file", type=Path, required=True)
    setup.add_argument("--dsn-file", type=Path, required=True, help="output JSON outside the checkout")
    workspace = setup.add_mutually_exclusive_group(required=True)
    workspace.add_argument("--workspace", type=UUID)
    workspace.add_argument("--workspace-name")
    setup.add_argument("--allow-paid", action="store_true")
    setup.add_argument("--max-usd")
    setup.add_argument("--max-calls", type=int)
    setup.add_argument("--max-input-tokens", type=int)
    setup.add_argument("--max-seconds", type=int)
    setup.set_defaults(handler=command_setup)

    smoke = commands.add_parser("smoke")
    smoke.add_argument("--dsn-file", type=Path, required=True, help="private JSON with app, auth and retail libpq DSNs")
    smoke.add_argument("--workspace", type=UUID, required=True, help="dedicated workspace UUID")
    smoke.add_argument("--fixture-root", type=Path, required=True, help="staged audited retail fixture directory")
    smoke.add_argument("--policy-file", type=Path, required=True, help="pinned tau2 retail policy.md")
    smoke.add_argument("--trace-dir", type=Path, required=True, help="private cassette directory")
    smoke.add_argument("--allow-paid", action="store_true")
    smoke.set_defaults(handler=command_smoke)

    registration = commands.add_parser("register", help="Register the frozen N2 study and save its receipt")
    run = commands.add_parser("run", help="Run a registered dev repeat")
    report = commands.add_parser("report", help="Summarize the two registered dev repeats offline")
    for command in (registration, run, report):
        command.add_argument("--manifests", type=Path, required=True, help="directory with the four frozen manifests")
        command.add_argument("--fixture-root", type=Path, required=True)
        command.add_argument("--policy-file", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True, help="registered private output outside the repository")
    registration.add_argument("--dsn-file", type=Path, required=True)
    registration.add_argument("--workspace", type=UUID, required=True)
    registration.set_defaults(handler=command_register)
    run.add_argument("--dsn-file", type=Path, required=True)
    run.add_argument("--split", choices=("dev", "held-out"), required=True)
    run.add_argument("--repeat", type=int, choices=(1, 2), required=True)
    run.add_argument("--max-usd", type=Decimal, required=True, help="aggregate cost ceiling for the selected repeat")
    run.add_argument("--pilot", action="store_true")
    run.add_argument("--allow-paid", action="store_true")
    run.set_defaults(handler=command_run)
    report.set_defaults(handler=command_report)

    n3 = commands.add_parser("n3", help="Registered baseline and tool-contract scenario study")
    n3_commands = n3.add_subparsers(dest="n3_command", required=True)
    for name in ("register", "run", "report"):
        subcommand = n3_commands.add_parser(name)
        subcommand.add_argument("--revision", type=int, choices=(1,), help="select revision 1 of 1")
        subcommand.add_argument("--e1-report", type=Path, help="frozen E1 dev report required by revision 1")
        subcommand.add_argument("--manifests", type=Path, required=True)
        subcommand.add_argument("--fixture-root", type=Path, required=True)
        subcommand.add_argument("--policy-file", type=Path, required=True)
        subcommand.add_argument("--out", type=Path, required=True)
        subcommand.add_argument("--dsn-file", type=Path, required=True)
        if name == "register":
            subcommand.add_argument("--workspace", type=UUID, required=True)
        else:
            subcommand.add_argument("--split", choices=("dev", "held-out"), required=True)
        if name == "run":
            subcommand.add_argument("--max-usd", type=Decimal, required=True, help="dev or all-in USD ceiling")
            subcommand.add_argument("--allow-paid", action="store_true")
        subcommand.set_defaults(handler=command_n3)

    n7 = commands.add_parser("n7", help="Dev-only implicit caching study")
    n7_commands = n7.add_subparsers(dest="n7_command", required=True)
    for name in ("register", "pilot", "run", "report"):
        command = n7_commands.add_parser(name)
        for option in ("dsn-file", "manifests", "fixture-root", "policy-file", "out"):
            command.add_argument(f"--{option}", type=Path, required=True)
        if name == "register":
            command.add_argument("--workspace", type=UUID, required=True)
        if name in {"pilot", "run"}:
            command.add_argument("--allow-paid", action="store_true")
        if name == "report":
            command.add_argument("--phase", choices=("pilot", "study"), required=True)
        command.set_defaults(handler=command_n7)

    n8 = commands.add_parser("n8", help="Dev-only prompt-injection study of the workbench agent")
    n8_commands = n8.add_subparsers(dest="n8_command", required=True)
    for name in ("register", "pilot", "run", "report"):
        command = n8_commands.add_parser(name)
        for option in ("dsn-file", "manifests", "fixture-root", "policy-file", "out"):
            command.add_argument(f"--{option}", type=Path, required=True)
        if name == "register":
            command.add_argument("--workspace", type=UUID, required=True)
        if name in {"pilot", "run"}:
            command.add_argument("--allow-paid", action="store_true")
        if name == "report":
            command.add_argument("--phase", choices=("pilot", "study"), required=True)
        command.set_defaults(handler=command_n8)


def command_n8(args: argparse.Namespace) -> int:
    try:
        from policyops_evals.scenarios.n8_cli import run

        return run(args)
    except Exception as error:
        return _error("n8 " + args.n8_command, error)


def command_n7(args: argparse.Namespace) -> int:
    try:
        from policyops_evals.scenarios.n7_cli import run

        return run(args)
    except Exception as error:
        return _error("n7 " + args.n7_command, error)


def command_n3(args: argparse.Namespace) -> int:
    try:
        from policyops_evals.scenarios.n3_cli import run

        return run(args)
    except Exception as error:
        return _error("n3 " + args.n3_command, error)


def command_setup(args: argparse.Namespace) -> int:
    from policyops_evals.scenarios.setup import SetupRefused, run_setup

    try:
        summary = run_setup(args)
    except SetupRefused as error:
        print(f"scenario setup refused ({error})", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"scenario setup stopped ({type(error).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(asdict(summary), default=str), flush=True)
    return 0


def command_smoke(args: argparse.Namespace) -> int:
    try:
        return _run_smoke(args)
    except Exception as error:
        # Provider and driver errors may carry raw requests, endpoints or connection credentials.
        return _error("smoke", error)


def _require_paid(allow_paid: bool) -> None:
    if not allow_paid or in_test_context():
        raise Refused("scenario requires operator execution outside tests with --allow-paid")


@contextmanager
def _operator_engines(dsn_file: Path) -> Iterator[tuple[dict[str, Engine], tuple[str, ...]]]:
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    from policyops.persistence.database import make_engine, verify_runtime_role
    from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
    from policyops_evals.retail_sim.bootstrap import RUNTIME as RETAIL_RUNTIME

    dsns = json.loads(read_bounded(dsn_file, SMOKE_DSN_MAX_BYTES))
    roles = {"app": APP_RUNTIME, "auth": AUTH_RUNTIME, "retail": RETAIL_RUNTIME}
    if not isinstance(dsns, dict) or set(dsns) != set(roles):
        raise Refused("invalid private scenario DSN roles")
    redactions: list[str] = []

    def engine_for(dsn: str) -> Engine:
        return make_engine(lambda: psycopg.connect(dsn, connect_timeout=5))

    with ExitStack() as stack:
        engines = {}
        for role, expected in roles.items():
            dsn = dsns[role]
            if not isinstance(dsn, str) or (parts := conninfo_to_dict(dsn)).get("user") != expected:
                raise Refused("scenario DSN role mismatch")
            redactions.append(dsn)
            if isinstance(password := parts.get("password"), str):
                redactions.append(password)
            engine = engine_for(dsn)
            stack.callback(engine.dispose)
            engines[role] = engine
        for role in ("app", "auth"):
            verify_runtime_role(engines[role], roles[role])
        yield engines, tuple(redactions)


@contextmanager
def _operator_profile(args: argparse.Namespace) -> Iterator[tuple[Profile, tuple[str, ...]]]:
    from loguru import logger

    from policyops.providers.tokenizer import load
    from policyops_evals.scenarios.runtime import Profile, load_policy, retail_store

    policy, tokenizer = load_policy(args.policy_file), load()
    with _operator_engines(args.dsn_file) as (engines, redactions):
        logger.disable("tau2")
        store = retail_store(engines["retail"], args.fixture_root)
        yield Profile(engines["app"], engines["auth"], store, policy, tokenizer), redactions


def _credential() -> str:
    value = os.environ.get("OPENAI_API_KEY", "").strip()
    if not value:
        raise Refused("OpenAI credential missing")
    return value


def _run_smoke(args: argparse.Namespace) -> int:
    _require_paid(args.allow_paid)

    import httpx2

    from policyops_evals.cli import outside_repository
    from policyops_evals.scenarios.cases import SCENARIOS
    from policyops_evals.scenarios.recording import Tape
    from policyops_evals.scenarios.runtime import (
        SMOKE_CAP,
        configuration,
        preflight,
        smoke_slot,
        usage,
    )

    preflight(configuration(), len(SCENARIOS))
    trace_dir = outside_repository(str(args.trace_dir)) / str(args.workspace)
    with _operator_profile(args) as (profile, redactions):
        profile.corpus_generation(args.workspace)
        for scenario in SCENARIOS:
            scenario.verify(profile.retail.fixture.raw)
        credential = _credential()
        slots = [smoke_slot(args.workspace, scenario) for scenario in SCENARIOS]
        for slot, scenario in zip(slots, SCENARIOS, strict=True):
            accounts = [usage(profile.app, assigned) for assigned in slots]
            if any(account.blocked for account in accounts) or sum(
                    account.settled + account.held for account in accounts) >= SMOKE_CAP:
                raise ValueError("aggregate smoke ledger blocked")
            summary = profile._run(
                scenario, slot, Tape(trace_dir / str(slot.id)),
                lambda: httpx2.AsyncHTTPTransport(trust_env=False, retries=0),
                env="local", credential=credential, redactor=slot.redactor((credential, *redactions)),
            )
            fields = asdict(summary)
            fields["gold_match"] = "yes" if summary.gold_match else "no"
            print(json.dumps(fields, default=str), flush=True)
            if usage(profile.app, slot).blocked:
                raise ValueError("smoke ledger blocked")
    return 0


def _error(command: str, error: Exception) -> int:
    # DB, provider and validation diagnostics can contain private inputs.
    detail = str(error) if isinstance(error, Refused) else type(error).__name__
    print(f"scenario {command} stopped ({detail})", file=sys.stderr)
    return 1


def command_register(args: argparse.Namespace) -> int:
    from policyops.persistence.evaluation import environment_repository
    from policyops.providers.tokenizer import load
    from policyops_evals.scenarios.runtime import active_policy_generation, load_policy
    from policyops_evals.scenarios.study import (
        load_inputs,
        private_root,
        register,
        registration_payload,
        write_registration,
    )

    try:
        out = private_root(args.out)
        inputs = load_inputs(args.manifests, args.fixture_root, args.policy_file)
        policy, tokenizer = load_policy(args.policy_file), load()
        with _operator_engines(args.dsn_file) as (engines, _):
            generation = active_policy_generation(engines["app"], args.workspace, policy, tokenizer)
        if generation is None:
            raise Refused("the registered workspace needs a digest-matched active corpus")
        repository = environment_repository()
        if repository is None:
            raise Refused("POLICYOPS_EVAL_DATABASE_DSN is required for registration")
        try:
            payload = registration_payload(inputs, args.workspace, generation, tokenizer.identity_sha256, out)
            document = register(repository, payload, len(inputs.dev))
            write_registration(out, document)
        finally:
            repository.engine.dispose()
        print(json.dumps({"study_id": document["study_id"], "sha256": document["receipt"]["sha256"],
                          "created_at": document["receipt"]["created_at"]}), flush=True)
        return 0
    except Exception as error:
        return _error("register", error)


def command_run(args: argparse.Namespace) -> int:
    try:
        return _run_batch(args)
    except Exception as error:
        return _error("run", error)


def _run_batch(args: argparse.Namespace) -> int:
    from policyops_evals.scenarios.study import require_dev

    require_dev(args.split)
    _require_paid(args.allow_paid)
    if args.pilot and args.repeat != 1:
        raise Refused("the pilot is the first 16 slots of dev repeat 1")

    import httpx2

    from policyops.persistence.evaluation import environment_repository
    from policyops_evals.scenarios.batch import AppBackend, preflight, run_batch, serial_lock
    from policyops_evals.scenarios.cases import Scenario
    from policyops_evals.scenarios.recording import Tape
    from policyops_evals.scenarios.reporting import collect, gate
    from policyops_evals.scenarios.runtime import Slot, Summary
    from policyops_evals.scenarios.study import (
        PILOT_SLOTS,
        assigned_slot,
        load_inputs,
        private_root,
        read_registration,
        registration_id,
    )

    preflight(args.max_usd, [], 0)
    out = private_root(args.out)
    inputs = load_inputs(args.manifests, args.fixture_root, args.policy_file)
    study_id, receipt = read_registration(out, inputs)
    bound = receipt["payload"]
    digest = receipt["sha256"]
    workspace = UUID(bound["workspace"])
    generation = UUID(bound["corpus_generation"])
    repository = environment_repository()
    if repository is None:
        raise Refused("POLICYOPS_EVAL_DATABASE_DSN is required to verify registration")
    try:
        config = repository.run_configuration(registration_id(study_id))
        if config is None or config.get("registration") != receipt or repository.study_manifest(study_id) != digest:
            raise Refused("database registration receipt mismatch")
    finally:
        repository.engine.dispose()

    cases = inputs.dev[:PILOT_SLOTS] if args.pilot else inputs.dev
    schedule = [(case, assigned_slot(study_id, workspace, args.split, args.repeat, case.key)) for case in cases]
    pilot_frame = [(args.repeat, case, slot) for case, slot in schedule]
    credential = _credential()
    with _operator_profile(args) as (profile, redactions), serial_lock(profile.app, study_id) as check_lock:
        if profile.tokenizer.identity_sha256 != bound["tokenizer_sha256"]:
            raise Refused("registered tokenizer digest changed")
        if profile.corpus_generation(workspace) != generation:
            raise Refused("registered policy corpus generation changed")

        def execute(case: Scenario, slot: Slot, tape: Tape) -> Summary:
            return profile._run(
                case, slot, tape, lambda: httpx2.AsyncHTTPTransport(trust_env=False, retries=0),
                env="local", credential=credential, redactor=slot.redactor((credential, *redactions)),
                expected_generation=generation,
            )

        backend = AppBackend(profile.app, workspace, bound["graph_sha256"], bound["prompt_sha256"], execute)
        try:
            results = run_batch(backend, schedule, out, digest, args.max_usd, check_lock=check_lock)
        except Refused:
            if args.pilot:
                saved, _ = collect(out, pilot_frame, digest)
                print(json.dumps({"pilot_gate": gate(pilot_frame, saved)}, sort_keys=True), flush=True)
            raise
        if args.pilot:
            verdict = gate(pilot_frame, results)
            print(json.dumps({"pilot_gate": verdict}, sort_keys=True), flush=True)
            return int(verdict["verdict"] != "proceed")
        print(json.dumps({"repeat": args.repeat, "recorded": len(results), "scheduled": len(schedule)}), flush=True)
        return 0


def command_report(args: argparse.Namespace) -> int:
    from policyops_evals.scenarios.reporting import collect, markdown, report
    from policyops_evals.scenarios.study import (
        REPEATS,
        assigned_slot,
        atomic_write,
        load_inputs,
        private_child,
        private_root,
        read_registration,
    )

    try:
        out = private_root(args.out)
        inputs = load_inputs(args.manifests, args.fixture_root, args.policy_file)
        study_id, receipt = read_registration(out, inputs)
        workspace = UUID(receipt["payload"]["workspace"])
        schedule = [(repeat, case, assigned_slot(study_id, workspace, "dev", repeat, case.key))
                    for repeat in REPEATS for case in inputs.dev]
        digest = receipt["sha256"]
        results, pending = collect(out, schedule, digest)
        summary = report(schedule, results, pending, digest=digest)
        encoded = json.dumps(summary, sort_keys=True, allow_nan=False)
        if len(encoded.encode()) > 128 * 1024:
            raise Refused("scenario report exceeds its size bound")
        atomic_write(private_child(out, "summary.md"), markdown(summary).encode())
        print(encoded, flush=True)
        return 0
    except Exception as error:
        return _error("report", error)
