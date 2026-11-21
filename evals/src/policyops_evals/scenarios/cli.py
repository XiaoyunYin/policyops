"""Explicit paid entrypoint. The scripted and replay paths construct only mock transports."""

import argparse
from contextlib import ExitStack
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
from uuid import UUID

from policyops_evals.scenarios import SMOKE_DSN_MAX_BYTES


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
        print(f"scenario smoke stopped ({type(error).__name__})", file=sys.stderr)
        return 1


def _run_smoke(args: argparse.Namespace) -> int:
    if (not args.allow_paid or "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ
            or os.environ.get("POLICYOPS_ENV") == "test"):
        print("scenario smoke requires operator execution with --allow-paid", file=sys.stderr)
        return 1

    import httpx2
    from loguru import logger
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from sqlalchemy import Engine

    from policyops.persistence.database import make_engine, verify_runtime_role
    from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
    from policyops.providers.tokenizer import load
    from policyops_evals.cli import outside_repository
    from policyops_evals.retail_sim.bootstrap import RUNTIME as RETAIL_RUNTIME
    from policyops_evals.scenarios.cases import SCENARIOS
    from policyops_evals.scenarios.recording import Tape
    from policyops_evals.scenarios.runtime import (
        SMOKE_CAP,
        Profile,
        configuration,
        load_policy,
        preflight,
        retail_store,
        smoke_slot,
        usage,
    )

    preflight(configuration(), len(SCENARIOS))
    with args.dsn_file.open("rb") as handle:
        raw = handle.read(SMOKE_DSN_MAX_BYTES + 1)
    if len(raw) > SMOKE_DSN_MAX_BYTES:
        raise ValueError("DSN file too large")
    dsns = json.loads(raw)
    roles = {"app": APP_RUNTIME, "auth": AUTH_RUNTIME, "retail": RETAIL_RUNTIME}
    if not isinstance(dsns, dict) or set(dsns) != set(roles):
        raise ValueError("invalid DSN file roles")
    redactions: list[str] = []
    for name, role in roles.items():
        dsn = dsns[name]
        if not isinstance(dsn, str) or (parts := conninfo_to_dict(dsn)).get("user") != role:
            raise ValueError("DSN file role mismatch")
        redactions.append(dsn)
        password = parts.get("password")
        if isinstance(password, str):
            redactions.append(password)
    trace_dir = outside_repository(str(args.trace_dir)) / str(args.workspace)
    policy, tokenizer = load_policy(args.policy_file), load()

    def engine_for(dsn: str) -> Engine:
        return make_engine(lambda: psycopg.connect(dsn, connect_timeout=5))

    with ExitStack() as stack:
        engines = {}
        for name in roles:
            engine = engine_for(dsns[name])
            stack.callback(engine.dispose)
            engines[name] = engine
        for name in ("app", "auth"):
            verify_runtime_role(engines[name], roles[name])
        logger.disable("tau2")
        store = retail_store(engines["retail"], args.fixture_root)
        profile = Profile(engines["app"], engines["auth"], store, policy, tokenizer)
        profile.corpus_generation(args.workspace)
        for scenario in SCENARIOS:
            scenario.verify(store.fixture.raw)
        credential = os.environ.get("OPENAI_API_KEY", "").strip()
        if not credential:
            raise ValueError("OpenAI credential missing")
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
