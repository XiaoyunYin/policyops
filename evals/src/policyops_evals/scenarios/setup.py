"""Provision the operator scenario through the retail and application persistence paths."""

from __future__ import annotations

import argparse
from base64 import b64decode
from collections.abc import Callable, Coroutine
from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from hmac import compare_digest
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import sys
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any, Literal
from uuid import UUID, uuid4

import httpx2
import psycopg
from psycopg.conninfo import make_conninfo
from pydantic import SecretStr
from sqlalchemy import Engine, text

from policyops.persistence.database import make_engine, transaction, verify_runtime_role
import policyops.persistence.migrate as app_migrate
from policyops.persistence.records import Workspace
from policyops.persistence.repositories import create_workspace
from policyops.persistence.roles import APP_MIGRATOR, APP_RUNTIME, AUTH_RUNTIME, scram_sha256_verifier
from policyops.providers.calls import Providers
from policyops.providers.tokenizer import Tokenizer, load
from policyops.retrieval.ingest import Outcome, PaidCaps, Request, ingest
from policyops_contracts.conversation import PolicyContext
from policyops_contracts.policy import RETAIL_POLICY
from policyops_evals.build import default_manifest_dir
from policyops_evals.cli import outside_repository
from policyops_evals.ingest_manifest import FILE_NAME
from policyops_evals.retail_sim import bootstrap, fixture
from policyops_evals.retail_sim import migrate as retail_migrate
from policyops_evals.scenarios import SMOKE_DSN_MAX_BYTES
from policyops_evals.scenarios.cases import SCENARIOS
from policyops_evals.scenarios.runtime import SCOPE, active_policy_generation, load_policy


MODEL = "text-embedding-3-small"
DIMENSIONS = 1536
MAX_USD = Decimal("0.01")
SMOKE_ROLES = {"app": APP_RUNTIME, "auth": AUTH_RUNTIME, "retail": bootstrap.RUNTIME}
PASSWORD_ROLES = {"app_migrator": APP_MIGRATOR, "retail_migrator": bootstrap.MIGRATOR, **SMOKE_ROLES}
SETUP_LOCK = 0x4E325F5331
EmbeddingHandler = Callable[[httpx2.Request], Coroutine[None, None, httpx2.Response]]


class SetupRefused(ValueError):
    """Fixed, credential-free refusal messages."""


@dataclass(frozen=True)
class SetupSummary:
    workspace_id: UUID
    corpus_generation_id: UUID
    content_digest: str
    status: Literal["created", "reused"]
    usd_spent: Decimal = Decimal(0)


def _test_execution() -> bool:
    return "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ or os.environ.get("POLICYOPS_ENV") == "test"


def _live_providers() -> Providers:
    if _test_execution():
        raise SetupRefused("live embeddings disabled in tests")
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise SetupRefused("OPENAI_API_KEY is required for embeddings")
    return Providers({"openai": SecretStr(key)}, lambda _: httpx2.AsyncHTTPTransport(trust_env=False, retries=0))


def _caps(args: argparse.Namespace) -> PaidCaps | None:
    values = (args.max_usd, args.max_calls, args.max_input_tokens, args.max_seconds)
    if not args.allow_paid and all(value is None for value in values):
        return None
    if not args.allow_paid or any(value is None for value in values):
        raise SetupRefused("--allow-paid and all four caps must be supplied together")
    try:
        paid = PaidCaps(MODEL, DIMENSIONS, Decimal(args.max_usd), args.max_calls, args.max_input_tokens,
                        args.max_seconds)
    except (InvalidOperation, ValueError):
        raise SetupRefused("invalid embedding caps") from None
    if paid.max_usd > MAX_USD:
        raise SetupRefused("embedding USD cap exceeds 0.01")
    return paid


def _validate_target(args: argparse.Namespace) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9.:%_-]{1,253}", args.db_host):
        raise SetupRefused("a single database hostname or IP is required")
    try:
        ip_address(args.db_host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9.])?", args.db_host):
            raise SetupRefused("a single database hostname or IP is required") from None
    if not 1 <= args.db_port <= 65535:
        raise SetupRefused("database port must be in 1..65535")
    if any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}", value)
           for value in (args.db_name, args.superuser)):
        raise SetupRefused("invalid database or superuser name")
    name = args.workspace_name
    if name is not None and (not 1 <= len(name) <= 200 or name != name.strip() or not name.isprintable()):
        raise SetupRefused("workspace name must be 1..200 printable characters without surrounding whitespace")
    try:
        target = outside_repository(str(args.dsn_file))
    except argparse.ArgumentTypeError:
        raise SetupRefused("DSN output is inside the repository") from None
    resolved = target.resolve()
    if target.is_symlink() or target.is_junction() or (target.exists() and not target.is_file()):
        raise SetupRefused("DSN output must be a regular file")
    if any((parent / ".git").exists() for parent in resolved.parents):
        raise SetupRefused("DSN output must be outside the repository")
    inputs = (args.policy_file, args.superuser_password_file,
              *(getattr(args, f"{role}_password_file") for role in PASSWORD_ROLES))
    if any(resolved == path.resolve() for path in inputs) or (
            args.fixture_root.resolve() in (resolved, *resolved.parents)):
        raise SetupRefused("DSN output overlaps a setup input")
    return resolved


def _read_password(path: Path) -> str:
    with path.open("rb") as handle:
        data = handle.read(4097)
    if len(data) > 4096:
        raise SetupRefused("password file exceeds size bound")
    data = data.removesuffix(b"\r\n") if data.endswith(b"\r\n") else data.removesuffix(b"\n")
    password = data.decode("utf-8")
    if not password or not password.isprintable():
        raise SetupRefused("password file must contain one printable UTF-8 line")
    return password


def _dsn(args: argparse.Namespace, role: str, password: str) -> str:
    return make_conninfo(host=args.db_host, hostaddr="", port=args.db_port, dbname=args.db_name, user=role,
                         password=password, options="-c timezone=UTC", connect_timeout=5)


def _provision_retail(admin: psycopg.Connection[Any], database: str, passwords: dict[str, str]) -> None:
    """Check existing configuration before bootstrap, which normally alters existing roles."""
    with admin.transaction():
        verifiers = {}
        missing = False
        for role, password in passwords.items():
            row = admin.execute(
                "SELECT rolpassword, rolcanlogin AND rolinherit AND NOT "
                "(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) "
                "AND rolconnlimit = -1 AND rolvaliduntil IS NULL "
                "AND NOT EXISTS (SELECT FROM pg_auth_members WHERE r.oid = roleid OR r.oid = member) "
                "AND NOT EXISTS (SELECT FROM pg_db_role_setting WHERE r.oid = setrole) "
                "FROM pg_authid r WHERE rolname = %s", (role,),
            ).fetchone()
            if row is None:
                missing = True
                verifiers[role] = scram_sha256_verifier(password)
            else:
                verifier, compatible = row
                if not compatible or not _matches_password(verifier, password):
                    raise SetupRefused("existing retail role configuration differs")
                verifiers[role] = verifier
        schema = admin.execute(
            "SELECT nspowner = to_regrole(%s), "
            "has_schema_privilege(to_regrole(%s), oid, 'USAGE'), "
            "has_schema_privilege(to_regrole(%s), oid, 'CREATE'), "
            "EXISTS (SELECT FROM aclexplode(nspacl) WHERE grantee = 0) "
            "FROM pg_namespace WHERE nspname = 'retail'", (bootstrap.MIGRATOR, bootstrap.RUNTIME, bootstrap.RUNTIME),
        ).fetchone()
        if schema is not None and (missing or tuple(schema) != (True, True, False, False)):
            raise SetupRefused("existing retail schema configuration differs")
        if schema is None:
            bootstrap.provision(admin, database, verifiers)
        else:
            bootstrap.check_isolation(admin)


def _matches_password(verifier: str | None, password: str) -> bool:
    if not verifier or not verifier.startswith("SCRAM-SHA-256$"):
        return False
    try:
        _, parameters, _ = verifier.split("$")
        iterations, salt = parameters.split(":")
        expected = scram_sha256_verifier(password, salt=b64decode(salt, validate=True), iterations=int(iterations))
    except (ValueError, OverflowError):
        return False
    return compare_digest(verifier, expected)


def _workspace(auth: Engine, workspace: UUID | None, name: str | None) -> UUID:
    with transaction(auth) as connection:
        ids = connection.execute(text(
            "SELECT id FROM identity.workspaces WHERE id = :id OR name = :name LIMIT 2"
        ), {"id": workspace, "name": name}).scalars().all()
        if len(ids) > 1:
            raise SetupRefused("workspace name is ambiguous; supply its UUID")
        if ids:
            return UUID(str(ids[0]))
        workspace = workspace or uuid4()
        slug = f"scenario-{workspace.hex}"
        new = Workspace(id=workspace, slug=slug, name=name or slug, created_at=datetime.now(UTC))
        create_workspace(connection, new)
    return workspace


def _preflight(plan: Outcome, caps: PaidCaps | None) -> None:
    estimate = plan.details["estimate"]
    if "frozen_total_local_tokens" not in estimate:
        return
    checks = None if caps is None else {
        "usd": Decimal(estimate["worst_usd"]) <= caps.max_usd,
        "calls": estimate["batches"] <= caps.max_calls,
        "tokens": estimate["frozen_total_local_tokens"] <= caps.max_input_tokens,
        "seconds": estimate["worst_seconds"] <= min(caps.max_seconds, plan.details.get("job_remaining_seconds",
                                                                                       caps.max_seconds)),
    }
    print(json.dumps({"embedding_preflight": {
        "model": MODEL, "dimensions": DIMENSIONS, "caps": caps.record() if caps else None,
        "estimate": estimate, "within_caps": checks,
    }}), file=sys.stderr, flush=True)
    if checks is None:
        raise SetupRefused("embedding work requires --allow-paid and explicit caps")
    if not all(checks.values()):
        raise SetupRefused("embedding preflight exceeds caps")


def _spent(outcome: Outcome) -> Decimal:
    scope = outcome.details.get("scope")
    return Decimal(scope["spent_usd"]) if scope else Decimal(0)


def _prepare_corpus(app: Engine, workspace: UUID, policy: PolicyContext, tokenizer: Tokenizer,
                    output_dir: Path, caps: PaidCaps | None, scripted: EmbeddingHandler | None) -> SetupSummary:
    active = active_policy_generation(app, workspace, policy, tokenizer)
    if active is not None:
        return SetupSummary(workspace, active, policy.sha256, "reused")

    def providers() -> Providers:
        if scripted is None:
            return _live_providers()
        return Providers({"openai": SecretStr("scenario-scripted-embedding")}, lambda _: httpx2.MockTransport(scripted))

    manifest = (default_manifest_dir() / FILE_NAME).read_bytes()
    with TemporaryDirectory(prefix=".scenario-policy-", dir=output_dir) as directory:
        root = Path(directory)
        staged = root / RETAIL_POLICY.path
        staged.parent.mkdir(parents=True)
        staged.write_bytes(policy.text.encode("utf-8"))
        request = Request(workspace, SCOPE.corpus_key, manifest, sha256(manifest).hexdigest(), root, paid=caps)
        env = "test" if scripted is not None else "local"
        plan = ingest(request, engine=app, tokenizer=tokenizer, providers=providers, env=env)
        if plan.outcome == "planned":
            _preflight(plan, caps)
            result = ingest(replace(request, mode="execute"), engine=app, tokenizer=tokenizer,
                            providers=providers, env=env)
        else:
            result = plan
    if result.outcome not in {"activated", "unchanged"}:
        raise SetupRefused(f"corpus ingest {result.outcome} ({result.reason})")
    active = active_policy_generation(app, workspace, policy, tokenizer)
    if active is None or str(active) != result.details["generation_id"]:
        raise SetupRefused("activated generation does not match the smoke policy")
    if result.outcome == "unchanged":
        return SetupSummary(workspace, active, policy.sha256, "reused")
    return SetupSummary(workspace, active, policy.sha256, "created", _spent(result) - _spent(plan))


def _smoke_dsns(dsns: dict[str, str]) -> bytes:
    raw = (json.dumps({label: dsns[role] for label, role in SMOKE_ROLES.items()}) + "\n").encode()
    if len(raw) > SMOKE_DSN_MAX_BYTES:
        raise SetupRefused("smoke DSNs exceed the output size bound")
    return raw


def _write_dsns(target: Path, raw: bytes) -> None:
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(dir=target.parent, prefix=".scenario-dsns-", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_setup(args: argparse.Namespace, *, scripted: EmbeddingHandler | None = None) -> SetupSummary:
    caps, output = _caps(args), _validate_target(args)
    if scripted is not None and not _test_execution():
        raise SetupRefused("scripted embeddings are test-only")
    policy, tokenizer = load_policy(args.policy_file), load()
    reviewed = fixture.load(args.fixture_root)
    for scenario in SCENARIOS:
        scenario.verify(reviewed.raw)
    passwords = {role: _read_password(getattr(args, f"{label}_password_file"))
                 for label, role in PASSWORD_ROLES.items()}
    retail_passwords = {role: passwords[role] for role in bootstrap.ROLES}
    if any(len(value) < 24 or not value.isascii() for value in retail_passwords.values()):
        raise SetupRefused("retail passwords require at least 24 printable ASCII characters")
    dsns = {role: _dsn(args, role, password) for role, password in passwords.items()}
    smoke_dsns = _smoke_dsns(dsns)
    admin_dsn = _dsn(args, args.superuser, _read_password(args.superuser_password_file))

    with ExitStack() as stack:
        def engine(role: str) -> Engine:
            target = make_engine(lambda: psycopg.connect(dsns[role]))
            stack.callback(target.dispose)
            return target

        with engine(APP_MIGRATOR).connect() as connection:
            if connection.exec_driver_sql("SELECT current_user").scalar_one() != APP_MIGRATOR:
                raise SetupRefused("application migrator role mismatch")
            if app_migrate.current(connection) != app_migrate.head():
                raise SetupRefused("application database must be migrated to head")
        app, auth = engine(APP_RUNTIME), engine(AUTH_RUNTIME)
        verify_runtime_role(app, APP_RUNTIME)
        verify_runtime_role(auth, AUTH_RUNTIME)
        admin = stack.enter_context(psycopg.connect(admin_dsn, autocommit=True))
        check = admin.execute(
            "SELECT rolsuper, pg_try_advisory_lock(%s) FROM pg_roles WHERE rolname = current_user",
            (SETUP_LOCK,),
        ).fetchone()
        if check is None or not check[0]:
            raise SetupRefused("retail bootstrap requires a superuser")
        if not check[1]:
            raise SetupRefused("another scenario setup is running for this database")
        _provision_retail(admin, args.db_name, retail_passwords)
        with engine(bootstrap.MIGRATOR).connect() as connection:
            if retail_migrate.current(connection) != retail_migrate.head():
                retail_migrate.upgrade(connection)
        with engine(bootstrap.RUNTIME).connect() as connection:
            if retail_migrate.current(connection) != retail_migrate.head():
                raise SetupRefused("retail runtime cannot verify head")
        workspace = _workspace(auth, args.workspace, args.workspace_name)
        output.parent.mkdir(parents=True, exist_ok=True)
        summary = _prepare_corpus(app, workspace, policy, tokenizer, output.parent, caps, scripted)
        _write_dsns(output, smoke_dsns)
    return summary
