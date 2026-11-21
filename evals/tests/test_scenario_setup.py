"""Offline operator setup checks and a scripted PostgreSQL round trip."""

from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
from uuid import uuid4

from psycopg.conninfo import conninfo_to_dict
import pytest

from policyops.persistence.database import make_engine
from policyops.persistence.roles import APP_MIGRATOR
from policyops.providers.tokenizer import load
from policyops.retrieval.ingest import Outcome, PaidCaps
from policyops_contracts.conversation import PolicyContext
from policyops_contracts.digest import text_sha256
from policyops_contracts.policy import RETAIL_POLICY
from policyops_evals.cli import REPOSITORY_ROOT, main, parser
from policyops_evals.retail_sim import bootstrap, fixture, migrate
from policyops_evals.scenarios import setup
from policyops_testing.app_database import AppCluster
from policyops_testing.postgres import OwnedPostgres
from policyops_testing.retrieval_fixtures import Embeddings
from policyops_testing.safety.retail import reviewed_tree


PAID_ARGS = ["--allow-paid", "--max-usd", "0.01", "--max-calls", "2", "--max-input-tokens", "8192",
             "--max-seconds", "120"]


def argv(root: Path, *, database: str = "scenario_test", port: int = 5432) -> list[str]:
    result = ["scenarios", "setup", "--db-host", "127.0.0.1", "--db-port", str(port), "--db-name", database,
              "--fixture-root", str(root / "fixture"), "--policy-file", str(root / "policy.md"),
              "--dsn-file", str(root / "smoke-dsns.json"), "--workspace-name", "Dedicated scenario"]
    for label in ("superuser", *setup.PASSWORD_ROLES):
        result.extend(("--" + label.replace("_", "-") + "-password-file", str(root / (label + ".txt"))))
    return result


def set_arg(command: list[str], option: str, value: str) -> None:
    command[command.index(option) + 1] = value


@pytest.mark.parametrize(("option", "value", "message"), [
    ("--db-port", "0", "database port"),
    ("--db-host", "host,another", "single database hostname"),
    ("--db-host", "fe80::1%zone,another", "single database hostname"),
    ("--db-name", "host=other", "invalid database"),
    ("--workspace-name", "  ", "workspace name"),
    ("--dsn-file", str(REPOSITORY_ROOT / "smoke-dsns.json"), "inside the repository"),
])
def test_invalid_target(tmp_path: Path, option: str, value: str, message: str) -> None:
    command = argv(tmp_path)
    set_arg(command, option, value)
    with pytest.raises(setup.SetupRefused, match=message):
        setup._validate_target(parser().parse_args(command))


def test_accepts_explicit_workspace_uuid_and_requires_file_paths(tmp_path: Path) -> None:
    workspace = uuid4()
    command = replace_workspace(argv(tmp_path), str(workspace))
    args = parser().parse_args(command)
    assert args.workspace == workspace
    assert setup._validate_target(args) == tmp_path / "smoke-dsns.json"
    with pytest.raises(SystemExit):
        parser().parse_args(command[:-2])
    with pytest.raises(SystemExit):
        parser().parse_args([*command, "--workspace-name", "Other"])


@pytest.mark.parametrize(("option", "value"), [
    ("--max-usd", "0.0101"), ("--max-usd", "NaN"), ("--max-usd", "wrong"),
    ("--max-calls", "0"), ("--max-input-tokens", "-1"), ("--max-seconds", "0"),
])
def test_caps_validation(tmp_path: Path, option: str, value: str) -> None:
    command = argv(tmp_path) + PAID_ARGS
    set_arg(command, option, value)
    with pytest.raises(setup.SetupRefused, match="cap"):
        setup._caps(parser().parse_args(command))


def test_caps_all_or_none(tmp_path: Path) -> None:
    command = argv(tmp_path)
    assert setup._caps(parser().parse_args(command)) is None
    for incomplete in (PAID_ARGS[:-2], PAID_ARGS[1:]):
        with pytest.raises(setup.SetupRefused, match="supplied together"):
            setup._caps(parser().parse_args(command + incomplete))


def test_refuses_dsns_larger_than_smoke_can_read(tmp_path: Path) -> None:
    args = parser().parse_args(argv(tmp_path))
    dsns = {role: setup._dsn(args, role, "\\" * 4096) for role in setup.SMOKE_ROLES.values()}
    with pytest.raises(setup.SetupRefused, match="output size bound"):
        setup._smoke_dsns(dsns)


@pytest.mark.parametrize(("field", "value", "failed"), [
    ("worst_usd", "0.011", "usd"),
    ("batches", 3, "calls"),
    ("frozen_total_local_tokens", 8193, "tokens"),
    ("worst_seconds", 121, "seconds"),
])
def test_preflight_reports_before_refusal(capsys: pytest.CaptureFixture[str], field: str, value: str | int,
                                          failed: str) -> None:
    caps = PaidCaps(setup.MODEL, setup.DIMENSIONS, setup.MAX_USD, 2, 8192, 120)
    estimate = {"batches": 2, "local_tokens": 400, "worst_usd": "0.0004", "worst_seconds": 80,
                "frozen_total_local_tokens": 800} | {field: value}
    plan = Outcome("planned", details={"estimate": estimate})
    with pytest.raises(setup.SetupRefused, match="preflight exceeds caps"):
        setup._preflight(plan, caps)
    output = capsys.readouterr()
    assert not output.out
    preflight = json.loads(output.err)["embedding_preflight"]
    assert preflight["estimate"] == estimate
    assert preflight["within_caps"] == {key: key != failed for key in ("usd", "calls", "tokens", "seconds")}


def test_no_paid_opt_in_and_live_embeddings_disabled(capsys: pytest.CaptureFixture[str]) -> None:
    plan = Outcome("planned", details={"estimate": {"batches": 1, "frozen_total_local_tokens": 400}})
    with pytest.raises(setup.SetupRefused, match="requires --allow-paid"):
        setup._preflight(plan, None)
    assert json.loads(capsys.readouterr().err)["embedding_preflight"]["caps"] is None
    with pytest.raises(setup.SetupRefused, match="disabled in tests"):
        setup._live_providers()


def test_active_policy_reuse_bypasses_ingest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    workspace, generation = uuid4(), uuid4()
    body = "Synthetic policy for the reuse decision."
    policy = PolicyContext(domain="retail", source="fictional", text=body, sha256=text_sha256(body))
    monkeypatch.setattr(setup, "active_policy_generation", lambda *args: generation)
    monkeypatch.setattr(setup, "ingest", lambda *args, **kwargs: pytest.fail("unexpected ingest"))
    monkeypatch.setattr(setup, "_live_providers", lambda: pytest.fail("unexpected provider"))
    engine = make_engine(lambda: pytest.fail("unexpected database connection"))
    try:
        summary = setup._prepare_corpus(engine, workspace, policy, load(), tmp_path, None, None)
    finally:
        engine.dispose()
    assert summary == setup.SetupSummary(workspace, generation, policy.sha256, "reused")


@pytest.mark.postgres
def test_setup_provisions_and_reuses(postgres: OwnedPostgres, tmp_path: Path,
                                    capsys: pytest.CaptureFixture[str]) -> None:
    database = AppCluster.provision(postgres).create_database("scenario_setup")
    try:
        database.upgrade()
        explicit = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
        source = Path(explicit) if explicit else reviewed_tree()
        fixture.stage(source, tmp_path / "fixture")
        (tmp_path / "policy.md").write_bytes((source / RETAIL_POLICY.path).read_bytes())
        for role in bootstrap.ROLES:
            if role not in postgres.passwords:
                postgres.register_role(role)
        for label, role in {"superuser": "postgres", **setup.PASSWORD_ROLES}.items():
            (tmp_path / (label + ".txt")).write_text(postgres.passwords[role] + "\n", encoding="utf-8")
        command = argv(tmp_path, database=database.name, port=postgres.port)
        paid = parser().parse_args(command + PAID_ARGS)
        transport = Embeddings()
        output = tmp_path / "smoke-dsns.json"
        with pytest.raises(setup.SetupRefused, match="preflight exceeds caps"):
            setup.run_setup(parser().parse_args([*command, *PAID_ARGS, "--max-input-tokens", "1"]),
                            scripted=transport.handle_async_request)
        assert json.loads(capsys.readouterr().err)["embedding_preflight"]["within_caps"]["tokens"] is False
        assert not transport.requests and not output.exists()
        created = setup.run_setup(paid, scripted=transport.handle_async_request)
        assert created.status == "created" and created.content_digest == RETAIL_POLICY.sha256
        assert 0 < created.usd_spent <= setup.MAX_USD
        requests = len(transport.requests)
        assert 0 < requests <= paid.max_calls
        assert json.loads(capsys.readouterr().err)["embedding_preflight"]["within_caps"] == {
            "usd": True, "calls": True, "tokens": True, "seconds": True}
        original = output.read_bytes()
        output_digest = sha256(original).digest()
        dsns = json.loads(original)
        assert {label: conninfo_to_dict(dsn)["user"] for label, dsn in dsns.items()} == setup.SMOKE_ROLES
        assert set(setup.SMOKE_ROLES.values()).isdisjoint({APP_MIGRATOR, bootstrap.MIGRATOR})
        with database.engine(bootstrap.RUNTIME).connect() as connection:
            assert migrate.current(connection) == migrate.head()
        assert main(command) == 0  # A normal CLI rerun requires neither a provider nor paid flags.
        captured = capsys.readouterr()
        assert not captured.err
        assert json.loads(captured.out) == {
            "workspace_id": str(created.workspace_id), "corpus_generation_id": str(created.corpus_generation_id),
            "content_digest": created.content_digest, "status": "reused", "usd_spent": "0",
        }
        uuid_args = replace_workspace(command, str(created.workspace_id))
        assert setup.run_setup(parser().parse_args(uuid_args)) == replace(
            created, status="reused", usd_spent=Decimal(0))
        assert len(transport.requests) == requests and sha256(output.read_bytes()).digest() == output_digest

        with database.superuser() as admin:
            admin.execute("ALTER ROLE retail_runtime NOINHERIT")
            try:
                with pytest.raises(setup.SetupRefused, match="retail role configuration differs"):
                    setup.run_setup(parser().parse_args(command))
                assert not admin.execute(
                    "SELECT rolinherit FROM pg_roles WHERE rolname = 'retail_runtime'").fetchone()[0]
            finally:
                admin.execute("ALTER ROLE retail_runtime INHERIT")
        (tmp_path / "retail.txt").write_text(secrets.token_urlsafe(24), encoding="utf-8")
        with pytest.raises(setup.SetupRefused, match="retail role configuration differs"):
            setup.run_setup(parser().parse_args(command))
        assert sha256(output.read_bytes()).digest() == output_digest
    finally:
        database.dispose()


def replace_workspace(command: list[str], workspace: str) -> list[str]:
    changed = command.copy()
    index = changed.index("--workspace-name")
    changed[index:index + 2] = ["--workspace", workspace]
    return changed
