"""Container composition behavior without Docker, external sockets or evaluator imports."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from cryptography import x509
import httpx
import psycopg
import pytest

from policyops.settings import REFUSED_LIBPQ_ENV
from policyops_contracts.scalars import CaseScope
from policyops_contracts.seeds import CaseCustomerBinding


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import compose_secrets, compose_smoke


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def runtime() -> Any:
    # Keep the separate evals environment out of application import discovery/type checking.
    return SimpleNamespace(**runpy.run_path(str(ROOT / "infra/compose/runtime.py")))


@pytest.fixture
def tls_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in REFUSED_LIBPQ_ENV:
        monkeypatch.delenv(name, raising=False)
    for name, value in {"HOST": "postgres", "PORT": "5432", "NAME": "policyops", "SSLMODE": "verify-full",
                        "SSLROOTCERT": "/run/secrets/postgres_tls_cert"}.items():
        monkeypatch.setenv("POLICYOPS_DB_" + name, value)


@pytest.mark.parametrize("role,database,autocommit", [
    ("postgres", "postgres", True), ("policyops_app_migrator", None, False),
    ("policyops_auth_runtime", None, False), ("policyops_app_runtime", None, False),
    ("policyops_worker_discovery", None, False), ("retail_migrator", None, False), ("retail_runtime", None, False),
])
def test_connect_passes_explicit_verified_tls(runtime: Any, tls_environment: None, monkeypatch: pytest.MonkeyPatch,
                                            role: str, database: str | None, autocommit: bool) -> None:
    calls = []
    monkeypatch.setitem(runtime.connect.__globals__, "secret", lambda role: "synthetic-password")
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: calls.append(kwargs))
    runtime.connect(role, database, autocommit=autocommit)
    assert calls == [{"host": "postgres", "port": 5432, "dbname": database or "policyops", "user": role,
                     "password": "synthetic-password", "sslmode": "verify-full",
                     "sslrootcert": "/run/secrets/postgres_tls_cert", "gssencmode": "disable",
                     "require_auth": "scram-sha-256", "connect_timeout": 3,
                     "options": "-c timezone=UTC -c statement_timeout=5000 -c lock_timeout=1000 "
                                "-c idle_in_transaction_session_timeout=5000",
                     "application_name": "policyops-compose", "autocommit": autocommit}]


@pytest.mark.parametrize("variable,value", [
    ("POLICYOPS_DB_SSLMODE", None), ("POLICYOPS_DB_SSLMODE", "require"), ("POLICYOPS_DB_SSLMODE", "disable"),
    ("POLICYOPS_DB_SSLMODE", "verify-ca"), ("POLICYOPS_DB_SSLROOTCERT", None),
    ("POLICYOPS_DB_SSLROOTCERT", ""), ("POLICYOPS_DB_SSLROOTCERT", "relative-canary"),
    *[(name, "ambient-canary") for name in REFUSED_LIBPQ_ENV],
])
def test_connect_fails_closed_before_secret_or_socket(runtime: Any, tls_environment: None,
                                                     monkeypatch: pytest.MonkeyPatch,
                                                     variable: str, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv(variable)
    else:
        monkeypatch.setenv(variable, value)
    calls = []
    monkeypatch.setitem(runtime.connect.__globals__, "secret", lambda role: calls.append("secret"))
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: calls.append("socket"))
    with pytest.raises(ValueError) as caught:
        runtime.connect("postgres")
    assert calls == [] and "canary" not in str(caught.value)


def test_demo_fixture_matches_server_owned_binding_contract(runtime: Any) -> None:
    from datetime import UTC, datetime

    from policyops.persistence.records import Membership

    config = runtime.demo()
    binding = CaseCustomerBinding(scope=CaseScope(workspace_id=UUID(config["workspace_id"]),
        case_id=UUID(config["case_id"])), seed_id=config["seed_id"], user_id=config["customer_id"],
        bound_at=datetime.now(UTC))
    assert binding.user_id == "james_johnson_9321"
    for user in config["users"]:
        Membership(id=UUID(config["case_id"]), workspace_id=UUID(config["workspace_id"]),
            principal_id=UUID(user["subject"]), role=user["role"], created_at=binding.bound_at)


def test_readiness_reports_dependency_failure_without_credentials(runtime: Any,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    class Connection:
        def __init__(self, role: str) -> None:
            self.role = role

        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def execute(self, query: str) -> Any:
            return SimpleNamespace(fetchone=lambda: (self.role,))

    globals_ = runtime.readiness.__globals__
    monkeypatch.setitem(globals_, "connect", Connection)
    monkeypatch.setitem(globals_, "get_health", lambda *_: True)
    monkeypatch.setenv("POLICYOPS_RETAIL_ORIGIN", "http://retail:8001")
    assert runtime.readiness() == (200, {"status": "ok", "checks": {
        "auth_database": True, "app_database": True, "retail": True}})
    monkeypatch.setitem(globals_, "get_health", lambda *_: False)
    status, body = runtime.readiness()
    assert status == 503 and body["checks"]["retail"] is False

    def unavailable(_role: str) -> Any:
        raise psycopg.OperationalError("credential-bearing failure text must stay private")

    monkeypatch.setitem(globals_, "connect", unavailable)
    status, body = runtime.readiness()
    assert status == 503 and not any(body["checks"].values())
    assert "credential" not in json.dumps(body)


@pytest.mark.parametrize("status,body", [(200, {"status": "ok"}), (200, []), (200, "bad-json"), (503, {})])
def test_health_client_refuses_malformed_and_failed_responses(runtime: Any, monkeypatch: pytest.MonkeyPatch,
                                                            status: int, body: Any) -> None:
    client_type = httpx.Client

    def response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=b"invalid" if body == "bad-json" else json.dumps(body).encode())

    monkeypatch.setattr(httpx, "Client", lambda **options: client_type(
        **options, transport=httpx.MockTransport(response)))
    assert runtime.get_health("http://retail:8001", "/healthz") is (body == {"status": "ok"})


def test_ready_route_requires_started_lifespan_and_returns_503(runtime: Any) -> None:
    async def application(scope: Any, receive: Any, send: Any) -> None:
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.complete"})

    wrapped = runtime.ReadyApp(application, lambda: (503, {"status": "unavailable", "checks": {"retail": False}}))

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped), base_url="http://127.0.0.1") as client:
            before = await client.get("/api/v1/health/ready")
            assert before.status_code == 503 and before.json()["status"] == "starting"
            wrapped.started = True
            failed = await client.get("/api/v1/health/ready")
            assert failed.status_code == 503 and failed.json()["checks"]["retail"] is False
            assert failed.headers["cache-control"] == "no-store"
            assert (await client.post("/api/v1/health/ready")).status_code == 405
        # Exercise actual forwarded lifecycle messages, including transition back to unready.
        observed: list[tuple[str, bool]] = []

        async def receive() -> dict[str, str]:
            return {"type": "lifespan.startup" if not observed else "lifespan.shutdown"}

        async def send(message: Any) -> None:
            observed.append((message["type"], wrapped.started))

        await wrapped({"type": "lifespan"}, receive, send)
        assert observed == [("lifespan.startup.complete", True), ("lifespan.shutdown.complete", False)]

    asyncio.run(scenario())


def test_worker_finishes_current_pass_and_stops_discovery(runtime: Any, monkeypatch: pytest.MonkeyPatch,
                                                       tmp_path: Path) -> None:
    stop = threading.Event()
    calls = []

    def finish_inflight() -> None:
        calls.append("inflight_finished")
        stop.set()  # same event the service's SIGTERM handler sets

    monkeypatch.setitem(runtime.worker_loop.__globals__, "HEARTBEAT", tmp_path / "heartbeat")
    runtime.worker_loop(stop, (finish_inflight, lambda: calls.append("unexpected_dispatch")), idle=0)
    assert calls == ["inflight_finished"] and (tmp_path / "heartbeat").is_file()


def test_engine_cleanup_preserves_setup_error(runtime: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    releases = []

    def dispose() -> None:
        releases.append(True)
        raise OSError("release failed")

    monkeypatch.setitem(runtime.own_engine.__wrapped__.__globals__, "engine",
                        lambda _: SimpleNamespace(dispose=dispose))
    with pytest.raises(ValueError, match="primary") as caught, runtime.own_engine("unused"):
        raise ValueError("primary")
    assert releases == [True] and "OSError" in caught.value.__notes__[0]


def test_secrets_generation_is_fresh_and_never_overwrites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Validate generated cryptographic material. Windows ACL enforcement is separately checked below;
    # the sandbox cannot establish host-wide permissions on behalf of an operator.
    monkeypatch.setattr(compose_secrets, "private_directory", lambda path: path.mkdir(mode=0o700))
    target = tmp_path / "secrets"
    names = compose_secrets.generate(target, "test-run")
    try:
        values = [(target / name).read_bytes() for name in compose_secrets.NAMES]
        assert len(set(values)) == len(values) and all(len(value) >= 48 for value in values)
        certificate = x509.load_pem_x509_certificate((target / "postgres_tls_cert").read_bytes())
        assert certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName) == ["postgres"]
        before = {name: (target / name).read_bytes() for name in names}
        with pytest.raises(FileExistsError):
            compose_secrets.generate(target, "another-run")
        assert before == {name: (target / name).read_bytes() for name in names}
        assert json.loads((target / "owner.json").read_bytes())["run_id"] == "test-run"
    finally:
        for name in names:
            (target / name).chmod(0o600)


def test_secret_paths_must_be_external_and_task_owned(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        compose_secrets.external_directory(str(ROOT / "secrets"), str(tmp_path))
    with pytest.raises(ValueError):
        compose_secrets.external_directory(str(tmp_path), str(tmp_path))
    assert compose_secrets.external_directory(str(tmp_path / "secret-run"), str(tmp_path)) == tmp_path / "secret-run"


def test_windows_acl_failure_is_fatal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name != "nt":
        pytest.skip("Windows ACL path")
    calls = []

    def denied(argv: list[str], **kwargs: Any) -> Any:
        calls.append(argv)
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(subprocess, "run", denied)
    with pytest.raises(OSError, match="ACL"):
        compose_secrets.private_directory(tmp_path / "denied")
    assert calls[0][0] == "icacls" and "/inheritance:r" in calls[0] and "/grant:r" in calls[0]


def test_smoke_cleanup_refuses_foreign_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver = compose_smoke.Driver(tmp_path, 8080)
    monkeypatch.setattr(driver, "containers", lambda: [{"Config": {"Labels": {"policyops.owner": "foreign"}}}])
    calls = []
    monkeypatch.setattr(driver, "compose", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(compose_smoke.SmokeError, match="foreign"):
        driver.cleanup()
    assert calls == []


def test_smoke_always_attempts_cleanup_after_startup_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICYOPS_TEMP_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["compose_smoke.py"])
    calls = []

    def failed(_self: Any) -> None:
        raise subprocess.TimeoutExpired(["docker", "compose", "up"], 1)

    monkeypatch.setattr(compose_smoke.Driver, "run", failed)
    monkeypatch.setattr(compose_smoke.Driver, "cleanup", lambda _self: calls.append("cleanup"))
    assert compose_smoke.main() == 1 and calls == ["cleanup"]
    reports = list((tmp_path / "compose").glob("*/report.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_bytes())
    assert report["passed"] is False and report["failure"]["type"] == "TimeoutExpired"


@pytest.mark.parametrize("name,expected", [
    ("nativeness_authoring_catalog.json", "RTXtzbE8g99e3C_Fy8wfFQLf9jZKPJVJN84VikuElVo"),
    ("production_judges.json", "6qEw5ztN1nVyrvo5mPvZquuBr0Ofrv6eqMZK-oGMoO0"),
])
def test_retail_accepts_only_reviewed_judge_configuration(
    name: str, expected: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = runpy.run_path(str(ROOT / "infra/compose/package_retail.py"))
    path = "tau2/judges/" + name
    assert package["JUDGE_CONFIG_SHA256"][path] == expected
    assert len(package["JUDGE_CONFIG_SHA256"]) == 2
    data = b'{"judge": "offline test configuration"}\n'
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    # Exercise the same byte/RECORD/pin comparisons with a tiny synthetic wheel.
    monkeypatch.setitem(package["JUDGE_CONFIG_SHA256"], path, digest)
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_bytes(data)
    info = tmp_path / "tau2-2.0.0.dist-info"
    info.mkdir()
    record = info / "RECORD"
    record.write_text(f"{path},sha256={digest},{len(data)}\ntau2/judges/code.py,,\n", encoding="utf-8")
    package["audit_payloads"](metadata.Distribution.at(info))
    target.write_bytes(b"changed bytes")
    with pytest.raises(RuntimeError, match="hash mismatch"):
        package["audit_payloads"](metadata.Distribution.at(info))
    # Updating RECORD along with bytes still cannot expand the reviewed pin.
    changed = base64.urlsafe_b64encode(hashlib.sha256(target.read_bytes()).digest()).decode().rstrip("=")
    record.write_text(f"{path},sha256={changed},13\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="hash mismatch"):
        package["audit_payloads"](metadata.Distribution.at(info))
    target.write_bytes(data)
    for declaration in ("", "md5=" + digest, "sha256=unreviewed"):
        record.write_text(f"{path},{declaration},{len(data)}\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="hash mismatch"):
            package["audit_payloads"](metadata.Distribution.at(info))


@pytest.mark.parametrize("path", ["tau2/tasks.json", "tau2/judges/other.json", "tau2/tasks.jsonl",
                                 "tau2/config.yaml", "tau2/config.yml", "tau2/data/hidden.txt"])
def test_retail_refuses_other_payloads(path: str, tmp_path: Path) -> None:
    package = runpy.run_path(str(ROOT / "infra/compose/package_retail.py"))
    info = tmp_path / "tau2-2.0.0.dist-info"
    info.mkdir()
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_bytes(b"unreviewed payload")
    (info / "RECORD").write_text(f"{path},,\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unexpected task/data"):
        package["audit_payloads"](metadata.Distribution.at(info))


def test_retail_refuses_missing_inventory(tmp_path: Path) -> None:
    package = runpy.run_path(str(ROOT / "infra/compose/package_retail.py"))
    with pytest.raises(RuntimeError, match="inventory missing"):
        package["audit_payloads"](metadata.Distribution.at(tmp_path))


@pytest.mark.parametrize("failure", ["exit", "timeout", "oserror"])
def test_smoke_failure_receipts_are_bounded_and_redacted(
    failure: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = compose_smoke.Driver(tmp_path, 8080)
    driver.secrets.mkdir()
    value = "generated-secret-value-1234567890"
    (driver.secrets / "postgres").write_text(value + "\n", encoding="utf-8")
    output = ("discarded-prefix\n" + "x" * 20000 + "\n" + "diagnostic context\n" * 80
              + value + "\npostgresql://" + "user:unknown-password@db/app\n"
              + "host=db user=other password='other password' dbname=app\n"
              + "-----BEGIN " + "PRIVATE KEY-----\nprivate-key-canary\n-----END PRIVATE KEY-----\n")

    def failed(*args: Any, **kwargs: Any) -> Any:
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], 1, output=output.encode(), stderr=b"timeout diagnostic")
        if failure == "oserror":
            raise OSError(output)
        return subprocess.CompletedProcess(args[0], 7, stdout=output, stderr="exit diagnostic")

    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises((compose_smoke.SmokeError, subprocess.TimeoutExpired, OSError)):
        driver.command("failing-tool", value)
    driver.save()
    report = json.loads((driver.root / "report.json").read_bytes())
    receipt = report["commands"][0]
    tail = receipt["output_tail"]
    assert len(tail) <= 16000 and len(tail.splitlines()) <= 60
    assert "diagnostic context" in tail and "discarded-prefix" not in tail
    assert "[REDACTED" in tail
    for secret in (value, "unknown-password", "other password", "private-key-canary"):
        assert secret not in json.dumps(report)
    assert receipt["exit_code"] == (7 if failure == "exit" else None)
    if failure != "exit":
        assert receipt["error_type"] in {"TimeoutExpired", "OSError"}


def test_smoke_failure_tail_limits_single_long_line(tmp_path: Path) -> None:
    driver = compose_smoke.Driver(tmp_path, 8080)
    assert driver.failure_tail("x" * 20000) == "x" * 16000


def test_smoke_redacts_partial_generation_and_retains_values_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = compose_smoke.Driver(tmp_path, 8080)
    value = "partial-generation-secret:/with-symbols"

    def failed(*args: Any, **kwargs: Any) -> Any:
        driver.secrets.mkdir()
        (driver.secrets / "postgres").write_text(value + "\n", encoding="utf-8")
        return subprocess.CompletedProcess(args[0], 1, stdout=value, stderr=urllib_encoded)

    from urllib.parse import quote

    urllib_encoded = quote(value, safe="")
    monkeypatch.setattr(subprocess, "run", failed)
    with pytest.raises(compose_smoke.SmokeError):
        driver.command("secret-generator")
    receipt = driver.report["commands"][0]
    assert value not in receipt["output_tail"] and urllib_encoded not in receipt["output_tail"]
    (driver.secrets / "postgres").unlink()
    driver.secrets.rmdir()
    assert driver.failure_tail(value, urllib_encoded) == "[REDACTED]\n[REDACTED]"


@pytest.mark.parametrize("dns,tcp", [(False, False), (True, False), (False, True)])
def test_internal_egress_probe_refuses_dns_or_tcp_success(
    dns: bool, tcp: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Import the in-container verifier without its sibling runtime import.
    import socket

    monkeypatch.syspath_prepend(str(ROOT / "infra/compose"))
    verifier = runpy.run_path(str(ROOT / "infra/compose/verify.py"))

    def resolve(*args: Any, **kwargs: Any) -> Any:
        if dns:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]
        raise socket.gaierror("blocked")

    def connect(*args: Any, **kwargs: Any) -> Any:
        if tcp:
            from contextlib import nullcontext

            return nullcontext()
        raise OSError("blocked")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "create_connection", connect)
    if dns or tcp:
        with pytest.raises(RuntimeError, match="internal-only service"):
            verifier["no_egress"]()
    else:
        assert verifier["no_egress"]() == {"external_dns_denied": True, "external_tcp_denied": True}
