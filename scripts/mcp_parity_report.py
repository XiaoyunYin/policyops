"""Test-only PostgreSQL replay through the real MCP SDK stdio client; JSON output stays outside the checkout."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime, timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import secrets
import shutil
import sys
import time
from typing import Any, Literal
from uuid import UUID, uuid4


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests/support"))

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import SecretStr

from policyops.auth.oidc import OidcClient
from policyops.auth.service import AuthService
from policyops.domain.roles import Action, Role
from policyops.mcp.config import Configuration
from policyops.mcp.contracts import TOOLS, PolicyObservation, Result
from policyops.mcp.service import ReadService
from policyops.persistence import identity
from policyops.persistence.database import transaction
from policyops.persistence.roles import AUTH_RUNTIME
from policyops.retrieval.ingest import Request, ingest
from policyops.settings import AuthSettings
from policyops_contracts.clock import SystemClock
from policyops_contracts.gateway import ToolError
from policyops_testing import network
from policyops_testing.app_database import AppCluster
from policyops_testing.corpus_fixtures import FixtureCorpus, write
from policyops_testing.gateway_cases import CASES
from policyops_testing.postgres import OwnedPostgres, owned_postgres
from policyops_testing.retrieval_fixtures import CAPS, TOKENIZER, Embeddings, documents
from policyops_testing.safety import matrix
from policyops_testing.safety.config import load_e05_config
from policyops_testing.safety.environment import Env, make_env, study_case
from policyops_testing.safety.retail import Service


REPO = Path(__file__).resolve().parents[1]
KEY = "mcp-policy"
Row = dict[str, Any]


def expected_ids(suites: tuple[str, ...] = ("matrix", "e05", "identity")) -> set[str]:
    ids: set[str] = set()
    if "matrix" in suites:
        ids.update(f"action/view_case/{actor}/{relation}" for actor in matrix.ACTORS for relation in matrix.RELATIONS)
        ids.update(f"rule/{case.case_id}/{index}" for case in CASES if case.tool in TOOLS
                   for index in range(len(case.steps)))
    if "e05" in suites:
        ids.update(f"e05/{f.fixture_id}/{kind}" for f in load_e05_config().fixtures
                   for kind in ("read_projection", "excluded_write"))
    if "identity" in suites:
        ids.update(("identity/active", "identity/revoked", "identity/expired"))
    return ids


def settings() -> AuthSettings:
    return AuthSettings(env="test", public_origin="http://127.0.0.1:8000",
                        oidc_issuer="https://issuer.example.invalid", oidc_client_id="mcp-parity",
                        oidc_client_secret=SecretStr("synthetic-mcp-client-secret"))


def credential(env: Env, principal: UUID | None = None, *, selected: UUID | None = None,
               expected: UUID | None = None, role: Role = Role.REVIEWER) -> tuple[Configuration, SecretStr]:
    now, cookie = datetime.now(UTC), uuid4().hex + uuid4().hex
    principal = principal or env.reviewer
    with transaction(env.db.engine(AUTH_RUNTIME)) as connection:
        identity.create_session(connection, session_id=uuid4(), principal_id=principal,
            workspace_id=selected or env.run.workspace_id, cookie_sha256=hashlib.sha256(cookie.encode()).hexdigest(),
            csrf_sha256="0" * 64, now=now, expires_at=now + timedelta(minutes=30), rotated_from=None)
    return Configuration(principal_id=principal, workspace_id=expected or env.run.workspace_id,
        run_id=env.run.run_id, role=role, binding=env.scope.binding, corpus_key=KEY,
        issued_at=now, expires_at=now + timedelta(minutes=30), timeout_seconds=15), SecretStr(cookie)


# Credential variable names are kept apart from their run-time values: the OIDC client secret is generated per
# run (the read server never contacts the issuer) and the database passwords come from the owned test cluster.
CREDENTIAL_VARIABLES = ("POLICYOPS_OIDC_CLIENT_SECRET", "POLICYOPS_DB_AUTH_PASSWORD", "POLICYOPS_DB_APP_PASSWORD")


def child_environment(env: Env, config: Configuration, cookie: SecretStr) -> dict[str, str]:
    server = env.db.server
    # No paid credentials are inherited by the MCP read server.
    kept = {k: v for k, v in os.environ.items() if not k.upper().startswith(("OPENAI_", "ANTHROPIC_", "PG"))}
    credentials = dict(zip(CREDENTIAL_VARIABLES, (secrets.token_urlsafe(24), server.passwords[AUTH_RUNTIME],
                                                  server.passwords["policyops_app_runtime"]), strict=True))
    return kept | credentials | {"PYTHONUTF8": "1", "POLICYOPS_MCP_CONFIG": config.model_dump_json(),
        "POLICYOPS_MCP_SESSION": cookie.get_secret_value(), "POLICYOPS_MCP_RETAIL_ORIGIN": env.origin,
        "POLICYOPS_MCP_RETAIL_KEY_HEX": env.service.key.hex(), "POLICYOPS_ENV": "test",
        "POLICYOPS_PUBLIC_ORIGIN": "http://127.0.0.1:8000", "POLICYOPS_OIDC_ISSUER": "https://issuer.example.invalid",
        "POLICYOPS_OIDC_CLIENT_ID": "mcp-parity",
        "POLICYOPS_DB_HOST": "127.0.0.1", "POLICYOPS_DB_PORT": str(server.port), "POLICYOPS_DB_NAME": env.db.name,
        "POLICYOPS_DB_SSLMODE": "disable"}


def fingerprint(result: Result) -> str:
    return hashlib.sha256(result.model_dump_json().encode()).hexdigest()


def classification(result: Result) -> tuple[bool, str | None]:
    return (False, str(result.result.code)) if isinstance(result.result, ToolError) else (True, None)


async def compare(env: Env, config: Configuration, cookie: SecretStr,
                  cases: Sequence[tuple[str, str, dict[str, Any], bool | None]], rows: list[Row],
                  *, revoke_after_first: bool = False,
                  expected_texts: dict[str, tuple[str, ...]] | None = None) -> None:
    oidc = OidcClient(settings(), SystemClock())
    try:
        auth = AuthService(settings(), oidc, env.db.engine(AUTH_RUNTIME), SystemClock())
        params = StdioServerParameters(command=sys.executable, args=["-B", "-m", "policyops.mcp"],
                                       env=child_environment(env, config, cookie), cwd=REPO)
        # Reuse direct clients too: warm samples must not charge HTTP client construction to one arm only.
        with closing(env.client()) as retail:
            direct_service = ReadService(config, cookie, auth, env.app, retail, SystemClock())
            await compare_session(params, direct_service, env, config, cases, rows,
                                  revoke_after_first=revoke_after_first, expected_texts=expected_texts)
    finally:
        oidc.close()


async def compare_session(params: StdioServerParameters, direct_service: ReadService, env: Env,
                          config: Configuration, cases: Sequence[tuple[str, str, dict[str, Any], bool | None]],
                          rows: list[Row], *, revoke_after_first: bool,
                          expected_texts: dict[str, tuple[str, ...]] | None) -> None:
    async with (stdio_client(params) as (read, stream),
                ClientSession(read, stream, read_timeout_seconds=25) as session):
        await session.initialize()
        if {tool.name for tool in (await session.list_tools()).tools} != set(TOOLS):
            raise AssertionError("fixed MCP tool list differs")
        for index, (case_id, name, args, oracle) in enumerate(cases):
            if index and revoke_after_first:
                with env.db.superuser() as connection:
                    connection.execute("UPDATE identity.memberships SET revoked_at = clock_timestamp() "
                                       "WHERE workspace_id = %s AND principal_id = %s",
                                       (env.run.workspace_id, config.principal_id))
            start = time.perf_counter()
            direct = direct_service.call(name, args)
            direct_ms = (time.perf_counter() - start) * 1000
            start = time.perf_counter()
            framed = await session.call_tool(name, args)
            mcp_ms = (time.perf_counter() - start) * 1000
            if not isinstance(framed, types.CallToolResult):
                raise AssertionError("unexpected MCP framing")
            remote = Result.model_validate_json(json.dumps(framed.structured_content))
            phase = (framed.meta or {}).get("policyops/worker_phase")
            if phase not in ("cold", "warm", "facade"):
                raise AssertionError("missing worker latency classification")
            expected_text = (expected_texts or {}).get(case_id, ())
            preserved = True
            if isinstance(remote.result, PolicyObservation):
                body = "\n".join(c.text for c in remote.result.citations)
                preserved = all(text in body for text in expected_text)
            elif expected_text:
                preserved = False
            allowed, code = classification(direct)
            remote_allowed, remote_code = classification(remote)
            rows.append({"case_id": case_id, "tool": name, "direct_allowed": allowed,
                "mcp_allowed": remote_allowed, "direct_code": code, "mcp_code": remote_code,
                "oracle_allowed": oracle, "decision_parity": allowed == remote_allowed,
                "code_parity": code == remote_code, "payload_parity": direct == remote,
                "direct_sha256": fingerprint(direct), "mcp_sha256": fingerprint(remote),
                "direct_ms": direct_ms, "mcp_ms": mcp_ms, "overhead_ms": mcp_ms - direct_ms,
                "worker_phase": phase,
                "framing_valid": framed.is_error == (not remote_allowed) and not framed.content,
                "untrusted_text_preserved": preserved,
                "citation_count": (len(remote.result.citations)
                                   if isinstance(remote.result, PolicyObservation) else 0)})


def publish(env: Env, root: Path) -> None:
    entries = [(f"fixture{index:03}", f"fixture{index:03} policy", f"fixture{index:03}\n" +
                fixture.customer_text + "\n" + fixture.tool_text)
               for index, fixture in enumerate(load_e05_config().fixtures)]
    raw, digest = write(root, [FixtureCorpus(KEY, "banking_knowledge", "tau2-banking/v1", documents(entries))])
    fake = Embeddings()
    result = ingest(Request(env.run.workspace_id, KEY, raw, digest, root, "execute", CAPS), engine=env.app,
                    tokenizer=TOKENIZER, providers=fake.providers(), env="test")
    if result.outcome != "activated":
        raise AssertionError("synthetic policy publication failed")


def run_replay(base: Env, root: Path, suites: tuple[str, ...] = ("matrix", "e05", "identity"),
               *, rows: list[Row] | None = None, worker_mode: Literal["cold", "warm"] = "warm") -> list[Row]:
    # Ingest uses synchronous job helpers. Finish publication before asyncio.run, unchanged ingest semantics.
    e05_env = study_case(base) if "e05" in suites else None
    if e05_env is not None:
        publish(e05_env, root / "policy")
    return asyncio.run(replay(base, suites, rows=rows, e05_env=e05_env, worker_mode=worker_mode))


async def replay(base: Env, suites: tuple[str, ...] = ("matrix", "e05", "identity"),
                 *, rows: list[Row] | None = None, e05_env: Env | None = None,
                 worker_mode: Literal["cold", "warm"] = "warm") -> list[Row]:
    rows = [] if rows is None else rows
    def credentials(env: Env, principal: UUID | None = None, *, role: Role = Role.REVIEWER
                    ) -> tuple[Configuration, SecretStr]:
        config, cookie = credential(env, principal, role=role)
        return config.model_copy(update={"worker_mode": worker_mode}), cookie
    if "matrix" in suites:
        # Exactly the T30 VIEW_CASE actor/relation cells. Other actions expose capabilities outside this facade.
        for actor in matrix.ACTORS:
            owner = study_case(base)
            principal = matrix.principal(owner, actor)
            for relation in matrix.RELATIONS:
                target = study_case(owner) if relation == "other_case_same_workspace" else owner
                if relation == "foreign_workspace":
                    target = make_env((base.service, base.origin), base.db)
                roles = matrix.roles_for(actor)
                config, cookie = credentials(target, principal, role=Role(sorted(roles)[0]) if roles else Role.ANALYST)
                if relation == "foreign_workspace":
                    # The session belongs to the original workspace; it cannot select the foreign case.
                    with transaction(base.db.engine(AUTH_RUNTIME)) as connection:
                        record = identity.load_session(connection, hashlib.sha256(cookie.get_secret_value().encode())
                                                       .hexdigest())
                        if record is None:
                            raise AssertionError("missing session")
                        connection.exec_driver_sql("UPDATE identity.sessions SET workspace_id = %s WHERE id = %s",
                                                   (owner.run.workspace_id, record.id))
                if relation in ("missing_workspace", "mismatched_workspace"):
                    with base.db.superuser() as connection:
                        connection.execute("UPDATE identity.sessions SET workspace_id = %s WHERE cookie_sha256 = %s",
                            (None if relation == "missing_workspace" else owner.run.workspace_id,
                             hashlib.sha256(cookie.get_secret_value().encode()).hexdigest()))
                    if relation == "mismatched_workspace":
                        workspace = uuid4()
                        config = config.model_copy(update={"workspace_id": workspace, "binding":
                            config.binding.model_copy(update={"scope": config.binding.scope.model_copy(
                                update={"workspace_id": workspace})})})
                oracle = matrix.allowed(Action.VIEW_CASE, actor) and relation in ("own", "other_case_same_workspace")
                await compare(target, config, cookie, [(f"action/view_case/{actor}/{relation}",
                    "get_order_details", {"order_id": target.order}, oracle)], rows)
        for case in CASES:
            if case.tool not in TOOLS:
                continue
            env = matrix.seed_rule_fixture(study_case(base), case)
            config, cookie = credentials(env)
            requests = []
            for index, raw in enumerate(case.steps):
                mapped = matrix.remap_result(raw, env.customer)
                if len(mapped.tool_calls) != 1 or mapped.tool_calls[0].name not in TOOLS:
                    raise AssertionError("applicable read case has unsupported sequence")
                call = mapped.tool_calls[0]
                requests.append((f"rule/{case.case_id}/{index}", call.name, json.loads(call.arguments_json),
                                 case.expect.kind != "error" if index == len(case.steps) - 1 else None))
            await compare(env, config, cookie, requests, rows)
    if "e05" in suites:
        if e05_env is None:
            raise ValueError("E05 publication must precede the event loop; use run_replay")
        env = e05_env
        config, cookie = credentials(env)
        requests = []
        expected_texts: dict[str, tuple[str, ...]] = {}
        for index, fixture in enumerate(load_e05_config().fixtures):
            # Original E05 candidates are ALL writes: refused at the fixed facade. Replay exact untrusted text
            # in immutable policy bodies as a read projection; do not claim to rerun E05's approval/write races.
            requests.extend([(f"e05/{fixture.fixture_id}/read_projection", "search_policy",
                              {"query": f"fixture{index:03}"}, True),
                             (f"e05/{fixture.fixture_id}/excluded_write", fixture.candidate_name,
                              json.loads(fixture.candidate_arguments_json), False)])
            expected_texts[f"e05/{fixture.fixture_id}/read_projection"] = (fixture.customer_text, fixture.tool_text)
        await compare(env, config, cookie, requests, rows, expected_texts=expected_texts)
        if any(row["case_id"].endswith("read_projection") and row["citation_count"] == 0 for row in rows):
            raise AssertionError("E05 untrusted policy text was not delivered")
    if "identity" in suites:
        env = study_case(base)
        config, cookie = credentials(env)
        args = {"order_id": env.order}
        await compare(env, config, cookie, [("identity/active", "get_order_details", args, True),
                                           ("identity/revoked", "get_order_details", args, False)], rows,
                      revoke_after_first=True)
        expired = config.model_copy(update={"issued_at": datetime.now(UTC) - timedelta(minutes=5),
                                             "expires_at": datetime.now(UTC) - timedelta(minutes=1)})
        await compare(env, expired, cookie, [("identity/expired", "get_order_details", args, False)], rows)
    return rows


def summary(rows: list[Row]) -> dict[str, Any]:
    overhead = sorted(float(row["overhead_ms"]) for row in rows)
    def percentile(q: float) -> float | None:
        return overhead[max(0, math.ceil(len(overhead) * q) - 1)] if overhead else None
    return {"calls": len(rows), "parity": sum(row["decision_parity"] and row["code_parity"] and
        row["payload_parity"] and row["framing_valid"] for row in rows),
        "unauthorized_disclosures": sum(row["mcp_allowed"] and (not row["direct_allowed"] or
                                        row["oracle_allowed"] is False) for row in rows),
        "false_denials_vs_direct": sum(row["direct_allowed"] and not row["mcp_allowed"] for row in rows),
        "oracle_failures": sum(row["oracle_allowed"] is not None and
                               row["direct_allowed"] != row["oracle_allowed"] for row in rows),
        "text_preservation_failures": sum(not row["untrusted_text_preserved"] for row in rows),
        "overhead_ms": {"p50": percentile(.5), "p95": percentile(.95), "max": max(overhead) if overhead else None},
        "latency_by_worker_phase": {phase: latency([row for row in rows if row.get("worker_phase") == phase])
                                    for phase in ("cold", "warm", "facade")}}


def latency(rows: list[Row]) -> dict[str, Any]:
    stats: dict[str, Any] = {"calls": len(rows)}
    for metric in ("direct_ms", "mcp_ms", "overhead_ms"):
        values = sorted(float(row[metric]) for row in rows)
        stats[metric] = {"p50": values[math.ceil(len(values) * .5) - 1] if values else None,
                         "p95": values[math.ceil(len(values) * .95) - 1] if values else None,
                         "max": max(values) if values else None}
    return stats


def output_path(raw: str) -> Path:
    root = Path(os.environ["POLICYOPS_TEMP_DIR"]).resolve()
    target = Path(raw).resolve()
    if root not in target.parents or target == REPO or REPO in target.parents:
        raise ValueError("output must be beneath POLICYOPS_TEMP_DIR outside the checkout")
    if any(part.casefold() == "reviewer" for part in target.parts) or target.exists():
        raise ValueError("output must be new and outside reviewer directories")
    return target


def cleanup_runtime(runtime: Path, server: OwnedPostgres | None, service: Service | None) -> list[str]:
    """Delete only this fresh run tree after actual process/container release is confirmed."""
    root = Path(os.environ["POLICYOPS_TEMP_DIR"]).resolve()
    target = runtime.resolve()
    if root not in target.parents or REPO in target.parents or target == root:
        return ["runtime containment refused"]
    if server is None or server.container_id or (service is not None and service.process is not None
                                               and service.process.poll() is None):
        return ["runtime retained: resource release unconfirmed"]
    try:
        shutil.rmtree(target)
    except OSError as exc:
        return ["runtime cleanup failed: " + type(exc).__name__]
    return []


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New JSON file under POLICYOPS_TEMP_DIR")
    parser.add_argument("--worker-mode", choices=("cold", "warm"), default="warm")
    args = parser.parse_args(argv)
    target = output_path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    runtime = target.parent / (target.stem + "-runtime-" + uuid4().hex[:8])
    runtime.mkdir()
    rows: list[Row] = []
    failure = None
    was_installed = network.installed()
    network.install()
    database = None
    owned_server = None
    service = None
    try:
        with owned_postgres(runtime / "postgres", "mcp-" + uuid4().hex[:12]) as server:
            owned_server = server
            database = AppCluster.provision(server).create_database("mcp_parity")
            database.upgrade()
            service = Service(server, database, runtime / "retail")
            with service.running() as origin:
                run_replay(make_env((service, origin), database), runtime, rows=rows, worker_mode=args.worker_mode)
    except Exception as exc:
        failure = type(exc).__name__  # never connection locals or exception text
    finally:
        if database is not None:
            database.dispose()
        if not was_installed:
            network.uninstall()
    stats = summary(rows)
    cleanup = cleanup_runtime(runtime, owned_server, service)
    complete = {row["case_id"] for row in rows} == expected_ids() and len(rows) == len(expected_ids())
    passed = complete and not failure and stats["parity"] == stats["calls"] and not any(
        stats[name] for name in ("unauthorized_disclosures", "false_denials_vs_direct", "oracle_failures",
                                 "text_preservation_failures")) and not cleanup
    report = {"schema_version": "policyops.mcp-parity/v2", "sdk": "mcp==2.3.0", "python": platform.python_version(),
        "timestamp": datetime.now(UTC).isoformat(), "rows": rows, "summary": stats, "failure": failure,
        "passed": passed, "complete": complete, "expected_calls": len(expected_ids()),
        "worker_mode": args.worker_mode,
        "latency_method": "nearest-rank paired samples, sequential direct then MCP; cold includes worker spawn "
        "and resource setup; warm reuses worker, engines and clients; facade uses no worker. Direct reuses its "
        "engines/clients; first use includes connection setup. Server/client handshake excluded. "
        "Phase groups include failures; overall overhead is a mixed population, not warm protocol overhead.",
        "limitations": ["Fixture-bound protocol parity, not a general security proof or retrieval quality score.",
            "E05 write candidates are excluded/refused; exact text is replayed as cited read-only policy data.",
            "Approval, consent, mutations, audit/evaluation APIs and write-only T30 cells are outside this facade."],
        "runtime_retained": str(runtime) if cleanup else None, "cleanup_failures": cleanup,
        "source_sha256": {p.relative_to(REPO).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted([*(REPO / "packages/policyops/src/policyops/mcp").glob("*.py"),
                             REPO / "scripts/mcp_parity_report.py", REPO / "uv.lock",
                             REPO / "tests/fixtures/safety/t30-v1.json",
                             REPO / "tests/fixtures/safety/t30-e05-v1.json"])}}
    target.write_bytes((json.dumps(report, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({"passed": passed, "summary": stats, "failure": failure, "report": str(target)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
