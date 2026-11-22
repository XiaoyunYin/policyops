"""Run one offline retail cancellation and verify local Grafana ingestion."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from importlib import import_module
import json
import logging.config
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.parse import urlencode
from uuid import UUID, uuid4

import httpx
import httpx2
from sqlalchemy import text

from policyops import telemetry as ot
from policyops.adapters.retail_client import Unknown
from policyops.api.serve import SERVE_LOG_CONFIG
from policyops.auth.service import Authorized, SessionContext
from policyops.domain.roles import Role
from policyops.gateway.ports import GatewayScope
from policyops.persistence import executions, runs
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, Principal
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME, WORKER_DISCOVERY
from policyops.providers.tokenizer import Tokenizer, load
from policyops.runtime.clock import DatabaseLeaseClock
from policyops.runtime.executions import build_execution_dispatcher
from policyops.runtime.review import build_review_runtime
from policyops.runtime.worker import Worker, build_worker
from policyops.services.cases import CaseService
from policyops.services.decisions import DecisionService
from policyops.services.execution import RetailOperations
from policyops.services.proposal_views import DecisionRequest
from policyops.settings import TelemetrySettings
from policyops.telemetry.sdk import Backend
from policyops_contracts.clock import SystemClock
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail import CancelPendingOrder
from policyops_contracts.retail_service import FIXTURE_SHA256
from policyops_testing.app_database import AppCluster
from policyops_testing.postgres import OwnedPostgres, owned_postgres
from policyops_testing.retrieval_fixtures import World, luna_reply


ROOT = Path(__file__).resolve().parents[1]
GRAFANA_PORT = "POLICYOPS_OBSERVABILITY_GRAFANA_PORT"
OTLP_PORT = "POLICYOPS_OBSERVABILITY_OTLP_PORT"
DASHBOARD = "policyops-observability"


def host_port(variable: str, default: int) -> int:
    digits = (os.environ.get(variable) or str(default)).lstrip("0")
    port = int(digits) if digits.isascii() and digits.isdecimal() and len(digits) <= 5 else 0
    if not 1 <= port <= 65535:
        raise ValueError(f"{variable} must be an integer from 1 to 65535")
    return port


@dataclass(frozen=True)
class Evidence:
    run: UUID
    trace: str
    proposal: UUID
    operation: UUID
    calls: int
    input_tokens: int
    output_tokens: int


def scripted(tokenizer: Tokenizer, replies: list[tuple[str, dict[str, object]]], prefix: str
             ) -> Callable[[httpx2.Request], httpx2.Response]:
    queue = iter(enumerate(replies, start=1))
    counted = 0

    def respond(request: httpx2.Request) -> httpx2.Response:
        nonlocal counted
        if request.url.path.endswith("/input_tokens"):
            counted = len(tokenizer.encoding.encode_ordinary(request.content.decode()))
            return httpx2.Response(200, json={"object": "response.input_tokens", "input_tokens": counted})
        index, (name, arguments) = next(queue)
        response = luna_reply("", id=f"resp_{prefix}_{index}", output=[
            {"type": "function_call", "name": name, "call_id": f"call_{index}", "arguments": json.dumps(arguments)},
        ], usage={"input_tokens": counted, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                  "output_tokens": 40, "output_tokens_details": {"reasoning_tokens": 8},
                  "total_tokens": counted + 40})(request)
        if not isinstance(response, httpx2.Response):
            raise RuntimeError("scripted reply must complete synchronously")
        return response
    return respond


def run_demo(postgres: OwnedPostgres, scratch: Path, fixture_tree: Path, backend: Backend) -> Evidence:
    # Evaluator and simulator imports belong to the local driver environment.
    bootstrap = import_module("policyops_evals.retail_sim.bootstrap")
    fixture = import_module("policyops_evals.retail_sim.fixture")
    migrate = import_module("policyops_evals.retail_sim.migrate")
    generator = import_module("policyops_evals.scenarios.generator")
    recording = import_module("policyops_evals.scenarios.recording")
    runtime = import_module("policyops_evals.scenarios.runtime")

    db = AppCluster.provision(postgres).create_database("observability")
    try:
        db.upgrade()
        for role in bootstrap.ROLES:
            if role not in postgres.passwords:
                postgres.register_role(role)
        with postgres.connect("postgres", db.name, autocommit=True) as admin:
            bootstrap.provision(admin, db.name, {role: postgres.passwords[role] for role in bootstrap.ROLES})
        with db.engine(bootstrap.MIGRATOR).connect() as connection:
            migrate.upgrade(connection)
        staged = scratch / "retail"
        fixture.stage(fixture_tree, staged)
        policy_path = fixture_tree / RETAIL_POLICY.path
        simulator = runtime.retail_store(db.engine(bootstrap.RUNTIME), staged)
        policy = policy_path.read_bytes()
        dev_cases = generator.generate_dev(simulator.fixture.raw, policy).cases["dev"]
        scenario = next(case for case in dev_cases if case.gold.stratum == "cancel")
        action = scenario.gold.action
        if not isinstance(action, CancelPendingOrder):
            raise RuntimeError("expected a cancellation candidate from the development split")
        world = World(db, scratch)
        world.publish({"policy": policy}, key=runtime.POLICY_CORPUS, domain="retail", render="identity")
        app, auth, discovery = db.engine(APP_RUNTIME), db.engine(AUTH_RUNTIME), db.engine(WORKER_DISCOVERY)
        wall, clock, tokenizer = SystemClock(), DatabaseLeaseClock(), load()
        profile = runtime.Profile(app, auth, simulator, runtime.load_policy(policy_path), tokenizer)
        slot = runtime.Slot(world.ws, uuid4())
        script = scripted(tokenizer, [
            ("find_user_id_by_email", {"email": scenario.visible.lookup_email}),
            ("get_order_details", {"order_id": scenario.world.order_id}),
            ("search_policy", {"query": "cancel"}),
            ("cancel_pending_order", action.model_dump(exclude={"tool"})),
        ], slot.id.hex)
        samples: list[int] = []

        def observe_queue(worker: Worker) -> None:
            worker.discovery_engine = discovery
            samples.append(len(worker.discover()))
            if not backend.flush(6):
                raise RuntimeError("queue telemetry flush failed")

        with ot.span("investigation", run_id=slot.run):
            trace = ot.correlation()["trace_id"]
            result = profile.run_scripted(scenario, slot, recording.Tape(), script, observe_queue=observe_queue)
            if not result.gold_match or result.stop_reason != "waiting_approval" or samples != [1, 0]:
                raise RuntimeError("scripted investigation did not present its cancellation and drain its job")
            with workspace_transaction(app, slot.workspace) as connection:
                [row] = repo.presented_rows_of_run(connection, slot.run)
                proposal = repo.get_proposal(connection, row.proposal_id, row.proposal_version)
                case = repo.get_case(connection, slot.case)
                if proposal is None or case is None:
                    raise RuntimeError("presented proposal or case was missing")
            operator = profile._operator(slot, wall)
            with ot.span("review.execute", proposal_id=proposal.proposal_id, outcome="recorded"):
                reply = CaseService(app, wall, clock).post_message(
                    operator, key=f"reply-{slot.id.hex}", case_id=slot.case, expected_version=case.version,
                    source="operator_entered_customer", text_value="Yes, please.")
                with workspace_transaction(app, slot.workspace) as connection:
                    consent = repo.get_consent(connection, proposal.proposal_id, proposal.proposal_version)
                if reply.status != 201 or consent is None or consent.customer_message_id != reply.message_id:
                    raise RuntimeError("staff-entered customer consent was not recorded")
            reviewer = uuid4()
            now = wall.now()
            with transaction(auth) as connection:
                repo.create_principal(connection, Principal(id=reviewer, issuer="https://reviewer.invalid",
                                                            subject=str(reviewer), display_name="Demo reviewer",
                                                            created_at=now))
                repo.add_membership(connection, Membership(id=uuid4(), workspace_id=slot.workspace,
                                                            principal_id=reviewer, role="reviewer", created_at=now))
            authorized = Authorized(SessionContext(uuid4(), reviewer, slot.workspace, now + timedelta(minutes=5),
                                                   "0" * 64), slot.workspace, frozenset({Role.REVIEWER}))
            with ot.span("review.finish", proposal_id=proposal.proposal_id, outcome="recorded"):
                approved = DecisionService(app, clock).decide(authorized, proposal.proposal_id, DecisionRequest(
                    proposal_version=proposal.proposal_version, action_digest=proposal.action_digest,
                    decision="approve", reason="Checked the customer consent and policy."))
                if approved.replayed or approved.decision.principal_id != reviewer:
                    raise RuntimeError("fresh reviewer approval was not recorded")

            # Reuse the same scope and the signed ASGI simulator boundary for the deterministic continuation.
            binding = profile._seed(scenario, slot, clock)
            with runtime.retail_client(simulator, slot, scenario) as client:
                @contextmanager
                def retail(_scope: GatewayScope) -> Iterator[RetailOperations]:
                    yield client

                review = build_review_runtime(env="test", app_engine=app, bindings=(binding,),
                    fixture_sha256=FIXTURE_SHA256, retail_origin="http://retail.invalid", retail_key=b"",
                    clock=clock, retail=retail)
                worker = build_worker(env="test", app_engine=app, discovery_engine=discovery,
                                      clock=clock, review=review)
                if worker.run_once() != 1:
                    raise RuntimeError("approval did not reach the review worker")
                dispatcher = build_execution_dispatcher(
                    env="test", app_engine=app, discovery_engine=discovery,
                    scopes=review.executor.scopes, retail=retail, clock=clock,
                )
                [step] = dispatcher.dispatch_once()
                if step.state != "succeeded" or worker.run_once() != 1 or worker.discover():
                    raise RuntimeError("dispatch or receipt delivery did not complete")
                with workspace_transaction(app, slot.workspace) as connection:
                    [execution] = executions.case_executions(connection, slot.case)
                    run = runs.get_run(connection, slot.run)
                    usage = connection.execute(text(
                        "SELECT count(*), sum(uncached_input_tokens + cache_read_tokens + cache_write_tokens), "
                        "sum(output_tokens) FROM app.usage_events WHERE run_id = :run"
                    ), {"run": slot.run}).one()
                operation = client.lookup(execution.operation_id, execution.request)
                if (run is None or run.state != "succeeded" or execution.proposal_id != proposal.proposal_id
                        or execution.proposal_version != proposal.proposal_version or execution.receipt is None
                        or isinstance(operation, Unknown) or operation.result is None
                        or operation.result.receipt != execution.receipt):
                    raise RuntimeError("application and simulator receipts did not agree on the same proposal")
                # This isolated database was created for one run. Inspect total effects across the simulator.
                with db.superuser() as connection:
                    effects = connection.execute(
                        "SELECT count(*) FROM retail.operations WHERE outcome = 'committed'").fetchone()
                if effects != (1,) or usage[0] != result.calls:
                    raise RuntimeError("expected one simulator effect and matching run usage")
                return Evidence(slot.run, trace, proposal.proposal_id, execution.operation_id,
                                int(usage[0]), int(usage[1]), int(usage[2]))
    finally:
        db.dispose()


def await_signals(grafana: str, evidence: Evidence, started: float) -> None:
    deadline = time.monotonic() + 30
    metric = 'policyops_provider_dispatch_duration_seconds_count{job="policyops-demo",model="gpt-6-luna"}'
    prom = f"{grafana}/api/datasources/proxy/uid/prometheus/api/v1/query"
    tempo = f"{grafana}/api/datasources/proxy/uid/tempo/api/traces/{evidence.trace}"
    with httpx.Client(timeout=1, trust_env=False, follow_redirects=False) as client:
        while time.monotonic() < deadline:
            try:
                traces = client.get(tempo)
                response = client.get(prom, params={"query": f"{metric} and (timestamp({metric}) >= {started})"})
                if traces.is_success and response.is_success:
                    points = response.json()["data"]["result"]
                    if sum(float(point["value"][1]) for point in points) == evidence.calls:
                        return
            except (httpx.TransportError, ValueError, TypeError, KeyError):
                pass
            time.sleep(0.25)
    raise RuntimeError("Grafana did not confirm this trace and the fresh provider metric within 30 seconds")


def main() -> int:
    """Start the local backend and leave it available for inspection after the disposable run."""
    try:
        grafana_port = host_port(GRAFANA_PORT, 3000)
        otlp_port = host_port(OTLP_PORT, 4318)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    grafana = f"http://127.0.0.1:{grafana_port}"
    otlp = f"http://127.0.0.1:{otlp_port}"
    try:
        if os.environ.get("POLICYOPS_ENV") not in (None, "local", "test"):
            raise RuntimeError("the observability demo requires a local environment")
        fixture = import_module("policyops_evals.retail_sim.fixture")

        temp = Path(os.environ["POLICYOPS_TEMP_DIR"])
        if not temp.is_absolute() or temp.resolve().is_relative_to(ROOT):
            raise RuntimeError("POLICYOPS_TEMP_DIR must be an absolute path outside the checkout")
        fixture_path = os.environ.get("POLICYOPS_RETAIL_FIXTURE_TREE")
        tree = Path(fixture_path) if fixture_path else fixture.find_reviewed_tree(Path(os.environ["UV_CACHE_DIR"]))
        if tree is None:
            raise RuntimeError("the pinned retail fixture tree is required")
        settings = TelemetrySettings(enabled=True, exporter="otlp",
                                     traces_url=f"{otlp}/v1/traces", metrics_url=f"{otlp}/v1/metrics")
        logging.config.dictConfig(SERVE_LOG_CONFIG)
        backend = ot.configure(settings, role="demo")
        if backend is None:
            raise RuntimeError("demo telemetry was not configured")
        try:
            subprocess.run(["docker", "compose", "-f", "infra/compose/observability.yaml", "up", "-d", "--wait",
                            "--wait-timeout", "120"], cwd=ROOT, check=True, timeout=180,
                           env={**os.environ, GRAFANA_PORT: str(grafana_port), OTLP_PORT: str(otlp_port)})
            started = time.time()
            with TemporaryDirectory(prefix="observability-", dir=temp) as work:
                scratch = Path(work)
                with owned_postgres(scratch, uuid4().hex[:12]) as postgres:
                    evidence = run_demo(postgres, scratch, tree, backend)
                if not backend.flush(8):
                    raise RuntimeError("final telemetry export failed")
            await_signals(grafana, evidence, started)
        finally:
            backend.close()
        query = urlencode({"from": int(started * 1000), "to": int(time.time() * 1000),
                           "var-run_id": evidence.run, "var-trace_id": evidence.trace})
        print(f"Run {evidence.run} · Trace {evidence.trace} · Simulator receipt {evidence.operation}")
        print(f"{grafana}/d/{DASHBOARD}?{query}")
        return 0
    except Exception as error:
        print(f"Observability demo failed ({type(error).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
