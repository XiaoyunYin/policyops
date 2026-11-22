"""Local operator composition of the existing workbench investigation."""

from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
import secrets
import time
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx
import httpx2
from pydantic import SecretStr
from sqlalchemy import Connection, Engine, text

from policyops.adapters.retail_client import RetailClient
from policyops.auth.service import Authorized, SessionContext
from policyops.budget.config import CHAT_ACTORS, DEFAULT_ACTORS, Caps, ChatActor, Configuration
from policyops.domain.roles import Role
from policyops.gateway.ports import GatewayScope, RetailPort
from policyops.orchestration.profile import InvestigationProfile
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, NewCase, Principal
import policyops.persistence.repositories as repo
import policyops.persistence.runs as runs
from policyops.providers.calls import Providers
from policyops.providers.contract import Provider
from policyops.providers.tokenizer import Tokenizer
from policyops.retrieval.parse import CHUNK_CONFIG
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock
from policyops.runtime.investigation import build_investigation_spec
from policyops.runtime.spec import RuntimeCatalog, RuntimeSpec
from policyops.runtime.worker import Worker
from policyops.services.runs import RunService
from policyops_contracts.clock import Clock, SystemClock
from policyops_contracts.conversation import AgentLimits, PolicyContext
from policyops_contracts.events import ErrorRaised, EventEnvelope, RunStopped
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail_service import FIXTURE_SHA256, CaseState
from policyops_contracts.retrieval import RetrievalConfig, RetrievalScope
from policyops_contracts.scalars import CaseScope
from policyops_contracts.seeds import CaseCustomerBinding
from policyops_evals.retail_sim import fixture
from policyops_evals.retail_sim.app import create_app
from policyops_evals.retail_sim.auth import Key
from policyops_evals.retail_sim.store import Store
from policyops_evals.scenarios import in_test_context
from policyops_evals.scenarios.cases import Scenario
from policyops_evals.scenarios.grading import grade
from policyops_evals.scenarios.recording import Recorder, Redactor, Tape


MODEL_CALLS = 8
ACTIVE_SECONDS = 120
MAX_STEPS = 16
LIMITS = AgentLimits(model_calls=MODEL_CALLS, steps_per_turn=7, knowledge_steps=2,
                     consecutive_invalid=2, max_output_tokens=1024)
POLICY_CORPUS = "tau2-retail-policy"
SCOPE = RetrievalScope(corpus_key=POLICY_CORPUS)
RETRIEVAL = RetrievalConfig(mode="lexical", max_chunks=2, max_evidence_tokens=512)
SMOKE_CAP = Decimal("0.03")
Handler = Callable[[httpx2.Request], httpx2.Response]


def configuration(cache_mode: str = "none") -> Configuration:
    actors = dict(DEFAULT_ACTORS)
    for name in CHAT_ACTORS:
        actor = actors[name]
        if not isinstance(actor, ChatActor):
            raise TypeError("missing chat actor")
        actors[name] = replace(actor, max_input=10_000, max_output=1024)
    actors["agent"] = ChatActor("agent", "gpt-6-luna", "low", cache_mode=cache_mode, max_input=10_000, max_output=1024)
    config = Configuration(actors=actors, caps=Caps(run_calls=MODEL_CALLS, request_max_input=10_000,
                                                   request_max_output=1024, active_seconds=ACTIVE_SECONDS))
    worst = config.reservation("agent").worst_usd * MODEL_CALLS
    return replace(config, caps=replace(config.caps, run_usd=worst))


def scenario_spec(*, env: str, engine: Engine, policy: PolicyContext, tokenizer: Tokenizer,
                  retail: Callable[[GatewayScope], RetailPort], providers: Callable[[], Providers],
                  bindings: tuple[CaseCustomerBinding, ...] = (), clock: LeaseClock | None = None,
                  wall_clock: Clock | None = None,
                  profile: InvestigationProfile = InvestigationProfile.BASELINE,
                  cache_mode: str = "none") -> RuntimeSpec:
    return build_investigation_spec(
        env=env, engine=engine, configuration=configuration(cache_mode), policy=policy,
        retrieval_scope=SCOPE, retrieval_config=RETRIEVAL, limits=LIMITS, max_steps=MAX_STEPS,
        bindings=bindings, fixture_sha256=FIXTURE_SHA256, retail=retail,
        providers=providers, tokenizer=tokenizer, clock=clock, wall_clock=wall_clock, profile=profile,
    )


def preflight(config: Configuration, slots: int) -> Decimal:
    worst = slots * config.caps.run_calls * config.reservation("agent").worst_usd
    if slots < 1 or worst > SMOKE_CAP or slots * config.caps.run_usd > SMOKE_CAP:
        raise ValueError("aggregate smoke cap exceeded")
    return worst


def load_policy(path: Path) -> PolicyContext:
    with path.open("rb") as handle:
        raw = handle.read(64 * 1024 + 1)
    return PolicyContext(domain="retail", source="pinned_retail_policy", text=raw.decode("utf-8"),
                         sha256=RETAIL_POLICY.sha256)


def active_policy_generation(engine: Engine, workspace: UUID, policy: PolicyContext,
                             tokenizer: Tokenizer) -> UUID | None:
    with workspace_transaction(engine, workspace) as connection:
        generation = connection.execute(text(
            "SELECT g.id FROM app.corpora c JOIN app.index_generations g "
            "ON g.workspace_id = c.workspace_id AND g.id = c.active_generation_id "
            "JOIN app.generation_documents d ON d.workspace_id = g.workspace_id AND d.generation_id = g.id "
            "WHERE c.corpus_key = :corpus AND c.domain = 'retail' AND g.status = 'ready' "
            "AND g.document_count = 1 AND g.chunk_count > 0 AND g.render = 'identity' "
            "AND g.chunk_config = :chunks AND g.tokenizer_sha256 = :tokenizer AND d.raw_sha256 = :policy"
        ), {"corpus": SCOPE.corpus_key, "tokenizer": tokenizer.identity_sha256, "policy": policy.sha256,
            "chunks": CHUNK_CONFIG}).scalar_one_or_none()
    return generation if isinstance(generation, UUID) else None


@dataclass(frozen=True)
class Slot:
    workspace: UUID
    id: UUID

    @property
    def run(self) -> UUID:
        return uuid5(self.id, "workbench-run")

    @property
    def case(self) -> UUID:
        return uuid5(self.id, "app-and-retail-case")

    @property
    def message(self) -> UUID:
        return uuid5(self.id, "seeded-message")

    def redactor(self, secrets: tuple[str, ...] = ()) -> Redactor:
        return Redactor({self.workspace: "workspace", self.run: "run", self.case: "case", self.message: "message"},
                        secrets)


def smoke_slot(workspace: UUID, scenario: Scenario) -> Slot:
    return Slot(workspace, uuid5(workspace, f"policyops:n2-s1/smoke/{scenario.key}"))


@dataclass(frozen=True)
class Summary:
    first_decision: str
    gold_match: bool
    calls: int
    settled_usd: Decimal
    held_usd: Decimal
    latency_ms: int
    stop_reason: str


@dataclass(frozen=True)
class Usage:
    calls: int = 0
    counts: int = 0
    settled: Decimal = Decimal(0)
    held: Decimal = Decimal(0)
    blocked: bool = False


def usage(engine: Engine, slot: Slot) -> Usage:
    with workspace_transaction(engine, slot.workspace) as connection:
        row = connection.execute(text(
            "SELECT s.spent_usd, s.held_usd, s.calls_consumed, s.counts_used, s.overrun, s.contract_block, "
            "a.settled, a.held FROM app.budget_scopes s CROSS JOIN LATERAL ("
            "SELECT COALESCE(sum(actual_usd) FILTER (WHERE state = 'settled'), 0) AS settled, "
            "COALESCE(sum(reserved_usd) FILTER (WHERE state IN ('reserved', 'dispatching', 'unresolved')), 0) AS held "
            "FROM app.usage_attempts WHERE scope_id = s.id AND workspace_id = s.workspace_id) a "
            "WHERE s.run_id = :run"
        ), {"run": slot.run}).mappings().one_or_none()
    if row is None:
        return Usage()
    if (row["settled"], row["held"]) != (row["spent_usd"], row["held_usd"]):
        raise ValueError("app ledger totals do not reconcile")
    return Usage(row["calls_consumed"], row["counts_used"], row["settled"], row["held"],
                 row["overrun"] or row["contract_block"] is not None)


@contextmanager
def retail_client(store: Store, slot: Slot, scenario: Scenario) -> Iterator[RetailClient]:
    """Run the real signed simulator API in process over ASGI, without a listening socket."""
    from policyops_evals.harness.inprocess import OwnedLoop

    key = secrets.token_bytes(32)
    transport = httpx.ASGITransport(app=create_app(store, Key(key)))
    loop = OwnedLoop()

    async def send(request: httpx.Request) -> httpx.Response:
        reply = await transport.handle_async_request(request)
        try:
            return httpx.Response(reply.status_code, content=await reply.aread(), headers=reply.headers)
        finally:
            await reply.aclose()

    def bridge(request: httpx.Request) -> httpx.Response:
        reply = loop.run(send(httpx.Request(request.method, request.url, headers=request.headers,
                                           content=request.read())), seconds=10)
        return reply

    try:
        with closing(RetailClient("http://retail.invalid", key, tenant_id=slot.workspace,
                                  case_id=slot.case, customer_id=scenario.world.customer_id,
                                  transport=httpx.MockTransport(bridge))) as client:
            if not isinstance(client.initialize(), CaseState):
                raise ValueError("retail case initialization unavailable")
            yield client
    finally:
        loop.close(seconds=2)


@dataclass(frozen=True)
class Profile:
    app: Engine
    auth: Engine
    retail: Store
    policy: PolicyContext
    tokenizer: Tokenizer

    def corpus_generation(self, workspace: UUID) -> UUID:
        generation = active_policy_generation(self.app, workspace, self.policy, self.tokenizer)
        if generation is None:
            raise ValueError("a digest-matched retail policy corpus is required in the dedicated workspace")
        return generation

    def run_scripted(self, scenario: Scenario, slot: Slot, tape: Tape, handler: Handler, *,
                     profile: InvestigationProfile = InvestigationProfile.BASELINE,
                     bind_spec: Callable[[RuntimeSpec], RuntimeSpec] | None = None,
                     observe_queue: Callable[[Worker], None] | None = None,
                     cache_mode: str = "none") -> Summary:
        token = secrets.token_urlsafe(24)
        return self._run(scenario, slot, tape, lambda: httpx2.MockTransport(handler),
                         env="test", credential=token, redactor=slot.redactor((token,)),
                         profile=profile, bind_spec=bind_spec, observe_queue=observe_queue, cache_mode=cache_mode)

    def _run(self, scenario: Scenario, slot: Slot, tape: Tape, transport: Callable[[], httpx2.AsyncBaseTransport],
             *, env: str, credential: str, redactor: Redactor, expected_generation: UUID | None = None,
             profile: InvestigationProfile = InvestigationProfile.BASELINE,
             bind_spec: Callable[[RuntimeSpec], RuntimeSpec] | None = None,
             observe_queue: Callable[[Worker], None] | None = None,
             cache_mode: str = "none") -> Summary:
        if env != "test" and in_test_context():
            raise ValueError("test scenarios require a mock provider transport")
        scenario.verify(self.retail.fixture.raw)
        generation = self.corpus_generation(slot.workspace)
        if expected_generation is not None and generation != expected_generation:
            raise ValueError("registered policy generation changed")
        wall, lease = SystemClock(), DatabaseLeaseClock()
        authorized = self._operator(slot, wall)
        binding = self._seed(scenario, slot, lease)

        def recording_transport(provider: Provider) -> httpx2.AsyncBaseTransport:
            if provider != "openai":
                raise ValueError("unexpected scenario provider")
            inner = transport()
            if env == "test" and not isinstance(inner, httpx2.MockTransport):
                raise ValueError("test scenarios require a mock provider transport")
            return Recorder(inner, tape, redactor)

        def providers() -> Providers:
            return Providers({"openai": SecretStr(credential)}, recording_transport)

        with retail_client(self.retail, slot, scenario) as client:
            spec = scenario_spec(
                env=env, engine=self.app, policy=self.policy, bindings=(binding,), retail=lambda _: client,
                providers=providers, tokenizer=self.tokenizer, clock=lease, wall_clock=wall, profile=profile,
                cache_mode=cache_mode,
            )
            if bind_spec is not None:
                spec = bind_spec(spec)
            catalog = RuntimeCatalog.of([spec], default=spec.spec_id)
            service = RunService(self.app, lease, catalog, wall, run_id_factory=lambda: slot.run)
            result = service.start(authorized, key=str(slot.id), case_id=slot.case, expected_version=1)
            if result.run_id != slot.run:
                raise ValueError("slot run identity mismatch")
            worker = Worker(self.app, self.app, lease, catalog)
            if observe_queue is not None:
                observe_queue(worker)
            stop, latency = self._work(worker, slot, tape, lease)
            if observe_queue is not None:
                observe_queue(worker)
        if self.corpus_generation(slot.workspace) != generation:
            raise ValueError("policy generation changed during the slot")
        accounting = usage(self.app, slot)
        complete = accounting.calls > 0 and accounting.calls == sum(
            item.phase == "create" and item.complete and item.response is not None for item in tape.records)
        label, matched = grade(scenario, tape.records, stop, complete_capture=complete)
        return Summary(label, matched, accounting.calls, accounting.settled, accounting.held, latency, stop)

    def _operator(self, slot: Slot, wall: SystemClock) -> Authorized:
        issuer = "https://policyops-scenario-operator.invalid"
        principal = uuid5(NAMESPACE_URL, f"{issuer}/{slot.workspace}")
        now = wall.now()
        with transaction(self.auth) as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                               {"key": str(principal)})
            if repo.find_principal(connection, issuer, str(slot.workspace)) is None:
                repo.create_principal(connection, Principal(id=principal, issuer=issuer, subject=str(slot.workspace),
                                                            display_name="Scenario operator", created_at=now))
                repo.add_membership(connection, Membership(id=uuid5(principal, "analyst"),
                                                            workspace_id=slot.workspace, principal_id=principal,
                                                            role="analyst", created_at=now))
        return Authorized(SessionContext(uuid5(principal, "local-session"), principal, slot.workspace,
                                         now + timedelta(minutes=5), "0" * 64), slot.workspace,
                          frozenset({Role.ANALYST}))

    def _seed(self, scenario: Scenario, slot: Slot, lease: DatabaseLeaseClock) -> CaseCustomerBinding:
        scope = CaseScope(workspace_id=slot.workspace, case_id=slot.case)
        with workspace_transaction(self.app, slot.workspace) as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                               {"key": str(slot.case)})
            case = repo.get_case(connection, slot.case)
            if case is None:
                now = lease.now(connection)
                case = repo.create_case(connection, NewCase(
                    id=slot.case, workspace_id=slot.workspace, scenario="retail",
                    customer_user_id=scenario.world.customer_id, created_by=None, created_at=now))
                repo.append_message(connection, message_id=slot.message, scope=scope, source="seeded", entered_by=None,
                                    text_value=scenario.visible.message, created_at=now)
            message = repo.message_by_id(connection, scope, slot.message)
            if (case.customer_user_id != scenario.world.customer_id or message is None
                    or message.source != "seeded" or message.text != scenario.visible.message):
                raise ValueError("slot case input changed")
        return CaseCustomerBinding(scope=scope, seed_id=f"retail-demo-{slot.case.int % 10_000:04d}",
                                   user_id=scenario.world.customer_id, bound_at=case.created_at)

    def _work(self, worker: Worker, slot: Slot, tape: Tape, lease: DatabaseLeaseClock) -> tuple[str, int]:
        deadline = time.monotonic() + ACTIVE_SECONDS + 5
        while True:
            with workspace_transaction(self.app, slot.workspace) as connection:
                run = runs.get_run(connection, slot.run)
                if run is None:
                    raise ValueError("slot run missing")
                finished = terminal_outcome(connection, run)
                if finished is not None:
                    return finished
                if tape.started_at is None:
                    elapsed = (lease.now(connection) - run.created_at).total_seconds()
                    tape.started_at = time.monotonic() - elapsed
                job = runs.execute_job_of(connection, slot.run)
                if job is None:
                    raise ValueError("slot execute job missing")
            if time.monotonic() >= deadline:
                raise ValueError("slot worker did not reach a stop")
            if not worker.process(job.id, slot.workspace):
                time.sleep(0.25)


def terminal_outcome(connection: Connection, run: runs.Run) -> tuple[str, int] | None:
    if not run.terminal and run.state != "waiting_approval":
        return None
    latency = int((run.updated_at - run.created_at).total_seconds() * 1000)
    for event in reversed(runs.events_after(connection, run, max(0, run.event_highwater - 32), 32)):
        if isinstance(event, EventEnvelope):
            if isinstance(event.payload, RunStopped):
                return event.payload.details.reason.value, latency
            if isinstance(event.payload, ErrorRaised):
                return event.payload.rule_id or event.payload.code.value, latency
    return run.state, latency


def retail_store(engine: Engine, root: Path) -> Store:
    loaded = fixture.load(root)
    store = Store(engine, loaded, fixture.upstream(loaded))
    store.require_head()
    return store
