"""Local Compose composition and seed for the pinned fictional retail investigation."""

from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from fastapi import APIRouter
from fastapi.responses import Response
import httpx2
from pydantic import BaseModel, SecretStr
from sqlalchemy import Connection, Engine, text

from policyops.adapters.retail_client import RetailClient, Unknown
from policyops.api.cases import view
from policyops.api.run_reads import Reads, Viewer
from policyops.budget.config import CHAT_ACTORS, DEFAULT_ACTORS, Caps, ChatActor, Configuration, EmbeddingActor
from policyops.domain.roles import Action
from policyops.gateway.ports import GatewayScope, RetailPort
from policyops.orchestration.profile import InvestigationProfile, InvestigationProfileV2, InvestigationVersion
from policyops.persistence import repositories as repo
from policyops.persistence.budget import workspace_liability
from policyops.persistence.database import workspace_transaction
from policyops.persistence.records import NewCase, exact_usd
from policyops.persistence.runs import Run, get_run
from policyops.providers import tokenizer
from policyops.providers.calls import Providers
from policyops.providers.contract import Provider
from policyops.providers.tokenizer import Tokenizer
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops.retrieval.parse import CHUNK_CONFIG
from policyops.runtime.clock import LeaseClock
from policyops.runtime.investigation import build_investigation_spec
from policyops.runtime.spec import RuntimeCatalog, StepContext
from policyops.services.writes import not_found, recheck
from policyops_contracts.conversation import AgentLimits, PolicyContext
from policyops_contracts.policy import RETAIL_POLICY
from policyops_contracts.retail import GetOrderDetails, GetUserDetails
from policyops_contracts.retail_service import FIXTURE_SHA256, OrderOutput, UserOutput
from policyops_contracts.retrieval import RetrievalConfig, RetrievalScope
from policyops_contracts.scalars import CaseScope
from policyops_contracts.seeds import CaseCustomerBinding


INPUTS = Path("/opt/live-agent")
MANIFEST_SHA256 = "266576117d1336b075c1d502b00fed371c81015081c129f65a1f801a06f0e2c5"
PROFILE = InvestigationProfile.TOOL_CONTRACT_V1R1
POLICY_CORPUS = "tau2-retail-policy"
SCOPE = RetrievalScope(corpus_key=POLICY_CORPUS)
RETRIEVAL = RetrievalConfig(mode="lexical", max_chunks=2, max_evidence_tokens=512)
LIMITS = AgentLimits(model_calls=8, steps_per_turn=7, knowledge_steps=2, consecutive_invalid=2,
                     max_output_tokens=1024)
CUSTOMER = "amelia_kim_4338"
EMAIL = "amelia.kim6460@example.com"
ORDER = "#W7634667"
MESSAGE = (f"My account email is {EMAIL}. Please cancel my pending order because I no longer need it. "
           "Can you check the cancellation policy first?")


class LiveAgentRefused(RuntimeError):
    """A fixed category safe to print at the container command boundary."""


def selected_profile() -> InvestigationVersion:
    value = os.environ.get("POLICYOPS_LIVE_AGENT_PROFILE", PROFILE.value)
    if value == PROFILE.value:
        return PROFILE
    if value == InvestigationProfileV2.TOOL_CONTRACT_V2.value:
        return InvestigationProfileV2.TOOL_CONTRACT_V2
    raise LiveAgentRefused("live_agent.invalid_profile")


def configuration() -> Configuration:
    # Keep these workbench settings aligned with the pinned retail study configuration.
    actors = dict(DEFAULT_ACTORS)
    for name in CHAT_ACTORS:
        actor = actors[name]
        if not isinstance(actor, ChatActor):
            raise TypeError("missing chat actor")
        actors[name] = replace(actor, max_input=10_000, max_output=1024)
    actors["agent"] = ChatActor("agent", "gpt-6-luna", "low", cache_mode="none", max_input=10_000, max_output=1024)
    config = Configuration(actors=actors, caps=Caps(run_calls=LIMITS.model_calls, request_max_input=10_000,
                                                   request_max_output=1024, active_seconds=120))
    return replace(config, caps=replace(config.caps, run_usd=preflight(config)))


def preflight(config: Configuration) -> Decimal:
    return config.caps.run_calls * config.reservation("agent").worst_usd


def max_usd() -> Decimal:
    try:
        value = Decimal(os.environ.get("POLICYOPS_LIVE_AGENT_MAX_USD", "0.50"))
        exact_usd(value, "live-agent aggregate cap")
    except (InvalidOperation, ValueError):
        raise LiveAgentRefused("live_agent.invalid_aggregate_cap") from None
    return value


def provider_secret(path: Path) -> SecretStr:
    try:
        with path.open(encoding="utf-8") as source:
            raw = source.read(4097)
        if raw.strip() and len(raw) <= 4096:
            return SecretStr(raw.strip())
    except (OSError, UnicodeError):
        pass
    raise LiveAgentRefused("live_agent.openai_secret_required")


def unavailable_providers() -> Providers:
    raise LiveAgentRefused("live_agent.api_provider_disabled")


def provider_access(key: SecretStr) -> Providers:
    def transport(provider: Provider) -> httpx2.AsyncBaseTransport:
        if provider != "openai":
            raise LiveAgentRefused("live_agent.provider_disabled")
        return httpx2.AsyncHTTPTransport(trust_env=False, retries=0)

    return Providers({"openai": key}, transport)


def inputs(root: Path) -> tuple[PolicyContext, Tokenizer]:
    with (root / RETAIL_POLICY.path).open("rb") as source:
        raw = source.read(64 * 1024 + 1)
    policy = PolicyContext(domain="retail", source="pinned_retail_policy", text=raw.decode("utf-8"),
                           sha256=RETAIL_POLICY.sha256)
    return policy, tokenizer.load(root / tokenizer.VOCABULARY_FILE)


def generation(connection: Connection, vocab: Tokenizer) -> UUID | None:
    result = connection.execute(text(
        "SELECT g.id FROM app.corpora c JOIN app.index_generations g "
        "ON g.workspace_id = c.workspace_id AND g.id = c.active_generation_id "
        "JOIN app.generation_documents d ON d.workspace_id = g.workspace_id AND d.generation_id = g.id "
        "WHERE c.corpus_key = :corpus AND c.domain = 'retail' AND g.status = 'ready' "
        "AND g.document_count = 1 AND g.chunk_count > 0 AND g.render = 'identity' "
        "AND g.chunk_config = :chunks AND g.tokenizer_sha256 = :tokenizer AND d.raw_sha256 = :policy"
    ), {"corpus": SCOPE.corpus_key, "tokenizer": vocab.identity_sha256, "policy": RETAIL_POLICY.sha256,
        "chunks": CHUNK_CONFIG}).scalar_one_or_none()
    return result if isinstance(result, UUID) else None


def corpus_manifest() -> bytes:
    """The retail-only entry from the reviewed tau2 ingestion manifest."""
    data = {
        "schema": "policyops.ingest-manifest/v1",
        "source": {
            "commit": RETAIL_POLICY.source_commit,
            "repository": "https://github.com/sierra-research/tau2-bench.git",
            "source_manifest_sha256": "fc0f802747a21405053c3ccf1a3124042d7aea10ce8339694ae0c3e515dc877a",
            "tree": "f6b4756d287ca59e654d76545e8d6dfb8618a020",
        },
        "corpora": [{
            "corpus_key": POLICY_CORPUS,
            "domain": "retail",
            "license": "MIT (tau2-bench root grant)",
            "license_scope": "root LICENSE: MIT License, Copyright (c) 2025 Sierra Research. The root license is the "
                             "only explicit grant found. It does not by itself prove the provenance of every data "
                             "file or linked asset.",
            "publisher": "Sierra Research",
            "render": "identity",
            "rendered_list_sha256": "e1353f5c6b3b68dee21009feff4c7bd555d60c71c522f248411f6137e4f7882b",
            "documents": [{"document_key": "policy", "git_blob": "d127e6b074654926f337d0d98b0e669ebe90d19e",
                           "path": RETAIL_POLICY.path, "sha256": RETAIL_POLICY.sha256, "size": 6699}],
        }],
    }
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def message_id(case: UUID) -> UUID:
    return uuid5(case, "policyops:live-agent:customer")


def case_binding(connection: Connection, scope: CaseScope, workspace: UUID) -> CaseCustomerBinding | None:
    if scope.workspace_id != workspace:
        return None
    case = repo.get_case(connection, scope.case_id)
    message = repo.message_by_id(connection, scope, message_id(scope.case_id))
    if (case is None or case.scenario != "retail" or case.customer_user_id != CUSTOMER
            or case.created_by != uuid5(workspace, "alice") or message is None
            or message.source != "simulated_customer" or message.sequence != 1 or message.text != MESSAGE):
        return None
    return CaseCustomerBinding(scope=scope, user_id=CUSTOMER, seed_id=f"retail-demo-{scope.case_id.int % 10_000:04d}",
                               bound_at=case.created_at)


def client(origin: str, key: bytes, scope: CaseScope, customer: str) -> RetailClient:
    return RetailClient(origin, key, tenant_id=scope.workspace_id, case_id=scope.case_id, customer_id=customer,
                        fixture_sha256=FIXTURE_SHA256)


def catalog(*, env: str, engine: Engine, loaded: tuple[PolicyContext, Tokenizer],
            workspace: UUID, providers: Callable[[], Providers],
            retail_origin: str | None = None, retail_key: bytes | None = None,
            clock: LeaseClock | None = None, aggregate: Decimal | None = None,
            profile: InvestigationVersion = PROFILE,
            record_run: Callable[[StepContext], tuple[Providers, Callable[[str, int], None]]]
            | None = None) -> RuntimeCatalog:
    policy, vocab = loaded

    def unowned_retail(_scope: GatewayScope) -> RetailPort:
        raise LiveAgentRefused("live_agent.retail_session_required")

    @contextmanager
    def retail_session(scope: GatewayScope) -> Iterator[RetailPort]:
        if retail_origin is None or retail_key is None:
            raise LiveAgentRefused("live_agent.api_retail_disabled")
        case = CaseScope(workspace_id=scope.run.workspace_id, case_id=scope.run.case_id)
        with closing(client(retail_origin, retail_key, case, scope.customer_user_id)) as connection:
            yield connection

    spec = build_investigation_spec(
        env=env, engine=engine, configuration=configuration(), policy=policy, retrieval_scope=SCOPE,
        retrieval_config=RETRIEVAL, limits=LIMITS, max_steps=16, bindings=(), fixture_sha256=FIXTURE_SHA256,
        case_binding=lambda conn, scope: case_binding(conn, scope, workspace),
        retail=unowned_retail, retail_session=retail_session, providers=providers, tokenizer=vocab,
        clock=clock, profile=profile, workspace_max_usd=aggregate, record_run=record_run,
    )
    return RuntimeCatalog.of((spec,), default=spec.spec_id)


def claim_refusal(connection: Connection, run: Run, *, workspace: UUID, aggregate: Decimal,
                  worst: Decimal, vocab: Tokenizer) -> str | None:
    scope = CaseScope(workspace_id=run.workspace_id, case_id=run.case_id)
    if case_binding(connection, scope, workspace) is None:
        return "live_agent.case_not_seeded"
    if generation(connection, vocab) is None:
        return "live_agent.corpus_not_ready"
    if run.state == "queued" and workspace_liability(connection) + worst > aggregate:
        return "live_agent.aggregate_cap"
    return None


def prepare_corpus(engine: Engine, workspace: UUID, root: Path, providers: Callable[[], Providers],
                   aggregate: Decimal, *, env: str) -> UUID:
    _, vocab = inputs(root)
    with workspace_transaction(engine, workspace) as connection:
        existing = generation(connection, vocab)
        if existing is not None:
            return existing
    embedding = DEFAULT_ACTORS["embedding"]
    if not isinstance(embedding, EmbeddingActor):
        raise TypeError("missing embedding actor")
    paid = PaidCaps(embedding.model, embedding.dimensions, Decimal("0.01"), 4, 16_000, 120)
    request = Request(workspace, SCOPE.corpus_key, corpus_manifest(), MANIFEST_SHA256, root,
                      mode="execute", paid=paid)
    result = ingest(request, engine=engine, tokenizer=vocab, providers=providers, env=env,
                    workspace_max_usd=aggregate)
    if result.reason == "usd_cap":
        raise LiveAgentRefused("live_agent.aggregate_cap")
    with workspace_transaction(engine, workspace) as connection:
        active = generation(connection, vocab)
    if result.outcome not in {"activated", "unchanged"} or active is None:
        raise LiveAgentRefused("live_agent.corpus_ingest_failed")
    return active


def seed_case(engine: Engine, workspace: UUID, *, retail_origin: str, retail_key: bytes) -> UUID:
    now = datetime.now(UTC)
    scope = CaseScope(workspace_id=workspace, case_id=uuid4())
    with closing(client(retail_origin, retail_key, scope, CUSTOMER)) as retail:
        if isinstance(retail.initialize(), Unknown):
            raise LiveAgentRefused("live_agent.simulator_initialization")
        user = retail.read(GetUserDetails(user_id=CUSTOMER))
        order = retail.read(GetOrderDetails(order_id=ORDER))
        if (isinstance(user, Unknown) or not isinstance(user.output, UserOutput)
                or user.output.user.email != EMAIL or user.output.user.order_ids != (ORDER,)
                or isinstance(order, Unknown) or not isinstance(order.output, OrderOutput)
                or order.output.order.status != "pending" or order.output.order.user_id != CUSTOMER):
            raise LiveAgentRefused("live_agent.fixture_mismatch")
    with workspace_transaction(engine, workspace) as connection:
        repo.create_case(connection, NewCase(id=scope.case_id, workspace_id=workspace, scenario="retail",
                         customer_user_id=CUSTOMER, created_by=uuid5(workspace, "alice"), created_at=now))
        repo.append_message(connection, message_id=message_id(scope.case_id), scope=scope, source="simulated_customer",
                            entered_by=None, text_value=MESSAGE, created_at=now)
    return scope.case_id


class Timing(BaseModel):
    created_at: datetime
    first_model_call_at: datetime | None
    proposal_persisted_at: datetime | None
    investigation_ended_at: datetime | None


def timing(connection: Connection, run: Run) -> Timing:
    row = connection.execute(text(
        "SELECT min(occurred_at) FILTER (WHERE event_type = 'proposal.presented') AS proposal, "
        "min(occurred_at) FILTER (WHERE event_type = 'run.state_changed' "
        "AND payload->>'current' IN ('waiting_approval','succeeded','failed','cancelled','budget_exceeded')) AS ended "
        "FROM app.run_events WHERE run_id = :run"
    ), {"run": run.id}).one()
    first = connection.execute(text(
        "SELECT min(a.created_at) FROM app.usage_attempts a JOIN app.budget_scopes s ON a.scope_id = s.id "
        "AND a.workspace_id = s.workspace_id WHERE s.run_id = :run AND a.actor = 'agent'"
    ), {"run": run.id}).scalar_one()
    return Timing(created_at=run.created_at, first_model_call_at=first, proposal_persisted_at=row.proposal,
                  investigation_ended_at=row.ended)


class Usage(BaseModel):
    call_count: int
    settled_usd: str
    held_usd: str
    timing: Timing


def usage_router(workspace: UUID) -> APIRouter:
    router = APIRouter()

    @router.get("/live-agent/runs/{run_id}/usage", response_model=Usage)
    def run_usage(run_id: UUID, authorized: Viewer, service: Reads) -> Response:
        with workspace_transaction(service.engine, authorized.workspace_id) as connection:
            recheck(connection, authorized, Action.VIEW_CASE)
            run = get_run(connection, run_id)
            if run is None or case_binding(connection, CaseScope(
                    workspace_id=run.workspace_id, case_id=run.case_id), workspace) is None:
                raise not_found("run")
            row = connection.execute(text(
                "SELECT calls_consumed, spent_usd, held_usd FROM app.budget_scopes WHERE run_id = :run"
            ), {"run": run_id}).one_or_none()
            measured = timing(connection, run)
        if row is None:
            return view(Usage(call_count=0, settled_usd="0", held_usd="0", timing=measured))
        return view(Usage(call_count=row.calls_consumed, settled_usd=format(row.spent_usd, "f"),
                          held_usd=format(row.held_usd, "f"), timing=measured))

    return router
