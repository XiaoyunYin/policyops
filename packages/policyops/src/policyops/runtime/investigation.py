"""Explicit library composition for a run-bound investigation; no server/provider defaults."""

import asyncio
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import timedelta
import time
from typing import Any
from uuid import UUID

from langgraph.errors import GraphRecursionError, NodeCancelledError
from langgraph.graph import START
from sqlalchemy import Engine

from policyops.budget.config import Configuration
from policyops.budget.ledger import Ledger, RunBinding
from policyops.gateway.ports import GatewayScope, PgSessionStore, RetailPort, ScopeMismatch, load_scope
from policyops.gateway.steps import Gateway
from policyops.gateway.stores import PgTargetEvidence
from policyops.orchestration import investigation_prompt as prompt
from policyops.orchestration.adapters import InvestigationAdapters
from policyops.orchestration.context import fit
from policyops.orchestration.facts import load_critical_facts
from policyops.orchestration.graph import GRAPH_ENTRY, GRAPH_NODES, GRAPH_TARGETS, InvestigationGraph, failed
from policyops.orchestration.ports import ModelPort, agent_model_port
from policyops.orchestration.profile import InvestigationProfile
from policyops.orchestration.state import (
    AwaitingApproval as ApprovalTerminal,
)
from policyops.orchestration.state import (
    InvestigationCompleted as CompletedTerminal,
)
from policyops.orchestration.state import (
    InvestigationFailed,
    InvestigationState,
    InvestigationStopped,
    state_from_json,
)
from policyops.orchestration.stops import InvestigationStop, stop_reason
from policyops.persistence import checkpoint_json as codec
from policyops.persistence import repositories as repo
from policyops.persistence import runs
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.checkpoints import InvestigationSaver
from policyops.persistence.citations import CitationRecorder
from policyops.persistence.database import (
    DatabaseUnavailable,
    NotFound,
    TransactionOutcomeUnknown,
    workspace_transaction,
)
from policyops.persistence.embeddings import EmbeddingStore
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.bounds import REQUEST_BOUNDS
from policyops.providers.calls import Providers
from policyops.providers.serialize import prepare
from policyops.providers.tokenizer import Tokenizer
from policyops.retrieval.grounding import EvidenceValidator
from policyops.retrieval.search import Retriever
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, require_test_environment
from policyops.runtime.spec import (
    AwaitingApproval,
    Failed,
    InvestigationCompleted,
    Outcome,
    Retry,
    RuntimeSpec,
    StepContext,
    Stopped,
    unconfirmed_stop,
)
from policyops.services.proposals import ProposalService
from policyops.telemetry import annotate, enabled, observed
from policyops_contracts.clock import Clock, SystemClock
from policyops_contracts.conversation import AgentLimits, PolicyContext, UserMessage
from policyops_contracts.errors import ErrorCode
from policyops_contracts.retrieval import RetrievalConfig, RetrievalScope, canonical_sha256
from policyops_contracts.seeds import CaseCustomerBinding
from policyops_contracts.stops import StopDetails, StopReason


# Bump deliberately for incompatible behavior changes not represented by the schemas/topology below.
GRAPH_VERSION = "policyops.investigation-graph/v2"


def graph_digest(profile: InvestigationProfile = InvestigationProfile.BASELINE) -> str:
    versions = codec.Envelope.model_json_schema()["properties"]
    schema = InvestigationState.model_json_schema()
    fields = {
        "version": GRAPH_VERSION,
        "nodes": GRAPH_NODES,
        "edges": [(START, GRAPH_ENTRY), *((source, target) for source in GRAPH_NODES for target in GRAPH_TARGETS)],
        "state_schema": schema,
        "codec_version": versions["codec_version"]["const"],
        "framework_checkpoint_version": versions["framework_version"]["const"],
    }
    if profile is InvestigationProfile.BASELINE:
        # The baseline never emits argument diagnostics. Hash its original checkpoint schema.
        definitions = schema["$defs"]
        del definitions["RuntimeNotice"]["properties"]["argument_issue"]
        del definitions["ToolArgumentIssue"], definitions["ToolName"]
    else:
        fields["profile"] = profile
    return canonical_sha256(fields)


@dataclass(frozen=True)
class InvestigationExecutor:
    engine: Engine
    env: str
    configuration: Configuration
    policy: PolicyContext
    limits: AgentLimits
    retrieval_scope: RetrievalScope
    retrieval_config: RetrievalConfig
    bindings: tuple[CaseCustomerBinding, ...]
    fixture_sha256: str
    retail: Callable[[GatewayScope], RetailPort]
    providers: Callable[[], Providers]
    tokenizer: Tokenizer
    clock: LeaseClock
    wall_clock: Clock
    max_steps: int
    lease: timedelta
    graph_sha256: str
    prompt_sha256: str
    config_sha256: str
    test_model: Callable[[Ledger, RunBinding], ModelPort] | None = None
    profile: InvestigationProfile = InvestigationProfile.BASELINE

    @observed("investigation")
    def execute(self, context: StepContext) -> Outcome:
        if enabled():
            annotate(run_id=context.run_id, job_id=context.claim_token.job_id, attempt=context.attempt,
                     generation=context.claim_token.generation)
        try:
            return asyncio.run(self._execute(context))
        except (codec.CheckpointCompatibilityError, codec.CheckpointStateVersionError,
                codec.CheckpointUnsafeTypeError, NotFound):
            return Failed(ErrorCode.UNAVAILABLE, "investigation.checkpoint_incompatible")
        except asyncio.CancelledError:
            raise
        except (DatabaseUnavailable, TransactionOutcomeUnknown):
            return Retry("investigation_database_unavailable")
        except AccountingUnconfirmed as error:
            return unconfirmed_stop(error.report)
        except InvestigationStop as error:
            return Stopped(error.details)
        except NodeCancelledError:
            # LangGraph wraps cancellation raised by a node body; resume its durable checkpoint.
            return Retry("investigation_node_cancelled")
        except ScopeMismatch:
            return Failed(ErrorCode.UNAVAILABLE, "investigation.case_binding")

    def fence(self, context: StepContext) -> None:
        if (context.claim_token.workspace_id, context.claim_token.run_id) != (context.workspace_id, context.run_id):
            raise runs.Fenced("context_binding_changed")
        with workspace_transaction(self.engine, context.workspace_id) as connection:
            run, _, _ = runs.check_fence(connection, context.claim_token, self.clock)
            if run.case_id != context.case_id or (run.graph_sha256, run.prompt_sha256, run.config_sha256) != (
                    self.graph_sha256, self.prompt_sha256, self.config_sha256):
                raise runs.Fenced("runtime_binding_changed")

    async def _execute(self, context: StepContext) -> Outcome:
        self.fence(context)
        with workspace_transaction(self.engine, context.workspace_id) as connection:
            run, _, now = runs.check_fence(connection, context.claim_token, self.clock)
            observed_monotonic = time.monotonic()
            case = repo.get_case(connection, context.case_id)
        if case is None or case.customer_user_id is None:
            return Failed(ErrorCode.UNAVAILABLE, "investigation.case_binding")
        seed = next((b for b in self.bindings if b.scope.workspace_id == context.workspace_id
                     and b.scope.case_id == context.case_id), None)
        if seed is None:
            return Failed(ErrorCode.UNAVAILABLE, "investigation.case_binding")
        scope = load_scope(self.engine, workspace_id=context.workspace_id, run_id=context.run_id, binding=seed,
                           fixture_sha256=self.fixture_sha256)
        saver = InvestigationSaver(engine=self.engine, scope=scope.run, token=context.claim_token, clock=self.clock,
                                   graph_sha256=self.graph_sha256, prompt_sha256=self.prompt_sha256,
                                   config_sha256=self.config_sha256)
        config = saver.config()
        config["recursion_limit"] = self.max_steps + 2
        saved = await saver.aget_tuple(config)
        initial: dict[str, Any] | None = None
        if saved is None:
            # A changed case before the first snapshot needs a new authorized run, never silent new input.
            if case.version != run.case_version:
                return Failed(ErrorCode.STALE_VERSION, "investigation.input_changed")
            transcript_list: list[UserMessage] = []
            identities: list[UUID] = []
            with workspace_transaction(self.engine, context.workspace_id) as connection:
                locked = repo.lock_case(connection, context.case_id)
                if locked is None or locked.version != run.case_version:
                    return Failed(ErrorCode.STALE_VERSION, "investigation.input_changed")
                facts = load_critical_facts(connection, context.case_id)
                after = 0
                content_bytes = 0
                while True:
                    page = repo.list_messages(connection, seed.scope, after_sequence=after, limit=64)
                    for message in page:
                        content_bytes += len(message.text.encode("utf-8"))
                        if len(identities) >= 256 or content_bytes > self.limits.transcript_bytes:
                            return Stopped(StopDetails(reason=StopReason.CONTEXT_LIMIT))
                        identities.append(message.message_id)
                        transcript_list.append(UserMessage(
                            text=f"[{message.source}; {message.message_id}] {message.text}"))
                    if len(page) < 64:
                        break
                    after = page[-1].sequence
            transcript = tuple(transcript_list)
            if not transcript:
                return Failed(ErrorCode.UNAVAILABLE, "investigation.input_missing")
            state = InvestigationState(state_version=2, workspace_id=context.workspace_id, case_id=context.case_id,
                                       run_id=context.run_id, graph_sha256=self.graph_sha256,
                                       prompt_sha256=self.prompt_sha256, config_sha256=self.config_sha256,
                                       input_message_ids=tuple(identities), transcript=transcript, critical_facts=facts,
                                       max_steps=self.max_steps, policy_sha256=self.policy.sha256,
                                       retrieval_sha256=self.retrieval_digest,
                                       actor_sha256=self.configuration.reservation("agent").config_sha256)
            state = fit(state, self.policy, self.limits, profile=self.profile)
            if state.terminal is not None:
                return outcome(state)
            initial = {"state": state.model_dump(mode="json")}
        else:
            channels = saved.checkpoint["channel_values"]
            raw = channels.get("state")
            if raw is None:
                start = channels.get("__start__")
                if start is None:
                    return Failed(ErrorCode.UNAVAILABLE, "investigation.checkpoint_incompatible")
                raw = start["state"]
            state = state_from_json(raw)
        if (state.policy_sha256, state.retrieval_sha256, state.actor_sha256, state.max_steps) != (
                self.policy.sha256, self.retrieval_digest, self.configuration.reservation("agent").config_sha256,
                self.max_steps):
            return Failed(ErrorCode.UNAVAILABLE, "investigation.checkpoint_incompatible")
        # Re-read only the saved input identities. Later customer turns are T22's responsibility.
        with workspace_transaction(self.engine, context.workspace_id) as connection:
            if any(repo.message_by_id(connection, seed.scope, identity) is None
                   for identity in state.input_message_ids):
                return Failed(ErrorCode.UNAVAILABLE, "investigation.input_changed")
        if state.terminal is not None:
            self.fence(context)
            return outcome(state)
        deadline = observed_monotonic + runs.remaining_us(run, now) / 1_000_000
        ledger = build_app_ledger(env=self.env, engine=self.engine, workspace_id=context.workspace_id,
                                  configuration=self.configuration, clock=self.clock, claim_token=context.claim_token)
        repaired = self.profile.tool_contract
        model = (self.test_model(ledger, RunBinding(context.run_id)) if self.test_model is not None else
                 agent_model_port(ledger, RunBinding(context.run_id), self.providers, detailed_tool_errors=repaired))
        retriever = Retriever(self.engine, context.workspace_id,
                              embeddings=EmbeddingStore(self.engine, context.workspace_id, env=self.env),
                              ledger=ledger, providers=self.providers, tokenizer=self.tokenizer, env=self.env,
                              rerank=self.retrieval_config.rerank is not None, stop_on_budget=True,
                              lexical_mode=self.profile.lexical_mode)
        adapters = InvestigationAdapters(retriever, self.retrieval_scope, self.retrieval_config,
                                         Gateway(scope, retail=self.retail(scope), sessions=PgSessionStore(self.engine),
                                                 clock=self.wall_clock, target_evidence=PgTargetEvidence(self.engine)),
                                         ProposalService(self.engine, self.clock), context.claim_token,
                                         EvidenceValidator(self.engine, context.workspace_id),
                                         CitationRecorder(self.engine, context.workspace_id),
                                         references={r.evidence_id: r for r in state.recorded_evidence},
                                         disclose_lookup_user_id=repaired)
        builder = InvestigationGraph(model, adapters, adapters, self.policy, self.limits, deadline,
                                   lambda: self.fence(context),
                                   lambda: (stop_reason(reason) if (reason := ledger.exhaustion(
                                       RunBinding(context.run_id))) is not None else None), profile=self.profile)
        graph = builder.compile(saver)
        stop = asyncio.Event()
        heartbeat_error: list[BaseException] = []

        async def invoke() -> dict[str, Any]:
            try:
                return await graph.ainvoke(initial, config, durability="sync")  # None resumes scheduler state
            except GraphRecursionError:
                latest = await saver.aget_tuple(config)
                raw_state = state if latest is None else state_from_json(latest.checkpoint["channel_values"]["state"])
                terminal = failed(raw_state, InvestigationFailed(kind="loop_ceiling"))
                await graph.aupdate_state(config, {"state": terminal.model_dump(mode="json")}, as_node="finalize")
                return {"state": terminal.model_dump(mode="json")}

        task = asyncio.create_task(invoke())

        async def heartbeat() -> None:
            try:
                while not stop.is_set():
                    try:
                        await asyncio.wait_for(stop.wait(), self.lease.total_seconds() / 3)
                    except TimeoutError:
                        if not context.heartbeat():
                            raise runs.Fenced("heartbeat_lost") from None
            except Exception as error:
                heartbeat_error.append(error)
                task.cancel()

        monitor = asyncio.create_task(heartbeat())
        primary: BaseException | None = None
        try:
            result = await task
            self.fence(context)
            final = outcome(state_from_json(result["state"]))
            return builder.accounting if builder.accounting is not None else final
        except asyncio.CancelledError as error:
            primary = heartbeat_error[0] if heartbeat_error else error
            raise primary from None
        except BaseException as error:
            primary = error
            raise
        finally:
            stop.set()
            try:
                await asyncio.wait_for(monitor, 1)
            except BaseException:
                if primary is None:
                    raise

    @property
    def retrieval_digest(self) -> str:
        fields: dict[str, object] = {"scope": self.retrieval_scope.model_dump(mode="json"),
                                     "config": self.retrieval_config.model_dump(mode="json")}
        if self.profile.tool_contract:
            fields["lexical_mode"] = self.profile.lexical_mode
        return canonical_sha256(fields)


def outcome(state: InvestigationState) -> Outcome:
    terminal = state.terminal
    if isinstance(terminal, ApprovalTerminal):
        return AwaitingApproval(terminal.proposal_id, terminal.proposal_version)
    if isinstance(terminal, CompletedTerminal) and state.final_text is not None:
        return InvestigationCompleted(terminal.message_id, state.final_text)
    if isinstance(terminal, InvestigationStopped):
        return Stopped(terminal.details)
    if isinstance(terminal, InvestigationFailed):
        return Failed(ErrorCode.UNAVAILABLE, f"investigation.{terminal.kind}")
    return Failed(ErrorCode.UNAVAILABLE, "investigation.checkpoint_incompatible")


def build_investigation_spec(*, env: str, engine: Engine, configuration: Configuration, policy: PolicyContext,
                             retrieval_scope: RetrievalScope, retrieval_config: RetrievalConfig,
                             bindings: tuple[CaseCustomerBinding, ...], fixture_sha256: str,
                             retail: Callable[[GatewayScope], RetailPort], providers: Callable[[], Providers],
                             tokenizer: Tokenizer, limits: AgentLimits | None = None, max_steps: int = 32,
                             clock: LeaseClock | None = None, wall_clock: Clock | None = None,
                             lease: timedelta = timedelta(seconds=30),
                             test_model: Callable[[Ledger, RunBinding], ModelPort] | None = None,
                             profile: InvestigationProfile = InvestigationProfile.BASELINE) -> RuntimeSpec:
    """Install the returned spec in the SAME catalog passed to the API runtime and worker."""
    if test_model is not None and env != "test":
        raise ValueError("test model factories require env=test")
    if policy.source == "fictional" and env != "test":
        raise ValueError("fictional policy requires env=test")
    if type(max_steps) is not int or not 1 <= max_steps <= 64:
        raise ValueError("max_steps must be 1..64")
    if not isinstance(profile, InvestigationProfile):
        raise ValueError("profile must be an InvestigationProfile")
    lease_clock = clock or DatabaseLeaseClock()
    require_test_environment(lease_clock, env)
    selected = limits or AgentLimits(knowledge_steps=16)
    if not 1 <= selected.knowledge_steps <= 16:
        raise ValueError("investigation knowledge_steps must be 1..16")
    if profile.tool_contract and selected.consecutive_invalid != 2:
        raise ValueError(f"{profile} requires consecutive_invalid=2")
    # Both provider capability checks are pure and run before any ledger/network work.
    prepare(prompt.request(policy, selected, (UserMessage(text="x"),), profile=profile), configuration, "agent")
    config_fields: dict[str, object] = {
        "v": "policyops.investigation-config/v2", "policy": policy.model_dump(mode="json"),
        "request_bounds": dict(REQUEST_BOUNDS), "limits": selected.model_dump(mode="json"),
        "max_steps": max_steps, "lease_seconds": str(lease.total_seconds()),
        "retrieval_scope": retrieval_scope.model_dump(mode="json"),
        "retrieval_config": retrieval_config.model_dump(mode="json"),
        "actors": {k: configuration.reservation(k).config_sha256 for k in configuration.actors},
        "caps": {k: str(v) for k, v in asdict(configuration.caps).items()},
        "fixture": fixture_sha256,
        "bindings": [b.model_dump(mode="json") for b in bindings],
    }
    if profile.tool_contract:
        config_fields.update(profile=profile, lexical_mode=profile.lexical_mode)
    config_sha = canonical_sha256(config_fields)
    executor = InvestigationExecutor(engine, env, configuration, policy, selected, retrieval_scope, retrieval_config,
                                     bindings, fixture_sha256, retail, providers, tokenizer, lease_clock,
                                     wall_clock or SystemClock(), max_steps, lease, graph_digest(profile),
                                     prompt.digest(profile), config_sha, test_model=test_model, profile=profile)
    spec_id = f"investigation.{profile}" if profile.tool_contract else "investigation.v2"
    return RuntimeSpec(spec_id, executor.graph_sha256, executor.prompt_sha256, config_sha, executor,
                       lease=lease, run_timeout=timedelta(seconds=configuration.caps.active_seconds),
                       test_only=env == "test")
