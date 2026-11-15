"""One retrieval step (T13): validate, replay or record the intent, obtain the query vector, read one snapshot, rank,
deliver and trace.

Order of a step (`Retriever.retrieve`):

1. Validate the query, scope and configuration (pure). The query's local cl100k count must be at most
   `MAX_QUERY_TOKENS` (the embedding tokenizer is right here: a query is an embedding input).
2. **Replay first** (read-only): if the step's deterministic trace exists, replay it for audit, whatever the run's
   state now. A trace without a matching intent, or with an unsupported payload, is refused (`replay_unsupported`);
   one whose request differs is `step_conflict`. Replay rebuilds the evidence from the immutable version bodies and
   verifies the body, evidence-text and payload digests (`replay_integrity` otherwise).
3. **Intent** (new steps only): the run must be active, the corpus present with a pointer, the allowlist inside the
   corpus, and the configuration's worst-case trace JSONB must measure within the column limits with a 10% margin.
   Then the immutable `(run, step)` intent is committed before any provider work; a different stored request is
   `step_conflict`.
4. **Query vector** (`dense`, `hybrid`), outside any transaction, under the step deadline:
   - the step's own query job (`query.<run>.<step>`) if it exists. It is used only if it completed with a valid cached
     vector; an unsettled job is never bypassed by a vector some other job cached;
   - otherwise a cache hit (no job, no call);
   - otherwise one run-bound foundation job (`run_job(run_id=...)`): exactly one input, charged to the run's shared
     budget scope.

   Availability outcomes (`budget`, `unresolved`, `vectors_invalid`, `job_unsettled`, `missing_vector`) make a hybrid
   step lexical-only and flagged under `dense_policy="lexical_fallback"`, and refuse otherwise. Never a fallback:
   cancellation (propagates), the deadline (`deadline_passed`), a lease held elsewhere past the bounded wait
   (`step_in_progress`), binding, identity, contract or configuration integrity (`embedding_integrity`,
   `step_conflict`),
   an invalid vector (`query_vector_invalid`).
5. **Snapshot** (`REPEATABLE READ READ ONLY`): the current generation, its embedding configuration (it must match the
   step's), the branches and the bounded candidate texts.
6. Pure fusion and delivery, counted with the evidence counter (whole assembled string).
   6a. **Optional rerank** (T14, `config.rerank` set and the Retriever built with reranking): one bounded structured
   request reorders the first fused documents, outside any transaction (`retrieval.rerank`). Layer B, in order: the
   global deadline (`deadline_passed`, whatever the stage said), the outcome's request identity and window
   (`rerank_integrity`), an applied ranking's labels (`rerank_integrity`), the local sub-deadline (`timeout`), local
   integrity / run state, then the policy: a fallback-class status delivers the baseline order, flagged, under
   `baseline_fallback`, or refuses `rerank_unavailable` under `refuse`. Delivery then runs unchanged on the
   (re)ordered documents.
7. **Trace** with its deterministic ID. On a conflict (a concurrent same-step writer), the stored trace is reread and
   verified like a replay, and returned. The stored winner is authoritative: a losing writer's ranking is never
   claimed applied.

Rerank gating happens after the replay lookup (a stored trace always replays for audit, with no adapter) and before
the intent: a rerank request on a Retriever without reranking is `config_invalid` (`rerank_not_configured`), on
`full_policy` `config_invalid` (`rerank_full_policy`), and an output limit above this Retriever's reranker actor
maximum `config_invalid` (`rerank_output_bound`). Nothing is written or reserved for these.

**Per-invocation work** is a local accumulator of one call, never state on the shared Retriever. A rerank-configured
step reports it as `invocation` on the result, or on a refusal after work; it is zero for an audit replay and is
carried through a lost trace race, so a paid losing writer still reports its own grants.

Deadline: checked at the explicit service phase boundaries and again before any result (new or replayed) is
returned; it is not checked inside each nested lookup of the query-vector phase or inside the snapshot's SQL. A
synchronous SQL call is not interrupted by the deadline: it may continue until control returns to the service, and a
step whose deadline has passed by the next boundary returns `deadline_passed`, never a result. What was already
committed stays committed: an intent, a settled embedding and a trace written before the expiry was observed are kept
(never rolled back or reissued), so a later timely retry of the same step replays the trace, or reuses the vector,
without a new call.

A result is a historical snapshot: `current_policy_validated` and `claim_support_validated` are always false, and the
caller must already have authorized the run, case and corpus.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import hashlib
import math
import struct
import time
from typing import get_args
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ValidationError
from sqlalchemy import Engine

from policyops.budget.ledger import Ledger
from policyops.orchestration.stops import InvestigationStop, stop_reason
from policyops.persistence.embeddings import EmbeddingStore, JobConflict, vector_text
from policyops.persistence.retrieval import (
    LexicalMode,
    RetrievalStore,
    Snapshot,
    Span,
    StepJob,
    StepRefused,
    StoredTrace,
)
from policyops.providers.calls import Providers
from policyops.providers.embedding_calls import (
    QUERY_PURPOSE,
    BindingMismatch,
    DeadlinePassed,
    EmbedLimits,
    JobReport,
    PreparedJob,
    check_binding,
    prepare_job,
    run_job,
)
from policyops.providers.embedding_contract import request_config_sha256
from policyops.providers.embeddings import input_sha256
from policyops.providers.tokenizer import InputRefused, Tokenizer
from policyops.retrieval.counting import EvidenceCounter, EvidenceDeadline
from policyops.retrieval.rank import (
    ChunkRow,
    Delivery,
    FullPolicyRefused,
    Fused,
    Hit,
    assemble,
    deliver,
    deliver_full_policy,
    fraction_text,
    fuse,
)
from policyops.retrieval.rerank import (
    FALLBACK_STATUSES,
    MIN_STAGE_SECONDS,
    PROMPT_SHA256,
    RESERVE_SECONDS,
    RerankOutcome,
    RerankPort,
    build_input,
    preflight,
    production_port,
    reorder,
    reranker_model,
    slug_or_none,
)
from policyops.runtime.clock import UnsafeTestHook, require_test_environment
from policyops.telemetry import annotate, observed
from policyops_contracts.embedding import EmbeddingJob
from policyops_contracts.retrieval import (
    MAX_RERANK_DOCUMENTS,
    BranchDocument,
    DeliveredChunk,
    DenseStatus,
    DenseUnavailable,
    EvidenceChunk,
    Exclusions,
    FusedDocument,
    InvocationWork,
    RerankAttempt,
    RerankModel,
    RerankSummary,
    RerankTrace,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    TraceCandidates,
    TraceScope,
    canonical_sha256,
)
from policyops_contracts.stops import StopDetails, StopReason


MAX_QUERY_TOKENS = 1024
TRACE_NAMESPACE = uuid5(NAMESPACE_URL, "policyops:retrieval-trace/v1")
_FLOAT32 = struct.Struct("<f")


class _Unavailable(Exception):
    """A dense-availability outcome, carrying what is known about provider work so a fallback reports it truthfully
    (the ledger stays the billing authority)."""

    def __init__(self, reason: DenseUnavailable, *, requests: int = 0, job_id: UUID | None = None) -> None:
        super().__init__(reason)
        self.reason: DenseUnavailable = reason
        self.requests, self.job_id = requests, job_id


def trace_id_for(workspace_id: UUID, run_id: UUID, step: int) -> UUID:
    return uuid5(TRACE_NAMESPACE, f"{workspace_id}:{run_id}:{step}")


def subject_for(run_id: UUID, step: int) -> str:
    return f"query.{run_id}.{step}"


def valid_vector(vector: Sequence[float]) -> bool:
    """1536 finite components with a nonzero norm after float32 rounding (pgvector's storage precision)."""
    if len(vector) != 1536 or not all(isinstance(v, float) and math.isfinite(v) for v in vector):
        return False
    try:
        rounded = [_FLOAT32.unpack(_FLOAT32.pack(v))[0] for v in vector]
    except (OverflowError, struct.error):  # finite in float64 but outside float32
        return False
    return all(math.isfinite(v) for v in rounded) and any(v != 0.0 for v in rounded)


def _refused(code: str, detail: str | None = None) -> RetrievalRefused:
    return RetrievalRefused.model_validate({"code": code, "detail": detail})


@dataclass
class _Work:
    """This invocation's own provider work (a local accumulator of one `retrieve` call, never Retriever state)."""

    embedding_requests: int = 0
    counts_claimed: int = 0
    inferences_dispatched: int = 0
    cleanup_unconfirmed: bool = False

    def invocation(self) -> InvocationWork:
        return InvocationWork(embedding_requests=self.embedding_requests, rerank_counts_claimed=self.counts_claimed,
                              rerank_inferences_dispatched=self.inferences_dispatched,
                              cleanup_unconfirmed=self.cleanup_unconfirmed)


# -- shared trace verification (C2 replay and the T14 query-less validator) ----------------------------------------

@dataclass(frozen=True)
class TraceProblem:
    code: str
    detail: str


@dataclass(frozen=True)
class CheckedRecord:
    candidates: TraceCandidates
    scope: TraceScope


def verify_record(stored: StoredTrace, *, run_id: UUID, expected_request: str | None = None,
                  expected_query_sha256: str | None = None) -> CheckedRecord | TraceProblem:
    """The stored trace's own consistency (pure), in the C2 replay order and with its codes. With
    `expected_request`/`expected_query_sha256` (replay) the request must be that query's; without them (query-less)
    the trace's request must equal its intent's."""
    try:
        candidates = TraceCandidates.model_validate_json(stored.candidates)
        scope = TraceScope.model_validate_json(stored.authorized_scope)
    except ValidationError:
        return TraceProblem("replay_unsupported", "the stored trace is not a supported retrieval trace")
    if stored.intent_request_sha256 is None:
        return TraceProblem("replay_unsupported", "the stored trace has no recorded intent")
    if expected_request is not None:
        if stored.intent_request_sha256 != expected_request or candidates.request_sha256 != expected_request:
            return TraceProblem("step_conflict", "this step already holds a different request")
    elif candidates.request_sha256 != stored.intent_request_sha256:
        return TraceProblem("replay_integrity", "the trace's request is not its intent's")
    if (stored.run_id, stored.generation_id) != (run_id, candidates.generation_id) or (
            expected_query_sha256 is not None and stored.query_sha256 != expected_query_sha256):
        return TraceProblem("replay_integrity", "the stored trace does not match its own record")
    if candidates.computed_payload_sha256() != candidates.payload_sha256:
        return TraceProblem("replay_integrity", "payload digest")
    if tuple(d.chunk_id for d in candidates.delivered) != stored.final_chunk_ids:
        return TraceProblem("replay_integrity", "delivered chunk IDs")
    return CheckedRecord(candidates, scope)


def span_entries(candidates: TraceCandidates) -> list[tuple[UUID, int, int]]:
    return [(d.document_version_id, d.start, d.end) for d in candidates.delivered]


def verify_evidence(candidates: TraceCandidates, spans: Sequence[Span | None]
                    ) -> tuple[list[ChunkRow], str] | TraceProblem:
    """Every delivered entry against its immutable version span (all of them), then the evidence-text digest."""
    if len(spans) != len(candidates.delivered):
        return TraceProblem("replay_integrity", "evidence spans")
    chunks: list[ChunkRow] = []
    for entry, span in zip(candidates.delivered, spans, strict=True):
        if (span is None or span.text is None or not span.body_digest_ok
                or span.document_version_id != entry.document_version_id or span.document_id != entry.document_id
                or span.version_number != entry.version_number
                or hashlib.sha256(span.text.encode("utf-8")).hexdigest() != entry.text_sha256):
            return TraceProblem("replay_integrity", f"evidence E{entry.evidence_number}")
        chunks.append(ChunkRow(entry.chunk_id, entry.document_id, entry.document_version_id, span.source_uri,
                               entry.version_number, entry.heading, entry.start, entry.end, span.text))
    evidence_text = assemble(chunks)
    if hashlib.sha256(evidence_text.encode("utf-8")).hexdigest() != candidates.evidence_text_sha256:
        return TraceProblem("replay_integrity", "evidence text digest")
    return chunks, evidence_text


@dataclass(frozen=True)
class RetrieverLimits:
    lease_seconds: float = 60.0
    wait_seconds: float = 10.0
    poll_seconds: float = 0.1
    attempt_seconds: float = 30.0


class Retriever:
    """The retrieval component for one workspace. `ledger` must be the app ledger of this workspace on `engine`
    (the foundation checks it); `providers` is called only when a provider request may be needed.

    Reranking is off unless `rerank=True` (the production adapter, constructed here from this Retriever's own ledger
    and providers factory, never injected) or a `rerank_port` that declares `test_only` with `env="test"`. Enabling
    it runs a pure preflight (actor, output limit, a maximal template through T11 `prepare`) before anything else.
    `lexical_mode` selects both lexical-only and hybrid lexical branches. Non-default modes extend the effective
    config/request fingerprint, preventing replay across modes without changing the legacy wire contract/digests."""

    def __init__(self, engine: Engine, workspace_id: UUID, *, embeddings: EmbeddingStore, ledger: Ledger,
                 providers: Callable[[], Providers], tokenizer: Tokenizer,
                 limits: RetrieverLimits | None = None, clock: Callable[[], float] = time.monotonic,
                 stop_on_budget: bool = False, rerank: bool = False, rerank_port: RerankPort | None = None,
                 env: str | None = None, lexical_mode: LexicalMode = "all_terms") -> None:
        if lexical_mode not in ("all_terms", "any_terms"):
            raise ValueError("invalid lexical mode")
        self.lexical_mode = lexical_mode
        # Rerank wiring first: before any read, reservation, credential or factory use.
        if rerank_port is not None:
            if getattr(rerank_port, "test_only", False) is not True or env != "test":
                raise UnsafeTestHook("an injected rerank port must be a test-only port in the test environment")
            require_test_environment(rerank_port, env)
        self._rerank_model: str | None = None
        if rerank or rerank_port is not None:
            preflight(ledger.configuration)
            self._rerank_model = reranker_model(ledger.configuration)
        # The composed boundary, checked before any read, cache use or write: the embedding store and the app
        # ledger must be this workspace's own components on this very engine (not merely consistent with each other).
        if embeddings.engine is not engine or embeddings.workspace_id != workspace_id:
            raise BindingMismatch("the embedding store belongs to another engine or workspace")
        check_binding(ledger, embeddings)  # the app ledger of the same workspace on the same engine
        self.store = RetrievalStore(engine, workspace_id)
        self.workspace_id = workspace_id
        self.embeddings, self.ledger, self.providers, self.tokenizer = embeddings, ledger, providers, tokenizer
        self.stop_on_budget = stop_on_budget
        self.limits = limits or RetrieverLimits()
        self.clock = clock
        self._rerank_port: RerankPort | None = None
        if self._rerank_model is not None:
            self._rerank_port = rerank_port if rerank_port is not None else production_port(ledger, providers)

    # -- entry point -----------------------------------------------------------------------------------------------

    def _config_sha256(self, query: RetrievalQuery) -> str:
        if self.lexical_mode == "all_terms":
            return query.config.sha256()
        return canonical_sha256({"config_sha256": query.config.sha256(), "lexical_mode": self.lexical_mode})

    def _request_sha256(self, query: RetrievalQuery) -> str:
        if self.lexical_mode == "all_terms":
            return query.request_sha256()
        return canonical_sha256({"v": "policyops.retrieval-request/v1", "query_sha256": query.query_sha256(),
                                 "scope_sha256": query.scope.sha256(), "config_sha256": self._config_sha256(query)})

    @observed("retrieval.step")
    async def retrieve(self, query: RetrievalQuery, *, deadline: float) -> RetrievalResult | RetrievalRefused:
        annotate(run_id=query.run_id, mode=query.config.mode)
        result = await self._observed_retrieve(query, deadline=deadline)
        annotate(outcome="refused" if isinstance(result, RetrievalRefused) else "completed")
        return result

    async def _observed_retrieve(self, query: RetrievalQuery, *, deadline: float) -> RetrievalResult | RetrievalRefused:
        work = _Work()
        outcome = await self._outcome(query, deadline, work)
        if isinstance(outcome, RetrievalRefused) and query.config.rerank is not None:
            return outcome.model_copy(update={"invocation": work.invocation()})  # what this call did before refusing
        return outcome

    async def _outcome(self, query: RetrievalQuery, deadline: float, work: _Work
                       ) -> RetrievalResult | RetrievalRefused:
        # A NaN would make every `clock() >= deadline` check false: refuse before any read, write, count or request.
        if isinstance(deadline, bool) or not isinstance(deadline, int | float) or not math.isfinite(deadline):
            return _refused("deadline_invalid")
        try:
            return await self._retrieve(query, float(deadline), work)
        except StepRefused as refused:
            if refused.code == "lexical_query_too_many_lexemes":
                return _refused("query_too_long", refused.code)
            return _refused(refused.code, refused.detail)
        except (DeadlinePassed, EvidenceDeadline):
            return _refused("deadline_passed")

    def _check_deadline(self, deadline: float) -> None:
        if self.clock() >= deadline:
            raise StepRefused("deadline_passed")

    def _rerank_gate(self, query: RetrievalQuery) -> str | None:
        """Per-query rerank checks (after the replay lookup, before the intent or any provider work)."""
        config = query.config.rerank
        if config is None:
            return None
        if self._rerank_port is None:
            return "rerank_not_configured"
        if query.config.mode == "full_policy":
            return "rerank_full_policy"
        actor = self.ledger.configuration.actors["reranker"]
        if config.max_output_tokens > getattr(actor, "max_output", 0):
            return "rerank_output_bound"
        return None

    async def _retrieve(self, query: RetrievalQuery, deadline: float, work: _Work
                        ) -> RetrievalResult | RetrievalRefused:
        self._check_deadline(deadline)
        try:
            if self.tokenizer.count(query.text) > MAX_QUERY_TOKENS:
                return _refused("query_too_many_tokens")
        except InputRefused:
            return _refused("query_invalid_text")
        config = query.config
        trace_id = trace_id_for(self.workspace_id, query.run_id, query.step)
        request = self._request_sha256(query)
        stored = self.store.find_trace(trace_id)
        if stored is not None:
            return self._replay(query, stored, request, deadline, work)  # nothing done yet: zero invocation work
        gate = self._rerank_gate(query)
        if gate is not None:
            return _refused("config_invalid", gate)
        self._check_deadline(deadline)
        intent = self.store.create_intent(
            run_id=query.run_id, step=query.step, trace_id=trace_id, request_sha256=request,
            query_sha256=query.query_sha256(), scope_sha256=query.scope.sha256(),
            config_sha256=self._config_sha256(query),
            corpus_key=query.scope.corpus_key, allowlist=query.scope.document_allowlist,
            full_policy=config.mode == "full_policy", worst_case=worst_case_trace(query))
        self._check_deadline(deadline)
        vector: tuple[float, ...] | None = None
        unavailable: DenseUnavailable | None = None
        requests = 0
        job_id: UUID | None = None
        if config.mode in ("dense", "hybrid"):
            try:
                vector, requests, job_id = await self._query_vector(query, deadline, work)
            except _Unavailable as missing:
                work.embedding_requests = missing.requests
                if config.mode == "dense" or config.dense_policy == "refuse":
                    return _refused("embedding_unavailable", missing.reason)
                unavailable, requests, job_id = missing.reason, missing.requests, missing.job_id
        work.embedding_requests = requests
        self._check_deadline(deadline)
        snapshot = self.store.snapshot(
            corpus_key=query.scope.corpus_key, mode=config.mode,
            query=query.text if config.mode in ("lexical", "hybrid") else "",
            query_vector=vector_text(vector) if vector is not None else None, document_ids=intent.document_ids,
            branch_documents=config.branch_documents, chunks_per_document=config.chunks_per_document,
            full_policy_max_chunks=config.full_policy_max_chunks, lexical_mode=self.lexical_mode)
        if vector is not None and (snapshot.embedding_model, snapshot.dimension, snapshot.request_config_sha256) != (
                config.embedding_model, config.embedding_dimensions,
                request_config_sha256(config.embedding_model, config.embedding_dimensions)):
            return _refused("embedding_integrity", "the generation's embedding configuration differs")
        self._check_deadline(deadline)
        counter = EvidenceCounter(self.tokenizer, deadline=deadline, clock=self.clock)
        fused: list[Fused] = []
        rerank: RerankTrace | None = None
        if config.mode == "full_policy":
            try:
                delivery = deliver_full_policy(list(snapshot.rows.values()), config, counter)
            except FullPolicyRefused as refused:
                return _refused(refused.code)
        else:
            fused = fuse(snapshot.lexical, snapshot.dense, config.rrf_k)
            ranked: list[Fused] = fused
            if config.rerank is not None:
                ranked, rerank = await self._rerank(query, request, snapshot, fused, deadline, work)
            delivery = deliver(ranked, snapshot.rows, config, counter)
        candidates = self._candidates(query, request, snapshot, fused, delivery, unavailable, vector is not None,
                                      rerank)
        scope = TraceScope(corpus_key=query.scope.corpus_key, step=query.step,
                           allowlist_sha256=canonical_sha256(list(query.scope.document_allowlist)),
                           document_ids=intent.document_ids, config_sha256=self._config_sha256(query),
                           query_sha256=query.query_sha256(), embedding_job_id=job_id)
        self._check_deadline(deadline)
        written = self.store.insert_trace(
            trace_id=trace_id, run_id=query.run_id, generation_id=snapshot.generation_id,
            query_sha256=query.query_sha256(), authorized_scope=scope.model_dump_json(),
            candidates=candidates.model_dump_json(), final_chunk_ids=[c.chunk_id for c in delivery.chunks])
        self._check_deadline(deadline)  # a trace committed late stays committed; a same-step retry replays it
        if not written:  # a concurrent same-step writer won: verify and return its stored result
            stored = self.store.find_trace(trace_id)
            if stored is None:
                return _refused("trace_unavailable", "the conflicting trace is not visible")
            return self._replay(query, stored, request, deadline, work)  # this invocation's own known work
        # Observed after the trace write, outside the snapshot: a later activation can always follow. This is an
        # observation for the caller, never authorization or current-policy validation.
        current = self.store.pointer(query.scope.corpus_key) == snapshot.generation_id
        self._check_deadline(deadline)
        return self._result(query, trace_id, candidates, delivery.chunks, delivery.evidence_text, replayed=False,
                            current=current, work=work)

    # -- optional rerank (stage 6a) --------------------------------------------------------------------------------

    async def _rerank(self, query: RetrievalQuery, request: str, snapshot: Snapshot, fused: list[Fused],
                      deadline: float, work: _Work) -> tuple[list[Fused], RerankTrace]:
        config, port, model = query.config.rerank, self._rerank_port, self._rerank_model
        if config is None or port is None or model is None:  # pragma: no cover - excluded by the gate
            raise StepRefused("rerank_integrity", "reranking is not configured")
        built = build_input(workspace_id=self.workspace_id, run_id=query.run_id, step=query.step,
                            request_sha256=request, query=query.text, config=config, fused=fused, rows=snapshot.rows,
                            chunks_per_document=query.config.chunks_per_document)
        window = built.window_document_ids
        outcome: RerankOutcome
        local: float | None = None  # the stage's absolute sub-deadline, kept to recheck after the port returns
        if built.skipped is not None:
            outcome = RerankOutcome(built.skipped, None, built.request_identity, window)
        else:
            # The sub-deadline is on time.monotonic() (T11's clock); the global deadline on this Retriever's clock.
            seconds = min(float(config.seconds), deadline - self.clock() - RESERVE_SECONDS)
            if seconds < MIN_STAGE_SECONDS:
                outcome = RerankOutcome("skipped_deadline", None, built.request_identity, window)
            else:
                local = time.monotonic() + seconds
                outcome = await port.rerank(built, deadline=local)  # cancellation propagates
        # Layer B. 0: the outcome's own work counters (a broken port is an integrity failure), then known work.
        counters = (outcome.counts_claimed, outcome.inferences_dispatched)
        if any(isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= 1 for n in counters) or not isinstance(
                outcome.cleanup_unconfirmed, bool):
            raise StepRefused("rerank_integrity", "the rerank outcome reports impossible work")
        work.counts_claimed += outcome.counts_claimed
        work.inferences_dispatched += outcome.inferences_dispatched
        work.cleanup_unconfirmed = work.cleanup_unconfirmed or outcome.cleanup_unconfirmed
        if self.stop_on_budget and any(a.fate == "unresolved" for a in outcome.attempts):
            raise InvestigationStop(StopDetails(reason=StopReason.USAGE_UNCONFIRMED, usage_unconfirmed=True,
                                                cleanup_unconfirmed=work.cleanup_unconfirmed))
        self._check_deadline(deadline)  # 1: the global deadline first, whatever the stage said
        if (outcome.request_identity, tuple(outcome.window_document_ids)) != (built.request_identity, window):
            raise StepRefused("rerank_integrity", "the rerank outcome is bound to another request")  # 2
        status = outcome.status
        labels = tuple(outcome.labels)
        if status == "applied" and (not labels or len(set(labels)) != len(labels)
                                    or not set(labels) <= set(built.labels)):
            raise StepRefused("rerank_integrity", "an applied ranking outside the window")  # 3
        reason = None if status == "applied" else slug_or_none(outcome.reason)
        if status == "applied" and local is not None and time.monotonic() >= local:
            # 4: a ranking returned after the local sub-deadline (e.g. after synchronous bookkeeping) is never used.
            status, reason = "timeout", "late_result"
        if status == "timeout_candidate":
            status = "timeout"  # 4: the local sub-deadline, with the global deadline alive (checked above)
        elif status == "integrity":
            raise StepRefused("rerank_integrity", slug_or_none(outcome.reason))  # 5
        elif status == "run_not_active":
            raise StepRefused("run_not_active")
        elif status != "applied" and status not in FALLBACK_STATUSES:
            raise StepRefused("rerank_integrity", "an unknown rerank status")
        if self.stop_on_budget and status in {"budget", "contract_block", "count_failed"}:
            raise InvestigationStop(StopDetails(reason=stop_reason(reason),
                cleanup_unconfirmed=work.cleanup_unconfirmed))
        if status != "applied" and config.policy == "refuse":
            raise StepRefused("rerank_unavailable", status)  # 6
        ranked = reorder(fused, window, labels) if status == "applied" else list(fused)  # 7
        try:
            trace = RerankTrace.model_validate({
                "status": status, "reason": reason,
                "model": model, "prompt_sha256": PROMPT_SHA256, "request_identity": built.request_identity,
                "input_sha256": built.input_sha256, "max_output_tokens": config.max_output_tokens,
                "excerpts_truncated": built.excerpts_truncated, "window": len(window),
                "order": tuple(f.document_id for f in ranked[:len(window)]), "attempts": tuple(outcome.attempts)})
        except ValidationError:
            raise StepRefused("rerank_integrity", "the rerank outcome is not recordable") from None
        return ranked, trace

    # -- query vector ----------------------------------------------------------------------------------------------

    async def _query_vector(self, query: RetrievalQuery, deadline: float,
                            work: _Work) -> tuple[tuple[float, ...], int, UUID | None]:
        config = query.config
        config_digest = request_config_sha256(config.embedding_model, config.embedding_dimensions)
        digest = input_sha256(query.text)
        prepared = self._prepared(query, deadline)  # pure: the identity this step's query job must have
        job = self.store.find_step_job(subject_for(query.run_id, query.step))
        if job is None:
            cached = self.embeddings.cached(config_digest, [digest]).get(digest)
            if cached is not None:
                if not valid_vector(cached):
                    raise StepRefused("query_vector_invalid")
                return cached, 0, None
        else:
            identity = prepared.identity
            if (job.purpose, job.subject_key, job.input_set_sha256, job.input_count, job.request_config_sha256,
                    job.tokenizer_sha256) != (identity.purpose, identity.subject_key, identity.input_set_sha256,
                                              identity.input_count, identity.request_config_sha256,
                                              identity.tokenizer_sha256):
                raise StepRefused("step_conflict", "the step's existing query job has another identity")
            if self._settled(job):
                cached = self.embeddings.cached(config_digest, [digest]).get(digest)
                if cached is None:
                    raise _Unavailable("missing_vector", job_id=job.job_id)
                if not valid_vector(cached):
                    raise StepRefused("query_vector_invalid")
                return cached, 0, job.job_id
        return await self._embed(query, prepared, deadline, work)

    @staticmethod
    def _settled(job: StepJob) -> bool:
        """Settled by the ledger, not by a label: every batch satisfied by the cache, or published with its attempt
        settled. A held, unresolved or released attempt is not settled. A complete job with no batch (its input was
        already cached when it was planned) has no attempt at all and is settled."""
        if not job.batch_states:
            return job.state == "complete"
        return all(state == "satisfied_by_cache" or (state == "published" and attempt == "settled")
                   for state, attempt in zip(job.batch_states, job.attempt_states, strict=True))

    def _prepared(self, query: RetrievalQuery, deadline: float) -> PreparedJob:
        job_input = EmbeddingJob(purpose=QUERY_PURPOSE, subject_key=subject_for(query.run_id, query.step),
                                 inputs=(query.text,))
        return prepare_job(job_input, self.ledger.configuration, self.tokenizer, deadline=deadline)

    async def _embed(self, query: RetrievalQuery, prepared: PreparedJob, deadline: float,
                     work: _Work) -> tuple[tuple[float, ...], int, UUID | None]:
        limits = EmbedLimits(lease_seconds=self.limits.lease_seconds, wait_seconds=self.limits.wait_seconds,
                             poll_seconds=self.limits.poll_seconds, attempt_seconds=self.limits.attempt_seconds)
        try:
            report = await run_job(self.ledger, self.embeddings, self._providers_once(), prepared,
                                   deadline=deadline, limits=limits, run_id=query.run_id)
        except JobConflict:
            raise StepRefused("step_conflict", "the step's query job holds another input") from None
        except BindingMismatch:
            raise StepRefused("embedding_integrity", "binding mismatch") from None
        work.embedding_requests = report.physical_requests  # known even when the outcome below refuses
        return self._interpret(report)

    def _providers_once(self) -> Providers:
        return self.providers()

    def _interpret(self, report: JobReport) -> tuple[tuple[float, ...], int, UUID | None]:
        requests, job_id = report.physical_requests, report.job_id
        if self.stop_on_budget and any(b.state == "unresolved" for b in report.batches):
            raise InvestigationStop(StopDetails(reason=StopReason.USAGE_UNCONFIRMED, usage_unconfirmed=True,
                cleanup_unconfirmed=any(b.cleanup_confirmed is False for b in report.batches)))
        if report.status == "complete" and len(report.vectors) == 1:
            vector = report.vectors[0].vector
            if not valid_vector(vector):
                raise StepRefused("query_vector_invalid")
            return vector, requests, report.job_id
        if report.status == "deadline":
            raise StepRefused("deadline_passed")
        if report.status == "in_progress_elsewhere":
            raise StepRefused("step_in_progress")
        if self.stop_on_budget and (report.status == "budget"
                or report.reason in {"blocked_by_contract", "blocked_by_overrun", "count_rejected"}):
            raise InvestigationStop(StopDetails(reason=stop_reason(report.reason)))
        if report.status == "budget":
            raise _Unavailable("budget", requests=requests, job_id=job_id)
        if report.reason == "run_not_active":
            raise StepRefused("run_not_active")
        states = {b.state for b in report.batches}
        if "vectors_invalid" in states:
            raise _Unavailable("vectors_invalid", requests=requests, job_id=job_id)
        if states & {"unresolved", "orphaned"}:
            raise _Unavailable("unresolved", requests=requests, job_id=job_id)
        if report.status == "complete":  # complete without exactly one vector: never guess
            raise StepRefused("embedding_integrity", "a completed query job has no single vector")
        raise StepRefused("embedding_integrity", f"query job {report.status}/{report.reason}")

    # -- trace payload ---------------------------------------------------------------------------------------------

    @staticmethod
    def _candidates(query: RetrievalQuery, request: str, snapshot: Snapshot, fused: Sequence[Fused],
                    delivery: Delivery, unavailable: DenseUnavailable | None, dense_used: bool,
                    rerank: RerankTrace | None = None) -> TraceCandidates:
        mode = query.config.mode

        def documents(hits: Sequence[Hit]) -> tuple[BranchDocument, ...]:
            return tuple(BranchDocument(document_id=h.document_id, rank=h.rank, score=h.score, chunk_ids=h.chunk_ids)
                         for h in hits)

        delivered = tuple(DeliveredChunk(
            evidence_number=n, chunk_id=c.chunk_id, document_id=c.document_id,
            document_version_id=c.document_version_id,
            version_number=c.version_number, start=c.start, end=c.end, heading=c.heading,
            text_sha256=hashlib.sha256(c.text.encode("utf-8")).hexdigest()) for n, c in enumerate(delivery.chunks, 1))
        dense_status: DenseStatus = "ok" if dense_used else ("unavailable" if unavailable else "not_used")
        body = TraceCandidates(
            request_sha256=request, generation_id=snapshot.generation_id, mode=mode,
            lexical_status=snapshot.lexical_status if mode in ("lexical", "hybrid") else "not_used",
            dense_status=dense_status, dense_unavailable=unavailable,
            lexical=documents(snapshot.lexical), dense=documents(snapshot.dense),
            fused=tuple(FusedDocument(document_id=f.document_id, rank=f.rank, rrf=fraction_text(f.rrf),
                                      lexical_rank=f.lexical_rank, dense_rank=f.dense_rank) for f in fused),
            delivered=delivered, evidence_tokens=delivery.evidence_tokens,
            evidence_text_sha256=hashlib.sha256(delivery.evidence_text.encode("utf-8")).hexdigest(),
            admission_attempts=delivery.admission_attempts,
            exclusions=Exclusions(dense_nan_distance=snapshot.dense_nan_distance,
                                  text_oversized=snapshot.text_oversized, count_refused=delivery.count_refused),
            rerank=rerank, payload_sha256="0" * 64)
        return body.model_copy(update={"payload_sha256": body.computed_payload_sha256()})

    def _result(self, query: RetrievalQuery, trace_id: UUID, candidates: TraceCandidates, chunks: Sequence[ChunkRow],
                evidence_text: str, *, replayed: bool, current: bool, work: _Work) -> RetrievalResult:
        evidence = tuple(EvidenceChunk(
            evidence_id=f"E{n}", chunk_id=c.chunk_id, document_id=c.document_id,
            document_version_id=c.document_version_id, source_uri=c.source_uri, version_number=c.version_number,
            heading=c.heading, start=c.start, end=c.end, text=c.text) for n, c in enumerate(chunks, 1))
        return RetrievalResult(
            trace_id=trace_id, run_id=query.run_id, step=query.step, generation_id=candidates.generation_id,
            generation_current=current, replayed=replayed, mode=candidates.mode,
            lexical_status=candidates.lexical_status, dense_status=candidates.dense_status,
            dense_unavailable=candidates.dense_unavailable, lexical=candidates.lexical, dense=candidates.dense,
            fused=candidates.fused, evidence=evidence, evidence_text=evidence_text,
            evidence_tokens=candidates.evidence_tokens, config_sha256=self._config_sha256(query),
            request_sha256=candidates.request_sha256, payload_sha256=candidates.payload_sha256,
            provider_requests=work.embedding_requests, rerank=_summary(candidates.rerank),
            invocation=work.invocation() if query.config.rerank is not None else None)

    # -- replay ----------------------------------------------------------------------------------------------------

    def _replay(self, query: RetrievalQuery, stored: StoredTrace, request: str, deadline: float,
                work: _Work) -> RetrievalResult | RetrievalRefused:
        """Rebuild and verify a stored trace. `work` is what this very invocation already did before it lost a
        same-step trace race (nothing for an ordinary audit replay); the stored trace's own history is never counted
        as this invocation's work."""
        self._check_deadline(deadline)  # the trace read has returned
        checked = verify_record(stored, run_id=query.run_id, expected_request=request,
                                expected_query_sha256=query.query_sha256())
        if isinstance(checked, TraceProblem):
            return _refused(checked.code, checked.detail)
        candidates = checked.candidates
        spans = self.store.spans(span_entries(candidates))
        self._check_deadline(deadline)
        evidence = verify_evidence(candidates, spans)
        if isinstance(evidence, TraceProblem):
            return _refused(evidence.code, evidence.detail)
        chunks, evidence_text = evidence
        self._check_deadline(deadline)
        current = self.store.pointer(query.scope.corpus_key) == candidates.generation_id
        self._check_deadline(deadline)
        return self._result(query, trace_id_for(self.workspace_id, query.run_id, query.step), candidates, chunks,
                            evidence_text, replayed=True, current=current, work=work)


def _summary(trace: RerankTrace | None) -> RerankSummary | None:
    if trace is None:
        return None
    return RerankSummary(status=trace.status, applied=trace.status == "applied", reason=trace.reason,
                         model=trace.model, order=trace.order, attempts=trace.attempts)


def worst_case_trace(query: RetrievalQuery) -> tuple[str, str]:
    """A trace JSON pair shaped like the largest this configuration can produce (maximum cardinalities, 4-byte
    characters in headings, maximum-length scores and fractions, and with reranking a full rerank record), measured by
    the database before any paid work. A measured bound with margin, not a proof for every input; the actual sizes are
    checked again at write time. Without reranking it is exactly the T13 pair."""
    config = query.config
    zero = UUID(int=0)
    ranked = config.mode != "full_policy"
    branch = tuple(BranchDocument(document_id=zero, rank=1000, score="-1234567890123456.12345678901234567890",
                                  chunk_ids=(zero,) * config.chunks_per_document)
                   for _ in range(config.branch_documents)) if ranked else ()
    fused = tuple(FusedDocument(document_id=zero, rank=1000, rrf="9" * 41 + "/" + "9" * 61, lexical_rank=1000,
                                dense_rank=1000) for _ in range(2 * config.branch_documents)) if ranked else ()
    delivered_count = config.max_chunks if ranked else config.full_policy_max_chunks
    delivered = tuple(DeliveredChunk(evidence_number=16, chunk_id=zero, document_id=zero, document_version_id=zero,
                                     version_number=2**53, start=2**31 - 2, end=2**31 - 1, heading="\U0001f600" * 500,
                                     text_sha256="f" * 64) for _ in range(delivered_count))
    longest_model: RerankModel = max(get_args(RerankModel), key=len)
    rerank = None if config.rerank is None or not ranked else RerankTrace(
        status="skipped_few_candidates", reason="a" * 64, model=longest_model, prompt_sha256="f" * 64,
        request_identity="f" * 64, input_sha256="f" * 64, max_output_tokens=1024,
        excerpts_truncated=MAX_RERANK_DOCUMENTS, window=MAX_RERANK_DOCUMENTS,
        order=(zero,) * MAX_RERANK_DOCUMENTS, attempts=(RerankAttempt(attempt_id=zero, fate="not_reserved",
                                                                      cleanup_confirmed=False),))
    candidates = TraceCandidates(
        request_sha256="f" * 64, generation_id=zero, mode=config.mode, lexical_status="empty_query",
        dense_status="unavailable", dense_unavailable="vectors_invalid", lexical=branch, dense=branch, fused=fused,
        delivered=delivered, evidence_tokens=16000, evidence_text_sha256="f" * 64, admission_attempts=256,
        exclusions=Exclusions(dense_nan_distance=10_000, text_oversized=10_000, count_refused=256),
        rerank=rerank, payload_sha256="f" * 64)
    scope = TraceScope(corpus_key="a" * 64, step=9999, allowlist_sha256="f" * 64, document_ids=(zero,) * 32,
                       config_sha256="f" * 64, query_sha256="f" * 64, embedding_job_id=zero)
    return scope.model_dump_json(), candidates.model_dump_json()
