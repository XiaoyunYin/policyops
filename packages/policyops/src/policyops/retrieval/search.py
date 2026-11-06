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
7. **Trace** with its deterministic ID. On a conflict (a concurrent same-step writer), the stored trace is reread and
   verified like a replay, and returned.

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
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ValidationError
from sqlalchemy import Engine

from policyops.budget.ledger import Ledger
from policyops.persistence.embeddings import EmbeddingStore, JobConflict, vector_text
from policyops.persistence.retrieval import RetrievalStore, Snapshot, StepJob, StepRefused, StoredTrace
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
from policyops_contracts.embedding import EmbeddingJob
from policyops_contracts.retrieval import (
    BranchDocument,
    DeliveredChunk,
    DenseStatus,
    DenseUnavailable,
    EvidenceChunk,
    Exclusions,
    FusedDocument,
    RetrievalQuery,
    RetrievalRefused,
    RetrievalResult,
    TraceCandidates,
    TraceScope,
    canonical_sha256,
)


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


@dataclass(frozen=True)
class RetrieverLimits:
    lease_seconds: float = 60.0
    wait_seconds: float = 10.0
    poll_seconds: float = 0.1
    attempt_seconds: float = 30.0


class Retriever:
    """The retrieval component for one workspace. `ledger` must be the app ledger of this workspace on `engine`
    (the foundation checks it); `providers` is called only when a provider request may be needed."""

    def __init__(self, engine: Engine, workspace_id: UUID, *, embeddings: EmbeddingStore, ledger: Ledger,
                 providers: Callable[[], Providers], tokenizer: Tokenizer,
                 limits: RetrieverLimits | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        # The composed boundary, checked before any read, cache use or write: the embedding store and the app
        # ledger must be this workspace's own components on this very engine (not merely consistent with each other).
        if embeddings.engine is not engine or embeddings.workspace_id != workspace_id:
            raise BindingMismatch("the embedding store belongs to another engine or workspace")
        check_binding(ledger, embeddings)  # the app ledger of the same workspace on the same engine
        self.store = RetrievalStore(engine, workspace_id)
        self.workspace_id = workspace_id
        self.embeddings, self.ledger, self.providers, self.tokenizer = embeddings, ledger, providers, tokenizer
        self.limits = limits or RetrieverLimits()
        self.clock = clock

    # -- entry point -----------------------------------------------------------------------------------------------

    async def retrieve(self, query: RetrievalQuery, *, deadline: float) -> RetrievalResult | RetrievalRefused:
        # A NaN would make every `clock() >= deadline` check false: refuse before any read, write, count or request.
        if isinstance(deadline, bool) or not isinstance(deadline, int | float) or not math.isfinite(deadline):
            return _refused("deadline_invalid")
        try:
            return await self._retrieve(query, float(deadline))
        except StepRefused as refused:
            return _refused(refused.code, refused.detail)
        except (DeadlinePassed, EvidenceDeadline):
            return _refused("deadline_passed")

    def _check_deadline(self, deadline: float) -> None:
        if self.clock() >= deadline:
            raise StepRefused("deadline_passed")

    async def _retrieve(self, query: RetrievalQuery, deadline: float) -> RetrievalResult | RetrievalRefused:
        self._check_deadline(deadline)
        try:
            if self.tokenizer.count(query.text) > MAX_QUERY_TOKENS:
                return _refused("query_too_many_tokens")
        except InputRefused:
            return _refused("query_invalid_text")
        config = query.config
        trace_id = trace_id_for(self.workspace_id, query.run_id, query.step)
        request = query.request_sha256()
        stored = self.store.find_trace(trace_id)
        if stored is not None:
            return self._replay(query, stored, request, deadline)
        self._check_deadline(deadline)
        intent = self.store.create_intent(
            run_id=query.run_id, step=query.step, trace_id=trace_id, request_sha256=request,
            query_sha256=query.query_sha256(), scope_sha256=query.scope.sha256(), config_sha256=config.sha256(),
            corpus_key=query.scope.corpus_key, allowlist=query.scope.document_allowlist,
            full_policy=config.mode == "full_policy", worst_case=worst_case_trace(query))
        self._check_deadline(deadline)
        vector: tuple[float, ...] | None = None
        unavailable: DenseUnavailable | None = None
        requests = 0
        job_id: UUID | None = None
        if config.mode in ("dense", "hybrid"):
            try:
                vector, requests, job_id = await self._query_vector(query, deadline)
            except _Unavailable as missing:
                if config.mode == "dense" or config.dense_policy == "refuse":
                    return _refused("embedding_unavailable", missing.reason)
                unavailable, requests, job_id = missing.reason, missing.requests, missing.job_id
        self._check_deadline(deadline)
        snapshot = self.store.snapshot(
            corpus_key=query.scope.corpus_key, mode=config.mode,
            query=query.text if config.mode in ("lexical", "hybrid") else "",
            query_vector=vector_text(vector) if vector is not None else None, document_ids=intent.document_ids,
            branch_documents=config.branch_documents, chunks_per_document=config.chunks_per_document,
            full_policy_max_chunks=config.full_policy_max_chunks)
        if vector is not None and (snapshot.embedding_model, snapshot.dimension, snapshot.request_config_sha256) != (
                config.embedding_model, config.embedding_dimensions,
                request_config_sha256(config.embedding_model, config.embedding_dimensions)):
            return _refused("embedding_integrity", "the generation's embedding configuration differs")
        self._check_deadline(deadline)
        counter = EvidenceCounter(self.tokenizer, deadline=deadline, clock=self.clock)
        fused: list[Fused] = []
        if config.mode == "full_policy":
            try:
                delivery = deliver_full_policy(list(snapshot.rows.values()), config, counter)
            except FullPolicyRefused as refused:
                return _refused(refused.code)
        else:
            fused = fuse(snapshot.lexical, snapshot.dense, config.rrf_k)
            delivery = deliver(fused, snapshot.rows, config, counter)
        candidates = self._candidates(query, request, snapshot, fused, delivery, unavailable, vector is not None)
        scope = TraceScope(corpus_key=query.scope.corpus_key, step=query.step,
                           allowlist_sha256=canonical_sha256(list(query.scope.document_allowlist)),
                           document_ids=intent.document_ids, config_sha256=config.sha256(),
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
            return self._replay(query, stored, request, deadline, requests)  # this invocation's own known requests
        # Observed after the trace write, outside the snapshot: a later activation can always follow. This is an
        # observation for the caller, never authorization or current-policy validation.
        current = self.store.pointer(query.scope.corpus_key) == snapshot.generation_id
        self._check_deadline(deadline)
        return self._result(query, trace_id, candidates, delivery.chunks, delivery.evidence_text, replayed=False,
                            current=current, requests=requests)

    # -- query vector ----------------------------------------------------------------------------------------------

    async def _query_vector(self, query: RetrievalQuery, deadline: float) -> tuple[tuple[float, ...], int, UUID | None]:
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
        return await self._embed(query, prepared, deadline)

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

    async def _embed(self, query: RetrievalQuery, prepared: PreparedJob,
                     deadline: float) -> tuple[tuple[float, ...], int, UUID | None]:
        limits = EmbedLimits(lease_seconds=self.limits.lease_seconds, wait_seconds=self.limits.wait_seconds,
                             poll_seconds=self.limits.poll_seconds, attempt_seconds=self.limits.attempt_seconds)
        try:
            report = await run_job(self.ledger, self.embeddings, self._providers_once(), prepared,
                                   deadline=deadline, limits=limits, run_id=query.run_id)
        except JobConflict:
            raise StepRefused("step_conflict", "the step's query job holds another input") from None
        except BindingMismatch:
            raise StepRefused("embedding_integrity", "binding mismatch") from None
        return self._interpret(report)

    def _providers_once(self) -> Providers:
        return self.providers()

    def _interpret(self, report: JobReport) -> tuple[tuple[float, ...], int, UUID | None]:
        requests, job_id = report.physical_requests, report.job_id
        if report.status == "complete" and len(report.vectors) == 1:
            vector = report.vectors[0].vector
            if not valid_vector(vector):
                raise StepRefused("query_vector_invalid")
            return vector, requests, report.job_id
        if report.status == "deadline":
            raise StepRefused("deadline_passed")
        if report.status == "in_progress_elsewhere":
            raise StepRefused("step_in_progress")
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
                    delivery: Delivery, unavailable: DenseUnavailable | None, dense_used: bool) -> TraceCandidates:
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
            payload_sha256="0" * 64)
        return body.model_copy(update={"payload_sha256": body.computed_payload_sha256()})

    def _result(self, query: RetrievalQuery, trace_id: UUID, candidates: TraceCandidates, chunks: Sequence[ChunkRow],
                evidence_text: str, *, replayed: bool, current: bool, requests: int) -> RetrievalResult:
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
            evidence_tokens=candidates.evidence_tokens, config_sha256=query.config.sha256(),
            request_sha256=candidates.request_sha256, payload_sha256=candidates.payload_sha256,
            provider_requests=requests)

    # -- replay ----------------------------------------------------------------------------------------------------

    def _replay(self, query: RetrievalQuery, stored: StoredTrace, request: str, deadline: float,
                requests: int = 0) -> RetrievalResult | RetrievalRefused:
        """Rebuild and verify a stored trace. `requests` is the number of embedding requests this very invocation
        already made before it lost a same-step trace race (0 for an ordinary audit replay); the stored trace's own
        history is never counted here."""
        self._check_deadline(deadline)  # the trace read has returned
        try:
            candidates = TraceCandidates.model_validate_json(stored.candidates)
            TraceScope.model_validate_json(stored.authorized_scope)
        except ValidationError:
            return _refused("replay_unsupported", "the stored trace is not a supported retrieval trace")
        if stored.intent_request_sha256 is None:
            return _refused("replay_unsupported", "the stored trace has no recorded intent")
        if stored.intent_request_sha256 != request or candidates.request_sha256 != request:
            return _refused("step_conflict", "this step already holds a different request")
        if (stored.run_id, stored.generation_id, stored.query_sha256) != (query.run_id, candidates.generation_id,
                                                                         query.query_sha256()):
            return _refused("replay_integrity", "the stored trace does not match its own record")
        if candidates.computed_payload_sha256() != candidates.payload_sha256:
            return _refused("replay_integrity", "payload digest")
        if tuple(d.chunk_id for d in candidates.delivered) != stored.final_chunk_ids:
            return _refused("replay_integrity", "delivered chunk IDs")
        spans = self.store.spans([(d.document_version_id, d.start, d.end) for d in candidates.delivered])
        self._check_deadline(deadline)
        chunks: list[ChunkRow] = []
        for entry, span in zip(candidates.delivered, spans, strict=True):
            if (span is None or span.text is None or not span.body_digest_ok or span.document_id != entry.document_id
                    or span.version_number != entry.version_number
                    or hashlib.sha256(span.text.encode("utf-8")).hexdigest() != entry.text_sha256):
                return _refused("replay_integrity", f"evidence E{entry.evidence_number}")
            chunks.append(ChunkRow(entry.chunk_id, entry.document_id, entry.document_version_id, span.source_uri,
                                   entry.version_number, entry.heading, entry.start, entry.end, span.text))
        evidence_text = assemble(chunks)
        if hashlib.sha256(evidence_text.encode("utf-8")).hexdigest() != candidates.evidence_text_sha256:
            return _refused("replay_integrity", "evidence text digest")
        self._check_deadline(deadline)
        current = self.store.pointer(query.scope.corpus_key) == candidates.generation_id
        self._check_deadline(deadline)
        return self._result(query, trace_id_for(self.workspace_id, query.run_id, query.step), candidates, chunks,
                            evidence_text, replayed=True, current=current, requests=requests)


def worst_case_trace(query: RetrievalQuery) -> tuple[str, str]:
    """A trace JSON pair shaped like the largest this configuration can produce (maximum cardinalities, 4-byte
    characters in headings, maximum-length scores and fractions), measured by the database before any paid work.
    A measured bound with margin, not a proof for every input; the actual sizes are checked again at write time."""
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
    candidates = TraceCandidates(
        request_sha256="f" * 64, generation_id=zero, mode=config.mode, lexical_status="empty_query",
        dense_status="unavailable", dense_unavailable="vectors_invalid", lexical=branch, dense=branch, fused=fused,
        delivered=delivered, evidence_tokens=16000, evidence_text_sha256="f" * 64, admission_attempts=256,
        exclusions=Exclusions(dense_nan_distance=10_000, text_oversized=10_000, count_refused=256),
        payload_sha256="f" * 64)
    scope = TraceScope(corpus_key="a" * 64, step=9999, allowlist_sha256="f" * 64, document_ids=(zero,) * 32,
                       config_sha256="f" * 64, query_sha256="f" * 64, embedding_job_id=zero)
    return scope.model_dump_json(), candidates.model_dump_json()
