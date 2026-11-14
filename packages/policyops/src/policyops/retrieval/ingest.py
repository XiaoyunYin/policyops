"""Corpus import orchestration (T12): verify, parse, check for a repeat, embed only cache misses, publish.

**Modes.** `plan` (the default) is read-only: it verifies the manifest and files, parses, builds the expected set,
compares it with the active generation, looks up the embedding cache and any existing job, and estimates the
remaining provider work. It writes nothing, reserves nothing, reads no credential and sends nothing. `execute`
allows writes. Provider work (at least one cache miss) additionally needs explicit paid caps (`PaidCaps`): model,
dimensions, USD, calls, input tokens and seconds, each bounded by `CEILINGS`. Without them an execute with misses is
refused before any write. An all-cached import publishes locally without paid caps.
`preflight` builds the same expected set and packs all distinct inputs assuming an empty cache, checks explicit
caps, and returns before any database connection, credential read or request.

**Paid preflight** (before any credential read, reservation or request), over the complete remaining miss plan
(the frozen plan of an existing job, otherwise the plan the foundation would freeze):
- batches times the actor's worst-case reservation within `max_usd`; batches within `max_calls`;
- `max_input_tokens` is a cumulative job budget: the frozen plan's total local tokens (every batch, attempted,
  published or held, not only the remaining ones) must be within it. The immutable plan fixes the effective budget;
  a larger requested ceiling on resume does not widen it, a smaller one refuses. The output records the requested
  ceiling, the frozen total and the remaining estimate separately; the requested ceiling itself is not persisted;
- batches times (`INGEST_LIMITS.attempt_seconds` plus `SETTLE_MARGIN_SECONDS`) within `max_seconds` and, on resume,
  the job's remaining immutable window;
- on resume, the stored job window and operation-scope caps must equal the requested caps (`resume_configuration_
  changed` otherwise: never widened, never a second job), and the scope must still have room.
The same caps are the ledger configuration used for admission (`PaidCaps.configuration`), so what is recorded is
what is enforced.

**Recovery.** A settled job (complete, or every batch published or satisfied by the cache with no held accounting,
after a crash before its final status) whose publication crashed is published from the cache with no provider call,
credential read or job change, even after its window elapsed. Cache availability alone is not enough: an existing
job that is not settled (incomplete, blocked, unresolved or orphaned batches, held accounting) goes through the gated
path even when every input happens to be cached, so an expired one is reported as `window_expired`, a terminal one
by its state, with the preserved state and the previous generation active; there is no new job and no reissue. A new
all-cached set with no job publishes locally.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from decimal import Decimal
from pathlib import Path
import time
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine

from policyops.budget.config import Caps, Configuration, EmbeddingActor
from policyops.budget.pricing import Usage, cost
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.corpora import (
    CorpusStore,
    JobRow,
    PublishRefused,
    StaleActivation,
    VerificationMismatch,
)
from policyops.persistence.embeddings import TERMINAL, EmbeddingStore, JobConflict
from policyops.providers.calls import Providers
from policyops.providers.embedding_calls import EmbedLimits, pack, prepare_job, run_job_sync
from policyops.providers.tokenizer import Tokenizer
from policyops.retrieval import archive_sources
from policyops.retrieval.corpus import CorpusRefused, Expected, build_expected
from policyops.retrieval.parse import CHUNK_CONFIG, PARSER_VERSION, ParseRefused
from policyops.retrieval.sources import SourceRefused, read_corpus
from policyops.runtime.clock import LeaseClock
from policyops_contracts.embedding import EmbeddingJob


PURPOSE = "ingestion"
OPERATION_KIND = "embedding"
INGEST_LIMITS = EmbedLimits(lease_seconds=120.0, wait_seconds=30.0, poll_seconds=0.25, attempt_seconds=30.0)
SETTLE_MARGIN_SECONDS = 10.0
PREPARE_SECONDS = 600.0
MAX_USD_CEILING = Decimal("1.00")
INT_CEILINGS: dict[str, int] = {"max_calls": 1000, "max_input_tokens": 5_120_000, "max_seconds": 3600}
CEILINGS: dict[str, str] = {"max_usd": str(MAX_USD_CEILING), **{k: str(v) for k, v in INT_CEILINGS.items()}}
Mode = Literal["plan", "execute", "preflight"]
EXIT = {"planned": 0, "unchanged": 0, "activated": 0, "refused": 2, "embedding_incomplete": 3,
        "stale_activation": 4, "verification_failed": 1, "failed": 1}


@dataclass(frozen=True)
class PaidCaps:
    model: str
    dimensions: int
    max_usd: Decimal
    max_calls: int
    max_input_tokens: int
    max_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.max_usd, Decimal) or not self.max_usd.is_finite():
            raise ValueError("max_usd must be a finite Decimal")
        exponent = self.max_usd.as_tuple().exponent
        if (self.max_usd <= 0 or self.max_usd > MAX_USD_CEILING or not isinstance(exponent, int)
                or exponent < -18):
            raise ValueError("max_usd must be a positive exact decimal within the ingestion ceiling")
        for name in ("dimensions", "max_calls", "max_input_tokens", "max_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
            if name in INT_CEILINGS and value > INT_CEILINGS[name]:
                raise ValueError(f"{name} exceeds the ingestion ceiling {INT_CEILINGS[name]}")

    def configuration(self) -> Configuration:
        """The ledger configuration actually used for admission: these caps, explicit and bounded."""
        return Configuration(caps=replace(Caps(), operation_usd=self.max_usd, operation_calls=self.max_calls,
                                          active_seconds=self.max_seconds))

    def record(self) -> dict[str, Any]:
        return {"model": self.model, "dimensions": self.dimensions, "max_usd": str(self.max_usd),
                "max_calls": self.max_calls, "max_input_tokens": self.max_input_tokens,
                "max_seconds": self.max_seconds}


@dataclass
class Outcome:
    outcome: str
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return EXIT[self.outcome]

    def to_json(self) -> dict[str, Any]:
        return {"outcome": self.outcome, "reason": self.reason, "exit_code": self.exit_code, **self.details}


@dataclass(frozen=True)
class Request:
    workspace_id: UUID
    corpus_key: str
    manifest_raw: bytes
    manifest_sha256: str
    acquisition_root: Path
    mode: Mode = "plan"
    paid: PaidCaps | None = None
    profile: Literal["markdown", "structural"] = "markdown"


def _base_actor() -> EmbeddingActor:
    actor = Configuration().actors["embedding"]
    assert isinstance(actor, EmbeddingActor)  # noqa: S101 - Configuration validates the actor type
    return actor


def ingest(request: Request, *, engine: Engine, tokenizer: Tokenizer, providers: Callable[[], Providers],
           env: str = "production", clock: LeaseClock | None = None,
           before_verify: Callable[[Connection, UUID], None] | None = None) -> Outcome:
    actor = _base_actor()
    base = Configuration()
    details: dict[str, Any] = {"mode": request.mode, "corpus_key": request.corpus_key,
                               "manifest_sha256": request.manifest_sha256, "parser": PARSER_VERSION,
                               "chunk_config": CHUNK_CONFIG, "ceilings": CEILINGS,
                               "paid": request.paid.record() if request.paid else None,
                               "price_revision": base.reservation("embedding").price_revision}
    if request.paid is not None and (request.paid.model, request.paid.dimensions) != (actor.model, actor.dimensions):
        return Outcome("refused", "paid_model_or_dimensions_mismatch", details)
    try:
        reader = archive_sources.read_corpus if request.profile == "structural" else read_corpus
        corpus = reader(request.manifest_raw, request.manifest_sha256, request.corpus_key, request.acquisition_root)
        expected = build_expected(corpus, tokenizer, tokenizer_sha256=tokenizer.identity_sha256, model=actor.model,
                                  dimensions=actor.dimensions, deadline=time.monotonic() + PREPARE_SECONDS)
    except (SourceRefused, CorpusRefused) as exc:
        return Outcome("refused", exc.code, details | {"detail": exc.detail})
    except ParseRefused as exc:
        return Outcome("refused", exc.code, details | {"offset": exc.offset})
    details |= {"profile": request.profile, "parser": corpus.parser_version, "chunk_config": corpus.chunk_config,
                "render": corpus.corpus.render, "corpus_manifest_sha256": corpus.corpus_manifest_sha256,
                "generation_key_sha256": expected.generation_key_sha256,
                "expected_set_sha256": expected.expected_set_sha256, "documents": len(expected.documents),
                "chunks": len(expected.chunks), "distinct_inputs": len(expected.inputs)}
    if request.mode == "preflight":
        return offline_preflight(request, expected, tokenizer, details)
    corpora = CorpusStore(engine, request.workspace_id)
    embeddings = EmbeddingStore(engine, request.workspace_id, env=env, clock=clock)
    if not corpora.workspace_visible():
        return Outcome("refused", "workspace_not_visible", details)
    snapshot = corpora.snapshot(request.corpus_key)
    if snapshot.exists and snapshot.domain != corpus.corpus.domain:
        return Outcome("refused", "corpus_domain_conflict", details)
    if snapshot.active_generation_key_sha256 == expected.generation_key_sha256:
        return Outcome("unchanged", None, details | {"generation_id": str(snapshot.active_generation_id)})
    digests: dict[str, str] = {}
    for chunk in expected.chunks:  # the same first-occurrence order as `expected.inputs`
        digests.setdefault(chunk.embed_input, chunk.embed_input_sha256)
    cached = embeddings.cached(expected.request_config_sha256, list(digests.values()))
    misses = [text for text, digest in digests.items() if digest not in cached]
    job = corpora.find_job(PURPOSE, expected.subject_key)
    details |= {"cached_inputs": len(expected.inputs) - len(misses), "missing_inputs": len(misses),
                "job_id": str(job.id) if job else None}
    if job is not None and (job.request_config_sha256, job.tokenizer_sha256) != (expected.request_config_sha256,
                                                                                 expected.tokenizer_sha256):
        return Outcome("refused", "job_identity_conflict", details)
    # Cache availability (possibly from another job) does not show that this set's own job finished: an existing
    # job must be settled before a cache-only publication, otherwise it goes through the same gated path.
    if misses or (job is not None and not _job_settled(job, embeddings, corpora)):
        stopped = _provider_work(request, expected, tokenizer, set(misses), job, embeddings, corpora, engine,
                                 providers, env, clock, details)
        if stopped is not None:
            return stopped
        cached = embeddings.cached(expected.request_config_sha256, list(digests.values()))
        if len(cached) != len(digests):
            return Outcome("embedding_incomplete", "vectors_unavailable",
                           details | {"missing_inputs": len(digests) - len(cached)})
    elif request.mode == "plan":
        return Outcome("planned", None, details | {"estimate": _estimate(0, 0)})
    try:
        result = corpora.publish(expected, {digest: cached[digest] for digest in digests.values()}, snapshot,
                                 before_verify=before_verify)
    except StaleActivation:
        return Outcome("stale_activation", "corpus_changed", details)
    except PublishRefused as exc:
        return Outcome("refused", exc.code, details | {"detail": exc.detail})
    except VerificationMismatch as exc:
        return Outcome("verification_failed", exc.code, details)
    return Outcome("activated", None, details | {
        "generation_id": str(result.generation_id),
        "retired_generation_id": str(result.retired_generation_id) if result.retired_generation_id else None,
        "documents_new": result.documents_new, "documents_reused": result.documents_reused,
        "versions_new": result.versions_new, "versions_reused": result.versions_reused,
        "inserted_text_bytes": result.inserted_text_bytes,
        "inserted_vector_text_bytes": result.inserted_vector_text_bytes,
        "seconds": {k: round(v, 6) for k, v in result.seconds.items()}})


def _estimate(batches: int, tokens: int) -> dict[str, Any]:
    worst = Configuration().reservation("embedding").worst_usd
    return {"batches": batches, "local_tokens": tokens,
            "local_estimated_usd": str(cost(Configuration().price("embedding"), Usage(tokens)).usd),
            "worst_usd": str(worst * batches),
            "worst_seconds": batches * (INGEST_LIMITS.attempt_seconds + SETTLE_MARGIN_SECONDS)}


def offline_preflight(request: Request, expected: Expected, tokenizer: Tokenizer, details: dict[str, Any]) -> Outcome:
    """Conservative empty-cache plan through the actual packer; no database/credentials/provider access."""
    prepared = prepare_job(EmbeddingJob(purpose=PURPOSE, subject_key=expected.subject_key, inputs=expected.inputs),
                           Configuration(), tokenizer, deadline=time.monotonic() + PREPARE_SECONDS)
    plans = pack(prepared, Configuration())(uuid4(), frozenset())
    tokens = sum(p.local_tokens for p in plans)
    estimate = _estimate(len(plans), tokens)
    details |= {"offline": True, "cache_assumption": "empty", "estimate": estimate,
                "all_passage_tokens": sum(c.tokens for c in expected.chunks)}
    paid = request.paid
    if paid is None:
        return Outcome("refused", "preflight_requires_explicit_caps", details)
    checks = {"usd": Decimal(estimate["worst_usd"]) <= paid.max_usd,
              "calls": len(plans) <= paid.max_calls, "tokens": tokens <= paid.max_input_tokens,
              "seconds": estimate["worst_seconds"] <= paid.max_seconds}
    details["within_caps"] = checks
    return Outcome("planned" if all(checks.values()) else "refused",
                   None if all(checks.values()) else "preflight_exceeds_caps", details)


SETTLED_BATCH_STATES = frozenset({"published", "satisfied_by_cache"})


def _job_settled(job: JobRow, embeddings: EmbeddingStore, corpora: CorpusStore) -> bool:
    """Complete, or (after a crash before its final status) every batch published or satisfied by the cache with no
    held accounting: a local, read-only reconciliation that needs no credential and no deadline change."""
    if job.state == "complete":
        return True
    if not set(corpora.batch_states(job.id)) <= SETTLED_BATCH_STATES:
        return False
    scope = embeddings.operation_scope(OPERATION_KIND, str(job.id))
    return scope is None or (scope.held_usd == 0 and scope.calls_held == 0 and scope.contract_block is None)


def _state(embeddings: EmbeddingStore, corpora: CorpusStore, job_id: UUID) -> dict[str, Any]:
    scope = embeddings.operation_scope(OPERATION_KIND, str(job_id))
    return {"batch_states": corpora.batch_states(job_id),
            "scope": None if scope is None else {
                "cap_usd": str(scope.cap_usd), "cap_calls": scope.cap_calls, "spent_usd": str(scope.spent_usd),
                "held_usd": str(scope.held_usd), "calls_consumed": scope.calls_consumed,
                "calls_held": scope.calls_held, "contract_block": scope.contract_block}}


def _provider_work(request: Request, expected: Expected, tokenizer: Tokenizer, misses: set[str], job: JobRow | None,
                   embeddings: EmbeddingStore, corpora: CorpusStore, engine: Engine,
                   providers: Callable[[], Providers], env: str, clock: LeaseClock | None,
                   details: dict[str, Any]) -> Outcome | None:
    """Plan, gate and run the remaining provider work; None when the job completed and publication may follow."""
    base = Configuration()
    job_input = EmbeddingJob(purpose=PURPOSE, subject_key=expected.subject_key, inputs=expected.inputs)
    remaining: float | None = None
    if job is not None:
        batches = embeddings.batches(job.id)
        open_batches = [b for b in batches if b.state not in TERMINAL]
        fresh = embeddings.unreserved([b.plan.attempt_id for b in open_batches])
        pending = [b.plan for b in open_batches if b.plan.attempt_id in fresh]
        details |= _state(embeddings, corpora, job.id) | {"job_state": job.state}
        if not open_batches:
            return Outcome("embedding_incomplete", "job_" + job.state, details)
        remaining = embeddings.remaining_seconds(job.id)
        details["job_remaining_seconds"] = round(remaining, 3)
        if remaining <= 0:
            return Outcome("embedding_incomplete", "window_expired", details)
        batch_count, tokens = len(pending), sum(p.local_tokens for p in pending)
        # The immutable frozen plan fixes the job's effective local-token budget: all batches, attempted or not.
        frozen_tokens = sum(b.plan.local_tokens for b in batches)
    else:
        prepared = prepare_job(job_input, base, tokenizer, deadline=time.monotonic() + PREPARE_SECONDS)
        cached = frozenset(c.embed_input_sha256 for c in expected.chunks if c.embed_input not in misses)
        plans = pack(prepared, base)(uuid4(), cached)  # an estimate only, never persisted
        batch_count, tokens = len(plans), sum(p.local_tokens for p in plans)
        frozen_tokens = tokens
    estimate = _estimate(batch_count, tokens) | {
        "frozen_total_local_tokens": frozen_tokens,
        "requested_token_ceiling": request.paid.max_input_tokens if request.paid else None}
    details["estimate"] = estimate
    if request.mode == "plan":
        return Outcome("planned", None, details)
    paid = request.paid
    if paid is None:
        if job is not None and batch_count == 0:  # only reserved (unresolved, orphaned or in-flight) work remains
            return Outcome("embedding_incomplete", "batches_unresolved", details)
        return Outcome("refused", "paid_execution_not_authorized", details)
    worst = base.reservation("embedding").worst_usd
    window = float(paid.max_seconds) if remaining is None else min(float(paid.max_seconds), remaining)
    if worst * batch_count > paid.max_usd:
        return Outcome("refused", "plan_exceeds_usd_cap", details)
    if batch_count > paid.max_calls:
        return Outcome("refused", "plan_exceeds_call_cap", details)
    if frozen_tokens > paid.max_input_tokens:  # cumulative: a resume cannot lower it below work already planned
        return Outcome("refused", "plan_exceeds_token_cap", details)
    if batch_count * (INGEST_LIMITS.attempt_seconds + SETTLE_MARGIN_SECONDS) > window:
        return Outcome("refused", "plan_exceeds_job_window", details)
    if job is not None:
        if round(job.window_seconds) != paid.max_seconds:
            return Outcome("refused", "resume_configuration_changed", details)
        scope = embeddings.operation_scope(OPERATION_KIND, str(job.id))
        if scope is not None:
            if (scope.cap_usd, scope.cap_calls) != (paid.max_usd, paid.max_calls):
                return Outcome("refused", "resume_configuration_changed", details)
            if (scope.cap_usd - scope.spent_usd - scope.held_usd < worst * batch_count
                    or scope.cap_calls - scope.calls_consumed - scope.calls_held < batch_count):
                return Outcome("refused", "plan_exceeds_scope_budget", details)
    configuration = paid.configuration()
    ledger = build_app_ledger(env=env, engine=engine, workspace_id=request.workspace_id,
                              configuration=configuration, clock=clock)
    prepared = prepare_job(job_input, configuration, tokenizer, deadline=time.monotonic() + PREPARE_SECONDS)
    try:
        report = run_job_sync(ledger, embeddings, providers(), prepared,
                              deadline=time.monotonic() + paid.max_seconds, limits=INGEST_LIMITS)
    except JobConflict:
        return Outcome("refused", "job_identity_conflict", details)
    details |= {"job_id": str(report.job_id), "physical_requests": report.physical_requests,
                "job_status": report.status}
    if report.job_id is not None:
        details |= _state(embeddings, corpora, report.job_id)
    if report.status != "complete":
        return Outcome("embedding_incomplete", report.reason or report.status, details)
    return None
