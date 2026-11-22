"""Ledger-integrated embedding jobs (T12): a persisted job, a frozen batch plan, and one accounted physical request
per batch, with exact evidence and a vector cache.

## Preparation (synchronous, before any reservation)

`prepare_job` validates the `EmbeddingJob`, counts every input with the local cl100k tokenizer (bounded per input
and per regex piece) and checks its deadline before every input and after the last one. That deadline is the
caller's, clamped to `PREPARE_SECONDS`. No asyncio timeout can interrupt this CPU work: its bounds are the
protection. The job identity binds the full intended ordered input set, the request configuration and the tokenizer.

## Binding

`run_job` refuses, before any write or request, a ledger that is not the app ledger of the embedding store's own
workspace on the same database engine.

## The plan and its deadline

`EmbeddingStore.plan_job` creates the job, all its inputs, its frozen plan and its immutable deadline
(`created_at + caps.active_seconds`, on the database clock) in one transaction, or returns the existing ones
unchanged (a different identity for the same subject is a `JobConflict`; a restart never extends the deadline). The
plan covers the distinct inputs not already cached at planning time, in first-occurrence order, packed greedily into
batches of at most 64 inputs, `EmbeddingActor.max_request_tokens` local tokens and `embeddings.MAX_REQUEST_BYTES`
UTF-8 input bytes (a new batch starts before an input that would cross any of the three). Each batch's operation is
`embed.<job>.b<ordinal>.<full batch digest>` and its ledger attempt is `uuid5(job, operation)`. An all-cached or
empty job has no batches and makes no call. Resume never re-batches.

The caller's deadline is clamped to `caps.active_seconds` from the start of this run and to the job's remaining
window. A new reservation, count or dispatch is refused once either has passed (the job window is checked on the
database clock); reconciling earlier attempts from their evidence is still allowed. The synchronous database
transactions (ledger and store) are **not** interrupted by the deadline, and no statement or lock timeout is set for
them: a transaction that waits on a row lock held elsewhere waits as long as the database lets it, and the deadline
is only checked again afterwards. Such a wait sends nothing; a dispatch still needs its ledger grant first.

## Before anything is reserved

- The OpenAI credential must be configured and no ambient SDK setting may be present: a certain local error never
  turns into an uncertain hold.
- Every planned batch without a ledger attempt must fit the operation scope's remaining USD (after spend and every
  outstanding hold), calls and counts. Otherwise nothing is reserved (`plan_exceeds_caps`). Nothing is ever reset.

## One batch

The ledger's single-winner transitions are the only permission to send: `claim_count` (once) and `begin_dispatch`
(once, and only `DispatchGranted` lets the request out). The batch lease guards job advancement only.
1. Claim the lease (a free, expired or own lease; the fence moves).
2. `reserve` (a replay returns the existing attempt). Then, by the attempt's state:
   - reserved, no count: `claim_count`; reserved, claimed: `record_count` with the **persisted** local count (an
     idempotent replay; source `local.tiktoken-cl100k`, no count request); reserved, admitted: `begin_dispatch`.
   - dispatching with evidence: settle or hold from that evidence (the earlier owner crashed after publishing).
   - dispatching without evidence: `orphaned`. The hold stays; nothing is sent, released or marked.
   - settled, unresolved or released: the batch is reconciled from its own evidence.
3. One request (`embeddings.fetch`) under the attempt cap and the job deadline. `fetch` hands over the complete body
   the moment it has arrived, before any cleanup is awaited. If a timeout or cancellation then interrupts the
   cleanup, the known bill is still classified, published and settled (and the cleanup is reported unconfirmed), and
   a cancellation is re-raised afterwards. Classification, publication and settlement are synchronous.
4. `publish` (evidence plus vectors, atomically; up to `publish_attempts` database tries, never a second request),
   then `settle` or `mark_unresolved` per the accounting table in `embeddings.py`. If publication fails, the bill is
   still settled and the batch is `orphaned`.
5. A fenced batch-state advance. A process that lost its lease keeps its billing writes but does not advance the
   batch; the next owner reconciles from the evidence.

**Releases.** A reservation is released only by the process whose own `record_count` produced the local rejection
or failure, while it still holds the batch lease. A refused claim or dispatch never releases: another live process
may own that attempt.

**Waiting.** A batch leased by another live owner is waited for (polling) for at most `wait_seconds` and the
deadline, then reported `in_progress_elsewhere`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
import math
import time
from typing import Literal
from uuid import UUID, uuid4, uuid5

from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError

from policyops.budget.config import Configuration, EmbeddingActor
from policyops.budget.ledger import (
    BudgetExhausted,
    CountGranted,
    DispatchGranted,
    Ledger,
    OperationBinding,
    RunBinding,
    Settlement,
)
from policyops.budget.pricing import cost
from policyops.persistence.budget import AppLedgerStore
from policyops.persistence.embeddings import (
    TERMINAL,
    Batch,
    BatchPlan,
    BatchState,
    EmbeddingStore,
    Evidence,
    EvidenceConflict,
    Job,
    JobIdentity,
    Lease,
    PlannedInput,
    norm_decimal,
)
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.calls import Providers
from policyops.providers.contract import ContractGap, require_clean_environment
from policyops.providers.embedding_contract import request_config_sha256
from policyops.providers.embeddings import (
    MAX_REQUEST_BYTES,
    Billing,
    Classified,
    Fetched,
    PreparedEmbedding,
    classify,
    diagnostic_of,
    digests_sha256,
    fetch,
    input_sha256,
    prepare,
    usage_of,
)
from policyops.providers.tokenizer import COUNT_SOURCE, InputRefused, Tokenizer
from policyops.telemetry import annotate, enabled, observed, provider_dispatch, provider_usage
from policyops_contracts.embedding import EmbeddedInput, EmbeddingJob


OPERATION_KIND = "embedding"
QUERY_PURPOSE = "query"  # run-bound query embeddings (T13); see `job_binding`
PREPARE_SECONDS = 60.0


@dataclass(frozen=True)
class EmbedLimits:
    lease_seconds: float = 120.0
    wait_seconds: float = 30.0
    poll_seconds: float = 0.25
    attempt_seconds: float = 60.0
    publish_attempts: int = 3

    def __post_init__(self) -> None:
        for name in ("lease_seconds", "wait_seconds", "poll_seconds", "attempt_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int | float) or not 0 < value <= 600:
                raise ValueError(f"{name} is a positive number of seconds up to 600")
        if isinstance(self.publish_attempts, bool) or not 1 <= self.publish_attempts <= 5:
            raise ValueError("publish_attempts is 1-5")


@dataclass(frozen=True)
class PreparedJob:
    job: EmbeddingJob
    identity: JobIdentity
    inputs: tuple[PlannedInput, ...]
    request_config_sha256: str


class DeadlinePassed(RuntimeError):
    pass


class BindingMismatch(ValueError):
    """The ledger and the embedding store do not belong to the same workspace and database."""


def _tokens_limit(configuration: Configuration) -> tuple[int, int]:
    actor = configuration.actors["embedding"]
    if not isinstance(actor, EmbeddingActor):
        raise ContractGap("the embedding actor has no embedding configuration")
    spec = configuration.registry.embedding(actor.model, dimensions=actor.dimensions)
    return min(actor.max_request_tokens, spec.per_input_max_tokens), actor.max_request_tokens


def _finite(deadline: object) -> float:
    if isinstance(deadline, bool) or not isinstance(deadline, float | int) or not math.isfinite(deadline):
        raise ValueError("deadline is a finite time.monotonic() instant")
    return float(deadline)


def prepare_job(job: EmbeddingJob, configuration: Configuration, tokenizer: Tokenizer, *,
                deadline: float) -> PreparedJob:
    """Synchronous CPU work before any reservation; the (clamped) deadline is checked around every input."""
    if not isinstance(job, EmbeddingJob):
        raise TypeError("job must be an EmbeddingJob")
    limit = min(_finite(deadline), time.monotonic() + PREPARE_SECONDS)
    per_input, _ = _tokens_limit(configuration)
    actor = configuration.actors["embedding"]
    if not isinstance(actor, EmbeddingActor):
        raise ContractGap("the embedding actor has no embedding configuration")
    inputs = []
    for position, text in enumerate(job.inputs):
        if time.monotonic() >= limit:
            raise DeadlinePassed("the deadline passed while counting inputs")
        tokens = tokenizer.count(text, position)
        if tokens > per_input:
            raise InputRefused("input_too_many_tokens", position)
        inputs.append(PlannedInput(position, input_sha256(text), text, tokens))
    if time.monotonic() >= limit:
        raise DeadlinePassed("the deadline passed while counting inputs")
    config = request_config_sha256(actor.model, actor.dimensions)
    identity = JobIdentity(job.purpose, job.subject_key, digests_sha256([i.input_sha256 for i in inputs]),
                           len(inputs), config, tokenizer.identity_sha256)
    return PreparedJob(job, identity, tuple(inputs), config)


def pack(prepared_job: PreparedJob, configuration: Configuration
         ) -> Callable[[UUID, frozenset[str]], list[BatchPlan]]:
    """The deterministic greedy plan over the distinct uncached inputs, in first-occurrence order: a new batch starts
    before an input that would cross the input count, local token or UTF-8 input byte limit of one request."""
    _, max_tokens = _tokens_limit(configuration)
    actor = configuration.actors["embedding"]
    if not isinstance(actor, EmbeddingActor):
        raise ContractGap("the embedding actor has no embedding configuration")
    max_inputs = min(64, actor.max_inputs)

    def build(job_id: UUID, cached: frozenset[str]) -> list[BatchPlan]:
        seen: set[str] = set()
        misses = []
        for item in prepared_job.inputs:
            if item.input_sha256 not in seen and item.input_sha256 not in cached:
                misses.append(item)
            seen.add(item.input_sha256)
        groups: list[list[PlannedInput]] = []
        for item in misses:
            group = groups[-1] if groups else None
            if (group is None or len(group) == max_inputs
                    or sum(i.local_tokens for i in group) + item.local_tokens > max_tokens
                    or sum(_size(i) for i in group) + _size(item) > MAX_REQUEST_BYTES):
                groups.append([item])
            else:
                group.append(item)
        plans = []
        for ordinal, group in enumerate(groups):
            batch_sha = digests_sha256([i.input_sha256 for i in group])
            request = prepare([i.text for i in group], configuration)
            operation = f"embed.{job_id}.b{ordinal:05d}.{batch_sha}"
            plans.append(BatchPlan(ordinal, tuple(i.position for i in group), batch_sha, request.request_sha256,
                                   sum(i.local_tokens for i in group), operation, uuid5(job_id, operation)))
        return plans
    return build


def _size(item: PlannedInput) -> int:
    return len(item.text.encode("utf-8"))


# -- reports -----------------------------------------------------------------------------------------------------

BatchFate = Literal["sent", "satisfied_by_cache", "reconciled", "orphaned", "in_progress_elsewhere", "refused",
                    "skipped"]
JobStatus = Literal["complete", "blocked", "incomplete", "budget", "deadline", "in_progress_elsewhere"]


@dataclass
class BatchReport:
    ordinal: int
    fate: BatchFate
    state: BatchState
    reason: str | None = None
    physical_request: bool = False
    cleanup_confirmed: bool | None = None


@dataclass
class JobReport:
    job_id: UUID | None
    status: JobStatus
    reason: str | None = None
    batches: list[BatchReport] = field(default_factory=list)
    vectors: tuple[EmbeddedInput, ...] = ()
    pending_evidence: Evidence | None = None
    pending_billing: Billing | None = None
    pending_request_id: str | None = None
    pending_cleanup_confirmed: bool | None = None

    @property
    def physical_requests(self) -> int:
        return sum(b.physical_request for b in self.batches)


class _Stop(Exception):
    def __init__(self, status: JobStatus, reason: str | None) -> None:
        super().__init__(reason)
        self.status, self.reason = status, reason


# -- evidence, settlement and publication -----------------------------------------------------------------------

def _evidence(batch: BatchPlan, job_id: UUID, prepared: PreparedEmbedding, classified: Classified,
              provider_request_id: str | None) -> Evidence | None:
    billing = classified.billing
    if billing is None or classified.outcome == "unknown":
        return None
    return Evidence(batch.attempt_id, job_id, batch.ordinal, prepared.request_sha256, prepared.input_sha256s,
                    billing.returned_model, billing.prompt_tokens, billing.total_tokens, provider_request_id,
                    classified.response_sha256,
                    None if classified.norms is None else tuple(norm_decimal(n) for n in classified.norms),
                    classified.outcome)


def _account(ledger: Ledger, attempt_id: UUID, outcome: str, billing: Billing | None,
             provider_request_id: str | None) -> None:
    """Settle or hold per the accounting table. The same inputs always give the same settlement, so a resume that
    accounts from stored evidence replays exactly."""
    if billing is None or outcome == "unknown":
        ledger.mark_unresolved(attempt_id)
    elif outcome in ("usage_contradiction", "model_mismatch"):
        ledger.mark_unresolved(attempt_id, block=f"embedding_{outcome}", diagnostic=diagnostic_of(outcome, billing))
    else:
        block = "embedding_count_mismatch" if outcome == "count_mismatch" else None
        ledger.settle(attempt_id, Settlement(usage_of(billing), provider_request_id, block))


STATE_OF: dict[str, BatchState] = {"published": "published", "vectors_invalid": "vectors_invalid",
                                   "count_mismatch": "blocked", "usage_contradiction": "blocked",
                                   "model_mismatch": "blocked", "unknown": "unresolved"}


def _from_evidence(ledger: Ledger, evidence: Evidence) -> BatchState:
    billing = Billing(evidence.returned_model, evidence.prompt_tokens, evidence.total_tokens)
    _account(ledger, evidence.attempt_id, evidence.outcome, billing, evidence.provider_request_id)
    return STATE_OF[evidence.outcome]


def _refusal_status(reason: str) -> JobStatus:
    """A refused claim or dispatch: another process's count or dispatch in flight, a budget limit, or a block."""
    if reason in ("dispatching", "count_claimed", "count_admitted"):
        return "in_progress_elsewhere"
    if reason in ("count_cap", "blocked_by_overrun"):
        return "budget"
    return "blocked"


def _credential(providers: Providers) -> SecretStr:
    """The OpenAI credential and a clean ambient environment, checked before anything is reserved."""
    credential = providers.credentials.get("openai")
    if not isinstance(credential, SecretStr):
        raise _Stop("blocked", "no_credential")
    try:
        require_clean_environment("openai")
    except ContractGap:
        raise _Stop("blocked", "ambient_sdk_settings") from None
    return credential


def check_binding(ledger: Ledger, store: EmbeddingStore) -> None:
    """The ledger must be the app ledger of the store's own workspace, on the very same engine."""
    books = ledger.store
    if not isinstance(books, AppLedgerStore):
        raise BindingMismatch("an embedding job is accounted in the app ledger")
    if books.workspace_id != store.workspace_id:
        raise BindingMismatch("the ledger and the embedding store belong to different workspaces")
    if books.engine is not store.engine:
        raise BindingMismatch("the ledger and the embedding store use different database engines")


# -- the runner --------------------------------------------------------------------------------------------------

@dataclass
class _Run:
    ledger: Ledger
    store: EmbeddingStore
    providers: Providers
    configuration: Configuration
    job: Job
    inputs: dict[int, PlannedInput]
    binding: OperationBinding | RunBinding
    owner: UUID
    deadline: float
    limits: EmbedLimits
    report: JobReport

    def texts(self, batch: BatchPlan) -> list[str]:
        return [self.inputs[p].text for p in batch.positions]

    def open(self) -> bool:
        """Whether a new reservation, count or dispatch may still start (monotonic and database clocks)."""
        return time.monotonic() < self.deadline and self.store.remaining_seconds(self.job.id) > 0

    async def lease(self, batch: Batch) -> Lease | Batch:
        """Our lease, or the batch as found once it reached a terminal state while we waited."""
        give_up = min(self.deadline, time.monotonic() + self.limits.wait_seconds)
        while True:
            lease = self.store.claim_lease(self.job.id, batch.plan.ordinal, self.owner, self.limits.lease_seconds)
            if lease is not None:
                return lease
            current = self.store.batch(self.job.id, batch.plan.ordinal)
            if current is not None and current.state in TERMINAL:
                return current
            if time.monotonic() + self.limits.poll_seconds >= give_up:
                raise _Stop("in_progress_elsewhere", f"batch {batch.plan.ordinal} is leased by another owner")
            await asyncio.sleep(self.limits.poll_seconds)

    def finish(self, lease: Lease, batch: BatchPlan, fate: BatchFate, state: BatchState, reason: str | None = None,
               physical: bool = False, cleanup: bool | None = None) -> None:
        # Fenced: a process that lost its lease keeps its billing writes but does not advance the batch.
        if not self.store.advance(lease, state):
            reason = "lease_lost" if reason is None else f"{reason}.lease_lost"
        self.store.release_lease(lease)
        self.report.batches.append(BatchReport(batch.ordinal, fate, state, reason, physical, cleanup))

    def stop(self, lease: Lease, status: JobStatus, reason: str) -> _Stop:
        self.store.release_lease(lease)
        return _Stop(status, reason)

    async def batch(self, found: Batch) -> None:
        plan = found.plan
        if found.state in TERMINAL:
            self.report.batches.append(BatchReport(plan.ordinal, "skipped", found.state))
            return
        got = await self.lease(found)
        if isinstance(got, Batch):
            self.report.batches.append(BatchReport(plan.ordinal, "skipped", got.state))
            return
        lease = got
        prepared = prepare(self.texts(plan), self.configuration)
        if prepared.request_sha256 != plan.request_sha256 or prepared.input_sha256s != tuple(
                self.inputs[p].input_sha256 for p in plan.positions):
            raise self.stop(lease, "blocked", f"batch {plan.ordinal} no longer matches its stored request")
        unreserved = bool(self.store.unreserved([plan.attempt_id]))
        cached = self.store.cached(self.job.identity.request_config_sha256, prepared.input_sha256s)
        if found.state == "planned" and unreserved and len(cached) == len(set(prepared.input_sha256s)):
            self.finish(lease, plan, "satisfied_by_cache", "satisfied_by_cache")
            return
        if unreserved and not self.open():
            raise self.stop(lease, "deadline", "deadline")
        try:
            reserved = self.ledger.reserve(self.binding, plan.attempt_id, "embedding", plan.operation_id,
                                           plan.request_sha256)
        except BudgetExhausted as error:
            raise self.stop(lease, "budget", error.reason) from None
        attempt = reserved.attempt
        if attempt.state in ("dispatching", "settled", "unresolved", "released"):
            evidence = self.store.evidence(plan.attempt_id)
            if evidence is not None:
                self.finish(lease, plan, "reconciled", _from_evidence(self.ledger, evidence))
            else:
                # Possibly sent and billed by an earlier owner; its result is not recoverable here. Nothing is sent,
                # released or marked on that attempt.
                self.finish(lease, plan, "orphaned", "orphaned", f"attempt_{attempt.state}")
            return
        if not self.open():
            raise self.stop(lease, "deadline", "deadline")
        credential = _credential(self.providers)
        owned_count = False
        if attempt.count_state == "none":
            claim = self.ledger.claim_count(plan.attempt_id, plan.request_sha256)
            if not isinstance(claim, CountGranted):
                self.report.batches.append(BatchReport(plan.ordinal, "refused", found.state, claim.reason))
                raise self.stop(lease, _refusal_status(claim.reason), claim.reason)
            owned_count, attempt = True, claim.attempt
        if attempt.count_state == "claimed":
            attempt = self.ledger.record_count(plan.attempt_id, tokens=plan.local_tokens, source=COUNT_SOURCE)
        if attempt.count_state != "admitted":
            if owned_count and self.store.holds(lease):
                self.ledger.release(plan.attempt_id)  # our own local rejection, still under our lease
            self.finish(lease, plan, "refused", "blocked", f"count_{attempt.count_state}")
            raise _Stop("blocked", f"count_{attempt.count_state}")
        if not self.open():
            raise self.stop(lease, "deadline", "deadline")
        decision = self.ledger.begin_dispatch(plan.attempt_id, plan.request_sha256)
        if not isinstance(decision, DispatchGranted):
            # Never released: another live process may own this attempt.
            self.report.batches.append(BatchReport(plan.ordinal, "refused", found.state, decision.reason))
            raise self.stop(lease, _refusal_status(decision.reason), decision.reason)
        await self.send(lease, plan, prepared, credential)

    @observed("provider.call")
    async def send(self, lease: Lease, plan: BatchPlan, prepared: PreparedEmbedding, credential: SecretStr) -> None:
        """After `DispatchGranted`: the attempt is never released. Every way out settles it or keeps its hold, and
        a body that has arrived is always accounted, even if its cleanup was interrupted."""
        annotate(provider="openai", model=prepared.model, operation="embedding", cost_class="unconfirmed")
        if isinstance(self.binding, RunBinding):
            annotate(run_id=self.binding.run_id)
        arrived: list[Fetched] = []
        try:
            cap = min(self.deadline, time.monotonic() + self.limits.attempt_seconds)
            with provider_dispatch("openai", prepared.model):
                async with asyncio.timeout_at(cap):
                    fetched = await fetch(prepared, lambda: self.providers.transport("openai"), credential,
                                          observe=arrived.append)
        except TimeoutError:
            if arrived:
                self.complete(lease, plan, prepared, arrived[0], cleanup=False, note="timeout_after_body")
            else:  # possibly sent and billed: the hold stays; the close was never observed
                provider_usage(provider="openai", model=prepared.model, outcome="unknown")
                self.hold_unconfirmed(plan.attempt_id, cleanup=False)
                self.finish(lease, plan, "sent", "unresolved", "timeout", physical=True, cleanup=False)
            if time.monotonic() >= self.deadline:
                raise _Stop("deadline", "deadline") from None
            return
        except BaseException as error:  # a cancellation, an ambient-setting refusal or anything unexpected
            note = "cancelled" if isinstance(error, asyncio.CancelledError) else "local_error"
            try:
                if arrived:
                    self.complete(lease, plan, prepared, arrived[0], cleanup=False, note=f"{note}_after_body")
                else:
                    provider_usage(provider="openai", model=prepared.model, outcome="error")
                    self.hold_unconfirmed(plan.attempt_id, cleanup=False)
                    self.finish(lease, plan, "sent", "unresolved", note, physical=True, cleanup=False)
            except Exception as cleanup:
                error.add_note(f"accounting unconfirmed: {type(cleanup).__name__}; reserved cost remains held")
            raise
        self.complete(lease, plan, prepared, fetched, cleanup=fetched.cleanup_confirmed)

    def complete(self, lease: Lease, plan: BatchPlan, prepared: PreparedEmbedding, fetched: Fetched, *,
                 cleanup: bool, note: str | None = None) -> None:
        """Synchronous accounting of one response: classify, publish, settle or hold, advance."""
        if fetched.raw is None:
            provider_usage(provider="openai", model=prepared.model, outcome="unknown")
            self.hold_unconfirmed(plan.attempt_id, cleanup=cleanup)
            self.finish(lease, plan, "sent", "unresolved", note or fetched.error, physical=fetched.sent,
                        cleanup=cleanup)
            return
        classified = classify(fetched.raw, prepared, plan.local_tokens)
        if enabled():
            usage = usage_of(classified.billing) if classified.settles and classified.billing is not None else None
            provider_usage(provider="openai", model=prepared.model,
                           outcome="completed" if classified.outcome == "published" else "failed",
                           input_tokens=usage.input_total if usage is not None else None,
                           output_tokens=0 if usage is not None else None,
                           usd=cost(self.configuration.price("embedding"), usage).usd if usage is not None else None)
        evidence = _evidence(plan, self.job.id, prepared, classified, fetched.provider_request_id)
        self.report.pending_evidence, self.report.pending_billing = evidence, classified.billing
        self.report.pending_request_id, self.report.pending_cleanup_confirmed = fetched.provider_request_id, cleanup
        try:
            published = evidence is None or self._publish(evidence, classified)
            _account(self.ledger, plan.attempt_id, classified.outcome, classified.billing, fetched.provider_request_id)
        except Exception as error:
            raise AccountingUnconfirmed(self.report) from error
        self.report.pending_evidence, self.report.pending_billing = None, None
        self.report.pending_request_id, self.report.pending_cleanup_confirmed = None, None
        state = STATE_OF[classified.outcome] if published else "orphaned"
        reason = note if published else ("publication_failed" if note is None else f"{note}.publication_failed")
        self.finish(lease, plan, "sent", state, reason, physical=True, cleanup=cleanup)

    def hold_unconfirmed(self, attempt_id: UUID, *, cleanup: bool) -> None:
        self.report.pending_cleanup_confirmed = cleanup
        try:
            self.ledger.mark_unresolved(attempt_id)
        except Exception as error:
            raise AccountingUnconfirmed(self.report) from error
        self.report.pending_cleanup_confirmed = None

    def _publish(self, evidence: Evidence, classified: Classified) -> bool:
        for attempt in range(self.limits.publish_attempts):
            try:
                self.store.publish(evidence, classified.vectors if classified.outcome == "published" else None)
                return True
            except EvidenceConflict:
                return False  # never retried: the stored evidence, batch or attempt disagrees with this response
            except DBAPIError:
                if attempt + 1 == self.limits.publish_attempts:
                    return False
        return False


def preflight(ledger: Ledger, store: EmbeddingStore, binding: OperationBinding, batches: Sequence[Batch]) -> None:
    """Every planned batch still without a ledger attempt must fit what the operation scope has left."""
    pending = store.unreserved([b.plan.attempt_id for b in batches if b.state not in TERMINAL])
    if not pending:
        return
    caps = ledger.configuration.caps
    worst = ledger.configuration.reservation("embedding").worst_usd
    scope = store.operation_scope(binding.kind, binding.key)
    if scope is None:
        room_usd, room_calls, room_counts = caps.operation_usd, caps.operation_calls, caps.operation_calls
    else:
        if scope.contract_block is not None:
            raise _Stop("blocked", "blocked_by_contract")
        room_usd = scope.cap_usd - scope.spent_usd - scope.held_usd
        room_calls = scope.cap_calls - scope.calls_consumed - scope.calls_held
        room_counts = scope.cap_counts - scope.counts_used
    if len(pending) * worst > room_usd or len(pending) > room_calls or len(pending) > room_counts:
        raise _Stop("budget", "plan_exceeds_caps")


def job_binding(identity: JobIdentity, run_id: UUID | None) -> RunBinding | Literal["operation"] | None:
    """The budget binding a job's immutable identity admits; None for a refused combination.

    A query job (`purpose == QUERY_PURPOSE`) is always run-bound: exactly one input, subject
    `query.<run_id>.<step>`, charged to that run's shared scope (T13). Every other job keeps its own operation scope
    (`run_id` must then be None), exactly as before: `"operation"` means `OperationBinding("embedding", <job id>)`,
    which `run_job` constructs once the actual job ID exists (it is never built with a placeholder key)."""
    if identity.purpose == QUERY_PURPOSE:
        if run_id is None or identity.input_count != 1 or not identity.subject_key.startswith(f"query.{run_id}."):
            return None
        return RunBinding(run_id)
    if run_id is not None:
        return None
    return "operation"


async def run_job(ledger: Ledger, store: EmbeddingStore, providers: Providers, prepared_job: PreparedJob, *,
                  deadline: float, owner: UUID | None = None, limits: EmbedLimits | None = None,
                  run_id: UUID | None = None) -> JobReport:
    """Plan (or resume) and run one embedding job. `deadline` is an absolute `time.monotonic()` instant, clamped to
    the server's active-seconds cap and the job's own immutable window.

    `run_id` (T13) binds a query job to its run's shared budget scope. The binding is derived from the job's immutable
    identity (`job_binding`) and checked before any write: a mismatch is `BindingMismatch`. A run-bound job also needs
    the run to be visible in this workspace and active (`EmbeddingStore.run_is_active`) before planning, cache use
    or terminal reconciliation; otherwise the report is `blocked`/`run_not_active` with no job and no write. Its plan
    is a single input, so there is no operation-scope preflight: the ledger's atomic run-scope reservation is the
    only admission (and its run lock and active checks stay authoritative)."""
    started = time.monotonic()
    requested = _finite(deadline)
    check_binding(ledger, store)
    derived = job_binding(prepared_job.identity, run_id)
    if derived is None:
        raise BindingMismatch("the job identity does not admit this budget binding")
    if isinstance(derived, RunBinding) and not store.run_is_active(derived.run_id):
        return JobReport(None, "blocked", "run_not_active")
    configuration = ledger.configuration
    window = configuration.caps.active_seconds
    job, batches = store.plan_job(prepared_job.identity, prepared_job.inputs, pack(prepared_job, configuration),
                                  window_seconds=window)
    remaining = store.remaining_seconds(job.id)
    binding: OperationBinding | RunBinding = (
        derived if isinstance(derived, RunBinding) else OperationBinding(OPERATION_KIND, str(job.id)))
    report = JobReport(job.id, "incomplete")
    run = _Run(ledger, store, providers, configuration, job, {i.position: i for i in prepared_job.inputs}, binding,
               owner or uuid4(), min(requested, started + window, time.monotonic() + remaining),
               limits or EmbedLimits(), report)
    try:
        if any(b.state not in TERMINAL for b in batches):
            _credential(providers)
            if isinstance(binding, OperationBinding):
                preflight(ledger, store, binding, batches)
        for batch in batches:
            await run.batch(batch)
    except _Stop as stop:
        report.status, report.reason = stop.status, stop.reason
    states = [b.state for b in store.batches(job.id)]
    if report.reason is None:
        if all(s in ("published", "satisfied_by_cache") for s in states):
            report.status = "complete"
        elif any(s == "blocked" for s in states):
            report.status = "blocked"
    cached = store.cached(job.identity.request_config_sha256, [i.input_sha256 for i in prepared_job.inputs])
    report.vectors = tuple(EmbeddedInput(position=i.position, input_sha256=i.input_sha256,
                                         vector=cached[i.input_sha256])
                           for i in prepared_job.inputs if i.input_sha256 in cached)
    if report.status in ("complete", "blocked"):
        current = store.job(job.id)
        if current is not None and current.state != report.status:
            store.set_job_state(job.id, report.status, current.version)
    return report


def run_job_sync(ledger: Ledger, store: EmbeddingStore, providers: Providers, prepared_job: PreparedJob, *,
                 deadline: float, owner: UUID | None = None, limits: EmbedLimits | None = None,
                 run_id: UUID | None = None) -> JobReport:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(run_job(ledger, store, providers, prepared_job, deadline=deadline, owner=owner,
                                   limits=limits, run_id=run_id))
    raise RuntimeError("run_job_sync cannot run inside an event loop; await run_job instead")
