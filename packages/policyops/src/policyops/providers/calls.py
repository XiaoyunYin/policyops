"""Ledger-integrated model calls (T11): prepare → reserve → count → dispatch → one SDK call → settle or keep the
liability, with bounded retries, at most one repair and one absolute deadline. The async `call` is the primary port.

## Per physical attempt

1. `serialize.prepare`: every local check, before anything is reserved. A `ContractGap` sends nothing and reserves
   nothing.
2. `reserve` (T10) binds the request fingerprint. The attempt ID is deterministic (`uuid5(invocation key, operation)`),
   so a duplicate or restarted caller finds the same attempt instead of creating a new one.
   - **Only the caller that created the attempt** goes on to claim, count, dispatch, record or release it.
   - A replay (`created=False`) returns at once without changing anything. Another caller may still own the attempt
     and be counting or sending, so it can never be marked failed or released by a duplicate. Recovering a stale
     claim needs the worker fence (T21) and is not attempted here.
3. `claim_count` → one count call → `record_count`. A count that fails, is rejected or is interrupted is final: no
   count retry. The owner then releases the attempt, which is legal because it is still `reserved` and was never
   dispatched.
4. `begin_dispatch` itself enforces the admitted count, the bound fingerprint and the scope blocks. A refusal sends
   nothing. Only an attempt still `reserved` is released; a replay that was already dispatched or settled is left
   exactly as it is.
5. After a grant, the attempt is **never** released:
   - it is settled when the usage is known and priced;
   - otherwise it is marked unresolved, with a contract block and an allowlisted diagnostic when the evidence was
     unpriceable;
   - that also covers a local failure before the bytes left and a cancellation.

## Bounds

- **Retries:** a retryable failure (429, 5xx, 529, a timeout or a connection error) is retried as a **new** attempt,
  up to `retries_per_request` times per logical request. The wait honours Retry-After within the deadline.
- **Repair:** an `invalid_output` gets at most one repair, a new logical request (and new attempts) whose retries
  are bounded the same way. This matches the T10 preflight factor `(1 + repairs) x (1 + retries)`.
- **No fallback:** there is no model switch.
- **Deadlines:** one absolute `time.monotonic()` deadline (`asyncio.timeout_at`) covers preparation, counts, requests,
  streams and retry sleeps. Inside it, each count and each request also has its own absolute cap,
  `min(attempt_seconds, caller deadline)` (60 s by default). It bounds the whole request, including a stream that
  keeps trickling bytes, not just each read. An expired attempt cap ends that attempt (unresolved after a dispatch,
  released before one), and the retry policy decides what follows.
- **Bookkeeping:** ledger bookkeeping runs outside the timed scopes, in its own short transactions, so an expired
  deadline cannot skip it. The provider may still be working after a local cancel; the hold remains.

Run-bound app ledgers require the investigation claim at admission; callers derive monotonic deadlines from the
persisted active allowance. SQL profiles bound operations, not total elapsed workflow time. The synchronous façade
refuses to run inside an existing event loop.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
import math
import time
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID, uuid5

import httpx2
from pydantic import SecretStr

from policyops.budget.config import Actor
from policyops.budget.ledger import (
    Binding,
    BudgetExhausted,
    CountGranted,
    DispatchGranted,
    Ledger,
    RunBinding,
    Settlement,
)
from policyops.budget.pricing import cost
from policyops.persistence.database import TransactionOutcomeUnknown
from policyops.providers.accounting import AccountingUnconfirmed
from policyops.providers.adapters import CountFailed, Invocation, as_contract_gap, count, invoke
from policyops.providers.contract import ContractGap, Provider, require_clean_environment
from policyops.providers.results import Evidence
from policyops.providers.serialize import PreparedRequest, prepare
from policyops.telemetry import annotate, enabled, observed, provider_usage
from policyops_contracts.model import Message, ModelRequest, ModelResult, TextPart
from policyops_contracts.provider_failures import failure_code


if TYPE_CHECKING:
    from policyops.providers.bedrock_auth import BedrockAccess


RETRYABLE_STATUS = frozenset({408, 409, 424, 429, 500, 502, 503, 504, 529})
RETRYABLE_ERRORS = frozenset({"timeout", "connection", "stream_without_final_response"})
REPAIR_TEXT = ("Your previous reply did not match the required format. Reply again, following the required "
               "schema exactly.")


def _count_limit(value: object, low: int, high: int, what: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{what} is an integer from {low} to {high}")


def _seconds(value: object, low: float, high: float, what: str) -> None:
    if (isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value)
            or not low <= value <= high):
        raise ValueError(f"{what} is a finite number of seconds from {low} to {high}")


@dataclass(frozen=True)
class CallLimits:
    retries_per_request: int = 1
    repairs: int = 1
    backoff_seconds: float = 1.0
    attempt_seconds: float = 60.0  # the absolute cap on one count or one request, stream included

    def __post_init__(self) -> None:
        _count_limit(self.retries_per_request, 0, 3, "retries_per_request")
        _count_limit(self.repairs, 0, 1, "repairs")
        _seconds(self.backoff_seconds, 0.0, 60.0, "backoff_seconds")
        _seconds(self.attempt_seconds, 0.001, 60.0, "attempt_seconds")


@dataclass(frozen=True)
class Providers:
    """Server-owned provider access: the credentials, and the inner transport each provider's requests go out on
    (`httpx2.AsyncHTTPTransport()` in production, a scripted mock offline)."""

    credentials: Mapping[str, SecretStr]
    transport: Callable[[Provider], httpx2.AsyncBaseTransport]
    bedrock: BedrockAccess | None = field(default=None, repr=False)


AttemptFate = Literal["settled", "unresolved", "released", "replayed", "refused", "not_reserved"]


@dataclass
class AttemptRecord:
    attempt_id: UUID
    operation_id: str
    request_sha256: str | None
    fate: AttemptFate | None = None
    reason: str | None = None
    cleanup_confirmed: bool | None = None  # None: no provider client was opened for this attempt
    # Which ledger grants this very call obtained for this attempt (set before the count / request is awaited, never
    # cleared): facts about grants, not proof that any bytes left the process. The ledger stays the billing authority.
    count_granted: bool = False
    dispatch_granted: bool = False
    # Normalized, bounded billing evidence survives a failed accounting transaction in this process.
    evidence: Evidence | None = None

    @property
    def failure_code(self) -> str | None:
        return failure_code(self.reason)


@dataclass
class CallReport:
    result: ModelResult | None
    status: Literal["result", "failed", "deadline", "budget", "contract_gap"]
    reason: str | None
    attempts: list[AttemptRecord] = field(default_factory=list)

    @property
    def failure_code(self) -> str | None:
        return failure_code(self.reason)

    @property
    def cleanup_unconfirmed(self) -> tuple[UUID, ...]:
        """Attempts whose count or request client could not be confirmed closed (their bills are unaffected)."""
        return tuple(record.attempt_id for record in self.attempts if record.cleanup_confirmed is False)


@dataclass
class _Pending:
    """What the bookkeeping after a deadline or cancellation must still do for the current attempt. It exists only
    for an attempt this call created (owns): a replayed attempt is never touched."""

    record: AttemptRecord
    phase: Literal["reserved", "counting", "dispatched"] = "reserved"
    invocation: Invocation | None = None


def _repair(request: ModelRequest) -> ModelRequest:
    messages = (*request.messages, Message(role="user", parts=(TextPart(text=REPAIR_TEXT),)))
    if request.messages[-1].role == "user":
        messages = (*request.messages[:-1], Message(role="user", parts=(*request.messages[-1].parts,
                                                                         TextPart(text=REPAIR_TEXT))))
    return request.model_copy(update={"messages": messages})


def _retryable(invocation: Invocation) -> bool:
    if invocation.status is not None:
        return invocation.status in RETRYABLE_STATUS
    return invocation.error in RETRYABLE_ERRORS


def _count_deviation(invocation: Invocation, counted: int | None, percent: int, minimum: int) -> Invocation:
    """The count admitted the request on `counted + headroom`. A known prompt larger than that means the count did
    not bound the request: the exact bill settles, and progress stops (`count_underestimate`). A prompt smaller than
    the count is fine. Mock counts prove only this check, not any provider's counting accuracy."""
    evidence = invocation.evidence
    if evidence is None or evidence.usage is None or evidence.block is not None or counted is None:
        return invocation
    headroom = max(-(-counted * percent // 100), minimum)
    if evidence.usage.input_total <= counted + headroom:
        return invocation
    evidence = replace(evidence, block="count_underestimate")
    result = None if invocation.result is None else as_contract_gap(invocation.result, "count_underestimate")
    return replace(invocation, evidence=evidence, result=result)


def _settle_or_hold(ledger: Ledger, attempt_id: UUID, invocation: Invocation) -> AttemptFate:
    evidence = invocation.evidence
    if evidence is not None and evidence.usage is not None:
        ledger.settle(attempt_id, Settlement(evidence.usage, evidence.provider_request_id, evidence.block))
        return "settled"
    if evidence is not None:
        ledger.mark_unresolved(attempt_id, block=evidence.block, diagnostic=evidence.diagnostic)
    else:
        ledger.mark_unresolved(attempt_id)
    return "unresolved"


def _finish_pending(ledger: Ledger, pending: _Pending | None) -> None:
    """Bookkeeping for an attempt interrupted by the deadline or a cancellation (outside the deadline scope)."""
    if pending is None:
        return
    record = pending.record
    if pending.phase in ("counting", "dispatched"):
        record.cleanup_confirmed = False  # interrupted while a provider client was open: its close was not observed
    if pending.phase == "dispatched":
        if pending.invocation is not None:
            record.fate = _settle_or_hold(ledger, record.attempt_id, pending.invocation)
        else:
            ledger.mark_unresolved(record.attempt_id)
            record.fate = "unresolved"
        return
    if pending.phase == "counting":
        ledger.record_count(record.attempt_id, tokens=None, source="interrupted")
    ledger.release(record.attempt_id)  # still reserved: never dispatched
    record.fate = "released"


class _Stop(Exception):  # an internal control-flow signal
    def __init__(self, report: CallReport) -> None:
        self.report = report


async def _capped(awaitable: Any, deadline: float, limits: CallLimits) -> Any:
    """Await under the attempt cap (an absolute instant). A TimeoutError from the caller's own deadline is re-raised;
    the attempt cap's own expiry raises `_AttemptExpired`."""
    cap = min(deadline, time.monotonic() + limits.attempt_seconds)
    try:
        async with asyncio.timeout_at(cap):
            return await awaitable
    except TimeoutError:
        if time.monotonic() >= deadline:
            raise
        raise _AttemptExpired from None


class _AttemptExpired(Exception):
    pass


@observed("provider.call")
async def _attempt(ledger: Ledger, providers: Providers, binding: Binding, key: UUID, operation: str,
                   prepared: PreparedRequest, actor: Actor, pending: list[_Pending | None],
                   report: CallReport, deadline: float, limits: CallLimits) -> Invocation:
    attempt_id = uuid5(key, operation)
    annotate(provider=prepared.provider, model=prepared.model, operation="chat", cost_class="not_dispatched")
    record = AttemptRecord(attempt_id, operation, prepared.request_sha256)
    report.attempts.append(record)
    try:
        reserved = ledger.reserve(binding, attempt_id, actor, operation, prepared.request_sha256)
    except BudgetExhausted as error:
        record.fate, record.reason = "not_reserved", error.reason
        raise _Stop(CallReport(None, "budget", error.reason, report.attempts)) from None
    attempt = reserved.attempt
    if not reserved.created:
        # Another caller (live or crashed) owns this attempt: change nothing, send nothing.
        record.fate, record.reason = "replayed", f"{attempt.state}.{attempt.count_state}"
        raise _Stop(CallReport(None, "failed", f"replayed_{attempt.state}", report.attempts))
    pending[0] = _Pending(record)
    credential = providers.credentials.get(prepared.provider, SecretStr(""))
    claim = ledger.claim_count(attempt_id, prepared.request_sha256)
    if not isinstance(claim, CountGranted):  # our own attempt, still reserved and never dispatched
        ledger.release(attempt_id)
        pending[0] = None
        record.fate, record.reason = "released", claim.reason
        raise _Stop(CallReport(None, "budget" if claim.reason == "count_cap" else "failed", claim.reason,
                               report.attempts))
    record.count_granted = True
    pending[0] = _Pending(record, "counting")
    tokens: int | None = None
    try:
        if prepared.provider == "bedrock":
            from policyops.providers.bedrock import input_bound

            tokens, source, record.cleanup_confirmed = input_bound(prepared), "bedrock.byte_bound.v1", True
        else:
            counted = await _capped(count(prepared, providers.transport(prepared.provider), credential), deadline,
                                    limits)
            tokens, source, record.cleanup_confirmed = counted.tokens, f"{prepared.provider}.count", \
                counted.cleanup_confirmed
    except CountFailed as error:
        source, record.reason, record.cleanup_confirmed = "failed", f"count.{error.code}", error.cleanup_confirmed
    except _AttemptExpired:
        # The count was cut off mid-flight: its close was never observed, so it is not claimed.
        source, record.reason, record.cleanup_confirmed = "failed", "count.attempt_timeout", False
    attempt = ledger.record_count(attempt_id, tokens=tokens, source=source)
    pending[0] = _Pending(record)
    if attempt.count_state != "admitted":
        ledger.release(attempt_id)
        pending[0] = None
        record.fate = "released"
        record.reason = record.reason or f"count_{attempt.count_state}"
        raise _Stop(CallReport(None, "failed", record.reason, report.attempts))
    decision = ledger.begin_dispatch(attempt_id, prepared.request_sha256)
    if not isinstance(decision, DispatchGranted):
        if decision.attempt.state == "reserved":
            ledger.release(attempt_id)
            record.fate = "released"
        else:
            record.fate = "replayed"
        pending[0] = None
        record.reason = decision.reason
        raise _Stop(CallReport(None, "failed", decision.reason, report.attempts))
    record.dispatch_granted = True
    pending[0] = _Pending(record, "dispatched")
    cache_mode = ledger.configuration.actors[actor].cache_mode  # type: ignore[union-attr]
    invocation: Invocation
    try:
        if prepared.provider == "bedrock":
            from policyops.providers.bedrock import invoke as bedrock_invoke

            if providers.bedrock is None:
                raise ContractGap("bedrock.credentials_missing")
            invocation = await _capped(bedrock_invoke(prepared, providers.transport(prepared.provider),
                                                     providers.bedrock), deadline, limits)
        else:
            invocation = await _capped(invoke(prepared, providers.transport(prepared.provider), credential,
                                              cache_mode=cache_mode), deadline, limits)
    except _AttemptExpired:
        # Possibly sent and billed: the hold stays. Its close was never observed, so it is not claimed.
        invocation = Invocation(sent=True, error="timeout", cleanup_confirmed=False)
    except BaseException:
        provider_usage(provider=prepared.provider, model=prepared.model, outcome="error")
        raise
    record.cleanup_confirmed = invocation.cleanup_confirmed and record.cleanup_confirmed is not False
    config = ledger.configuration.actors[actor]
    invocation = _count_deviation(invocation, attempt.counted_input_tokens,
                                  0 if prepared.provider == "bedrock" else config.count_headroom_percent,
                                  0 if prepared.provider == "bedrock" else config.count_headroom_min)
    record.evidence = invocation.evidence
    if enabled():
        usage = invocation.evidence.usage if invocation.evidence is not None else None
        provider_usage(provider=prepared.provider, model=prepared.model,
                       outcome=invocation.result.outcome if invocation.result is not None else "failed",
                       input_tokens=usage.input_total if usage is not None else None,
                       output_tokens=usage.output if usage is not None else None,
                       usd=cost(ledger.configuration.price(actor), usage).usd if usage is not None else None)
    pending[0] = _Pending(record, "dispatched", invocation)
    try:
        record.fate = _settle_or_hold(ledger, attempt_id, invocation)
    except Exception as error:
        record.reason = "accounting_unconfirmed"
        raise AccountingUnconfirmed(report) from error
    pending[0] = None
    record.reason = invocation.error or (invocation.result.reason_code if invocation.result else None)
    return invocation


async def _run(ledger: Ledger, providers: Providers, binding: Binding, key: UUID, operation: str,
               request: ModelRequest, actor: Actor, limits: CallLimits, deadline: float,
               pending: list[_Pending | None], report: CallReport) -> CallReport:
    for repair in range(1 + limits.repairs):
        try:
            prepared = prepare(request, ledger.configuration, actor)
        except ContractGap as error:
            return CallReport(None, "contract_gap", str(error)[:200], report.attempts)
        if prepared.provider == "bedrock":
            try:
                require_clean_environment("bedrock")
            except ContractGap as error:
                return CallReport(None, "contract_gap", str(error), report.attempts)
        if ((prepared.provider == "bedrock" and providers.bedrock is None)
                or (prepared.provider != "bedrock" and not isinstance(
                    providers.credentials.get(prepared.provider), SecretStr))):
            return CallReport(None, "contract_gap", f"no server credential for {prepared.provider}", report.attempts)
        for retry in range(1 + limits.retries_per_request):
            invocation = await _attempt(ledger, providers, binding, key, f"{operation}.r{repair}.a{retry}",
                                        prepared, actor, pending, report, deadline, limits)
            result = invocation.result
            if result is not None and result.outcome == "contract_gap":
                return CallReport(result, "contract_gap", result.reason_code, report.attempts)  # no retry, no repair
            if result is not None:
                if result.outcome == "invalid_output" and repair < limits.repairs:
                    break  # one repair: a new logical request
                status: Literal["result", "failed"] = "result"
                return CallReport(result, status, result.reason_code, report.attempts)
            if not _retryable(invocation) or retry == limits.retries_per_request:
                return CallReport(None, "failed", invocation.error, report.attempts)
            wait = invocation.retry_after if invocation.retry_after is not None else limits.backoff_seconds
            if time.monotonic() + wait >= deadline:
                return CallReport(None, "failed", "retry_after_beyond_deadline", report.attempts)
            await asyncio.sleep(wait)
        request = _repair(request)
    return CallReport(None, "failed", "repair_exhausted", report.attempts)


@observed("provider.request")
async def call(ledger: Ledger, providers: Providers, binding: Binding, invocation_key: UUID, operation: str,
               request: ModelRequest, actor: Actor, *, deadline: float, limits: CallLimits | None = None
               ) -> CallReport:
    """`deadline` is an absolute `time.monotonic()` instant (the event loop's clock)."""
    if isinstance(binding, RunBinding):
        annotate(run_id=binding.run_id)
    result = await _call(ledger, providers, binding, invocation_key, operation, request, actor,
                         deadline=deadline, limits=limits)
    annotate(outcome=result.status)
    return result


async def _call(ledger: Ledger, providers: Providers, binding: Binding, invocation_key: UUID, operation: str,
                request: ModelRequest, actor: Actor, *, deadline: float, limits: CallLimits | None = None
                ) -> CallReport:
    if isinstance(deadline, bool) or not isinstance(deadline, float | int) or not math.isfinite(deadline):
        raise ValueError("deadline is a finite time.monotonic() instant")
    if deadline <= time.monotonic():
        return CallReport(None, "deadline", "deadline_already_passed")
    pending: list[_Pending | None] = [None]
    report = CallReport(None, "failed", None)
    try:
        async with asyncio.timeout_at(deadline):
            return await _run(ledger, providers, binding, invocation_key, operation, request, actor,
                              limits or CallLimits(), float(deadline), pending, report)
    except _Stop as stop:
        return stop.report
    except (TransactionOutcomeUnknown, AccountingUnconfirmed):
        # A lost dispatch acknowledgement grants no send authority and no safe release authority.
        # A failed settlement keeps normalized evidence reachable through the typed error's report.
        raise
    except TimeoutError:
        if pending[0] is not None:
            pending[0].record.reason = "timeout"
        try:
            _finish_pending(ledger, pending[0])
        except Exception as error:
            raise AccountingUnconfirmed(report) from error
        return CallReport(None, "deadline", "deadline", report.attempts)
    except asyncio.CancelledError as primary:
        if pending[0] is not None:
            pending[0].record.reason = "cancelled"
        try:
            _finish_pending(ledger, pending[0])
        except Exception as cleanup:
            primary.add_note(f"accounting unconfirmed: {type(cleanup).__name__}; reserved cost remains held")
        raise
    except Exception as primary:
        # Anything unexpected: the current attempt is still finished conservatively (unresolved after a grant,
        # released before one), then the error propagates.
        try:
            _finish_pending(ledger, pending[0])
        except Exception as cleanup:
            primary.add_note(f"accounting cleanup also failed: {type(cleanup).__name__}")
        raise


def call_sync(ledger: Ledger, providers: Providers, binding: Binding, invocation_key: UUID, operation: str,
              request: ModelRequest, actor: Actor, *, deadline: float, limits: CallLimits | None = None
              ) -> CallReport:
    """For synchronous callers (the T09 worker thread). Inside a running event loop, use `call`."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(call(ledger, providers, binding, invocation_key, operation, request, actor,
                                deadline=deadline, limits=limits))
    raise RuntimeError("call_sync cannot run inside an event loop; await providers.calls.call instead")
