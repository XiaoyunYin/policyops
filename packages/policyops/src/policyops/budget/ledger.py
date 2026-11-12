"""The usage budget ledger (T10): atomic reservations, dispatch grants and settlement, with the same rules for the
app workbench ledger and the evaluation ledger (each behind a `LedgerStore`).

## Attempts

An attempt is one accounted provider request; a retry is a new attempt. Its operations:
- `reserve`: creates `reserved`. In one transaction it holds the worst-case cost and one call slot in **every**
  applicable scope. The scopes come from a canonical binding (a run, an operation, or a study with an invocation and
  a scenario), never from a caller's list, so a parent cannot be left out. Reserving an existing attempt ID with the
  same intent is a replay; with any other intent it is a conflict.
- `begin_dispatch`: moves reserved → dispatching and commits before any provider I/O. It consumes the call slot for
  good. Only the call that makes this transition gets `DispatchGranted`. Any other call (a concurrent duplicate, or a
  replay in any later state) gets `DispatchRefused` and must not send anything. An attempt reserved earlier is also
  refused while any of its scopes is overrun or its run is no longer active; it stays `reserved` and may be released.
- `release`: only a `reserved` attempt (never dispatched) can be released, which returns its hold and slot. A
  dispatched attempt is never released: not by a timeout, a restart, a cancellation or a lost lease.
- `mark_unresolved`: moves dispatching → unresolved when usage is unknown (timeout, crash, missing usage). The
  conservative hold stays. On a settled attempt it is a no-op, so a known result is never downgraded.
- `settle`: moves dispatching or unresolved → settled, with known usage.
  - The cost uses the attempt's own price revision and the actual whole-prompt tier. The hold moves to spent at the
    true cost.
  - If the cost exceeds the reservation, the attempt and **every** scope it charges are marked `overrun`. This is a
    sticky block on new holds and dispatches.
  - Settling again with the same usage is a replay; different usage is a conflict that keeps the original.
  - Settling after a run is cancelled or a claim is fenced out records the bill but authorizes nothing else.

## Request identity and counting (T11, revision 0007)

- Every new attempt is intent version 2. It binds `request_sha256`, the fingerprint of the exact prepared provider
  request, so a changed message, tool, schema, effort or limit is a different attempt. Version 1 attempts from
  revision 0006 keep their digest. They can still be settled, marked unresolved or released, but never dispatched.
- `claim_count`: one supported token count per attempt, claimed (none → claimed) and committed before the count
  call. Only the transition returns `CountGranted`. It consumes a count unit, which is never returned, in every
  scope. `record_count` stores the counted tokens and admits the attempt only if they fit `max_input` with the
  actor's headroom. `begin_dispatch` re-checks that itself, along with the bound request fingerprint.
- A **contract block** is separate from the monetary overrun. It is set when a provider's response broke the request
  contract or could not be priced. Like an overrun, it is sticky on the attempt and every scope it charges, and stops
  new holds, counts and dispatches.
  - `mark_unresolved(block=…)` keeps the conservative hold when the usage cannot be priced; no bill is invented.
  - `settle(Settlement(block=…))` records an exact bill for a known mismatch.

## Locks and time

Every operation locks in one fixed order:
1. run and claim job rows for run-bound admission (reserve/count/dispatch), ordered against reclaim/cancellation;
2. the scope rows, ordered by (kind rank, ID);
3. the attempt row.

Release, dispatch and settle first read the attempt's immutable scope bindings without a lock, then take the locks in
that order and revalidate. Nothing locks an attempt before its scopes. Times come from the database clock, read
after the locks. No transaction spans provider I/O.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal
import hashlib
import json
import re
from types import MappingProxyType
from typing import Literal, Protocol
from uuid import UUID

from policyops.budget.config import Actor, Caps, Configuration
from policyops.budget.prices import PriceSnapshot, UnknownPrice
from policyops.budget.pricing import Usage, cost


State = Literal["reserved", "dispatching", "released", "settled", "unresolved"]
ScopeKind = Literal["run", "operation", "study", "invocation", "scenario"]
KIND_RANK: Mapping[str, int] = MappingProxyType({"run": 0, "operation": 0, "study": 0, "invocation": 1,
                                                 "scenario": 2})
SLUG = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
SHA256 = re.compile(r"[0-9a-f]{64}")


class LedgerError(ValueError):
    rule_id = "budget.error"


class BudgetExhausted(LedgerError):
    """A cap would be exceeded, or a scope is blocked by an earlier overrun; nothing was reserved."""

    def __init__(self, scope_kind: str, reason: str) -> None:
        super().__init__(f"{scope_kind} budget: {reason}")
        self.scope_kind = scope_kind
        self.reason = reason
        self.rule_id = f"budget.{reason}"


class LedgerConflict(LedgerError):
    """An existing attempt or scope has different immutable content; the original is kept."""

    rule_id = "budget.conflict"


class IllegalTransition(LedgerError):
    """The attempt's state does not allow the operation (for example releasing a dispatched attempt)."""

    rule_id = "budget.illegal_transition"


class ScopeInactive(LedgerError):
    """The bound run is no longer active, so nothing new may be reserved for it."""

    rule_id = "budget.run_not_active"


class NotFound(LedgerError):
    """No such attempt or scope (or it is outside the current workspace: indistinguishable by design)."""

    rule_id = "budget.not_found"


# -- bindings and values -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class RunBinding:
    """A workbench run's single scope, created on first use with the server's run caps."""

    run_id: UUID


@dataclass(frozen=True)
class OperationBinding:
    """A non-run operation's scope (such as an ingestion job), with the server's operation caps."""

    kind: str
    key: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not SLUG.fullmatch(self.kind):
            raise ValueError("an operation kind is a slug")
        if not isinstance(self.key, str) or not 1 <= len(self.key) <= 200:
            raise ValueError("an operation key has 1-200 characters")


@dataclass(frozen=True)
class EvalBinding:
    """An evaluation attempt charges its scenario, its invocation and their common study."""

    study_id: UUID
    invocation_id: UUID
    scenario_id: UUID


Binding = RunBinding | OperationBinding | EvalBinding


@dataclass(frozen=True, order=True)
class ScopeRef:
    rank: int
    id: UUID
    kind: ScopeKind

    @staticmethod
    def of(kind: ScopeKind, scope_id: UUID) -> ScopeRef:
        return ScopeRef(KIND_RANK[kind], scope_id, kind)


def lock_order(refs: Sequence[ScopeRef]) -> list[ScopeRef]:
    """Kind rank, then the ID's canonical string, which is also PostgreSQL's uuid order."""
    return sorted(set(refs), key=lambda ref: (ref.rank, str(ref.id)))


@dataclass(frozen=True)
class Scope:
    id: UUID
    kind: ScopeKind
    cap_usd: Decimal
    cap_calls: int
    spent_usd: Decimal
    held_usd: Decimal
    calls_consumed: int
    calls_held: int
    overrun: bool
    cap_counts: int = 0
    counts_used: int = 0
    contract_block: str | None = None

    @property
    def available_usd(self) -> Decimal:
        """What a new hold may still take: active and unresolved holds count as committed."""
        return self.cap_usd - self.spent_usd - self.held_usd


def check_digest(value: object, what: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{what} is 64 lowercase hex characters")
    return value


def check_slug(value: object, what: str) -> str:
    if not isinstance(value, str) or not SLUG.fullmatch(value):
        raise ValueError(f"{what} is a slug")
    return value


@dataclass(frozen=True)
class Intent:
    """Everything an attempt is reserved under; its digest is its idempotency identity.

    Version 1 (T10, revision 0006) has no request fingerprint. Version 2 (T11) binds `request_sha256`, the
    fingerprint of the exact prepared provider request. A v1 digest is only ever verified with the v1 function, never
    recomputed as v2."""

    actor: Actor
    provider: str
    model: str
    price_revision: str
    config_sha256: str
    cache_mode: str
    max_input: int
    max_output: int
    operation_id: str
    reserved_usd: Decimal
    scope_ids: tuple[UUID, ...]
    request_sha256: str | None = None
    version: int = 2

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope_ids", tuple(self.scope_ids))
        if self.version not in (1, 2) or isinstance(self.version, bool):
            raise ValueError("an intent version is 1 or 2")
        if (self.version == 2) != (self.request_sha256 is not None):
            raise ValueError("a version 2 intent, and only one, has a request fingerprint")
        if self.request_sha256 is not None:
            check_digest(self.request_sha256, "request_sha256")

    def digest(self) -> str:
        body: dict[str, object] = {
            "v": "policyops.usage-intent/v1", "actor": self.actor, "provider": self.provider, "model": self.model,
            "price_revision": self.price_revision, "config_sha256": self.config_sha256,
            "cache_mode": self.cache_mode, "max_input": self.max_input, "max_output": self.max_output,
            "operation_id": self.operation_id, "reserved_usd": format(self.reserved_usd.normalize(), "f"),
            "scope_ids": sorted(str(s) for s in self.scope_ids)}
        if self.version == 2:
            body["v"] = "policyops.usage-intent/v2"
            body["request_sha256"] = self.request_sha256
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


CountState = Literal["none", "claimed", "admitted", "rejected", "failed"]
DIAGNOSTIC_FIELDS = ("input_tokens", "cache_read", "cache_creation", "cache_creation_5m", "cache_creation_1h",
                     "output", "reasoning", "total")


@dataclass(frozen=True)
class Diagnostic:
    """Token counts and reason codes kept for an attempt whose usage could not be priced. Allowlisted and small:
    never content, exception text or provider response JSON."""

    codes: tuple[str, ...]
    counts: Mapping[str, int | None] = MappingProxyType({})

    def __post_init__(self) -> None:
        codes = tuple(self.codes)
        if not 1 <= len(codes) <= 8:
            raise ValueError("a diagnostic has 1-8 reason codes")
        for code in codes:
            check_slug(code, "a diagnostic code")
        counts = dict(self.counts)
        for name, value in counts.items():
            if name not in DIAGNOSTIC_FIELDS:
                raise ValueError(f"{name!r} is not a diagnostic field")
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                                      or not 0 <= value < 2**31):
                raise ValueError(f"diagnostic {name} must be a non-negative integer or None")
        object.__setattr__(self, "codes", codes)
        object.__setattr__(self, "counts", MappingProxyType(counts))

    def canonical(self) -> dict[str, object]:
        return {"v": "policyops.usage-diagnostic/v1", "codes": list(self.codes),
                "counts": {name: self.counts[name] for name in sorted(self.counts)}}


@dataclass(frozen=True)
class Attempt:
    id: UUID
    intent: Intent
    intent_sha256: str
    state: State
    provider_request_id: str | None = None
    usage_sha256: str | None = None
    actual_tier: str | None = None
    actual_usd: Decimal | None = None
    overrun: bool = False
    count_state: CountState = "none"
    counted_input_tokens: int | None = None
    count_source: str | None = None
    contract_block: str | None = None
    diagnostic: Diagnostic | None = None


@dataclass(frozen=True)
class Settlement:
    """Known, fully priced usage reported for a dispatched attempt, with the provider's request ID when it gave one.
    `block` records a known contract mismatch: the exact bill settles and further progress stops."""

    usage: Usage
    provider_request_id: str | None = None
    block: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.usage, Usage):
            raise TypeError("usage must be a Usage")
        if self.provider_request_id is not None and (not isinstance(self.provider_request_id, str)
                                                     or not 1 <= len(self.provider_request_id) <= 200):
            raise ValueError("a provider request ID has 1-200 characters")
        if self.block is not None:
            check_slug(self.block, "a contract block")

    def canonical(self) -> dict[str, object]:
        # v1 (T10) is kept byte-for-byte for reported reasoning, so v1 digests and replays still match; v2 records an
        # unreported reasoning count as null rather than an observed zero.
        body: dict[str, object] = {
            "v": "policyops.usage/v1" if self.usage.reasoning is not None else "policyops.usage/v2",
            "input_total": self.usage.input_total, "cache_read": self.usage.cache_read,
            "cache_writes": dict(sorted(self.usage.cache_writes.items())), "output": self.usage.output,
            "reasoning": self.usage.reasoning, "provider_request_id": self.provider_request_id}
        if self.block is not None:
            body["block"] = self.block
        return body

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Reserved:
    attempt: Attempt
    created: bool


@dataclass(frozen=True)
class CountGranted:
    """The only result that permits one count call for this attempt, once."""

    attempt: Attempt


@dataclass(frozen=True)
class CountRefused:
    """Do not count. The attempt was already counted (or counting failed), is past `reserved`, is a legacy v1
    attempt, its run is no longer active, a scope is blocked, or the count resource is exhausted."""

    attempt: Attempt
    reason: str


@dataclass(frozen=True)
class DispatchGranted:
    """The only result that permits sending the request, once."""

    attempt: Attempt


RefusalReason = Literal["dispatching", "released", "settled", "unresolved", "blocked_by_overrun",
                        "blocked_by_contract", "run_not_active", "legacy_intent", "request_mismatch",
                        "count_not_admitted", "configuration_changed"]


@dataclass(frozen=True)
class DispatchRefused:
    """Do not send anything. Either the attempt is past `reserved` (its state is the reason), or it is still
    `reserved` but cannot be sent: a scope is overrun or contract-blocked, its run is no longer active, it is a
    legacy v1 attempt, the presented request is not the bound one, its count was not admitted, or the actor
    configuration it was reserved under has changed."""

    attempt: Attempt
    reason: RefusalReason


@dataclass(frozen=True)
class Settled:
    attempt: Attempt
    replayed: bool


# -- the store port ----------------------------------------------------------------------------------------------

class LedgerTransaction(Protocol):
    """One database transaction of one store. Each store accepts only its own binding types."""

    def now(self) -> datetime: ...

    def bind(self, binding: Binding, caps: Caps) -> tuple[ScopeRef, ...]:
        """Lock the bound run (`FOR SHARE`, refusing a terminal run), then find or create the binding's scopes.
        No scope row is locked yet."""
        ...

    def attempt_refs(self, attempt_id: UUID) -> tuple[ScopeRef, ...] | None:
        """The attempt's immutable scope bindings, read without a lock."""
        ...

    def run_active(self, refs: Sequence[ScopeRef]) -> bool:
        """Lock the run of a run scope among `refs` (`FOR SHARE`) and report whether it is active; True otherwise."""
        ...

    def check_admission(self, refs: Sequence[ScopeRef]) -> None:
        """Recheck dispatch authority after scope/attempt waits, immediately before granting new work."""
        ...

    def lock_scopes(self, refs: Sequence[ScopeRef]) -> list[Scope]:
        """Lock the scopes `FOR UPDATE`, one by one in the given order."""
        ...

    def lock_attempt(self, attempt_id: UUID) -> Attempt | None: ...
    def insert_attempt(self, attempt: Attempt, now: datetime) -> None: ...
    def update_attempt(self, attempt: Attempt, now: datetime, settlement: Settlement | None = None) -> None: ...
    def update_scope(self, scope: Scope, now: datetime) -> None: ...
    def record_usage(self, attempt: Attempt, settlement: Settlement, now: datetime) -> None: ...


class LedgerStore(Protocol):
    def transaction(self) -> AbstractContextManager[LedgerTransaction]: ...


# -- the rules ---------------------------------------------------------------------------------------------------

def check_room(scope: Scope, amount: Decimal) -> None:
    if scope.overrun:
        raise BudgetExhausted(scope.kind, "blocked_by_overrun")
    if scope.contract_block is not None:
        raise BudgetExhausted(scope.kind, "blocked_by_contract")
    if amount > scope.available_usd:
        raise BudgetExhausted(scope.kind, "usd_cap")
    if scope.calls_consumed + scope.calls_held + 1 > scope.cap_calls:
        raise BudgetExhausted(scope.kind, "call_cap")


def admitted(counted: int, max_input: int, headroom_percent: int, headroom_min: int) -> bool:
    """A counted request is admitted when its tokens plus the headroom fit the admitted maximum prompt."""
    headroom = max(-(-counted * headroom_percent // 100), headroom_min)
    return counted + headroom <= max_input


def blocked(scope: Scope, block: str | None) -> Scope:
    return scope if block is None or scope.contract_block is not None else replace(scope, contract_block=block)


class Ledger:
    def __init__(self, store: LedgerStore, configuration: Configuration,
                 earlier_snapshots: Sequence[PriceSnapshot] = ()) -> None:
        self.store = store
        self.configuration = configuration
        # A revision names one immutable price table: a second, different table under the same revision is refused
        # here, before anything is reserved or settled, so declaration order can never reprice an old attempt.
        snapshots: dict[str, PriceSnapshot] = {}
        for snapshot in (*earlier_snapshots, configuration.registry.snapshot):
            if not isinstance(snapshot, PriceSnapshot):
                raise TypeError("price snapshots must be PriceSnapshot values")
            known = snapshots.setdefault(snapshot.revision, snapshot)
            if known != snapshot:
                raise ValueError(f"price revision {snapshot.revision!r} is declared with different prices")
        self.snapshots: Mapping[str, PriceSnapshot] = MappingProxyType(snapshots)

    def _snapshot(self, revision: str) -> PriceSnapshot:
        found = self.snapshots.get(revision)
        if found is None:
            raise UnknownPrice(f"price revision {revision!r} is not installed")
        return found

    def reserve(self, binding: Binding, attempt_id: UUID, actor: Actor, operation_id: str,
                request_sha256: str) -> Reserved:
        if not isinstance(attempt_id, UUID):
            raise TypeError("attempt_id must be a UUID")
        if not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 200:
            raise ValueError("an operation ID has 1-200 characters")
        check_digest(request_sha256, "request_sha256")
        planned = self.configuration.reservation(actor)  # an unknown model/price/cache mode fails here, before spend
        with self.store.transaction() as tx:
            refs = lock_order(tx.bind(binding, self.configuration.caps))
            scopes = tx.lock_scopes(refs)
            intent = Intent(actor, planned.provider, planned.model, planned.price_revision, planned.config_sha256,
                            planned.cache_mode, planned.max_input, planned.max_output, operation_id,
                            planned.worst_usd, tuple(ref.id for ref in refs), request_sha256)
            existing = tx.lock_attempt(attempt_id)
            tx.check_admission(refs)
            if existing is not None:
                if existing.intent_sha256 != intent.digest():
                    raise LedgerConflict(f"attempt {attempt_id} was reserved with a different intent")
                return Reserved(existing, created=False)
            for scope in scopes:
                check_room(scope, planned.worst_usd)
            now = tx.now()
            attempt = Attempt(attempt_id, intent, intent.digest(), "reserved")
            tx.insert_attempt(attempt, now)
            for scope in scopes:
                tx.update_scope(replace(scope, held_usd=scope.held_usd + planned.worst_usd,
                                        calls_held=scope.calls_held + 1), now)
            return Reserved(attempt, created=True)

    @staticmethod
    def _refs(tx: LedgerTransaction, attempt_id: UUID) -> list[ScopeRef]:
        refs = tx.attempt_refs(attempt_id)  # immutable bindings, read before any lock
        if not refs:
            raise NotFound(f"no attempt {attempt_id}")
        return lock_order(refs)

    @staticmethod
    def _lock(tx: LedgerTransaction, attempt_id: UUID, refs: list[ScopeRef]) -> tuple[list[Scope], Attempt]:
        scopes = tx.lock_scopes(refs)
        attempt = tx.lock_attempt(attempt_id)
        if attempt is None or set(attempt.intent.scope_ids) != {ref.id for ref in refs}:
            raise NotFound(f"no attempt {attempt_id}")
        return scopes, attempt

    def _headroom(self, attempt: Attempt) -> tuple[int, int] | None:
        """The count headroom of the actor configuration the attempt was reserved under, or None when the server's
        configuration for that actor has changed since (the attempt can then no longer be counted or sent)."""
        planned = self.configuration.reservation(attempt.intent.actor)
        if planned.config_sha256 != attempt.intent.config_sha256:
            return None
        config = self.configuration.actors[attempt.intent.actor]
        return config.count_headroom_percent, config.count_headroom_min

    def claim_count(self, attempt_id: UUID, request_sha256: str) -> CountGranted | CountRefused:
        """none → claimed, committed before the count call. It consumes one count unit in every charged scope; a
        unit is never returned, so a release and re-reservation cannot count without limit. There is no count
        retry: a claimed, failed or completed count is never claimed again."""
        check_digest(request_sha256, "request_sha256")
        with self.store.transaction() as tx:
            refs = self._refs(tx, attempt_id)
            active = tx.run_active(refs)
            scopes, attempt = self._lock(tx, attempt_id, refs)
            tx.check_admission(refs)
            if attempt.intent.version != 2:
                return CountRefused(attempt, "legacy_intent")
            if attempt.intent.request_sha256 != request_sha256:
                return CountRefused(attempt, "request_mismatch")
            if attempt.state != "reserved":
                return CountRefused(attempt, attempt.state)
            if attempt.count_state != "none":
                return CountRefused(attempt, f"count_{attempt.count_state}")
            if not active:
                return CountRefused(attempt, "run_not_active")
            for scope in scopes:
                if scope.overrun:
                    return CountRefused(attempt, "blocked_by_overrun")
                if scope.contract_block is not None:
                    return CountRefused(attempt, "blocked_by_contract")
                if scope.counts_used + 1 > scope.cap_counts:
                    return CountRefused(attempt, "count_cap")
            now = tx.now()
            claimed = replace(attempt, count_state="claimed")
            tx.update_attempt(claimed, now)
            for scope in scopes:
                tx.update_scope(replace(scope, counts_used=scope.counts_used + 1), now)
            return CountGranted(claimed)

    def record_count(self, attempt_id: UUID, *, tokens: int | None, source: str) -> Attempt:
        """claimed → admitted | rejected (with the counted tokens) or failed (`tokens=None`). Recording the same result
        again is a replay; any other result is a conflict."""
        check_slug(source, "a count source")
        if tokens is not None and (isinstance(tokens, bool) or not isinstance(tokens, int) or not 0 <= tokens < 2**31):
            raise ValueError("counted tokens must be a non-negative integer")
        with self.store.transaction() as tx:
            _scopes, attempt = self._lock(tx, attempt_id, self._refs(tx, attempt_id))
            if attempt.count_state in ("admitted", "rejected", "failed"):
                if attempt.counted_input_tokens == tokens and attempt.count_source == (None if tokens is None
                                                                                       else source):
                    return attempt
                raise LedgerConflict(f"attempt {attempt_id} already has a different count")
            if attempt.count_state != "claimed":
                raise IllegalTransition(f"attempt {attempt_id} has no claimed count")
            if tokens is None:
                recorded = replace(attempt, count_state="failed")
            else:
                headroom = self._headroom(attempt)
                state: CountState = ("admitted" if headroom is not None
                                     and admitted(tokens, attempt.intent.max_input, *headroom) else "rejected")
                recorded = replace(attempt, count_state=state, counted_input_tokens=tokens, count_source=source)
            tx.update_attempt(recorded, tx.now())
            return recorded

    def begin_dispatch(self, attempt_id: UUID, request_sha256: str) -> DispatchGranted | DispatchRefused:
        check_digest(request_sha256, "request_sha256")
        with self.store.transaction() as tx:
            refs = self._refs(tx, attempt_id)
            active = tx.run_active(refs)
            scopes, attempt = self._lock(tx, attempt_id, refs)
            tx.check_admission(refs)
            if attempt.state != "reserved":
                return DispatchRefused(attempt, attempt.state)
            if attempt.intent.version != 2:
                return DispatchRefused(attempt, "legacy_intent")
            if attempt.intent.request_sha256 != request_sha256:
                return DispatchRefused(attempt, "request_mismatch")
            if not active:
                return DispatchRefused(attempt, "run_not_active")
            if any(scope.overrun for scope in scopes):
                return DispatchRefused(attempt, "blocked_by_overrun")
            if attempt.contract_block is not None or any(scope.contract_block is not None for scope in scopes):
                return DispatchRefused(attempt, "blocked_by_contract")
            headroom = self._headroom(attempt)
            if headroom is None:
                return DispatchRefused(attempt, "configuration_changed")
            if (attempt.count_state != "admitted" or attempt.counted_input_tokens is None
                    or not admitted(attempt.counted_input_tokens, attempt.intent.max_input, *headroom)):
                return DispatchRefused(attempt, "count_not_admitted")
            now = tx.now()
            dispatching = replace(attempt, state="dispatching")
            tx.update_attempt(dispatching, now)
            for scope in scopes:
                tx.update_scope(replace(scope, calls_held=scope.calls_held - 1,
                                        calls_consumed=scope.calls_consumed + 1), now)
            return DispatchGranted(dispatching)

    def release(self, attempt_id: UUID) -> Attempt:
        with self.store.transaction() as tx:
            scopes, attempt = self._lock(tx, attempt_id, self._refs(tx, attempt_id))
            if attempt.state == "released":
                return attempt
            if attempt.state != "reserved":
                raise IllegalTransition(f"a {attempt.state} attempt cannot be released (it may have been billed)")
            now = tx.now()
            released = replace(attempt, state="released")
            tx.update_attempt(released, now)
            for scope in scopes:  # a consumed count unit is not returned
                tx.update_scope(replace(scope, held_usd=scope.held_usd - attempt.intent.reserved_usd,
                                        calls_held=scope.calls_held - 1), now)
            return released

    def mark_unresolved(self, attempt_id: UUID, *, block: str | None = None,
                        diagnostic: Diagnostic | None = None) -> Attempt:
        """dispatching → unresolved: usage is unknown or cannot be priced. The conservative hold stays, and nothing
        is invented. With `block`, the attempt and every scope it charges are contract-blocked."""
        if block is not None:
            check_slug(block, "a contract block")
        if diagnostic is not None and not isinstance(diagnostic, Diagnostic):
            raise TypeError("diagnostic must be a Diagnostic")
        with self.store.transaction() as tx:
            scopes, attempt = self._lock(tx, attempt_id, self._refs(tx, attempt_id))
            if attempt.state == "settled":
                return attempt  # never downgrade a known result
            if attempt.state not in ("dispatching", "unresolved"):
                raise IllegalTransition(f"a {attempt.state} attempt was never dispatched")
            if attempt.state == "unresolved" and block is None and diagnostic is None:
                return attempt
            now = tx.now()
            unresolved = replace(attempt, state="unresolved", contract_block=attempt.contract_block or block,
                                 diagnostic=attempt.diagnostic or diagnostic)
            tx.update_attempt(unresolved, now)
            for scope in scopes:
                if block is not None and scope.contract_block is None:
                    tx.update_scope(blocked(scope, block), now)
            return unresolved

    def settle(self, attempt_id: UUID, settlement: Settlement) -> Settled:
        if not isinstance(settlement, Settlement):
            raise TypeError("settlement must be a Settlement")
        with self.store.transaction() as tx:
            scopes, attempt = self._lock(tx, attempt_id, self._refs(tx, attempt_id))
            digest = settlement.digest()
            if attempt.state == "settled":
                if attempt.usage_sha256 != digest:
                    raise LedgerConflict(f"attempt {attempt_id} was settled with different usage")
                return Settled(attempt, replayed=True)
            if attempt.state not in ("dispatching", "unresolved"):
                raise IllegalTransition(f"a {attempt.state} attempt was never dispatched")
            price = self._snapshot(attempt.intent.price_revision).price(attempt.intent.model)
            priced = cost(price, settlement.usage)
            overrun = priced.usd > attempt.intent.reserved_usd
            now = tx.now()
            settled = replace(attempt, state="settled", provider_request_id=settlement.provider_request_id,
                              usage_sha256=digest, actual_tier=priced.tier, actual_usd=priced.usd, overrun=overrun,
                              contract_block=attempt.contract_block or settlement.block)
            tx.update_attempt(settled, now, settlement)
            tx.record_usage(settled, settlement, now)
            for scope in scopes:
                tx.update_scope(blocked(replace(scope, held_usd=scope.held_usd - attempt.intent.reserved_usd,
                                                spent_usd=scope.spent_usd + priced.usd,
                                                overrun=scope.overrun or overrun), settlement.block), now)
            return Settled(settled, replayed=False)
