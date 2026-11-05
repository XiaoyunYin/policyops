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

## Locks and time

Every operation locks in one fixed order:
1. the run row (`FOR SHARE`), only for reserve and dispatch, so a concurrent cancellation is ordered before or after;
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

    @property
    def available_usd(self) -> Decimal:
        """What a new hold may still take: active and unresolved holds count as committed."""
        return self.cap_usd - self.spent_usd - self.held_usd


@dataclass(frozen=True)
class Intent:
    """Everything an attempt is reserved under; its digest is its idempotency identity."""

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

    def digest(self) -> str:
        body = {"v": "policyops.usage-intent/v1", "actor": self.actor, "provider": self.provider, "model": self.model,
                "price_revision": self.price_revision, "config_sha256": self.config_sha256,
                "cache_mode": self.cache_mode, "max_input": self.max_input,
                "max_output": self.max_output, "operation_id": self.operation_id,
                "reserved_usd": format(self.reserved_usd.normalize(), "f"),
                "scope_ids": sorted(str(s) for s in self.scope_ids)}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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


@dataclass(frozen=True)
class Settlement:
    """Known usage reported for a dispatched attempt, with the provider's request ID when it gave one."""

    usage: Usage
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.usage, Usage):
            raise TypeError("usage must be a Usage")
        if self.provider_request_id is not None and (not isinstance(self.provider_request_id, str)
                                                     or not 1 <= len(self.provider_request_id) <= 200):
            raise ValueError("a provider request ID has 1-200 characters")

    def canonical(self) -> dict[str, object]:
        return {"v": "policyops.usage/v1", "input_total": self.usage.input_total, "cache_read": self.usage.cache_read,
                "cache_writes": dict(sorted(self.usage.cache_writes.items())), "output": self.usage.output,
                "reasoning": self.usage.reasoning, "provider_request_id": self.provider_request_id}

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Reserved:
    attempt: Attempt
    created: bool


@dataclass(frozen=True)
class DispatchGranted:
    """The only result that permits sending the request, once."""

    attempt: Attempt


RefusalReason = Literal["dispatching", "released", "settled", "unresolved", "blocked_by_overrun", "run_not_active"]


@dataclass(frozen=True)
class DispatchRefused:
    """Do not send anything. Either the attempt is past `reserved` (its state is the reason), or it is still
    `reserved` but a scope it charges is overrun or its run is no longer active."""

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
    if amount > scope.available_usd:
        raise BudgetExhausted(scope.kind, "usd_cap")
    if scope.calls_consumed + scope.calls_held + 1 > scope.cap_calls:
        raise BudgetExhausted(scope.kind, "call_cap")


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

    def reserve(self, binding: Binding, attempt_id: UUID, actor: Actor, operation_id: str) -> Reserved:
        if not isinstance(attempt_id, UUID):
            raise TypeError("attempt_id must be a UUID")
        if not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 200:
            raise ValueError("an operation ID has 1-200 characters")
        planned = self.configuration.reservation(actor)  # an unknown model/price/cache mode fails here, before spend
        with self.store.transaction() as tx:
            refs = lock_order(tx.bind(binding, self.configuration.caps))
            scopes = tx.lock_scopes(refs)
            intent = Intent(actor, planned.provider, planned.model, planned.price_revision, planned.config_sha256,
                            planned.cache_mode, planned.max_input, planned.max_output, operation_id,
                            planned.worst_usd, tuple(ref.id for ref in refs))
            existing = tx.lock_attempt(attempt_id)
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

    def begin_dispatch(self, attempt_id: UUID) -> DispatchGranted | DispatchRefused:
        with self.store.transaction() as tx:
            refs = self._refs(tx, attempt_id)
            active = tx.run_active(refs)
            scopes, attempt = self._lock(tx, attempt_id, refs)
            if attempt.state != "reserved":
                return DispatchRefused(attempt, attempt.state)
            if not active:
                return DispatchRefused(attempt, "run_not_active")
            if any(scope.overrun for scope in scopes):
                return DispatchRefused(attempt, "blocked_by_overrun")
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
            for scope in scopes:
                tx.update_scope(replace(scope, held_usd=scope.held_usd - attempt.intent.reserved_usd,
                                        calls_held=scope.calls_held - 1), now)
            return released

    def mark_unresolved(self, attempt_id: UUID) -> Attempt:
        with self.store.transaction() as tx:
            _scopes, attempt = self._lock(tx, attempt_id, self._refs(tx, attempt_id))
            if attempt.state in ("unresolved", "settled"):
                return attempt  # never downgrade a known result
            if attempt.state != "dispatching":
                raise IllegalTransition(f"a {attempt.state} attempt was never dispatched")
            unresolved = replace(attempt, state="unresolved")
            tx.update_attempt(unresolved, tx.now())
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
                              usage_sha256=digest, actual_tier=priced.tier, actual_usd=priced.usd, overrun=overrun)
            tx.update_attempt(settled, now, settlement)
            tx.record_usage(settled, settlement, now)
            for scope in scopes:
                tx.update_scope(replace(scope, held_usd=scope.held_usd - attempt.intent.reserved_usd,
                                        spent_usd=scope.spent_usd + priced.usd,
                                        overrun=scope.overrun or overrun), now)
            return Settled(settled, replayed=False)
