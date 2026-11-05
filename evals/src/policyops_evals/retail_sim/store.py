"""Durable per-case state, versions, operation outcomes and receipts (PostgreSQL, as `retail_runtime`).

Every transaction sets the tenant/case row-level-security scope and finite `lock_timeout`/`statement_timeout`.
Lock order is fixed: the case row first, then everything else.

* **Mutation** (`mutate`): lock the case row (`FOR UPDATE`) → look up the operation ID *under the lock* (an existing
  row with the same fingerprint replays; another fingerprint conflicts) → scope and exact version coverage → the
  upstream tool on an isolated candidate (`engine.mutate`) → one terminal row, committed atomically with the new
  state, versions and receipt, or with nothing else changed. `version_conflict` is terminal too.
* **Fence** (`fence`): the same lock; an absent operation becomes a terminal `fenced` row bound to the expected
  original fingerprint. A late original with that fingerprint then replays `fenced`.
* **Lookup** (`lookup`) never fences: absence is `unknown`.
* **Read** (`read`): `FOR SHARE` on the case row, then the versions, in one transaction; nothing is written.
* **Nonces** (`use_nonce`): one committed row per (tenant, case, jti); a second use is refused.
No network or model call happens inside any transaction.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
import json
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError

from policyops_contracts.retail import ResourceVersion
from policyops_contracts.retail_service import (
    CaseInitialization,
    CaseState,
    FenceRequest,
    LookupResult,
    MutationRequest,
    OperationResult,
    ReadRequest,
    ReadResult,
    Receipt,
    ServiceContext,
    operation_fingerprint,
)
from policyops_evals.retail_sim import codec, engine
from policyops_evals.retail_sim.fixture import Fixture, Upstream
from policyops_evals.retail_sim.migrate import current, head


LOCK_TIMEOUT = "2s"
STATEMENT_TIMEOUT = "15s"


class StoreError(Exception):
    status = 500

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CaseNotFound(StoreError):
    status = 404


class NotFound(StoreError):
    status = 404


class Conflict(StoreError):
    status = 409


class InvalidRequest(StoreError):
    status = 400


class Rejected(StoreError):
    status = 422


class Replayed(StoreError):
    status = 401


class Expired(StoreError):
    """The signed context expired while the request waited (for the case lock, a fault delay or the candidate);
    nothing was applied. Service-authentication enforcement only, not staff approval."""

    status = 401


def _now() -> datetime:
    return datetime.now(UTC)


class Store:
    def __init__(self, engine_: Engine, fixture: Fixture, upstream: Upstream,
                 clock: Callable[[], datetime] = _now) -> None:
        self.engine, self.fixture, self.upstream, self.clock = engine_, fixture, upstream, clock

    def require_head(self) -> None:
        with self.engine.connect() as connection:
            if current(connection) != head():
                raise RuntimeError("the retail schema is not at the head revision; run the retail migrations")

    @contextmanager
    def _tx(self, tenant_id: UUID, case_id: UUID) -> Iterator[Connection]:
        with self.engine.connect() as connection, connection.begin():
            connection.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
            connection.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))
            connection.execute(text("SELECT set_config('retail.tenant_id', :t, true), "
                                    "set_config('retail.case_id', :c, true)"),
                               {"t": str(tenant_id), "c": str(case_id)})
            yield connection

    # -- nonces ------------------------------------------------------------------------------------------------

    def use_nonce(self, context: ServiceContext) -> None:
        with self._tx(context.tenant_id, context.case_id) as c:
            c.execute(text("DELETE FROM retail.token_uses WHERE expires_at < now()"))
            used = c.execute(text(
                "INSERT INTO retail.token_uses (tenant_id, case_id, jti, expires_at) VALUES (:t, :c, :j, "
                "to_timestamp(:e)) ON CONFLICT DO NOTHING RETURNING jti"),
                {"t": context.tenant_id, "c": context.case_id, "j": context.jti, "e": context.exp}).first()
        if used is None:
            raise Replayed("nonce_replayed")

    # -- initialization ----------------------------------------------------------------------------------------

    def initialize(self, context: ServiceContext, request: CaseInitialization) -> CaseState:
        if (request.fixture_sha256, context.fixture_sha256) != (self.fixture.sha256, self.fixture.sha256) or \
                request.customer_id != context.customer_id:
            raise InvalidRequest("identity_mismatch")
        db = codec.decode(self.fixture.raw, self.upstream.retail_db)
        state = codec.dump(db)
        if request.customer_id not in state["users"]:
            raise InvalidRequest("unknown_customer")
        raw = codec.encode(db)
        now = self.clock()
        with self._tx(context.tenant_id, context.case_id) as c:
            created = c.execute(text(
                "INSERT INTO retail.case_states (tenant_id, case_id, customer_id, fixture_id, fixture_sha256, codec, "
                "version, state, state_sha256, created_at, updated_at) VALUES (:t, :c, :customer, :fid, :fsha, "
                ":codec, 1, :state, :ssha, :now, :now) ON CONFLICT DO NOTHING RETURNING version"),
                {"t": context.tenant_id, "c": context.case_id, "customer": request.customer_id,
                 "fid": request.fixture_id, "fsha": request.fixture_sha256, "codec": codec.CODEC, "state": raw,
                 "ssha": codec.digest(raw), "now": now}).first()
            if created is not None:
                resources = [{"t": context.tenant_id, "c": context.case_id, "k": "user", "r": request.customer_id}]
                resources += [{"t": context.tenant_id, "c": context.case_id, "k": "order", "r": oid}
                              for oid, order in state["orders"].items() if order["user_id"] == request.customer_id]
                c.execute(text("INSERT INTO retail.case_resources (tenant_id, case_id, kind, resource_id, version) "
                               "VALUES (:t, :c, :k, :r, 1)"), resources)
                return CaseState(fixture_id=request.fixture_id, fixture_sha256=request.fixture_sha256,
                                 customer_id=request.customer_id, case_version=1, created=True)
            row = c.execute(text("SELECT customer_id, fixture_id, fixture_sha256, version FROM retail.case_states"
                                 )).mappings().one()
        if (row["customer_id"], row["fixture_id"], row["fixture_sha256"]) != \
                (request.customer_id, request.fixture_id, request.fixture_sha256):
            raise Conflict("case_identity_conflict")
        return CaseState(fixture_id=request.fixture_id, fixture_sha256=request.fixture_sha256,
                         customer_id=request.customer_id, case_version=row["version"], created=False)

    def _case(self, c: Connection, context: ServiceContext, lock: str) -> Any:
        if lock not in ("", "FOR SHARE", "FOR UPDATE"):
            raise ValueError("unknown lock clause")
        row = c.execute(text("SELECT customer_id, fixture_sha256, version, state FROM retail.case_states "  # noqa: S608
                             + lock)  # one of three fixed clauses
                        ).mappings().first()
        if row is None:
            raise CaseNotFound("case_not_found")
        if (row["customer_id"], row["fixture_sha256"]) != (context.customer_id, context.fixture_sha256):
            raise Conflict("case_identity_conflict")
        return row

    @staticmethod
    def _versions(c: Connection) -> dict[engine.Resource, int]:
        return {(r["kind"], r["resource_id"]): r["version"] for r in c.execute(text(
            "SELECT kind, resource_id, version FROM retail.case_resources")).mappings()}

    # -- reads -------------------------------------------------------------------------------------------------

    def read(self, context: ServiceContext, request: ReadRequest) -> ReadResult:
        with self._tx(context.tenant_id, context.case_id) as c:
            row = self._case(c, context, "FOR SHARE")
            versions = self._versions(c)
        try:
            output, shown = engine.read(self.upstream, bytes(row["state"]), request.call, context.customer_id,
                                        lambda r: engine.CATALOG_VERSION if r[0] == "product" else versions[r])
        except engine.NotInScope:
            raise NotFound("not_found") from None
        except engine.ReadRejected:
            raise Rejected("upstream_rejected") from None
        listed = tuple(ResourceVersion(kind=k, resource_id=r,
                                       version=engine.CATALOG_VERSION if k == "product" else versions[(k, r)])
                       for k, r in sorted(shown))
        return ReadResult(output=output, case_version=row["version"], resource_versions=listed)

    # -- operations --------------------------------------------------------------------------------------------

    def _existing(self, c: Connection, operation_id: UUID) -> Any:
        return c.execute(text("SELECT * FROM retail.operations WHERE operation_id = :o"),
                         {"o": operation_id}).mappings().first()

    @staticmethod
    def _result(row: Any, *, replayed: bool) -> OperationResult:
        receipt = None if row["receipt"] is None else Receipt.model_validate_json(json.dumps(row["receipt"]))
        return OperationResult(operation_id=str(row["operation_id"]), operation_sha256=row["operation_sha256"],
                               outcome=row["outcome"], receipt=receipt, replayed=replayed)

    def _require_unexpired(self, context: ServiceContext) -> None:
        if context.exp <= self.clock().timestamp():
            raise Expired("context_expired_before_apply")

    def _record(self, c: Connection, context: ServiceContext, operation_id: UUID, fingerprint: str, tool: str | None,
                outcome: str, code: str | None, version: int, receipt: Receipt | None = None) -> OperationResult:
        # Every terminal write (a commit, a rejection, a version conflict or a fence) passes here, under the case
        # lock and inside the same transaction as any state change: an expired context rolls all of it back.
        self._require_unexpired(context)
        after = version + 1 if outcome == "committed" else version
        c.execute(text(
            "INSERT INTO retail.operations (tenant_id, case_id, operation_id, operation_sha256, tool, outcome, code, "
            "case_version_before, case_version_after, receipt, created_at) VALUES (:t, :c, :o, :sha, :tool, :outcome, "
            ":code, :before, :after, CAST(:receipt AS jsonb), :now)"),
            {"t": context.tenant_id, "c": context.case_id, "o": operation_id, "sha": fingerprint, "tool": tool,
             "outcome": outcome, "code": code, "before": version, "after": after,
             "receipt": None if receipt is None else receipt.model_dump_json(), "now": self.clock()})
        return OperationResult(operation_id=str(operation_id), operation_sha256=fingerprint, outcome=outcome,  # type: ignore[arg-type]
                               receipt=receipt, replayed=False)

    def fingerprint(self, context: ServiceContext, operation_id: UUID, request: MutationRequest) -> str:
        return operation_fingerprint(tenant_id=context.tenant_id, case_id=context.case_id,
                                     customer_id=context.customer_id, fixture_sha256=context.fixture_sha256,
                                     operation_id=operation_id, request=request)

    def mutate(self, context: ServiceContext, operation_id: UUID, request: MutationRequest,
               before_commit: Callable[[], None] = lambda: None) -> OperationResult:
        fingerprint = self.fingerprint(context, operation_id, request)
        call = request.call
        try:
            with self._tx(context.tenant_id, context.case_id) as c:
                row = self._case(c, context, "FOR UPDATE")  # the case lock first, then the operation lookup
                existing = self._existing(c, operation_id)
                if existing is not None:
                    if existing["operation_sha256"] != fingerprint:
                        raise Conflict("operation_conflict")
                    return self._result(existing, replayed=True)
                raw = bytes(row["state"])
                state = codec.dump(codec.decode(raw, self.upstream.retail_db))
                try:
                    engine.check_scope(state, call, context.customer_id)
                except engine.NotInScope:
                    raise NotFound("not_found") from None
                given = {(v.kind, v.resource_id): v.version for v in request.expected_versions}
                versions = self._versions(c)
                # The order and user versions first: a stale proposal is a terminal version conflict even when the
                # current state no longer contains the items it named. Then exact coverage, catalog included.
                core = engine.core_versions(call, context.customer_id)
                if not core <= set(given):
                    raise InvalidRequest("expected_versions_mismatch")
                if any(versions.get(key) != given[key] for key in core):
                    return self._record(c, context, operation_id, fingerprint, call.tool, "version_conflict",
                                        "stale_versions", row["version"])
                required = engine.required_versions(state, call, context.customer_id)
                extra = set(given) - required
                # Exact coverage when every named item resolves. When one does not, upstream rejects the call (a
                # terminal row below), so only the unresolvable catalog entries may be extra.
                if not required <= set(given) or (extra and not (
                        engine.unresolved_items(state, call) and all(key[0] == "product" for key in extra))):
                    raise InvalidRequest("expected_versions_mismatch")
                if any(given[key] != engine.CATALOG_VERSION for key in required if key[0] == "product"):
                    return self._record(c, context, operation_id, fingerprint, call.tool, "version_conflict",
                                        "stale_versions", row["version"])
                attempt = engine.mutate(self.upstream, raw, call, request.expected_effect, context.customer_id)
                if attempt.outcome != "committed":
                    return self._record(c, context, operation_id, fingerprint, call.tool, attempt.outcome,
                                        attempt.code, row["version"])
                if attempt.state is None or attempt.effect is None:  # pragma: no cover - committed carries both
                    raise RuntimeError("a committed attempt must carry its state and effect")
                version = row["version"]
                now = self.clock()
                c.execute(text("UPDATE retail.case_states SET version = :v, state = :s, state_sha256 = :sha, "
                               "updated_at = :now"),
                          {"v": version + 1, "s": attempt.state, "sha": codec.digest(attempt.state), "now": now})
                for kind, resource in sorted(attempt.changed):
                    bumped = c.execute(text("UPDATE retail.case_resources SET version = version + 1 WHERE kind = :k "
                                            "AND resource_id = :r RETURNING version"),
                                       {"k": kind, "r": resource}).first()
                    if bumped is None:
                        raise InvalidRequest("untracked_resource_changed")  # rolls the whole candidate back
                after = self._versions(c)
                receipt = Receipt(
                    operation_id=str(operation_id), operation_sha256=fingerprint, tool=call.tool,
                    actual_effect=attempt.effect, case_version_before=version, case_version_after=version + 1,
                    resource_versions_after=tuple(
                        ResourceVersion(kind=k, resource_id=r,
                                        version=engine.CATALOG_VERSION if k == "product" else after[(k, r)])
                        for k, r in sorted(required)),
                    state_sha256_after=codec.digest(attempt.state), committed_at=now)
                result = self._record(c, context, operation_id, fingerprint, call.tool, "committed", None, version,
                                      receipt)
                before_commit()
                return result
        except IntegrityError:
            raise Conflict("operation_conflict") from None  # a concurrent insert of the same ID; retry replays

    def lookup(self, context: ServiceContext, operation_id: UUID) -> LookupResult:
        with self._tx(context.tenant_id, context.case_id) as c:
            self._case(c, context, "")
            existing = self._existing(c, operation_id)
        if existing is None:
            return LookupResult(state="unknown")
        return LookupResult(state="found", result=self._result(existing, replayed=True))

    def fence(self, context: ServiceContext, operation_id: UUID, request: FenceRequest) -> OperationResult:
        with self._tx(context.tenant_id, context.case_id) as c:
            row = self._case(c, context, "FOR UPDATE")
            existing = self._existing(c, operation_id)
            if existing is not None:
                if existing["operation_sha256"] != request.operation_sha256:
                    raise Conflict("operation_conflict")
                return self._result(existing, replayed=True)
            return self._record(c, context, operation_id, request.operation_sha256, None, "fenced", None,
                                row["version"])

    # -- faults (test and demo configuration only) -------------------------------------------------------------

    def arm_fault(self, context: ServiceContext, fault: str, count: int) -> None:
        with self._tx(context.tenant_id, context.case_id) as c:
            self._case(c, context, "FOR UPDATE")
            c.execute(text("INSERT INTO retail.fault_plans (tenant_id, case_id, fault, remaining, created_at) VALUES "
                           "(:t, :c, :f, :n, :now) ON CONFLICT (tenant_id, case_id, fault) DO UPDATE SET remaining = "
                           "EXCLUDED.remaining"),
                      {"t": context.tenant_id, "c": context.case_id, "f": fault, "n": count, "now": self.clock()})

    def take_fault(self, context: ServiceContext, fault: str) -> bool:
        """Consume one armed fault of this kind (one-shot); True when one was armed."""
        with self._tx(context.tenant_id, context.case_id) as c:
            taken = c.execute(text("UPDATE retail.fault_plans SET remaining = remaining - 1 WHERE fault = :f "
                                   "AND remaining > 0 RETURNING remaining"), {"f": fault}).first()
        return taken is not None
