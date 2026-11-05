"""The embedding job, plan, evidence and cache store (T12; schema from revision 0009). Static SQL only.

It runs as the app runtime inside `workspace_transaction`, so forced RLS confines every row to one workspace, and it
verifies at construction that its engine really authenticates as that restricted role.

- `plan_job` creates a job with its full intended input set, its frozen batch plan and its immutable deadline
  (`created_at + window_seconds`, on the database clock) in **one** transaction, or finds the existing job for the
  same `(purpose, subject_key)`. An existing job with any other input set, request configuration or tokenizer is a
  `JobConflict`. An existing plan and deadline are returned as stored: never re-batched or extended.
- Leases (`claim_lease`, `advance`, `release_lease`) guard job advancement only. A lease is claimed with one guarded
  `UPDATE` (free, expired or already ours) and bumps the fence; every advancement is fenced. Times are the database
  clock's.
- `publish` writes one attempt's evidence and, for a published outcome, its vectors in **one** transaction, after
  checking the evidence against the stored batch (attempt, request fingerprint and exact ordered input digests) and
  the ledger attempt (same request fingerprint and operation). The cache configuration key is the stored job's, never
  a caller's value.
  Evidence is first-write-wins: a replay must be identical, anything else is an `EvidenceConflict`. Cache rows are
  inserted with `ON CONFLICT DO NOTHING`, so an existing vector is never replaced.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
import math
import struct
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, text

from policyops.persistence.database import verify_runtime_role, workspace_transaction
from policyops.persistence.roles import APP_RUNTIME
from policyops.runtime.clock import DatabaseLeaseClock, LeaseClock, require_test_environment


BatchState = Literal["planned", "satisfied_by_cache", "published", "vectors_invalid", "blocked", "unresolved",
                     "orphaned"]
JobState = Literal["running", "complete", "blocked", "incomplete"]
EvidenceOutcome = Literal["published", "vectors_invalid", "count_mismatch", "usage_contradiction", "model_mismatch"]
TERMINAL: frozenset[str] = frozenset({"satisfied_by_cache", "published", "vectors_invalid", "blocked"})
_FLOAT32 = struct.Struct("<f")


class JobConflict(ValueError):
    """The subject already has a job with a different input set, request configuration or tokenizer."""


class EvidenceConflict(ValueError):
    """Evidence that does not match its batch, or differs from the evidence already recorded for the attempt."""


@dataclass(frozen=True)
class JobIdentity:
    purpose: str
    subject_key: str
    input_set_sha256: str
    input_count: int
    request_config_sha256: str
    tokenizer_sha256: str


@dataclass(frozen=True)
class PlannedInput:
    position: int
    input_sha256: str
    text: str
    local_tokens: int


@dataclass(frozen=True)
class BatchPlan:
    ordinal: int
    positions: tuple[int, ...]
    batch_sha256: str
    request_sha256: str
    local_tokens: int
    operation_id: str
    attempt_id: UUID


@dataclass(frozen=True)
class Batch:
    plan: BatchPlan
    state: BatchState
    lease_owner: UUID | None
    lease_until: datetime | None
    fence: int


@dataclass(frozen=True)
class Job:
    id: UUID
    identity: JobIdentity
    state: JobState
    version: int
    deadline_at: datetime
    created: bool


@dataclass(frozen=True)
class Lease:
    job_id: UUID
    ordinal: int
    owner: UUID
    fence: int


@dataclass(frozen=True)
class Evidence:
    attempt_id: UUID
    job_id: UUID
    ordinal: int
    request_sha256: str
    input_digests: tuple[str, ...]
    returned_model: str
    prompt_tokens: int
    total_tokens: int
    provider_request_id: str | None
    response_sha256: str
    norms: tuple[Decimal, ...] | None
    outcome: EvidenceOutcome


@dataclass(frozen=True)
class OperationScope:
    cap_usd: Decimal
    cap_calls: int
    cap_counts: int
    spent_usd: Decimal
    held_usd: Decimal
    calls_consumed: int
    calls_held: int
    counts_used: int
    contract_block: str | None


def norm_decimal(value: float) -> Decimal:
    """A finite float norm as the exact decimal of its shortest repr (stored in a numeric[] diagnostic column)."""
    if not math.isfinite(value):
        raise ValueError("a norm is finite")
    return Decimal(repr(value))


def vector_text(vector: Sequence[float]) -> str:
    return "[" + ",".join(repr(float(v)) for v in vector) + "]"


def parse_vector(value: str) -> tuple[float, ...]:
    """pgvector's text form, re-rounded to float32 (its storage precision) so values compare exactly."""
    if not value.startswith("[") or not value.endswith("]"):
        raise ValueError("not a vector")
    return tuple(_FLOAT32.unpack(_FLOAT32.pack(float(part)))[0] for part in value[1:-1].split(","))


def _one(connection: Connection, sql: str, params: Mapping[str, Any]) -> dict[str, Any] | None:
    row = connection.execute(text(sql), dict(params)).mappings().first()
    return dict(row) if row is not None else None


JOB_COLUMNS = ("id, purpose, subject_key, input_set_sha256, input_count, request_config_sha256, tokenizer_sha256, "
               "state, version, deadline_at")
BATCH_COLUMNS = ("ordinal, positions, batch_sha256, request_sha256, local_tokens, operation_id, attempt_id, state, "
                 "lease_owner, lease_until, fence")
EVIDENCE_COLUMNS = ("attempt_id, job_id, ordinal, request_sha256, input_digests, returned_model, prompt_tokens, "
                    "total_tokens, provider_request_id, response_sha256, norms, outcome")


def _job(row: Mapping[str, Any], created: bool) -> Job:
    identity = JobIdentity(row["purpose"], row["subject_key"], row["input_set_sha256"], row["input_count"],
                           row["request_config_sha256"], row["tokenizer_sha256"])
    return Job(row["id"], identity, row["state"], row["version"], row["deadline_at"], created)


def _batch(row: Mapping[str, Any]) -> Batch:
    plan = BatchPlan(row["ordinal"], tuple(row["positions"]), row["batch_sha256"], row["request_sha256"],
                     row["local_tokens"], row["operation_id"], row["attempt_id"])
    return Batch(plan, row["state"], row["lease_owner"], row["lease_until"], row["fence"])


def _evidence(row: Mapping[str, Any]) -> Evidence:
    norms = None if row["norms"] is None else tuple(Decimal(n) for n in row["norms"])
    return Evidence(row["attempt_id"], row["job_id"], row["ordinal"], row["request_sha256"],
                    tuple(row["input_digests"]), row["returned_model"], row["prompt_tokens"], row["total_tokens"],
                    row["provider_request_id"], row["response_sha256"], norms, row["outcome"])


class EmbeddingStore:
    def __init__(self, engine: Engine, workspace_id: UUID, *, env: str, clock: LeaseClock | None = None) -> None:
        self.clock = clock or DatabaseLeaseClock()
        require_test_environment(self.clock, env)  # before any database access
        if not isinstance(workspace_id, UUID):
            raise TypeError("workspace_id must be a UUID")
        verify_runtime_role(engine, APP_RUNTIME)
        self.engine = engine
        self.workspace_id = workspace_id

    @contextmanager
    def _tx(self) -> Iterator[Connection]:
        with workspace_transaction(self.engine, self.workspace_id) as connection:
            yield connection

    # -- jobs and plans --------------------------------------------------------------------------------------------

    def plan_job(self, identity: JobIdentity, inputs: Sequence[PlannedInput],
                 pack: Callable[[UUID, frozenset[str]], Sequence[BatchPlan]], *,
                 window_seconds: int) -> tuple[Job, list[Batch]]:
        """The job and its frozen plan. `pack(job_id, cached_digests)` builds the plan for a new job only; it sees
        the cache as of this transaction. A new job's deadline is `now + window_seconds` (database clock)."""
        if len(inputs) != identity.input_count:
            raise ValueError("the input count does not match the job identity")
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or not 1 <= window_seconds <= 86_400:
            raise ValueError("a job window is 1-86400 seconds")
        with self._tx() as connection:
            now = self.clock.now(connection)
            created = connection.execute(text(
                "INSERT INTO app.embedding_jobs (id, workspace_id, purpose, subject_key, input_set_sha256, "
                "input_count, request_config_sha256, tokenizer_sha256, state, created_at, deadline_at, updated_at) "
                "VALUES (:id, app.current_workspace(), :purpose, :subject_key, :input_set, :input_count, :config, "
                ":tokenizer, 'running', :now, :deadline, :now) "
                "ON CONFLICT (workspace_id, purpose, subject_key) DO NOTHING RETURNING id"),
                {"id": uuid4(), "purpose": identity.purpose, "subject_key": identity.subject_key,
                 "input_set": identity.input_set_sha256, "input_count": identity.input_count,
                 "config": identity.request_config_sha256, "tokenizer": identity.tokenizer_sha256,
                 "now": now, "deadline": now + timedelta(seconds=window_seconds)}).first()
            row = _one(connection, f"SELECT {JOB_COLUMNS} FROM app.embedding_jobs "  # noqa: S608
                       "WHERE purpose = :purpose AND subject_key = :subject_key",
                       {"purpose": identity.purpose, "subject_key": identity.subject_key})
            if row is None:
                raise JobConflict("the job could not be created or found")
            job = _job(row, created is not None)
            if job.identity != identity:
                raise JobConflict(f"subject {identity.subject_key!r} already has a job with a different input set, "
                                  "configuration or tokenizer")
            if job.created:
                if inputs:
                    connection.execute(text(
                        "INSERT INTO app.embedding_job_inputs (workspace_id, job_id, position, input_sha256, text, "
                        "local_tokens) VALUES (app.current_workspace(), :job, :position, :digest, :text, :tokens)"),
                        [{"job": job.id, "position": i.position, "digest": i.input_sha256, "text": i.text,
                          "tokens": i.local_tokens} for i in inputs])
                digests = sorted({i.input_sha256 for i in inputs})
                cached = frozenset(connection.execute(text(
                    "SELECT input_sha256 FROM app.embedding_cache WHERE request_config_sha256 = :config "
                    "AND input_sha256 = ANY(:digests)"),
                    {"config": identity.request_config_sha256, "digests": digests}).scalars().all())
                plans = list(pack(job.id, cached))
                if plans:
                    connection.execute(text(
                        "INSERT INTO app.embedding_batches (workspace_id, job_id, ordinal, positions, batch_sha256, "
                        "request_sha256, local_tokens, operation_id, attempt_id, state, updated_at) VALUES "
                        "(app.current_workspace(), :job, :ordinal, :positions, :batch, :request, :tokens, "
                        ":operation, :attempt, 'planned', :now)"),
                        [{"job": job.id, "ordinal": p.ordinal, "positions": list(p.positions),
                          "batch": p.batch_sha256, "request": p.request_sha256, "tokens": p.local_tokens,
                          "operation": p.operation_id, "attempt": p.attempt_id, "now": now} for p in plans])
            batches = self._batches(connection, job.id)
        return job, batches

    @staticmethod
    def _batches(connection: Connection, job_id: UUID) -> list[Batch]:
        rows = connection.execute(text(f"SELECT {BATCH_COLUMNS} FROM app.embedding_batches "  # noqa: S608
                                       "WHERE job_id = :job ORDER BY ordinal"), {"job": job_id}).mappings().all()
        return [_batch(dict(row)) for row in rows]

    def batches(self, job_id: UUID) -> list[Batch]:
        with self._tx() as connection:
            return self._batches(connection, job_id)

    def batch(self, job_id: UUID, ordinal: int) -> Batch | None:
        with self._tx() as connection:
            row = _one(connection, f"SELECT {BATCH_COLUMNS} FROM app.embedding_batches "  # noqa: S608
                       "WHERE job_id = :job AND ordinal = :ordinal", {"job": job_id, "ordinal": ordinal})
        return None if row is None else _batch(row)

    def inputs(self, job_id: UUID) -> list[PlannedInput]:
        with self._tx() as connection:
            rows = connection.execute(text(
                "SELECT position, input_sha256, text, local_tokens FROM app.embedding_job_inputs WHERE job_id = :job "
                "ORDER BY position"), {"job": job_id}).mappings().all()
        return [PlannedInput(r["position"], r["input_sha256"], r["text"], r["local_tokens"]) for r in rows]

    def set_job_state(self, job_id: UUID, state: JobState, expected_version: int) -> bool:
        with self._tx() as connection:
            now = self.clock.now(connection)
            done = connection.execute(text(
                "UPDATE app.embedding_jobs SET state = :state, version = version + 1, "
                "updated_at = greatest(updated_at, :now) WHERE id = :job AND version = :version"),
                {"state": state, "now": now, "job": job_id, "version": expected_version})
        return bool(done.rowcount)

    def remaining_seconds(self, job_id: UUID) -> float:
        """Seconds left before the job's immutable deadline, on the database clock (zero or less: expired)."""
        with self._tx() as connection:
            now = self.clock.now(connection)
            deadline = connection.execute(text("SELECT deadline_at FROM app.embedding_jobs WHERE id = :job"),
                                          {"job": job_id}).scalar_one()
        return float((deadline - now).total_seconds())

    def job(self, job_id: UUID) -> Job | None:
        with self._tx() as connection:
            row = _one(connection, f"SELECT {JOB_COLUMNS} FROM app.embedding_jobs WHERE id = :id",  # noqa: S608
                       {"id": job_id})
        return None if row is None else _job(row, False)

    def unreserved(self, attempt_ids: Sequence[UUID]) -> set[UUID]:
        """Which of these planned attempts have no ledger row yet (for the job-wide cap preflight)."""
        if not attempt_ids:
            return set()
        with self._tx() as connection:
            found = set(connection.execute(text("SELECT id FROM app.usage_attempts WHERE id = ANY(:ids)"),
                                           {"ids": list(attempt_ids)}).scalars().all())
        return set(attempt_ids) - found

    def operation_scope(self, kind: str, key: str) -> OperationScope | None:
        with self._tx() as connection:
            row = _one(connection, "SELECT cap_usd, cap_calls, cap_counts, spent_usd, held_usd, calls_consumed, "
                       "calls_held, counts_used, contract_block FROM app.budget_scopes WHERE operation_kind = :kind "
                       "AND operation_key = :key", {"kind": kind, "key": key})
        return None if row is None else OperationScope(**row)

    # -- leases (job advancement only) -----------------------------------------------------------------------------

    def claim_lease(self, job_id: UUID, ordinal: int, owner: UUID, seconds: float) -> Lease | None:
        """The batch's lease for `owner`, if it is free, expired or already `owner`'s; the fence always moves."""
        with self._tx() as connection:
            now = self.clock.now(connection)
            row = connection.execute(text(
                "UPDATE app.embedding_batches SET lease_owner = :owner, lease_until = :until, fence = fence + 1, "
                "updated_at = greatest(updated_at, :now) WHERE job_id = :job AND ordinal = :ordinal "
                "AND (lease_owner IS NULL OR lease_until <= :now OR lease_owner = :owner) RETURNING fence"),
                {"owner": owner, "until": now + timedelta(seconds=seconds), "now": now, "job": job_id,
                 "ordinal": ordinal}).first()
        return None if row is None else Lease(job_id, ordinal, owner, row[0])

    def advance(self, lease: Lease, state: BatchState) -> bool:
        """Fenced: only the current lease holder (same owner and fence) moves the batch state."""
        with self._tx() as connection:
            now = self.clock.now(connection)
            done = connection.execute(text(
                "UPDATE app.embedding_batches SET state = :state, updated_at = greatest(updated_at, :now) "
                "WHERE job_id = :job AND ordinal = :ordinal AND lease_owner = :owner AND fence = :fence"),
                {"state": state, "now": now, "job": lease.job_id, "ordinal": lease.ordinal, "owner": lease.owner,
                 "fence": lease.fence})
        return bool(done.rowcount)

    def holds(self, lease: Lease) -> bool:
        with self._tx() as connection:
            now = self.clock.now(connection)
            row = _one(connection, "SELECT 1 AS held FROM app.embedding_batches WHERE job_id = :job AND "
                       "ordinal = :ordinal AND lease_owner = :owner AND fence = :fence AND lease_until > :now",
                       {"job": lease.job_id, "ordinal": lease.ordinal, "owner": lease.owner, "fence": lease.fence,
                        "now": now})
        return row is not None

    def release_lease(self, lease: Lease) -> bool:
        with self._tx() as connection:
            now = self.clock.now(connection)
            done = connection.execute(text(
                "UPDATE app.embedding_batches SET lease_owner = NULL, lease_until = NULL, "
                "updated_at = greatest(updated_at, :now) WHERE job_id = :job AND ordinal = :ordinal "
                "AND lease_owner = :owner AND fence = :fence"),
                {"now": now, "job": lease.job_id, "ordinal": lease.ordinal, "owner": lease.owner,
                 "fence": lease.fence})
        return bool(done.rowcount)

    # -- evidence and cache ----------------------------------------------------------------------------------------

    def evidence(self, attempt_id: UUID) -> Evidence | None:
        with self._tx() as connection:
            row = _one(connection, f"SELECT {EVIDENCE_COLUMNS} FROM app.embedding_attempt_evidence "  # noqa: S608
                       "WHERE attempt_id = :attempt", {"attempt": attempt_id})
        return None if row is None else _evidence(row)

    def publish(self, evidence: Evidence, vectors: Sequence[Sequence[float]] | None) -> bool:
        """The evidence and (for `published`) its vectors, atomically. True if this call recorded the evidence,
        False for an identical replay."""
        if (evidence.outcome == "published") != (vectors is not None):
            raise EvidenceConflict("only published evidence carries vectors")
        if vectors is not None and len(vectors) != len(evidence.input_digests):
            raise EvidenceConflict("one vector per input")
        with self._tx() as connection:
            batch = _one(connection, f"SELECT {BATCH_COLUMNS} FROM app.embedding_batches "  # noqa: S608
                         "WHERE job_id = :job AND ordinal = :ordinal FOR SHARE",
                         {"job": evidence.job_id, "ordinal": evidence.ordinal})
            if batch is None or batch["attempt_id"] != evidence.attempt_id \
                    or batch["request_sha256"] != evidence.request_sha256:
                raise EvidenceConflict("the evidence does not belong to this batch's attempt and request")
            stored = connection.execute(text(
                "SELECT position, input_sha256 FROM app.embedding_job_inputs WHERE job_id = :job "
                "AND position = ANY(:positions)"), {"job": evidence.job_id,
                                                     "positions": list(batch["positions"])}).all()
            by_position = {position: digest for position, digest in stored}
            if tuple(by_position.get(p) for p in batch["positions"]) != evidence.input_digests:
                raise EvidenceConflict("the evidence inputs are not the batch's exact ordered inputs")
            attempt = _one(connection, "SELECT request_sha256, operation_id FROM app.usage_attempts WHERE id = :id",
                           {"id": evidence.attempt_id})
            if attempt is None or attempt["request_sha256"] != evidence.request_sha256 \
                    or attempt["operation_id"] != batch["operation_id"]:
                raise EvidenceConflict("the ledger attempt was not reserved for this exact request")
            request_config_sha256 = connection.execute(text(
                "SELECT request_config_sha256 FROM app.embedding_jobs WHERE id = :job"),
                {"job": evidence.job_id}).scalar_one()
            now = self.clock.now(connection)
            inserted = connection.execute(text(
                "INSERT INTO app.embedding_attempt_evidence (workspace_id, attempt_id, job_id, ordinal, "
                "request_sha256, input_digests, returned_model, prompt_tokens, total_tokens, provider_request_id, "
                "response_sha256, norms, outcome, created_at) VALUES (app.current_workspace(), :attempt, :job, "
                ":ordinal, :request, :inputs, :model, :prompt, :total, :request_id, :response, :norms, :outcome, "
                ":now) ON CONFLICT (workspace_id, attempt_id) DO NOTHING RETURNING attempt_id"),
                {"attempt": evidence.attempt_id, "job": evidence.job_id, "ordinal": evidence.ordinal,
                 "request": evidence.request_sha256, "inputs": list(evidence.input_digests),
                 "model": evidence.returned_model, "prompt": evidence.prompt_tokens, "total": evidence.total_tokens,
                 "request_id": evidence.provider_request_id, "response": evidence.response_sha256,
                 "norms": None if evidence.norms is None else list(evidence.norms), "outcome": evidence.outcome,
                 "now": now}).first()
            if inserted is None:
                row = _one(connection, f"SELECT {EVIDENCE_COLUMNS} FROM app.embedding_attempt_evidence "  # noqa: S608
                           "WHERE attempt_id = :attempt", {"attempt": evidence.attempt_id})
                if row is None or _evidence(row) != evidence:
                    raise EvidenceConflict(f"attempt {evidence.attempt_id} already has different evidence")
                return False
            if vectors is not None:
                connection.execute(text(
                    "INSERT INTO app.embedding_cache (workspace_id, input_sha256, request_config_sha256, attempt_id, "
                    "vector, created_at) VALUES (app.current_workspace(), :digest, :config, :attempt, "
                    "CAST(:vector AS vector), :now) "
                    "ON CONFLICT (workspace_id, input_sha256, request_config_sha256) DO NOTHING"),
                    [{"digest": digest, "config": request_config_sha256, "attempt": evidence.attempt_id,
                      "vector": vector_text(vector), "now": now}
                     for digest, vector in zip(evidence.input_digests, vectors, strict=True)])
        return True

    def cached(self, request_config_sha256: str, digests: Sequence[str]) -> dict[str, tuple[float, ...]]:
        if not digests:
            return {}
        with self._tx() as connection:
            rows = connection.execute(text(
                "SELECT input_sha256, vector::text FROM app.embedding_cache WHERE request_config_sha256 = :config "
                "AND input_sha256 = ANY(:digests)"),
                {"config": request_config_sha256, "digests": sorted(set(digests))}).all()
        return {digest: parse_vector(vector) for digest, vector in rows}
