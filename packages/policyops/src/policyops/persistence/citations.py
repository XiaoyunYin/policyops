"""Citation recording and historical reconciliation (T14; existing `app.citations`, grants, RLS and T12 guard).

A `CitationBundle` is an assertion to recheck, never authority: it carries no status, and a pydantic shape or a
constructor is not the authorization mechanism. The caller's context (`run_id`, `authorized_steps`, `corpus_key`) is a
separate input that must equal the bundle's; a mismatch refuses before any SQL.

**`record`**: one short `READ COMMITTED` read-write transaction on the recorder's own connection, owned from
acquisition, with static SQL only and no provider, human or model work inside:

1. the corpus row `FOR SHARE` (T12 publication takes it `FOR UPDATE`, so an activation is ordered entirely before or
   after this transaction); the equal rows already present are observed;
2. every claim's generation must be the active one (`stale_evidence` otherwise: new writes need current evidence);
3. every claim is rechecked on this connection: the trace ID derives from this workspace, run and step; the stored
   trace and its intent pass the shared query-less checks; the payload and request digests, the delivered `E`-to-chunk
   mapping (a ready chunk that was not delivered in that step fails), the document and version, the stored version
   digest, the span inside the delivered chunk, the quote digest and the exact body slice. The first failure refuses
   the whole batch (`record_claim_mismatch:<field>`);
4. deadline checkpoint, then `INSERT … ON CONFLICT (id) DO NOTHING` for every distinct ID not already present (the
   unchanged T12 guard runs on each new row), then every distinct ID is read back and compared field by field, with
   the body slice against the quote; an absent or unequal row is `citation_id_conflict`;
5. COMMIT. An exception from COMMIT has an unknown outcome: `record_ambiguous`, never success. A COMMIT acknowledged
   after the deadline returns `deadline_passed` with `committed="observed"`; the rows are kept.

New writes are all-or-none; equal rows that already existed are a normal state (an earlier subset, or another bundle
citing the same span) and are reported, never rewritten. A concurrent uncommitted insert of the same ID makes
PostgreSQL wait on that key: a synchronous wait with configured SQL timeout profiles, with checkpoints
only after control returns. `recorded` claims only that these exact rows exist and were, at commit, ready-generation
evidence delivered to this run's authorized step, quoting the exact body slice; not that they stay current.

**`reconcile`**: read-only and historical. It reads `app.citations`, the step records and the version bodies (never
`app.chunks`), so it works after an activation. `not_observed_yet` and `missing_ids` never prove absence (an ambiguous
COMMIT may still be completing); there is no definitive "not recorded", and an observation never authorizes a write.

Cleanup failures (rollback, close) are attached as type-only notes to the original failure, never replacing it.
Fault injection exists only as an explicit test-only `FaultPlan` (fixed points, no callbacks), refused outside tests.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
import hashlib
import time
from typing import Any, ClassVar, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ValidationError
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from policyops.persistence.database import (
    DatabaseUnavailable,
    classify_sql_failure,
    connect_runtime,
    initialize_transaction,
    verify_runtime_role,
    workspace_transaction,
)
from policyops.persistence.retrieval import RetrievalStore, read_spans, read_step_record
from policyops.persistence.roles import APP_RUNTIME
from policyops.retrieval.grounding import (
    StepEvidence,
    StepFailure,
    check_step,
    check_step_evidence,
    context_problem,
    deadline_problem,
)
from policyops.retrieval.search import span_entries, trace_id_for
from policyops.runtime.clock import require_test_environment
from policyops_contracts.grounding import CitationBundle, CitationClaim, ReconcileOutcome, RecordOutcome


CITATION_NAMESPACE = uuid5(NAMESPACE_URL, "policyops:citation/v1")
MAX_SPAN_CODE_POINTS = 20_000
ROWS_SQL = (
    "SELECT c.id, c.trace_id, c.chunk_id, c.document_version_id, c.span_start, c.span_end, t.run_id, "
    "encode(sha256(convert_to(v.body, 'UTF8')), 'hex') = v.sha256 AS digest_ok, "
    "EXISTS (SELECT 1 FROM app.generation_documents m WHERE m.workspace_id = c.workspace_id "
    "AND m.generation_id = t.generation_id AND m.document_version_id = c.document_version_id) AS member, "
    "CASE WHEN c.span_end <= char_length(v.body) AND c.span_end - c.span_start <= :limit THEN "
    "substring(v.body FROM c.span_start + 1 FOR c.span_end - c.span_start) END AS span_text "
    "FROM app.citations c "
    "JOIN app.retrieval_traces t ON t.workspace_id = c.workspace_id AND t.id = c.trace_id "
    "JOIN app.document_versions v ON v.workspace_id = c.workspace_id AND v.id = c.document_version_id "
    "WHERE c.id = ANY(CAST(:ids AS uuid[]))")
INSERT_SQL = (
    "INSERT INTO app.citations (id, workspace_id, trace_id, chunk_id, document_version_id, span_start, span_end, "
    "created_at) SELECT e.id, app.current_workspace(), e.trace_id, e.chunk_id, e.version_id, e.span_start, "
    "e.span_end, now() FROM unnest(CAST(:ids AS uuid[]), CAST(:traces AS uuid[]), CAST(:chunks AS uuid[]), "
    "CAST(:versions AS uuid[]), CAST(:starts AS integer[]), CAST(:ends AS integer[])) "
    "AS e(id, trace_id, chunk_id, version_id, span_start, span_end) ON CONFLICT (id) DO NOTHING RETURNING id")
_STALE_GUARD = "citation_chunk_not_ready"


def citation_id(workspace_id: UUID, trace_id: UUID, chunk_id: UUID, span_start: int, span_end: int) -> UUID:
    """`uuid5(CITATION_NAMESPACE, "{workspace}:{trace}:{chunk}:{start}:{end}")`: canonical lowercase hyphenated
    UUIDs and unpadded base-10 offsets."""
    return uuid5(CITATION_NAMESPACE, f"{workspace_id}:{trace_id}:{chunk_id}:{span_start}:{span_end}")


class RecorderFault(Exception):
    """Raised only by a test-only `FaultPlan`."""


@dataclass(frozen=True)
class FaultPlan:
    """Test-only fault points (no callbacks): fail after the full recheck, the inserts and the read-back but before
    COMMIT is sent, or after a real COMMIT returned (a lost acknowledgement)."""

    before_commit: bool = False
    after_commit: bool = False
    test_only: ClassVar[bool] = True


@dataclass(frozen=True)
class _Row:
    trace_id: UUID
    chunk_id: UUID
    document_version_id: UUID
    span_start: int
    span_end: int
    run_id: UUID
    digest_ok: bool
    member: bool
    span_text: str | None

    def stored_equal(self, claim: CitationClaim, run_id: UUID) -> bool:
        """The stored row's own fields (and its run, version digest and generation membership) equal the claim's. An
        unequal row with the claim's deterministic ID is a conflict; the quote itself is the claim's recheck."""
        return ((self.trace_id, self.chunk_id, self.document_version_id, self.span_start, self.span_end, self.run_id)
                == (claim.trace_id, claim.chunk_id, claim.document_version_id, claim.span_start, claim.span_end,
                    run_id) and self.digest_ok and self.member)

    def equals(self, claim: CitationClaim, run_id: UUID) -> bool:
        """Stored fields equal and the body slice is exactly the claim's quote (the read-back after the recheck)."""
        return self.stored_equal(claim, run_id) and self.span_text == claim.quote


def _rows(connection: Connection, ids: Sequence[UUID]) -> dict[UUID, _Row]:
    found = connection.execute(text(ROWS_SQL), {"ids": list(ids), "limit": MAX_SPAN_CODE_POINTS}).mappings().all()
    return {r["id"]: _Row(r["trace_id"], r["chunk_id"], r["document_version_id"], r["span_start"], r["span_end"],
                          r["run_id"], bool(r["digest_ok"]), bool(r["member"]), r["span_text"]) for r in found}


_EVIDENCE_FIELDS = {"trace_not_found": "trace", "trace_integrity": "trace", "corpus_mismatch": "corpus"}


def recheck(claim: CitationClaim, evidence: StepEvidence | StepFailure, *, workspace_id: UUID,
            run_id: UUID) -> str | None:
    """The first claim field that the stored records contradict, or None (pure)."""
    if claim.trace_id != trace_id_for(workspace_id, run_id, claim.step):
        return "trace_id"
    if isinstance(evidence, StepFailure):
        return _EVIDENCE_FIELDS[evidence.status]
    checked = evidence.checked
    if claim.trace_payload_sha256 != checked.candidates.payload_sha256:
        return "trace_payload_sha256"
    if claim.request_sha256 != checked.intent.request_sha256:
        return "request_sha256"
    if claim.generation_id != checked.candidates.generation_id:
        return "generation_id"
    found = evidence.entry(claim.evidence_id)
    if found is None:
        return "evidence_id"
    entry, chunk, span = found
    for name, stored in (("chunk_id", entry.chunk_id), ("document_id", entry.document_id),
                         ("document_version_id", entry.document_version_id),
                         ("chunk_text_sha256", entry.text_sha256), ("version_sha256", span.version_sha256)):
        if getattr(claim, name) != stored:
            return name
    if not entry.start <= claim.span_start < claim.span_end <= entry.end:
        return "span"
    if hashlib.sha256(claim.quote.encode("utf-8")).hexdigest() != claim.quote_sha256:
        return "quote_sha256"
    if chunk.text[claim.span_start - entry.start:claim.span_end - entry.start] != claim.quote:
        return "quote"
    return None


class _Refusal(Exception):
    def __init__(self, code: str, failing: int | None = None) -> None:
        super().__init__(code)
        self.code, self.failing = code, failing


@dataclass(frozen=True)
class _Prepared:
    bundle: CitationBundle
    claim_ids: tuple[UUID, ...]
    distinct_ids: tuple[UUID, ...]
    first: dict[UUID, CitationClaim]  # the first claim of each distinct ID

    def counts(self) -> dict[str, Any]:
        return {"claims": len(self.claim_ids), "distinct": len(self.distinct_ids), "claim_ids": self.claim_ids,
                "distinct_ids": self.distinct_ids}


class CitationRecorder:
    """Records and reconciles citation bundles for one workspace as the app runtime (verified at construction)."""

    def __init__(self, engine: Engine, workspace_id: UUID, *, clock: Callable[[], float] = time.monotonic,
                 env: str | None = None, faults: FaultPlan | None = None) -> None:
        if faults is not None:
            if env != "test":
                raise ValueError("a fault plan is only allowed when POLICYOPS_ENV=test")
            require_test_environment(faults, env)
        if not isinstance(workspace_id, UUID):
            raise TypeError("workspace_id must be a UUID")
        verify_runtime_role(engine, APP_RUNTIME)
        self.engine, self.workspace_id, self.clock, self._faults = engine, workspace_id, clock, faults
        self._store = RetrievalStore(engine, workspace_id)

    # -- shared preparation (pure) ---------------------------------------------------------------------------------

    def _prepare(self, bundle: CitationBundle) -> _Prepared | None:
        try:
            bundle = CitationBundle.model_validate_json(bundle.model_dump_json())  # never trust a constructed DTO
        except (ValidationError, AttributeError):
            return None
        ids = tuple(citation_id(self.workspace_id, c.trace_id, c.chunk_id, c.span_start, c.span_end)
                    for c in bundle.claims)
        first: dict[UUID, CitationClaim] = {}
        for identifier, claim in zip(ids, bundle.claims, strict=True):
            first.setdefault(identifier, claim)
        return _Prepared(bundle, ids, tuple(sorted(first)), first)

    @staticmethod
    def _context_matches(prepared: _Prepared, run_id: UUID, authorized_steps: Collection[int], corpus_key: str) -> bool:
        bundle = prepared.bundle
        return (context_problem(run_id, authorized_steps, corpus_key) is None and bundle.run_id == run_id
                and bundle.corpus_key == corpus_key and all(c.step in authorized_steps for c in bundle.claims))

    def _evidence(self, read: Callable[[UUID], Any], spans: Callable[[Any], Any], run_id: UUID, corpus_key: str,
                  steps: Sequence[int], checkpoint: Callable[[], None]) -> dict[int, StepEvidence | StepFailure]:
        result: dict[int, StepEvidence | StepFailure] = {}
        for step in steps:
            record = read(trace_id_for(self.workspace_id, run_id, step))
            checkpoint()
            checked = check_step(record, workspace_id=self.workspace_id, run_id=run_id, step=step,
                                 corpus_key=corpus_key)
            if isinstance(checked, StepFailure):
                result[step] = checked
                continue
            result[step] = check_step_evidence(checked, spans(span_entries(checked.candidates)))
            checkpoint()
        return result

    # -- record ----------------------------------------------------------------------------------------------------

    def record(self, bundle: CitationBundle, *, run_id: UUID, authorized_steps: Collection[int], corpus_key: str,
               deadline: float) -> RecordOutcome:
        prepared = self._prepare(bundle)
        if prepared is None:
            return RecordOutcome(status="refused", code="bundle_invalid", committed="none", claims=0, distinct=0)
        counts = prepared.counts()
        problem = deadline_problem(deadline, self.clock)
        if problem == "deadline_invalid":
            return RecordOutcome(status="refused", code=problem, committed="none", **counts)
        if problem == "deadline_passed":
            return RecordOutcome(status="deadline_passed", code=problem, committed="none", **counts)
        if not self._context_matches(prepared, run_id, authorized_steps, corpus_key):
            return RecordOutcome(status="refused", code="record_context_mismatch", committed="none", **counts)
        connection = connect_runtime(self.engine)  # owned from acquisition: always closed below
        try:
            outcome = self._record_in(connection, prepared, run_id, corpus_key, float(deadline))
        except BaseException as primary:
            try:
                connection.close()  # rolls back an open transaction
            except BaseException as cleanup:
                primary.add_note(f"citation connection close also failed: {type(cleanup).__name__}")
            raise
        try:
            connection.close()
        except BaseException as cleanup:
            cleanup.add_note(f"the citation transaction had already ended with status {outcome.status}")
            raise
        if outcome.status == "recorded" and self.clock() >= deadline:
            # The commit was acknowledged, but the cleanup returned after the deadline: the rows are kept (observed),
            # never reported as a timely success.
            return outcome.model_copy(update={"status": "deadline_passed", "code": "deadline_passed"})
        return outcome

    def _record_in(self, connection: Connection, prepared: _Prepared, run_id: UUID, corpus_key: str,
                   deadline: float) -> RecordOutcome:
        counts = prepared.counts()

        def checkpoint() -> None:  # a phase guard: no further reads once the deadline is observed
            if self.clock() >= deadline:
                raise _Refusal("deadline_passed")

        connection.execution_options(isolation_level="READ COMMITTED")
        transaction = connection.begin()
        existing_before: tuple[UUID, ...] = ()
        try:
            initialize_transaction(connection, self.workspace_id)
            corpus = connection.execute(text(
                "SELECT corpus_key, active_generation_id FROM app.corpora WHERE corpus_key = :k FOR SHARE"),
                {"k": corpus_key}).mappings().first()
            checkpoint()  # the row-lock wait itself may have exhausted the deadline
            before = _rows(connection, prepared.distinct_ids)
            existing_before = tuple(i for i in prepared.distinct_ids
                                    if i in before and before[i].stored_equal(prepared.first[i], run_id))
            checkpoint()  # after the existing-row read
            if any(i in before and i not in existing_before for i in prepared.distinct_ids):
                raise _Refusal("citation_id_conflict")
            if corpus is None:
                raise _Refusal("record_context_mismatch")
            claims = prepared.bundle.claims
            if any(c.generation_id != corpus["active_generation_id"] for c in claims):
                raise _Refusal("stale_evidence")
            evidence = self._evidence(lambda t: read_step_record(connection, t),
                                      lambda e: read_spans(connection, e), run_id, corpus_key,
                                      sorted({c.step for c in claims}), checkpoint)
            for index, claim in enumerate(claims):
                field = recheck(claim, evidence[claim.step], workspace_id=self.workspace_id, run_id=run_id)
                if field is not None:
                    raise _Refusal(f"record_claim_mismatch:{field}", index)
            checkpoint()  # before any write
            new = [i for i in prepared.distinct_ids if i not in before]
            inserted: set[UUID] = set()
            if new:
                rows = [prepared.first[i] for i in new]
                try:
                    inserted = set(connection.execute(text(INSERT_SQL), {
                        "ids": new, "traces": [c.trace_id for c in rows], "chunks": [c.chunk_id for c in rows],
                        "versions": [c.document_version_id for c in rows], "starts": [c.span_start for c in rows],
                        "ends": [c.span_end for c in rows]}).scalars().all())
                except DBAPIError as error:
                    if isinstance(classify_sql_failure(error, "body"), DatabaseUnavailable):
                        raise  # outer transaction handler owns rollback and transient classification
                    raise _Refusal("stale_evidence" if _STALE_GUARD in _primary_message(error)
                                   else "citation_integrity") from None
            after = _rows(connection, prepared.distinct_ids)
            if not all(i in after and after[i].equals(prepared.first[i], run_id) for i in prepared.distinct_ids):
                raise _Refusal("citation_id_conflict")  # hidden (another workspace's ID) or unequal
            checkpoint()  # before COMMIT
            if self._faults is not None and self._faults.before_commit:
                raise RecorderFault("test-only fault before COMMIT")
        except _Refusal as refusal:
            transaction.rollback()
            if refusal.code == "deadline_passed":
                return RecordOutcome(status="deadline_passed", code="deadline_passed", committed="none",
                                     existing_ids=existing_before, existing=len(existing_before), **counts)
            return RecordOutcome(status="refused", code=refusal.code, failing_claim=refusal.failing,
                                 committed="none", existing_ids=existing_before, existing=len(existing_before),
                                 missing=len(prepared.distinct_ids) - len(existing_before), **counts)
        except BaseException as primary:
            try:
                transaction.rollback()
            except BaseException as cleanup:
                primary.add_note(f"citation rollback also failed: {type(cleanup).__name__}")
            if isinstance(primary, Exception):
                classified = classify_sql_failure(primary, "body")
                if classified is not None:
                    raise classified from primary
            raise
        try:
            transaction.commit()
            if self._faults is not None and self._faults.after_commit:
                raise RecorderFault("test-only lost COMMIT acknowledgement")
        except Exception:  # the outcome of COMMIT is unknown: never success, never a new write
            return RecordOutcome(status="record_ambiguous", committed="unknown", **counts)
        existing = tuple(i for i in prepared.distinct_ids if i not in inserted)
        result = {"inserted": len(inserted), "existing": len(existing), "existing_ids": existing, **counts}
        if self.clock() >= deadline:  # acknowledged late: the rows are kept, never deleted
            return RecordOutcome(status="deadline_passed", code="deadline_passed", committed="observed", **result)
        return RecordOutcome(status="recorded", committed="observed", **result)

    # -- reconcile (read-only, historical) -------------------------------------------------------------------------

    def reconcile(self, bundle: CitationBundle, *, run_id: UUID, authorized_steps: Collection[int], corpus_key: str,
                  deadline: float) -> ReconcileOutcome:
        prepared = self._prepare(bundle)
        if prepared is None:
            return ReconcileOutcome(status="refused", code="bundle_invalid")
        ids: dict[str, Any] = {"claim_ids": prepared.claim_ids, "distinct_ids": prepared.distinct_ids}
        problem = deadline_problem(deadline, self.clock)
        if problem is not None:
            return ReconcileOutcome(status="refused" if problem == "deadline_invalid" else "deadline_passed",
                                    code=problem, **ids)
        if not self._context_matches(prepared, run_id, authorized_steps, corpus_key):
            return ReconcileOutcome(status="refused", code="record_context_mismatch", **ids)
        limit = float(deadline)

        def checkpoint() -> None:
            if self.clock() >= limit:
                raise _Refusal("deadline_passed")

        try:
            with workspace_transaction(self.engine, self.workspace_id) as connection:
                observed = _rows(connection, prepared.distinct_ids)
            checkpoint()
            claims = prepared.bundle.claims
            evidence = self._evidence(self._store.step_record, self._store.spans, run_id, corpus_key,
                                      sorted({c.step for c in claims}), checkpoint)
            for index, claim in enumerate(claims):
                if recheck(claim, evidence[claim.step], workspace_id=self.workspace_id, run_id=run_id) is not None:
                    return ReconcileOutcome(status="citation_integrity", code="citation_integrity",
                                            failing_claim=index, **ids)
            if any(i in observed and not observed[i].stored_equal(prepared.first[i], run_id)
                   for i in prepared.distinct_ids):
                return ReconcileOutcome(status="citation_id_conflict", code="citation_id_conflict", **ids)
            generations = {c.generation_id for c in claims}
            current = None
            if len(generations) == 1:
                current = self._store.pointer(corpus_key) == next(iter(generations))
            checkpoint()  # the final guard before any result
        except _Refusal:
            return ReconcileOutcome(status="deadline_passed", code="deadline_passed", **ids)
        matched = tuple(i for i in prepared.distinct_ids if i in observed)
        missing = tuple(i for i in prepared.distinct_ids if i not in observed)
        status: Literal["recorded", "incomplete", "not_observed_yet"] = (
            "recorded" if not missing else ("incomplete" if matched else "not_observed_yet"))
        return ReconcileOutcome(status=status, matched_ids=matched, missing_ids=missing, generation_current=current,
                                **ids)


def _primary_message(error: DBAPIError) -> str:
    """The server's primary message only (never the statement or its parameters)."""
    diag = getattr(error.orig, "diag", None)
    message = getattr(diag, "message_primary", None)
    return message if isinstance(message, str) else ""
