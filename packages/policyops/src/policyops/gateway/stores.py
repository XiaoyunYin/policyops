"""PostgreSQL implementations of the T17 precheck's `DecisionStore` and `EvidencePort` (T18).

**`PgDecisionStore`** returns authority records of exactly one run. A proposal is returned only when its row is in the
run's workspace, case and run **and** its status is `presented`, and its stored body re-validates with its digest
equal to the indexed key (`repositories.get_proposal`). A superseded, expired or never-presented version, or a
self-consistent old body, is `None`, so the precheck refuses it (`proposal_not_found`). Statuses only move forward
(database trigger), so a superseded version can never become presented again. Consents and approvals are read by ID
within the same run.

**Evidence currentness** (`evidence_status`) uses T14's own criterion, re-applied:
1. discover the citations' immutable identities, including their corpus keys (an unlocked read, never the check);
2. lock the distinct corpora FOR SHARE in sorted key order (publication takes the corpus row FOR UPDATE and then, in
   the same transaction, switches the active generation and the document version statuses);
3. read every citation again, after the locks, and require for each reference: the citation exists, its document
   version and whole-version digest (`content_sha256`) match, its chunk's generation is the locked corpus's active
   generation and `ready`, and its document version is `active` with no `effective_to`. When `run_id` is given (at
   proposal creation), the citation's retrieval trace must also belong to that run.
A mismatch is `stale_evidence`; contradictory signals (an active generation citing a retired version, a citation of an
unowned legacy generation) are `evidence_inconsistent`. Neither is resolved. An active pointer to a non-ready
generation is also checked, but the runtime role never observes it: RLS (`chunks_app_ready`) hides that generation's
chunks, so its citations are not found and are refused as `stale_evidence`. A pass means the evidence was current
and consistent at that statement; it says nothing about later, and nothing about the truth of the cited text, which
stays untrusted data.

**`PgEvidencePort.is_current(workspace_id, ref)`** repeats the currentness checks for its workspace and reference. The
accepted port has no run argument, so it does not, and cannot, recheck run provenance: that is checked once at
creation and preserved by the immutable sealed proposal.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import Connection, Engine

from policyops.persistence import repositories as repo
from policyops.persistence.database import ImmutableRecord, workspace_transaction
from policyops_contracts.consent import ApprovalDecision, CustomerConsent
from policyops_contracts.proposal import ActionProposal, EvidenceRef
from policyops_contracts.scalars import RunScope


EvidenceStatus = Literal["current", "stale_evidence", "evidence_inconsistent"]


def evidence_status(connection: Connection, references: Sequence[EvidenceRef], *,
                    run_id: UUID | None) -> EvidenceStatus:
    """Lock-then-reread currentness of every reference, in the caller's workspace transaction."""
    if not references:
        return "current"
    ids = sorted({reference.evidence_id for reference in references}, key=str)
    discovered = repo.evidence_rows(connection, ids)  # step 1: identities only
    if len(discovered) != len(ids):
        return "stale_evidence"
    keys = [row.corpus_key for row in discovered.values()]
    if any(key is None for key in keys):
        return "evidence_inconsistent"  # a legacy generation with no owning corpus has no active pointer
    pointers = repo.lock_corpora(connection, [key for key in keys if key is not None])  # step 2
    fresh = repo.evidence_rows(connection, ids)  # step 3: everything checked is read after the locks
    if set(fresh) != set(ids):
        return "stale_evidence"
    for reference in references:
        row = fresh[reference.evidence_id]
        if row.corpus_key is None or row.corpus_key not in pointers:
            return "evidence_inconsistent"
        if (row.document_version_id, row.version_sha256) != (reference.document_version_id,
                                                              reference.content_sha256):
            return "stale_evidence"
        if run_id is not None and row.trace_run_id != run_id:
            return "stale_evidence"
        active = pointers[row.corpus_key]
        if row.generation_id != active:
            return "stale_evidence"
        if row.generation_status != "ready":  # defense in depth: RLS already hides such chunks from the runtime role
            return "evidence_inconsistent"  # the active pointer names a generation that is not ready
        if row.version_status != "active" or row.version_effective_to is not None:
            return "evidence_inconsistent"  # the active generation cites a version that is not active
    return "current"


class PgEvidencePort:
    """`EvidencePort` over the persisted citations; one short workspace transaction per call."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def is_current(self, workspace_id: UUID, reference: EvidenceRef) -> bool:
        with workspace_transaction(self._engine, workspace_id) as connection:
            return evidence_status(connection, (reference,), run_id=None) == "current"


class PgDecisionStore:
    """`DecisionStore` over the persisted T18 records of one run; one short workspace transaction per call."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def proposal(self, run: RunScope, proposal_id: UUID, proposal_version: int) -> ActionProposal | None:
        with workspace_transaction(self._engine, run.workspace_id) as connection:
            row = repo.proposal_row(connection, proposal_id, proposal_version)
            if row is None or row.status != "presented" or (row.workspace_id, row.case_id, row.run_id) != (
                    run.workspace_id, run.case_id, run.run_id):
                return None
            try:
                proposal = repo.get_proposal(connection, proposal_id, proposal_version)
            except (ImmutableRecord, ValidationError):  # a body that disagrees with its keys is no authority
                return None
        if proposal is None or proposal.scope != run or proposal.action_digest != row.action_digest:
            return None
        return proposal

    def consent(self, run: RunScope, consent_id: UUID) -> CustomerConsent | None:
        with workspace_transaction(self._engine, run.workspace_id) as connection:
            return repo.consent_by_id(connection, run, consent_id)

    def approval(self, run: RunScope, approval_id: UUID) -> ApprovalDecision | None:
        with workspace_transaction(self._engine, run.workspace_id) as connection:
            return repo.decision_by_id(connection, run, approval_id)
