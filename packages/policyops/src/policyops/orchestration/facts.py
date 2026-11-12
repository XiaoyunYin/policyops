"""Read existing proposal, presentation, consent and decision rows as bounded, typed context data."""

from typing import cast
from uuid import UUID

from sqlalchemy import Connection

from policyops.orchestration.state import CriticalFact, CriticalStatus
from policyops.orchestration.stops import InvestigationStop
from policyops.persistence import repositories as repo
from policyops.persistence.database import ImmutableRecord
from policyops_contracts.scalars import CaseScope
from policyops_contracts.stops import StopDetails, StopReason


def critical_fact(connection: Connection, row: repo.ProposalRow) -> CriticalFact:
    presentation = repo.get_presentation(connection, row.proposal_id, row.proposal_version)
    consent = repo.get_consent(connection, row.proposal_id, row.proposal_version)
    decision = repo.get_decision(connection, row.proposal_id, row.proposal_version)
    proposal = repo.get_proposal(connection, row.proposal_id, row.proposal_version)
    if proposal is None:
        raise ImmutableRecord("critical proposal missing")
    message = None if presentation is None else repo.message_by_id(connection,
        CaseScope(workspace_id=row.workspace_id, case_id=row.case_id), presentation.message_id)
    if presentation is not None and (message is None or message.text != proposal.presentation.text):
        raise ImmutableRecord("critical presentation changed")
    return CriticalFact(proposal_id=row.proposal_id, proposal_version=row.proposal_version,
        action_digest=row.action_digest, status=cast(CriticalStatus, row.status),
        expires_at=row.expires_at,
        presentation_message_id=None if presentation is None else presentation.message_id,
        presentation_text=None if message is None else message.text,
        presentation_sha256=None if presentation is None else presentation.presentation_sha256,
        consent_id=None if consent is None else consent.consent_id,
        consent_expires_at=None if consent is None else consent.expires_at,
        decision_id=None if decision is None else decision.approval_id,
        decision=None if decision is None else decision.decision,
        decision_expires_at=None if decision is None else decision.expires_at)


def load_critical_facts(connection: Connection, case_id: UUID) -> tuple[CriticalFact, ...]:
    rows = repo.case_proposal_page(connection, case_id, after=None, limit=65)
    if len(rows) > 64:
        raise InvestigationStop(StopDetails(reason=StopReason.CONTEXT_LIMIT))
    return tuple(critical_fact(connection, row) for row in rows)
