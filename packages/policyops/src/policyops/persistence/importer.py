"""Import the synthetic example world (policyops.domain.examples) through the typed repositories.

Fictional data only: the World IDs and the committed contract examples (proposal, presentation, consent, approval).
Identity rows go through the auth runtime, everything else through the app runtime in the example workspace's
scope, so the import exercises the same roles, RLS policies and constraints as the application. Seeded filler
messages make the stored case sequences match the example consent's recorded sequences (presentation 10, reply 11).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from sqlalchemy import Engine, text

from policyops.domain.examples import World, build_examples
from policyops.persistence import repositories as repo
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.records import Membership, NewCase, NewRun, Principal, Workspace
from policyops_contracts.consent import ApprovalDecision, CaseMessage, CustomerConsent, ProposalPresentationRecord
from policyops_contracts.digest import text_sha256
from policyops_contracts.proposal import ActionProposal


ISSUER = "https://issuer.example.invalid"
PROPOSAL_ROW = UUID(int=4001)


class AlreadyImported(RuntimeError):
    """The example workspace already exists; the import is not repeated."""


@dataclass(frozen=True)
class ImportReport:
    workspace_id: UUID
    principals: int
    memberships: int
    messages: int
    proposals: int
    consents: int
    decisions: int


def import_synthetic_world(*, auth: Engine, app: Engine) -> ImportReport:
    world = World()
    examples = build_examples()
    proposal = ActionProposal.model_validate_json(examples["action-proposal.exchange.json"])
    presentation = ProposalPresentationRecord.model_validate_json(examples["proposal-presentation.json"])
    reply = CaseMessage.model_validate_json(examples["case-message.operator-entered-yes.json"])
    consent = CustomerConsent.model_validate_json(examples["customer-consent.json"])
    decision = ApprovalDecision.model_validate_json(examples["approval-decision.json"])
    start = world.now - timedelta(minutes=10)

    with transaction(auth) as connection:
        if connection.execute(text("SELECT 1 FROM identity.workspaces WHERE id = :id"),
                              {"id": world.workspace}).first() is not None:
            raise AlreadyImported(f"workspace {world.workspace} already exists")
        repo.create_workspace(connection, Workspace(id=world.workspace, slug="example-workspace",
                                                    name="Example workspace (synthetic)", created_at=start))
        people = ((world.analyst, "analyst-0001", "Example Analyst", "analyst"),
                  (world.reviewer, "reviewer-0001", "Example Reviewer", "reviewer"))
        for principal_id, subject, name, role in people:
            repo.create_principal(connection, Principal(id=principal_id, issuer=ISSUER, subject=subject,
                                                        display_name=name, created_at=start))
            repo.add_membership(connection, Membership(id=UUID(int=principal_id.int + 1000),
                                                       workspace_id=world.workspace, principal_id=principal_id,
                                                       role=role, created_at=start))  # type: ignore[arg-type]

    with workspace_transaction(app, world.workspace) as connection:
        case = repo.create_case(connection, NewCase(id=world.case, workspace_id=world.workspace, scenario="retail",
                                                    customer_user_id=world.user_id, created_by=world.analyst,
                                                    created_at=start))
        repo.create_run(connection, NewRun(
            id=world.run, workspace_id=world.workspace, case_id=world.case, case_version=case.version,
            mode="workbench", graph_sha256=text_sha256("synthetic-graph"),
            prompt_sha256=text_sha256("synthetic-prompt"), config_sha256=text_sha256("synthetic-config"),
            deadline_at=world.now + timedelta(hours=1), created_at=start))
        for number in range(1, presentation.message_sequence):
            repo.append_message(connection, message_id=UUID(int=600 + number), scope=world.case_scope,
                                source="seeded", entered_by=None, text_value=f"Seeded synthetic message {number}.",
                                created_at=start + timedelta(seconds=number))
        repo.append_message(connection, message_id=presentation.message_id, scope=world.case_scope, source="agent",
                            entered_by=None, text_value=proposal.presentation.text,
                            created_at=presentation.presented_at)
        stored = repo.append_message(connection, message_id=reply.message_id, scope=world.case_scope,
                                     source=reply.source, entered_by=reply.entered_by, text_value=reply.text,
                                     created_at=reply.created_at)
        if stored != reply or consent.customer_message_sequence != stored.sequence:
            raise RuntimeError("the imported reply does not match the example record")
        repo.insert_proposal(connection, PROPOSAL_ROW, proposal)
        repo.mark_presented(connection, presentation)
        repo.record_consent(connection, consent)
        repo.record_decision(connection, decision)
    return ImportReport(workspace_id=world.workspace, principals=2, memberships=2,
                        messages=presentation.message_sequence + 1, proposals=1, consents=1, decisions=1)
