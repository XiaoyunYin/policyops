// Routed pages inside a selected workspace. Areas whose workflow is not built yet say so plainly and offer no
// controls; nothing here simulates a working feature.

import type { ReactNode } from "react";
import { Link, useParams } from "react-router";

import { ApprovalInbox } from "../approvals/ApprovalInbox";
import { ApprovalDetail } from "../approvals/ApprovalDetail";
import { listMembers, type MeOut } from "../api/client";
import { CaseDetail } from "../cases/CaseDetail";
import { CaseQueue } from "../cases/CaseQueue";
import { capabilities, ROLE_LABELS, type Capability } from "../session/permissions";
import { useSessionResource } from "../session/SessionProvider";
import { EmptyState, ErrorPanel, Status, useDocumentTitle } from "../ui/feedback";
import { PAGE_HEADING_ID } from "./AppShell";
import { uuid } from "../runs/contracts";

function PageHeader({ title, description }: { title: string; description?: string }) {
  useDocumentTitle(title);
  return (
    <header className="page-header">
      <h1 id={PAGE_HEADING_ID} tabIndex={-1}>{title}</h1>
      {description !== undefined ? <p className="muted">{description}</p> : null}
    </header>
  );
}

function Forbidden({ title }: { title: string }) {
  return (
    <>
      <PageHeader title={title} />
      <section className="panel panel-error" role="alert">
        <h2>You don't have access</h2>
        <p>Your roles in this workspace don't include this area. Ask a workspace administrator if you need it.</p>
        <Link className="button" to="/cases">Go to cases</Link>
      </section>
    </>
  );
}

function Gate({ me, need, title, children }: { me: MeOut; need: Capability; title: string; children: ReactNode }) {
  return capabilities(me.roles).has(need) ? children : <Forbidden title={title} />;
}

export function CasesPage({ me }: { me: MeOut }) {
  return (
    <Gate me={me} need="readCases" title="Cases">
      <PageHeader title="Cases" description="Customer-support cases in this workspace." />
      <CaseQueue me={me} />
    </Gate>
  );
}

export function CaseDetailPage({ me }: { me: MeOut }) {
  const { caseId = "", runId, citationId } = useParams();
  if (!uuid(caseId) || (runId !== undefined && !uuid(runId)) || (citationId !== undefined && !uuid(citationId))) {
    return <NotFoundPage />;
  }
  return (
    <Gate me={me} need="readCases" title="Case">
      <PageHeader title="Case" />
      {/* Keyed by case: nothing from one case's view survives into another's. */}
      <CaseDetail key={caseId} caseId={caseId} runId={runId} citationId={citationId} me={me} />
    </Gate>
  );
}

export function ApprovalsPage({ me }: { me: MeOut }) {
  return (
    <Gate me={me} need="decideProposals" title="Approvals">
      <PageHeader title="Approvals" description="Review exact proposals with current customer consent." />
      <ApprovalInbox />
    </Gate>
  );
}

export function ApprovalDetailPage({ me }: { me: MeOut }) {
  const { proposalId = "", version = "" } = useParams();
  const parsed = Number(version);
  if (!uuid(proposalId) || !/^[1-9][0-9]*$/.test(version) || !Number.isSafeInteger(parsed)) return <NotFoundPage />;
  return <Gate me={me} need="readCases" title="Proposal review"><PageHeader title="Proposal review" />
    <ApprovalDetail key={`${proposalId}:${version}`} id={proposalId} version={parsed} me={me} /></Gate>;
}

function MemberList() {
  const { resource, reload } = useSessionResource(listMembers, "members");
  if (resource.status === "loading") {
    return <Status label="Loading members…" />;
  }
  if (resource.status === "failed") {
    return <ErrorPanel error={resource.error} onRetry={reload} />;
  }
  if (resource.data.length === 0) {
    return <EmptyState title="No memberships" />;
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="visually-hidden">Memberships</caption>
        <thead>
          <tr>
            <th scope="col">Principal</th>
            <th scope="col">Role</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody>
          {resource.data.map((member) => (
            <tr key={member.membership_id}>
              <td><code>{member.principal_id}</code></td>
              <td>{ROLE_LABELS[member.role]}</td>
              <td>{member.active ? "Active" : "Revoked"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MembersPage({ me }: { me: MeOut }) {
  return (
    <Gate me={me} need="manageMembers" title="Members">
      <PageHeader title="Members" description="Role memberships in this workspace." />
      <MemberList />
    </Gate>
  );
}

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState title="There's nothing at this address">
        <Link className="button" to="/cases">Go to cases</Link>
      </EmptyState>
    </>
  );
}
