import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Link, useLocation } from "react-router";
import { expectedContextOf, sameContext, type BoundRequestOptions, type MeOut } from "../api/client";
import { CAPACITY_NOTICE, Timestamp, WriteStatus } from "../cases/common";
import { EvidenceViewer } from "../evidence/EvidenceViewer";
import { capabilities } from "../session/permissions";
import { useSessionResource, useWriteEntries, useWriteLedger } from "../session/SessionProvider";
import { ErrorPanel, Status } from "../ui/feedback";
import { getProposal, listCitations, listRuns, type InspectedProposal } from "./api";
import { ActivityTimeline } from "./ActivityTimeline";
import type { EventEnvelope, Payload } from "./contracts";
import { useRunObservation } from "./useRunObservation";
import { RunOutcomeCard } from "./RunOutcomeCard";
import { isTerminal } from "./reducer";

type Posted = Extract<Payload, { type: "case.message_posted" }>;
export function RunWorkspace({ caseId, runId, citationId, me, onMessages }: {
  caseId: string; runId?: string | undefined; citationId?: string | undefined; me: MeOut; onMessages: (messages: Posted[]) => void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const load = useCallback((options: BoundRequestOptions) => listRuns(caseId, cursor, options), [caseId, cursor]);
  const { resource, reload } = useSessionResource(load, `runs:${caseId}:${cursor ?? "latest"}`);
  const selected = runId ?? (resource.status === "ready" ? resource.data.items[0]?.run_id : undefined);
  return <section className="run-workspace" aria-labelledby="workspace-heading">
    <div className="section-bar"><div><p className="eyebrow">Operator workbench</p><h2 id="workspace-heading">Investigations</h2></div>
      <Button className="button" onPress={reload}>Refresh investigations</Button></div>
    {resource.status === "loading" ? <Status label="Finding investigations…" /> : resource.status === "failed"
      ? <ErrorPanel error={resource.error} onRetry={reload} /> : resource.data.items.length === 0
        ? <p className="muted">No investigation yet.</p> : <nav className="run-selector" aria-label="Select investigation">
          {resource.data.items.map((r) => <Link key={r.run_id} className={`run-option${r.run_id === selected ? " selected" : ""}`}
            aria-current={r.run_id === selected ? "page" : undefined} to={`/cases/${caseId}/runs/${r.run_id}`}>
            <span>{r.state.replaceAll("_", " ")}</span><Timestamp value={r.created_at} /><code>{r.run_id.slice(0, 8)}</code>
          </Link>)}
          <div className="actions"><Button className="button" isDisabled={cursor === null} onPress={() => { setCursor(null); }}>Latest runs</Button>
            <Button className="button" isDisabled={resource.data.next_cursor === null}
              onPress={() => { setCursor(resource.data.next_cursor); }}>Older runs</Button></div>
        </nav>}
    {selected !== undefined ? <SelectedRun key={selected} caseId={caseId} runId={selected} citationId={citationId}
      me={me} onMessages={onMessages} /> : null}
  </section>;
}

function SelectedRun({ caseId, runId, citationId, me, onMessages }: {
  caseId: string; runId: string; citationId?: string | undefined; me: MeOut; onMessages: (messages: Posted[]) => void;
}) {
  const ledger = useWriteLedger();
  const entries = useWriteEntries();
  const [attempt, setAttempt] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const observation = useRunObservation(caseId, runId, attempt);
  const seen = useRef(0);
  const reload = useCallback(() => { setAttempt((v) => v + 1); }, []);
  useEffect(() => ledger.onSettled((entry) => {
    if (entry.kind === "cancelRun" && entry.runId === runId && entry.phase === "applied") reload();
  }), [ledger, runId, reload]);
  const activity = observation.activity;
  useEffect(() => {
    if (activity === null) return;
    const fresh = activity.events.filter((e): e is EventEnvelope => "payload" in e && e.sequence > seen.current);
    seen.current = activity.cursor;
    const messages = fresh.map((e) => e.payload).filter((p): p is Posted => p.type === "case.message_posted");
    if (messages.length > 0) onMessages(messages.slice(-50));
  }, [activity, onMessages]);
  const context = expectedContextOf(me);
  const cancellations = entries.filter((e) => e.kind === "cancelRun" && e.runId === runId && sameContext(e.context, context));
  const cancel = (): void => {
    const result = ledger.begin({ kind: "cancelRun", caseId, runId, ifMatch: null, payload: null });
    if ("refused" in result && result.refused === "capacity") setNotice(CAPACITY_NOTICE);
  };
  const relevant = activity?.events.filter((e) => "payload" in e && ["proposal.presented", "consent.recorded",
    "consent.clarification_requested", "approval.decided"].includes(e.payload.type)).at(-1)?.sequence ?? 0;
  // Snapshot proposal reference survives tail eviction. A presentation event can advance it while streaming.
  const presented = activity?.events.filter((e): e is EventEnvelope => "payload" in e && e.payload.type === "proposal.presented").at(-1)?.payload;
  // The observer publishes the canonical snapshot ref through Activity, rather than inferring from summaries.
  const ref = activity?.proposalRef ?? null;
  const proposalRef = presented?.type === "proposal.presented" ? presented : ref;
  return <div className="selected-run">
    <section className="run-banner" aria-label="Investigation lifecycle">
      <div><p className="eyebrow">Investigation lifecycle</p><p className="run-state">{activity?.run.state.replaceAll("_", " ") ?? "Loading investigation"}</p>
        <p className="muted"><code>{runId}</code> · Activity {observation.phase}</p></div>
      <div className="actions"><Button className="button" onPress={reload}>Reload activity</Button>
        {capabilities(me.roles).has("operateCases") ? <Button className="button" onPress={cancel}
          isDisabled={activity === null || isTerminal(activity.run) || cancellations.some((e) => ["inFlight", "unknown"].includes(e.phase))}>Cancel investigation</Button> : null}</div>
    </section>
    <p className="muted">Investigation status is separate from the action result. Cancellation does not undo a dispatched action.</p>
    {notice !== null ? <p role="alert">{notice}</p> : null}
    {cancellations.map((entry) => <div key={entry.id}><WriteStatus entry={entry} onRefresh={reload} />
      {entry.phase === "applied" ? <p role="status">Cancellation request recorded. Current facts are being refreshed.</p> : null}</div>)}
    {observation.error !== null ? <ErrorPanel error={observation.error} onRetry={reload} /> : null}
    {activity === null && observation.error === null ? <Status label="Loading investigation activity…" /> : null}
    {activity !== null ? <RunOutcomeCard integrityError={observation.error?.kind === "malformed"} activity={activity} /> : null}
    {activity !== null ? <div className="workbench-grid"><div className="workbench-main">
      <ActivityTimeline activity={activity} />
      {proposalRef !== null ? <ProposalPanel key={`${proposalRef.proposal_id}:${String(proposalRef.proposal_version)}`}
        caseId={caseId} runId={runId} id={proposalRef.proposal_id} version={proposalRef.proposal_version} revision={relevant} /> : null}
    </div><aside className="workbench-sources" aria-label="Run sources">
      <RunEvidenceList caseId={caseId} runId={runId} revision={activity.cursor} />
      {citationId !== undefined ? <EvidenceViewer key={citationId} caseId={caseId} runId={runId} citationId={citationId} /> : null}
    </aside></div> : null}
  </div>;
}

function ProposalPanel({ caseId, runId, id, version, revision }: {
  caseId: string; runId: string; id: string; version: number; revision: number;
}) {
  const load = useCallback((options: BoundRequestOptions) => getProposal(caseId, runId, id, version, options), [caseId, runId, id, version]);
  const { resource, reload } = useSessionResource(load, `proposal:${id}:${String(version)}:${String(revision)}`);
  return <section className="proposal-panel" aria-labelledby="proposal-heading">
    <div className="section-bar"><h3 id="proposal-heading">Presented action</h3><Button className="button" onPress={reload}>Refresh proposal</Button></div>
    {resource.status === "loading" ? <Status label="Loading exact proposal…" /> : resource.status === "failed"
      ? <ErrorPanel error={resource.error} onRetry={reload} /> : <ProposalInspection caseId={caseId} runId={runId} proposal={resource.data} />}
  </section>;
}
function ProposalInspection({ caseId, runId, proposal: p }: { caseId: string; runId: string; proposal: InspectedProposal }) {
  return <><p className="message-text">{p.text}</p><p className="muted">Version {String(p.version)} · {p.state.replaceAll("_", " ")}</p>
    <p className="wrap-anywhere"><strong>Action digest</strong> <code>{p.digest}</code></p>
    <h4>Sealed resource versions</h4><ul>{p.resources.map((r) => <li key={`${r.kind}:${r.resourceId}`}>{r.kind} {r.resourceId} · version {String(r.version)}</li>)}</ul>
    <h4>Customer consent</h4>{p.consent === null ? <p>No current customer consent recorded.</p> : <>
      <p className="message-text">{p.consent.text}</p><p className="muted">{p.consent.source === "operator_entered_customer" ? "Entered by staff (simulation)" : "Simulated customer"}
        {p.consent.enteredBy !== null ? ` · ${p.consent.enteredBy}` : ""}. Expires <Timestamp value={p.consent.expires} />.</p></>}
    <p className="muted">Customer consent is separate from staff approval. Neither establishes execution success.</p>
    <p><Link className="button" to={`/approvals/${p.id}/versions/${String(p.version)}`}>Inspect exact proposal and staff review</Link></p>
    <h4>Proposal sources</h4>{p.evidence.length === 0 ? <p>No cited sources recorded.</p> : <ul>{p.evidence.map((e) => <li key={e.id}>
      <Link to={`/cases/${caseId}/runs/${runId}/evidence/${e.id}`} state={{ versionId: e.versionId, versionDigest: e.digest }}>Inspect source {e.id.slice(0, 8)}</Link></li>)}</ul>}
  </>;
}
function RunEvidenceList({ caseId, runId, revision }: { caseId: string; runId: string; revision: number }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const load = useCallback((options: BoundRequestOptions) => listCitations(caseId, runId, cursor, options), [caseId, runId, cursor]);
  // Explicit refresh and a terminal activity burst reload the currently visible bounded page.
  const { resource, reload } = useSessionResource(load, `citations:${runId}:${cursor ?? "first"}`);
  const location = useLocation();
  const restored = useRef<string | null>(null);
  useEffect(() => {
    const state = location.state as { focusCitation?: string } | null;
    if (state?.focusCitation !== undefined && resource.status === "ready" && restored.current !== location.key) {
      const link = document.getElementById(`citation-${state.focusCitation}`);
      if (link !== null) { link.focus(); restored.current = location.key; }
    }
  }, [location, resource]);
  useEffect(() => {
    if (revision === 0) return;
    const timer = setTimeout(reload, 300);
    return () => { clearTimeout(timer); };
  }, [revision, reload]);
  return <section className="sources-panel" aria-labelledby="sources-heading"><div className="section-bar"><h3 id="sources-heading">Sources recorded for this run</h3>
    <Button className="button" onPress={reload}>Refresh sources</Button></div>
    {resource.status === "loading" ? <Status label="Loading run sources…" /> : resource.status === "failed"
      ? <ErrorPanel error={resource.error} onRetry={reload} /> : <>
        {resource.data.items.length === 0 ? <p className="muted">No cited sources recorded.</p> : <ul className="source-list">{resource.data.items.map((c) => <li key={c.citation_id}>
          <Link id={`citation-${c.citation_id}`} to={`/cases/${caseId}/runs/${runId}/evidence/${c.citation_id}`}>
            <span>Source {c.citation_id.slice(0, 8)}</span><span className="muted">{c.source_uri}</span></Link>
          <small>Recorded version {c.document_version_id.slice(0, 8)} · offsets {String(c.span_start)}–{String(c.span_end)}</small>
        </li>)}</ul>}
        <div className="actions"><Button className="button" isDisabled={cursor === null} onPress={() => { setCursor(null); }}>First sources</Button>
          <Button className="button" isDisabled={resource.data.next_cursor === null} onPress={() => { setCursor(resource.data.next_cursor); }}>Next sources</Button></div>
      </>}
  </section>;
}
