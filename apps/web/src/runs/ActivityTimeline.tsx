import { useRef, useState } from "react";
import { Button } from "react-aria-components/Button";
import { Timestamp } from "../cases/common";
import type { ReplayItem } from "./contracts";
import { RENDERED, type Activity } from "./reducer";

export function activityLabel(item: ReplayItem): string {
  if (!("payload" in item)) return "Unsupported activity event";
  const p = item.payload;
  switch (p.type) {
    case "run.state_changed": return `Investigation ${p.current.replaceAll("_", " ")}`;
    case "case.message_posted": return p.source === "staff_note" ? "Internal staff note recorded" : "Conversation message recorded";
    case "run.stopped": return `Investigation stopped · ${p.details.reason.replaceAll("_", " ")}`;
    case "tool.requested": return `Requested ${p.tool.replaceAll("_", " ")}`;
    case "tool.finished": return `Tool ${p.outcome} · ${p.tool.replaceAll("_", " ")}`;
    case "proposal.presented": return `Proposal presented · version ${String(p.proposal_version)}`;
    case "consent.recorded": return "Customer consent recorded · separate from staff approval";
    case "consent.clarification_requested": return `Customer clarification needed · ${p.reason.replaceAll("_", " ")}`;
    case "approval.decided": return p.decision === "approve" ? "Staff approval recorded · execution pending" : "Staff rejection recorded";
    case "escalation.requested": return "Human assistance requested";
    case "error.raised": return p.rule_id === "live_agent.aggregate_cap" ? "Workspace cost cap refused the investigation"
      : `Reported error · ${p.code.replaceAll("_", " ")}`;
    case "execution.changed": return p.state === "unknown" ? "Execution outcome unconfirmed"
      : `Execution activity · ${p.state}`;
    case "review.outcome": return p.outcome === "unknown" ? "Outcome unconfirmed · reconciliation required"
      : `Action result recorded · ${p.outcome}`;
  }
}

export function ActivityTimeline({ activity }: { activity: Activity }) {
  const [anchor, setAnchor] = useState<number | null>(null);
  const navigation = useRef<HTMLButtonElement>(null);
  const events = activity.events;
  let start = anchor === null ? Math.max(0, events.length - RENDERED)
    : Math.max(0, events.findIndex((e) => e.sequence >= anchor));
  if (start < 0) start = 0;
  const page = events.slice(start, start + RENDERED);
  const first = page[0]?.sequence ?? 0;
  const last = page.at(-1)?.sequence ?? 0;
  const fresh = events.filter((e) => e.sequence > last).length;
  const move = (index: number): void => {
    setAnchor(events[Math.max(0, Math.min(events.length - 1, index))]?.sequence ?? null);
    navigation.current?.focus();
  };
  return <section className="activity-panel" aria-labelledby="activity-heading">
    <div className="section-bar"><div><p className="eyebrow">Run activity</p><h3 id="activity-heading">Latest retained activity</h3></div>
      <span className="status-pill">{String(activity.cursor)} recorded</span></div>
    {activity.historyGap ? <p className="notice">Some activity is no longer retained. Current facts were refreshed.</p> : null}
    {!activity.projectionsComplete ? <p className="notice" role="alert">Outcome unavailable — refresh required.
      Retained activity cannot establish all historical outcome facts.</p> : null}
    {page.length === 0 ? <p className="muted">No retained activity.</p> : <>
      <p className="muted table-note">Sequences {String(first)}–{String(last)}. {String(Math.max(0, first - 1))} earlier
        positions are outside this page. At most 500 activities are retained here.</p>
      <ol className="activity-list" aria-label="Investigation activity">
        {page.map((e) => <li key={e.event_id} className="activity-item">
          <span className="activity-sequence" aria-hidden="true">{String(e.sequence).padStart(2, "0")}</span>
          <div><p>{activityLabel(e)}</p>{"occurred_at" in e ? <Timestamp value={e.occurred_at} /> : null}</div>
        </li>)}
      </ol>
    </>}
    <div className="actions activity-paging">
      <Button ref={navigation} className="button" isDisabled={start === 0} onPress={() => { move(start - RENDERED); }}>Earlier</Button>
      <Button className="button" isDisabled={start + RENDERED >= events.length} onPress={() => { move(start + RENDERED); }}>Newer</Button>
      <Button className="button" onPress={() => { setAnchor(null); navigation.current?.focus(); }}>Jump to latest</Button>
    </div>
    <p role="status" aria-live="polite" aria-atomic="true" className="muted table-note">
      {anchor !== null && fresh > 0 ? `${String(fresh)} new activities. Use Jump to latest.`
        : anchor === null ? `Activity updated through sequence ${String(activity.cursor)}.` : ""}
    </p>
  </section>;
}
