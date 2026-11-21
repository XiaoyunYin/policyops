import type { Activity } from "./reducer";
import type { EventEnvelope } from "./contracts";

const REASONS: Readonly<Record<string, string>> = {
  review_rejected: "Reviewer rejected the proposal", proposal_expired: "Proposal expired", proposal_stale: "Proposal changed",
  run_deadline_exceeded: "Investigation deadline passed", run_terminal: "Investigation ended", initiator_not_authorized: "Initiator no longer authorized",
  review_record_invalid: "Review binding invalid", review_retries_exhausted: "Review attempts exhausted", upstream_rejected: "Upstream refused the action",
  effect_mismatch: "Effect did not match", money_unrepresentable: "Money could not be represented exactly", version_conflict: "Resource version changed",
  precheck_refused: "Execution precheck refused", cancelled_before_dispatch: "Cancelled before dispatch", fenced: "Execution fenced before committing",
};
const STOPS: Readonly<Record<string, string>> = { usd_cap: "Cost limit", call_cap: "Call limit", count_cap: "Count limit",
  input_tokens: "Input token limit", active_time: "Active time limit", tool_cap: "Tool limit",
  retrieval_cap: "Policy retrieval limit", invalid_cap: "Invalid reply limit", context_limit: "Context limit",
  overrun: "Budget overrun", contract_block: "Contract validation", usage_unconfirmed: "Usage unconfirmed" };
function action(event: EventEnvelope | undefined): { title: string; tone: string; reason?: string | undefined; operation?: string | undefined; receipt?: string | undefined } {
  const p = event?.payload;
  if (p?.type !== "review.outcome" && p?.type !== "execution.changed") return { title: "No confirmed action result", tone: "neutral" };
  const operation = p.operation_id ?? undefined;
  const committed = p.type === "review.outcome" ? p.outcome === "succeeded" && p.reason === "committed"
    : p.state === "succeeded" && p.outcome === "committed";
  if (committed && p.execution_id != null && operation !== undefined && p.receipt_sha256 != null)
    return { title: "Action committed — receipt recorded", tone: "success", operation, receipt: p.receipt_sha256 };
  const fenced = p.type === "review.outcome" ? p.outcome === "reconciled" && p.reason === "fenced"
    : p.state === "reconciled" && p.outcome === "fenced";
  if (fenced) return { title: "Reconciled — no business effect committed", tone: "neutral", operation };
  const refused = p.type === "review.outcome" ? p.outcome === "refused" : p.state === "failed";
  if (refused) {
    const code = p.type === "review.outcome" ? p.reason : p.outcome;
    return { title: "Action refused", tone: "refused", operation, reason: code == null ? "Reason unavailable" : REASONS[code] ?? "Reason unavailable" };
  }
  if (p.type === "execution.changed" && (p.state === "pending" || p.state === "dispatched"))
    return { title: p.state === "pending" ? "Execution pending" : "Dispatched — result pending", tone: "neutral", operation };
  return { title: p.type === "execution.changed" ? "Outcome unconfirmed — checking for a receipt" : "Outcome unconfirmed — reconciliation required", tone: "warning", operation };
}
export function RunOutcomeCard({ activity, proposalId, version, integrityError = false }: {
  activity: Activity; proposalId?: string; version?: number; integrityError?: boolean;
}) {
  const candidates = [activity.latestReview, activity.latestExecution].filter((e): e is EventEnvelope => e !== null).sort((a, b) => b.sequence - a.sequence);
  const review = activity.latestReview?.payload;
  const hasBinding = review?.type === "review.outcome" || activity.proposalRef !== null;
  const mismatched = proposalId !== undefined && ((review?.type === "review.outcome"
    && (review.proposal_id !== proposalId || review.proposal_version !== version))
    || !hasBinding || (activity.proposalRef !== null && (activity.proposalRef.proposal_id !== proposalId || activity.proposalRef.proposal_version !== version)));
  const outcome = !activity.projectionsComplete || mismatched || integrityError ? { title: "Outcome unavailable — refresh required", tone: "warning" }
    : action(candidates[0]);
  const stop = activity.latestStop?.payload;
  const selected = candidates[0]?.payload;
  const executionId = selected?.type === "review.outcome" || selected?.type === "execution.changed" ? selected.execution_id : null;
  const ref = selected?.type === "review.outcome" ? { proposal_id: selected.proposal_id, proposal_version: selected.proposal_version } : activity.proposalRef;
  const lifecycle = stop?.type === "run.stopped" ? `Investigation stopped — ${STOPS[stop.details.reason] ?? "Reason unavailable"}`
    : `Investigation ${activity.run.state === "succeeded" ? "completed" : activity.run.state.replaceAll("_", " ")}`;
  return <section className={`outcome-card outcome-${outcome.tone}`} aria-label="Run outcome">
    <section aria-label="Investigation result"><p className="eyebrow">Investigation lifecycle</p><h3>{lifecycle}</h3>
      {stop?.type === "run.stopped" ? <><p>{stop.details.cleanup_unconfirmed ? "Cleanup pending." : ""}</p>
        {stop.details.usage_unconfirmed ? <p className="notice">Usage remains unconfirmed.</p> : null}</> : null}</section>
    <section aria-label="Action outcome"><p className="eyebrow">Action outcome</p><h3>{outcome.title}</h3>
      {outcome.reason !== undefined ? <p>{outcome.reason}</p> : null}
      {outcome.receipt !== undefined && activity.run.state === "cancelled" ? <p className="notice">Receipt arrived after cancellation</p> : null}
      <dl className="evidence-metadata">{outcome.operation !== undefined ? <div><dt>Operation ID</dt><dd><code>{outcome.operation}</code></dd></div> : null}
        {executionId != null ? <div><dt>Execution ID</dt><dd><code>{executionId}</code></dd></div> : null}
        {ref !== null ? <div><dt>Outcome proposal reference</dt><dd><code>{ref.proposal_id}</code> · version {String(ref.proposal_version)}</dd></div> : null}
        {selected?.type === "review.outcome" && selected.decision_id != null ? <div><dt>Decision ID</dt><dd><code>{selected.decision_id}</code></dd></div> : null}
        {outcome.receipt !== undefined ? <div><dt>Receipt reference · SHA-256</dt><dd><code>{outcome.receipt}</code></dd></div> : null}</dl>
    </section><p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">{lifecycle}. {outcome.title}</p>
  </section>;
}
