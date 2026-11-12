import { ApiError, type RunView } from "../api/client";
import type { EventEnvelope, ReplayItem, RunSnapshot } from "./contracts";

export const RETAINED = 500;
export const RENDERED = 100;
export interface Activity {
  readonly run: RunView;
  readonly cursor: number;
  readonly proposalRef: RunSnapshot["proposal_ref"];
  readonly events: readonly ReplayItem[];
  readonly latestReview: EventEnvelope | null;
  readonly latestStop: EventEnvelope | null;
  readonly latestExecution: EventEnvelope | null;
  readonly projectionsComplete: boolean;
  readonly historyGap: boolean;
}
export class ActivityGap extends Error { override name = "ActivityGap"; }
function protocol(): never { throw new ApiError("malformed"); }
// Key order in JSON is not semantic; bounded event objects have a shallow, closed schema.
function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  const r = v as Record<string, unknown>;
  return `{${Object.keys(r).sort().map((k) => `${JSON.stringify(k)}:${canonical(r[k])}`).join(",")}}`;
}
const equal = (a: ReplayItem, b: ReplayItem): boolean => canonical(a) === canonical(b);
function terminal(e: EventEnvelope | null): { execution: string; operation: string; truth: string } | null {
  const p = e?.payload;
  if (p?.type === "execution.changed" && ["succeeded", "reconciled", "failed"].includes(p.state))
    return { execution: p.execution_id, operation: p.operation_id, truth: p.state === "failed" ? "refused" : p.state };
  if (p?.type === "review.outcome" && p.execution_id != null && p.operation_id != null
      && p.outcome !== "unknown") return { execution: p.execution_id, operation: p.operation_id, truth: p.outcome };
  return null;
}
function project(state: Activity, event: EventEnvelope): Activity {
  const p = event.payload;
  if (p.type === "proposal.presented") return { ...state, proposalRef: { proposal_id: p.proposal_id, proposal_version: p.proposal_version } };
  if (p.type === "run.state_changed") return { ...state, run: { ...state.run, state: p.current } };
  if (p.type === "run.stopped") return { ...state, latestStop: event };
  if (p.type !== "review.outcome" && p.type !== "execution.changed") return state;
  const previous = state.latestReview?.payload;
  if (p.type === "review.outcome" && previous?.type === "review.outcome"
      && previous.execution_id === p.execution_id && previous.observed_ledger_version != null
      && p.observed_ledger_version != null) {
    if (p.observed_ledger_version < previous.observed_ledger_version) return state;
    if (p.observed_ledger_version === previous.observed_ledger_version) {
      if (canonical(p) !== canonical(previous)) protocol();
      return state;
    }
  }
  const prior = [state.latestReview, state.latestExecution].filter((v): v is EventEnvelope => v !== null);
  const nextTruth = terminal(event);
  for (const e of prior) {
    const old = e.payload;
    if (old.type !== "review.outcome" && old.type !== "execution.changed") continue;
    if (old.execution_id != null && p.execution_id != null
        && (old.execution_id !== p.execution_id || old.operation_id !== p.operation_id)) protocol();
    const truth = terminal(e);
    if (truth !== null) {
      if (nextTruth !== null && nextTruth.truth !== truth.truth) protocol();
      if (nextTruth === null) return state; // an older/uncertain projection cannot erase terminal facts
      if (truth.truth === "succeeded" && old.receipt_sha256 !== p.receipt_sha256) protocol();
    }
  }
  return p.type === "review.outcome" ? { ...state, latestReview: event } : { ...state, latestExecution: event };
}
export function hydrate(snapshot: RunSnapshot, historyGap = false, previous?: Activity): Activity {
  let state: Activity = { run: snapshot.run, cursor: snapshot.highwater, events: snapshot.events,
    proposalRef: snapshot.proposal_ref,
    latestReview: null, latestStop: null, latestExecution: null,
    projectionsComplete: snapshot.projections_complete, historyGap };
  const projections = [snapshot.latest_review, snapshot.latest_stop, snapshot.latest_execution,
    previous?.latestReview ?? null, previous?.latestStop ?? null, previous?.latestExecution ?? null];
  const merged = new Map<number, ReplayItem>();
  for (const e of [...snapshot.events, ...projections.filter((e): e is EventEnvelope => e !== null)]) {
    const old = merged.get(e.sequence);
    if (old !== undefined && !equal(old, e)) protocol();
    merged.set(e.sequence, e);
  }
  for (const e of [...merged.values()].sort((a, b) => a.sequence - b.sequence)) {
    if ("payload" in e) state = project(state, e);
  }
  // The canonical snapshot run state wins over old state-change entries in a truncated tail.
  return { ...state, run: snapshot.run, proposalRef: snapshot.proposal_ref };
}
export function append(state: Activity, items: readonly ReplayItem[]): Activity {
  for (const e of items) {
    if (e.sequence <= state.cursor) {
      const retained = state.events.find((v) => v.sequence === e.sequence);
      if (retained !== undefined && !equal(retained, e)) protocol();
      continue;
    }
    if (e.sequence !== state.cursor + 1) throw new ActivityGap();
    if (state.events.some((v) => v.event_id === e.event_id)) protocol();
    if ("payload" in e) state = project(state, e);
    state = { ...state, cursor: e.sequence, events: [...state.events, e].slice(-RETAINED),
      projectionsComplete: state.projectionsComplete && "payload" in e,
      run: { ...state.run, event_highwater: e.sequence } };
  }
  return state;
}

export function needsObservation(state: Activity): boolean {
  if (state.run.state === "cancelled" || !state.projectionsComplete) return true;
  const e = state.latestExecution?.payload;
  const r = state.latestReview?.payload;
  return (e?.type === "execution.changed" && ["pending", "dispatched", "unknown"].includes(e.state))
    || (r?.type === "review.outcome" && r.outcome === "unknown") || state.run.state === "reconciling";
}
export const isTerminal = (run: RunView): boolean => ["succeeded", "failed", "cancelled", "budget_exceeded"].includes(run.state);
