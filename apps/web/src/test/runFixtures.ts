import { expectedContextOf, type RunView } from "../api/client";
import type { CitationSummary, EventEnvelope, EvidenceView, Payload, RunSnapshot } from "../runs/contracts";
import { caseView, me, PRINCIPAL, WORKSPACE_A } from "./fakeApi";

export const CASE = caseView(1, "retail");
export const RUN_ID = "e0000000-0000-4000-8000-000000000001";
export const CITATION_ID = "a0000000-0000-4000-8000-000000000001";
export const EXECUTION_ID = "b0000000-0000-4000-8000-000000000001";
export const OPERATION_ID = "b0000000-0000-4000-8000-000000000002";
export const PROPOSAL_ID = "b0000000-0000-4000-8000-000000000003";
export const DECISION_ID = "b0000000-0000-4000-8000-000000000004";
export const NOW = "2026-11-12T09:00:00Z";
export const SCOPE = { workspace_id: WORKSPACE_A.workspace_id, case_id: CASE.case_id, run_id: RUN_ID };
export const CONTEXT = expectedContextOf(me());
if (CONTEXT === null) throw new Error("fixture context");
export function run(changes: Partial<RunView> = {}): RunView {
  return { run_id: RUN_ID, case_id: CASE.case_id, case_version: 1, version: 1, mode: "workbench", state: "running",
    initiated_by: PRINCIPAL, event_highwater: 0, config_sha256: "a".repeat(64), graph_sha256: "b".repeat(64),
    prompt_sha256: "c".repeat(64), created_at: NOW, updated_at: NOW, deadline_at: NOW, ...changes };
}
export function event(sequence: number, payload: Payload = { type: "escalation.requested", rule_id: "test.activity" }): EventEnvelope {
  return { event_id: `f0000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`, schema_version: "policyops.run-event/v1",
    event_version: 1, scope: SCOPE, sequence, occurred_at: NOW, payload };
}
export function snapshot(changes: Partial<RunSnapshot> = {}): RunSnapshot {
  return { run: run(), retention_floor: 0, highwater: 0, proposal_ref: null, events: [], latest_review: null,
    latest_stop: null, latest_execution: null, projections_complete: true, server_time: NOW, ...changes };
}
export function committed(sequence: number): EventEnvelope {
  return event(sequence, { type: "execution.changed", execution_id: EXECUTION_ID, operation_id: OPERATION_ID,
    tool: "cancel_pending_order", state: "succeeded", attempt: 1, outcome: "committed", receipt_sha256: "d".repeat(64), code: null });
}
export function review(sequence: number, outcome: "unknown" | "succeeded" | "reconciled", version: number): EventEnvelope {
  return event(sequence, { type: "review.outcome", proposal_id: PROPOSAL_ID, proposal_version: 1,
    execution_id: EXECUTION_ID, operation_id: OPERATION_ID, decision_id: DECISION_ID,
    message_id: CITATION_ID, outcome, reason: outcome === "succeeded" ? "committed" : outcome === "reconciled" ? "fenced" : "outcome_unconfirmed",
    observed_ledger_version: version, receipt_sha256: outcome === "succeeded" ? "d".repeat(64) : null });
}
export function citation(): CitationSummary {
  return { citation_id: CITATION_ID, scope: SCOPE, document_id: PROPOSAL_ID, document_version_id: DECISION_ID,
    version_sha256: "a".repeat(64), source_uri: "javascript:<img src=x onerror=evil()>", span_start: 1, span_end: 4 };
}
export async function evidence(text = "x😀e\u0301z"): Promise<EvidenceView> {
  const quote = Array.from(text).slice(1, 4).join("");
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(quote));
  const sha = Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
  return { ...citation(), version: "1", excerpt_start: 0, excerpt_end: Array.from(text).length, text, quote_sha256: sha };
}
export function frame(e: EventEnvelope): string { return `id: ${String(e.sequence)}\nevent: ${e.payload.type}\ndata: ${JSON.stringify(e)}\n\n`; }
export function byteStream(text: string, width = 8192): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  return new ReadableStream({ pull(controller) {
    if (offset >= bytes.length) controller.close();
    else { controller.enqueue(bytes.slice(offset, offset + width)); offset += width; }
  } });
}
