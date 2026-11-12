// Generated DTOs plus bounded wire decoders. A TypeScript assertion alone never validates network data.
import { ApiError, runView, type ExpectedContext } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type EventEnvelope = S["EventEnvelope"];
export type ReplayItem = EventEnvelope | S["UnsupportedEventView"];
export type RunSnapshot = S["RunSnapshot"];
export type RunPage = S["RunPage"];
export type CitationSummary = S["CitationSummary"];
export type CitationPage = S["CitationPage"];
export type EvidenceView = S["EvidenceView"];
export type ProposalDetail = S["ProposalDetailView"];
export type Payload = EventEnvelope["payload"];
export type Scope = { workspace_id: string; case_id: string; run_id: string };

export function bad(): never { throw new ApiError("malformed"); }
export function record(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? v as Record<string, unknown> : bad();
}
export const uuid = (v: unknown): v is string => typeof v === "string"
  && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
export const digest = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
export const integer = (v: unknown, min = 0): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= min;
const date = (v: unknown): boolean => typeof v === "string" && v.length <= 40
  && /(?:Z|\+00:00)$/.test(v) && Number.isFinite(Date.parse(v));
const text = (v: unknown, max: number): v is string => typeof v === "string" && Array.from(v).length <= max;
const one = (v: unknown, values: readonly unknown[]): boolean => values.includes(v);
const nullable = (v: unknown, test: (v: unknown) => boolean): boolean => v === null || test(v);
const opt = (v: unknown, test: (v: unknown) => boolean): boolean => v === undefined || nullable(v, test);
export const RUN_STATES = ["queued", "running", "waiting_input", "waiting_approval", "reconciling", "succeeded",
  "failed", "cancelled", "budget_exceeded"] as const;
export const STOP_REASONS = ["usd_cap", "call_cap", "count_cap", "input_tokens", "active_time", "tool_cap",
  "context_limit", "overrun", "contract_block", "usage_unconfirmed"] as const;
const NONCOMMIT = ["upstream_rejected", "effect_mismatch", "money_unrepresentable", "version_conflict", "fenced",
  "precheck_refused", "cancelled_before_dispatch"];
const REVIEW_REASONS = ["review_rejected", "proposal_expired", "proposal_stale", "run_deadline_exceeded",
  "run_terminal", "initiator_not_authorized", "review_record_invalid", "review_retries_exhausted", ...NONCOMMIT];
const TOOLS = ["find_user_id_by_email", "find_user_id_by_name_zip", "get_user_details", "get_order_details",
  "get_product_details", "get_item_details", "list_all_product_types", "calculate", "transfer_to_human_agents",
  "cancel_pending_order", "modify_pending_order_address", "modify_pending_order_payment", "modify_pending_order_items",
  "return_delivered_order_items", "exchange_delivered_order_items", "modify_user_address"];
const slug = (v: unknown): boolean => typeof v === "string" && /^[a-z][a-z0-9_.-]{0,63}$/.test(v);
const SOURCES = ["seeded", "simulated_customer", "operator_entered_customer", "staff_note", "agent"];
const ERRORS = ["invalid_input", "unauthenticated", "forbidden", "not_found", "conflict", "stale_version", "expired",
  "customer_not_authenticated", "customer_mismatch", "policy_denied", "policy_unsupported", "consent_required",
  "consent_ambiguous", "approval_required", "separation_of_duties", "protocol_violation", "upstream_money_precision",
  "rate_limited", "unavailable", "internal", "context_changed"];

export function scopeOf(v: unknown, scope: Scope): void {
  const s = record(v);
  if (s["workspace_id"] !== scope.workspace_id || s["case_id"] !== scope.case_id || s["run_id"] !== scope.run_id) bad();
}

export function parseEvent(v: unknown, scope: Scope): EventEnvelope {
  const e = record(v);
  if (e["schema_version"] !== "policyops.run-event/v1" || e["event_version"] !== 1 || !uuid(e["event_id"])
      || !integer(e["sequence"], 1) || !date(e["occurred_at"])) bad();
  scopeOf(e["scope"], scope);
  const p = record(e["payload"]);
  let valid = false;
  switch (p["type"]) {
    case "run.state_changed":
      valid = nullable(p["previous"], (v) => one(v, RUN_STATES)) && one(p["current"], RUN_STATES); break;
    case "case.message_posted":
      valid = uuid(p["message_id"]) && integer(p["message_sequence"], 1) && one(p["source"], SOURCES); break;
    case "run.stopped": {
      const d = record(p["details"]);
      valid = uuid(p["message_id"]) && one(d["reason"], STOP_REASONS)
        && opt(d["usage_unconfirmed"], (v) => typeof v === "boolean")
        && opt(d["cleanup_unconfirmed"], (v) => typeof v === "boolean")
        && (d["reason"] !== "usage_unconfirmed" || d["usage_unconfirmed"] === true); break;
    }
    case "tool.requested": {
      const kind = TOOLS.indexOf(String(p["tool"])) >= 9 ? "write"
        : one(p["tool"], ["calculate", "transfer_to_human_agents"]) ? "generic" : "read";
      valid = one(p["tool"], TOOLS) && p["kind"] === kind && digest(p["call_sha256"]); break;
    }
    case "tool.finished":
      valid = one(p["tool"], TOOLS) && one(p["outcome"], ["ok", "denied", "escalated", "error", "unknown"])
        && opt(p["rule_id"], slug); break;
    case "proposal.presented":
      valid = uuid(p["proposal_id"]) && integer(p["proposal_version"], 1) && digest(p["action_digest"])
        && date(p["expires_at"]); break;
    case "consent.recorded":
      valid = uuid(p["consent_id"]) && uuid(p["proposal_id"]) && digest(p["action_digest"]); break;
    case "consent.clarification_requested":
      valid = uuid(p["proposal_id"]) && one(p["reason"], ["ambiguous_reply", "declined", "stale_presentation", "expired"]); break;
    case "approval.decided":
      valid = uuid(p["approval_id"]) && uuid(p["proposal_id"]) && one(p["decision"], ["approve", "reject"]); break;
    case "escalation.requested": valid = slug(p["rule_id"]); break;
    case "error.raised":
      valid = one(p["code"], ERRORS) && opt(p["rule_id"], slug) && uuid(p["correlation_id"])
        && typeof p["retryable"] === "boolean"; break;
    case "execution.changed":
      valid = uuid(p["execution_id"]) && uuid(p["operation_id"]) && one(p["tool"], TOOLS.slice(9))
        && one(p["state"], ["pending", "dispatched", "succeeded", "failed", "unknown", "reconciled"])
        && integer(p["attempt"]) && p["attempt"] <= 100 && opt(p["code"], slug)
        && opt(p["outcome"], (v) => one(v, ["committed", ...NONCOMMIT])) && opt(p["receipt_sha256"], digest);
      // Contradictory terminal facts are a protocol error, never a success projection.
      if (p["state"] === "succeeded") valid &&= p["outcome"] === "committed" && digest(p["receipt_sha256"]);
      else if (p["state"] === "reconciled") valid &&= p["outcome"] === "fenced" && p["receipt_sha256"] == null;
      else if (p["state"] === "failed") valid &&= one(p["outcome"], NONCOMMIT) && p["receipt_sha256"] == null;
      else valid &&= p["outcome"] == null && p["receipt_sha256"] == null;
      break;
    case "review.outcome": {
      const execution = p["execution_id"] != null;
      valid = uuid(p["proposal_id"]) && integer(p["proposal_version"], 1) && uuid(p["message_id"])
        && opt(p["decision_id"], uuid) && opt(p["execution_id"], uuid) && opt(p["operation_id"], uuid)
        && opt(p["observed_ledger_version"], (v) => integer(v, 1)) && opt(p["receipt_sha256"], digest)
        && (execution ? uuid(p["decision_id"]) && uuid(p["operation_id"]) && integer(p["observed_ledger_version"], 1)
          : p["operation_id"] == null && p["observed_ledger_version"] == null);
      switch (p["outcome"]) {
        case "succeeded": valid &&= execution && p["reason"] === "committed" && digest(p["receipt_sha256"]); break;
        case "reconciled": valid &&= execution && p["reason"] === "fenced" && p["receipt_sha256"] == null; break;
        case "unknown": valid &&= execution && p["reason"] === "outcome_unconfirmed" && p["receipt_sha256"] == null; break;
        case "refused": valid &&= one(p["reason"], REVIEW_REASONS.filter((v) => v !== "fenced"))
          && p["receipt_sha256"] == null; break;
        default: valid = false;
      } break;
    }
  }
  if (!valid) bad();
  // Return only typed data; UI never renders arbitrary payload JSON.
  return e as EventEnvelope;
}

export function parseReplay(v: unknown, scope: Scope): ReplayItem {
  const e = record(v);
  if ("payload" in e) return parseEvent(e, scope);
  if (!uuid(e["event_id"]) || !integer(e["sequence"], 1) || !text(e["event_type"], 256)
      || !text(e["schema_version"], 256) || Object.keys(e).length !== 4) bad();
  return e as S["UnsupportedEventView"];
}

export function parseSnapshot(v: unknown, scope: Scope): RunSnapshot {
  const s = record(v);
  const run = runView(s["run"], scope.case_id);
  if (run.run_id !== scope.run_id || !integer(s["retention_floor"]) || !integer(s["highwater"])
      || s["retention_floor"] > s["highwater"] || s["highwater"] !== run.event_highwater
      || typeof s["projections_complete"] !== "boolean" || !date(s["server_time"])
      || !Array.isArray(s["events"]) || s["events"].length > 100) bad();
  // getSnapshot requests tail=100. A truncated/holed response must not install a cursor past missing positions.
  if (s["events"].length !== Math.min(100, s["highwater"] - s["retention_floor"])) bad();
  let last = Math.max(s["retention_floor"], s["highwater"] - 100);
  const events = s["events"].map((v) => {
    const e = parseReplay(v, scope);
    if (e.sequence !== last + 1 || e.sequence > Number(s["highwater"])) bad();
    last = e.sequence;
    return e;
  });
  const projection = (key: string, type: Payload["type"]): EventEnvelope | null => {
    if (s[key] === null) return null;
    const event = parseEvent(s[key], scope);
    if (event.payload.type !== type || event.sequence > Number(s["highwater"])) bad();
    return event;
  };
  if (s["proposal_ref"] !== null) {
    const ref = record(s["proposal_ref"]);
    if (!uuid(ref["proposal_id"]) || !integer(ref["proposal_version"], 1)) bad();
  }
  return { ...s, run, events, latest_review: projection("latest_review", "review.outcome"),
    latest_stop: projection("latest_stop", "run.stopped"), latest_execution: projection("latest_execution", "execution.changed") } as RunSnapshot;
}

export function parseCitation(v: unknown, scope: Scope): CitationSummary {
  const c = record(v);
  scopeOf(c["scope"], scope);
  if (!uuid(c["citation_id"]) || !uuid(c["document_id"]) || !uuid(c["document_version_id"])
      || !digest(c["version_sha256"]) || !text(c["source_uri"], 2000) || !integer(c["span_start"])
      || !integer(c["span_end"], 1) || c["span_end"] <= c["span_start"]) bad();
  return c as CitationSummary;
}

export async function parseEvidence(v: unknown, scope: Scope, citationId: string): Promise<EvidenceView> {
  const e = record(v);
  const c = parseCitation(e, scope);
  if (c.citation_id !== citationId || !text(e["version"], 200) || !integer(e["excerpt_start"])
      || !integer(e["excerpt_end"]) || e["excerpt_start"] > c.span_start || e["excerpt_end"] < c.span_end
      || c.span_end - c.span_start > 20000 || c.span_start - e["excerpt_start"] > 256
      || e["excerpt_end"] - c.span_end > 256 || !text(e["text"], 20512) || !digest(e["quote_sha256"])) bad();
  const points = Array.from(e["text"]); // Wire offsets explicitly count Unicode code points, not graphemes.
  if (points.length !== e["excerpt_end"] - e["excerpt_start"]) bad();
  const quote = points.slice(c.span_start - e["excerpt_start"], c.span_end - e["excerpt_start"]).join("");
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(quote));
  const actual = [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (actual !== e["quote_sha256"]) bad();
  return e as EvidenceView;
}

export function scope(context: ExpectedContext, caseId: string, runId: string): Scope {
  if (!uuid(caseId) || !uuid(runId)) bad();
  return { workspace_id: context.workspaceId, case_id: caseId, run_id: runId };
}
