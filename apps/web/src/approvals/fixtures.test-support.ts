import { FakeApi, PRINCIPAL, json, me } from "../test/fakeApi";
import { CASE, CITATION_ID, CONTEXT, DECISION_ID, NOW, PROPOSAL_ID, RUN_ID, SCOPE, byteStream, run, snapshot } from "../test/runFixtures";
import type { Decision, DecisionPayload, Detail, Page } from "./api";
import type { Role, BoundRequestOptions } from "../api/client";

export const DETAIL_PATH = `/api/v1/proposals/${PROPOSAL_ID}`;
export const DECIDE_PATH = `${DETAIL_PATH}/decision`;
export const ROUTE = `/approvals/${PROPOSAL_ID}/versions/7`;
export const LATER = "2026-11-12T09:10:00Z";
export function detail(changes: Partial<Detail> = {}): Detail {
  return { proposal: { schema_version: "policyops.action-proposal/v1", proposal_id: PROPOSAL_ID, proposal_version: 7,
    action_digest: "a".repeat(64), intent_digest: "b".repeat(64), scope: SCOPE, customer_user_id: "alice_1",
    action: { tool: "cancel_pending_order", order_id: "#W1234567", reason: "ordered by mistake" },
    effect: { kind: "cancel_pending_order", order_id: "#W1234567", reason: "ordered by mistake", status_before: "pending", status_after: "cancelled",
      refunds: [{ payment_method_id: "credit_card_1234567", amount: { amount_minor: 12345, currency: "USD" }, timing: "5 to 7 business days" }] },
    presentation: { text: "Cancel #W1234567.\nRefund the recorded payment. <script>inert</script>", text_sha256: "c".repeat(64) },
    policy: { path: "retail/policy.md", source_commit: "d".repeat(40), sha256: "e".repeat(64) }, rule_ids: ["retail.cancel"],
    resource_versions: [{ kind: "order", resource_id: "#W1234567", version: 12 }], evidence: [{ evidence_id: CITATION_ID, document_version_id: DECISION_ID, content_sha256: "a".repeat(64) }],
    rationale: "The order is pending and can be cancelled.", created_at: NOW, expires_at: LATER },
    row_status: "presented", state: "awaiting_decision", presentation: { message_id: CITATION_ID, message_sequence: 4, presented_at: NOW },
    consent: { consent_id: CITATION_ID, customer_message_id: DECISION_ID, customer_message_sequence: 5, customer_message_text: "Yes, cancel that exact order.",
      message_source: "operator_entered_customer", entered_by: PRINCIPAL, basis: "explicit_affirmation", confirmed_at: NOW, expires_at: LATER },
    decision: null, server_time: NOW, ...changes };
}
export function decision(payload: DecisionPayload, principal = PRINCIPAL): Decision {
  return { schema_version: "policyops.approval-decision/v1", approval_id: DECISION_ID, proposal_id: PROPOSAL_ID, scope: SCOPE,
    consent_id: CITATION_ID, principal_id: principal, role: "reviewer", decided_at: NOW, expires_at: LATER, ...payload };
}
export const PAYLOAD: DecisionPayload = { proposal_version: 7, action_digest: "a".repeat(64), decision: "approve", reason: "Checked exact terms." };
export function page(): Page {
  const p = detail().proposal;
  return { items: [{ proposal_id: p.proposal_id, proposal_version: p.proposal_version, case_id: CASE.case_id, run_id: RUN_ID,
    tool: p.action.tool, action_digest: p.action_digest, state: "awaiting_decision", created_at: NOW, expires_at: LATER }], next_cursor: null };
}
export function fixture(roles: Role[] = ["reviewer"]) {
  const api = new FakeApi().on("GET", "/api/v1/me", json(200, me({ roles })))
    .on("GET", DETAIL_PATH, () => json(200, detail())).on("GET", "/api/v1/approvals", json(200, page()));
  api.on("GET", `/api/v1/runs/${RUN_ID}/snapshot`, () => json(200, snapshot({ run: run({ state: "succeeded" }), proposal_ref: { proposal_id: PROPOSAL_ID, proposal_version: 7 } })));
  api.stream(`/api/v1/runs/${RUN_ID}/events`, () => byteStream(""));
  return api;
}
export const OPTIONS: BoundRequestOptions = { context: CONTEXT ?? (() => { throw new Error("fixture"); })(), signal: new AbortController().signal };
