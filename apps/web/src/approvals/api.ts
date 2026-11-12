import { getBoundJson, postDecisionJson, type BoundRequestOptions, type ExpectedContext } from "../api/client";
import type { components } from "../api/schema";
import { checkMessageText } from "../cases/text";
import { cursorOf } from "../runs/api";
import { bad, digest, integer, record, scopeOf, uuid } from "../runs/contracts";

type S = components["schemas"];
export type Detail = S["ProposalDetailView"];
export type Decision = S["ApprovalDecision"];
export type DecisionPayload = S["DecisionRequest"];
export type Page = S["ProposalPage"];
const STATES = ["awaiting_presentation", "awaiting_consent", "awaiting_decision", "approved", "approval_expired", "rejected", "superseded", "expired"];
type Check = (v: unknown) => boolean;
const text = (max: number, min = 1): Check => (v) => typeof v === "string" && v.length <= max * 2
  && Array.from(v).length >= min && Array.from(v).length <= max
  // Controls and unpaired surrogates are invalid wire text; /u treats full surrogate pairs as code points.
  // eslint-disable-next-line no-control-regex
  && !/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\ud800-\udfff]/u.test(v);
export const date: Check = (v) => typeof v === "string" && v.length <= 40 && /(?:Z|\+00:00)$/.test(v) && Number.isFinite(Date.parse(v));
const one = (...values: unknown[]): Check => (v) => values.includes(v);
const array = (check: Check, max: number, min = 0): Check => (v) => Array.isArray(v) && v.length >= min && v.length <= max && v.every(check);
function shape(fields: Record<string, Check>): Check {
  return (v) => {
    if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
    const r = v as Record<string, unknown>;
    return Object.keys(r).length === Object.keys(fields).length && Object.entries(fields).every(([k, check]) => check(r[k]));
  };
}
const positive: Check = (v) => integer(v, 1);
const nullable = (check: Check): Check => (v) => v === null || check(v);
const addressFields = { address1: text(100), address2: text(100, 0), city: text(100), state: text(100), country: text(100), zip: text(5) };
const address = shape(addressFields);
const id = text(64);
const money = shape({ amount_minor: (v) => typeof v === "number" && Number.isSafeInteger(v) && Math.abs(v) <= 10 ** 12, currency: one("USD") });
const timing = one("immediately", "5 to 7 business days");
const reason = one("no longer needed", "ordered by mistake");
const items = array(id, 50, 1);
const actionFields: Record<string, Record<string, Check>> = {
  cancel_pending_order: { order_id: id, reason },
  modify_pending_order_address: { order_id: id, ...addressFields },
  modify_user_address: { user_id: id, ...addressFields },
  modify_pending_order_payment: { order_id: id, payment_method_id: id },
  modify_pending_order_items: { order_id: id, item_ids: items, new_item_ids: items, payment_method_id: id },
  exchange_delivered_order_items: { order_id: id, item_ids: items, new_item_ids: items, payment_method_id: id },
  return_delivered_order_items: { order_id: id, item_ids: items, payment_method_id: id },
};
const effects: Record<string, Record<string, Check>> = {
  cancel_pending_order: { order_id: id, reason, status_before: one("pending"), status_after: one("cancelled"),
    refunds: array(shape({ payment_method_id: id, amount: money, timing }), 50, 1) },
  modify_pending_order_address: { order_id: id, address_before: address, address_after: address, status_after: one("pending") },
  modify_user_address: { user_id: id, address_before: address, address_after: address },
  modify_pending_order_payment: { order_id: id, from_payment_method_id: id, to_payment_method_id: id, amount: money,
    refund_timing: timing, status_after: one("pending") },
  return_delivered_order_items: { order_id: id, items: array(shape({ item_id: id, price: money }), 50, 1),
    returned_items_price_total: money, refund_payment_method_id: id, status_before: one("delivered"), status_after: one("return requested") },
};
for (const tool of ["modify_pending_order_items", "exchange_delivered_order_items"]) effects[tool] = {
  order_id: id, changes: array(shape({ item_id: id, new_item_id: id, product_id: id, price_before: money, price_after: money }), 50, 1),
  price_difference: money, payment_method_id: id, status_before: one(tool === "modify_pending_order_items" ? "pending" : "delivered"),
  status_after: one(tool === "modify_pending_order_items" ? "pending (item modified)" : "exchange requested"), one_time_action: one(true),
};
const runScope = shape({ workspace_id: uuid, case_id: uuid, run_id: uuid });
export function validReason(v: string): boolean { return text(500)(v) && checkMessageText(v).problem === null; }
export function parseDecision(v: unknown): Decision {
  if (!shape({ schema_version: one("policyops.approval-decision/v1"), approval_id: uuid, scope: runScope, proposal_id: uuid,
    proposal_version: positive, action_digest: digest, consent_id: uuid, principal_id: uuid, role: one("reviewer"),
    decision: one("approve", "reject"), reason: text(500), decided_at: date, expires_at: date })(v)) bad();
  const d = v as Decision;
  if (Date.parse(d.decided_at) >= Date.parse(d.expires_at)) bad();
  return d;
}
export function sameDecision(d: Decision, proposalId: string, payload: DecisionPayload, context: ExpectedContext): boolean {
  return d.proposal_id === proposalId && d.proposal_version === payload.proposal_version && d.action_digest === payload.action_digest
    && d.principal_id === context.principalId && d.scope.workspace_id === context.workspaceId
    && d.decision === payload.decision && d.reason === payload.reason;
}
export function parseDetail(v: unknown, proposalId: string, version: number, context: ExpectedContext): Detail {
  if (!uuid(proposalId) || !integer(version, 1)) bad();
  const d = record(v); const p = record(d["proposal"]); const a = record(p["action"]); const e = record(p["effect"]);
  const tool = String(a["tool"]); const af = actionFields[tool]; const ef = effects[tool];
  if (!Object.hasOwn(actionFields, tool) || !Object.hasOwn(effects, tool) || af === undefined || ef === undefined
      || !shape({ tool: one(tool), ...af })(a) || !shape({ kind: one(tool), ...ef })(e)) bad();
  if (!shape({ schema_version: one("policyops.action-proposal/v1"), proposal_id: one(proposalId), proposal_version: one(version),
    scope: runScope, action_digest: digest, intent_digest: digest, customer_user_id: id, action: () => true, effect: () => true,
    presentation: shape({ text: text(8000), text_sha256: digest }), policy: shape({ path: text(500), sha256: digest, source_commit: (v) => typeof v === "string" && /^[a-f0-9]{40}$/.test(v) }),
    rule_ids: array(text(64), 64, 1), resource_versions: array(shape({ kind: one("order", "user", "product"), resource_id: id, version: positive }), 64, 1),
    evidence: array(shape({ evidence_id: uuid, document_version_id: uuid, content_sha256: digest }), 32), rationale: text(1000), created_at: date, expires_at: date })(p)) bad();
  const s = record(p["scope"]);
  if (s["workspace_id"] !== context.workspaceId || !date(d["server_time"]) || !STATES.includes(String(d["state"]))
      || !["created", "presented", "superseded", "expired"].includes(String(d["row_status"]))) bad();
  if (d["presentation"] !== null && !shape({ message_id: uuid, message_sequence: positive, presented_at: date })(d["presentation"])) bad();
  if (d["consent"] !== null && !shape({ consent_id: uuid, customer_message_id: uuid, customer_message_sequence: positive,
    customer_message_text: text(4000), message_source: one("simulated_customer", "operator_entered_customer"), entered_by: nullable(uuid),
    basis: one("explicit_affirmation", "simulator_confirmation_event"), confirmed_at: date, expires_at: date })(d["consent"])) bad();
  const detail = d as Detail;
  const proposal = detail.proposal;
  if (Date.parse(proposal.created_at) >= Date.parse(proposal.expires_at)
      || (detail.consent !== null && (Date.parse(detail.consent.confirmed_at) >= Date.parse(detail.consent.expires_at)
        || (detail.consent.message_source === "operator_entered_customer") !== (detail.consent.entered_by !== null)))) bad();
  // Refuse cross-field substitutions before offering a review, even when individual DTO shapes look valid.
  if (("order_id" in a && a["order_id"] !== e["order_id"]) || ("user_id" in a && a["user_id"] !== e["user_id"])) bad();
  if (tool === "cancel_pending_order" && a["reason"] !== e["reason"]) bad();
  if (tool === "modify_pending_order_address" || tool === "modify_user_address") {
    const after = record(e["address_after"]);
    if (Object.keys(addressFields).some((k) => a[k] !== after[k])) bad();
    if (tool === "modify_user_address" && a["user_id"] !== proposal.customer_user_id) bad();
  }
  if (tool === "modify_pending_order_payment" && a["payment_method_id"] !== e["to_payment_method_id"]) bad();
  if (tool === "modify_pending_order_items" || tool === "exchange_delivered_order_items") {
    const changes = e["changes"] as Record<string, unknown>[];
    if (JSON.stringify(a["item_ids"]) !== JSON.stringify(changes.map((r) => r["item_id"]))
        || JSON.stringify(a["new_item_ids"]) !== JSON.stringify(changes.map((r) => r["new_item_id"]))
        || a["payment_method_id"] !== e["payment_method_id"]) bad();
  }
  if (tool === "return_delivered_order_items") {
    const items = e["items"] as Record<string, unknown>[];
    if (JSON.stringify(a["item_ids"]) !== JSON.stringify(items.map((r) => r["item_id"]))
        || a["payment_method_id"] !== e["refund_payment_method_id"]) bad();
  }
  if (detail.decision !== null) {
    const decision = parseDecision(detail.decision);
    scopeOf(decision.scope, detail.proposal.scope);
    if (decision.proposal_id !== proposalId || decision.proposal_version !== version || decision.action_digest !== p["action_digest"]
        || decision.consent_id !== detail.consent?.consent_id) bad();
  }
  return detail;
}
export async function getDetail(id: string, version: number, options: BoundRequestOptions): Promise<Detail> {
  if (!uuid(id) || !integer(version, 1)) bad();
  return parseDetail(await getBoundJson(`/api/v1/proposals/${id}?version=${String(version)}`, options), id, version, options.context);
}
export async function listApprovals(cursor: string | null, options: BoundRequestOptions): Promise<Page> {
  const q = new URLSearchParams({ limit: "25" }); if (cursor !== null) q.set("cursor", cursor);
  const p = record(await getBoundJson(`/api/v1/approvals?${q.toString()}`, options));
  if (!array(shape({ proposal_id: uuid, proposal_version: positive, case_id: uuid, run_id: uuid, tool: (v) => typeof v === "string" && Object.hasOwn(actionFields, v),
    action_digest: digest, state: (v) => STATES.includes(String(v)), created_at: date, expires_at: date }), 25)(p["items"])) bad();
  return { items: p["items"] as Page["items"], next_cursor: cursorOf(p["next_cursor"]) };
}
export async function decide(id: string, payload: DecisionPayload, options: BoundRequestOptions) {
  if (!uuid(id) || !positive(payload.proposal_version) || !digest(payload.action_digest) || !validReason(payload.reason)
    || !["approve", "reject"].includes(payload.decision)) bad();
  const written = await postDecisionJson(id, payload, options);
  const d = parseDecision(written.value);
  if (!sameDecision(d, id, payload, options.context)) bad();
  return { value: d, replayed: written.replayed };
}
