import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { PROPOSAL_ID } from "../test/runFixtures";
import { parseDetail, type Detail } from "./api";
import { EffectDiff } from "./Inspection";
import { OPTIONS, detail } from "./fixtures.test-support";

type Proposal = Detail["proposal"];
const before = { address1: "1 Old St", address2: "", city: "Old City", state: "CA", country: "USA", zip: "12345" };
const after = { ...before, address1: "2 New St" };
const price = { amount_minor: 9901, currency: "USD" } as const;
const order_id = "#W1234567";
const payment_method_id = "credit_card_1234567";
const fixtures: { action: Proposal["action"]; effect: Proposal["effect"]; beforeValue: string }[] = [
  { action: { tool: "modify_pending_order_address", order_id, ...after },
    effect: { kind: "modify_pending_order_address", order_id, address_before: before, address_after: after, status_after: "pending" }, beforeValue: "1 Old St" },
  { action: { tool: "modify_user_address", user_id: "alice_1", ...after },
    effect: { kind: "modify_user_address", user_id: "alice_1", address_before: before, address_after: after }, beforeValue: "1 Old St" },
  { action: { tool: "modify_pending_order_payment", order_id, payment_method_id },
    effect: { kind: "modify_pending_order_payment", order_id, from_payment_method_id: "paypal_1234567", to_payment_method_id: payment_method_id,
      amount: price, refund_timing: "5 to 7 business days", status_after: "pending" }, beforeValue: "paypal_1234567" },
  ...(["modify_pending_order_items", "exchange_delivered_order_items"] as const).map((tool) => ({
    action: { tool, order_id, payment_method_id, item_ids: ["1234567890"], new_item_ids: ["1234567891"] },
    effect: { kind: tool, order_id, payment_method_id, changes: [{ item_id: "1234567890", new_item_id: "1234567891", product_id: "1234567892", price_before: price,
      price_after: { ...price, amount_minor: 10001 } }], price_difference: { ...price, amount_minor: 100 },
      status_before: tool === "modify_pending_order_items" ? "pending" as const : "delivered" as const,
      status_after: tool === "modify_pending_order_items" ? "pending (item modified)" as const : "exchange requested" as const, one_time_action: true as const }, beforeValue: "9901 minor units · USD",
  })),
  { action: { tool: "return_delivered_order_items", order_id, payment_method_id, item_ids: ["1234567890"] },
    effect: { kind: "return_delivered_order_items", order_id, refund_payment_method_id: payment_method_id, items: [{ item_id: "1234567890", price }],
      returned_items_price_total: price, status_before: "delivered", status_after: "return requested" }, beforeValue: "delivered" },
];
test.each(fixtures)("$action.tool displays only typed before/after fields and keeps exact money", ({ action, effect, beforeValue }) => {
  const d = detail(); d.proposal = { ...d.proposal, action, effect };
  const decoded = parseDetail(d, PROPOSAL_ID, 7, OPTIONS.context);
  render(<EffectDiff detail={decoded} />);
  expect(screen.getByRole("table", { name: "Recorded before and after values" }).textContent).toContain(beforeValue);
  expect(screen.queryByText("$99.01")).toBeNull();
  if (effect.kind === "modify_pending_order_address") expect(screen.getByRole("table").textContent).not.toContain("Status");
  const mismatch = structuredClone(d);
  if ("order_id" in mismatch.proposal.effect) mismatch.proposal.effect.order_id = "#W9999999";
  else mismatch.proposal.effect.user_id = "bob_1";
  expect(() => parseDetail(mismatch, PROPOSAL_ID, 7, OPTIONS.context)).toThrow();
});
