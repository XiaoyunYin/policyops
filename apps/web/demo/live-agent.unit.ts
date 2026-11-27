// @vitest-environment node
import { describe, expect, it } from "vitest";
import type { components } from "../src/api/schema";
import { liveCasePath } from "./guards.ts";
import { captions, poll, proposalReady, receiptReady } from "./live-agent.ts";

type Snapshot = components["schemas"]["RunSnapshot"];
const id = "00000000-0000-0000-0000-000000000017";
const digest = "a".repeat(64);
const ref = { proposal_id: id, proposal_version: 1 };

describe("live-agent recording", () => {
  it("uses factual captions and accepts only a seeded case path", () => {
    expect(captions.start.toLowerCase()).toContain("fictional retail data");
    expect(captions.active).toContain("live GPT-6-Luna calls");
    expect(captions.consent).toContain("simulated customer consent");
    expect(captions.approval.toLowerCase()).toContain("a separate reviewer approves");
    expect(liveCasePath(`/cases/${id}`)).toBe(`/cases/${id}`);
    expect(() => liveCasePath(`/cases/${id}?search`)).toThrow(/seeded/);
  });

  it("distinguishes a pending proposal from a stop and an investigation that ended without one", () => {
    const state = (value: Snapshot["run"]["state"], proposal_ref: Snapshot["proposal_ref"] = null) =>
      ({ run: { state: value }, proposal_ref, events: [] });
    expect(proposalReady(state("running"))).toBeUndefined();
    expect(proposalReady(state("waiting_approval", ref))).toEqual(ref);
    expect(() => proposalReady(state("succeeded"))).toThrow(captions.ended_without_proposal);
    expect(() => proposalReady(state("budget_exceeded"))).toThrow(captions.stopped);
  });

  it("requires a matching approval and committed execution receipt", () => {
    const snapshot = {
      projections_complete: true,
      latest_review: { payload: { type: "review.outcome", outcome: "succeeded", reason: "committed",
        proposal_id: id, proposal_version: 1, decision_id: id, operation_id: id, execution_id: id, receipt_sha256: digest } },
      latest_execution: { payload: { type: "execution.changed", state: "succeeded", outcome: "committed",
        tool: "cancel_pending_order", operation_id: id, execution_id: id, receipt_sha256: digest } },
    } as Snapshot;
    expect(receiptReady(snapshot, ref, id)).toBe(digest);
    expect(() => receiptReady(snapshot, { ...ref, proposal_version: 2 }, id)).toThrow(captions.action_failed);
    expect(() => receiptReady({ ...snapshot, latest_execution: null }, ref, id)).toThrow(captions.action_failed);
  });

  it("times out an outstanding read and returns a ready receipt immediately", async () => {
    await expect(poll(() => new Promise(() => undefined), 20, "proposal_timeout")).rejects
      .toMatchObject({ outcome: "proposal_timeout", message: captions.proposal_timeout });
    await expect(poll(() => Promise.resolve(undefined), 20, "receipt_timeout")).rejects
      .toMatchObject({ outcome: "receipt_timeout" });
    await expect(poll(() => Promise.resolve(digest), 100, "receipt_timeout")).resolves.toBe(digest);
  });
});
