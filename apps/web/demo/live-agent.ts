import { expect, type Browser } from "@playwright/test";
import { setTimeout as hold } from "node:timers/promises";
import type { components } from "../src/api/schema";
import { ACTION_TIMEOUT, restrictPage } from "./browser.ts";
import { capture, within } from "./capture.ts";
import { caption, center, identity, newContext, read, signIn, submitOnce, verifyFixture,
  type Fixture } from "./walkthrough.ts";

type Schema = components["schemas"];
type Snapshot = Schema["RunSnapshot"];
type ProposalRef = Schema["ProposalRef"];
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const USD = /^\d+(?:\.\d+)?$/;
const check = expect.configure({ timeout: ACTION_TIMEOUT });
const PROPOSAL_TIMEOUT = 140_000;
const RECEIPT_TIMEOUT = 45_000;

export const captions = {
  opening: "Opening the seeded case in the fictional retail workspace",
  start: "Fictional retail data · a customer asks to cancel a pending order",
  active: "Investigation activity · configured for live GPT-6-Luna calls",
  proposal: "Alice inspects the proposed cancellation",
  evidence: "Alice inspects the cited cancellation policy",
  consent: "Alice enters simulated customer consent",
  approval: "A separate reviewer approves the proposed cancellation",
  committed: "The retail simulator committed the cancellation and returned a verified receipt",
  ended_without_proposal: "The investigation ended without a proposal",
  stopped: "The investigation stopped before proposing a cancellation",
  aggregate_cap: "The workspace cost cap refused this investigation",
  proposal_timeout: "The investigation did not show a proposal within the recording time limit",
  uncited_proposal: "The cancellation proposal has no recorded citation",
  action_failed: "The simulator action ended without a committed receipt",
  receipt_timeout: "A verified simulator receipt did not arrive within the recording time limit",
  recording_failed: "The walkthrough stopped before verification finished",
} as const;

type Stop = "ended_without_proposal" | "stopped" | "aggregate_cap" | "proposal_timeout" | "uncited_proposal"
  | "action_failed" | "receipt_timeout" | "recording_failed";

export class RecordingStop extends Error {
  // Node runs this recorder with type stripping only, so no parameter properties.
  readonly outcome: Stop;
  constructor(outcome: Stop) { super(captions[outcome]); this.outcome = outcome; }
}

export function proposalReady(snapshot: Pick<Snapshot, "proposal_ref" | "events"> & {
  run: Pick<Snapshot["run"], "state">;
}): ProposalRef | undefined {
  switch (snapshot.run.state) {
    case "waiting_approval": return snapshot.proposal_ref ?? undefined;
    case "succeeded": throw new RecordingStop("ended_without_proposal");
    case "failed":
      if (snapshot.events.some((e) => "payload" in e && e.payload.type === "error.raised"
          && e.payload.rule_id === "live_agent.aggregate_cap")) throw new RecordingStop("aggregate_cap");
      throw new RecordingStop("stopped");
    case "cancelled":
    case "budget_exceeded": throw new RecordingStop("stopped");
    default: return undefined;
  }
}

export function receiptReady(snapshot: Snapshot, proposal: ProposalRef, decisionId: string): string | undefined {
  const review = snapshot.latest_review?.payload;
  if (review?.type === "review.outcome" && review.outcome !== "unknown") {
    const execution = snapshot.latest_execution?.payload;
    const digest = review.receipt_sha256;
    if (snapshot.projections_complete && review.outcome === "succeeded" && review.reason === "committed"
        && review.proposal_id === proposal.proposal_id && review.proposal_version === proposal.proposal_version
        && review.decision_id === decisionId && execution?.type === "execution.changed"
        && execution.state === "succeeded" && execution.outcome === "committed"
        && review.operation_id === execution.operation_id && review.execution_id === execution.execution_id
        && execution.tool === "cancel_pending_order" && digest !== null && DIGEST.test(digest)
        && digest === execution.receipt_sha256) return digest;
    throw new RecordingStop("action_failed");
  }
  return undefined;
}

export async function poll<T>(readValue: () => Promise<T | undefined>, ms: number,
  timeout: "proposal_timeout" | "receipt_timeout"): Promise<T> {
  const deadline = performance.now() + ms;
  const timedOut = new RecordingStop(timeout);
  const clock = new AbortController();
  const expiry = hold(ms, undefined, { signal: clock.signal }).then(() => { throw timedOut; });
  // No requests are started past the deadline, and the outstanding read is independently bounded.
  try {
    while (performance.now() < deadline) {
      const value = await Promise.race([readValue(), expiry]);
      if (value !== undefined) return value;
      await Promise.race([hold(Math.min(750, Math.max(0, deadline - performance.now()))), expiry]);
    }
    throw timedOut;
  } finally {
    clock.abort();
  }
}

interface Usage {
  call_count: number;
  settled_usd: string;
  held_usd: string;
}

interface Summary {
  run_id: string | null;
  outcome: "committed" | Stop;
  call_count: number | null;
  settled_usd: string | null;
  held_usd: string | null;
  receipt_sha256: string | null;
  case_version: number | null;
  proposal_version: number | null;
}

const liveCapture = { maxBytes: 24_000_000, validate(seconds: number, bytes: number): void {
  if (!Number.isFinite(seconds) || seconds < 2 || seconds > 300 || bytes < 1 || bytes > this.maxBytes) {
    throw new Error("Live-agent WebM exceeded its capture bounds or could not be decoded");
  }
} };

export async function liveWalkthrough(browser: Browser, origin: string, passwords: { alice: string; bob: string },
  path: string) {
  const bob = (await signIn(browser, origin, "bob", "reviewer", passwords.bob, false)).session;
  const alice = (await signIn(browser, origin, "alice", "analyst", passwords.alice, false)).session;
  if (alice.principal === bob.principal || alice.workspace !== bob.workspace) throw new Error("Expected separate roles");
  const caseId = path.slice(7);
  const caseApi = `/api/v1/cases/${caseId}`;
  const context = await newContext(browser, origin);
  try {
    const encoderContext = await newContext(browser, origin);
    try {
      const encoder = await within(encoderContext.newPage(), "Opening video encoder");
      const page = await within(context.newPage(), "Opening recorded page");
      const guard = await restrictPage(context, page, origin, false);
      let viewer = alice;
      await within(context.addCookies(alice.cookies), "Loading analyst session");
      await page.goto("/cases");
      const analyst = await identity(context, "analyst");
      if (analyst.principal !== alice.principal || analyst.workspace !== alice.workspace) {
        throw new Error("Analyst session changed");
      }
      await center(page.getByRole("heading", { name: "Cases", exact: true }));
      await caption(page, captions.opening);
      const recording = await capture(page, encoder, liveCapture);
      const summary: Summary = {
        run_id: null, outcome: "recording_failed", call_count: null, settled_usd: null, held_usd: null,
        receipt_sha256: null, case_version: null, proposal_version: null,
      };
      const recordUsage = async (): Promise<void> => {
        if (summary.run_id === null) return;
        const usage = await read<Usage>(context, `/api/v1/live-agent/runs/${summary.run_id}/usage`, viewer);
        if (!Number.isSafeInteger(usage.call_count) || usage.call_count < 0 || typeof usage.settled_usd !== "string"
            || typeof usage.held_usd !== "string" || !USD.test(usage.settled_usd) || !USD.test(usage.held_usd)) {
          throw new Error("Ledger usage was malformed");
        }
        summary.call_count = usage.call_count;
        summary.settled_usd = usage.settled_usd;
        summary.held_usd = usage.held_usd;
      };
      try {
        try {
          await hold(1200);
          await page.goto(path);
          await center(page.getByRole("button", { name: "Start investigation", exact: true }));
          await caption(page, captions.start);
          await hold(2600);
          recording.check();
          // The normal browser write must start the run and navigate to its workbench.
          const started = await submitOnce<Schema["RunView"]>(page, guard, `${caseApi}/runs`,
            "Start investigation", "Investigation start", 202);
          if (!UUID.test(started.run_id) || started.case_id !== caseId
              || !Number.isSafeInteger(started.case_version) || started.case_version < 1) {
            throw new Error("The start response did not identify the seeded case");
          }
          summary.run_id = started.run_id;
          summary.case_version = started.case_version;
          const runPath = `${path}/runs/${started.run_id}`;
          const snapshot = async (): Promise<Snapshot> => {
            const current = await read<Snapshot>(context, `/api/v1/runs/${started.run_id}/snapshot`, viewer);
            if (current.run.run_id !== started.run_id || current.run.case_id !== caseId) {
              throw new Error("The activity snapshot identifies a different run");
            }
            return current;
          };
          await page.waitForURL((url) => url.pathname === runPath);
          await center(page.getByRole("region", { name: "Latest retained activity", exact: true }));
          await caption(page, captions.active);
          const ref = await poll(async () => proposalReady(await snapshot()), PROPOSAL_TIMEOUT, "proposal_timeout");
          if (!UUID.test(ref.proposal_id) || !Number.isSafeInteger(ref.proposal_version) || ref.proposal_version < 1) {
            throw new Error("The completed proposal identity was malformed");
          }
          summary.proposal_version = ref.proposal_version;
          const { items } = await read<Schema["ProposalPage"]>(context, `${caseApi}/proposals?limit=100`, alice);
          const fixture: Fixture | undefined = items.find((item) => item.proposal_id === ref.proposal_id
            && item.proposal_version === ref.proposal_version);
          if (fixture?.tool !== "cancel_pending_order" || fixture.case_id !== caseId
              || fixture.run_id !== started.run_id || !DIGEST.test(fixture.action_digest)) {
            throw new Error("The expected cancellation proposal was not found");
          }
          const approvalPath = `/approvals/${ref.proposal_id}/versions/${String(ref.proposal_version)}`;
          const approvalApi = `/api/v1/proposals/${ref.proposal_id}`;
          const detail = await read<Schema["ProposalDetailView"]>(context,
            `${approvalApi}?version=${String(ref.proposal_version)}`, alice);
          if (detail.proposal.evidence.length === 0) throw new RecordingStop("uncited_proposal");
          const action = page.getByRole("region", { name: "Presented action", exact: true });
          await check(action).toContainText(fixture.action_digest);
          await center(action.locator(".message-text").first());
          await caption(page, captions.proposal);
          await hold(2000);
          await action.getByRole("link", { name: /^Inspect source / }).first().click();
          const evidence = page.getByRole("region", { name: "Historical evidence", exact: true });
          await center(evidence.locator(".evidence-excerpt"));
          await caption(page, captions.evidence);
          await hold(3500);
          await evidence.getByRole("link", { name: "Close evidence", exact: true }).click();

          const input = page.getByRole("textbox", { name: "Message", exact: true });
          await center(input);
          await caption(page, captions.consent);
          const source = page.getByRole("radio", { name: "Customer message, entered by me" });
          // The live case view can re-render while it settles; select by keyboard and retry briefly (bounded).
          for (let attempt = 0; attempt < 6 && !(await source.isChecked()); attempt++) {
            await source.focus();
            await source.press("Space");
            if (!(await source.isChecked())) await hold(500);
          }
          if (!(await source.isChecked())) {
            throw new Error(`Customer-message source not selectable (disabled=${String(await source.isDisabled())}, `
              + `count=${String(await source.count())})`);
          }
          await input.fill("yes");
          await page.getByRole("button", { name: /^Post customer message/ }).click();
          await verifyFixture(context, alice, fixture);
          recording.check();
          const posted = await submitOnce<Schema["policyops__services__cases__MessagePosted"]>(
            page, guard, `${caseApi}/messages`, "Confirm post", "Simulated consent");
          if (posted.case.case_id !== caseId || !UUID.test(posted.message.message_id)
              || posted.message.source !== "operator_entered_customer" || posted.message.text !== "yes") {
            throw new Error("Simulated consent response did not match the case");
          }
          await check(action).toContainText("Entered by staff (simulation)");
          await hold(2500);

          await within(context.clearCookies(), "Clearing analyst session");
          await within(context.addCookies(bob.cookies), "Loading reviewer session");
          const reviewer = await identity(context, "reviewer");
          if (reviewer.principal !== bob.principal || reviewer.workspace !== bob.workspace) {
            throw new Error("Reviewer session changed");
          }
          viewer = bob;
          await page.goto(approvalPath);
          await check(page.locator(".approval-identity")).toContainText(fixture.action_digest);
          const consent = page.getByRole("region", { name: "Customer consent", exact: true });
          await check(consent).toContainText("Entered by staff (simulation)");
          await check(consent.getByText("yes", { exact: true })).toBeVisible();
          const reason = page.getByRole("textbox", { name: "Decision reason" });
          await center(reason);
          await caption(page, captions.approval);
          await reason.fill("Verified the pending order, cancellation policy, and simulated customer consent.");
          await page.getByRole("button", { name: /^Approve…$/ }).click();
          await check(page.getByRole("alertdialog")).toContainText(fixture.action_digest);
          await verifyFixture(context, bob, fixture, posted.message.message_id);
          recording.check();
          const decision = await submitOnce<Schema["ApprovalDecision"]>(
            page, guard, `${approvalApi}/decision`, "Confirm approval", "Staff approval");
          if (!UUID.test(decision.approval_id) || decision.principal_id !== bob.principal || decision.decision !== "approve"
              || decision.action_digest !== fixture.action_digest || decision.proposal_id !== ref.proposal_id
              || decision.proposal_version !== ref.proposal_version) {
            throw new Error("The recorded approval did not match the proposal");
          }
          const digest = await poll(async () => receiptReady(await snapshot(), ref, decision.approval_id),
            RECEIPT_TIMEOUT, "receipt_timeout");
          const outcome = page.getByRole("region", { name: "Action outcome", exact: true });
          await check(outcome.getByRole("heading", { name: "Action committed — receipt recorded" })).toBeVisible();
          await check(outcome.getByText(digest, { exact: true })).toBeVisible();
          await center(outcome);
          summary.receipt_sha256 = digest;
          await recordUsage();
          if (summary.call_count === null || summary.call_count < 1) throw new Error("No ledgered model call was recorded");
          guard.check();
          await caption(page, captions.committed);
          summary.outcome = "committed";
          await hold(4500);
        } catch (error) {
          summary.outcome = error instanceof RecordingStop ? error.outcome : "recording_failed";
          if (!(error instanceof RecordingStop)) {
            // Code-authored or Playwright messages only; keep the first line, bounded, for local diagnosis.
            const first = error instanceof Error ? (error.message.split("\n")[0] ?? "").slice(0, 300) : "non-error throw";
            console.error(`Live-agent recorder error: ${first}`);
          }
          await caption(page, captions[summary.outcome]);
          await recordUsage().catch(() => { /* Unverified totals remain null in the sanitized summary. */ });
          await hold(3500);
        }
        return { summary, ...await recording.finish() };
      } finally {
        recording.cancel();
      }
    } finally {
      await within(encoderContext.close(), "Closing video encoder");
    }
  } finally {
    await within(context.close(), "Closing recorded context");
  }
}
