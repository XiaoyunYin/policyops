import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { json } from "../test/fakeApi";
import { renderApp } from "../test/renderApp";
import { CASE, DECISION_ID, EXECUTION_ID, OPERATION_ID, PROPOSAL_ID, RUN_ID, committed, event, frame, review, run, snapshot, byteStream } from "../test/runFixtures";
import { fixture, ROUTE } from "../approvals/fixtures.test-support";
import { hydrate, append } from "./reducer";
import { parseSnapshot } from "./contracts";
import { SCOPE } from "../test/runFixtures";
import { RunOutcomeCard } from "./RunOutcomeCard";

afterEach(() => { vi.useRealTimers(); });
describe("factual action outcome mapping", () => {
  test("successful investigation without typed action facts stays unconfirmed; fenced is distinct from committed", () => {
    const base = hydrate(snapshot({ run: run({ state: "succeeded" }) }));
    const view = render(<RunOutcomeCard activity={base} />);
    expect(screen.getByRole("heading", { name: "Investigation completed" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "No confirmed action result" })).toBeTruthy();
    const fenced = append(base, [review(1, "reconciled", 1)]); view.rerender(<RunOutcomeCard activity={fenced} />);
    expect(screen.getByRole("heading", { name: "Reconciled — no business effect committed" })).toBeTruthy();
    expect(screen.queryByText("Action committed — receipt recorded")).toBeNull();
  });
  test("cancelled lifecycle survives unknown → late receipt correction, reload and an older review revision", () => {
    let state = hydrate(snapshot({ run: run({ state: "cancelled" }) }));
    state = append(state, [review(1, "unknown", 3)]); const view = render(<RunOutcomeCard activity={state} />);
    expect(screen.getByRole("heading", { name: "Outcome unconfirmed — reconciliation required" })).toBeTruthy();
    state = append(state, [committed(2), review(3, "unknown", 2)]); view.rerender(<RunOutcomeCard activity={state} />);
    expect(screen.getByRole("heading", { name: "Investigation cancelled" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Action committed — receipt recorded" })).toBeTruthy(); expect(screen.getByText("Receipt arrived after cancellation")).toBeTruthy();
    expect(screen.getByText("d".repeat(64))).toBeTruthy(); expect(screen.queryByRole("button", { name: /Retry execution/ })).toBeNull();
    const fresh = hydrate(snapshot({ run: run({ state: "cancelled", event_highwater: 3 }), highwater: 3,
      events: [review(1, "unknown", 3), committed(2), review(3, "unknown", 2)], latest_execution: committed(2), latest_review: review(3, "unknown", 2) }));
    view.rerender(<RunOutcomeCard activity={fresh} />); expect(screen.getByText("Receipt arrived after cancellation")).toBeTruthy();
  });
  test("stop cleanup/usage warnings do not overwrite a known receipt; incomplete projections cannot look successful", () => {
    const stop = event(2, { type: "run.stopped", message_id: DECISION_ID, details: { reason: "usage_unconfirmed", cleanup_unconfirmed: true, usage_unconfirmed: true } });
    const state = append(hydrate(snapshot()), [committed(1), stop]); const view = render(<RunOutcomeCard activity={state} />);
    expect(screen.getByRole("heading", { name: "Action committed — receipt recorded" })).toBeTruthy();
    expect(screen.getByText("Usage remains unconfirmed.")).toBeTruthy(); expect(screen.getByText("Cleanup pending.")).toBeTruthy();
    view.rerender(<RunOutcomeCard activity={{ ...state, projectionsComplete: false }} />);
    expect(screen.getByRole("heading", { name: "Outcome unavailable — refresh required" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Action committed — receipt recorded" })).toBeNull();
    view.rerender(<RunOutcomeCard activity={state} integrityError />);
    expect(screen.queryByRole("heading", { name: "Action committed — receipt recorded" })).toBeNull();
  });
  test("an exact-version detail cannot attribute an unbound run receipt to its proposal", () => {
    const state = append(hydrate(snapshot()), [committed(1)]);
    render(<RunOutcomeCard activity={state} proposalId={PROPOSAL_ID} version={7} />);
    expect(screen.getByRole("heading", { name: "Outcome unavailable — refresh required" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Action committed — receipt recorded" })).toBeNull();
  });
  test("invalid committed facts and conflicting terminal truth are rejected", () => {
    const e = committed(1); if (e.payload.type !== "execution.changed") throw new Error("fixture"); e.payload.receipt_sha256 = null;
    expect(() => parseSnapshot(snapshot({ run: run({ event_highwater: 1 }), highwater: 1, events: [e] }), SCOPE)).toThrow();
    expect(() => append(hydrate(snapshot()), [committed(1), review(2, "reconciled", 2)])).toThrow();
  });
  test.each(["pending", "dispatched", "unknown", "failed", "reconciled"] as const)("typed execution %s uses a closed factual state", (state) => {
    const e = event(1, { type: "execution.changed", execution_id: EXECUTION_ID, operation_id: OPERATION_ID, tool: "cancel_pending_order", state,
      attempt: 1, code: null, receipt_sha256: null, outcome: state === "failed" ? "precheck_refused" : state === "reconciled" ? "fenced" : null });
    render(<RunOutcomeCard activity={append(hydrate(snapshot()), [e])} />);
    const title = state === "pending" ? "Execution pending" : state === "dispatched" ? "Dispatched — result pending" : state === "failed" ? "Action refused"
      : state === "reconciled" ? "Reconciled — no business effect committed" : "Outcome unconfirmed — checking for a receipt";
    expect(screen.getByRole("heading", { name: title })).toBeTruthy();
  });
  test("approval detail observes a cancelled run through late receipt and reload, without execution retry", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "performance"] });
    const api = fixture(); let late = false;
    const unknown = review(1, "unknown", 1); if (unknown.payload.type === "review.outcome") unknown.payload.proposal_version = 7;
    const receipt = committed(2);
    api.on("GET", `/api/v1/runs/${RUN_ID}/snapshot`, () => json(200, snapshot({ run: run({ state: "cancelled", event_highwater: late ? 2 : 1 }),
      highwater: late ? 2 : 1, events: late ? [unknown, receipt] : [unknown], latest_review: unknown, latest_execution: late ? receipt : null,
      proposal_ref: { proposal_id: PROPOSAL_ID, proposal_version: 7 } })));
    api.stream(`/api/v1/runs/${RUN_ID}/events`, () => byteStream(late ? frame(receipt) : ""));
    const view = renderApp(ROUTE); await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    expect(screen.getByRole("heading", { name: "Outcome unconfirmed — reconciliation required" })).toBeTruthy();
    late = true; await act(async () => { await vi.advanceTimersByTimeAsync(5100); });
    expect(screen.getByRole("heading", { name: "Action committed — receipt recorded" })).toBeTruthy(); expect(screen.getByText("Receipt arrived after cancellation")).toBeTruthy();
    view.unmount(); renderApp(ROUTE); await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    expect(screen.getByText("Receipt arrived after cancellation")).toBeTruthy(); expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });
  test("case cancel after dispatch keeps action unknown until the later factual receipt", async () => {
    const api = fixture(["analyst"]); const casePath = `/api/v1/cases/${CASE.case_id}`; const runPath = `/api/v1/runs/${RUN_ID}`;
    let cancelled = false;
    const dispatched = event(1, { type: "execution.changed", execution_id: EXECUTION_ID, operation_id: OPERATION_ID, tool: "cancel_pending_order", state: "dispatched", attempt: 1, code: null, outcome: null, receipt_sha256: null });
    const unknown = review(2, "unknown", 1);
    api.on("GET", casePath, () => new Response(JSON.stringify(CASE), { headers: { ETag: '"1"' } }));
    api.on("GET", `${casePath}/messages`, json(200, { items: [], next_after_sequence: null }));
    api.on("GET", `${casePath}/runs`, json(200, { items: [run()], next_cursor: null }));
    api.on("GET", `${runPath}/citations`, json(200, { items: [], next_cursor: null }));
    api.on("GET", `${runPath}/snapshot`, () => json(200, snapshot({ run: run({ state: cancelled ? "cancelled" : "running", event_highwater: cancelled ? 2 : 1 }),
      highwater: cancelled ? 2 : 1, events: cancelled ? [dispatched, unknown] : [dispatched], latest_execution: dispatched, latest_review: cancelled ? unknown : null })));
    api.stream(`${runPath}/events`, () => cancelled ? byteStream("") : new ReadableStream());
    api.on("POST", `${runPath}/cancel`, () => { cancelled = true; return new Response(JSON.stringify(run({ state: "cancelled" })), { headers: { ETag: '"1"' } }); });
    const { user } = renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}`);
    await screen.findByRole("heading", { name: "Dispatched — result pending" });
    await user.click(screen.getByRole("button", { name: "Cancel investigation" }));
    expect(await screen.findByRole("heading", { name: "Outcome unconfirmed — reconciliation required" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Investigation cancelled" })).toBeTruthy();
    const receipt = committed(3);
    api.on("GET", `${runPath}/snapshot`, json(200, snapshot({ run: run({ state: "cancelled", event_highwater: 3 }), highwater: 3,
      events: [dispatched, unknown, receipt], latest_execution: receipt, latest_review: unknown })));
    await user.click(screen.getByRole("button", { name: "Reload activity" }));
    expect(await screen.findByText("Receipt arrived after cancellation")).toBeTruthy(); expect(api.callsTo("POST", `${runPath}/cancel`)).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Retry execution" })).toBeNull();
  });
});
