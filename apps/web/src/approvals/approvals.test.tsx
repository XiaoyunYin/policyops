import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { renderApp, settle } from "../test/renderApp";
import { OTHER_PRINCIPAL, PRINCIPAL, WORKSPACE_B, envelope, json, me, setCsrfCookie } from "../test/fakeApi";
import { CITATION_ID, DECISION_ID, NOW, PROPOSAL_ID, RUN_ID } from "../test/runFixtures";
import { getDetail, parseDetail, validReason, type DecisionPayload } from "./api";
import { DECIDE_PATH, DETAIL_PATH, LATER, OPTIONS, PAYLOAD, ROUTE, decision, detail, fixture, page } from "./fixtures.test-support";

afterEach(() => { vi.useRealTimers(); setCsrfCookie(null); });
async function prepare(user: ReturnType<typeof renderApp>["user"], reject = false) {
  await user.type(await screen.findByRole("textbox", { name: "Decision reason" }), PAYLOAD.reason);
  await user.click(screen.getByRole("button", { name: reject ? "Reject…" : "Approve…" }));
  return screen.getByRole("alertdialog", { name: "Confirm exact staff decision" });
}
describe("exact approval review", () => {
  test("an explicit outcome read retry restarts a blocked observation without posting", async () => {
    const api = fixture(); const path = `/api/v1/runs/${RUN_ID}/snapshot`;
    api.next("GET", path, json(503, envelope("unavailable", "Snapshot temporarily unavailable.", true)));
    const { user } = renderApp(ROUTE); await screen.findByRole("heading", { name: "Service unavailable" });
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { name: "No confirmed action result" })).toBeTruthy();
    expect(api.callsTo("GET", path).length).toBeGreaterThan(1); expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(0);
  });
  test("renders exact version/digest/arguments, typed money and consent separately; evidence is version-bound", async () => {
    const api = fixture(); renderApp(ROUTE);
    const args = await screen.findByRole("region", { name: "Action arguments" });
    expect(args.textContent).toContain("#W1234567"); expect(args.textContent).toContain("ordered by mistake");
    expect(screen.getByRole("region", { name: "Effect diff" }).textContent).toContain("12345 minor units · USD");
    const consent = screen.getByRole("region", { name: "Customer consent" });
    expect(consent.textContent).toContain("Entered by staff (simulation)"); expect(consent.textContent).toContain(DECISION_ID);
    expect(consent.textContent).toContain("explicit_affirmation"); expect(consent.textContent).toContain(PRINCIPAL);
    const text = screen.getByRole("region", { name: "Presentation text" });
    expect(text.textContent).toContain(detail().proposal.presentation.text); expect(text.querySelector("script")).toBeNull();
    expect(screen.getByRole("region", { name: "Staff approval" }).textContent).toContain("Staff approval decision");
    expect(screen.getByRole("link", { name: /Inspect source/ }).getAttribute("href")).toContain(`/evidence/${CITATION_ID}`);
    expect(api.callsTo("GET", DETAIL_PATH)[0]?.url).toContain("version=7");
    expect(screen.getByText("a".repeat(64), { selector: ".approval-identity code" })).toBeTruthy();
    expect(screen.getByText("Version", { exact: false, selector: ".approval-identity p" }).textContent).toContain("7");
    expect(api.calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });
  test("keyboard confirmation freezes exact payload and sends one bound CSRF request without write headers", async () => {
    const api = fixture(); setCsrfCookie("review-token");
    api.on("POST", DECIDE_PATH, (call) => json(201, decision(call.body as DecisionPayload)));
    const { user } = renderApp(ROUTE); const dialog = await prepare(user);
    expect(dialog.textContent).toContain("Version 7"); expect(dialog.textContent).toContain(PAYLOAD.action_digest);
    expect(dialog.textContent).toContain(PAYLOAD.reason);
    const confirm = within(dialog).getByRole("button", { name: "Confirm approval" });
    confirm.focus(); await user.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { name: "Approval recorded — execution pending" })).toBeTruthy();
    const calls = api.callsTo("POST", DECIDE_PATH); expect(calls).toHaveLength(1); expect(calls[0]?.body).toEqual(PAYLOAD);
    expect(calls[0]?.headers.get("X-CSRF-Token")).toBe("review-token");
    expect(calls[0]?.headers.get("PolicyOps-Expected-Principal")).toBe(PRINCIPAL);
    expect(calls[0]?.headers.has("Idempotency-Key")).toBe(false); expect(calls[0]?.headers.has("If-Match")).toBe(false);
    expect(screen.queryByText("Action committed — receipt recorded")).toBeNull();
  });
  test("Escape sends nothing, restores focus, and permits editing; double activation confirms once", async () => {
    const api = fixture(); const pending = api.defer("POST", DECIDE_PATH);
    const { user } = renderApp(ROUTE); await prepare(user); await user.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).toBeNull(); expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(0);
    expect(document.activeElement?.textContent).toContain("Approve");
    await user.click(screen.getByRole("button", { name: "Approve…" }));
    const button = screen.getByRole("button", { name: "Confirm approval" });
    act(() => { fireEvent.click(button); fireEvent.click(button); });
    await waitFor(() => { expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1); });
    pending.resolve(json(201, decision(PAYLOAD)));
    expect(await screen.findByRole("heading", { name: "Approval recorded — execution pending" })).toBeTruthy();
  });
  test("unknown then an auth refusal keeps ambiguity; explicit replay sends identical frozen payload", async () => {
    const api = fixture(); api.next("POST", DECIDE_PATH, new TypeError("lost reply"));
    api.next("POST", DECIDE_PATH, json(403, envelope("forbidden", "Reviewer membership revoked.")));
    api.next("POST", DECIDE_PATH, () => new Response(JSON.stringify(decision(PAYLOAD)), { status: 200, headers: { "Idempotent-Replayed": "true" } }));
    const { user } = renderApp(ROUTE); await prepare(user); await user.click(screen.getByRole("button", { name: "Confirm approval" }));
    expect(await screen.findByRole("heading", { name: "Decision unconfirmed" })).toBeTruthy();
    expect(screen.getByRole<HTMLTextAreaElement>("textbox", { name: "Decision reason" }).disabled).toBe(true);
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Retry the same decision" }));
    expect(await screen.findByText(/This retry was refused/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Decision unconfirmed" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Retry the same decision" }));
    expect(await screen.findByRole("heading", { name: "Approval recorded — execution pending" })).toBeTruthy();
    expect(api.callsTo("POST", DECIDE_PATH).map((c) => c.body)).toEqual([PAYLOAD, PAYLOAD, PAYLOAD]);
  });
  test.each([409, 410])("%i stale/expiry refusal remains visible with canonical reload; no automatic retry", async (status) => {
    const api = fixture(); api.on("POST", DECIDE_PATH, json(status, { ...envelope(status === 410 ? "expired" : "conflict", "Version no longer eligible."), rule_id: "api.proposal_superseded" }));
    const { user } = renderApp(ROUTE); await prepare(user); await user.click(screen.getByRole("button", { name: "Confirm approval" }));
    expect(await screen.findByRole("heading", { name: "Decision refused" })).toBeTruthy();
    expect(screen.getByText("api.proposal_superseded")).toBeTruthy(); expect(screen.queryByRole("alertdialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Reload canonical detail" }));
    await waitFor(() => { expect(api.callsTo("GET", DETAIL_PATH).length).toBeGreaterThan(2); });
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1);
  });
  test("rejection records a decision, never replans or reports execution success", async () => {
    const api = fixture(); api.on("POST", DECIDE_PATH, (call) => json(201, decision(call.body as DecisionPayload)));
    const { user } = renderApp(ROUTE); await prepare(user, true); await user.click(screen.getByRole("button", { name: "Confirm rejection" }));
    expect(await screen.findByRole("heading", { name: "Rejection recorded" })).toBeTruthy();
    expect(api.calls.filter((c) => c.method === "POST").map((c) => c.body)).toEqual([{ ...PAYLOAD, decision: "reject" }]);
  });
  test.each([["analyst"], ["admin"], ["auditor"]] as const)("%s inspects without decision controls", async (role) => {
    fixture([role]); renderApp(ROUTE); expect(await screen.findByText(/Inspection only/)).toBeTruthy();
    expect(screen.queryByRole("textbox", { name: "Decision reason" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve…" })).toBeNull();
  });
  test("admin + reviewer union permits decisions; absent persisted consent disables both", async () => {
    const api = fixture(["admin", "reviewer"]); api.on("GET", DETAIL_PATH, json(200, detail({ consent: null, state: "awaiting_consent" })));
    renderApp(ROUTE); const approve = await screen.findByRole("button", { name: "Approve…" });
    expect(approve.hasAttribute("disabled")).toBe(true); expect(screen.getByRole("button", { name: "Reject…" }).hasAttribute("disabled")).toBe(true);
  });
  test("a background canonical replacement invalidates confirmation and requires fresh review", async () => {
    const api = fixture(); const { user } = renderApp(ROUTE); await prepare(user);
    const next = detail(); next.proposal.action_digest = "f".repeat(64);
    api.on("GET", DETAIL_PATH, json(200, next));
    act(() => { window.dispatchEvent(new Event("focus")); });
    await waitFor(() => { expect(screen.queryByRole("alertdialog")).toBeNull(); });
    expect(screen.getByRole<HTMLTextAreaElement>("textbox", { name: "Decision reason" }).value).toBe("");
    expect(screen.getByText(/Canonical proposal details changed/)).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Refresh exact proposal" }));
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(0);
  });
  test.each(["proposal", "consent"])("%s expiry during confirmation disables new writes and announces only thresholds", async (which) => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "performance"] });
    const api = fixture(); const d = detail(); d.proposal.expires_at = which === "proposal" ? "2026-11-12T09:00:02Z" : LATER;
    if (d.consent !== null) d.consent.expires_at = which === "consent" ? "2026-11-12T09:00:02Z" : LATER;
    api.on("GET", DETAIL_PATH, json(200, d));
    const { user } = renderApp(ROUTE); await prepare(user);
    api.on("GET", DETAIL_PATH, () => json(200, { ...d, server_time: "2026-11-12T09:00:03Z", state: "expired" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.queryByRole("alertdialog")).toBeNull(); expect(screen.getByRole("button", { name: "Approve…" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByText("Review expired. New decisions are disabled.")).toBeTruthy(); expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(0);
  });
  test("reload reconstructs another reviewer's decision on the pinned version and never posts", async () => {
    const api = fixture(); api.on("GET", DETAIL_PATH, json(200, detail({ decision: decision(PAYLOAD, OTHER_PRINCIPAL), state: "approved" })));
    const view = renderApp(ROUTE); expect(await screen.findByRole("heading", { name: "Already decided by another reviewer" })).toBeTruthy();
    view.unmount(); renderApp(ROUTE); expect(await screen.findByRole("heading", { name: "Already decided by another reviewer" })).toBeTruthy();
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(0); expect(api.callsTo("GET", DETAIL_PATH).every((c) => c.url.includes("version=7"))).toBe(true);
  });
  test("navigation preserves unresolved frozen decisions and canonical read can confirm after a lost response", async () => {
    const api = fixture(); api.next("POST", DECIDE_PATH, new TypeError("lost"));
    const { user } = renderApp(ROUTE); await prepare(user); await user.click(screen.getByRole("button", { name: "Confirm approval" }));
    await screen.findByRole("heading", { name: "Decision unconfirmed" });
    await user.click(screen.getByRole("link", { name: "← Approval inbox" }));
    await user.click(await screen.findByRole("link", { name: "Review version 7" }));
    expect(await screen.findByRole("heading", { name: "Decision unconfirmed" })).toBeTruthy();
    api.on("GET", DETAIL_PATH, json(200, detail({ decision: decision(PAYLOAD), state: "approved" })));
    await user.click(screen.getByRole("button", { name: "Reload canonical detail" }));
    expect(await screen.findByRole("heading", { name: "Approval recorded — execution pending" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Decision unconfirmed" })).toBeNull(); expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1);
  });
  test("a canonical decision from another reviewer disables retries of an earlier unconfirmed attempt", async () => {
    const api = fixture(); api.next("POST", DECIDE_PATH, new TypeError("lost"));
    const { user } = renderApp(ROUTE); await prepare(user); await user.click(screen.getByRole("button", { name: "Confirm approval" }));
    await screen.findByRole("heading", { name: "Decision unconfirmed" });
    api.on("GET", DETAIL_PATH, json(200, detail({ decision: decision(PAYLOAD, OTHER_PRINCIPAL), state: "approved" })));
    await user.click(screen.getByRole("button", { name: "Reload canonical detail" }));
    expect(await screen.findByRole("heading", { name: "Already decided by another reviewer" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Retry the same decision" })).toBeNull();
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1);
  });
  test("cookie context rotation strips a pending decision; returning to the original principal cannot resurrect its reason or retry", async () => {
    const api = fixture(); api.next("POST", DECIDE_PATH, new TypeError("lost"));
    api.on("GET", "/api/v1/cases", json(200, { items: [], next_cursor: null }));
    const { user } = renderApp(ROUTE); await prepare(user); await user.click(screen.getByRole("button", { name: "Confirm approval" }));
    await screen.findByRole("heading", { name: "Decision unconfirmed" });
    api.on("GET", "/api/v1/me", json(200, me({ roles: ["reviewer"], principal: OTHER_PRINCIPAL })));
    act(() => { document.dispatchEvent(new Event("visibilitychange")); });
    await waitFor(() => { expect(screen.getByTestId("location").textContent).toBe("/cases"); });
    expect(screen.queryByText(PAYLOAD.reason)).toBeNull();
    api.on("GET", "/api/v1/me", json(200, me({ roles: ["reviewer"] })));
    act(() => { document.dispatchEvent(new Event("visibilitychange")); }); await settle();
    await user.click(screen.getByRole("link", { name: "Approvals" }));
    await user.click(await screen.findByRole("link", { name: "Review version 7" }));
    expect(await screen.findByRole("heading", { name: "Decision unconfirmed" })).toBeTruthy();
    expect(screen.queryByText(PAYLOAD.reason)).toBeNull(); expect(screen.queryByRole("button", { name: "Retry the same decision" })).toBeNull();
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(1);
  });
  test("two independent clients share a decision service: one wins, the second sees stale canonical truth", async () => {
    const api = fixture(); let stored: ReturnType<typeof decision> | null = null;
    api.on("GET", DETAIL_PATH, () => json(200, detail(stored === null ? {} : { decision: stored, state: "approved" })));
    api.on("POST", DECIDE_PATH, (call) => {
      if (stored !== null) return json(409, { ...envelope("conflict", "Already decided."), rule_id: "api.proposal_already_decided" });
      stored = decision(call.body as DecisionPayload, call.headers.get("PolicyOps-Expected-Principal") ?? PRINCIPAL); return json(201, stored);
    });
    const a = renderApp(ROUTE); await within(a.container).findByRole("textbox", { name: "Decision reason" });
    api.on("GET", "/api/v1/me", json(200, me({ roles: ["reviewer"], principal: OTHER_PRINCIPAL })));
    const b = renderApp(ROUTE); await within(b.container).findByRole("textbox", { name: "Decision reason" });
    for (const view of [a, b]) await view.user.type(within(view.container).getByRole("textbox", { name: "Decision reason" }), PAYLOAD.reason);
    await a.user.click(within(a.container).getByRole("button", { name: "Approve…" }));
    await a.user.click(screen.getByRole("button", { name: "Confirm approval" }));
    await within(a.container).findByRole("heading", { name: "Approval recorded — execution pending" });
    await b.user.click(within(b.container).getByRole("button", { name: "Approve…" }));
    await b.user.click(screen.getByRole("button", { name: "Confirm approval" }));
    expect(await within(b.container).findByRole("heading", { name: "Already decided by another reviewer" })).toBeTruthy();
    expect(within(b.container).getByRole("heading", { name: "Decision refused" })).toBeTruthy();
    expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(2);
  });
});

describe("bounded inbox and reads", () => {
  test("a stale exact-detail read that ignores abort cannot cross a workspace transition", async () => {
    const api = fixture(); const pending = api.defer("GET", DETAIL_PATH);
    api.on("GET", "/api/v1/cases", json(200, { items: [], next_cursor: null }));
    renderApp(ROUTE); await screen.findByText("Loading exact proposal…");
    api.on("GET", "/api/v1/me", json(200, me({ roles: ["reviewer"], workspace: WORKSPACE_B })));
    act(() => { document.dispatchEvent(new Event("visibilitychange")); });
    await waitFor(() => { expect(screen.getByTestId("location").textContent).toBe("/cases"); });
    pending.resolve(json(200, detail())); await settle();
    expect(screen.queryByRole("region", { name: "Action arguments" })).toBeNull();
    expect(screen.queryByText("#W1234567")).toBeNull(); expect(api.callsTo("POST", DECIDE_PATH)).toHaveLength(0);
  });
  test("retains at most 200 deduplicated rows and moves focus to Refresh if its row disappears", async () => {
    const api = fixture(); let offset = 0;
    api.on("GET", "/api/v1/approvals", () => {
      const first = page().items[0]; if (first === undefined) throw new Error("fixture");
      const items = Array.from({ length: 25 }, (_, i) => ({ ...first, proposal_version: offset + i + 1 })); offset += 25;
      return json(200, { items, next_cursor: `page${String(offset)}` });
    });
    const { user } = renderApp("/approvals"); await screen.findByRole("link", { name: "Review version 25" });
    for (let i = 0; i < 7; i++) {
      await user.click(screen.getByRole("button", { name: "Load more approvals" }));
      await screen.findByRole("link", { name: `Review version ${String((i + 2) * 25)}` });
    }
    expect(screen.getAllByRole("link", { name: /^Review version/ })).toHaveLength(200);
    expect(screen.getByRole("button", { name: "Load more approvals" }).hasAttribute("disabled")).toBe(true);
    screen.getByRole("link", { name: "Review version 200" }).focus();
    act(() => { window.dispatchEvent(new Event("focus")); });
    await screen.findByRole("link", { name: "Review version 225" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Refresh inbox" }));
  });
  test("loading/empty/forbidden, cursor paging dedupe and visible refresh", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const api = fixture(); const pending = api.defer("GET", "/api/v1/approvals"); const { user } = renderApp("/approvals");
    expect(await screen.findByText("Loading approvals…")).toBeTruthy();
    const p = page(); pending.resolve(json(200, { ...p, next_cursor: "page2" }));
    await screen.findByRole("link", { name: "Review version 7" });
    api.on("GET", "/api/v1/approvals", json(200, p)); await user.click(screen.getByRole("button", { name: "Load more approvals" }));
    await waitFor(() => { expect(api.callsTo("GET", "/api/v1/approvals")).toHaveLength(2); });
    expect(api.callsTo("GET", "/api/v1/approvals")[1]?.url).toContain("cursor=page2"); expect(screen.getAllByRole("link", { name: "Review version 7" })).toHaveLength(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); }); expect(api.callsTo("GET", "/api/v1/approvals")).toHaveLength(3);
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); }); expect(api.callsTo("GET", "/api/v1/approvals")).toHaveLength(3);
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true }); vi.useRealTimers();
    api.on("GET", "/api/v1/approvals", json(200, { items: [], next_cursor: null }));
    act(() => { document.dispatchEvent(new Event("visibilitychange")); }); expect(await screen.findByRole("heading", { name: "No approvals waiting" })).toBeTruthy();
    api.on("GET", "/api/v1/approvals", json(403, envelope("forbidden", "Reviewer revoked.")));
    await user.click(screen.getByRole("button", { name: "Refresh inbox" })); expect(await screen.findByRole("heading", { name: "You don't have access" })).toBeTruthy();
  });
  test("malformed route and foreign/malformed detail never render protected arguments", async () => {
    const api = fixture(); renderApp(`/approvals/${PROPOSAL_ID}/versions/9007199254740993`);
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy(); expect(api.callsTo("GET", DETAIL_PATH)).toHaveLength(0);
    const d = detail(); d.proposal.scope.workspace_id = WORKSPACE_B.workspace_id;
    expect(() => parseDetail(d, PROPOSAL_ID, 7, OPTIONS.context)).toThrow();
    const bad = detail(); bad.proposal.effect = { ...bad.proposal.effect, kind: "modify_user_address" } as typeof bad.proposal.effect;
    expect(() => parseDetail(bad, PROPOSAL_ID, 7, OPTIONS.context)).toThrow();
    const substituted = detail(); if (substituted.proposal.effect.kind === "cancel_pending_order") substituted.proposal.effect.order_id = "#W9999999";
    expect(() => parseDetail(substituted, PROPOSAL_ID, 7, OPTIONS.context)).toThrow();
    api.on("GET", DETAIL_PATH, json(200, d)); await expect(getDetail(PROPOSAL_ID, 7, OPTIONS)).rejects.toThrow();
  });
  test.each(["", "x".repeat(501), "\ud800", "\u007f", "\r"])("invalid reason %j is refused locally", (reason) => { expect(validReason(reason)).toBe(false); });
  test("reason accepts 500 Unicode code points without rounding a version", () => {
    expect(validReason("😀".repeat(500))).toBe(true); expect(validReason("\n\tChecked")).toBe(true);
    expect(() => parseDetail({ ...detail(), proposal: { ...detail().proposal, proposal_version: 2 ** 53 } }, PROPOSAL_ID, 7, OPTIONS.context)).toThrow();
    expect(NOW).toBeTruthy();
  });
});
