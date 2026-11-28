import { act, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, test } from "vitest";
import { type MessageView, type Role, type RunView } from "../api/client";
import { FakeApi, envelope, json, me } from "../test/fakeApi";
import { renderApp, settle } from "../test/renderApp";
import { CASE, CITATION_ID, NOW, RUN_ID, citation, evidence, event, frame, run, snapshot, byteStream,
  PROPOSAL_ID, DECISION_ID } from "../test/runFixtures";
import { parseEvidence, parseSnapshot } from "./contracts";

const CASE_PATH = `/api/v1/cases/${CASE.case_id}`;
const RUN_PATH = `/api/v1/runs/${RUN_ID}`;
function fixture(roles: Role[] = ["analyst"], state: RunView["state"] = "succeeded") {
  const api = new FakeApi();
  api.on("GET", "/api/v1/me", json(200, me({ roles })));
  api.on("GET", CASE_PATH, new Response(JSON.stringify(CASE), { headers: { ETag: '"1"' } }));
  api.on("GET", `${CASE_PATH}/messages`, json(200, { items: [], next_after_sequence: null }));
  api.on("GET", `${CASE_PATH}/runs`, json(200, { items: [run({ state })], next_cursor: null }));
  api.on("GET", `${RUN_PATH}/snapshot`, () => json(200, snapshot({ run: run({ state }) })));
  api.on("GET", `${RUN_PATH}/citations`, json(200, { items: [], next_cursor: null }));
  api.stream(`${RUN_PATH}/events`, () => byteStream(""));
  return api;
}
describe("workbench routes and writes", () => {
  test("a persisted investigation reason survives a case reload and model text stays inert", async () => {
    const api = fixture(["analyst"]);
    const text = '<img src=x onerror="alert(1)">The policy does not cover this request.';
    const posted: MessageView = { message_id: CITATION_ID, case_id: CASE.case_id, sequence: 1,
      source: "agent", entered_by: null, text, text_sha256: "a".repeat(64), created_at: NOW };
    const outcome = event(1, { type: "investigation.outcome", reason: "cited_decline" });
    api.on("GET", `${CASE_PATH}/messages`, () => json(200, { items: [posted], next_after_sequence: null }));
    api.on("GET", `${RUN_PATH}/snapshot`, () => json(200, snapshot({ highwater: 1,
      run: run({ state: "succeeded", event_highwater: 1 }), events: [outcome], latest_investigation: outcome })));
    const url = `/cases/${CASE.case_id}/runs/${RUN_ID}`;
    const opened = renderApp(url);
    expect(await screen.findByText("The investigation declined the request with a policy citation")).toBeTruthy();
    opened.unmount();
    renderApp(url);
    expect(await screen.findByText("The investigation declined the request with a policy citation")).toBeTruthy();
    const message = await screen.findByText(text);
    expect(message.querySelector("img")).toBeNull();
    expect(message.textContent).toBe(text);
  });

  test("case entry discovers a run; a pinned reload uses the exact ID and never posts", async () => {
    const api = fixture(["auditor"]);
    renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}`);
    expect(await screen.findByRole("region", { name: "Investigation lifecycle" })).toBeTruthy();
    expect(await screen.findByText("Activity settled", { exact: false })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Start investigation" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel investigation" })).toBeNull();
    expect(api.calls.filter((c) => c.method !== "GET")).toHaveLength(0);
  });
  test("successful start attaches its validated run and refreshes the case", async () => {
    const api = fixture();
    api.on("GET", `${CASE_PATH}/runs`, json(200, { items: [], next_cursor: null }));
    api.on("POST", `${CASE_PATH}/runs`, new Response(JSON.stringify(run()), { status: 202, headers: { ETag: '"1"' } }));
    const { user } = renderApp(`/cases/${CASE.case_id}`);
    await user.click(await screen.findByRole("button", { name: "Start investigation" }));
    expect(await screen.findByRole("region", { name: "Investigation lifecycle" })).toBeTruthy();
    expect(await screen.findByTestId("location")).toHaveProperty("textContent", `/cases/${CASE.case_id}/runs/${RUN_ID}`);
    expect(api.callsTo("GET", CASE_PATH).length).toBeGreaterThanOrEqual(2);
    expect(api.callsTo("POST", `${CASE_PATH}/runs`)[0]?.headers.get("If-Match")).toBe('"1"');
  });
  test("cancel uses a run identity, no If-Match, and preserves uncertainty after a refused retry", async () => {
    const api = fixture(["analyst"], "running");
    api.stream(`${RUN_PATH}/events`, () => new ReadableStream());
    const path = `${RUN_PATH}/cancel`;
    api.next("POST", path, new TypeError("lost reply"));
    api.next("POST", path, json(403, envelope("forbidden", "Refused.")));
    api.next("POST", path, new Response(JSON.stringify(run({ state: "cancelled" })), { headers: { ETag: '"1"' } }));
    const { user } = renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}`);
    const cancel = await screen.findByRole("button", { name: "Cancel investigation" });
    await waitFor(() => { expect(cancel.hasAttribute("disabled")).toBe(false); });
    await user.click(cancel);
    expect(await screen.findByRole("heading", { name: "Cancellation request unconfirmed" })).toBeTruthy();
    expect(cancel.hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("button", { name: "Retry the same request" }));
    expect(await screen.findByText(/The retry was refused/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Cancellation request unconfirmed" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Retry the same request" }));
    expect(await screen.findByText(/Cancellation request recorded/)).toBeTruthy();
    const calls = api.callsTo("POST", path);
    expect(calls).toHaveLength(3);
    expect(new Set(calls.map((c) => c.headers.get("Idempotency-Key"))).size).toBe(1);
    expect(calls.every((c) => !c.headers.has("If-Match"))).toBe(true);
  });
  test("a foreign case/run association and malformed route never render protected activity", async () => {
    const api = fixture();
    api.on("GET", `${RUN_PATH}/snapshot`, json(200, snapshot({ run: { ...run(), case_id: RUN_ID } })));
    const view = renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}`);
    expect(await screen.findByRole("heading", { name: "Unexpected response" })).toBeTruthy();
    expect(screen.queryByRole("list", { name: "Investigation activity" })).toBeNull();
    view.unmount();
    const count = api.calls.length;
    renderApp(`/cases/${CASE.case_id}/runs/not-a-uuid`);
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy();
    expect(api.calls.slice(count).every((c) => c.path === "/api/v1/me")).toBe(true);
  });
  test("streamed message seeks its exact sequence without advancing the loaded prefix", async () => {
    const api = fixture();
    const message = { message_id: CITATION_ID, case_id: CASE.case_id, sequence: 500, source: "agent", entered_by: null,
      text: "A newly recorded answer.", text_sha256: "a".repeat(64), created_at: NOW };
    api.on("GET", `${CASE_PATH}/messages`, (call) => json(200,
      new URL(call.url, "http://app.test").searchParams.get("after_sequence") === "499"
        ? { items: [message], next_after_sequence: null } : { items: [], next_after_sequence: null }));
    let reads = 0;
    const marker = event(1, { type: "case.message_posted", message_id: CITATION_ID, message_sequence: 500, source: "agent" });
    api.on("GET", `${RUN_PATH}/snapshot`, () => json(200, reads++ === 0 ? snapshot() : snapshot({ highwater: 1,
      run: run({ event_highwater: 1, state: "succeeded" }), events: [marker] })));
    api.stream(`${RUN_PATH}/events`, () => byteStream(frame(marker)));
    renderApp(`/cases/${CASE.case_id}`);
    expect(await screen.findByText(message.text)).toBeTruthy();
    const after = api.callsTo("GET", `${CASE_PATH}/messages`).map((c) => new URL(c.url, "http://app.test").searchParams.get("after_sequence"));
    expect(after).toContain("499");
    expect(screen.getByRole("list", { name: "Latest messages" }).textContent).toContain(message.text);
  });
  test("a live agent message refreshes the case version before the next customer post", async () => {
    const api = fixture(["analyst"], "running");
    const messagesPath = `${CASE_PATH}/messages`;
    const agent: MessageView = {
      message_id: CITATION_ID, case_id: CASE.case_id, sequence: 1, source: "agent", entered_by: null,
      text: "Review the proposed cancellation.", text_sha256: "a".repeat(64), created_at: NOW,
    };
    const customer: MessageView = {
      ...agent, message_id: PROPOSAL_ID, sequence: 2, source: "operator_entered_customer",
      entered_by: run().initiated_by, text: "yes",
    };
    const marker = event(1, { type: "case.message_posted", message_id: agent.message_id,
      message_sequence: agent.sequence, source: agent.source });
    let stream: ReadableStreamDefaultController<Uint8Array> | undefined;
    api.stream(`${RUN_PATH}/events`, () => new ReadableStream({ start(controller) { stream = controller; } }));
    api.on("POST", messagesPath, (call) => call.headers.get("If-Match") === '"2"'
      ? new Response(JSON.stringify({ case: { ...CASE, version: 3 }, message: customer }),
        { status: 201, headers: { ETag: '"3"' } })
      : json(409, { ...envelope("stale_version", "The case changed."), rule_id: "api.stale_version" }));

    const { user } = renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}`);
    const summary = await screen.findByRole("region", { name: "Case summary" });
    expect(within(summary).getByText("1", { exact: true })).toBeTruthy();
    await waitFor(() => { expect(stream).toBeDefined(); });
    const olderRead = api.defer("GET", CASE_PATH);
    await user.click(within(summary).getByRole("button", { name: "Refresh" }));
    await waitFor(() => { expect(olderRead.call).not.toBeNull(); });

    const liveRead = api.defer("GET", CASE_PATH);
    api.on("GET", messagesPath, json(200, { items: [agent], next_after_sequence: null }));
    act(() => { stream?.enqueue(new TextEncoder().encode(frame(marker))); });
    await waitFor(() => { expect(liveRead.call).not.toBeNull(); });
    expect(screen.queryByText(agent.text)).toBeNull();
    expect(screen.getByRole("button", { name: "Start investigation" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("radio", { name: "Customer message, entered by me" }));
    await user.type(screen.getByRole("textbox", { name: "Message" }), "yes");
    expect(screen.getByRole("button", { name: "Post customer message…" }).hasAttribute("disabled")).toBe(true);
    expect(api.callsTo("POST", messagesPath)).toHaveLength(0);

    liveRead.resolve(new Response(JSON.stringify({ ...CASE, version: 2 }), { headers: { ETag: '"2"' } }));
    expect(await screen.findByText(agent.text)).toBeTruthy();
    expect(within(summary).getByText("2", { exact: true })).toBeTruthy();
    olderRead.resolve(new Response(JSON.stringify(CASE), { headers: { ETag: '"1"' } }));
    await settle();
    expect(within(summary).getByText("2", { exact: true })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Post customer message…" }));
    await user.click(screen.getByRole("button", { name: "Confirm post" }));
    expect(await screen.findByText("yes", { selector: ".message-text" })).toBeTruthy();
    expect(api.callsTo("POST", messagesPath).map((call) => call.headers.get("If-Match"))).toEqual(['"2"']);
    expect(screen.queryByRole("heading", { name: "Your message wasn't posted" })).toBeNull();
  });
});

describe("historical evidence", () => {
  test("quote hash/code-point validation handles emoji and combining marks, and rejects bad bindings", async () => {
    const e = await evidence();
    expect(await parseEvidence(e, e.scope, e.citation_id)).toEqual(e);
    await expect(parseEvidence({ ...e, quote_sha256: "f".repeat(64) }, e.scope, e.citation_id)).rejects.toThrow();
    await expect(parseEvidence({ ...e, span_end: 100 }, e.scope, e.citation_id)).rejects.toThrow();
    await expect(parseEvidence(e, { ...e.scope, run_id: PROPOSAL_ID }, e.citation_id)).rejects.toThrow();
    expect(() => parseSnapshot({ ...snapshot(), highwater: 9 }, e.scope)).toThrow();
  });
  test("malicious text/URI remain inert, close returns to and focuses the source link", async () => {
    const api = fixture();
    const e = await evidence('x😀e\u0301z <script>evil()</script><img onerror="evil()"><svg onload="evil()">[link](javascript:evil())');
    api.on("GET", `${RUN_PATH}/citations`, json(200, { items: [citation()], next_cursor: null }));
    api.on("GET", `/api/v1/evidence/${CITATION_ID}`, json(200, e));
    const { user, container } = renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}/evidence/${CITATION_ID}`);
    expect(await screen.findByText(/Quote SHA-256/)).toBeTruthy();
    expect(container.querySelector("mark")?.textContent).toBe("😀e\u0301");
    expect(container.querySelector("script, img, svg, a[href^='javascript:']")).toBeNull();
    expect(container.textContent).toContain("<script>evil()</script>");
    expect(screen.getByText(e.source_uri, { selector: "dd" })).toBeTruthy();
    await user.click(screen.getByRole("link", { name: "Close evidence" }));
    await waitFor(() => { expect(document.activeElement?.id).toBe(`citation-${CITATION_ID}`); });
    expect(screen.queryByRole("heading", { name: "Historical evidence" })).toBeNull();
  });
  test.each([403, 404, 409])("read refusal %s drops the excerpt", async (status) => {
    const api = fixture();
    api.on("GET", `/api/v1/evidence/${CITATION_ID}`, json(status, envelope(status === 403 ? "forbidden" : status === 404 ? "not_found" : "conflict", "Unavailable.")));
    renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}/evidence/${CITATION_ID}`);
    expect(await screen.findByText(status === 403 ? "Evidence access is unavailable." : status === 404
      ? "This evidence is hidden or missing." : "Evidence integrity could not be verified.")).toBeTruthy();
    expect(document.querySelector("mark")).toBeNull();
  });
  test("late excerpt is dropped when navigating to another source", async () => {
    const api = fixture();
    const pending = api.defer("GET", `/api/v1/evidence/${CITATION_ID}`);
    const e = await evidence();
    api.on("GET", `${RUN_PATH}/citations`, json(200, { items: [{ ...citation(), citation_id: PROPOSAL_ID }], next_cursor: null }));
    api.on("GET", `/api/v1/evidence/${PROPOSAL_ID}`, json(404, envelope("not_found", "No source.")));
    const { user } = renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}/evidence/${CITATION_ID}`);
    const source = await screen.findByRole("link", { name: /Source b0000000/ });
    await user.click(source);
    act(() => { pending.resolve(json(200, e)); });
    expect(await screen.findByText("This evidence is hidden or missing.")).toBeTruthy();
    expect(document.querySelector("mark")).toBeNull();
    expect(pending.call?.signal?.aborted).toBe(true);
  });
  test("proposal binding survives a tail with no presentation marker", async () => {
    const api = fixture();
    api.on("GET", `${RUN_PATH}/snapshot`, json(200, snapshot({ run: run({ state: "succeeded" }),
      proposal_ref: { proposal_id: PROPOSAL_ID, proposal_version: 2 } })));
    api.on("GET", `/api/v1/proposals/${PROPOSAL_ID}`, json(200, { state: "awaiting_consent", consent: null,
      proposal: { proposal_id: PROPOSAL_ID, proposal_version: 2, action_digest: "f".repeat(64), scope: citation().scope,
        presentation: { text: "Cancel the recorded order." }, resource_versions: [{ kind: "order", resource_id: "#W1234567", version: 3 }],
        evidence: [{ evidence_id: CITATION_ID, document_version_id: DECISION_ID, content_sha256: "a".repeat(64) }] } }));
    renderApp(`/cases/${CASE.case_id}/runs/${RUN_ID}`);
    const panel = await screen.findByRole("region", { name: "Presented action" });
    expect(await within(panel).findByText("Cancel the recorded order.")).toBeTruthy();
    expect(panel.textContent).toContain("order #W1234567 · version 3");
    expect(api.callsTo("GET", `/api/v1/proposals/${PROPOSAL_ID}`)[0]?.url).toContain("version=2");
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });
});
