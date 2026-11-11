// Composed regressions for the case queue, detail, composer and investigation control: the real App, session
// controller and write ledger against the fake fetch boundary (jsdom; not a browser or the real server).

import { act, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, test } from "vitest";

import type { CaseView, MessagePage, MessageView, Role } from "../api/client";
import {
  FakeApi,
  WORKSPACE_B,
  caseView,
  envelope,
  json,
  me,
  setCsrfCookie,
  unauthenticated,
  type RecordedCall,
} from "../test/fakeApi";
import { becomeVisible, renderApp, settle } from "../test/renderApp";

afterEach(() => {
  setCsrfCookie(null);
});

const CASE = caseView(1, "Refund for damaged blender");
const ID = CASE.case_id;
const CASE_PATH = `/api/v1/cases/${ID}`;
const MESSAGES = `${CASE_PATH}/messages`;
const RUNS = `${CASE_PATH}/runs`;

function at(version: number): CaseView {
  return { ...CASE, version };
}

function withHeaders(status: number, body: unknown, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

function caseReply(version: number): Response {
  return withHeaders(200, at(version), { ETag: `"${String(version)}"` });
}

function message(sequence: number, text = `Message ${String(sequence)}`,
                 source: MessageView["source"] = "seeded"): MessageView {
  return {
    message_id: `d0000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`, case_id: ID, sequence, source,
    text, text_sha256: "a".repeat(64), entered_by: source === "seeded" ? null : "11111111-1111-4111-8111-111111111111",
    created_at: "2026-11-02T10:30:00Z",
  };
}

function page(items: MessageView[], next: number | null = null): MessagePage {
  return { items, next_after_sequence: next };
}

function posted(sequence: number, version: number, text: string, replayed = false,
                source: MessageView["source"] = "staff_note"): Response {
  return withHeaders(201, { message: message(sequence, text, source), case: at(version) }, {
    ETag: `"${String(version)}"`, ...(replayed ? { "Idempotent-Replayed": "true" } : {}) });
}

function openCase(roles: Role[] = ["analyst"], version = 2, messages: MessagePage = page([message(1)])): FakeApi {
  setCsrfCookie("csrf-token");
  return new FakeApi().on("GET", "/api/v1/me", json(200, me({ roles })))
    .on("GET", CASE_PATH, caseReply(version)).on("GET", MESSAGES, json(200, messages));
}

function writeIdentity(call: RecordedCall): unknown[] {
  return [call.headers.get("Idempotency-Key"), call.headers.get("If-Match"), JSON.stringify(call.body),
          call.headers.get("PolicyOps-Expected-Workspace")];
}

async function writeNote(user: ReturnType<typeof renderApp>["user"], text: string): Promise<void> {
  await user.click(await screen.findByRole("radio", { name: "Staff note" }));
  await user.type(screen.getByRole("textbox", { name: "Message" }), text);
}

describe("case queue", () => {
  test("pages with the server cursor, drops duplicate rows, and stops at the page cap", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()));
    let served = 0;
    api.on("GET", "/api/v1/cases", (call) => {
      const cursor = new URL(call.url, "http://app.test").searchParams.get("cursor");
      expect(cursor).toBe(served === 0 ? null : `c${String(served)}`);
      served += 1;
      // Each page repeats the previous page's last row, which must not be shown twice.
      const items = Array.from({ length: 25 }, (_, index) => caseView((served - 1) * 24 + index + 1, "Case"));
      return json(200, { items, next_cursor: `c${String(served)}` });
    });
    const { user } = renderApp();
    expect(await screen.findAllByRole("link", { name: /^Case, Open/ })).toHaveLength(25);
    for (let click = 0; click < 7; click += 1) {
      await user.click(await screen.findByRole("button", { name: "Load more" }));
      await screen.findByRole("button", { name: click === 6 ? "Refresh" : "Load more" });
    }
    await settle();
    expect(served).toBe(8);
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
    expect(screen.getAllByRole("link", { name: /^Case, Open/ })).toHaveLength(25 + 7 * 24);
    expect(screen.getByText(/Showing the first 193 cases/)).toBeTruthy();
  });

  test("a filter change supersedes an earlier page that answers late", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()));
    const first = api.defer("GET", "/api/v1/cases");
    api.on("GET", "/api/v1/cases", json(200, { items: [{ ...caseView(2, "Closed one"), status: "closed" }],
                                                next_cursor: null }));
    const { user } = renderApp();
    await user.click(await screen.findByRole("radio", { name: "Closed" }));
    expect(await screen.findByText("Closed one")).toBeTruthy();
    expect(new URL(api.callsTo("GET", "/api/v1/cases")[1]?.url ?? "", "http://app.test").searchParams.get("status"))
      .toBe("closed");
    first.resolve(json(200, { items: [caseView(3, "Stale open one")], next_cursor: null }));
    await settle();
    expect(screen.queryByText("Stale open one")).toBeNull();
  });

  test("New case sends one keyed request and opens the created case", async () => {
    const api = openCase();
    api.on("GET", "/api/v1/cases", json(200, { items: [], next_cursor: null }));
    const create = api.defer("POST", "/api/v1/cases");
    const { user } = renderApp();
    const button = await screen.findByRole("button", { name: "New case" });
    await user.click(button);
    await user.click(button); // a second activation while the first is in flight sends nothing
    expect(api.callsTo("POST", "/api/v1/cases")).toHaveLength(1);
    expect(create.call?.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    create.resolve(withHeaders(201, at(1), { ETag: "\"1\"" }));
    await waitFor(() => {
      expect(screen.getByTestId("location").textContent).toBe(CASE_PATH.replace("/api/v1", ""));
    });
  });

  test("an auditor sees cases but no create, composer or investigation control", async () => {
    const api = openCase(["auditor"]);
    api.on("GET", "/api/v1/cases", json(200, { items: [CASE], next_cursor: null }));
    const { user } = renderApp();
    expect(await screen.findByText(/Your role can read cases/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "New case" })).toBeNull();
    await user.click(screen.getByRole("link", { name: /Refund for damaged blender/ }));
    expect(await screen.findByText(/Your role can read this case but not add to it/)).toBeTruthy();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("button", { name: "Start investigation" })).toBeNull();
  });
});

describe("conversation and composer", () => {
  test("labels every source in plain text and posts a staff note against the shown version", async () => {
    const api = openCase(["analyst"], 2, page([message(1, "<b>Hi</b>", "operator_entered_customer"),
                                               message(2, "Internal", "staff_note")]));
    api.next("POST", MESSAGES, posted(3, 3, "Checked the order"));
    api.next("POST", MESSAGES, posted(4, 4, "Second note"));
    const { user } = renderApp(`/cases/${ID}`);
    expect(await screen.findByText("<b>Hi</b>")).toBeTruthy(); // text, never markup
    const list = screen.getByRole("list", { name: "Messages" });
    expect(within(list).getByText("Customer message · entered by staff (simulation)")).toBeTruthy();
    expect(within(list).getByText("Staff note · internal, not sent to the customer")).toBeTruthy();
    expect(screen.getByRole("radio", { name: "Simulated customer (model)" }).hasAttribute("disabled")).toBe(true);

    await writeNote(user, "Checked the order");
    const post = screen.getByRole("button", { name: "Post" });
    await user.dblClick(post);
    expect(await screen.findByText("Checked the order", { selector: ".message-text" })).toBeTruthy();
    const calls = api.callsTo("POST", MESSAGES);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.get("If-Match")).toBe("\"2\"");
    expect(calls[0]?.body).toEqual({ source: "staff_note", text: "Checked the order" });
    expect(screen.getByText("Posted as a staff note.")).toBeTruthy();

    await writeNote(user, "Second note");
    await user.click(screen.getByRole("button", { name: "Post" }));
    await screen.findByText("Second note", { selector: ".message-text" });
    const second = api.callsTo("POST", MESSAGES)[1];
    expect(second?.headers.get("If-Match")).toBe("\"3\"");
    expect(second?.headers.get("Idempotency-Key")).not.toBe(calls[0]?.headers.get("Idempotency-Key"));
  });

  test("a customer message needs explicit confirmation and is labeled as staff-entered", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, posted(2, 3, "Where is my refund?", false, "operator_entered_customer"));
    const { user } = renderApp(`/cases/${ID}`);
    await user.click(await screen.findByRole("radio", { name: "Customer message, entered by me" }));
    await user.type(screen.getByRole("textbox", { name: "Message" }), "Where is my refund?");
    await user.click(screen.getByRole("button", { name: "Post customer message…" }));
    expect(api.callsTo("POST", MESSAGES)).toHaveLength(0);
    expect(screen.getByRole("group").textContent).toContain("not customer consent");
    await user.click(screen.getByRole("button", { name: "Confirm post" }));
    expect(await screen.findByText("Where is my refund?", { selector: ".message-text" })).toBeTruthy();
    expect(api.callsTo("POST", MESSAGES)[0]?.body).toEqual({ source: "operator_entered_customer",
                                                             text: "Where is my refund?" });
  });

  test("a first-attempt stale version keeps the draft; the next send is a new request", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, json(409, { ...envelope("stale_version", "The case changed; reload it and retry."),
                                           rule_id: "api.stale_version" }));
    api.next("POST", MESSAGES, posted(2, 4, "Retry text"));
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Retry text");
    await user.click(screen.getByRole("button", { name: "Post" }));
    expect((await screen.findByRole("heading", { name: "Your message wasn't posted" }))).toBeTruthy();
    expect(screen.getByRole<HTMLTextAreaElement>("textbox", { name: "Message" }).value).toBe("Retry text");
    api.on("GET", CASE_PATH, caseReply(3)).on("GET", MESSAGES, json(200, page([])));
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByText("3");
    await user.click(screen.getByRole("button", { name: "Post" }));
    await screen.findByText("Retry text", { selector: ".message-text" });
    const [first, second] = api.callsTo("POST", MESSAGES);
    expect(second?.headers.get("Idempotency-Key")).not.toBe(first?.headers.get("Idempotency-Key"));
    expect(second?.headers.get("If-Match")).toBe("\"3\"");
  });

  test("an unknown outcome stays unknown when a retry is refused before replay, and settles on a replay", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, new TypeError("connection reset"));
    api.next("POST", MESSAGES, json(403, { ...envelope("forbidden", "Your role does not allow this action."),
                                           rule_id: "auth.role" }));
    api.next("POST", MESSAGES, posted(2, 3, "Refund approved?", true));
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Refund approved?");
    await user.click(screen.getByRole("button", { name: "Post" }));
    expect(await screen.findByRole("heading", { name: "We couldn't confirm whether your message was posted" }))
      .toBeTruthy();
    expect(screen.queryByRole("button", { name: /Dismiss/ })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Retry the same request" }));
    expect(await screen.findByText(/The retry was refused/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "We couldn't confirm whether your message was posted" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Retry the same request" }));
    expect(await screen.findByText("Refund approved?", { selector: ".message-text" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: /couldn't confirm/ })).toBeNull();
    const calls = api.callsTo("POST", MESSAGES).map(writeIdentity);
    expect(calls).toHaveLength(3);
    expect(calls[1]).toEqual(calls[0]);
    expect(calls[2]).toEqual(calls[0]);
  });

  test("a 401 on a retry reloads the session, keeps the earlier outcome unknown and drops its text", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, new TypeError("connection reset"));
    api.next("POST", MESSAGES, unauthenticated());
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Sensitive draft");
    await user.click(screen.getByRole("button", { name: "Post" }));
    await user.click(await screen.findByRole("button", { name: "Retry the same request" }));
    expect(await screen.findByText(/no longer holds its text/)).toBeTruthy();
    expect(document.body.textContent).not.toContain("Sensitive draft");
    expect(screen.getByRole("heading", { name: "We couldn't confirm whether your message was posted" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Retry the same request" })).toBeNull();
    expect(screen.getByRole("textbox", { name: "Message" }).hasAttribute("readonly")).toBe(true);
    expect(api.callsTo("GET", "/api/v1/me")).toHaveLength(2);
    expect(api.callsTo("POST", MESSAGES)).toHaveLength(2);
  });

  test("a malformed 2xx (bad replay header) is unknown, not success", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, withHeaders(201, { message: message(2, "Hello", "staff_note"), case: at(3) },
                                           { ETag: "\"3\"", "Idempotent-Replayed": "yes" }));
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Hello");
    await user.click(screen.getByRole("button", { name: "Post" }));
    expect(await screen.findByRole("heading", { name: "We couldn't confirm whether your message was posted" }))
      .toBeTruthy();
    expect(screen.queryByText("Hello", { selector: ".message-text" })).toBeNull();
  });

  test("a late write answer after the workspace changed never reaches the new view", async () => {
    const api = openCase();
    const pending = api.defer("POST", MESSAGES);
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Old workspace text");
    await user.click(screen.getByRole("button", { name: "Post" }));
    api.on("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .on("GET", "/api/v1/cases", json(200, { items: [], next_cursor: null }));
    await becomeVisible();
    expect(await screen.findByRole("heading", { name: "No cases in this workspace" })).toBeTruthy();
    const meCalls = api.callsTo("GET", "/api/v1/me").length;
    pending.resolve(posted(2, 3, "Old workspace text"));
    await settle();
    expect(document.body.textContent).not.toContain("Old workspace text");
    expect(screen.queryByRole("heading", { name: /couldn't confirm|wasn't posted/ })).toBeNull();
    expect(api.callsTo("GET", "/api/v1/me")).toHaveLength(meCalls);
  });

  test("an older snapshot from a replay or a slow read never rolls the version back", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, posted(2, 5, "First"));
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "First");
    await user.click(screen.getByRole("button", { name: "Post" }));
    await screen.findByText("First", { selector: ".message-text" });
    expect(screen.getByText("5")).toBeTruthy();
    api.on("GET", CASE_PATH, caseReply(4)).on("GET", MESSAGES, json(200, page([])));
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await settle();
    expect(screen.getByText("5")).toBeTruthy();
    expect(screen.queryByText("4")).toBeNull();
  });

  test("posting beyond a partly loaded history keeps the history cursor at the loaded prefix", async () => {
    const first = Array.from({ length: 200 }, (_, index) => message(index + 1));
    const api = openCase(["analyst"], 502, page(first, 200));
    api.next("POST", MESSAGES, posted(502, 503, "Newest note"));
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Newest note");
    await user.click(screen.getByRole("button", { name: "Post" }));
    expect(await screen.findByText("Newest note", { selector: ".message-text" })).toBeTruthy();
    expect(screen.getByText(/Some earlier messages aren't loaded yet/)).toBeTruthy();
    api.on("GET", MESSAGES, json(200, page(Array.from({ length: 200 }, (_, index) => message(index + 201)), 400)));
    await user.click(screen.getByRole("button", { name: "Load more messages" }));
    await screen.findByText("Message 400");
    const after = api.callsTo("GET", MESSAGES).map((call) =>
      new URL(call.url, "http://app.test").searchParams.get("after_sequence"));
    expect(after).toEqual(["0", "200"]);
    expect(within(screen.getByRole("list", { name: "Messages" })).getAllByRole("listitem")).toHaveLength(400);
    expect(within(screen.getByRole("list", { name: "Your latest posts" })).getAllByRole("listitem")).toHaveLength(1);
  });
});

describe("investigation control", () => {
  test("the real unconfigured-runtime refusal says nothing started and shows no activity", async () => {
    const api = openCase();
    api.on("POST", RUNS, json(503, { ...envelope("unavailable", "No run runtime is configured on this server."),
                                     rule_id: "runtime.unconfigured" }));
    const { user } = renderApp(`/cases/${ID}`);
    await user.click(await screen.findByRole("button", { name: "Start investigation" }));
    expect(await screen.findByRole("heading", { name: "Investigations aren't available on this server" }))
      .toBeTruthy();
    expect(screen.queryByText(/Starting an investigation/)).toBeNull();
    expect(screen.queryByRole("button", { name: /Cancel/ })).toBeNull();
    expect(api.callsTo("POST", RUNS)).toHaveLength(1);
    expect(api.callsTo("POST", RUNS)[0]?.body).toEqual({ mode: "workbench" });
    expect(api.callsTo("POST", RUNS)[0]?.headers.get("If-Match")).toBe("\"2\"");
  });

  test("a generic 503 without the runtime rule stays unconfirmed", async () => {
    const api = openCase();
    api.on("POST", RUNS, new Response("Bad gateway", { status: 503 }));
    const { user } = renderApp(`/cases/${ID}`);
    await user.click(await screen.findByRole("button", { name: "Start investigation" }));
    expect(await screen.findByRole("heading", { name: "We couldn't confirm whether the investigation was started" }))
      .toBeTruthy();
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(api.callsTo("POST", RUNS)).toHaveLength(1); // never retried automatically
  });
});

function runAccepted(version: number, replayed: boolean): Response {
  return withHeaders(202, {
    run_id: "e0000000-0000-4000-8000-000000000001", case_id: ID, case_version: 2, version, mode: "workbench",
    state: "queued", initiated_by: "11111111-1111-4111-8111-111111111111", event_highwater: 0,
    config_sha256: "a".repeat(64), graph_sha256: "b".repeat(64), prompt_sha256: "c".repeat(64),
    created_at: "2026-11-11T12:00:00Z", updated_at: "2026-11-11T12:00:00Z", deadline_at: "2026-11-11T12:30:00Z",
  }, { ETag: `"${String(version)}"`, ...(replayed ? { "Idempotent-Replayed": "true" } : {}) });
}

describe("a temporary refusal after an unknown start", () => {
  // A refused attempt stores no record for its key, so these conditions can change before the earlier attempt
  // arrives: another run may finish, another worker may have a runtime. They must not settle the earlier start.
  const refusals = [
    [409, "conflict", "api.run_active", "Another investigation is active for this case."],
    [503, "unavailable", "runtime.unconfigured", "No run runtime is configured on this server."],
  ] as const;
  for (const [status, code, rule, detail] of refusals) {
    test(`${rule} keeps it unknown with the same request, and a later replay settles it`, async () => {
      const api = openCase();
      api.next("POST", RUNS, new TypeError("connection reset"));
      api.next("POST", RUNS, json(status, { ...envelope(code, detail), rule_id: rule }));
      api.next("POST", RUNS, runAccepted(1, true));
      const { user } = renderApp(`/cases/${ID}`);
      await user.click(await screen.findByRole("button", { name: "Start investigation" }));
      const unknown = { name: "We couldn't confirm whether the investigation was started" };
      expect(await screen.findByRole("heading", unknown)).toBeTruthy();
      await user.click(screen.getByRole("button", { name: "Retry the same request" }));
      expect(await screen.findByText(/The retry was refused/)).toBeTruthy();
      expect(screen.getByRole("heading", unknown)).toBeTruthy();
      expect(screen.queryByRole("heading", { name: "Investigations aren't available on this server" })).toBeNull();
      expect(screen.getByRole("button", { name: "Start investigation" }).hasAttribute("disabled")).toBe(true);
      await user.click(screen.getByRole("button", { name: "Retry the same request" }));
      expect(await screen.findByText(/The investigation had already been requested/)).toBeTruthy();
      expect(screen.queryByRole("heading", unknown)).toBeNull();
      const calls = api.callsTo("POST", RUNS).map(writeIdentity);
      expect(calls).toHaveLength(3);
      expect(calls[1]).toEqual(calls[0]);
      expect(calls[2]).toEqual(calls[0]);
    });
  }

  test("a first-attempt run_active refusal settles only that attempt", async () => {
    const api = openCase();
    api.next("POST", RUNS, json(409, { ...envelope("conflict", "Another investigation is active for this case."),
                                       rule_id: "api.run_active" }));
    const { user } = renderApp(`/cases/${ID}`);
    await user.click(await screen.findByRole("button", { name: "Start investigation" }));
    await waitFor(() => {
      expect(api.callsTo("POST", RUNS)).toHaveLength(1);
      expect(screen.getByRole("button", { name: "Start investigation" }).hasAttribute("disabled")).toBe(false);
    });
    expect(screen.queryByRole("heading", { name: /couldn't confirm/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry the same request" })).toBeNull();
  });
});

describe("keyboard, focus and sign-out", () => {
  test("Escape leaves the customer-message confirmation and returns focus to the message field", async () => {
    const api = openCase();
    const { user } = renderApp(`/cases/${ID}`);
    await user.click(await screen.findByRole("radio", { name: "Customer message, entered by me" }));
    await user.type(screen.getByRole("textbox", { name: "Message" }), "Where is my refund?");
    await user.click(screen.getByRole("button", { name: "Post customer message…" }));
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Confirm post" }));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("button", { name: "Confirm post" })).toBeNull();
    const field = screen.getByRole("textbox", { name: "Message" });
    expect(document.activeElement).toBe(field);
    await user.type(field, " Thanks");
    expect((field as HTMLTextAreaElement).value).toBe("Where is my refund? Thanks");
    await user.click(screen.getByRole("button", { name: "Post customer message…" }));
    await user.click(screen.getByRole("button", { name: "Back to editing" }));
    expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "Message" }));
    expect(api.callsTo("POST", MESSAGES)).toHaveLength(0);
  });

  test("a successful post clears the draft and returns focus to the message field", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, posted(2, 3, "Checked the order"));
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Checked the order");
    await user.click(screen.getByRole("button", { name: "Post" }));
    await screen.findByText("Checked the order", { selector: ".message-text" });
    const field = screen.getByRole("textbox", { name: "Message" });
    await waitFor(() => {
      expect(document.activeElement).toBe(field);
    });
    expect((field as HTMLTextAreaElement).value).toBe("");
    expect(api.callsTo("POST", MESSAGES)).toHaveLength(1);
  });

  async function signOutFromMenu(user: ReturnType<typeof renderApp>["user"]): Promise<void> {
    await user.click(screen.getByRole("button", { name: "Account" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }));
  }

  test("with an unresolved write, sign-out warns first; keep working and Escape send nothing", async () => {
    const api = openCase();
    api.next("POST", MESSAGES, new TypeError("connection reset"));
    api.on("POST", "/api/v1/auth/logout", new Response(null, { status: 204 }));
    const { user } = renderApp(`/cases/${ID}`);
    await writeNote(user, "Refund approved?");
    await user.click(screen.getByRole("button", { name: "Post" }));
    await screen.findByRole("heading", { name: "We couldn't confirm whether your message was posted" });

    await signOutFromMenu(user);
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.textContent).toContain("doesn't cancel it");
    expect(dialog.textContent).toContain("message text kept here for retrying it will be lost");
    expect(dialog.textContent).not.toMatch(/[0-9]/); // names no count or request
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: "Keep working" }));
    await user.click(within(dialog).getByRole("button", { name: "Keep working" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(api.callsTo("POST", "/api/v1/auth/logout")).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Retry the same request" })).toBeTruthy();

    await signOutFromMenu(user);
    await screen.findByRole("alertdialog");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(api.callsTo("POST", "/api/v1/auth/logout")).toHaveLength(0);

    await signOutFromMenu(user);
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Sign out anyway" }));
    await waitFor(() => {
      expect(api.callsTo("POST", "/api/v1/auth/logout")).toHaveLength(1);
    });
  });

  test("with nothing unresolved, sign-out is immediate", async () => {
    const api = openCase();
    api.on("POST", "/api/v1/auth/logout", new Response(null, { status: 204 }));
    const { user } = renderApp(`/cases/${ID}`);
    await screen.findByText("Message 1");
    await signOutFromMenu(user);
    await waitFor(() => {
      expect(api.callsTo("POST", "/api/v1/auth/logout")).toHaveLength(1);
    });
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });
});
