// Late results across context changes, through the composed app. Deferred replies ignore their abort signal; the
// client still settles an aborted request at once and the shell remounts per generation, so these tests cover the
// composed behavior. resource.test.tsx covers the generation guard alone.

import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { FakeApi, WORKSPACE_A, WORKSPACE_B, caseView, casePage, envelope, json, me, noContent, setCsrfCookie,
         unauthenticated } from "../test/fakeApi";
import { becomeVisible, renderApp, settle } from "../test/renderApp";
import { SessionController } from "./controller";

afterEach(() => {
  setCsrfCookie(null);
  vi.useRealTimers();
});

const NORTH_CASE = casePage(caseView(1, "North refund"));
const SOUTH_CASE = casePage(caseView(2, "South exchange"));

async function chooseSouth(user: ReturnType<typeof renderApp>["user"]): Promise<void> {
  await user.click(screen.getByRole("button", { name: /Workspace/ }));
  await user.click(await screen.findByRole("option", { name: "South support" }));
}

describe("workspace switch", () => {
  test("removes old content at once, sends a live POST and never shows the old workspace's late reply", async () => {
    setCsrfCookie("token-1");
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()));
    const northCases = api.defer("GET", "/api/v1/cases");
    const { user } = renderApp();
    await screen.findByRole("heading", { name: "Cases", level: 1 });
    await waitFor(() => {
      expect(northCases.call).not.toBeNull();
    });
    const select = api.defer("POST", "/api/v1/auth/workspace");

    await chooseSouth(user);
    expect(screen.getByRole("status").textContent).toContain("Switching to South support");
    expect(screen.queryByRole("navigation")).toBeNull();
    expect(screen.queryByRole("heading", { name: "Cases" })).toBeNull();
    // The old request was aborted; the switch POST went out on a fresh, live signal.
    expect(northCases.call?.signal?.aborted).toBe(true);
    await waitFor(() => {
      expect(select.call).not.toBeNull();
    });
    expect(select.call?.signal?.aborted).toBe(false);

    api.on("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .on("GET", "/api/v1/cases", json(200, SOUTH_CASE));
    select.resolve(noContent());
    expect(await screen.findByText("South exchange")).toBeTruthy();

    northCases.resolve(json(200, NORTH_CASE));
    await settle();
    expect(screen.queryByText("North refund")).toBeNull();
    expect(screen.getByText("South exchange")).toBeTruthy();
    expect(screen.getByTestId("location").textContent).toBe("/cases");
  });

  test("a late 401 from the old workspace does not end the new session", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()));
    const northCases = api.defer("GET", "/api/v1/cases");
    api.on("POST", "/api/v1/auth/workspace", noContent());
    const { user } = renderApp();
    await waitFor(() => {
      expect(northCases.call).not.toBeNull();
    });
    api.on("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .on("GET", "/api/v1/cases", json(200, SOUTH_CASE));
    await chooseSouth(user);
    await screen.findByText("South exchange");

    northCases.resolve(unauthenticated());
    await settle();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getByText("South exchange")).toBeTruthy();
  });

  test("a lost switch response reloads /me first; if the switch applied, the new workspace is shown", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()))
      .on("GET", "/api/v1/cases", json(200, NORTH_CASE));
    const { user } = renderApp();
    await screen.findByText("North refund");
    api.next("POST", "/api/v1/auth/workspace", new TypeError("connection reset"))
      .on("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .on("GET", "/api/v1/cases", json(200, SOUTH_CASE));
    await chooseSouth(user);

    expect(await screen.findByText("South exchange")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(api.callsTo("GET", "/api/v1/me")).toHaveLength(2);
  });

  test("a lost switch response with the old workspace still selected reloads it fresh and says so", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .on("GET", "/api/v1/cases", json(200, NORTH_CASE));
    const { user } = renderApp();
    await screen.findByText("North refund");
    api.next("POST", "/api/v1/auth/workspace", new TypeError("connection reset"));
    await chooseSouth(user);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Couldn't switch to South support");
    expect(await screen.findByText("North refund")).toBeTruthy();
    expect(api.callsTo("GET", "/api/v1/me")).toHaveLength(2);
    expect(api.callsTo("GET", "/api/v1/cases")).toHaveLength(2);
  });

  test("a refused switch is reconciled through /me as well", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .on("GET", "/api/v1/cases", json(200, NORTH_CASE));
    const { user } = renderApp();
    await screen.findByText("North refund");
    api.next("POST", "/api/v1/auth/workspace", json(404, envelope("not_found", "Not found.")));
    await chooseSouth(user);
    expect((await screen.findByRole("alert")).textContent).toContain("Couldn't switch to South support");
    expect(api.callsTo("GET", "/api/v1/me")).toHaveLength(2);
  });

  test("a 401 on the switch ends the session", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .on("GET", "/api/v1/cases", json(200, NORTH_CASE));
    const { user } = renderApp();
    await screen.findByText("North refund");
    api.next("POST", "/api/v1/auth/workspace", unauthenticated());
    await chooseSouth(user);
    expect(await screen.findByRole("alertdialog", { name: "Your session ended" })).toBeTruthy();
  });
});

describe("sign-out", () => {
  test("clears content before the POST, which gets a live signal; late replies stay discarded", async () => {
    setCsrfCookie("token-1");
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()));
    const cases = api.defer("GET", "/api/v1/cases");
    const signOut = api.defer("POST", "/api/v1/auth/logout");
    const { user } = renderApp();
    await waitFor(() => {
      expect(cases.call).not.toBeNull();
    });
    await user.click(screen.getByRole("button", { name: "Account" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }));

    expect(screen.getByRole("status").textContent).toContain("Signing out");
    expect(cases.call?.signal?.aborted).toBe(true);
    await waitFor(() => {
      expect(signOut.call).not.toBeNull();
    });
    expect(signOut.call?.signal?.aborted).toBe(false);
    expect(signOut.call?.headers.get("X-CSRF-Token")).toBe("token-1");

    signOut.resolve(noContent());
    await screen.findByRole("heading", { name: "You've signed out" });
    cases.resolve(json(200, NORTH_CASE));
    await settle();
    expect(screen.queryByText("North refund")).toBeNull();
    expect(screen.getByRole("heading", { name: "You've signed out" })).toBeTruthy();
  });

  test("a late 401 after sign-out does not show the expiry dialog", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .on("POST", "/api/v1/auth/logout", noContent());
    const cases = api.defer("GET", "/api/v1/cases");
    const { user } = renderApp();
    await waitFor(() => {
      expect(cases.call).not.toBeNull();
    });
    await user.click(screen.getByRole("button", { name: "Account" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }));
    await screen.findByRole("heading", { name: "You've signed out" });
    cases.resolve(unauthenticated());
    await settle();
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  test("a lost sign-out response is reported as unconfirmed; a retry answered 401 confirms it", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .on("GET", "/api/v1/cases", json(200, NORTH_CASE))
      .next("POST", "/api/v1/auth/logout", new TypeError("connection reset"))
      .next("POST", "/api/v1/auth/logout", json(500, envelope("internal", "Something went wrong.")))
      .next("POST", "/api/v1/auth/logout", unauthenticated());
    const { user } = renderApp();
    await screen.findByText("North refund");
    await user.click(screen.getByRole("button", { name: "Account" }));
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }));

    const heading = await screen.findByRole("heading", { name: "Sign-out not confirmed" });
    const page = heading.closest("main");
    expect(page?.textContent).toContain("may still be active");
    expect(page?.textContent).not.toMatch(/you're still signed in|you have signed out/i);
    expect(screen.queryByText("North refund")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Try signing out again" }));
    expect(await screen.findByRole("heading", { name: "Sign-out not confirmed" })).toBeTruthy();
    await waitFor(() => {
      expect(api.callsTo("POST", "/api/v1/auth/logout")).toHaveLength(2);
    });
    await user.click(screen.getByRole("button", { name: "Try signing out again" }));
    expect(await screen.findByRole("heading", { name: "You've signed out" })).toBeTruthy();
    expect(api.callsTo("POST", "/api/v1/auth/logout")).toHaveLength(3);
  });
});

describe("expiry", () => {
  test("a 401 elsewhere ends the session; the pending request's late success stays hidden", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()));
    const cases = api.defer("GET", "/api/v1/cases");
    renderApp();
    await waitFor(() => {
      expect(cases.call).not.toBeNull();
    });
    api.next("GET", "/api/v1/me", unauthenticated());
    await becomeVisible(); // background /me check answered 401
    const dialog = await screen.findByRole("alertdialog", { name: "Your session ended" });
    expect(cases.call?.signal?.aborted).toBe(true);

    cases.resolve(json(200, NORTH_CASE));
    await settle();
    expect(screen.queryByText("North refund")).toBeNull();
    expect(screen.getByRole("alertdialog")).toBe(dialog);
  });

  test("after signing in again elsewhere, an old 401 does not end the renewed session", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()));
    const oldCases = api.defer("GET", "/api/v1/cases");
    renderApp();
    await waitFor(() => {
      expect(oldCases.call).not.toBeNull();
    });
    api.next("GET", "/api/v1/me", unauthenticated());
    await becomeVisible();
    await screen.findByRole("alertdialog");

    api.next("GET", "/api/v1/me", json(200, me())).on("GET", "/api/v1/cases", json(200, NORTH_CASE));
    await becomeVisible(); // signed in again in another tab
    expect(await screen.findByText("North refund")).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeNull();

    oldCases.resolve(unauthenticated());
    await settle();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getByText("North refund")).toBeTruthy();
  });

  test("a workspace changed in another tab replaces the shown workspace", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()))
      .next("GET", "/api/v1/cases", json(200, NORTH_CASE));
    renderApp();
    await screen.findByText("North refund");
    api.next("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .next("GET", "/api/v1/cases", json(200, SOUTH_CASE));
    await becomeVisible();
    expect(await screen.findByText("South exchange")).toBeTruthy();
    expect(screen.queryByText("North refund")).toBeNull();
    expect(screen.getByRole("button", { name: /Workspace/ }).textContent).toContain("South support");
  });
});

describe("controller timeouts", () => {
  test("a switch with no answer is uncertain: /me decides before any workspace is shown", async () => {
    vi.useFakeTimers();
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()));
    const controller = new SessionController({ timeoutMs: 1000 });
    controller.boot();
    await vi.advanceTimersByTimeAsync(0);
    expect(controller.getState().status).toBe("ready");

    api.defer("POST", "/api/v1/auth/workspace"); // never answered
    api.next("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })));
    controller.switchWorkspace(WORKSPACE_B.workspace_id);
    expect(controller.getState().status).toBe("switching");
    await vi.advanceTimersByTimeAsync(1000);

    const state = controller.getState();
    expect(state.status === "ready" && state.me.workspace_id).toBe(WORKSPACE_B.workspace_id);
    expect(state.status === "ready" && state.notice).toBeNull();
    expect(api.calls.map((call) => `${call.method} ${call.path}`))
      .toEqual(["GET /api/v1/me", "POST /api/v1/auth/workspace", "GET /api/v1/me"]);
    controller.dispose();
  });

  test("a stale scope cannot report expiry", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_A })));
    const controller = new SessionController();
    controller.boot();
    const first = controller.scope();
    await vi.waitFor(() => {
      expect(controller.getState().status).toBe("ready");
    });
    controller.boot();
    await vi.waitFor(() => {
      expect(controller.getState().status).toBe("ready");
    });
    controller.reportUnauthenticated(first);
    expect(controller.getState().status).toBe("ready");
    controller.reportUnauthenticated(controller.scope());
    expect(controller.getState().status).toBe("expired");
    controller.dispose();
  });
});
