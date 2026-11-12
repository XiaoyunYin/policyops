import { screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, test } from "vitest";

import type { Role } from "./api/client";
import { FakeApi, WORKSPACE_B, caseView, casePage, envelope, json, me, members, noContent, setCsrfCookie,
         unauthenticated } from "./test/fakeApi";
import { renderApp, settle } from "./test/renderApp";

afterEach(() => {
  setCsrfCookie(null);
});

function signedIn(roles: Role[] = ["analyst"]): FakeApi {
  return new FakeApi().on("GET", "/api/v1/me", json(200, me({ roles })))
    .on("GET", "/api/v1/cases", json(200, casePage(caseView(1, "Refund for damaged blender"))));
}

describe("session bootstrap", () => {
  test("shows a loading status until /me answers, then the sign-in page for no session", async () => {
    const api = new FakeApi();
    const answer = api.defer("GET", "/api/v1/me");
    renderApp("/members");
    expect(screen.getByRole("status").textContent).toContain("Loading PolicyOps");
    expect(screen.queryByRole("link", { name: "Sign in" })).toBeNull();

    answer.resolve(unauthenticated());
    const link = await screen.findByRole("link", { name: "Sign in" });
    expect(link.getAttribute("href")).toBe("/api/v1/auth/login?return_to=%2Fmembers");
    expect(document.title).toBe("Sign in · PolicyOps");
  });

  test("under StrictMode's effect replay the session still boots and loads once visible", async () => {
    const api = signedIn();
    renderApp("/cases", { strict: true });
    expect(await screen.findByText("Refund for damaged blender")).toBeTruthy();
    // The replayed effects abort the first bootstrap; only current-generation results are applied.
    expect(api.callsTo("GET", "/api/v1/me").filter((call) => call.signal?.aborted === false)).toHaveLength(1);
  });

  test("an unsafe current path signs in to the case list instead", async () => {
    new FakeApi().on("GET", "/api/v1/me", unauthenticated());
    renderApp("/api/v1/auth/logout");
    const link = await screen.findByRole("link", { name: "Sign in" });
    expect(link.getAttribute("href")).toBe("/api/v1/auth/login?return_to=%2Fcases");
  });

  test("a failed bootstrap offers a retry that loads the session", async () => {
    new FakeApi().next("GET", "/api/v1/me", new TypeError("offline"))
      .on("GET", "/api/v1/me", json(200, me())).on("GET", "/api/v1/cases", json(200, casePage()));
    const { user } = renderApp();
    expect(await screen.findByRole("heading", { name: "Can't reach PolicyOps" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Reload session" }));
    expect(await screen.findByRole("heading", { name: "No cases in this workspace" })).toBeTruthy();
  });

  test("a principal without memberships is told so and can sign out", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, me({ workspace: null, workspaces: [] })))
      .on("POST", "/api/v1/auth/logout", noContent());
    const { user } = renderApp();
    expect(await screen.findByRole("heading", { name: "No workspace access" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("heading", { name: "You've signed out" })).toBeTruthy();
  });

  test("without a selected workspace the user chooses one; the shell appears after the server confirms", async () => {
    setCsrfCookie("token-1");
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me({ workspace: null })))
      .on("POST", "/api/v1/auth/workspace", noContent())
      .on("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .on("GET", "/api/v1/cases", json(200, casePage(caseView(2, "Exchange wrong size"))));
    const { user } = renderApp();
    await screen.findByRole("heading", { name: "Choose a workspace" });
    await user.click(screen.getByRole("button", { name: /South support/ }));

    expect(await screen.findByText("Exchange wrong size")).toBeTruthy();
    const [select] = api.callsTo("POST", "/api/v1/auth/workspace");
    expect(select?.body).toEqual({ workspace_id: WORKSPACE_B.workspace_id });
    expect(select?.headers.get("X-CSRF-Token")).toBe("token-1");
    expect(api.callsTo("GET", "/api/v1/me")).toHaveLength(2);
  });
});

describe("case list states", () => {
  test("loading, then rows rendered as text", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()));
    const cases = api.defer("GET", "/api/v1/cases");
    renderApp();
    expect(await screen.findByRole("heading", { name: "Cases", level: 1 })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("Loading cases");

    cases.resolve(json(200, casePage(caseView(1, "<img src=x onerror=alert(1)> refund"))));
    const cell = await screen.findByText("<img src=x onerror=alert(1)> refund");
    expect(cell.querySelector("img")).toBeNull();
    expect(screen.getByRole("table", { name: "Cases" })).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  test("an empty workspace explains itself and offers only the queue's real actions", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, me())).on("GET", "/api/v1/cases", json(200, casePage()));
    renderApp();
    expect(await screen.findByRole("heading", { name: "No cases in this workspace" })).toBeTruthy();
    expect(within(screen.getByRole("main")).getAllByRole("button").map((button) => button.textContent))
      .toEqual(["Refresh", "New case"]);
  });

  test("a retryable failure can be retried; the reference is shown", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .next("GET", "/api/v1/cases", json(503, envelope("unavailable", "Database unavailable.", true)))
      .on("GET", "/api/v1/cases", json(200, casePage(caseView(3, "Address change"))));
    const { user } = renderApp();
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading").textContent).toBe("Service unavailable");
    expect(alert.textContent).toContain("5f0c2d1e-7a3b-4c8d-9e6f-0123456789ab");
    await user.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Address change")).toBeTruthy();
  });

  test("a server refusal is shown with its detail and no retry", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .on("GET", "/api/v1/cases", json(403, envelope("forbidden", "Your membership was revoked.")));
    renderApp();
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading").textContent).toBe("You don't have access");
    expect(alert.textContent).toContain("Your membership was revoked.");
    expect(within(alert).queryByRole("button")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
  });

  test("an internal error never shows server text", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .on("GET", "/api/v1/cases", json(500, envelope("internal", "Traceback: secret internals")));
    renderApp();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Something went wrong");
    expect(alert.textContent).not.toContain("Traceback");
  });
});

describe("role union presentation", () => {
  const matrix: [Role[], string[], boolean][] = [
    [["analyst"], ["Cases"], false],
    [["reviewer"], ["Cases", "Approvals"], false],
    [["admin"], ["Cases", "Members"], false],
    [["reviewer", "admin"], ["Cases", "Approvals", "Members"], false],
    [["auditor"], ["Cases"], true],
  ];
  test.each(matrix)("%j sees %j", async (roles, entries, readOnly) => {
    signedIn(roles);
    renderApp();
    const nav = await screen.findByRole("navigation", { name: "Primary" });
    expect(within(nav).getAllByRole("link").map((link) => link.textContent)).toEqual(entries);
    expect(screen.queryByText("Read-only") !== null).toBe(readOnly);
  });

  test("admin alone is refused the decision area, even by direct URL, without asking the server", async () => {
    const api = signedIn(["admin"]);
    renderApp("/approvals");
    expect(await screen.findByRole("heading", { name: "You don't have access" })).toBeTruthy();
    expect(api.calls.map((call) => call.path)).toEqual(["/api/v1/me"]);
  });

  test("a reviewer reaches the approval inbox", async () => {
    signedIn(["reviewer"]).on("GET", "/api/v1/approvals", json(200, { items: [], next_cursor: null }));
    renderApp("/approvals");
    expect(await screen.findByRole("heading", { name: "No approvals waiting" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Refresh inbox" })).toBeTruthy();
  });

  test("an analyst is refused the member list", async () => {
    signedIn(["analyst"]);
    renderApp("/members");
    expect(await screen.findByRole("heading", { name: "You don't have access" })).toBeTruthy();
  });

  test("admin + reviewer sees members; a server 403 there is shown as a refusal", async () => {
    signedIn(["reviewer", "admin"]).next("GET", "/api/v1/workspace/members",
      json(403, envelope("forbidden", "Your role does not allow this.")))
      .on("GET", "/api/v1/workspace/members", json(200, members(
        { membership_id: "a1a1a1a1-0000-4000-8000-000000000001", principal_id: "p-1", role: "auditor", active: true })));
    renderApp("/members");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Your role does not allow this.");
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("keyboard and focus", () => {
  test("the skip link is the first stop and moves focus to the main content", async () => {
    signedIn();
    const { user } = renderApp();
    await screen.findByText("Refund for damaged blender");
    (document.activeElement as HTMLElement | null)?.blur();
    await user.tab();
    expect(document.activeElement?.textContent).toBe("Skip to main content");
    await user.keyboard("{Enter}");
    expect(document.activeElement).toBe(screen.getByRole("main"));
  });

  test("navigation moves focus to the new page heading and updates the title", async () => {
    signedIn(["admin"]).on("GET", "/api/v1/workspace/members", json(200, []));
    const { user } = renderApp();
    await screen.findByText("Refund for damaged blender");
    await user.click(screen.getByRole("link", { name: "Members" }));
    const heading = await screen.findByRole("heading", { name: "Members", level: 1 });
    expect(document.activeElement).toBe(heading);
    expect(document.title).toBe("Members · PolicyOps");
    expect(screen.getByTestId("location").textContent).toBe("/members");
  });

  test("the workspace switcher works from the keyboard", async () => {
    setCsrfCookie("token-1");
    const api = signedIn().on("POST", "/api/v1/auth/workspace", noContent());
    const { user } = renderApp();
    await screen.findByText("Refund for damaged blender");
    api.on("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .on("GET", "/api/v1/cases", json(200, casePage(caseView(9, "South case"))));

    screen.getByRole("button", { name: /Workspace/ }).focus();
    await user.keyboard("{ArrowDown}");
    const listbox = await screen.findByRole("listbox");
    expect(within(listbox).getAllByRole("option").map((option) => option.textContent))
      .toEqual(["North support", "South support"]);
    await user.keyboard("{ArrowDown}{Enter}");

    expect(await screen.findByText("South case")).toBeTruthy();
    expect(api.callsTo("POST", "/api/v1/auth/workspace")[0]?.body).toEqual({ workspace_id: WORKSPACE_B.workspace_id });
  });

  test("the account menu signs out from the keyboard", async () => {
    setCsrfCookie("token-1");
    const api = signedIn().on("POST", "/api/v1/auth/logout", noContent());
    const { user } = renderApp();
    await screen.findByText("Refund for damaged blender");
    screen.getByRole("button", { name: "Account" }).focus();
    await user.keyboard("{Enter}");
    const item = await screen.findByRole("menuitem", { name: "Sign out" });
    await waitFor(() => {
      expect(document.activeElement).toBe(item);
    });
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { name: "You've signed out" })).toBeTruthy();
    expect(api.callsTo("POST", "/api/v1/auth/logout")[0]?.headers.get("X-CSRF-Token")).toBe("token-1");
    expect(screen.getByRole("link", { name: "Sign in" }).getAttribute("href"))
      .toBe("/api/v1/auth/login?return_to=%2Fcases");
  });

  test("an expired session shows a dialog that keeps focus and cannot be dismissed", async () => {
    new FakeApi().on("GET", "/api/v1/me", json(200, me())).on("GET", "/api/v1/cases", unauthenticated());
    const { user } = renderApp("/cases");
    const dialog = await screen.findByRole("alertdialog", { name: "Your session ended" });
    const link = within(dialog).getByRole("link", { name: "Sign in again" });
    expect(link.getAttribute("href")).toBe("/api/v1/auth/login?return_to=%2Fcases");
    await waitFor(() => {
      expect(dialog.contains(document.activeElement)).toBe(true);
    });
    await user.keyboard("{Escape}");
    await user.tab();
    await user.tab();
    expect(screen.getByRole("alertdialog")).toBe(dialog);
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(screen.queryByRole("navigation")).toBeNull();
  });
});

test("an unknown address inside the workspace is a plain not-found page", async () => {
  signedIn();
  renderApp("/nowhere");
  expect(await screen.findByRole("heading", { name: "Page not found" })).toBeTruthy();
  await settle();
});
