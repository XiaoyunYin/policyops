// Expected-context reconciliation through the composed app. The fake API stands in for the server's 409
// context_changed and 401 refusals; it does not prove the server binding (see the PostgreSQL integration tests).
// Every test counts the automatic requests, so a reconciliation that loops would fail here rather than hang.

import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, test, vi } from "vitest";

import { EXPECTED_PRINCIPAL_HEADER, EXPECTED_WORKSPACE_HEADER, listCases, listMembers } from "../api/client";
import { FakeApi, OTHER_PRINCIPAL, PRINCIPAL, WORKSPACE_A, WORKSPACE_B, caseView, casePage, contextChanged, envelope,
         json, me, unauthenticated } from "../test/fakeApi";
import { becomeVisible, renderApp, settle } from "../test/renderApp";
import { SessionController, type Scope } from "./controller";
import { SessionProvider, useSessionResource, useSessionState } from "./SessionProvider";

const NORTH_CASE = casePage(caseView(1, "North refund"));
const SOUTH_CASE = casePage(caseView(2, "South exchange"));
const NOTICE = "Your session changed in another window";

function counts(api: FakeApi): { me: number; cases: number } {
  return { me: api.callsTo("GET", "/api/v1/me").length, cases: api.callsTo("GET", "/api/v1/cases").length };
}

function sentContext(api: FakeApi, path: string): (string | null)[][] {
  return api.callsTo("GET", path).map((call) => [call.headers.get(EXPECTED_PRINCIPAL_HEADER),
                                                 call.headers.get(EXPECTED_WORKSPACE_HEADER)]);
}

/** Let reconciliation and any (unwanted) further rounds run, then return the counts. */
async function quiet(api: FakeApi): Promise<{ me: number; cases: number }> {
  for (let round = 0; round < 5; round += 1) {
    await settle();
  }
  return counts(api);
}

afterEach(async () => {
  await settle();
});

describe("context_changed", () => {
  test("clears the old view, reloads /me once, resets the route and shows a generic notice", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me({ roles: ["admin"] })));
    const oldMembers = api.defer("GET", "/api/v1/workspace/members");
    renderApp("/members");
    await waitFor(() => {
      expect(oldMembers.call).not.toBeNull();
    });
    expect(oldMembers.call?.headers.get(EXPECTED_WORKSPACE_HEADER)).toBe(WORKSPACE_A.workspace_id);

    const reload = api.defer("GET", "/api/v1/me");
    oldMembers.resolve(contextChanged());
    expect(await screen.findByText("Your session changed. Reloading…")).toBeTruthy();
    expect(screen.queryByRole("navigation")).toBeNull(); // the old workspace's shell is gone at once
    expect(screen.getByTestId("location").textContent).toBe("/cases");

    api.on("GET", "/api/v1/cases", json(200, SOUTH_CASE));
    reload.resolve(json(200, me({ workspace: WORKSPACE_B, roles: ["admin"] })));
    expect(await screen.findByText("South exchange")).toBeTruthy();
    expect(screen.getByRole("status", { name: "" }).textContent).toContain(NOTICE);
    expect(screen.getByRole("button", { name: /Workspace/ }).textContent).toContain("South support");
    expect(await quiet(api)).toEqual({ me: 2, cases: 1 });
    expect(api.callsTo("GET", "/api/v1/workspace/members")).toHaveLength(1); // the refused read is not retried
    expect(sentContext(api, "/api/v1/cases")).toEqual([[PRINCIPAL, WORKSPACE_B.workspace_id]]);
  });

  test("a different principal in the same workspace is reconciled the same way, with the same copy", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me())).next("GET", "/api/v1/cases", contextChanged());
    api.next("GET", "/api/v1/me", json(200, me({ principal: OTHER_PRINCIPAL })))
      .next("GET", "/api/v1/cases", json(200, NORTH_CASE));
    renderApp();
    expect(await screen.findByText("North refund")).toBeTruthy();
    expect(screen.getByText(NOTICE)).toBeTruthy();
    expect(sentContext(api, "/api/v1/cases")).toEqual([[PRINCIPAL, WORKSPACE_A.workspace_id],
                                                       [OTHER_PRINCIPAL, WORKSPACE_A.workspace_id]]);
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 });
  });

  test("a late refusal from an earlier generation is ignored", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()));
    const oldCases = api.defer("GET", "/api/v1/cases");
    renderApp();
    await waitFor(() => {
      expect(oldCases.call).not.toBeNull();
    });
    api.next("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .next("GET", "/api/v1/cases", json(200, SOUTH_CASE));
    await becomeVisible(); // this tab noticed the change itself
    expect(await screen.findByText("South exchange")).toBeTruthy();

    oldCases.resolve(contextChanged());
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 });
    expect(screen.getByText("South exchange")).toBeTruthy();
    expect(screen.queryByText("Your session changed. Reloading…")).toBeNull();
  });

  test("a reconciled view refused again stops with the refusal and an explicit reload that replays nothing",
       async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me())).on("GET", "/api/v1/cases", contextChanged());
    const { user } = renderApp();
    expect(await screen.findByRole("heading", { name: "PolicyOps couldn't load your session" })).toBeTruthy();
    expect(screen.getByText(/so this request was not applied/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull(); // the refused request is not offered
    expect(screen.queryByRole("navigation")).toBeNull(); // no earlier workspace content
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 }); // finite: one reconciliation, then a stable state

    // The operator reloads the session: /me under a new generation, again bounded to one automatic recovery.
    await user.click(screen.getByRole("button", { name: "Reload session" }));
    expect(await screen.findByRole("heading", { name: "PolicyOps couldn't load your session" })).toBeTruthy();
    expect(await quiet(api)).toEqual({ me: 4, cases: 4 });
    expect(api.calls.every((call) => call.method === "GET")).toBe(true);

    // Once the server accepts the context again, the same action restores the view.
    api.on("GET", "/api/v1/cases", json(200, NORTH_CASE));
    await user.click(screen.getByRole("button", { name: "Reload session" }));
    expect(await screen.findByText("North refund")).toBeTruthy();
    expect(screen.queryByText(NOTICE)).toBeNull();
    expect(await quiet(api)).toEqual({ me: 5, cases: 5 });
  });

  test("an ordinary conflict stays with the resource and reconciles nothing", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()))
      .next("GET", "/api/v1/cases", json(409, envelope("stale_version", "The case changed; reload it.")));
    renderApp();
    expect(await screen.findByText("The case changed; reload it.")).toBeTruthy();
    expect(await quiet(api)).toEqual({ me: 1, cases: 1 });
    expect(screen.queryByText(NOTICE)).toBeNull();
  });
});

describe("401 reconciliation", () => {
  test("a 401 while /me shows another workspace reconciles to it instead of ending the session", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me())).next("GET", "/api/v1/cases", unauthenticated())
      .next("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })))
      .next("GET", "/api/v1/cases", json(200, SOUTH_CASE));
    renderApp();
    expect(await screen.findByText("South exchange")).toBeTruthy();
    expect(screen.getByText(NOTICE)).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 });
  });

  test("a 401 while /me shows the same context reloads the view without a notice", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me())).next("GET", "/api/v1/cases", unauthenticated())
      .next("GET", "/api/v1/me", json(200, me())).next("GET", "/api/v1/cases", json(200, NORTH_CASE));
    renderApp();
    expect(await screen.findByText("North refund")).toBeTruthy();
    expect(screen.queryByText(NOTICE)).toBeNull();
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 });
  });

  test("a 401 confirmed by /me ends the session", async () => {
    const api = new FakeApi().next("GET", "/api/v1/me", json(200, me())).next("GET", "/api/v1/cases", unauthenticated())
      .next("GET", "/api/v1/me", unauthenticated());
    renderApp();
    expect(await screen.findByRole("alertdialog", { name: "Your session ended" })).toBeTruthy();
    expect(await quiet(api)).toEqual({ me: 2, cases: 1 });
  });

  test("a standing /me 200 with a protected endpoint that keeps answering 401 stops after one reconciliation", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me())).on("GET", "/api/v1/cases", unauthenticated());
    renderApp();
    expect(await screen.findByRole("alertdialog", { name: "Your session ended" })).toBeTruthy();
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 }); // no 401 -> /me -> remount loop across generations
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 }); // and the state stays put
    expect(screen.getByRole("alertdialog", { name: "Your session ended" })).toBeTruthy();
  });

  test("a success after a reconciliation closes the incident, so a later 401 reconciles again", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me()));
    const controller = new SessionController();
    const ready = async (): Promise<Scope> => {
      await vi.waitFor(() => {
        expect(controller.getState().status).toBe("ready");
      });
      return controller.scope();
    };
    controller.boot();
    const first = await ready();
    expect(first.context?.workspaceId).toBe(WORKSPACE_A.workspace_id);
    controller.reportUnauthenticated(first, "cases");
    expect(controller.getState().status).toBe("reconciling");
    const second = await ready();
    controller.reportSuccess(first, "cases"); // stale: closes nothing
    controller.reportSuccess(second, "members"); // a sibling's success: the refused resource has not recovered
    controller.reportSuccess(second, "cases"); // the refused resource succeeded in the reconciled view
    controller.reportUnauthenticated(second, "members");
    expect(controller.getState().status).toBe("reconciling"); // a new incident, not an expiry
    const third = await ready();
    controller.reportUnauthenticated(first, "cases"); // stale: ignored
    expect(controller.getState().status).toBe("ready");
    controller.reportSuccess(third, "cases"); // not the resource that opened this recovery
    controller.reportUnauthenticated(third, "cases"); // refused again before "members" succeeded: stop
    expect(controller.getState().status).toBe("expired");
    expect(api.callsTo("GET", "/api/v1/me")).toHaveLength(3);
    controller.dispose();
  });
});

// Two resources in one view, as on any page that loads more than one. In every generation the refused one answers
// only after its sibling's success has been reported: that success must not reopen automatic recovery. Without the
// bound this loops until the per-test fetch budget refuses further requests (test/network.ts).
function Resources() {
  useSessionResource(listCases, "cases");
  const { resource } = useSessionResource(listMembers, "members");
  return <p data-testid="members">{resource.status}</p>;
}

function TwoResources() {
  const state = useSessionState();
  return (
    <>
      <p data-testid="session">{state.status}</p>
      {state.status === "ready" ? <Resources key={state.generation} /> : null}
    </>
  );
}

describe("a successful sibling does not rearm recovery", () => {
  test.each([
    { status: 401, refusal: unauthenticated, terminal: "expired" },
    { status: 409, refusal: contextChanged, terminal: "bootFailed" },
  ])("$status: one automatic /me reload, then $terminal", async ({ refusal, terminal }) => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me({ roles: ["admin"] })))
      .on("GET", "/api/v1/cases", json(200, NORTH_CASE))
      .on("GET", "/api/v1/workspace/members", async () => {
        await new Promise((resolve) => setTimeout(resolve, 0)); // after the sibling's success
        return refusal();
      });
    render(<MemoryRouter><SessionProvider><TwoResources /></SessionProvider></MemoryRouter>);
    await waitFor(() => {
      expect(screen.getByTestId("session").textContent).toBe(terminal);
    });
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 });
    expect(api.callsTo("GET", "/api/v1/workspace/members")).toHaveLength(2);
    expect(screen.getByTestId("session").textContent).toBe(terminal);
  });

  test("the refused resource's own success closes the incident without further reloads", async () => {
    const api = new FakeApi().on("GET", "/api/v1/me", json(200, me({ roles: ["admin"] })))
      .on("GET", "/api/v1/cases", json(200, NORTH_CASE))
      .next("GET", "/api/v1/workspace/members", contextChanged())
      .on("GET", "/api/v1/workspace/members", json(200, []));
    render(<MemoryRouter><SessionProvider><TwoResources /></SessionProvider></MemoryRouter>);
    await waitFor(() => {
      expect(screen.queryByTestId("members")?.textContent).toBe("ready");
    });
    expect(await quiet(api)).toEqual({ me: 2, cases: 2 });
    expect(api.callsTo("GET", "/api/v1/workspace/members")).toHaveLength(2);
    expect(screen.getByTestId("session").textContent).toBe("ready");
  });
});
