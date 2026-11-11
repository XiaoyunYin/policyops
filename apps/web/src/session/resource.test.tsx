// The generation guard in useSessionResource on its own: here the consumer stays mounted across a generation change
// (no keyed remount) and its loader ignores the abort signal entirely, so only the guard can discard late results.

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { beforeEach, expect, test } from "vitest";

import { ApiError } from "../api/client";
import { FakeApi, WORKSPACE_B, json, me } from "../test/fakeApi";
import { becomeVisible, settle } from "../test/renderApp";
import { SessionProvider, useSessionResource, useSessionState } from "./SessionProvider";

let pending: { resolve: (value: string) => void; reject: (error: unknown) => void }[] = [];

function loadIgnoringAbort(): Promise<string> {
  return new Promise((resolve, reject) => {
    pending.push({ resolve, reject });
  });
}

function Consumer() {
  const { resource } = useSessionResource(loadIgnoringAbort, "probe");
  return <p data-testid="resource">{resource.status === "ready" ? resource.data : resource.status}</p>;
}

function Harness() {
  const state = useSessionState();
  return (
    <>
      <p data-testid="session">{state.status === "ready" ? `ready:${state.me.workspace_id ?? ""}` : state.status}</p>
      {state.status === "ready" ? <Consumer /> : null}
    </>
  );
}

async function startThenChangeWorkspaceElsewhere(): Promise<void> {
  const api = new FakeApi().next("GET", "/api/v1/me", json(200, me()));
  render(<MemoryRouter><SessionProvider><Harness /></SessionProvider></MemoryRouter>);
  await screen.findByText("loading");
  expect(pending).toHaveLength(1);
  api.next("GET", "/api/v1/me", json(200, me({ workspace: WORKSPACE_B })));
  await becomeVisible();
  expect(screen.getByTestId("session").textContent).toBe(`ready:${WORKSPACE_B.workspace_id}`);
}

beforeEach(() => {
  pending = [];
});

test("a late success from an earlier generation is discarded while the consumer stays mounted", async () => {
  await startThenChangeWorkspaceElsewhere();
  pending[0]?.resolve("data from the previous workspace");
  await settle();
  expect(screen.getByTestId("resource").textContent).toBe("loading");
});

test("a late 401 from an earlier generation neither shows an error nor ends the session", async () => {
  await startThenChangeWorkspaceElsewhere();
  pending[0]?.reject(new ApiError("http", 401, "unauthenticated", "Sign in again."));
  await settle();
  expect(screen.getByTestId("session").textContent).toBe(`ready:${WORKSPACE_B.workspace_id}`);
  expect(screen.getByTestId("resource").textContent).toBe("loading");
});
