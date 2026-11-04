import { expect, test } from "vitest";

import { GUARDED, NetworkBlockedError, isBlocked, takeBlockedAttempts } from "./network";

// Evaluated while this file is imported, before any hook runs. The sentinel is a data: URL, so even without the
// guard the call would be answered locally rather than reaching a network.
const blockedAtImport = Object.fromEntries(GUARDED.map((name) => [name, isBlocked(name)]));
const importTimeFetch: Promise<string> = fetch("data:text/plain,reached").then(
  (response) => response.text(),
  (error: unknown) => (error instanceof NetworkBlockedError ? "blocked" : "other error"),
);

test("network globals are already blocked while test files are imported", async () => {
  expect(blockedAtImport).toEqual({ fetch: true, XMLHttpRequest: true, WebSocket: true, EventSource: true });
  expect(await importTimeFetch).toBe("blocked");
  expect(takeBlockedAttempts()).toEqual(["fetch(data:text/plain,reached)"]);
});
