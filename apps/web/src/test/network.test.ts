import { expect, test } from "vitest";

import { FETCH_BUDGET, FetchBudgetExhaustedError, NetworkBlockedError, installFake, takeBlockedAttempts,
         verifyNoBlockedAttempts } from "./network";

test("fetch is refused and the attempt is recorded", async () => {
  await expect(fetch("https://example.com/api")).rejects.toBeInstanceOf(NetworkBlockedError);
  await expect(fetch(new Request("http://127.0.0.1:8000/x"))).rejects.toBeInstanceOf(NetworkBlockedError);
  expect(takeBlockedAttempts()).toEqual(["fetch(https://example.com/api)", "fetch(http://127.0.0.1:8000/x)"]);
});

test("XMLHttpRequest, WebSocket and EventSource are refused", () => {
  const request = new XMLHttpRequest();
  expect(() => {
    request.open("GET", "https://example.com/");
  }).toThrow(NetworkBlockedError);
  expect(() => new WebSocket("wss://example.com/socket")).toThrow(NetworkBlockedError);
  expect(() => new EventSource("/events")).toThrow(NetworkBlockedError);
  expect(takeBlockedAttempts()).toHaveLength(3);
});

test("a swallowed attempt is still reported", async () => {
  await fetch("https://example.com/").catch(() => undefined);
  expect(() => {
    verifyNoBlockedAttempts();
  }).toThrow(/unexpected network attempts: fetch\(https:\/\/example.com\/\)/);
});

test("a test can install a fake for one global", async () => {
  installFake("fetch", () => Promise.resolve(new Response("fake body")));
  const response = await fetch("https://example.com/");
  expect(await response.text()).toBe("fake body");
});

test("the fake was reset after the previous test", async () => {
  // Runs after the fake-installing test (file order).
  await expect(fetch("https://example.com/")).rejects.toBeInstanceOf(NetworkBlockedError);
  takeBlockedAttempts();
});

test("a fetch fake is metered: past the per-test budget requests are refused and a swallowed refusal is reported",
     async () => {
  let served = 0;
  installFake("fetch", () => {
    served += 1;
    return Promise.resolve(new Response("ok"));
  });
  for (let index = 0; index < FETCH_BUDGET; index += 1) {
    await fetch("/api/v1/me");
  }
  await expect(fetch("/api/v1/me")).rejects.toBeInstanceOf(FetchBudgetExhaustedError);
  await fetch("/api/v1/me").catch(() => undefined); // swallowed by the caller
  expect(served).toBe(FETCH_BUDGET); // the refused requests never reached the fake
  expect(() => {
    verifyNoBlockedAttempts();
  }).toThrow(/per-test budget of 200 \(request 201\).*\(request 202\)/);
});

test("the budget was reset with the fake", async () => {
  // Runs after the budget test (file order).
  installFake("fetch", () => Promise.resolve(new Response("fresh")));
  expect(await (await fetch("/api/v1/me")).text()).toBe("fresh");
});
